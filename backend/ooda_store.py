# -*- coding: utf-8 -*-
"""
M.I.R.V. — OODA Store (F3)
==========================
JSONL-backed store for OODA runs/steps. Write dual (primary JSONL per run + index JSONL).

- No new Supabase tables (per AGENTS.md rule)
- Thread-safe with RLock
- Stdlib only
- Integrates with audit_log/SIEM on key actions
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend import audit_log
from backend import siem

DATA_DIR = Path(__file__).parent / "data" / "ooda"
DATA_DIR.mkdir(parents=True, exist_ok=True)

_LOCK = threading.RLock()

_OODA_PHASES = {"observe", "orient", "decide", "act"}
_OODA_STATUS = {"open", "in-progress", "confirmed", "mitigated", "false-positive", "resolved"}
_RUN_STATUS = {"running", "paused", "done", "aborted"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_path(run_id: str) -> Path:
    safe = "".join(c for c in str(run_id) if c.isalnum() or c in "-_")
    if not safe:
        safe = "run"
    return DATA_DIR / f"{safe}.jsonl"


def _index_path() -> Path:
    return DATA_DIR / "index.jsonl"


@dataclass
class OODAStep:
    step_id: str
    run_id: str
    phase: str
    ts: str
    input: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    actions: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    technique_id: str = ""
    confidence: float = 0.0
    ooda_status: str = "open"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class OODARun:
    run_id: str
    assessment_id: Optional[str] = None
    target: str = ""
    goal: str = ""
    mode: str = "assist"  # assist|pentest
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    steps: List[OODAStep] = field(default_factory=list)
    status: str = "running"
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # steps as dicts
        d["steps"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps]
        return d


def create_run(target: str = "", goal: str = "", mode: str = "assist", assessment_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> OODARun:
    if mode not in ("assist", "pentest"):
        mode = "assist"
    run = OODARun(
        run_id=str(uuid.uuid4()),
        assessment_id=assessment_id,
        target=target or "",
        goal=goal or "",
        mode=mode,
        meta=meta or {},
    )
    with _LOCK:
        _append_jsonl(_run_path(run.run_id), {"type": "run", "run": run.to_dict()})
        _append_jsonl(_index_path(), {"type": "run_index", "run_id": run.run_id, "target": run.target, "goal": run.goal, "mode": run.mode, "status": run.status, "created_at": run.created_at, "assessment_id": run.assessment_id})
    try:
        audit_log.log_event("ooda.run_created", {"run_id": run.run_id, "target": run.target, "mode": run.mode})
        siem.ingest_event({"source": "ooda", "type": "run_created", "severity": "info", "target": run.target or run.run_id, "details": {"run_id": run.run_id, "mode": run.mode}})
    except Exception:
        pass
    return run


def append_step(run_id: str, phase: str, input_data: Optional[Dict[str, Any]] = None, reasoning: str = "", actions: Optional[List[Dict[str, Any]]] = None, evidence: Optional[List[Dict[str, Any]]] = None, findings: Optional[List[Dict[str, Any]]] = None, technique_id: str = "", confidence: float = 0.0, ooda_status: str = "open") -> OODAStep:
    if phase not in _OODA_PHASES:
        raise ValueError(f"invalid phase: {phase}")
    if ooda_status not in _OODA_STATUS:
        ooda_status = "open"
    try:
        confidence = float(confidence)
    except Exception:
        confidence = 0.0
    if confidence < 0.0:
        confidence = 0.0
    if confidence > 1.0:
        confidence = 1.0

    step = OODAStep(
        step_id=str(uuid.uuid4()),
        run_id=run_id,
        phase=phase,
        ts=_now_iso(),
        input=input_data or {},
        reasoning=reasoning or "",
        actions=actions or [],
        evidence=evidence or [],
        findings=findings or [],
        technique_id=technique_id or "",
        confidence=confidence,
        ooda_status=ooda_status,
    )
    with _LOCK:
        _append_jsonl(_run_path(run_id), {"type": "step", "step": step.to_dict()})
        _append_jsonl(_index_path(), {"type": "step_index", "run_id": run_id, "step_id": step.step_id, "phase": phase, "ts": step.ts})
        _update_index_status(run_id, "running")
    try:
        audit_log.log_event("ooda.step_appended", {"run_id": run_id, "phase": phase, "step_id": step.step_id, "findings": len(step.findings)})
    except Exception:
        pass
    return step


def update_run_status(run_id: str, status: str) -> bool:
    if status not in _RUN_STATUS:
        return False
    with _LOCK:
        _append_jsonl(_run_path(run_id), {"type": "status", "run_id": run_id, "status": status, "ts": _now_iso()})
        _update_index_status(run_id, status)
    try:
        audit_log.log_event("ooda.run_status", {"run_id": run_id, "status": status})
        siem.ingest_event({"source": "ooda", "type": "run_status", "severity": "info", "target": run_id, "details": {"status": status}})
    except Exception:
        pass
    return True


def get_run(run_id: str) -> Optional[OODARun]:
    path = _run_path(run_id)
    if not path.exists():
        return None
    steps: List[OODAStep] = []
    run_meta: Dict[str, Any] = {}
    status = "running"
    with _LOCK:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            t = obj.get("type")
            if t == "run" and obj.get("run"):
                r = obj["run"]
                run_meta = r
                status = r.get("status") or status
            elif t == "step" and obj.get("step"):
                s = obj["step"]
                steps.append(OODAStep(
                    step_id=s.get("step_id") or str(uuid.uuid4()),
                    run_id=s.get("run_id") or run_id,
                    phase=s.get("phase") or "observe",
                    ts=s.get("ts") or _now_iso(),
                    input=s.get("input") or {},
                    reasoning=s.get("reasoning") or "",
                    actions=s.get("actions") or [],
                    evidence=s.get("evidence") or [],
                    findings=s.get("findings") or [],
                    technique_id=s.get("technique_id") or "",
                    confidence=float(s.get("confidence") or 0.0),
                    ooda_status=s.get("ooda_status") or "open",
                ))
            elif t == "status":
                status = obj.get("status") or status
    run = OODARun(
        run_id=run_meta.get("run_id") or run_id,
        assessment_id=run_meta.get("assessment_id"),
        target=run_meta.get("target") or "",
        goal=run_meta.get("goal") or "",
        mode=run_meta.get("mode") or "assist",
        created_at=run_meta.get("created_at") or _now_iso(),
        updated_at=run_meta.get("updated_at") or _now_iso(),
        steps=steps,
        status=status,
        meta=run_meta.get("meta") or {},
    )
    return run


def list_runs(limit: int = 50) -> List[Dict[str, Any]]:
    ipath = _index_path()
    if not ipath.exists():
        return []
    out: Dict[str, Dict[str, Any]] = {}
    with _LOCK:
        for line in ipath.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            t = obj.get("type")
            if t == "run_index":
                rid = obj.get("run_id")
                if rid:
                    out[rid] = {**out.get(rid, {}), **obj, "last_ts": obj.get("created_at")}
            elif t == "step_index":
                rid = obj.get("run_id")
                if rid and rid in out:
                    out[rid]["last_ts"] = obj.get("ts") or out[rid].get("last_ts")
                    out[rid]["steps"] = int(out[rid].get("steps") or 0) + 1
            elif t == "status_index":
                rid = obj.get("run_id")
                if rid and rid in out:
                    out[rid]["status"] = obj.get("status") or out[rid]["status"]
    items = list(out.values())
    items.sort(key=lambda x: x.get("last_ts") or x.get("created_at") or "", reverse=True)
    return items[: max(1, min(int(limit), 200))]


def _append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _update_index_status(run_id: str, status: str) -> None:
    _append_jsonl(_index_path(), {"type": "status_index", "run_id": run_id, "status": status, "ts": _now_iso()})
