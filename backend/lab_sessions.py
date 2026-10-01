"""
lab_sessions.py -- MIRV Module

Lab Sessions workspace — organise authorized lab / HTB-style work as
machines -> sessions -> evidence steps, with deterministic flag detection,
AI analysis over the FULL chronological history, and narrated write-ups.

Ported from the afsh4ck/exploitpath data model (machines/sessions/steps/
analyses) and adapted to MIRV's registry conventions:

  * In-memory, thread-safe registry (authoritative).
  * Opt-in persistence via ``workspace_store`` (key ``lab_sessions``) when
    ``MIRV_PERSIST_WORKSPACE=1`` and Supabase is available.
  * Editing or deleting evidence recomputes flags/phase and invalidates stale
    AI analyses, mirroring ExploitPath's integrity guarantee.

This module never connects to a target and never executes commands; it only
stores and analyses operator-pasted evidence.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.flag_detection import (
    derive_session_state,
    detect_flag,
    normalize_detection,
)

try:
    from backend import workspace_store as _store
except ImportError:  # pragma: no cover
    _store = None  # type: ignore[assignment]

_logger = logging.getLogger("vulnforge.lab_sessions")

VALID_OS = frozenset({"linux", "windows"})
VALID_DIFFICULTY = frozenset({"easy", "medium", "hard", "insane"})
VALID_MACHINE_STATUS = frozenset({"active", "pwned", "archived"})
VALID_PHASES = frozenset({"recon", "foothold", "privesc", "complete"})

MAX_MACHINES = 500
MAX_SESSIONS_PER_MACHINE = 50
MAX_STEPS_PER_SESSION = 1000
MAX_COMMAND_LENGTH = 12000
MAX_OUTPUT_LENGTH = 60000
MAX_NOTES_LENGTH = 8000
MAX_TITLE_LENGTH = 160
MAX_ANALYSES_PER_SESSION = 50

_PERSIST_KEY = "lab_sessions"


def _now_iso() -> str:
    """UTC ISO-8601 timestamp with Z suffix (stable, sortable)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clip(value: Any, limit: int) -> str:
    return str(value if value is not None else "")[:limit]


@dataclass
class Machine:
    """A lab machine (authorized target)."""

    id: str
    name: str
    ip: str = ""
    operating_system: str = "linux"
    difficulty: str = "easy"
    status: str = "active"
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Step:
    """A single chronological evidence record."""

    id: str
    session_id: str
    command: str
    output: str = ""
    notes: str = ""
    detected_flag_type: str = "none"
    detected_flag_value: Optional[str] = None
    order: int = 0
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LabSession:
    """A focused run against a machine."""

    id: str
    machine_id: str
    title: str
    phase: str = "recon"
    user_flag_captured: bool = False
    root_flag_captured: bool = False
    user_flag_value: Optional[str] = None
    root_flag_value: Optional[str] = None
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Analysis:
    """A structured AI analysis snapshot for a session."""

    id: str
    session_id: str
    model: str
    current_phase: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    next_objective: str = ""
    safe_commands: List[str] = field(default_factory=list)
    rationale: str = ""
    cautions: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -- Module-level registry (thread-safe) -----------------------------------
_lock = threading.Lock()
_machines: Dict[str, Machine] = {}
_sessions: Dict[str, LabSession] = {}
_steps: Dict[str, Step] = {}
_analyses: Dict[str, Analysis] = {}
_step_counter = 0


def _validate(value: str, allowed: frozenset, field_name: str) -> Optional[str]:
    if value not in allowed:
        return f"invalid {field_name} '{value}'. Allowed: {', '.join(sorted(allowed))}"
    return None


# ── Machines ───────────────────────────────────────────────────────────────

def create_machine(
    name: str,
    ip: str = "",
    operating_system: str = "linux",
    difficulty: str = "easy",
    status: str = "active",
) -> Machine:
    """Create a lab machine. Raises ValueError on invalid input."""
    name = (name or "").strip()
    if not name:
        raise ValueError("machine name is required")
    for value, allowed, label in (
        (operating_system, VALID_OS, "operating_system"),
        (difficulty, VALID_DIFFICULTY, "difficulty"),
        (status, VALID_MACHINE_STATUS, "status"),
    ):
        err = _validate(value, allowed, label)
        if err:
            raise ValueError(err)
    with _lock:
        if len(_machines) >= MAX_MACHINES:
            raise ValueError(f"max {MAX_MACHINES} machines reached")
        m = Machine(
            id=uuid.uuid4().hex[:12],
            name=name,
            ip=(ip or "").strip()[:45],
            operating_system=operating_system,
            difficulty=difficulty,
            status=status,
        )
        _machines[m.id] = m
    _persist()
    return m


def list_machines() -> List[Dict[str, Any]]:
    with _lock:
        items = [m.to_dict() for m in _machines.values()]
        counts = {sid: 0 for sid in _sessions}
        for s in _sessions.values():
            counts[s.machine_id] = counts.get(s.machine_id, 0) + 1
        for d in items:
            d["session_count"] = counts.get(d["id"], 0)
    items.sort(key=lambda d: d["updated_at"], reverse=True)
    return items


def get_machine(mid: str) -> Optional[Dict[str, Any]]:
    with _lock:
        m = _machines.get(mid)
        return m.to_dict() if m else None


def update_machine(mid: str, **fields: Any) -> Optional[Dict[str, Any]]:
    """Update a machine. Returns updated dict or None if not found/invalid."""
    with _lock:
        m = _machines.get(mid)
        if not m:
            return None
        if "name" in fields:
            name = (fields["name"] or "").strip()
            if not name:
                return None
            m.name = name
        if "ip" in fields:
            m.ip = _clip(fields["ip"], 45).strip()
        for key, allowed, label in (
            ("operating_system", VALID_OS, "operating_system"),
            ("difficulty", VALID_DIFFICULTY, "difficulty"),
            ("status", VALID_MACHINE_STATUS, "status"),
        ):
            if key in fields and fields[key] is not None:
                if _validate(fields[key], allowed, label):
                    return None
                setattr(m, key, fields[key])
        m.updated_at = _now_iso()
        result = m.to_dict()
    _persist()
    return result


def delete_machine(mid: str) -> bool:
    """Delete a machine and cascade its sessions/steps/analyses."""
    with _lock:
        if mid not in _machines:
            return False
        session_ids = [s.id for s in _sessions.values() if s.machine_id == mid]
        for sid in session_ids:
            _delete_session_locked(sid)
        del _machines[mid]
    _persist()
    return True


# ── Sessions ───────────────────────────────────────────────────────────────

def create_session(machine_id: str, title: str) -> LabSession:
    """Create a session for an existing machine."""
    title = (title or "").strip()
    if not title:
        raise ValueError("session title is required")
    with _lock:
        if machine_id not in _machines:
            raise ValueError("machine not found")
        if sum(1 for s in _sessions.values() if s.machine_id == machine_id) >= MAX_SESSIONS_PER_MACHINE:
            raise ValueError(f"max {MAX_SESSIONS_PER_MACHINE} sessions per machine reached")
        s = LabSession(
            id=uuid.uuid4().hex[:12],
            machine_id=machine_id,
            title=title[:MAX_TITLE_LENGTH],
        )
        _sessions[s.id] = s
        _machines[machine_id].updated_at = _now_iso()
    _persist()
    return s


def list_sessions(machine_id: Optional[str] = None) -> List[Dict[str, Any]]:
    with _lock:
        items = [
            s.to_dict()
            for s in _sessions.values()
            if machine_id is None or s.machine_id == machine_id
        ]
        step_counts: Dict[str, int] = {}
        for st in _steps.values():
            step_counts[st.session_id] = step_counts.get(st.session_id, 0) + 1
        for d in items:
            d["step_count"] = step_counts.get(d["id"], 0)
    items.sort(key=lambda d: d["updated_at"], reverse=True)
    return items


def get_session(sid: str) -> Optional[Dict[str, Any]]:
    with _lock:
        s = _sessions.get(sid)
        return s.to_dict() if s else None


def update_session(sid: str, title: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return None
        if title is not None:
            title = (title or "").strip()
            if not title:
                return None
            s.title = title[:MAX_TITLE_LENGTH]
        s.updated_at = _now_iso()
        result = s.to_dict()
    _persist()
    return result


def _delete_session_locked(sid: str) -> bool:
    """Delete a session + children. Caller must hold the lock."""
    s = _sessions.pop(sid, None)
    if not s:
        return False
    for key in [k for k, v in _steps.items() if v.session_id == sid]:
        del _steps[key]
    for key in [k for k, v in _analyses.items() if v.session_id == sid]:
        del _analyses[key]
    return True


def delete_session(sid: str) -> bool:
    with _lock:
        deleted = _delete_session_locked(sid)
    if deleted:
        _persist()
    return deleted


# ── Steps (evidence) ───────────────────────────────────────────────────────

def _prior_history_locked(sid: str) -> str:
    steps = sorted(
        (st for st in _steps.values() if st.session_id == sid),
        key=lambda st: (st.order, st.created_at, st.id),
    )
    return "\n".join(f"{st.command}\n{st.output}" for st in steps)


def _recompute_session_locked(sid: str) -> Optional[LabSession]:
    """Re-evaluate flags/phase for a session. Caller holds the lock."""
    s = _sessions.get(sid)
    if not s:
        return None
    steps = sorted(
        (st for st in _steps.values() if st.session_id == sid),
        key=lambda st: (st.order, st.created_at, st.id),
    )
    detections = []
    prior = ""
    for st in steps:
        detection = detect_flag(st.command, st.output, prior)
        st.detected_flag_type = detection.get("type", "none")
        st.detected_flag_value = detection.get("value")
        detections.append(detection)
        prior += f"{st.command}\n{st.output}\n"

    latest_phase = None
    session_analyses = [a for a in _analyses.values() if a.session_id == sid]
    if session_analyses:
        latest = max(session_analyses, key=lambda a: (a.created_at, a.id))
        latest_phase = latest.current_phase
    state = derive_session_state(detections, latest_phase)
    s.user_flag_captured = state["userFlagCaptured"]
    s.root_flag_captured = state["rootFlagCaptured"]
    s.user_flag_value = state["userFlagValue"]
    s.root_flag_value = state["rootFlagValue"]
    s.phase = state["phase"]
    s.updated_at = _now_iso()
    return s


def add_step(
    session_id: str,
    command: str,
    output: str = "",
    notes: str = "",
) -> Optional[Dict[str, Any]]:
    """Append an evidence step. Detects flags and invalidates stale analyses."""
    global _step_counter
    command = (command or "").strip()
    if not command:
        return None
    with _lock:
        if session_id not in _sessions:
            return None
        if sum(1 for st in _steps.values() if st.session_id == session_id) >= MAX_STEPS_PER_SESSION:
            return None
        _step_counter += 1
        step = Step(
            id=uuid.uuid4().hex[:12],
            session_id=session_id,
            command=_clip(command, MAX_COMMAND_LENGTH),
            output=_clip(output, MAX_OUTPUT_LENGTH),
            notes=_clip(notes, MAX_NOTES_LENGTH),
            order=_step_counter,
        )
        _steps[step.id] = step
        # New evidence invalidates prior AI analyses.
        for key in [k for k, a in _analyses.items() if a.session_id == session_id]:
            del _analyses[key]
        _recompute_session_locked(session_id)
        result = step.to_dict()
    _persist()
    return result


def update_step(
    step_id: str,
    command: Optional[str] = None,
    output: Optional[str] = None,
    notes: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    with _lock:
        step = _steps.get(step_id)
        if not step:
            return None
        if command is not None:
            command = (command or "").strip()
            if not command:
                return None
            step.command = _clip(command, MAX_COMMAND_LENGTH)
        if output is not None:
            step.output = _clip(output, MAX_OUTPUT_LENGTH)
        if notes is not None:
            step.notes = _clip(notes, MAX_NOTES_LENGTH)
        for key in [k for k, a in _analyses.items() if a.session_id == step.session_id]:
            del _analyses[key]
        _recompute_session_locked(step.session_id)
        result = step.to_dict()
    _persist()
    return result


def delete_step(step_id: str) -> bool:
    with _lock:
        step = _steps.pop(step_id, None)
        if not step:
            return False
        for key in [k for k, a in _analyses.items() if a.session_id == step.session_id]:
            del _analyses[key]
        _recompute_session_locked(step.session_id)
    _persist()
    return True


def list_steps(session_id: str) -> List[Dict[str, Any]]:
    with _lock:
        steps = [
            st.to_dict() for st in _steps.values() if st.session_id == session_id
        ]
    steps.sort(key=lambda d: (d["order"], d["created_at"], d["id"]))
    return steps


# ── Analyses ───────────────────────────────────────────────────────────────

def save_analysis(session_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Persist a structured AI analysis and sync the session phase."""
    with _lock:
        if session_id not in _sessions:
            return None
        existing = [k for k, a in _analyses.items() if a.session_id == session_id]
        while len(existing) >= MAX_ANALYSES_PER_SESSION:
            oldest = min(
                (a for a in _analyses.values() if a.session_id == session_id),
                key=lambda a: (a.created_at, a.id),
            )
            _analyses.pop(oldest.id, None)
            existing = [k for k, a in _analyses.items() if a.session_id == session_id]
        phase = data.get("current_phase") or data.get("currentPhase") or "recon"
        if phase not in VALID_PHASES:
            phase = "recon"
        a = Analysis(
            id=uuid.uuid4().hex[:12],
            session_id=session_id,
            model=_clip(data.get("model", ""), 80),
            current_phase=phase,
            summary=_clip(data.get("summary", ""), MAX_NOTES_LENGTH),
            evidence=[_clip(x, 2000) for x in (data.get("evidence") or [])][:20],
            next_objective=_clip(data.get("next_objective", data.get("nextObjective", "")), MAX_NOTES_LENGTH),
            safe_commands=[_clip(x, 1000) for x in (data.get("safe_commands") or data.get("safeCommands") or [])][:10],
            rationale=_clip(data.get("rationale", ""), MAX_NOTES_LENGTH),
            cautions=[_clip(x, 1000) for x in (data.get("cautions") or [])][:20],
        )
        _analyses[a.id] = a
        if phase != "complete" and not _sessions[session_id].root_flag_captured:
            _sessions[session_id].phase = phase
        _sessions[session_id].updated_at = _now_iso()
        result = a.to_dict()
    _persist()
    return result


def latest_analysis(session_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        items = [a for a in _analyses.values() if a.session_id == session_id]
        if not items:
            return None
        latest = max(items, key=lambda a: (a.created_at, a.id))
        return latest.to_dict()


def get_workspace(session_id: str) -> Optional[Dict[str, Any]]:
    """Return session + machine + ordered steps + latest analysis."""
    with _lock:
        s = _sessions.get(session_id)
        if not s:
            return None
        machine = _machines.get(s.machine_id)
        steps = sorted(
            (st.to_dict() for st in _steps.values() if st.session_id == session_id),
            key=lambda d: (d["order"], d["created_at"], d["id"]),
        )
        analysis = None
        session_analyses = [a for a in _analyses.values() if a.session_id == session_id]
        if session_analyses:
            latest = max(session_analyses, key=lambda a: (a.created_at, a.id))
            analysis = latest.to_dict()
        session = s.to_dict()
        if machine:
            session["machine_name"] = machine.name
            session["machine_ip"] = machine.ip
            session["operating_system"] = machine.operating_system
            session["difficulty"] = machine.difficulty
            session["machine_status"] = machine.status
        else:
            session["machine_name"] = ""
            session["machine_ip"] = ""
            session["operating_system"] = "linux"
            session["difficulty"] = "easy"
            session["machine_status"] = "active"
        return {"session": session, "steps": steps, "analysis": analysis}


# ── Summary / reset / persistence ──────────────────────────────────────────

def summary() -> Dict[str, Any]:
    with _lock:
        by_os: Dict[str, int] = {}
        by_phase: Dict[str, int] = {}
        for m in _machines.values():
            by_os[m.operating_system] = by_os.get(m.operating_system, 0) + 1
        for s in _sessions.values():
            by_phase[s.phase] = by_phase.get(s.phase, 0) + 1
        return {
            "machines": len(_machines),
            "sessions": len(_sessions),
            "steps": len(_steps),
            "analyses": len(_analyses),
            "user_flags": sum(1 for s in _sessions.values() if s.user_flag_captured),
            "root_flags": sum(1 for s in _sessions.values() if s.root_flag_captured),
            "by_os": by_os,
            "by_phase": by_phase,
        }


def reset_lab_sessions() -> None:
    """Clear the registry (used by tests)."""
    global _step_counter
    with _lock:
        _machines.clear()
        _sessions.clear()
        _steps.clear()
        _analyses.clear()
        _step_counter = 0
    if _store and _store.is_enabled():
        _store.clear_cache(_PERSIST_KEY)


def export_state() -> List[Dict[str, Any]]:
    """Full serializable state (machines with nested sessions/steps)."""
    with _lock:
        out = []
        for m in _machines.values():
            machine = m.to_dict()
            machine["sessions"] = []
            for s in _sessions.values():
                if s.machine_id != m.id:
                    continue
                sess = s.to_dict()
                sess["steps"] = [
                    st.to_dict()
                    for st in sorted(
                        (x for x in _steps.values() if x.session_id == s.id),
                        key=lambda x: (x.order, x.created_at, x.id),
                    )
                ]
                sess["analyses"] = [
                    a.to_dict() for a in _analyses.values() if a.session_id == s.id
                ]
                machine["sessions"].append(sess)
            out.append(machine)
    out.sort(key=lambda d: d["created_at"])
    return out


def import_state(rows: List[Dict[str, Any]], replace: bool = False) -> Dict[str, Any]:
    """Restore machines/sessions/steps/analyses from JSON. Skips invalid rows."""
    if not isinstance(rows, list):
        raise ValueError("debe ser una lista de machines")
    imported = sessions_in = steps_in = skipped = 0
    with _lock:
        if replace:
            _machines.clear()
            _sessions.clear()
            _steps.clear()
            _analyses.clear()
        for row in rows:
            if not isinstance(row, dict):
                skipped += 1
                continue
            name = (row.get("name") or "").strip()
            if not name:
                skipped += 1
                continue
            mid = row.get("id") or uuid.uuid4().hex[:12]
            if mid in _machines and not replace:
                continue
            _machines[mid] = Machine(
                id=mid,
                name=name,
                ip=_clip(row.get("ip", ""), 45),
                operating_system=row.get("operating_system", "linux")
                if row.get("operating_system") in VALID_OS else "linux",
                difficulty=row.get("difficulty", "easy")
                if row.get("difficulty") in VALID_DIFFICULTY else "easy",
                status=row.get("status", "active")
                if row.get("status") in VALID_MACHINE_STATUS else "active",
                created_at=row.get("created_at", _now_iso()),
                updated_at=row.get("updated_at", _now_iso()),
            )
            imported += 1
            for sess in row.get("sessions", []) or []:
                if not isinstance(sess, dict):
                    continue
                sid = sess.get("id") or uuid.uuid4().hex[:12]
                title = (sess.get("title") or "").strip()
                if not title:
                    continue
                _sessions[sid] = LabSession(
                    id=sid, machine_id=mid, title=title[:MAX_TITLE_LENGTH],
                    created_at=sess.get("created_at", _now_iso()),
                    updated_at=sess.get("updated_at", _now_iso()),
                )
                sessions_in += 1
                for st in sess.get("steps", []) or []:
                    if not isinstance(st, dict) or not (st.get("command") or "").strip():
                        continue
                    stid = st.get("id") or uuid.uuid4().hex[:12]
                    _steps[stid] = Step(
                        id=stid, session_id=sid,
                        command=_clip(st.get("command"), MAX_COMMAND_LENGTH),
                        output=_clip(st.get("output"), MAX_OUTPUT_LENGTH),
                        notes=_clip(st.get("notes"), MAX_NOTES_LENGTH),
                        order=int(st.get("order", 0) or 0),
                        created_at=st.get("created_at", _now_iso()),
                    )
                    steps_in += 1
                for a in sess.get("analyses", []) or []:
                    if not isinstance(a, dict):
                        continue
                    aid = a.get("id") or uuid.uuid4().hex[:12]
                    phase = a.get("current_phase") if a.get("current_phase") in VALID_PHASES else "recon"
                    _analyses[aid] = Analysis(
                        id=aid, session_id=sid,
                        model=_clip(a.get("model"), 80), current_phase=phase,
                        summary=_clip(a.get("summary"), MAX_NOTES_LENGTH),
                        evidence=[_clip(x, 2000) for x in (a.get("evidence") or [])][:20],
                        next_objective=_clip(a.get("next_objective"), MAX_NOTES_LENGTH),
                        safe_commands=[_clip(x, 1000) for x in (a.get("safe_commands") or [])][:10],
                        rationale=_clip(a.get("rationale"), MAX_NOTES_LENGTH),
                        cautions=[_clip(x, 1000) for x in (a.get("cautions") or [])][:20],
                        created_at=a.get("created_at", _now_iso()),
                    )
                _recompute_session_locked(sid)
    if imported:
        _persist()
    return {
        "imported": imported,
        "sessions": sessions_in,
        "steps": steps_in,
        "skipped": skipped,
        "total": len(_machines),
    }


def _persist() -> None:
    """Best-effort snapshot of the whole registry to Supabase."""
    if not _store or not _store.is_enabled():
        return
    try:
        _store.upsert(_PERSIST_KEY, export_state())
    except Exception as exc:  # pragma: no cover - defensive
        _logger.warning("lab_sessions persist failed: %s", exc)


def load_from_store() -> None:
    """Hydrate the in-memory registry from the persisted snapshot (startup)."""
    if not _store:
        return
    rows = _store.load(_PERSIST_KEY)
    if not rows:
        return
    try:
        import_state(rows, replace=True)
        _logger.info("lab_sessions: loaded %d machines from store", len(_machines))
    except Exception as exc:  # pragma: no cover - defensive
        _logger.warning("lab_sessions load failed: %s", exc)
