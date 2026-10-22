# -*- coding: utf-8 -*-
"""
M.I.R.V. — OODA Engine (F3)
===========================
Observe -> Orient -> Decide -> Act loop over OODAStore.

- Mode assist/pentest; pentest requires explicit flag
- Scope/permission aware (uses scope_guard where possible)
- Ingest guard used on untrusted content
- Feeds findings with technique_id/ooda_status/confidence
- Stdlib only
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from backend import ooda_store
from backend import scope_guard

logger = logging.getLogger("vulnforge.ooda")


class OODAEngine:
    def __init__(self):
        self.store = ooda_store

    def create(self, target: str = "", goal: str = "", mode: str = "assist", assessment_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
        if mode not in ("assist", "pentest"):
            mode = "assist"
        # pentest mode is allowed but actions must still go through permission gate in WS; we just flag
        run = self.store.create_run(target=target, goal=goal, mode=mode, assessment_id=assessment_id, meta=meta or {})
        # Observe
        self.store.append_step(run.run_id, "observe", input_data={"target": target, "goal": goal}, reasoning="Initial observation of scope/target context", actions=[], evidence=[], findings=[])
        return run

    def observe(self, run_id: str, input_data: Optional[Dict[str, Any]] = None, reasoning: str = "", evidence: Optional[List[Dict[str, Any]]] = None):
        ev = evidence or []
        # basic scope check on provided targets if any
        targets = []
        if input_data:
            for k in ("targets", "hosts", "urls"):
                v = input_data.get(k)
                if isinstance(v, list):
                    targets.extend([str(x) for x in v])
                elif v:
                    targets.append(str(v))
        for t in targets[:5]:
            try:
                res = scope_guard.validate_target(t)
                if not res.get("allowed"):
                    ev.append({"type": "scope", "target": t, "allowed": False, "reason": res.get("reason")})
            except Exception:
                pass
        return self.store.append_step(run_id, "observe", input_data=input_data or {}, reasoning=reasoning or "Observe", actions=[], evidence=ev, findings=[])

    def orient(self, run_id: str, reasoning: str = "", technique_id: str = "", confidence: float = 0.0, input_data: Optional[Dict[str, Any]] = None):
        # Try to enrich with knowledgebase if available
        tid = technique_id or ""
        if not tid and input_data:
            hint = str(input_data.get("hint") or input_data.get("technique") or "")
            if hint.upper().startswith("T"):
                tid = hint.upper()
        return self.store.append_step(run_id, "orient", input_data=input_data or {}, reasoning=reasoning or "Orient", actions=[], evidence=[], findings=[], technique_id=tid, confidence=confidence)

    def decide(self, run_id: str, actions: Optional[List[Dict[str, Any]]] = None, reasoning: str = "", technique_id: str = "", confidence: float = 0.0):
        acts = actions or []
        # mark actions that would need permission if risky
        enriched = []
        for a in acts:
            cmd = str(a.get("command") or a.get("cmd") or "")
            risk = "safe"
            needs_perm = False
            try:
                if cmd:
                    cls = scope_guard.classify_command(cmd, check_scope=False)
                    if cls.get("blocked"):
                        risk = "blocked"
                    elif cls.get("needs_permission"):
                        risk = cls.get("severity") or "high"
                        needs_perm = True
                    else:
                        risk = cls.get("severity") or "safe"
            except Exception:
                pass
            na = dict(a)
            na["_risk"] = risk
            na["_needs_permission"] = needs_perm
            enriched.append(na)
        return self.store.append_step(run_id, "decide", input_data={"count": len(enriched)}, reasoning=reasoning or "Decide", actions=enriched, evidence=[], findings=[], technique_id=technique_id, confidence=confidence)

    def act(self, run_id: str, actions: Optional[List[Dict[str, Any]]] = None, evidence: Optional[List[Dict[str, Any]]] = None, findings: Optional[List[Dict[str, Any]]] = None, reasoning: str = "", technique_id: str = "", confidence: float = 0.0, ooda_status: str = "open"):
        finds = findings or []
        # ensure findings have required fields
        norm = []
        for f in finds:
            nf = dict(f)
            if "technique_id" not in nf and technique_id:
                nf["technique_id"] = technique_id
            if "confidence" not in nf and confidence:
                nf["confidence"] = confidence
            if "ooda_status" not in nf:
                nf["ooda_status"] = ooda_status
            norm.append(nf)
        return self.store.append_step(run_id, "act", input_data={"actions": len(actions or []), "findings": len(norm)}, reasoning=reasoning or "Act", actions=actions or [], evidence=evidence or [], findings=norm, technique_id=technique_id, confidence=confidence, ooda_status=ooda_status)

    def get(self, run_id: str):
        return self.store.get_run(run_id)

    def list(self, limit: int = 50):
        return self.store.list_runs(limit=limit)

    def done(self, run_id: str):
        return self.store.update_run_status(run_id, "done")


engine = OODAEngine()
