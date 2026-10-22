# -*- coding: utf-8 -*-
"""
M.I.R.V. — Drafter-Reviewer (F8)
===============================
Evidence-based drafting/review/revise using agency_agents personas.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from backend import agency_agents

logger = logging.getLogger("vulnforge.draft_review")


def _build_evidence_block(evidence: List[Dict[str, Any]] | Dict[str, Any]) -> str:
    if isinstance(evidence, dict):
        return json.dumps(evidence, ensure_ascii=False, indent=2)
    try:
        return json.dumps(evidence or [], ensure_ascii=False, indent=2)
    except Exception:
        return str(evidence)


def draft(evidence: List[Dict[str, Any]] | Dict[str, Any], persona: str = "security-penetration-tester") -> Dict[str, Any]:
    ev = _build_evidence_block(evidence)
    sys = agency_agents.build_persona_prompt(persona, task="Write a factual technical finding/report draft using ONLY the provided evidence. Do not invent vulns. Be concise.")
    prompt = f"## Evidence (JSON)\n{ev}\n\n## Task\nDraft findings: title, severity, affected, proof, impact, recommendation. Only cite items present in evidence."
    try:
        from backend import main
        text = main._call_llm_sync("local", "", "llama3", [{"role": "system", "content": sys}, {"role": "user", "content": prompt}], timeout=60, max_tokens=1024)
    except Exception as e:
        text = f"Draft error: {e}\n\nEvidence:\n{ev[:2000]}"
    return {"ok": True, "draft": text, "persona": persona}


def review(draft_text: str, evidence: List[Dict[str, Any]] | Dict[str, Any], persona: str = "security-appsec-engineer") -> Dict[str, Any]:
    ev = _build_evidence_block(evidence)
    sys = agency_agents.build_persona_prompt(persona, task="Review the draft against evidence. Flag hallucinations, missing evidence, severity issues.")
    prompt = f"## Evidence (JSON)\n{ev}\n\n## Draft\n{draft_text}\n\n## Review\nReturn a checklist: OK/MISSING/ISSUE with brief rationale. Do not add new findings."
    try:
        from backend import main
        text = main._call_llm_sync("local", "", "llama3", [{"role": "system", "content": sys}, {"role": "user", "content": prompt}], timeout=60, max_tokens=1024)
    except Exception as e:
        text = f"Review error: {e}"
    return {"ok": True, "review": text, "persona": persona}


def revise(draft_text: str, review_text: str, evidence: List[Dict[str, Any]] | Dict[str, Any], persona: str = "security-penetration-tester") -> Dict[str, Any]:
    ev = _build_evidence_block(evidence)
    sys = agency_agents.build_persona_prompt(persona, task="Revise the draft to address review issues using ONLY evidence.")
    prompt = f"## Evidence (JSON)\n{ev}\n\n## Draft\n{draft_text}\n\n## Review\n{review_text}\n\n## Task\nProduce revised version with only evidence-backed claims."
    try:
        from backend import main
        text = main._call_llm_sync("local", "", "llama3", [{"role": "system", "content": sys}, {"role": "user", "content": prompt}], timeout=60, max_tokens=1024)
    except Exception as e:
        text = draft_text
    return {"ok": True, "revised": text, "persona": persona}
