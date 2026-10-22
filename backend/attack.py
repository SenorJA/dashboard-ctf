# -*- coding: utf-8 -*-
"""
M.I.R.V. — ATT&CK mapping (F4)
==============================
Extend findings with technique_id + coverage/gap endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend import knowledgebase


def enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    f = dict(finding)
    if f.get("technique_id"):
        tid = str(f["technique_id"]).upper()
        f["technique_id"] = tid
        m = knowledgebase.get_mitre(tid)
        if m:
            f.setdefault("tactic", m.get("tactic"))
            f.setdefault("technique_name", m.get("name"))
        return f
    # try to infer from type/tool
    t = str(f.get("type") or "").lower()
    tool = str(f.get("tool") or "").lower()
    title = str(f.get("title") or "").lower()
    tid = ""
    if "exploit" in t or "rce" in title or tool in ("metasploit",):
        tid = "T1190"
    elif "cred" in t or "password" in title or tool == "hydra":
        tid = "T1110"
    elif "port" in t or tool in ("nmap", "masscan"):
        tid = "T1046"
    elif "smb" in title:
        tid = "T1021"
    elif "priv" in t or "escalat" in title:
        tid = "T1068"
    if tid:
        f["technique_id"] = tid
        m = knowledgebase.get_mitre(tid)
        if m:
            f["tactic"] = m.get("tactic")
            f["technique_name"] = m.get("name")
    return f


def list_techniques(q: str = "") -> List[Dict[str, Any]]:
    return knowledgebase.search_mitre(q)


def coverage_by_technique(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    covered = set()
    for f in findings or []:
        tid = f.get("technique_id") or f.get("mitre") or f.get("technique")
        if tid:
            covered.add(str(tid).upper())
    all_t = [m["id"] for m in knowledgebase.MITRE_DB]
    missing = sorted([t for t in all_t if t not in covered])
    return {"covered": sorted(list(covered)), "all": all_t, "missing": missing, "coverage_pct": round(len(covered)/max(1,len(all_t))*100, 1)}
