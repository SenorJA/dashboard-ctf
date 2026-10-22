# -*- coding: utf-8 -*-
"""
M.I.R.V. — HID / Rubber Ducky Detection (F7)
=============================================
Lightweight heuristics for DuckyScript/inject.bin analysis and findings.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


DUCKY_KEYWORDS = ["GUI", "WINDOWS", "CTRL", "CONTROL", "ALT", "SHIFT", "ENTER", "STRING", "DELAY", "REM", "REPEAT", "LED", "DEFAULTDELAY"]


def analyze_duckyscript(text: str) -> Dict[str, Any]:
    t = text or ""
    findings: List[Dict[str, Any]] = []
    lines = [l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith("REM")]
    kw = sum(1 for k in DUCKY_KEYWORDS if k in t.upper())
    if "STRING" in t.upper() and any(s in t.upper() for s in ["POWERSHELL", "CMD", "IEX", "INVOKE-EXPRESSION", "NET USER", "REG ADD"]):
        findings.append({"type": "hid_suspicious_string", "severity": "medium", "detail": "DuckyScript contains potentially malicious STRING payload"})
    if "GUI r" in t.upper() or "WINDOWS r" in t.upper():
        findings.append({"type": "hid_run_dialog", "severity": "info", "detail": "Uses Run dialog (GUI r/WINDOWS r)"})
    return {"ok": True, "lines": len(lines), "keywords": kw, "findings": findings, "suspicious": any(f["severity"] in ("high","medium") for f in findings)}


def analyze_inject_bin(data: bytes) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    if not data:
        return {"ok": False, "error": "empty"}
    # simple heuristics
    if len(data) < 4:
        findings.append({"type": "hid_small_bin", "severity": "info", "detail": "Very small inject.bin"})
    # look for printable strings
    s = data.decode("latin-1", errors="ignore")
    if any(x in s.upper() for x in ["POWERSHELL", "CMD.EXE", "IEX(", "NET USER"]):
        findings.append({"type": "hid_suspicious_bin", "severity": "high", "detail": "inject.bin contains suspicious strings"})
    return {"ok": True, "size": len(data), "findings": findings, "suspicious": any(f["severity"] in ("high","medium") for f in findings)}
