# -*- coding: utf-8 -*-
"""
M.I.R.V. — Browser Automation (F6)
===================================
Playwright-driven navigation/screenshot/DOM extraction with findings
pushed to browser_capture (and audit/SIEM).
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

from backend import audit_log
from backend import browser_capture
from backend import ingest_guard
from backend import siem

logger = logging.getLogger("vulnforge.browser_auto")

PLAYWRIGHT_MCP_URL = os.getenv("PLAYWRIGHT_MCP_URL", "http://localhost:8931")


def _post_json(url: str, payload: Dict[str, Any], timeout: int = 60):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "MIRV-BrowserAuto/1.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def crawl(url: str, actions: Optional[List[Dict[str, Any]]] = None, session_name: str = "playwright-crawl") -> Dict[str, Any]:
    if not url:
        raise ValueError("url required")
    # Guard the URL/inputs via ingest_guard conceptually
    clean, findings_g = ingest_guard.guard(url)
    steps = []
    routes = []
    forms = []
    findings: List[Dict[str, Any]] = []
    # Try to use playwright MCP if available
    try:
        # attempt navigate + snapshot
        res = _post_json(f"{PLAYWRIGHT_MCP_URL}/navigate", {"url": clean}, timeout=60)
        steps.append({"action": "navigate", "url": clean, "ok": True})
        try:
            snap = _post_json(f"{PLAYWRIGHT_MCP_URL}/snapshot", {}, timeout=60)
            html = snap.get("html") or snap.get("content") or ""
            if html:
                # basic route/form extraction
                import re
                for m in re.findall(r'href=["\']([^"\']+)["\']', html):
                    if m.startswith('http') or m.startswith('/'):
                        routes.append(m)
                for m in re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', html):
                    forms.append(m or "#")
                # guard html
                html_clean, fg = ingest_guard.guard(html, add_banner=False)
                if fg:
                    for f in fg:
                        if f.get("severity") in ("high", "medium"):
                            findings.append({"type": "prompt_injection_dom", "severity": f.get("severity"), "detail": f.get("title"), "source": "browser_automation"})
        except Exception as e:
            steps.append({"action": "snapshot", "err": str(e)})
    except Exception as e:
        steps.append({"action": "navigate", "err": str(e), "ok": False})
        # fallback: record as attempted crawl
        findings.append({"type": "browser_crawl_attempt", "severity": "info", "detail": f"playwright-mcp unavailable: {e}", "url": clean})

    # dedupe
    routes = list(dict.fromkeys(routes))
    forms = list(dict.fromkeys(forms))

    try:
        audit_log.log_event("browser.crawl", {"url": clean, "routes": len(routes), "findings": len(findings)})
        siem.ingest_event({"source": "browser", "type": "crawl", "severity": "info", "target": clean, "details": {"routes": len(routes)}})
    except Exception:
        pass

    return {"ok": True, "url": clean, "routes": routes[:200], "forms": forms[:100], "steps": steps, "findings": findings}
