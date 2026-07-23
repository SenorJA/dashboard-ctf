"""
backend/burp_bridge.py — Burp Suite Bridge for MIRV

Provides an in-memory ingest store for HTTP requests captured by the
MIRV Burp plugin (or any compatible sender), endpoint summarization,
task queueing, and bidirectional conversion between MIRV findings and
Burp issues (raw HTTP/1.1 requests).

This module is intentionally dependency-light: it uses only the Python
standard library so it can be imported with no extra installation. All
state lives in module-level dicts guarded by a single lock — this is a
local single-process bridge, not a distributed store.

Design goals
------------
* O(1) ingest — Burp may stream hundreds of requests/minute.
* Bounded memory — _MAX_ENTRIES cap with LRU eviction.
* No secrets in logs — bodies ARE stored (replay is the point) but
  the auth token and Supabase keys are never persisted here.
* Safe raw HTTP reconstruction — `request_to_raw_http` always emits a
  syntactically valid HTTP/1.1 request line + Host header.

Auth
----
An optional shared token can be configured via the ``MIRV_BURP_TOKEN``
env var. When set, every mutating call (and the ingest endpoint) must
present the same token via the ``X-MIRV-Token`` header. Validation uses
``hmac.compare_digest`` (timing-safe). The token is NEVER logged.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit, parse_qsl

# ── Module-level state ──────────────────────────────────────────────
_requests: dict[str, "CapturedRequest"] = {}
_endpoints: dict[str, "EndpointSummary"] = {}  # keyed by "METHOD path"
_tasks: list["BurpTask"] = []
_issues: dict[str, "BurpIssue"] = {}
_snapshots: list[dict] = []  # page cookies/localStorage for auth replay
_lock = threading.RLock()

_MAX_ENTRIES = 5000           # cap for _requests (LRU evict oldest)
_MAX_SNAPSHOTS = 100          # cap for _snapshots
_MAX_BODY = 64 * 1024         # 64KB body cap
_BODY_TRUNC_MARKER = "\n...[truncated by MIRV bridge]"

_logger = logging.getLogger("vulnforge.burp")

# ── Auth token ──────────────────────────────────────────────────────
def _load_token() -> str:
    """Load the bridge auth token from env (never logged)."""
    return os.getenv("MIRV_BURP_TOKEN", "").strip()


def verify_token(provided: Optional[str]) -> bool:
    """Timing-safe token comparison. Empty configured token = open bridge."""
    expected = _load_token()
    if not expected:
        return True  # open bridge mode
    if not provided:
        return False
    return hmac.compare_digest(expected, provided)


# ── Dataclasses ─────────────────────────────────────────────────────
@dataclass
class CapturedRequest:
    id: str
    method: str
    url: str
    path: str
    headers: dict
    body: Optional[str]
    response_status: Optional[int]
    response_headers: Optional[dict]
    response_body: Optional[str]
    source: str
    received_at: str


@dataclass
class EndpointSummary:
    method: str
    path: str
    params: list[str]
    hit_count: int
    last_seen: str


@dataclass
class BurpTask:
    id: str
    request_id: str
    status: str  # pending | scanning | done
    created_at: str


@dataclass
class BurpIssue:
    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    url: str
    method: str
    request_raw: str
    finding_id: Optional[str]
    created_at: str


# ── Helpers ─────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cap_body(body: Optional[str]) -> Optional[str]:
    """Truncate body to _MAX_BODY with a visible marker."""
    if body is None:
        return None
    if len(body) <= _MAX_BODY:
        return body
    return body[:_MAX_BODY] + _BODY_TRUNC_MARKER


def _normalize_headers(headers: Any) -> dict:
    """Accept dict | list[str] | None → dict of name→value (last wins)."""
    if not headers:
        return {}
    out: dict[str, str] = {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            out[str(k)] = str(v)
    elif isinstance(headers, (list, tuple)):
        for line in headers:
            line = str(line)
            if not line or ":" not in line:
                continue
            name, _, value = line.partition(":")
            out[name.strip()] = value.strip()
    return out


def _extract_query_params(url: str) -> list[str]:
    parts = urlsplit(url)
    if not parts.query:
        return []
    return [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]


def _extract_body_params(body: Optional[str], content_type: str = "") -> list[str]:
    """Best-effort body param extraction.

    NOTE: only form-encoded bodies are parsed here. JSON body parameter
    extraction is intentionally skipped (would require schema awareness
    and could leak into false-positive endpoints). Callers needing JSON
    parsing should extend this function explicitly.
    """
    if not body:
        return []
    ct = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ct or ("=" in body and "{" not in body[:50]):
        try:
            return [name for name, _ in parse_qsl(body, keep_blank_values=True)]
        except Exception:
            return []
    return []


def _split_url(url: str) -> str:
    """Return path without query string."""
    return urlsplit(url).path or "/"


# ── Core functions ──────────────────────────────────────────────────
def ingest_request(
    method: str,
    url: str,
    headers: Any = None,
    body: Optional[str] = None,
    response_status: Optional[int] = None,
    response_headers: Any = None,
    response_body: Optional[str] = None,
    source: str = "burp",
) -> dict:
    """Store a captured HTTP request and update endpoint summaries.

    Returns ``{"ok": True, "request": {...}}``.
    """
    method = (method or "GET").upper().strip()
    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "url is required"}

    hdrs = _normalize_headers(headers)
    body = _cap_body(body)
    resp_hdrs = _normalize_headers(response_headers) if response_headers is not None else None
    resp_body = _cap_body(response_body) if response_body is not None else None
    path = _split_url(url)

    req_id = uuid.uuid4().hex
    captured = CapturedRequest(
        id=req_id,
        method=method,
        url=url,
        path=path,
        headers=hdrs,
        body=body,
        response_status=response_status,
        response_headers=resp_hdrs,
        response_body=resp_body,
        source=source or "burp",
        received_at=_now_iso(),
    )

    with _lock:
        # LRU eviction when full
        if len(_requests) >= _MAX_ENTRIES:
            # evict oldest by received_at
            oldest_id = min(_requests.keys(), key=lambda k: _requests[k].received_at)
            _requests.pop(oldest_id, None)
            _logger.debug("evicted oldest request %s (LRU)", oldest_id)

        _requests[req_id] = captured

        # endpoint summary
        ep_key = f"{method} {path}"
        ct = hdrs.get("Content-Type", "") or hdrs.get("content-type", "")
        params = sorted(
            set(_extract_query_params(url))
            | set(_extract_body_params(body, ct))
        )
        if ep_key in _endpoints:
            ep = _endpoints[ep_key]
            # merge params + increment hits
            merged = sorted(set(ep.params) | set(params))
            ep.params = merged
            ep.hit_count += 1
            ep.last_seen = captured.received_at
        else:
            _endpoints[ep_key] = EndpointSummary(
                method=method,
                path=path,
                params=params,
                hit_count=1,
                last_seen=captured.received_at,
            )

    _logger.info("ingested %s %s (id=%s)", method, path, req_id[:8])
    return {"ok": True, "request": asdict(captured)}


def ingest_snapshot(
    page_url: str,
    cookies: Any = None,
    local_storage: Any = None,
    session_storage: Any = None,
) -> dict:
    """Store a browser snapshot (cookies + storage) for later auth replay."""
    snap = {
        "id": uuid.uuid4().hex,
        "page_url": page_url,
        "cookies": cookies or [],
        "local_storage": local_storage or {},
        "session_storage": session_storage or {},
        "received_at": _now_iso(),
    }
    with _lock:
        _snapshots.append(snap)
        if len(_snapshots) > _MAX_SNAPSHOTS:
            del _snapshots[: len(_snapshots) - _MAX_SNAPSHOTS]
    return {"ok": True, "id": snap["id"]}


def list_requests(
    limit: int = 50,
    offset: int = 0,
    method: Optional[str] = None,
    path_filter: Optional[str] = None,
    status: Optional[int] = None,
) -> list[dict]:
    """Return filtered + paginated requests, newest first."""
    with _lock:
        items = list(_requests.values())
    if method:
        items = [r for r in items if r.method == method.upper()]
    if path_filter:
        pf = path_filter.lower()
        items = [r for r in items if pf in r.path.lower()]
    if status is not None:
        items = [r for r in items if r.response_status == status]
    # Sort newest-first; tiebreak by insertion order (dict preserves it)
    # so equal timestamps don't yield non-deterministic output.
    indexed = list(enumerate(items))
    indexed.sort(key=lambda kv: (kv[1].received_at, kv[0]), reverse=True)
    items = [v for _, v in indexed]
    if offset < 0:
        offset = 0
    if limit < 0:
        limit = 0
    return [asdict(r) for r in items[offset: offset + limit]]


def get_request(req_id: str) -> Optional[dict]:
    with _lock:
        r = _requests.get(req_id)
        return asdict(r) if r else None


def list_endpoints(limit: int = 100) -> list[dict]:
    """Endpoint summaries sorted by hit_count desc."""
    with _lock:
        items = list(_endpoints.values())
    items.sort(key=lambda e: e.hit_count, reverse=True)
    if limit < 0:
        limit = 0
    return [asdict(e) for e in items[:limit]]


def queue_task(request_id: str) -> dict:
    """Create a pending BurpTask referencing a captured request."""
    with _lock:
        if request_id not in _requests:
            return {"ok": False, "error": "request_id not found"}
        task = BurpTask(
            id=uuid.uuid4().hex,
            request_id=request_id,
            status="pending",
            created_at=_now_iso(),
        )
        _tasks.append(task)
    return {"ok": True, "task": asdict(task)}


def list_tasks(limit: int = 50) -> list[dict]:
    with _lock:
        items = list(_tasks)
    if limit < 0:
        limit = 0
    return [asdict(t) for t in items[:limit]]


def update_task(task_id: str, status: str) -> dict:
    valid = {"pending", "scanning", "done"}
    if status not in valid:
        return {"ok": False, "error": f"status must be one of {sorted(valid)}"}
    with _lock:
        for t in _tasks:
            if t.id == task_id:
                t.status = status
                return {"ok": True, "task": asdict(t)}
    return {"ok": False, "error": "task not found"}


def add_issue(
    title: str,
    severity: str,
    url: str,
    method: str,
    request_raw: str,
    finding_id: Optional[str] = None,
) -> dict:
    sev = (severity or "info").lower().strip()
    if sev not in {"critical", "high", "medium", "low", "info"}:
        return {"ok": False, "error": "invalid severity"}
    issue = BurpIssue(
        id=uuid.uuid4().hex,
        title=title or "",
        severity=sev,
        url=url or "",
        method=(method or "GET").upper(),
        request_raw=request_raw or "",
        finding_id=finding_id,
        created_at=_now_iso(),
    )
    with _lock:
        _issues[issue.id] = issue
    return {"ok": True, "issue": asdict(issue)}


def list_issues(limit: int = 50) -> list[dict]:
    with _lock:
        items = list(_issues.values())
    indexed = list(enumerate(items))
    indexed.sort(key=lambda kv: (kv[1].created_at, kv[0]), reverse=True)
    items = [v for _, v in indexed]
    if limit < 0:
        limit = 0
    return [asdict(i) for i in items[:limit]]


# ── Conversions ─────────────────────────────────────────────────────
def request_to_raw_http(req: "CapturedRequest") -> str:
    """Build a raw HTTP/1.1 request string from a captured request."""
    parts = urlsplit(req.url)
    host = parts.hostname or req.headers.get("Host") or req.headers.get("host") or ""
    # request line
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    lines = [f"{req.method} {target} HTTP/1.1"]
    # ensure Host header present
    seen_host = False
    for name, value in req.headers.items():
        if name.lower() == "host":
            seen_host = True
        lines.append(f"{name}: {value}")
    if not seen_host and host:
        lines.insert(1, f"Host: {host}")
    raw = "\r\n".join(lines)
    if req.body:
        raw += "\r\n\r\n" + req.body
    else:
        raw += "\r\n\r\n"
    return raw


def _severity_map(sev: str) -> str:
    s = (sev or "info").lower().strip()
    aliases = {"informational": "info", "warning": "medium", "critical": "critical",
               "high": "high", "medium": "medium", "low": "low", "info": "info"}
    return aliases.get(s, "info")


def finding_to_burp_issue(finding: dict) -> dict:
    """Convert a MIRV finding dict to a BurpIssue.

    MIRV findings have: what, severity, target, tool, data (dict). The
    data block may contain ``curl`` (raw command), ``http`` (raw req),
    or ``request_raw``. We try them in order, falling back to a minimal
    raw request built from the target URL.
    """
    if not isinstance(finding, dict):
        return {"ok": False, "error": "finding must be a dict"}

    title = finding.get("what") or finding.get("title") or "MIRV Finding"
    severity = _severity_map(finding.get("severity", "info"))
    target = finding.get("target") or ""
    method = (finding.get("method") or "GET").upper()
    data = finding.get("data") or {}
    raw = ""

    if isinstance(data, dict):
        if data.get("request_raw"):
            raw = str(data["request_raw"])
        elif data.get("http"):
            raw = str(data["http"])
        elif data.get("curl"):
            # parse a minimal raw request out of curl command (best effort)
            raw = _curl_to_raw(str(data["curl"]), target or "")
        elif data.get("request"):
            raw = str(data["request"])

    if not raw and target:
        # build a minimal raw request referencing the target URL
        cap = CapturedRequest(
            id="", method=method, url=target, path=_split_url(target),
            headers={}, body=None, response_status=None,
            response_headers=None, response_body=None,
            source="mirv-finding", received_at=_now_iso(),
        )
        raw = request_to_raw_http(cap)

    issue = BurpIssue(
        id=uuid.uuid4().hex,
        title=title,
        severity=severity,
        url=target,
        method=method,
        request_raw=raw,
        finding_id=finding.get("id"),
        created_at=_now_iso(),
    )
    with _lock:
        _issues[issue.id] = issue
    return {"ok": True, "issue": asdict(issue)}


def _curl_to_raw(curl: str, fallback_url: str = "") -> str:
    """Best-effort parse a curl command into a raw HTTP request."""
    try:
        import shlex
        tokens = shlex.split(curl)
        if not tokens or tokens[0] != "curl":
            return ""
        url = fallback_url
        method = "GET"
        headers: list[str] = []
        body = ""
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("-X", "--request") and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
                continue
            if tok in ("-H", "--header") and i + 1 < len(tokens):
                headers.append(tokens[i + 1])
                i += 2
                continue
            if tok in ("-d", "--data", "--data-raw") and i + 1 < len(tokens):
                body = tokens[i + 1]
                if method == "GET":
                    method = "POST"
                i += 2
                continue
            if tok.startswith("http"):
                url = tok
            i += 1

        if not url:
            return ""
        parts = urlsplit(url)
        host = parts.hostname or ""
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        lines = [f"{method} {target} HTTP/1.1"]
        if host:
            lines.append(f"Host: {host}")
        for h in headers:
            lines.append(h)
        raw = "\r\n".join(lines)
        if body:
            raw += "\r\n\r\n" + body
        else:
            raw += "\r\n\r\n"
        return raw
    except Exception as e:
        _logger.debug("curl_to_raw failed: %s", e)
        return ""


def export_findings_as_burp(findings: list[dict]) -> dict:
    """Batch convert MIRV findings → BurpIssue dicts."""
    if not isinstance(findings, list):
        return {"ok": False, "error": "findings must be a list"}
    issues = []
    for f in findings:
        res = finding_to_burp_issue(f)
        if res.get("ok"):
            issues.append(res["issue"])
    return {"ok": True, "issues": issues}


def report_to_mirv_findings(req: "CapturedRequest") -> list[dict]:
    """Convert a captured request into MIRV finding format (severity info)."""
    finding = {
        "id": req.id,
        "what": "captured-request",
        "severity": "info",
        "target": req.url,
        "tool": req.source,
        "data": {
            "method": req.method,
            "path": req.path,
            "headers": req.headers,
            "body": req.body,
            "response_status": req.response_status,
            "response_headers": req.response_headers,
            "response_body": req.response_body,
            "received_at": req.received_at,
        },
    }
    return [finding]


def clear_all() -> dict:
    """Empty every in-memory store."""
    with _lock:
        _requests.clear()
        _endpoints.clear()
        _tasks.clear()
        _issues.clear()
        _snapshots.clear()
    _logger.info("all bridge stores cleared")
    return {"ok": True}


def status() -> dict:
    """Return counts for each store."""
    with _lock:
        return {
            "ok": True,
            "requests": len(_requests),
            "endpoints": len(_endpoints),
            "tasks": len(_tasks),
            "issues": len(_issues),
            "snapshots": len(_snapshots),
            "max_entries": _MAX_ENTRIES,
            "token_required": bool(_load_token()),
        }