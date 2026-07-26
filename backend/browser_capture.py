"""
browser_capture.py -- MIRV Module

Browser HTTP traffic capture and security analysis engine.

Parses HAR 1.2 archives exported from browser DevTools or proxy tools,
stores captured requests in memory, and runs a battery of 10 security
check categories against each session.  Results are converted into
MIRV-compatible findings for integration into the findings dashboard.

Design goals
------------
* Zero external dependencies -- stdlib only (json, re, uuid, threading, etc.)
* Thread-safe in-memory store with bounded limits.
* Har parsing is lenient: missing fields default gracefully.
* All analysis is synchronous (CPU-bound, no I/O).
* Risk score formula: critical=25, high=10, medium=5, low=1, info=0, capped at 100.

Security checks shipped out-of-the-box
--------------------------------------
A. Cookie flags (heuristic on HAR)
B. Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
C. Mixed content (active / passive)
D. Sensitive data in URLs
E. Insecure redirects
F. Missing auth on API endpoints
G. CORS misconfigurations
H. Information leakage (X-Powered-By, Server version)
I. Large responses
J. Insecure WebSocket (ws://)

All functions are synchronous and thread-safe (module-level lock).
"""

from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

# ── Logger ──
logger = logging.getLogger("vulnforge.browser_capture")


# ════════════════════════════════════════════════════════════════
#  Constants
# ════════════════════════════════════════════════════════════════

_MAX_SESSIONS = 100
_MAX_REQUESTS_PER_SESSION = 50000
_MAX_BODY = 128 * 1024  # 128 KB
_BODY_TRUNC_MARKER = "\n...[truncated by MIRV browser capture]"

_SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 5, "low": 1, "info": 0}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SESSION_LIKE_COOKIES = re.compile(
    r"(?:session|token|auth|jwt|sid|jsessionid|phpsessid|asp\.net_sessionid|connect\.sid)",
    re.IGNORECASE,
)

_SENSITIVE_PARAM_NAME_RE = re.compile(
    r"(?:token|api[_-]?key|secret|password|jwt|bearer|access[_-]?token|auth[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)

_JWT_VALUE_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

_AWS_KEY_RE = re.compile(r"^AKIA[0-9A-Z]{16}")

_HIGH_ENTROPY_RE = re.compile(r"^[A-Za-z0-9+/=_-]{32,}$")

_VERSIONED_SERVER_RE = re.compile(
    r"(?:Apache|Nginx|IIS|LiteSpeed|OpenResty|Cloudflare|Caddy|Gunicorn|uWSGI|Tomcat)/[\d.]+",
    re.IGNORECASE,
)

_HTML_CONTENT_TYPES = re.compile(r"text/html|application/xhtml", re.IGNORECASE)


# ════════════════════════════════════════════════════════════════
#  Data classes
# ════════════════════════════════════════════════════════════════

@dataclass
class CapturedRequest:
    """A single HTTP request/response pair extracted from a HAR entry."""
    id: str
    session_id: str
    method: str
    url: str
    headers: dict
    body: Optional[str]
    response_status: Optional[int]
    response_headers: Optional[dict]
    response_body: Optional[str]
    timing: Optional[dict]
    cookies: list
    query_params: list
    ip: Optional[str]
    protocol: Optional[str]
    mime_type: Optional[str]
    redirect_url: Optional[str]
    captured_at: str


@dataclass
class BrowserSession:
    """A browser capture session containing imported HAR data."""
    id: str
    name: str
    target: str
    created_at: str
    request_count: int
    har_version: Optional[str]
    har_creator: Optional[dict]
    analysis: Optional[dict]  # CaptureAnalysis as dict or None
    tags: list


@dataclass
class CaptureAnalysis:
    """Aggregated security analysis for a browser capture session."""
    session_id: str
    analyzed_at: str
    total_requests: int
    findings_count: dict   # {critical, high, medium, low, info}
    security_issues: list
    cookies_analysis: dict
    headers_analysis: dict
    mixed_content: list
    sensitive_in_urls: list
    insecure_redirects: list
    missing_auth: list
    cors_issues: list
    info_leakage: list
    large_responses: list
    websocket_issues: list
    risk_score: float
    recommendations: list


# ════════════════════════════════════════════════════════════════
#  In-memory storage
# ════════════════════════════════════════════════════════════════

_sessions: dict[str, BrowserSession] = {}
_requests: dict[str, list[CapturedRequest]] = {}
_analyses: dict[str, CaptureAnalysis] = {}
_lock = threading.Lock()


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

def _now_iso() -> str:
    """Current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _normalize_har_headers(har_headers: list) -> dict:
    """
    Convert HAR header list ``[{"name": "X", "value": "Y"}, ...]``
    into a flat dict ``{"X": "Y"}``.  Last value wins on duplicate names.
    """
    if not har_headers or not isinstance(har_headers, list):
        return {}
    out: dict[str, str] = {}
    for entry in har_headers:
        if isinstance(entry, dict):
            name = entry.get("name", "")
            value = entry.get("value", "")
            if name:
                out[name] = str(value)
    return out


def _extract_domain(url: str) -> str:
    """Return the hostname from a URL string, or empty string on failure."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def _is_html_content_type(ct: str) -> bool:
    """Return True if the content-type header indicates HTML."""
    if not ct:
        return False
    return bool(_HTML_CONTENT_TYPES.search(ct))


def _detect_sensitive_param_name(name: str) -> bool:
    """Return True if the parameter name looks like a secret."""
    return bool(_SENSITIVE_PARAM_NAME_RE.search(name))


def _detect_sensitive_param_value(value: str) -> bool:
    """
    Return True if the value looks like a JWT, AWS key,
    or other high-entropy sensitive string.
    """
    if not value or len(value) < 8:
        return False
    if _JWT_VALUE_RE.match(value):
        return True
    if _AWS_KEY_RE.match(value):
        return True
    if _HIGH_ENTROPY_RE.match(value) and len(value) >= 40:
        return True
    return False


def _severity_rank(sev: str) -> int:
    """Return numeric rank for severity sorting (lower = more severe)."""
    return _SEVERITY_RANK.get(sev, 99)


def _cap_body(body: Optional[str]) -> Optional[str]:
    """Truncate body to _MAX_BODY with a visible marker."""
    if body is None:
        return None
    if len(body) <= _MAX_BODY:
        return body
    return body[:_MAX_BODY] + _BODY_TRUNC_MARKER


# ════════════════════════════════════════════════════════════════
#  Core: HAR parsing
# ════════════════════════════════════════════════════════════════

def parse_har(har_json: dict, session_id: str = "") -> list[CapturedRequest]:
    """
    Parse a HAR 1.2 JSON dict into a list of CapturedRequest objects.

    For each entry in ``har_json["log"]["entries"]``:
    - Normalizes headers from HAR ``[{"name":"X","value":"Y"}]`` to ``{"X":"Y"}``
    - Extracts method, url, headers, body, response fields, timing, cookies,
      query_params, ip, protocol, mime_type, redirect_url, captured_at
    - Truncates response_body to ``_MAX_BODY``
    - Skips entries with missing 'request' or 'response'

    Args:
        har_json: Parsed HAR JSON dict.
        session_id: Associated session ID to tag each request.

    Returns:
        List of CapturedRequest objects.
    """
    log = har_json.get("log", har_json)  # tolerate missing "log" wrapper
    entries = log.get("entries", [])
    if not isinstance(entries, list):
        return []

    requests: list[CapturedRequest] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        req = entry.get("request")
        resp = entry.get("response")

        # Skip entries with missing request or response
        if not req or not isinstance(req, dict):
            continue
        if not resp or not isinstance(resp, dict):
            continue

        method = (req.get("method") or "GET").upper().strip()
        url = req.get("url", "")
        headers = _normalize_har_headers(req.get("headers", []))
        body = req.get("postData", {})
        body_text = body.get("text") if isinstance(body, dict) else None

        # Cookies from request
        raw_cookies = req.get("cookies", [])
        cookies = []
        if isinstance(raw_cookies, list):
            for c in raw_cookies:
                if isinstance(c, dict):
                    cookies.append({"name": c.get("name", ""), "value": c.get("value", "")})

        # Query params
        raw_params = req.get("queryString", [])
        query_params = []
        if isinstance(raw_params, list):
            for p in raw_params:
                if isinstance(p, dict):
                    query_params.append({"name": p.get("name", ""), "value": p.get("value", "")})

        # IP and protocol from request
        ip = req.get("clientIPAddress") or req.get("ip") or None
        protocol = req.get("httpVersion") or None

        # Response
        resp_status = resp.get("status")
        resp_headers = _normalize_har_headers(resp.get("headers", []))

        # Response body content
        resp_content = resp.get("content", {})
        resp_body = None
        if isinstance(resp_content, dict):
            resp_body = resp_content.get("text")
            if resp_body is not None:
                resp_body = str(resp_body)

        resp_body = _cap_body(resp_body)

        # MIME type from response content
        mime_type = None
        if isinstance(resp_content, dict):
            mime_type = resp_content.get("mimeType")

        # Redirect URL
        redirect_url = None
        for hdr_name in ("Location", "location"):
            if hdr_name in resp_headers:
                redirect_url = resp_headers[hdr_name]
                break

        # Timing
        timing = entry.get("time")
        timing_dict = None
        if timing is not None:
            timing_dict = {"total": timing}
        # Also capture detailed timing if present
        detailed_time = entry.get("timings", entry.get(" timings", None))
        if isinstance(detailed_time, dict):
            timing_dict = detailed_time

        # Captured-at timestamp
        started = entry.get("startedDateTime", "")

        captured = CapturedRequest(
            id=str(uuid.uuid4()),
            session_id=session_id,
            method=method,
            url=url,
            headers=headers,
            body=body_text,
            response_status=resp_status if isinstance(resp_status, int) else None,
            response_headers=resp_headers if resp_headers else None,
            response_body=resp_body,
            timing=timing_dict,
            cookies=cookies,
            query_params=query_params,
            ip=ip,
            protocol=protocol,
            mime_type=mime_type,
            redirect_url=redirect_url,
            captured_at=started or _now_iso(),
        )
        requests.append(captured)

    return requests


# ════════════════════════════════════════════════════════════════
#  Core: Import HAR
# ════════════════════════════════════════════════════════════════

def import_har(file_bytes: bytes, filename: str) -> dict:
    """
    Import a HAR file and create a new browser capture session.

    Steps:
    1. Decode bytes (UTF-8, latin-1 fallback)
    2. JSON parse and validate ``log.version`` starts with ``1.``
    3. Parse entries via ``parse_har()``
    4. Extract target: most frequent domain from URLs
    5. Create session + store requests under lock
    6. Enforce ``_MAX_SESSIONS`` limit (evict oldest)

    Args:
        file_bytes: Raw file content.
        filename: Original filename for naming.

    Returns:
        ``{"ok": True, "session": {...}}`` on success, ``{"ok": False, "error": "..."}`` on failure.
    """
    # 1. Decode
    try:
        text = file_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        try:
            text = file_bytes.decode("latin-1")
        except Exception as e:
            return {"ok": False, "error": f"Failed to decode file: {e}"}

    # 2. Parse JSON
    try:
        har_json = json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        return {"ok": False, "error": f"Invalid JSON: {e}"}

    log = har_json.get("log", har_json)
    version = log.get("version", "")
    if not isinstance(version, str) or not version.startswith("1."):
        return {"ok": False, "error": f"Unsupported HAR version: {version!r} (expected 1.x)"}

    har_creator = log.get("creator", {})

    # 3. Parse entries
    session_id = uuid.uuid4().hex
    entries = parse_har(har_json, session_id=session_id)

    # 4. Extract target (most frequent domain)
    domain_counts: dict[str, int] = {}
    for req in entries:
        domain = _extract_domain(req.url)
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    if domain_counts:
        target = max(domain_counts, key=domain_counts.get)
    else:
        target = "unknown"

    # 5. Session name from filename
    name = filename
    if "." in name:
        name = name.rsplit(".", 1)[0]

    now = _now_iso()
    session = BrowserSession(
        id=session_id,
        name=name,
        target=target,
        created_at=now,
        request_count=len(entries),
        har_version=version,
        har_creator=har_creator if isinstance(har_creator, dict) else None,
        analysis=None,
        tags=[],
    )

    # 6. Store
    with _lock:
        # Enforce session limit
        if len(_sessions) >= _MAX_SESSIONS:
            oldest_id = min(_sessions.keys(), key=lambda k: _sessions[k].created_at)
            _sessions.pop(oldest_id, None)
            _requests.pop(oldest_id, None)
            _analyses.pop(oldest_id, None)
            logger.debug("Evicted oldest session %s (limit reached)", oldest_id)

        _sessions[session_id] = session
        _requests[session_id] = entries

    logger.info(
        "HAR imported: session=%s name=%s target=%s requests=%d",
        session_id[:8], name, target, len(entries),
    )

    return {"ok": True, "session": asdict(session)}


# ════════════════════════════════════════════════════════════════
#  Security analysis helpers
# ════════════════════════════════════════════════════════════════

def _check_cookie_flags(req: CapturedRequest) -> list[dict]:
    """Check A: Cookie flags (heuristic — HAR doesn't expose HttpOnly/Secure)."""
    issues: list[dict] = []
    if not req.cookies:
        return issues

    is_http = req.url.lower().startswith("http://")

    for cookie in req.cookies:
        name = cookie.get("name", "")
        if not name:
            continue

        # Check if session-like cookie is sent over plain HTTP
        if _SESSION_LIKE_COOKIES.search(name) and is_http:
            issues.append({
                "check_id": "cookie-missing-httponly",
                "severity": "medium",
                "category": "cookie_flags",
                "title": "Session cookie may lack HttpOnly flag",
                "detail": f"Cookie '{name}' is session-like and sent over plain HTTP. "
                          "It likely lacks HttpOnly and/or Secure flags.",
                "url": req.url,
                "evidence": f"Cookie: {name}=***",
                "recommendation": "Set HttpOnly and Secure flags on session cookies. "
                                  "Use HTTPS exclusively.",
            })

        # Check if any cookie is sent over HTTP (missing Secure)
        if is_http:
            issues.append({
                "check_id": "cookie-missing-secure",
                "severity": "medium",
                "category": "cookie_flags",
                "title": "Cookie sent over insecure HTTP",
                "detail": f"Cookie '{name}' is transmitted over plain HTTP without the Secure flag.",
                "url": req.url,
                "evidence": f"Cookie: {name}=***",
                "recommendation": "Use HTTPS and set the Secure flag on all cookies.",
            })

    return issues


def _check_security_headers(req: CapturedRequest) -> list[dict]:
    """Check B: Security headers on HTML responses."""
    issues: list[dict] = []
    if not req.response_headers:
        return issues

    # Only check HTML responses
    ct = req.response_headers.get("Content-Type", "") or req.response_headers.get("content-type", "")
    if not _is_html_content_type(ct):
        return issues

    hdr_keys_lower = {k.lower(): k for k in req.response_headers.keys()}

    # CSP
    if "content-security-policy" not in hdr_keys_lower:
        issues.append({
            "check_id": "header-missing-csp",
            "severity": "high",
            "category": "security_headers",
            "title": "Missing Content-Security-Policy header",
            "detail": "The HTML response does not include a Content-Security-Policy header.",
            "url": req.url,
            "evidence": f"Content-Type: {ct}",
            "recommendation": "Implement a strict Content-Security-Policy to prevent XSS and data injection.",
        })

    # HSTS (only for HTTPS)
    is_https = req.url.lower().startswith("https://")
    if is_https and "strict-transport-security" not in hdr_keys_lower:
        issues.append({
            "check_id": "header-missing-hsts",
            "severity": "high",
            "category": "security_headers",
            "title": "Missing Strict-Transport-Security header",
            "detail": "HTTPS response does not include HSTS header.",
            "url": req.url,
            "evidence": f"Content-Type: {ct}",
            "recommendation": "Add Strict-Transport-Security header with a long max-age.",
        })

    # X-Frame-Options
    if "x-frame-options" not in hdr_keys_lower:
        issues.append({
            "check_id": "header-missing-xfo",
            "severity": "medium",
            "category": "security_headers",
            "title": "Missing X-Frame-Options header",
            "detail": "The HTML response does not include X-Frame-Options header.",
            "url": req.url,
            "evidence": f"Content-Type: {ct}",
            "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
        })

    # X-Content-Type-Options
    if "x-content-type-options" not in hdr_keys_lower:
        issues.append({
            "check_id": "header-missing-xcto",
            "severity": "low",
            "category": "security_headers",
            "title": "Missing X-Content-Type-Options header",
            "detail": "The response does not include X-Content-Type-Options header.",
            "url": req.url,
            "evidence": f"Content-Type: {ct}",
            "recommendation": "Set X-Content-Type-Options to 'nosniff'.",
        })

    return issues


def _check_mixed_content(req: CapturedRequest) -> list[dict]:
    """Check C: Mixed content (HTTPS page loading HTTP resources)."""
    issues: list[dict] = []

    if not req.url.lower().startswith("https://"):
        return issues

    # Check if the response loads external resources over HTTP
    if not req.response_body:
        return issues

    # Active mixed content: scripts, iframes
    http_script_re = re.compile(r'<(?:script|iframe|object|embed)[^>]*\ssrc\s*=\s*["\']http://', re.IGNORECASE)
    if http_script_re.search(req.response_body):
        issues.append({
            "check_id": "mixed-content-active",
            "severity": "high",
            "category": "mixed_content",
            "title": "Active mixed content detected",
            "detail": "HTTPS page loads scripts or iframes over plain HTTP.",
            "url": req.url,
            "evidence": "Script/iframe src with http:// in HTTPS page",
            "recommendation": "Load all active resources over HTTPS. "
                              "Use protocol-relative URLs or // prefix.",
        })

    # Passive mixed content: images, css, fonts
    http_passive_re = re.compile(
        r'<(?:img|link)[^>]*\s(?:src|href)\s*=\s*["\']http://', re.IGNORECASE
    )
    if http_passive_re.search(req.response_body):
        issues.append({
            "check_id": "mixed-content-passive",
            "severity": "medium",
            "category": "mixed_content",
            "title": "Passive mixed content detected",
            "detail": "HTTPS page loads images, CSS, or fonts over plain HTTP.",
            "url": req.url,
            "evidence": "Image/link src with http:// in HTTPS page",
            "recommendation": "Load all passive resources over HTTPS.",
        })

    return issues


def _check_sensitive_in_urls(req: CapturedRequest) -> list[dict]:
    """Check D: Sensitive data in URLs."""
    issues: list[dict] = []

    for param in req.query_params:
        name = param.get("name", "")
        value = param.get("value", "")

        if _detect_sensitive_param_name(name):
            issues.append({
                "check_id": "sensitive-token-in-url",
                "severity": "high",
                "category": "sensitive_urls",
                "title": "Sensitive parameter name in URL",
                "detail": f"Parameter '{name}' appears to contain a secret/token.",
                "url": req.url,
                "evidence": f"Query param: {name}=***",
                "recommendation": "Never pass secrets in URL query parameters. "
                                  "Use Authorization headers or POST body instead.",
            })
        elif _detect_sensitive_param_value(value):
            issues.append({
                "check_id": "sensitive-value-in-url",
                "severity": "medium",
                "category": "sensitive_urls",
                "title": "Sensitive value detected in URL",
                "detail": f"Parameter '{name}' contains a value that looks like a JWT, "
                          "AWS key, or high-entropy token.",
                "url": req.url,
                "evidence": f"Query param: {name}=***",
                "recommendation": "Avoid exposing secrets in URLs. "
                                  "Use request headers or encrypted body instead.",
            })

    return issues


def _check_insecure_redirects(req: CapturedRequest) -> list[dict]:
    """Check E: Insecure redirects (3xx to HTTP)."""
    issues: list[dict] = []

    if not req.response_status:
        return issues

    if req.response_status < 300 or req.response_status >= 400:
        return issues

    if not req.redirect_url:
        return issues

    redirect_lower = req.redirect_url.lower()

    if redirect_lower.startswith("http://"):
        issues.append({
            "check_id": "insecure-redirect-http",
            "severity": "high",
            "category": "insecure_redirects",
            "title": "Redirect to insecure HTTP",
            "detail": f"HTTP {req.response_status} redirect to {req.redirect_url}",
            "url": req.url,
            "evidence": f"Location: {req.redirect_url}",
            "recommendation": "Redirect to HTTPS URLs only. "
                              "Implement HSTS to prevent downgrade attacks.",
        })

        # Also flag HTTPS → HTTP downgrade
        if req.url.lower().startswith("https://"):
            issues.append({
                "check_id": "insecure-redirect-downgrade",
                "severity": "high",
                "category": "insecure_redirects",
                "title": "HTTPS to HTTP downgrade redirect",
                "detail": f"HTTPS page redirects to plain HTTP: {req.redirect_url}",
                "url": req.url,
                "evidence": f"Location: {req.redirect_url}",
                "recommendation": "Never redirect from HTTPS to HTTP. "
                                  "Maintain encryption throughout the redirect chain.",
            })

    return issues


def _check_missing_auth(req: CapturedRequest) -> list[dict]:
    """Check F: Missing auth on API endpoints."""
    issues: list[dict] = []

    path = urlparse(req.url).path.lower() if req.url else ""

    api_prefixes = ("/api/", "/admin/", "/v1/", "/v2/", "/graphql", "/rest/")
    if not any(path.startswith(p) for p in api_prefixes):
        return issues

    hdr_keys_lower = {k.lower() for k in req.headers.keys()}
    has_auth = "authorization" in hdr_keys_lower
    has_cookie = "cookie" in hdr_keys_lower

    if not has_auth and not has_cookie:
        issues.append({
            "check_id": "missing-auth-api-endpoint",
            "severity": "medium",
            "category": "missing_auth",
            "title": "API endpoint accessed without authentication",
            "detail": f"Request to {path} has no Authorization or Cookie header.",
            "url": req.url,
            "evidence": "No Authorization or Cookie header present",
            "recommendation": "Ensure all API endpoints require authentication. "
                              "Use Bearer tokens, API keys, or session cookies.",
        })

    return issues


def _check_cors(req: CapturedRequest) -> list[dict]:
    """Check G: CORS misconfigurations."""
    issues: list[dict] = []
    if not req.response_headers:
        return issues

    acao = None
    acac = None
    for k, v in req.response_headers.items():
        kl = k.lower()
        if kl == "access-control-allow-origin":
            acao = v
        elif kl == "access-control-allow-credentials":
            acac = v

    if acao is None:
        return issues

    has_credentials = acac and acac.lower() == "true"

    if acao == "*" and has_credentials:
        issues.append({
            "check_id": "cors-wildcard-credentials",
            "severity": "high",
            "category": "cors",
            "title": "CORS wildcard with credentials",
            "detail": "Access-Control-Allow-Origin is '*' with Allow-Credentials: true. "
                      "This is a dangerous misconfiguration.",
            "url": req.url,
            "evidence": f"ACAO: {acao}, ACAC: {acac}",
            "recommendation": "Never use wildcard origin with credentials. "
                              "Whitelist specific trusted origins.",
        })
    elif acao == "*":
        issues.append({
            "check_id": "cors-wildcard",
            "severity": "low",
            "category": "cors",
            "title": "CORS wildcard origin",
            "detail": "Access-Control-Allow-Origin is '*'. Any site can read the response.",
            "url": req.url,
            "evidence": f"ACAO: {acao}",
            "recommendation": "Restrict CORS to specific trusted origins.",
        })

    # Reflected origin check
    req_origin = None
    for k, v in req.headers.items():
        if k.lower() == "origin":
            req_origin = v
            break

    if req_origin and acao == req_origin and has_credentials:
        issues.append({
            "check_id": "cors-reflected-origin",
            "severity": "medium",
            "category": "cors",
            "title": "CORS reflects request origin with credentials",
            "detail": "Access-Control-Allow-Origin mirrors the request Origin header "
                      "with Allow-Credentials: true. May indicate overly permissive CORS.",
            "url": req.url,
            "evidence": f"Origin: {req_origin}, ACAO: {acao}",
            "recommendation": "Validate the reflected origin against an allowlist. "
                              "Do not blindly mirror the Origin header.",
        })

    return issues


def _check_info_leakage(req: CapturedRequest) -> list[dict]:
    """Check H: Information leakage headers."""
    issues: list[dict] = []
    if not req.response_headers:
        return issues

    for k, v in req.response_headers.items():
        if k.lower() == "x-powered-by" and v:
            issues.append({
                "check_id": "info-leakage-x-powered-by",
                "severity": "low",
                "category": "info_leakage",
                "title": "X-Powered-By header reveals technology",
                "detail": f"The X-Powered-By header is present: {v}",
                "url": req.url,
                "evidence": f"X-Powered-By: {v}",
                "recommendation": "Remove the X-Powered-By header to avoid leaking "
                                  "technology stack information.",
            })

        if k.lower() == "server" and v:
            if _VERSIONED_SERVER_RE.search(v):
                issues.append({
                    "check_id": "info-leakage-server-version",
                    "severity": "low",
                    "category": "info_leakage",
                    "title": "Server header reveals version",
                    "detail": f"The Server header exposes version information: {v}",
                    "url": req.url,
                    "evidence": f"Server: {v}",
                    "recommendation": "Remove or obfuscate the Server header version "
                                      "to hinder fingerprinting.",
                })

    return issues


def _check_large_responses(req: CapturedRequest) -> list[dict]:
    """Check I: Large responses."""
    issues: list[dict] = []

    if not req.response_headers:
        return issues

    # Try to get content length from header
    content_length = 0
    for k, v in req.response_headers.items():
        if k.lower() == "content-length":
            try:
                content_length = int(v)
            except (ValueError, TypeError):
                pass
            break

    # Also check actual body length
    body_len = len(req.response_body) if req.response_body else 0
    resp_size = max(content_length, body_len)

    if resp_size > 1024 * 1024:  # > 1MB
        is_json = False
        ct = ""
        for k, v in req.response_headers.items():
            if k.lower() == "content-type":
                ct = v
                break
        if "json" in ct.lower():
            is_json = True

        if is_json:
            issues.append({
                "check_id": "large-response-json",
                "severity": "medium",
                "category": "large_responses",
                "title": "Large JSON response",
                "detail": f"JSON response is {resp_size:,} bytes (>1MB). "
                          "May indicate data over-exposure.",
                "url": req.url,
                "evidence": f"Content-Type: {ct}, Size: {resp_size:,} bytes",
                "recommendation": "Implement pagination or field selection to reduce "
                                  "response sizes. Large JSON responses may leak bulk data.",
            })
        else:
            issues.append({
                "check_id": "large-response",
                "severity": "info",
                "category": "large_responses",
                "title": "Large response",
                "detail": f"Response is {resp_size:,} bytes (>1MB).",
                "url": req.url,
                "evidence": f"Size: {resp_size:,} bytes",
                "recommendation": "Consider compressing or paginating large responses.",
            })

    return issues


def _check_websocket(req: CapturedRequest) -> list[dict]:
    """Check J: Insecure WebSocket (ws://)."""
    issues: list[dict] = []

    url_lower = req.url.lower()
    if url_lower.startswith("ws://"):
        issues.append({
            "check_id": "websocket-insecure",
            "severity": "medium",
            "category": "websocket",
            "title": "Insecure WebSocket connection",
            "detail": "The request uses ws:// instead of wss://. "
                      "Data is transmitted in cleartext.",
            "url": req.url,
            "evidence": f"URL scheme: ws://",
            "recommendation": "Use wss:// (WebSocket Secure) for all WebSocket connections.",
        })

    return issues


# ════════════════════════════════════════════════════════════════
#  Core: Analyze single request
# ════════════════════════════════════════════════════════════════

def analyze_request(req: CapturedRequest) -> list[dict]:
    """
    Run all 10 security check categories on a single captured request.

    Args:
        req: The CapturedRequest to analyze.

    Returns:
        List of issue dicts, each with: check_id, severity, category,
        title, detail, url, evidence, recommendation.
    """
    issues: list[dict] = []

    issues.extend(_check_cookie_flags(req))
    issues.extend(_check_security_headers(req))
    issues.extend(_check_mixed_content(req))
    issues.extend(_check_sensitive_in_urls(req))
    issues.extend(_check_insecure_redirects(req))
    issues.extend(_check_missing_auth(req))
    issues.extend(_check_cors(req))
    issues.extend(_check_info_leakage(req))
    issues.extend(_check_large_responses(req))
    issues.extend(_check_websocket(req))

    return issues


# ════════════════════════════════════════════════════════════════
#  Core: Analyze session
# ════════════════════════════════════════════════════════════════

def analyze_session(session_id: str) -> Optional[CaptureAnalysis]:
    """
    Run security analysis on all requests in a session.

    1. Retrieve session + requests from the store.
    2. Run ``analyze_request()`` on each.
    3. Aggregate findings into a ``CaptureAnalysis``.
    4. Compute risk score: critical=25, high=10, medium=5, low=1, info=0, min(score, 100).
    5. Generate top 5 recommendations.
    6. Store and return the analysis.

    Args:
        session_id: The session to analyze.

    Returns:
        CaptureAnalysis object or None if session not found.
    """
    with _lock:
        session = _sessions.get(session_id)
        reqs = _requests.get(session_id, [])

    if session is None:
        return None

    all_issues: list[dict] = []
    cookies_analysis: dict[str, Any] = {"total_cookies": 0, "session_cookies": 0, "http_cookies": 0}
    headers_analysis: dict[str, Any] = {"pages_checked": 0, "missing_csp": 0, "missing_hsts": 0}
    mixed_content_list: list[dict] = []
    sensitive_in_urls_list: list[dict] = []
    insecure_redirects_list: list[dict] = []
    missing_auth_list: list[dict] = []
    cors_issues_list: list[dict] = []
    info_leakage_list: list[dict] = []
    large_responses_list: list[dict] = []
    websocket_issues_list: list[dict] = []

    for req in reqs:
        issues = analyze_request(req)
        all_issues.extend(issues)

        # Aggregate into category buckets
        for issue in issues:
            cat = issue.get("category", "")
            if cat == "mixed_content":
                mixed_content_list.append(issue)
            elif cat == "sensitive_urls":
                sensitive_in_urls_list.append(issue)
            elif cat == "insecure_redirects":
                insecure_redirects_list.append(issue)
            elif cat == "missing_auth":
                missing_auth_list.append(issue)
            elif cat == "cors":
                cors_issues_list.append(issue)
            elif cat == "info_leakage":
                info_leakage_list.append(issue)
            elif cat == "large_responses":
                large_responses_list.append(issue)
            elif cat == "websocket":
                websocket_issues_list.append(issue)

        # Cookies stats
        cookies_analysis["total_cookies"] += len(req.cookies)
        for c in req.cookies:
            name = c.get("name", "")
            if _SESSION_LIKE_COOKIES.search(name):
                cookies_analysis["session_cookies"] += 1
            if req.url.lower().startswith("http://"):
                cookies_analysis["http_cookies"] += 1

        # Headers stats
        ct = ""
        if req.response_headers:
            for k, v in req.response_headers.items():
                if k.lower() == "content-type":
                    ct = v
                    break
        if _is_html_content_type(ct):
            headers_analysis["pages_checked"] += 1
            hdr_keys = {k.lower() for k in (req.response_headers or {}).keys()}
            if "content-security-policy" not in hdr_keys:
                headers_analysis["missing_csp"] += 1
            if req.url.lower().startswith("https://") and "strict-transport-security" not in hdr_keys:
                headers_analysis["missing_hsts"] += 1

    # Count severities
    findings_count: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in all_issues:
        sev = issue.get("severity", "info")
        if sev in findings_count:
            findings_count[sev] += 1

    # Risk score
    risk_score = 0.0
    for sev, count in findings_count.items():
        risk_score += _SEVERITY_WEIGHTS.get(sev, 0) * count
    risk_score = min(risk_score, 100.0)

    # Top 5 recommendations
    recommendations = _generate_recommendations(all_issues)

    analysis = CaptureAnalysis(
        session_id=session_id,
        analyzed_at=_now_iso(),
        total_requests=len(reqs),
        findings_count=findings_count,
        security_issues=all_issues,
        cookies_analysis=cookies_analysis,
        headers_analysis=headers_analysis,
        mixed_content=mixed_content_list,
        sensitive_in_urls=sensitive_in_urls_list,
        insecure_redirects=insecure_redirects_list,
        missing_auth=missing_auth_list,
        cors_issues=cors_issues_list,
        info_leakage=info_leakage_list,
        large_responses=large_responses_list,
        websocket_issues=websocket_issues_list,
        risk_score=risk_score,
        recommendations=recommendations,
    )

    with _lock:
        _analyses[session_id] = analysis
        # Update session analysis field
        if session_id in _sessions:
            _sessions[session_id].analysis = asdict(analysis)

    logger.info(
        "Session analysis complete: session=%s issues=%d risk=%.1f",
        session_id[:8], len(all_issues), risk_score,
    )

    return analysis


def _generate_recommendations(issues: list[dict]) -> list[str]:
    """Generate top 5 recommendations based on the most impactful findings."""
    if not issues:
        return ["No security issues detected. Continue monitoring."]

    # Priority-based recommendation mapping
    rec_map: dict[str, tuple[int, str]] = {
        "header-missing-csp": (10, "Implement Content-Security-Policy headers on all HTML pages."),
        "header-missing-hsts": (9, "Add Strict-Transport-Security header with a minimum 1-year max-age."),
        "cors-wildcard-credentials": (9, "Fix CORS: replace wildcard origin with explicit allowlist."),
        "insecure-redirect-http": (8, "Use HTTPS for all redirects. Implement HSTS."),
        "insecure-redirect-downgrade": (8, "Eliminate HTTPS to HTTP redirects immediately."),
        "mixed-content-active": (7, "Load all scripts and iframes over HTTPS."),
        "sensitive-token-in-url": (7, "Move tokens from URL parameters to Authorization headers."),
        "cookie-missing-httponly": (6, "Set HttpOnly and Secure flags on session cookies."),
        "cookie-missing-secure": (6, "Use HTTPS exclusively and set the Secure flag on cookies."),
        "mixed-content-passive": (5, "Load all images, CSS, and fonts over HTTPS."),
        "sensitive-value-in-url": (5, "Remove sensitive values from URLs."),
        "missing-auth-api-endpoint": (4, "Enforce authentication on all API endpoints."),
        "cors-reflected-origin": (4, "Validate CORS origins against an allowlist."),
        "large-response-json": (3, "Implement pagination for large JSON responses."),
        "header-missing-xfo": (3, "Add X-Frame-Options to prevent clickjacking."),
        "websocket-insecure": (3, "Use wss:// for all WebSocket connections."),
        "info-leakage-x-powered-by": (2, "Remove X-Powered-By header."),
        "info-leakage-server-version": (2, "Obfuscate or remove server version header."),
        "header-missing-xcto": (2, "Add X-Content-Type-Options: nosniff."),
        "cors-wildcard": (1, "Restrict CORS to specific trusted origins."),
        "large-response": (1, "Consider compressing large responses."),
    }

    # Count by check_id
    check_counts: dict[str, int] = {}
    for issue in issues:
        cid = issue.get("check_id", "")
        check_counts[cid] = check_counts.get(cid, 0) + 1

    # Build prioritized recommendation list
    scored_recs: list[tuple[int, str]] = []
    for cid, count in check_counts.items():
        if cid in rec_map:
            priority, rec_text = rec_map[cid]
            # Boost by occurrence count
            scored_recs.append((priority * count, rec_text))

    # Sort by score descending
    scored_recs.sort(key=lambda x: x[0], reverse=True)

    # Deduplicate and return top 5
    seen_recs: set[str] = set()
    top_recs: list[str] = []
    for _, rec_text in scored_recs:
        if rec_text not in seen_recs:
            seen_recs.add(rec_text)
            top_recs.append(rec_text)
        if len(top_recs) >= 5:
            break

    return top_recs if top_recs else ["Review all security findings and apply recommended fixes."]


# ════════════════════════════════════════════════════════════════
#  Core: Session CRUD
# ════════════════════════════════════════════════════════════════

def list_sessions(limit: int = 50, offset: int = 0) -> list[dict]:
    """
    List browser capture sessions, sorted by created_at descending.

    Args:
        limit:  Max sessions to return (default 50, max 200).
        offset: Pagination offset.

    Returns:
        List of session dicts.
    """
    limit = min(max(limit, 1), 200)

    with _lock:
        sessions = list(_sessions.values())

    sessions.sort(key=lambda s: s.created_at, reverse=True)
    return [asdict(s) for s in sessions[offset: offset + limit]]


def get_session(session_id: str) -> Optional[dict]:
    """
    Retrieve a single session by ID.

    Args:
        session_id: The session UUID.

    Returns:
        Session dict or None if not found.
    """
    with _lock:
        session = _sessions.get(session_id)
        return asdict(session) if session else None


def get_requests(
    session_id: str,
    limit: int = 50,
    offset: int = 0,
    method_filter: Optional[str] = None,
    domain_filter: Optional[str] = None,
) -> list[dict]:
    """
    Retrieve requests for a session with optional filtering.

    Args:
        session_id:    The session UUID.
        limit:         Max requests to return (default 50, max 500).
        offset:        Pagination offset.
        method_filter: Filter by HTTP method (e.g., "GET", "POST").
        domain_filter: Filter by domain substring in URL.

    Returns:
        List of request dicts (newest first).
    """
    limit = min(max(limit, 1), 500)

    with _lock:
        reqs = list(_requests.get(session_id, []))

    if method_filter:
        method_upper = method_filter.upper().strip()
        reqs = [r for r in reqs if r.method == method_upper]

    if domain_filter:
        domain_lower = domain_filter.lower()
        reqs = [r for r in reqs if domain_lower in _extract_domain(r.url).lower()]

    # Sort newest first
    indexed = list(enumerate(reqs))
    indexed.sort(key=lambda kv: (kv[1].captured_at, kv[0]), reverse=True)
    reqs = [v for _, v in indexed]

    return [asdict(r) for r in reqs[offset: offset + limit]]


def delete_session(session_id: str) -> bool:
    """
    Delete a session and all associated requests and analyses.

    Args:
        session_id: The session UUID.

    Returns:
        True if deleted, False if not found.
    """
    with _lock:
        if session_id not in _sessions:
            return False
        del _sessions[session_id]
        _requests.pop(session_id, None)
        _analyses.pop(session_id, None)

    logger.info("Session deleted: %s", session_id)
    return True


# ════════════════════════════════════════════════════════════════
#  Core: MIRV Findings Integration
# ════════════════════════════════════════════════════════════════

def report_to_mirv_findings(analysis: CaptureAnalysis) -> list[dict]:
    """
    Convert security issues from a CaptureAnalysis into MIRV-compatible
    findings format.

    Each issue becomes a dict with: tool, severity, title, detail,
    target, type, and extra metadata.  Results are sorted by severity
    (critical first) and capped at 200 findings.

    Args:
        analysis: The CaptureAnalysis to convert.

    Returns:
        List of MIRV finding dicts.
    """
    findings: list[dict] = []

    for issue in analysis.security_issues:
        sev = issue.get("severity", "info")
        findings.append({
            "tool": "browser-capture",
            "severity": sev,
            "title": issue.get("title", "Security issue"),
            "detail": issue.get("detail", ""),
            "target": issue.get("url", ""),
            "type": "vuln" if sev in ("critical", "high", "medium") else "info",
            "extra": {
                "check_id": issue.get("check_id", ""),
                "category": issue.get("category", ""),
                "evidence": issue.get("evidence", ""),
                "recommendation": issue.get("recommendation", ""),
                "risk_score": analysis.risk_score,
            },
        })

    # Sort by severity (critical first)
    findings.sort(key=lambda x: _severity_rank(x["severity"]))

    # Cap at 200
    return findings[:200]


# ════════════════════════════════════════════════════════════════
#  Core: Status
# ════════════════════════════════════════════════════════════════

def status() -> dict:
    """Return counts for each in-memory store."""
    with _lock:
        total_requests = sum(len(r) for r in _requests.values())
        return {
            "ok": True,
            "sessions": len(_sessions),
            "total_requests": total_requests,
            "analyses": len(_analyses),
            "max_sessions": _MAX_SESSIONS,
            "max_requests_per_session": _MAX_REQUESTS_PER_SESSION,
            "max_body": _MAX_BODY,
        }


# ════════════════════════════════════════════════════════════════
#  Utility: Reset (for testing)
# ════════════════════════════════════════════════════════════════

def reset() -> None:
    """Clear all in-memory state. For testing only."""
    global _sessions, _requests, _analyses
    with _lock:
        _sessions = {}
        _requests = {}
        _analyses = {}
    logger.info("Browser capture store reset")
