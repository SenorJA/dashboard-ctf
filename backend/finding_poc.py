"""
backend/finding_poc.py — Reproducible Proof-of-Concept (PoC) for MIRV findings.

Inspired by PentesterFlow's ``confirm_finding`` tool, this module standardizes
how a MIRV finding captures the **full reproduction context** of a
vulnerability so that any other operator (or a future you) can replay the
issue in one command and obtain identical evidence.

A ``FindingPoC`` bundles:

* method + URL (the request target)
* headers (cookies, auth, custom)
* body (raw request body)
* parameter + payload (which input was injected and with what value)
* response_status + response_excerpt (proof the issue fired)
* curl_command (one-liner ready to paste in a shell)
* raw_request (syntactically valid HTTP/1.1 request)
* remediation + impact (human-readable context)
* evidence_hash (short sha256 of the response excerpt — tamper detection)

The module is **standard-library only** (no FastAPI / Supabase deps) so it
can be imported from tests, the CLI, or any worker. ``replay_poc`` shells out
to ``curl`` because that is exactly what the curl_command field encodes —
re-implementing HTTP client logic would defeat the "same command" promise.

Security notes
--------------
* ``sanitize_payload`` only strips NULL/control bytes. It deliberately
  preserves ``<>`` / quotes because XSS/SQLi payloads depend on them.
* ``replay_poc`` uses ``subprocess.run`` with a list of args (NEVER
  ``shell=True``) built via ``shlex.split`` — the curl_command is parsed,
  not string-interpolated, so payload values cannot escape the argv.
* No secrets are logged. If a header looks like ``Authorization`` or
  ``Cookie`` it is kept as-is in the stored PoC (replay is the point) but
  ``response_excerpt`` is truncated to ``MAX_RESPONSE_EXCERPT`` chars.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

# ── Logger (no secrets) ──────────────────────────────────────────────
import logging
_logger = logging.getLogger("vulnforge.poc")

# ── Constants ───────────────────────────────────────────────────────
MAX_RESPONSE_EXCERPT = 500
MAX_RAW_REQUEST_SIZE = 8192

# Loose allow-list used only as a sanity check, never as a security gate.
# (Real XSS/SQLi payloads legitimately contain ``<>`` "'*&|`` — see
# ``sanitize_payload`` for the actual safe-display logic.)
PAYLOAD_SANITIZATION_RE = re.compile(
    r"^[A-Za-z0-9+/=_\-.@\s,;:{}()\[\]\'\"<>|&*!$%^!?]*$"
)

# Valid HTTP request methods (RFC 7231 + common extensions).
_VALID_METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    "CONNECT", "TRACE", "PURGE", "LINK", "UNLINK", "PROPFIND", "PROPPATCH",
    "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
}


# ── Dataclass ───────────────────────────────────────────────────────
@dataclass
class FindingPoC:
    """Reproducible PoC for a MIRV finding."""

    finding_id: str
    method: str                            # GET, POST, PUT, DELETE, ...
    url: str                               # full URL
    headers: dict                          # request headers (cookie, auth)
    body: Optional[str]                    # request body
    parameter: Optional[str]               # affected param name
    payload: Optional[str]                # actual injected payload
    response_status: Optional[int]
    response_excerpt: Optional[str]        # short excerpt proving the issue
    curl_command: str                      # ready-to-run curl one-liner
    raw_request: str                      # raw HTTP/1.1 request
    remediation: Optional[str] = None
    impact: str = ""                       # one-line impact statement
    evidence_hash: Optional[str] = None    # sha256(excerpt)[:12] for tamper detection


# ── Helpers ─────────────────────────────────────────────────────────
def _now_uuid() -> str:
    return str(uuid.uuid4())


def sanitize_payload(payload: str) -> str:
    """Strip NULL + C0 control chars from a payload for *display*.

    This is deliberately minimal: XSS/SQLi PoCs legitimately contain
    ``<>`` ``"`` ``'`` ``&`` ``|`` ``*`` ``!`` — none of those are removed.
    Only byte 0x00 and other C0 control bytes (except the printable
    whitespace HT/LF/CR which are common in multi-line payloads) are
    stripped, so the resulting string is safe to render in a UI textarea
    without breaking terminal/JSON parsers.
    """
    if payload is None:
        return ""
    if not isinstance(payload, str):
        payload = str(payload)
    # Allow HT(0x09) LF(0x0A) CR(0x0D); strip 0x00..0x08, 0x0B..0x1F, 0x7F.
    return "".join(
        ch for ch in payload
        if ch in ("\t", "\n", "\r") or (0x20 <= ord(ch) < 0x7F) or ord(ch) > 0x9F
    )


def validate_url(url: str) -> bool:
    """Basic URL validation: scheme is http(s) and host non-empty."""
    if not url or not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url.strip())
    except Exception:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _truncate(text: Optional[str], limit: int) -> Optional[str]:
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit]


def _evidence_hash(excerpt: Optional[str]) -> Optional[str]:
    if not excerpt:
        return None
    return hashlib.sha256(excerpt.encode("utf-8", errors="replace")).hexdigest()[:12]


def _quote_shell(value: str) -> str:
    """Wrap a value in single quotes for safe shell inclusion.

    Single quotes inside the value are closed, escaped as ``'\\'``', then
    the quote re-opened. This is the canonical Bourne-shell idiom and is
    safe regardless of the value's contents.
    """
    return "'" + value.replace("'", "'\\''") + "'"


def _build_curl_command(
    method: str,
    url: str,
    headers: dict,
    body: Optional[str],
    verify_tls: bool = True,
) -> str:
    """Build a ready-to-run curl one-liner (no shell=True needed at replay
    time because ``parse_curl_to_poc`` re-shlex-splits it)."""
    parts: list[str] = ["curl", "-sS", "-X", method, _quote_shell(url)]
    if not verify_tls:
        parts.append("-k")
    for name, value in (headers or {}).items():
        parts.extend(["-H", _quote_shell(f"{name}: {value}")])
    if body is not None and body != "":
        parts.extend(["--data-raw", _quote_shell(body)])
    parts.append("-i")  # include response status line / headers in output
    return " ".join(parts)


def _build_raw_request(
    method: str,
    url: str,
    headers: dict,
    body: Optional[str],
) -> str:
    """Build a syntactically valid HTTP/1.1 request string.

    Includes a synthesized ``Host`` header (from the URL netloc) if the
    caller did not provide one. Adds ``Content-Length`` when a body exists
    and the caller did not specify it.
    """
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    netloc = parts.netloc

    # Merge caller headers; case-insensitive dedup.
    hdrs: dict[str, str] = {}
    for k, v in (headers or {}).items():
        hdrs[k] = str(v)
    lower = {k.lower(): k for k in hdrs}
    if "host" not in lower and netloc:
        hdrs["Host"] = netloc
    if body and "content-length" not in {k.lower() for k in hdrs}:
        hdrs["Content-Length"] = str(len(body.encode("utf-8", errors="replace")))
    if body and "content-type" not in {k.lower() for k in hdrs}:
        # Only hint form-encoded as a conservative default; callers wanting
        # JSON should set Content-Type explicitly.
        # (Skip auto-add to avoid misleading POST bodies — let caller decide.)
        pass

    lines = [f"{method} {path} HTTP/1.1"]
    for name, value in hdrs.items():
        lines.append(f"{name}: {value}")
    request = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        request += body
    # Hard cap to avoid pathological blobs bloating the stored finding.
    if len(request) > MAX_RAW_REQUEST_SIZE:
        request = request[:MAX_RAW_REQUEST_SIZE]
    return request


# ── Core functions ──────────────────────────────────────────────────
def build_poc(
    method: str,
    url: str,
    headers: Optional[dict] = None,
    body: Optional[str] = None,
    parameter: Optional[str] = None,
    payload: Optional[str] = None,
    response_status: Optional[int] = None,
    response_excerpt: Optional[str] = None,
    remediation: Optional[str] = None,
    impact: str = "",
) -> FindingPoC:
    """Build a ``FindingPoC`` from request/response context.

    * Generates ``finding_id`` (uuid4).
    * Builds ``curl_command`` and ``raw_request``.
    * Truncates ``response_excerpt`` to ``MAX_RESPONSE_EXCERPT``.
    * Computes ``evidence_hash`` from the excerpt (sha256[:12]).
    """
    method = (method or "GET").upper().strip()
    url = (url or "").strip()
    headers = dict(headers or {})
    body = body if (body is None or isinstance(body, str)) else str(body)
    excerpt = _truncate(response_excerpt, MAX_RESPONSE_EXCERPT)

    poc = FindingPoC(
        finding_id=_now_uuid(),
        method=method,
        url=url,
        headers=headers,
        body=body,
        parameter=parameter,
        payload=payload,
        response_status=response_status,
        response_excerpt=excerpt,
        curl_command="",          # filled below
        raw_request="",           # filled below
        remediation=remediation,
        impact=impact or "",
        evidence_hash=_evidence_hash(excerpt),
    )
    poc.curl_command = _build_curl_command(method, url, headers, body)
    poc.raw_request = _build_raw_request(method, url, headers, body)
    return poc


def poc_to_finding(
    poc: FindingPoC,
    what: str,
    severity: str,
    target: str,
    tool: str = "manual",
) -> dict:
    """Convert a ``FindingPoC`` into the standard MIRV finding dict."""
    return {
        "what": what,
        "severity": severity,
        "target": target,
        "tool": tool,
        "data": {
            "poc": asdict(poc),
            "method": poc.method,
            "url": poc.url,
            "parameter": poc.parameter,
            "payload": poc.payload,
            "evidence_hash": poc.evidence_hash,
        },
    }


def finding_to_poc(finding: dict) -> Optional[FindingPoC]:
    """Reconstruct a ``FindingPoC`` from a MIRV finding dict.

    Returns ``None`` when the finding carries neither ``data.poc`` nor the
    legacy ``data.curl`` field.
    """
    if not isinstance(finding, dict):
        return None
    data = finding.get("data") or {}
    if not isinstance(data, dict):
        return None

    poc_dict = data.get("poc")
    if not isinstance(poc_dict, dict):
        # Fall back to a minimal reconstruction from fields.
        curl = data.get("curl")
        if not curl:
            return None
        # Try to round-trip via the curl parser, attaching any extra context.
        poc = parse_curl_to_poc(
            curl,
            response_excerpt=data.get("response_excerpt"),
            response_status=data.get("response_status"),
        )
        poc.parameter = data.get("parameter")
        poc.payload = data.get("payload")
        poc.finding_id = data.get("finding_id") or poc.finding_id
        poc.remediation = data.get("remediation")
        poc.impact = data.get("impact", "")
        return poc

    # Reconstruct from serialized dict.
    def _g(key, default=None):
        v = poc_dict.get(key, default)
        return v

    return FindingPoC(
        finding_id=_g("finding_id", _now_uuid()),
        method=_g("method", "GET"),
        url=_g("url", ""),
        headers=_g("headers", {}) or {},
        body=_g("body"),
        parameter=_g("parameter"),
        payload=_g("payload"),
        response_status=_g("response_status"),
        response_excerpt=_g("response_excerpt"),
        curl_command=_g("curl_command", ""),
        raw_request=_g("raw_request", ""),
        remediation=_g("remediation"),
        impact=_g("impact", ""),
        evidence_hash=_g("evidence_hash"),
    )


def replay_poc(
    poc: FindingPoC,
    timeout: int = 30,
    verify_tls: bool = False,
) -> dict:
    """Execute the PoC's curl_command and return a structured result.

    We use ``shlex.split`` + ``subprocess.run`` (never ``shell=True``).
    The ``-k`` flag is injected when ``verify_tls`` is False and the
    stored command does not already contain it.

    Returns a dict shaped::

        {
            "ok": bool,
            "status_code": Optional[int],
            "response_excerpt": str (first 500 chars),
            "evidence_hash": Optional[str],
            "matches_original": bool,
            "elapsed_ms": int,
            "error": Optional[str],
        }
    """
    import time

    if not poc or not poc.curl_command:
        return {
            "ok": False, "status_code": None, "response_excerpt": "",
            "evidence_hash": None, "matches_original": False,
            "elapsed_ms": 0, "error": "no curl_command in PoC",
        }

    cmd_str = poc.curl_command
    try:
        args = shlex.split(cmd_str)
    except ValueError as e:
        return {
            "ok": False, "status_code": None, "response_excerpt": "",
            "evidence_hash": None, "matches_original": False,
            "elapsed_ms": 0, "error": f"bad curl_command: {e}",
        }

    if not verify_tls and "-k" not in args and "--insecure" not in args:
        args.append("-k")

    start = time.monotonic()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # we inspect the response ourselves
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        out = (proc.stdout or "") + (proc.stderr or "")
        excerpt = out[:MAX_RESPONSE_EXCERPT]

        # Best-effort parse the HTTP status line (curl -i prepends it).
        # Also extract the body portion (after the blank-line separator) so
        # that the evidence hash can be compared against the original
        # response_excerpt hash which was computed from body-only content.
        status_code: Optional[int] = None
        body_text = out  # fallback: full output
        header_end = -1
        for i, line in enumerate(out.splitlines(keepends=True)):
            stripped = line.strip()
            if stripped.startswith("HTTP/") and " " in stripped and status_code is None:
                try:
                    status_code = int(stripped.split(" ", 2)[1])
                except (ValueError, IndexError):
                    pass
            # The blank line after HTTP headers marks the body start.
            if status_code is not None and stripped == "" and header_end < 0:
                header_end = sum(len(l) for l in out.splitlines(keepends=True)[: i + 1])
                break
        if header_end > 0:
            body_text = out[header_end:]

        body_excerpt = body_text[:MAX_RESPONSE_EXCERPT].rstrip("\r\n")
        new_hash = _evidence_hash(body_excerpt)
        matches = bool(
            poc.evidence_hash and new_hash and new_hash == poc.evidence_hash
        )
        return {
            "ok": True,
            "status_code": status_code,
            "response_excerpt": body_excerpt,
            "evidence_hash": new_hash,
            "matches_original": matches,
            "elapsed_ms": elapsed_ms,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": False, "status_code": None, "response_excerpt": "",
            "evidence_hash": None, "matches_original": False,
            "elapsed_ms": elapsed_ms, "error": "timeout",
        }
    except subprocess.CalledProcessError as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": False, "status_code": None, "response_excerpt": "",
            "evidence_hash": None, "matches_original": False,
            "elapsed_ms": elapsed_ms, "error": f"subprocess error: {e}",
        }
    except FileNotFoundError:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": False, "status_code": None, "response_excerpt": "",
            "evidence_hash": None, "matches_original": False,
            "elapsed_ms": elapsed_ms, "error": "curl binary not found",
        }
    except Exception as e:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "ok": False, "status_code": None, "response_excerpt": "",
            "evidence_hash": None, "matches_original": False,
            "elapsed_ms": elapsed_ms, "error": f"unexpected: {e}",
        }


def parse_curl_to_poc(
    curl_str: str,
    response_excerpt: str = "",
    response_status: Optional[int] = None,
) -> FindingPoC:
    """Parse a ``curl ...`` one-liner into a ``FindingPoC``.

    Recognizes the common flags: ``-X``, ``-H``, ``--header``, ``--data``,
    ``--data-raw``, ``-d``, ``--cookie``, ``-k`` / ``--insecure``, ``-i``,
    ``-s``, ``-S``, ``-sS``.
    """
    if not curl_str or not isinstance(curl_str, str):
        return build_poc("GET", "")

    s = curl_str.strip()
    try:
        tokens = shlex.split(s)
    except ValueError:
        # Fall back to whitespace split if quoting is malformed.
        tokens = s.split()

    if not tokens:
        return build_poc("GET", "")

    # Strip leading "curl" / env prefix.
    if tokens and tokens[0].endswith("curl"):
        tokens = tokens[1:]
    elif tokens and tokens[0] == "curl":
        tokens = tokens[1:]

    method = "GET"
    url = ""
    headers: dict[str, str] = {}
    body: Optional[str] = None
    cookie: Optional[str] = None
    has_body_arg = False

    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t in ("-X", "--request") and i + 1 < n:
            method = tokens[i + 1].upper()
            i += 2
            continue
        if t in ("-H", "--header") and i + 1 < n:
            hdr = tokens[i + 1]
            if ":" in hdr:
                name, _, value = hdr.partition(":")
                headers[name.strip()] = value.strip()
            i += 2
            continue
        if t in ("--data", "--data-raw", "--data-binary", "-d") and i + 1 < n:
            body = tokens[i + 1]
            has_body_arg = True
            i += 2
            continue
        if t == "--cookie" and i + 1 < n:
            cookie = tokens[i + 1]
            i += 2
            continue
        if t in ("-k", "--insecure", "-s", "-S", "-sS", "-i", "--include", "-L",
                 "--location", "--compressed", "-A", "--user-agent"):
            # boolean / non-capturing flags; -A/--user-agent expect a value
            # but we don't model them as headers here.
            if t in ("-A", "--user-agent") and i + 1 < n:
                headers["User-Agent"] = tokens[i + 1]
                i += 2
                continue
            i += 1
            continue
        if t.startswith("-"):
            # Unknown flag; skip it (and its value if it obviously takes one).
            i += 1
            continue
        # First non-flag positional is the URL.
        url = t
        i += 1

    # If a body was supplied without an explicit -X, curl defaults to POST.
    if has_body_arg and method == "GET":
        method = "POST"
    if cookie and "Cookie" not in {k for k in headers}:
        headers["Cookie"] = cookie

    if not validate_url(url) and url:
        # Tolerate partial URLs (e.g. ``example.com/api``) by re-prefixing.
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url

    return build_poc(
        method=method,
        url=url,
        headers=headers,
        body=body,
        response_status=response_status,
        response_excerpt=response_excerpt or "",
    )


def finding_to_markdown_report(finding: dict) -> str:
    """Render a MIRV finding as a self-contained Markdown report."""
    if not isinstance(finding, dict):
        return "## Finding\n\n_(invalid finding object)_\n"

    what = finding.get("what", "Untitled finding") or "Untitled finding"
    severity = (finding.get("severity", "info") or "info").lower()
    target = finding.get("target", "") or ""
    tool = finding.get("tool", "") or ""
    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🔵", "info": "⚪",
    }.get(severity, "⚪")

    lines: list[str] = []
    lines.append(f"## {severity_emoji} {severity.upper()} — {what}")
    lines.append("")
    lines.append(f"- **Target:** `{target}`" if target else "- **Target:** _unknown_")
    if tool:
        lines.append(f"- **Detected by:** `{tool}`")
    lines.append("")

    poc = finding_to_poc(finding)
    if poc:
        lines.append("### Reproducible PoC")
        lines.append("")
        lines.append(f"- **Affected:** `{poc.method} {poc.url}`")
        if poc.parameter:
            lines.append(f"- **Parameter:** `{poc.parameter}`")
        if poc.payload:
            lines.append("- **Payload:**")
            lines.append("")
            lines.append("```")
            lines.append(sanitize_payload(poc.payload))
            lines.append("```")
            lines.append("")
        if poc.curl_command:
            lines.append("#### PoC (curl)")
            lines.append("")
            lines.append("```bash")
            lines.append(poc.curl_command)
            lines.append("```")
            lines.append("")
        if poc.raw_request:
            lines.append("#### Raw HTTP request")
            lines.append("")
            lines.append("```http")
            lines.append(poc.raw_request)
            lines.append("```")
            lines.append("")
        if poc.response_status is not None:
            lines.append(f"- **Response status:** `{poc.response_status}`")
        if poc.response_excerpt:
            lines.append("#### Response excerpt (evidence)")
            lines.append("")
            lines.append("```")
            lines.append(poc.response_excerpt)
            lines.append("```")
            lines.append("")
        if poc.evidence_hash:
            lines.append(f"- **Evidence hash:** `{poc.evidence_hash}` "
                         f"_(sha256[:12] of the excerpt above)_")
        if poc.impact:
            lines.append("")
            lines.append("### Impact")
            lines.append("")
            lines.append(poc.impact)
        if poc.remediation:
            lines.append("")
            lines.append("### Remediation")
            lines.append("")
            lines.append(poc.remediation)
    else:
        data = finding.get("data") or {}
        if isinstance(data, dict) and data:
            lines.append("### Notes")
            lines.append("")
            lines.append("```json")
            import json as _json
            try:
                lines.append(_json.dumps(data, indent=2, default=str)[:MAX_RAW_REQUEST_SIZE])
            except Exception:
                lines.append(str(data)[:MAX_RAW_REQUEST_SIZE])
            lines.append("```")
        else:
            lines.append("_No reproducible PoC context stored for this finding._")

    lines.append("")
    return "\n".join(lines)


def validate_poc(poc: FindingPoC) -> list[str]:
    """Return a list of validation error messages. Empty list = valid."""
    errors: list[str] = []
    if poc is None:
        return ["poc is None"]
    if not poc.method or poc.method.upper() != poc.method or poc.method not in _VALID_METHODS:
        errors.append(f"invalid method '{poc.method}'")
    if not validate_url(poc.url):
        errors.append(f"invalid url '{poc.url}'")
    if not isinstance(poc.headers, dict):
        errors.append("headers must be a dict")
    else:
        for k, v in poc.headers.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float)):
                errors.append(f"bad header entry {k!r}:{v!r}")
                break
    if poc.response_status is not None:
        if not isinstance(poc.response_status, int) or poc.response_status < 100 or poc.response_status > 599:
            errors.append(f"invalid response_status {poc.response_status!r}")
    if poc.body is not None and not isinstance(poc.body, str):
        errors.append("body must be str or None")
    return errors


def poc_from_burp_request(captured: dict) -> Optional[FindingPoC]:
    """Convert a Burp Bridge ``CapturedRequest``-shaped dict into a PoC.

    The dict may carry any of: ``method``, ``url``, ``headers``, ``body``,
    ``response_status``, ``response_body``. Returns ``None`` if mandatory
    fields (``url``) are missing.
    """
    if not isinstance(captured, dict):
        return None
    url = captured.get("url")
    if not url or not isinstance(url, str):
        return None
    method = (captured.get("method") or "GET").upper()
    headers = captured.get("headers") or {}
    if not isinstance(headers, dict):
        # Burp bridge also accepts a list-of-strings header form.
        # Normalize defensively.
        if isinstance(headers, (list, tuple)):
            norm: dict[str, str] = {}
            for line in headers:
                line = str(line)
                if ":" in line:
                    name, _, value = line.partition(":")
                    norm[name.strip()] = value.strip()
            headers = norm
        else:
            headers = {}
    body = captured.get("body")
    if body is not None and not isinstance(body, str):
        body = str(body)
    response_status = captured.get("response_status")
    if response_status is not None:
        try:
            response_status = int(response_status)
        except (TypeError, ValueError):
            response_status = None
    response_body = captured.get("response_body") or captured.get("response_excerpt")
    return build_poc(
        method=method,
        url=url,
        headers=headers,
        body=body,
        response_status=response_status,
        response_excerpt=response_body,
    )


__all__ = [
    "FindingPoC",
    "MAX_RESPONSE_EXCERPT",
    "MAX_RAW_REQUEST_SIZE",
    "PAYLOAD_SANITIZATION_RE",
    "build_poc",
    "poc_to_finding",
    "finding_to_poc",
    "replay_poc",
    "parse_curl_to_poc",
    "finding_to_markdown_report",
    "sanitize_payload",
    "validate_url",
    "validate_poc",
    "poc_from_burp_request",
]