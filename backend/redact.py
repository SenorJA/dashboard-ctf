"""
redact.py — M.I.R.V. Global Redaction System
============================================

Shape-preserving redaction of secrets, PII, and credentials whenever
data crosses a *trust boundary* in MIRV:

    * Payloads sent to external LLMs via ``/api/ai/chat``
    * Data persisted into ``mission_history`` (later reused as AI context)
    * Lines written to the ``vulnforge.log`` file
    * Report / export generators
    * Snapshot stores

Design choices
--------------
- **Shape-preserving**: keys, list order, nested structure are kept; only
  the *sensitive values* are replaced by deterministic placeholders like
  ``[AWS_KEY]``, ``[OPENAI_KEY]``, ``[REDACTED]``, ...
- **Opt-in per call site**: importing this module does NOT change any
  behaviour. Call sites must explicitly wrap their data via
  ``redact_string`` / ``redact_dict`` / ``redact_ai_payload`` / ...
- **OSINT-friendly**: public IPv4/IPv6 addresses are *preserved* (they are
  useful for reconnaissance). Only private/loopback IPs may be masked in
  :func:`redact_log_line`.
- **Idempotent**: redacting an already-redacted string is a no-op (the
  placeholders themselves don't match any pattern).
- **No external deps**: stdlib only (re + json + logging + typing).

Patterns are evaluated in order: the most specific patterns run first,
generic high-entropy fallbacks run last. Credit-card candidates are
validated with the Luhn algorithm so we don't blow away timestamps, port
numbers, or random numeric strings.
"""

from __future__ import annotations

import io
import json
import re
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("vulnforge.redact")


# ══════════════════════════════════════════════════════════════════
#  Luhn check (credit cards)
# ══════════════════════════════════════════════════════════════════

def _luhn_check(card_number: str) -> bool:
    """Return True if ``card_number`` passes the Luhn checksum.

    Non-digit characters are stripped before validation; we require at
    least 13 digits so we don't Luhn-check short numbers that happen to
    match the regex by accident.
    """
    digits = [int(c) for c in re.sub(r'\D', '', card_number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact_credit_card_callback(m: "re.Match") -> str:
    """Regex replacement callback: redact only if the match passes Luhn."""
    match = m.group(0)
    if _luhn_check(match):
        return '[CREDIT_CARD]'
    return match  # preserve non-Luhn numbers (timestamps, ports, ...)


# ══════════════════════════════════════════════════════════════════
#  Private IP detection (for log line redaction)
# ══════════════════════════════════════════════════════════════════

_PRIVATE_IP_RE = re.compile(
    r'^(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|0\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r')$'
)

_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _is_private_ip(value: str) -> bool:
    return bool(_PRIVATE_IP_RE.match(value))


# ══════════════════════════════════════════════════════════════════
#  Redaction patterns
# ══════════════════════════════════════════════════════════════════
#  Each entry is (compiled_regex, replacement). The replacement may be:
#   - a plain string with optional backrefs (\1, \g<name>...)
#   - a callable taking the match and returning the substituted text
#
#  Patterns are intentionally ordered from MOST specific (provider
#  specific keys) to LEAST specific (generic ``Long token`` fallback).

REDACT_PATTERNS: list[tuple[re.Pattern, Any]] = [
    # ── Cloud provider access keys ──────────────────────────────
    (re.compile(r'(AKIA|ASIA)[0-9A-Z]{16}'), '[AWS_KEY]'),
    (re.compile(r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
     'aws_secret_access_key=[AWS_SECRET]'),

    # ── GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_) ───────────────
    (re.compile(r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}'), '[GITHUB_TOKEN]'),

    # ── OpenAI / generic LLM keys (sk-...) ──────────────────────
    (re.compile(r'sk-[A-Za-z0-9]{20,}'), '[OPENAI_KEY]'),

    # ── Google API keys ─────────────────────────────────────────
    (re.compile(r'AIza[0-9A-Za-z_\-]{35}'), '[GOOGLE_KEY]'),

    # ── Slack tokens ────────────────────────────────────────────
    (re.compile(r'xox[abp]-[A-Za-z0-9-]+'), '[SLACK_TOKEN]'),

    # ── Stripe secret keys (live/test) ─────────────────────────
    (re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}'), '[STRIPE_KEY]'),

    # ── Bearer / Authorization headers ──────────────────────────
    (re.compile(r'(Authorization\s*[:=]\s*["\']?Bearer\s+)([A-Za-z0-9_\-\.=]+)',
                re.IGNORECASE),
     r'\1[BEARER]'),
    (re.compile(r'(Bearer\s+)([A-Za-z0-9_\-\.=]{20,})'), r'\1[BEARER]'),

    # ── JWT (3-segment signed OR 2-segment alg:none) ────────────
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'),
     '[JWT]'),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.?'),
     '[JWT_FRAGMENT]'),

    # ── URL userinfo passwords: scheme://user:pass@host ─────────
    (re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+):([^:/@\s]+)@'),
     r'\1:[REDACTED]@'),

    # ── Generic api_key=/key=/token=/secret=/password= forms ────
    (re.compile(
        r'((?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*["\']?)'
        r'([A-Za-z0-9_\-\.=/+]{8,})',
        re.IGNORECASE),
     r'\1[REDACTED]'),
    (re.compile(
        r'(["\']?(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)["\']?\s*[:=]\s*["\']?)'
        r'([A-Za-z0-9_\-\.=/+]{8,})',
        re.IGNORECASE),
     r'\1[REDACTED]'),

    # ── Cookies ─────────────────────────────────────────────────
    (re.compile(r'([Cc]ookie\s*[:=]\s*["\']?)([A-Za-z0-9_\-\.=/+; ]{20,})'),
     r'\1[COOKIE]'),
    (re.compile(r'([Ss]et-[Cc]ookie\s*[:=]\s*["\']?[^;]+)([^;"\']+)'),
     r'\1[COOKIE_VALUE]'),
    (re.compile(r'x-api-key\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})',
                re.IGNORECASE),
     'x-api-key=[API_KEY]'),

    # ── PEM private-key blocks (multiline) ───────────────────────
    (re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'
        r'[\s\S]*?'
        r'-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----'),
     '[PRIVATE_KEY]'),

    # ── Generic high-entropy fallback (>= 40 alnum, no spaces) ──
    (re.compile(r'\b[A-Za-z0-9+/_\-]{40,}\b'), '[LONG_TOKEN]'),

    # ── Credit cards (Luhn-validated via callback) ──────────────
    (re.compile(r'\b(?:\d[ -]*?){13,19}\b'), _redact_credit_card_callback),
]


# ══════════════════════════════════════════════════════════════════
#  Core redaction primitives
# ══════════════════════════════════════════════════════════════════

def redact_string(s: str, patterns: Optional[list] = None) -> str:
    """Apply every redaction pattern to ``s`` and return the masked text.

    ``patterns`` defaults to :data:`REDACT_PATTERNS`. Passing a custom
    list lets callers cherry-pick rules (e.g. only public-IP filtering).
    The function never raises — if a regex fails it logs and skips.
    """
    if not isinstance(s, str) or not s:
        return s if isinstance(s, str) else ''

    active = patterns if patterns is not None else REDACT_PATTERNS
    out = s
    for pat, repl in active:
        try:
            out = pat.sub(repl, out)
        except re.error as e:  # pragma: no cover — defensive
            logger.warning("redact_string: bad pattern %r: %s", pat.pattern, e)
            continue
    return out


def redact_dict(d: dict, max_depth: int = 10, _visited: Optional[set] = None) -> dict:
    """Recursively redact every string value inside ``d``.

    Preserves keys, order, and structural shape. Detects reference cycles
    via ``id()`` tracking. ``max_depth`` protects against pathological
    nesting / cycle edge cases.
    """
    if not isinstance(d, dict):
        return d
    if _visited is None:
        _visited = set()
    obj_id = id(d)
    if obj_id in _visited or max_depth <= 0:
        return d
    _visited.add(obj_id)
    try:
        result: dict = {}
        for k, v in d.items():
            if isinstance(v, str):
                result[k] = redact_string(v)
            elif isinstance(v, dict):
                result[k] = redact_dict(v, max_depth - 1, _visited)
            elif isinstance(v, list):
                result[k] = redact_list(v, max_depth - 1, _visited)
            else:
                result[k] = v
        return result
    finally:
        _visited.discard(obj_id)


def redact_list(lst: list, max_depth: int = 10, _visited: Optional[set] = None) -> list:
    """Recursively redact every string in ``lst`` preserving length/order."""
    if not isinstance(lst, list):
        return lst
    if _visited is None:
        _visited = set()
    obj_id = id(lst)
    if obj_id in _visited or max_depth <= 0:
        return lst
    _visited.add(obj_id)
    try:
        result: list = []
        for v in lst:
            if isinstance(v, str):
                result.append(redact_string(v))
            elif isinstance(v, dict):
                result.append(redact_dict(v, max_depth - 1, _visited))
            elif isinstance(v, list):
                result.append(redact_list(v, max_depth - 1, _visited))
            else:
                result.append(v)
        return result
    finally:
        _visited.discard(obj_id)


def redact_json(s: str) -> str:
    """Parse ``s`` as JSON, redact, and re-serialize.

    Falls back to :func:`redact_string` if the input is not valid JSON
    (we never want redaction itself to throw).
    """
    if not isinstance(s, str) or not s:
        return s if isinstance(s, str) else ''
    try:
        parsed = json.loads(s)
    except (ValueError, TypeError):
        return redact_string(s)
    if isinstance(parsed, dict):
        return json.dumps(redact_dict(parsed), ensure_ascii=False)
    if isinstance(parsed, list):
        return json.dumps(redact_list(parsed), ensure_ascii=False)
    # primitives
    return json.dumps(parsed, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════════
#  Specialised wrappers for typical call sites
# ══════════════════════════════════════════════════════════════════

def redact_log_line(line: str) -> str:
    """Redact a single log line.

    First applies :func:`redact_string` (covers tokens / passwords),
    then masks *private* IPv4 addresses (10/172.16/192.168/127/0).
    Public IPs are kept — they're useful for OSINT correlation.
    """
    if not isinstance(line, str) or not line:
        return line if isinstance(line, str) else ''

    out = redact_string(line)

    def _ip_cb(m: "re.Match") -> str:
        ip = m.group(0)
        return '[PRIVATE_IP]' if _is_private_ip(ip) else ip

    out = _IPV4_RE.sub(_ip_cb, out)
    return out


def redact_ai_payload(messages: list[dict]) -> list[dict]:
    """Redact user-supplied content before sending to an external LLM.

    Each message is expected to be ``{"role": "user|assistant|system",
    "content": "..."}``. The role and any function/tool-call structure
    is preserved verbatim; only textual fields are masked.

    Handles OpenAI-style nested ``content`` lists
    (``[{"type": "text", "text": "..."}]``) and ``function_call`` /
    ``tool_calls`` blocks.
    """
    if not isinstance(messages, list):
        return messages if isinstance(messages, list) else []
    out: list[dict] = []
    for m in messages:
        if not isinstance(m, dict):
            out.append(m)
            continue
        msg = dict(m)  # shallow copy, preserve role
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = redact_string(content)
        elif isinstance(content, list):
            msg["content"] = [
                {**part, "text": redact_string(part["text"])}
                if isinstance(part, dict) and isinstance(part.get("text"), str)
                else part
                for part in content
            ]
        # tool/function call arguments are JSON-encoded strings
        for key in ("function_call", "tool_calls"):
            if isinstance(msg.get(key), dict):
                args = msg[key].get("arguments")
                if isinstance(args, str):
                    msg[key] = {**msg[key], "arguments": redact_json(args)}
        out.append(msg)
    return out


def redact_report(content: dict) -> dict:
    """Redact sensitive fields inside a scan report dict.

    Summary fields (``title``, ``target``, ``severity``, ``tool``) are
    kept so the exported report stays readable. Rich fields likely to
    embed raw tool output (``parsed_data``, ``raw``, ``detail``,
    ``output``, ``evidence``) are recursively masked.
    """
    if not isinstance(content, dict):
        return content
    RICH_FIELDS = {"parsed_data", "raw", "detail", "output", "evidence",
                   "body", "response", "headers", "commands", "stdout",
                   "stderr", "findings_summary", "tools_used"}
    safe: dict = {}
    for k, v in content.items():
        if k in RICH_FIELDS:
            if isinstance(v, str):
                safe[k] = redact_string(v)
            elif isinstance(v, dict):
                safe[k] = redact_dict(v)
            elif isinstance(v, list):
                safe[k] = redact_list(v)
            else:
                safe[k] = v
        elif isinstance(v, dict):
            safe[k] = redact_dict(v)
        elif isinstance(v, list):
            safe[k] = redact_list(v)
        elif isinstance(v, str) and k in ("token", "secret", "password",
                                          "passwd", "api_key", "apikey"):
            safe[k] = redact_string(v)
        else:
            safe[k] = v
    return safe


def is_sensitive_value(value: str) -> bool:
    """Return True if ``value`` triggers any redaction pattern.

    Used by callers to gate expensive flows (e.g. only mount a redacted
    snapshot when the original actually contains secrets).
    """
    if not isinstance(value, str) or not value:
        return False
    for pat, _ in REDACT_PATTERNS:
        if pat.search(value):
            # For credit cards: confirm Luhn so we don't flag timestamps
            if pat.pattern == r'\b(?:\d[ -]*?){13,19}\b':
                m = pat.search(value)
                if m and _luhn_check(m.group(0)):
                    return True
                continue
            return True
    return False


def list_redaction_matches(text: str) -> list[dict]:
    """Return a list of ``{pattern, match, replacement}`` dicts.

    Used by the ``POST /api/redact/check`` debugging endpoint.
    """
    if not isinstance(text, str) or not text:
        return []
    hits: list[dict] = []
    for idx, (pat, repl) in enumerate(REDACT_PATTERNS):
        for m in pat.finditer(text):
            original = m.group(0)
            if callable(repl):
                replacement = repl(m)
            else:
                replacement = pat.sub(
                    lambda mm, _r=repl: _r, original
                )
            # credit-card non-Luhn: skip (not actually sensitive)
            if isinstance(repl, Callable) and original == replacement:
                continue
            hits.append({
                "pattern_index": idx,
                "pattern": pat.pattern,
                "match": original[:128],
                "replacement": replacement if isinstance(replacement, str)
                                  else str(replacement),
            })
    return hits


# ══════════════════════════════════════════════════════════════════
#  Stream wrapper (for log handler integration)
# ══════════════════════════════════════════════════════════════════

class RedactingStreamWrapper:
    """Wrap any stream-like object so writes are auto-redacted.

    Drop-in replacement for ``sys.stdout`` / file handles, e.g.::

        handler = logging.StreamHandler(
            RedactingStreamWrapper(open("vulnforge.log", "a"))
        )

    The default redactor is :func:`redact_log_line` because that's the
    most appropriate for the logging use-case (masks secrets AND
    private IPs). Pass ``redactor=redact_string`` if you only want
    token/secret masking.
    """

    def __init__(self, stream, redactor: Callable[[str], str] = redact_log_line):
        self.stream = stream
        self._redactor = redactor

    def write(self, msg: str) -> int:
        if isinstance(msg, str) and msg:
            msg = self._redactor(msg)
        return self.stream.write(msg)

    def flush(self) -> None:
        if hasattr(self.stream, "flush"):
            self.stream.flush()

    def close(self) -> None:
        if hasattr(self.stream, "close"):
            self.stream.close()

    def fileno(self) -> int:
        return self.stream.fileno()

    def isatty(self) -> bool:
        return getattr(self.stream, "isatty", lambda: False)()

    def writable(self) -> bool:
        return getattr(self.stream, "writable", lambda: True)()

    def readable(self) -> bool:
        return getattr(self.stream, "readable", lambda: False)()

    def __getattr__(self, name):
        # Delegate any other attribute (encoding, newlines, mode, ...)
        return getattr(self.stream, name)


def redact_fh(stream):
    """Convenience helper — wrap ``stream`` with the default redactor."""
    return RedactingStreamWrapper(stream)


__all__ = [
    "REDACT_PATTERNS",
    "redact_string",
    "redact_dict",
    "redact_list",
    "redact_json",
    "redact_log_line",
    "redact_ai_payload",
    "redact_report",
    "redact_fh",
    "is_sensitive_value",
    "list_redaction_matches",
    "RedactingStreamWrapper",
    "_luhn_check",
]