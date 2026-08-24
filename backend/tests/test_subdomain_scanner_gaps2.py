"""
tests/test_subdomain_scanner_gaps2.py — Coverage gap closure for subdomain_scanner.py.

Targets the 8 statements / 6 branch groups that existing tests leave uncovered:

    243     _normalize_subdomain with empty raw → None
    266     _http_get_json with empty body → None
    287     _fetch_crtsh item not dict → continue
    316     _fetch_wayback empty row → continue
    373-374 _resolve_subdomain gethostbyname returns loopback → no result
    385-386 _resolve_subdomain outer exception → None

All HTTP + DNS mocked — no real traffic.
"""

from __future__ import annotations

import json
import socket
from unittest.mock import patch

import pytest

from backend.subdomain_scanner import (
    _fetch_crtsh,
    _fetch_wayback,
    _http_get_json,
    _normalize_subdomain,
    _resolve_subdomain,
)


# ── fakes ────────────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal urllib response with context-manager protocol."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        if n is None or n < 0:
            return self._body
        return self._body[:n]


DOMAIN = "example.com"


# ════════════════════════════════════════════════════════════════
#  Line 243: _normalize_subdomain with empty raw
# ════════════════════════════════════════════════════════════════


def test_normalize_subdomain_empty_raw():
    """Empty raw string returns None (line 243)."""
    assert _normalize_subdomain("", DOMAIN) is None
    assert _normalize_subdomain(None, DOMAIN) is None
    assert _normalize_subdomain("   ", DOMAIN) is None


# ════════════════════════════════════════════════════════════════
#  Line 266: _http_get_json with empty body
# ════════════════════════════════════════════════════════════════


def test_http_get_json_empty_body():
    """Empty response body returns None (line 266)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"", 200)):
        result = _http_get_json("https://crt.sh/?q=example.com", 10.0)
    assert result is None


# ════════════════════════════════════════════════════════════════
#  Line 287: _fetch_crtsh item not dict
# ════════════════════════════════════════════════════════════════


def test_fetch_crtsh_item_not_dict():
    """crt.sh data with non-dict items → skipped via continue (line 287)."""
    crt_data = json.dumps([
        "not-a-dict",
        42,
        {"name_value": "sub.example.com"},
        None,
    ]).encode()
    with patch("urllib.request.urlopen", return_value=_FakeResp(crt_data, 200)):
        subs, err = _fetch_crtsh(DOMAIN, 10.0)
    assert err is None
    assert "sub.example.com" in subs
    # Non-dict items were silently skipped


# ════════════════════════════════════════════════════════════════
#  Line 316: _fetch_wayback empty row
# ════════════════════════════════════════════════════════════════


def test_fetch_wayback_empty_row():
    """Wayback CDX with empty rows → skipped via continue (line 316)."""
    cdx_data = json.dumps([
        ["original"],
        [],  # empty row
        "not-a-list",
        ["sub.example.com"],
    ]).encode()
    with patch("urllib.request.urlopen", return_value=_FakeResp(cdx_data, 200)):
        subs, err = _fetch_wayback(DOMAIN, 10.0)
    assert err is None
    assert "sub.example.com" in subs


# ════════════════════════════════════════════════════════════════
#  Lines 373-374: _resolve_subdomain gethostbyname returns loopback
# ════════════════════════════════════════════════════════════════


async def test_resolve_subdomain_loopback_ip():
    """gethostbyname returns 127.x → condition False, no result (lines 373-374)."""
    # getaddrinfo fails → ips empty → gethostbyname fallback
    with patch("asyncio.AbstractEventLoop.getaddrinfo", side_effect=socket.gaierror("fail")):
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            result = await _resolve_subdomain("sub.example.com", timeout=3.0)
    assert result is None  # loopback IP rejected


async def test_resolve_subdomain_gethostbyname_success():
    """gethostbyname returns a valid IP → SubdomainResult returned (lines 373-374)."""
    # getaddrinfo fails → ips empty → gethostbyname returns valid IP
    with patch("asyncio.AbstractEventLoop.getaddrinfo", side_effect=socket.gaierror("fail")):
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            result = await _resolve_subdomain("sub.example.com", timeout=3.0)
    assert result is not None
    assert result.resolved_ips == ["93.184.216.34"]
    assert result.record_type == "A"


# ════════════════════════════════════════════════════════════════
#  Lines 385-386: _resolve_subdomain outer exception
#  NOTE: lines 385-386 (outer except Exception: return None) are
#  DEFENSIVE DEAD CODE — unreachable in practice because:
#  1. Lines 328-329 (full_domain.split) are OUTSIDE the outer try
#  2. All code inside the outer try (331-384) is wrapped in inner
#     try/except blocks that catch Exception
#  3. The only lines inside the outer try but outside inner tries
#     are `if ips:` (357) and `return None` (384) — neither can raise
#  Accepted as uncoverable defensive code.
