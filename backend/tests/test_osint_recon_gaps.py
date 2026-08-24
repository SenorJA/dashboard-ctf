"""
tests/test_osint_recon_gaps.py — Coverage gap closure for osint_recon.py.

Targets the 28 statements / 16 branch groups that test_osint_recon.py
(75 tests) leaves uncovered:

    165-166  _fetch HTTPError where e.read() itself raises
    229     _parse_bing_results block without <h2><a> link
    282     check_email_breach HackerTarget unavailable (resp not ok)
    304-305 check_email_breach HIBP non-404 error
    362-363 verify_email DNS-over-HTTPS general exception
    375-376 verify_email asyncio.to_thread fallback exception
    406-407 google_dorking pages not int → default 1
    584     wayback domain with "://" scheme
    591-592 wayback limit not int → default 20
    601     wayback CDX returns None (unparseable body)
    613     wayback row malformed (not list or len < 3)
    648     ip_geolocation data None or not dict
    672     ip_geolocation AbuseIPDB configured but invalid response
    721-722 username_recon _fetch raises inside _check
    755     github_recon GITHUB_TOKEN set → Authorization header
    761-766 github_recon 404 / 403 / other error

All network I/O mocked — no real traffic.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.osint_recon import (
    _fetch,
    _parse_bing_results,
    check_email_breach,
    github_recon,
    google_dorking,
    ip_geolocation,
    username_recon,
    verify_email,
    wayback_machine_lookup,
)


# ── fakes ────────────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal file-like urllib response."""

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


class _BadReader:
    """File-like whose read() always raises — for HTTPError err_body fallback."""

    def read(self, n=-1):
        raise IOError("simulated read failure")


def _http_error(code: int, body=b""):
    """Build a real urllib HTTPError."""
    return urllib.error.HTTPError(
        "http://example.invalid", code, "err", {}, io.BytesIO(body)
    )


def _http_error_bad_reader(code: int):
    """Build an HTTPError whose .read() raises (covers lines 165-166)."""
    return urllib.error.HTTPError(
        "http://example.invalid", code, "err", {}, _BadReader()
    )


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Ensure no optional API keys leak between tests."""
    for key in (
        "HIBP_API_KEY", "GITHUB_TOKEN", "NUMVERIFY_API_KEY",
        "IPINFO_TOKEN", "ABUSEIPDB_API_KEY", "ABUSEIPDB_KEY",
        "TINEYE_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


# ════════════════════════════════════════════════════════════════
#  Lines 165-166: _fetch HTTPError where e.read() raises
# ════════════════════════════════════════════════════════════════


async def test_fetch_http_error_read_fails():
    """HTTPError whose .read() raises → err_body falls back to empty string."""
    with patch("urllib.request.urlopen", side_effect=_http_error_bad_reader(500)):
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is False
    assert resp["status"] == 500
    assert resp["body"] == ""


# ════════════════════════════════════════════════════════════════
#  Line 229: _parse_bing_results block without link
# ════════════════════════════════════════════════════════════════


def test_parse_bing_results_block_without_link():
    """A b_algo block with no <h2><a> link is skipped via continue (line 229)."""
    html = '<ol id="b_results"><li class="b_algo"><div>no link here</div></li></ol>'
    results = _parse_bing_results(html)
    assert results == []


# ════════════════════════════════════════════════════════════════
#  Line 282: check_email_breach HackerTarget unavailable
# ════════════════════════════════════════════════════════════════


async def test_check_email_breach_hackertarget_network_error():
    """When HackerTarget fetch fails (resp not ok), note gets the error (line 282)."""
    async def fake_fetch(url, timeout=10.0, headers=None, method="GET", data=None):
        return {"ok": False, "status": None, "error": "Network error: refused", "body": ""}
    with patch("backend.osint_recon._fetch", side_effect=fake_fetch):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert "HackerTarget unavailable" in (result["note"] or "")


# ════════════════════════════════════════════════════════════════
#  Lines 304-305: check_email_breach HIBP non-404 error
# ════════════════════════════════════════════════════════════════


async def test_check_email_breach_hibp_500_error(monkeypatch):
    """HIBP configured + returns 500 (not 404) → note includes HIBP unavailable."""
    monkeypatch.setenv("HIBP_API_KEY", "test-key")

    async def fake_fetch(url, timeout=10.0, headers=None, method="GET", data=None):
        if "hackertarget" in url:
            return {"ok": True, "status": 200, "text": ""}
        return {"ok": False, "status": 500, "error": "HTTP 500", "body": ""}

    with patch("backend.osint_recon._fetch", side_effect=fake_fetch):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert "HIBP unavailable" in (result["note"] or "")


# ════════════════════════════════════════════════════════════════
#  Lines 362-363: verify_email DNS-over-HTTPS general exception
# ════════════════════════════════════════════════════════════════


async def test_verify_email_dns_over_https_exception(monkeypatch):
    """When _fetch raises (patched to raise), the outer except catches it (362-363)."""
    async def boom(*a, **kw):
        raise RuntimeError("simulated _fetch crash")

    with patch("backend.osint_recon._fetch", side_effect=boom):
        with patch("socket.getaddrinfo", return_value=[]):
            result = await verify_email("user@example.com")
    assert result["ok"] is True
    assert result["valid_format"] is True
    assert result["domain_resolves"] is False


# ════════════════════════════════════════════════════════════════
#  Lines 375-376: verify_email asyncio.to_thread fallback exception
# ════════════════════════════════════════════════════════════════


async def test_verify_email_to_thread_fallback_exception(monkeypatch):
    """When asyncio.to_thread raises, domain_resolves falls to False (375-376)."""
    # dns.google returns NXDOMAIN so domain_resolves=False → enters fallback
    dns_json = json.dumps({"Status": 3, "Comment": "NXDOMAIN"}).encode()
    with patch("urllib.request.urlopen", return_value=_FakeResp(dns_json, 200)):
        with patch("asyncio.to_thread", side_effect=RuntimeError("thread crash")):
            result = await verify_email("nobody@example.com")
    assert result["ok"] is True
    assert result["domain_resolves"] is False


# ════════════════════════════════════════════════════════════════
#  Lines 406-407: google_dorking pages not int
# ════════════════════════════════════════════════════════════════


async def test_google_dorking_pages_not_int():
    """pages='abc' triggers TypeError → defaults to 1 (lines 406-407)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"", 200)):
        result = await google_dorking("test query", pages="abc")
    assert result["ok"] is True
    assert result["pages"] == 1


async def test_google_dorking_pages_none():
    """pages=None triggers TypeError → defaults to 1."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"", 200)):
        result = await google_dorking("test query", pages=None)
    assert result["ok"] is True
    assert result["pages"] == 1


# ════════════════════════════════════════════════════════════════
#  Line 584: wayback domain with scheme
# ════════════════════════════════════════════════════════════════


async def test_wayback_domain_with_scheme():
    """Domain with '://' gets netloc extracted (line 584)."""
    cdx = json.dumps([
        ["timestamp", "original", "statuscode"],
        ["20240101", "example.com/", "200"],
    ]).encode()
    with patch("urllib.request.urlopen", return_value=_FakeResp(cdx, 200)):
        result = await wayback_machine_lookup("https://example.com")
    assert result["ok"] is True
    assert result["domain"] == "example.com"


# ════════════════════════════════════════════════════════════════
#  Lines 591-592: wayback limit not int
# ════════════════════════════════════════════════════════════════


async def test_wayback_limit_not_int():
    """limit='abc' triggers ValueError → defaults to 20 (lines 591-592)."""
    cdx = json.dumps([
        ["timestamp", "original", "statuscode"],
        ["20240101", "example.com/", "200"],
    ]).encode()
    with patch("urllib.request.urlopen", return_value=_FakeResp(cdx, 200)):
        result = await wayback_machine_lookup("example.com", limit="abc")
    assert result["ok"] is True
    assert result["limit"] == 20


# ════════════════════════════════════════════════════════════════
#  Line 601: wayback CDX returns None (unparseable body)
# ════════════════════════════════════════════════════════════════


async def test_wayback_cdx_unparseable():
    """When CDX body is not JSON, _parse_json returns None → error (line 601)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"not json at all", 200)):
        result = await wayback_machine_lookup("example.com")
    assert result["ok"] is False
    assert "unavailable" in (result.get("error") or "").lower() or \
           "error" in (result.get("error") or "").lower()


# ════════════════════════════════════════════════════════════════
#  Line 613: wayback row malformed (not list or len < 3)
# ════════════════════════════════════════════════════════════════


async def test_wayback_row_malformed():
    """Rows that are not lists or have < 3 elements are skipped (line 613)."""
    cdx = json.dumps([
        ["timestamp", "original", "statuscode"],
        "not-a-list",
        ["only-two", "cols"],
        ["20240101", "example.com/", "200"],
    ]).encode()
    with patch("urllib.request.urlopen", return_value=_FakeResp(cdx, 200)):
        result = await wayback_machine_lookup("example.com")
    assert result["ok"] is True
    assert result["total"] == 1  # only the valid row


# ════════════════════════════════════════════════════════════════
#  Line 648: ip_geolocation data None or not dict
# ════════════════════════════════════════════════════════════════


async def test_ip_geolocation_data_not_dict():
    """When ipinfo returns a JSON list (not dict), error is returned (line 648)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b'["not", "a", "dict"]', 200)):
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is False
    assert "ipinfo" in (result.get("error") or "").lower() or \
           "geo" in (result.get("error") or "").lower()


async def test_ip_geolocation_unparseable():
    """When ipinfo returns non-JSON, _parse_json returns None → error (line 648)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"<<<html>>>", 200)):
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is False


# ════════════════════════════════════════════════════════════════
#  Line 672: ip_geolocation AbuseIPDB configured but invalid response
# ════════════════════════════════════════════════════════════════


async def test_ip_geolocation_abuse_error(monkeypatch):
    """AbuseIPDB key set but response is not valid → abuse dict has error (672)."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")

    def fake(req, timeout=None):
        url = req.full_url
        if "ipinfo.io" in url:
            return _FakeResp(b'{"city": "MTV", "country": "US"}', 200)
        if "abuseipdb" in url:
            return _FakeResp(b'{"unexpected": true}', 200)
        return _FakeResp(b"", 200)

    with patch("urllib.request.urlopen", fake):
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is True
    assert result["abuse"] is not None
    assert "error" in result["abuse"]


# ════════════════════════════════════════════════════════════════
#  Lines 721-722: username_recon _fetch raises inside _check
# ════════════════════════════════════════════════════════════════


async def test_username_recon_fetch_exception():
    """When _fetch raises inside _check, the exception is caught per-platform (721-722)."""
    async def boom(*a, **kw):
        raise RuntimeError("simulated crash")

    with patch("backend.osint_recon._fetch", side_effect=boom):
        result = await username_recon("testuser")
    assert result["ok"] is True
    assert result["checked"] > 0
    for p in result["profiles"]:
        assert p["exists"] is False
        assert p["error"] is not None


# ════════════════════════════════════════════════════════════════
#  Line 755: github_recon with GITHUB_TOKEN set
# ════════════════════════════════════════════════════════════════


async def test_github_recon_with_token(monkeypatch):
    """GITHUB_TOKEN set → Authorization header is added (line 755)."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token")

    user_json = json.dumps({
        "login": "testuser", "name": "Test User", "bio": "bio",
        "public_repos": 5, "followers": 10, "following": 3,
        "html_url": "https://github.com/testuser",
        "avatar_url": "https://github.com/testuser.png",
        "created_at": "2020-01-01T00:00:00Z",
    }).encode()
    repos_json = json.dumps([
        {"name": "repo1", "html_url": "https://github.com/testuser/repo1",
         "stargazers_count": 5, "language": "Python", "description": "test"},
    ]).encode()

    async def fake_fetch(url, timeout=10.0, headers=None, method="GET", data=None):
        if "/repos" in url:
            return {"ok": True, "status": 200, "text": repos_json.decode()}
        return {"ok": True, "status": 200, "text": user_json.decode()}

    mock_fetch = AsyncMock(side_effect=fake_fetch)
    with patch("backend.osint_recon._fetch", mock_fetch):
        result = await github_recon("testuser")
    assert result["ok"] is True
    assert result["profile"]["login"] == "testuser"
    # Verify the Authorization header was set (line 755)
    first_call = mock_fetch.call_args_list[0]
    headers_passed = first_call.kwargs.get("headers") or {}
    assert headers_passed.get("Authorization") == "token ghp_test_token"


# ════════════════════════════════════════════════════════════════
#  Lines 761-766: github_recon 404 / 403 / other error
# ════════════════════════════════════════════════════════════════


async def test_github_recon_404():
    """GitHub 404 → 'User not found' (lines 762-763)."""
    async def fake_fetch(url, timeout=10.0, headers=None, method="GET", data=None):
        return {"ok": False, "status": 404, "error": "HTTP 404", "body": ""}
    with patch("backend.osint_recon._fetch", side_effect=fake_fetch):
        result = await github_recon("nonexistentuser12345")
    assert result["ok"] is False
    assert "not found" in result["error"].lower()


async def test_github_recon_403():
    """GitHub 403 → rate limited message (lines 764-765)."""
    async def fake_fetch(url, timeout=10.0, headers=None, method="GET", data=None):
        return {"ok": False, "status": 403, "error": "HTTP 403", "body": ""}
    with patch("backend.osint_recon._fetch", side_effect=fake_fetch):
        result = await github_recon("testuser")
    assert result["ok"] is False
    assert "rate" in result["error"].lower() or "limit" in result["error"].lower()


async def test_github_recon_500():
    """GitHub 500 → generic unavailable error (line 766)."""
    async def fake_fetch(url, timeout=10.0, headers=None, method="GET", data=None):
        return {"ok": False, "status": 500, "error": "HTTP 500", "body": ""}
    with patch("backend.osint_recon._fetch", side_effect=fake_fetch):
        result = await github_recon("testuser")
    assert result["ok"] is False
    assert "unavailable" in result["error"].lower() or "HTTP" in result["error"]
