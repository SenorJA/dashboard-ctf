"""
tests/test_osint_recon.py — Passive OSINT recon module (BlackTrace port).

Unit tests for ``backend/osint_recon.py`` (all network I/O mocked at
``urllib.request.urlopen`` / ``socket``) plus endpoint tests for the
``/api/osint/*`` routes in ``main.py`` (module functions patched via
``@patch("backend.osint_recon.<func>")``).

Run:
    python -m pytest backend/tests/test_osint_recon.py -q
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import socket
import sys
import urllib.error
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402
from backend.osint_recon import (  # noqa: E402
    TIMEOUT_DEFAULT,
    USER_AGENT,
    _fetch,
    _parse_ddg_results,
    _parse_json,
    check_email_breach,
    github_recon,
    google_dorking,
    ip_geolocation,
    phone_number_lookup,
    reverse_image_search,
    username_recon,
    verify_email,
    wayback_machine_lookup,
)

# ──────────────────────────────────────────────────────────────
#  Fakes
# ──────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal file-like response compatible with urllib response usage."""

    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self._body = body
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        if n is None or n < 0:
            return self._body
        return self._body[:n]


def _fake_urlopen(body: bytes, status: int = 200):
    """Return a MagicMock urlopen that always yields the same response."""

    def fake(req, timeout=None):
        return _FakeResp(body, status)

    return MagicMock(side_effect=fake)


def _http_error(code: int, body: bytes = b""):
    """Build a real urllib HTTPError for the _fetch error branches."""
    return urllib.error.HTTPError("http://example.invalid", code, "err", {}, io.BytesIO(body))


DDG_HTML = """
<html><body>
<div class="result">
  <h2 class="result__title">
    <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&amp;rut=abc">Example Title</a>
  </h2>
  <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&amp;rut=abc">Example snippet text &amp; more</a>
</div>
</body></html>
"""

BING_HTML = """
<ol id="b_results">
<li class="b_algo">
  <h2><a href="https://example.com/bing-page">Bing Title</a></h2>
  <div class="b_caption"><p>Bing snippet here</p></div>
</li>
</ol>
"""

CDX_JSON = json.dumps([
    ["timestamp", "original", "statuscode"],
    ["20240101120000", "example.com/", "200"],
    ["20240202130000", "example.com/about", "404"],
])


@pytest.fixture(autouse=True)
def _clear_osint_env(monkeypatch):
    """Ensure no optional API keys leak between tests."""
    for key in (
        "HIBP_API_KEY",
        "GITHUB_TOKEN",
        "NUMVERIFY_API_KEY",
        "IPINFO_TOKEN",
        "ABUSEIPDB_API_KEY",
        "ABUSEIPDB_KEY",
        "TINEYE_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.fixture()
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _patch_db_unavailable():
    """Neutralize Supabase during app startup handlers (as other suites do)."""
    with patch("backend.database.is_available", return_value=False), \
         patch("backend.database.get_client", return_value=None):
        yield


# ════════════════════════════════════════════════════════════════
#  _fetch helper
# ════════════════════════════════════════════════════════════════


async def test_fetch_ok_returns_text_and_headers():
    """_fetch returns status + decoded text and sends a MIRV User-Agent."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b'{"a": 1}', 200)) as m:
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is True
    assert resp["status"] == 200
    assert json.loads(resp["text"]) == {"a": 1}
    req = m.call_args[0][0]
    assert req.get_method() == "GET"
    assert "MIRV-OSINT" in (req.get_header("User-agent") or "")


async def test_fetch_http_error_returns_code_and_body():
    """_fetch maps HTTP errors to ok=False with the status code."""
    with patch("urllib.request.urlopen", side_effect=_http_error(500, b"boom")):
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is False
    assert resp["status"] == 500
    assert resp["body"] == "boom"


async def test_fetch_urlerror_returns_network_error():
    """_fetch maps URLError (connection refused) to a clean error dict."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is False
    assert "Network error" in resp["error"]


async def test_fetch_timeout_returns_timeout_error():
    """_fetch maps socket.timeout to a timeout error dict."""
    with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is False
    assert "Timeout" in resp["error"]


async def test_fetch_generic_exception_is_caught():
    """_fetch never raises — unexpected exceptions become error dicts."""
    with patch("urllib.request.urlopen", side_effect=ValueError("weird")):
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is False
    assert resp["error"] == "weird"


async def test_fetch_head_method():
    """_fetch forwards the requested HTTP method (used by username_recon)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"", 200)) as m:
        resp = await _fetch("https://example.com/x", method="HEAD")
    assert resp["ok"] is True
    assert m.call_args[0][0].get_method() == "HEAD"


def test_parse_json_ok_and_error_body():
    """_parse_json parses success text and HTTP-error bodies."""
    assert _parse_json({"ok": True, "text": '{"a": 1}'}) == {"a": 1}
    assert _parse_json({"ok": False, "body": '{"m": "nope"}'}) == {"m": "nope"}
    assert _parse_json({"ok": True, "text": "not json"}) is None
    assert _parse_json({"ok": False, "body": ""}) is None


def test_parse_ddg_results_resolves_redirect():
    """DDG parser resolves /l/?uddg= redirects and captures snippets."""
    results = _parse_ddg_results(DDG_HTML)
    assert len(results) == 1
    assert results[0]["url"] == "https://example.com/page"
    assert results[0]["title"] == "Example Title"
    assert results[0]["snippet"] == "Example snippet text & more"
    assert results[0]["engine"] == "duckduckgo"


def test_parse_ddg_results_skips_non_http_links():
    """DDG parser drops relative/anchor-only hrefs."""
    html_page = '<a rel="nofollow" class="result__a" href="#top">Jump</a>'
    assert _parse_ddg_results(html_page) == []


# ════════════════════════════════════════════════════════════════
#  check_email_breach
# ════════════════════════════════════════════════════════════════


async def test_check_email_breach_found():
    """Pastebin lookup with paste URLs marks the email as found."""
    with patch("urllib.request.urlopen", _fake_urlopen(
        b"https://pastebin.com/abc\nhttps://pastebin.com/def\n", 200
    )):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert result["found"] is True
    assert result["paste_urls"] == ["https://pastebin.com/abc", "https://pastebin.com/def"]
    assert result["breaches"] == []
    assert result["source"] == "hackertarget"


async def test_check_email_breach_not_found():
    """Empty HackerTarget response means no pastes found."""
    with patch("urllib.request.urlopen", _fake_urlopen(b"", 200)):
        result = await check_email_breach("nobody@example.com")
    assert result["ok"] is True
    assert result["found"] is False
    assert result["paste_urls"] == []


async def test_check_email_breach_invalid_format():
    """Invalid email formats return an error without network I/O."""
    result = await check_email_breach("not-an-email")
    assert result["ok"] is False
    assert "Invalid" in result["error"]


async def test_check_email_breach_network_error():
    """A failed HackerTarget request degrades to a not-found + note."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert result["found"] is False
    assert "HackerTarget unavailable" in (result["note"] or "")


async def test_check_email_breach_hackertarget_error_line():
    """HackerTarget 'error ...' responses are treated as no data + note."""
    with patch("urllib.request.urlopen", _fake_urlopen(b"error invalid ip\n", 200)):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert result["found"] is False
    assert "error invalid ip" in (result["note"] or "")


async def test_check_email_breach_hibp_found(monkeypatch):
    """With HIBP_API_KEY set, breach names are attached to the result."""
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    calls = {"n": 0}

    def fake(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResp(b"https://pastebin.com/abc", 200)
        # urllib capitalizes header keys — compare case-insensitively.
        lower_headers = {k.lower(): v for k, v in req.headers.items()}
        assert lower_headers.get("hibp-api-key") == "test-key"
        return _FakeResp(json.dumps([
            {"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Emails"], "Description": "d"}
        ]).encode(), 200)

    with patch("urllib.request.urlopen", fake):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert result["found"] is True
    assert result["breaches"][0]["name"] == "Adobe"
    assert result["breaches"][0]["date"] == "2013-10-04"
    assert result["source"] == "hackertarget+hibp"


async def test_check_email_breach_hibp_404(monkeypatch):
    """HIBP 404 means no breaches — result stays found=False."""
    monkeypatch.setenv("HIBP_API_KEY", "test-key")

    def fake(req, timeout=None):
        if req.full_url.startswith("https://api.hackertarget.com"):
            return _FakeResp(b"", 200)
        raise _http_error(404)

    with patch("urllib.request.urlopen", fake):
        result = await check_email_breach("nobody@example.com")
    assert result["ok"] is True
    assert result["found"] is False
    assert result["breaches"] == []


async def test_check_email_breach_hibp_unavailable(monkeypatch):
    """HIBP errors other than 404 become a note, not a crash."""
    monkeypatch.setenv("HIBP_API_KEY", "test-key")

    def fake(req, timeout=None):
        if req.full_url.startswith("https://api.hackertarget.com"):
            return _FakeResp(b"", 200)
        raise _http_error(429)

    with patch("urllib.request.urlopen", fake):
        result = await check_email_breach("user@example.com")
    assert result["ok"] is True
    assert "HIBP unavailable" in (result["note"] or "")


# ════════════════════════════════════════════════════════════════
#  verify_email
# ════════════════════════════════════════════════════════════════


async def test_verify_email_valid_with_mx():
    """Valid format + MX answers from dns.google produce MX records."""
    dns_json = json.dumps({
        "Status": 0,
        "Answer": [
            {"name": "example.com.", "type": 15, "TTL": 3600, "data": "20 mx2.example.com."},
            {"name": "example.com.", "type": 15, "TTL": 3600, "data": "10 mail.example.com."},
        ],
    }).encode()
    with patch("urllib.request.urlopen", _fake_urlopen(dns_json)):
        result = await verify_email("user@example.com")
    assert result["ok"] is True
    assert result["valid_format"] is True
    assert result["domain"] == "example.com"
    assert result["mx_records"] == ["10 mail.example.com", "20 mx2.example.com"]
    assert result["domain_resolves"] is True
    assert result["disposable"] is False


async def test_verify_email_invalid_format():
    """Malformed emails return valid_format=False."""
    result = await verify_email("nope@@example")
    assert result["ok"] is True
    assert result["valid_format"] is False
    assert result["mx_records"] == []


async def test_verify_email_disposable_domain():
    """Known disposable domains are flagged without network I/O."""
    with patch("urllib.request.urlopen", _fake_urlopen(b'{"Status": 0, "Answer": []}', 200)):
        result = await verify_email("x@mailinator.com")
    assert result["ok"] is True
    assert result["disposable"] is True
    assert result["valid_format"] is True


async def test_verify_email_nxdomain(monkeypatch):
    """NXDOMAIN (Status 3) yields domain_resolves=False via DNS fallback."""
    with patch("urllib.request.urlopen", _fake_urlopen(b'{"Status": 3, "Comment": "NXDOMAIN"}', 200)):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nxdomain")):
            result = await verify_email("nobody@example.com")
    assert result["ok"] is True
    assert result["domain_resolves"] is False
    assert result["mx_records"] == []


async def test_verify_email_dns_fallback(monkeypatch):
    """When dns.google fails, plain DNS resolution still resolves the domain."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]):
            result = await verify_email("user@example.com")
    assert result["ok"] is True
    assert result["valid_format"] is True
    assert result["domain_resolves"] is True


# ════════════════════════════════════════════════════════════════
#  google_dorking
# ════════════════════════════════════════════════════════════════


async def test_google_dorking_parses_results():
    """DuckDuckGo + Bing HTML results are parsed into title/url/snippet."""
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(DDG_HTML.encode(), 200),
        _FakeResp(BING_HTML.encode(), 200),
    ]):
        result = await google_dorking("site:example.com filetype:pdf")
    assert result["ok"] is True
    assert result["engine"] == "duckduckgo+bing"
    urls = [r["url"] for r in result["results"]]
    assert "https://example.com/page" in urls
    assert "https://example.com/bing-page" in urls
    bing = next(r for r in result["results"] if r["engine"] == "bing")
    assert bing["snippet"] == "Bing snippet here"
    assert result["search_urls"]["google"].startswith("https://www.google.com/search?q=")


async def test_google_dorking_empty_query():
    """Empty queries return an error dict."""
    result = await google_dorking("   ")
    assert result["ok"] is False


async def test_google_dorking_pages_fetch_count():
    """pages=N issues N requests per engine (2 engines)."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b"", 200)) as m:
        result = await google_dorking("test", pages=2)
    assert result["ok"] is True
    assert result["pages"] == 2
    assert m.call_count == 4


async def test_google_dorking_dedupes_results():
    """The same URL from both engines is only reported once."""
    bing_dup = BING_HTML.replace("https://example.com/bing-page", "https://example.com/page")
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(DDG_HTML.encode(), 200),
        _FakeResp(bing_dup.encode(), 200),
    ]):
        result = await google_dorking("test")
    assert result["ok"] is True
    assert result["result_count"] == 1


async def test_google_dorking_network_error_degrades():
    """Failed search fetches produce an empty (but ok) result set."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        result = await google_dorking("test")
    assert result["ok"] is True
    assert result["results"] == []


# ════════════════════════════════════════════════════════════════
#  phone_number_lookup
# ════════════════════════════════════════════════════════════════


async def test_phone_number_lookup_numverify(monkeypatch):
    """With NUMVERIFY_API_KEY, carrier/line-type are resolved."""
    monkeypatch.setenv("NUMVERIFY_API_KEY", "test-key")
    payload = json.dumps({
        "valid": True, "country_name": "Spain", "carrier": "Vodafone", "line_type": "mobile",
    }).encode()
    with patch("urllib.request.urlopen", _fake_urlopen(payload)) as m:
        result = await phone_number_lookup("+34 612 345 678")
    assert result["ok"] is True
    assert result["phone"] == "+34612345678"
    assert result["country"] == "Spain"
    assert result["carrier"] == "Vodafone"
    assert result["line_type"] == "mobile"
    assert result["valid"] is True
    assert "numverify.com" in m.call_args[0][0].full_url


async def test_phone_number_lookup_no_key_web_fallback():
    """Without a key, a passive DDG search provides context snippets."""
    with patch("urllib.request.urlopen", _fake_urlopen(DDG_HTML.encode(), 200)):
        result = await phone_number_lookup("+14155551234")
    assert result["ok"] is True
    assert result["phone"] == "+14155551234"
    assert result["country"] is None
    assert len(result["web_results"]) >= 1
    assert "NUMVERIFY_API_KEY" in (result["note"] or "")


async def test_phone_number_lookup_key_bad_response_falls_back(monkeypatch):
    """A bad numverify response degrades to the public fallback."""
    monkeypatch.setenv("NUMVERIFY_API_KEY", "test-key")
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(b'{"success": false}', 200),
        _FakeResp(DDG_HTML.encode(), 200),
    ]):
        result = await phone_number_lookup("+14155551234")
    assert result["ok"] is True
    assert result["country"] is None
    assert len(result["web_results"]) >= 1


async def test_phone_number_lookup_invalid():
    """Too-short numbers return an error dict."""
    result = await phone_number_lookup("123")
    assert result["ok"] is False
    assert "Invalid phone number" in result["error"]


# ════════════════════════════════════════════════════════════════
#  reverse_image_search
# ════════════════════════════════════════════════════════════════


async def test_reverse_image_search_tineye(monkeypatch):
    """With TINEYE_API_KEY, TinEye API results are returned."""
    monkeypatch.setenv("TINEYE_API_KEY", "test-key")
    payload = json.dumps({
        "results": [
            {"image_name": "photo.jpg", "backlink_title": "Match 1",
             "backlink_url": "https://example.com/match", "image_url": "https://cdn.example.com/i.jpg"}
        ]
    }).encode()
    with patch("urllib.request.urlopen", _fake_urlopen(payload)) as m:
        result = await reverse_image_search("https://example.com/photo.jpg")
    assert result["ok"] is True
    assert result["engine"] == "tineye"
    assert result["results"][0]["title"] == "Match 1"
    assert result["results"][0]["source"] == "tineye"
    assert "api.tineye.com" in m.call_args[0][0].full_url


async def test_reverse_image_search_ddg_fallback():
    """Without a key, a passive DDG search + engine URLs are returned."""
    with patch("urllib.request.urlopen", _fake_urlopen(DDG_HTML.encode(), 200)):
        result = await reverse_image_search("https://example.com/photo.jpg")
    assert result["ok"] is True
    assert result["engine"] == "duckduckgo"
    assert result["results"][0]["url"] == "https://example.com/page"
    assert "Google Lens" in result["engines"]
    assert "No TINEYE_API_KEY" in (result["note"] or "")


async def test_reverse_image_search_invalid_url():
    """Non-http image URLs return an error dict."""
    result = await reverse_image_search("not-a-url")
    assert result["ok"] is False


# ════════════════════════════════════════════════════════════════
#  wayback_machine_lookup
# ════════════════════════════════════════════════════════════════


async def test_wayback_machine_lookup_parses():
    """CDX JSON rows become timestamp/url/status/archive_url snapshots."""
    with patch("urllib.request.urlopen", _fake_urlopen(CDX_JSON.encode(), 200)) as m:
        result = await wayback_machine_lookup("example.com", limit=5)
    assert result["ok"] is True
    assert result["total"] == 2
    snap = result["snapshots"][0]
    assert snap["timestamp"] == "20240101120000"
    assert snap["url"] == "example.com/"
    assert snap["status"] == "200"
    assert snap["archive_url"] == "https://web.archive.org/web/20240101120000/example.com/"
    assert result["snapshots"][1]["status"] == "404"
    req = m.call_args[0][0]
    assert "collapse=urlkey" in req.full_url and "limit=5" in req.full_url


async def test_wayback_machine_lookup_empty():
    """An empty CDX array means no archived snapshots."""
    with patch("urllib.request.urlopen", _fake_urlopen(b"[]", 200)):
        result = await wayback_machine_lookup("example.com")
    assert result["ok"] is True
    assert result["total"] == 0
    assert result["snapshots"] == []


async def test_wayback_machine_lookup_invalid_domain():
    """Invalid domains return an error without network I/O."""
    result = await wayback_machine_lookup("not a domain")
    assert result["ok"] is False


async def test_wayback_machine_lookup_network_error():
    """CDX API failures surface as clean error dicts."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        result = await wayback_machine_lookup("example.com")
    assert result["ok"] is False
    assert "error" in result


async def test_wayback_machine_lookup_unexpected_payload():
    """Non-list CDX payloads are rejected cleanly."""
    with patch("urllib.request.urlopen", _fake_urlopen(b'{"error": "boom"}', 200)):
        result = await wayback_machine_lookup("example.com")
    assert result["ok"] is False
    assert "unexpected payload" in result["error"]


# ════════════════════════════════════════════════════════════════
#  ip_geolocation
# ════════════════════════════════════════════════════════════════


async def test_ip_geolocation_success():
    """ipinfo.io payload is mapped to flat geolocation fields."""
    payload = json.dumps({
        "ip": "8.8.8.8", "city": "Mountain View", "region": "California", "country": "US",
        "org": "AS15169 Google LLC", "loc": "37.4056,-122.0775", "postal": "94043",
        "timezone": "America/Los_Angeles", "hostname": "dns.google",
    }).encode()
    with patch("urllib.request.urlopen", _fake_urlopen(payload)) as m:
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is True
    assert result["ip"] == "8.8.8.8"
    assert result["city"] == "Mountain View"
    assert result["org"] == "AS15169 Google LLC"
    assert result["loc"] == "37.4056,-122.0775"
    assert result["abuse"] is None
    assert "ipinfo.io/8.8.8.8/json" in m.call_args[0][0].full_url


async def test_ip_geolocation_invalid_ip():
    """Invalid IP syntax returns an error dict."""
    result = await ip_geolocation("999.999.999.999")
    assert result["ok"] is False
    assert "Invalid IP" in result["error"]


async def test_ip_geolocation_abuseipdb(monkeypatch):
    """With ABUSEIPDB_API_KEY, the abuse block is populated."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(b'{"ip": "8.8.8.8", "city": "X", "country": "US", "org": "AS1", "loc": "0,0"}', 200),
        _FakeResp(json.dumps({
            "data": {"abuseConfidenceScore": 100, "totalReports": 25,
                     "reports": [{"reportedAt": "2026-01-01", "comment": "spam"}]}
        }).encode(), 200),
    ]) as m:
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is True
    assert result["abuse"]["abuse_confidence_score"] == 100
    assert result["abuse"]["total_reports"] == 25
    assert result["abuse"]["reports_90d"][0]["comment"] == "spam"
    assert "api.abuseipdb.com" in m.call_args[0][0].full_url


async def test_ip_geolocation_abuseipdb_failure(monkeypatch):
    """A failed AbuseIPDB call is surfaced inside the abuse block."""
    monkeypatch.setenv("ABUSEIPDB_KEY", "legacy-key")
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(b'{"ip": "8.8.8.8", "city": "X", "country": "US"}', 200),
        urllib.error.URLError("refused"),
    ]):
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is True
    assert result["abuse"]["error"]


async def test_ip_geolocation_failure():
    """ipinfo.io failures surface as clean error dicts."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        result = await ip_geolocation("8.8.8.8")
    assert result["ok"] is False


# ════════════════════════════════════════════════════════════════
#  username_recon
# ════════════════════════════════════════════════════════════════


async def test_username_recon_exists_and_missing():
    """HEAD probes mark 200 as exists and 404/errors as missing."""
    def fake(req, timeout=None):
        url = req.full_url
        if "reddit.com/" in url:
            raise _http_error(404)
        if "twitch.tv/" in url:
            raise urllib.error.URLError("conn refused")
        return _FakeResp(b"", 200)

    with patch("urllib.request.urlopen", MagicMock(side_effect=fake)) as m:
        result = await username_recon("target1")
    assert result["ok"] is True
    assert result["checked"] == 18
    assert result["found"] == 16
    github = next(p for p in result["profiles"] if p["platform"] == "GitHub")
    assert github["exists"] is True
    assert github["status_code"] == 200
    reddit = next(p for p in result["profiles"] if p["platform"] == "Reddit")
    assert reddit["exists"] is False
    assert reddit["status_code"] == 404
    twitch = next(p for p in result["profiles"] if p["platform"] == "Twitch")
    assert twitch["exists"] is False
    assert twitch["error"]
    # HEAD requests are used (no GET bodies).
    assert all(call.args[0].get_method() == "HEAD" for call in m.call_args_list)


async def test_username_recon_timeout():
    """Per-request timeouts produce exists=False with a timeout error."""
    with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        result = await username_recon("target2")
    assert result["ok"] is True
    assert all(p["exists"] is False for p in result["profiles"])
    assert any("Timeout" in (p["error"] or "") for p in result["profiles"])


async def test_username_recon_invalid_username():
    """Invalid usernames return an error dict."""
    result = await username_recon("bad name!!")
    assert result["ok"] is False
    result = await username_recon("")
    assert result["ok"] is False


# ════════════════════════════════════════════════════════════════
#  github_recon
# ════════════════════════════════════════════════════════════════

GITHUB_USER = {
    "login": "octocat", "name": "The Octocat", "bio": "octocat",
    "public_repos": 8, "public_gists": 8, "followers": 20, "following": 0,
    "created_at": "2011-01-25T18:44:36Z", "updated_at": "2016-06-21T22:25:22Z",
    "html_url": "https://github.com/octocat", "blog": "https://github.com/blog",
    "location": "San Francisco", "company": "GitHub", "twitter_username": None,
}
GITHUB_REPOS = [
    {"name": "Hello-World", "html_url": "https://github.com/octocat/Hello-World",
     "description": "My first repo", "language": "Python",
     "stargazers_count": 100, "forks_count": 5, "updated_at": "2024-01-01T00:00:00Z"},
]


async def test_github_recon_success():
    """GitHub user + repos are mapped into a profile and repo list."""
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(json.dumps(GITHUB_USER).encode(), 200),
        _FakeResp(json.dumps(GITHUB_REPOS).encode(), 200),
    ]) as m:
        result = await github_recon("octocat")
    assert result["ok"] is True
    assert result["found"] is True
    assert result["profile"]["login"] == "octocat"
    assert result["profile"]["followers"] == 20
    assert result["repos"][0]["name"] == "Hello-World"
    assert result["repos"][0]["stargazers_count"] == 100
    assert result["repo_count"] == 1
    assert "api.github.com/users/octocat" in m.call_args_list[0][0][0].full_url


async def test_github_recon_not_found():
    """GitHub 404 maps to a 'User not found' error dict."""
    with patch("urllib.request.urlopen", side_effect=_http_error(404, b'{"message": "Not Found"}')):
        result = await github_recon("ghost-user-12345")
    assert result["ok"] is False
    assert "not found" in result["error"].lower()


async def test_github_recon_rate_limited():
    """GitHub 403 maps to a rate-limit error dict."""
    with patch("urllib.request.urlopen", side_effect=_http_error(
        403, b'{"message": "API rate limit exceeded"}'
    )):
        result = await github_recon("octocat")
    assert result["ok"] is False
    assert "rate limited" in result["error"]


async def test_github_recon_network_error():
    """Network failures surface as clean error dicts."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        result = await github_recon("octocat")
    assert result["ok"] is False


async def test_github_recon_repos_failure_keeps_profile():
    """A failed repos fetch still returns the user profile."""
    with patch("urllib.request.urlopen", side_effect=[
        _FakeResp(json.dumps(GITHUB_USER).encode(), 200),
        _http_error(403),
    ]):
        result = await github_recon("octocat")
    assert result["ok"] is True
    assert result["profile"]["login"] == "octocat"
    assert result["repos"] == []


async def test_github_recon_invalid_json():
    """Non-JSON GitHub responses produce a clean error dict."""
    with patch("urllib.request.urlopen", _fake_urlopen(b"<html>not json</html>", 200)):
        result = await github_recon("octocat")
    assert result["ok"] is False
    assert "invalid JSON" in result["error"]


async def test_github_recon_invalid_username():
    """Invalid usernames return an error dict."""
    result = await github_recon("bad name!")
    assert result["ok"] is False


# ════════════════════════════════════════════════════════════════
#  /api/osint/* endpoints
# ════════════════════════════════════════════════════════════════


def test_email_endpoint_success(client):
    """POST /api/osint/email returns combined breach + verification data."""
    breach = {"ok": True, "email": "user@example.com", "found": True,
              "paste_urls": ["https://pastebin.com/abc"], "breaches": [],
              "source": "hackertarget", "note": None}
    verification = {"ok": True, "email": "user@example.com", "valid_format": True,
                    "domain": "example.com", "mx_records": ["10 mail.example.com"],
                    "disposable": False, "domain_resolves": True}
    with patch("backend.osint_recon.check_email_breach", new_callable=AsyncMock) as m_b, \
         patch("backend.osint_recon.verify_email", new_callable=AsyncMock) as m_v:
        m_b.return_value = breach
        m_v.return_value = verification
        resp = client.post("/api/osint/email", json={"email": "user@example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["breach"]["found"] is True
    assert data["verification"]["mx_records"] == ["10 mail.example.com"]
    m_b.assert_awaited_once_with("user@example.com")


def test_email_endpoint_empty_422(client):
    """Empty email body is rejected with 422."""
    resp = client.post("/api/osint/email", json={"email": ""})
    assert resp.status_code == 422


def test_email_endpoint_missing_body_422(client):
    """Missing required fields trigger Pydantic 422."""
    resp = client.post("/api/osint/email", json={})
    assert resp.status_code == 422


def test_email_endpoint_500(client):
    """Module exceptions become 500 JSON errors."""
    with patch("backend.osint_recon.check_email_breach", new_callable=AsyncMock,
               side_effect=RuntimeError("boom")):
        resp = client.post("/api/osint/email", json={"email": "user@example.com"})
    assert resp.status_code == 500
    assert resp.json()["ok"] is False


def test_dork_endpoint_success(client):
    """POST /api/osint/dork returns parsed dork results."""
    result = {"ok": True, "query": "site:example.com", "engine": "duckduckgo+bing",
              "pages": 1, "result_count": 1,
              "results": [{"title": "T", "url": "https://example.com/p", "snippet": "s", "engine": "bing"}],
              "search_urls": {"google": "https://www.google.com/search?q=x"}}
    with patch("backend.osint_recon.google_dorking", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.post("/api/osint/dork", json={"query": "site:example.com", "pages": 2})
    assert resp.status_code == 200
    assert resp.json()["result_count"] == 1
    m.assert_awaited_once_with("site:example.com", pages=2)


def test_dork_endpoint_empty_query_422(client):
    """Empty query body is rejected with 422."""
    resp = client.post("/api/osint/dork", json={"query": ""})
    assert resp.status_code == 422


def test_dork_endpoint_500(client):
    """Module exceptions become 500 JSON errors."""
    with patch("backend.osint_recon.google_dorking", new_callable=AsyncMock,
               side_effect=RuntimeError("boom")):
        resp = client.post("/api/osint/dork", json={"query": "test"})
    assert resp.status_code == 500


def test_phone_endpoint_success(client):
    """POST /api/osint/phone returns normalized phone data."""
    result = {"ok": True, "phone": "+14155551234", "country": "US", "carrier": None,
              "line_type": None, "valid": False, "web_results": [], "note": None}
    with patch("backend.osint_recon.phone_number_lookup", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.post("/api/osint/phone", json={"phone": "+14155551234"})
    assert resp.status_code == 200
    assert resp.json()["phone"] == "+14155551234"
    m.assert_awaited_once_with("+14155551234")


def test_phone_endpoint_422(client):
    """Missing body fields trigger Pydantic 422."""
    resp = client.post("/api/osint/phone", json={})
    assert resp.status_code == 422


def test_reverse_image_endpoint_success(client):
    """POST /api/osint/reverse-image returns engine results."""
    result = {"ok": True, "image_url": "https://example.com/a.jpg", "engine": "duckduckgo",
              "results": [], "engines": {"Google Lens": "https://lens.google.com"}, "note": None}
    with patch("backend.osint_recon.reverse_image_search", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.post("/api/osint/reverse-image", json={"image_url": "https://example.com/a.jpg"})
    assert resp.status_code == 200
    assert resp.json()["engine"] == "duckduckgo"
    m.assert_awaited_once_with("https://example.com/a.jpg")


def test_reverse_image_endpoint_422(client):
    """Missing body fields trigger Pydantic 422."""
    resp = client.post("/api/osint/reverse-image", json={})
    assert resp.status_code == 422


def test_wayback_endpoint_success(client):
    """GET /api/osint/wayback returns parsed snapshots."""
    result = {"ok": True, "domain": "example.com", "limit": 5, "total": 1,
              "snapshots": [{"timestamp": "20240101120000", "url": "example.com/", "status": "200",
                             "archive_url": "https://web.archive.org/web/x/example.com/"}]}
    with patch("backend.osint_recon.wayback_machine_lookup", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.get("/api/osint/wayback", params={"domain": "example.com", "limit": 5})
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
    m.assert_awaited_once_with("example.com", limit=5)


def test_wayback_endpoint_missing_domain_422(client):
    """Missing domain query param is rejected with 422."""
    resp = client.get("/api/osint/wayback")
    assert resp.status_code == 422


def test_wayback_endpoint_500(client):
    """Module exceptions become 500 JSON errors."""
    with patch("backend.osint_recon.wayback_machine_lookup", new_callable=AsyncMock,
               side_effect=RuntimeError("boom")):
        resp = client.get("/api/osint/wayback", params={"domain": "example.com"})
    assert resp.status_code == 500


def test_ip_endpoint_success(client):
    """GET /api/osint/ip returns geolocation fields."""
    result = {"ok": True, "ip": "8.8.8.8", "city": "Mountain View", "region": "California",
              "country": "US", "org": "AS15169 Google LLC", "loc": "37.4056,-122.0775",
              "postal": "94043", "timezone": "America/Los_Angeles", "hostname": "dns.google",
              "abuse": None}
    with patch("backend.osint_recon.ip_geolocation", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.get("/api/osint/ip", params={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    assert resp.json()["city"] == "Mountain View"
    m.assert_awaited_once_with("8.8.8.8")


def test_ip_endpoint_missing_422(client):
    """Missing ip query param is rejected with 422."""
    resp = client.get("/api/osint/ip")
    assert resp.status_code == 422


def test_username_endpoint_success(client):
    """POST /api/osint/username returns the platform probe list."""
    result = {"ok": True, "username": "target1", "checked": 18, "found": 1,
              "profiles": [{"platform": "GitHub", "url": "https://github.com/target1",
                            "exists": True, "status_code": 200, "error": None}]}
    with patch("backend.osint_recon.username_recon", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.post("/api/osint/username", json={"username": "target1"})
    assert resp.status_code == 200
    assert resp.json()["found"] == 1
    m.assert_awaited_once_with("target1")


def test_username_endpoint_422(client):
    """Missing body fields trigger Pydantic 422."""
    resp = client.post("/api/osint/username", json={})
    assert resp.status_code == 422


def test_github_endpoint_success(client):
    """GET /api/osint/github returns profile + repos."""
    result = {"ok": True, "found": True, "username": "octocat", "repo_count": 1,
              "profile": {"login": "octocat"}, "repos": [{"name": "Hello-World"}]}
    with patch("backend.osint_recon.github_recon", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.get("/api/osint/github", params={"username": "octocat"})
    assert resp.status_code == 200
    assert resp.json()["repos"][0]["name"] == "Hello-World"
    m.assert_awaited_once_with("octocat")


def test_github_endpoint_missing_422(client):
    """Missing username query param is rejected with 422."""
    resp = client.get("/api/osint/github")
    assert resp.status_code == 422


def test_github_endpoint_500(client):
    """Module exceptions become 500 JSON errors."""
    with patch("backend.osint_recon.github_recon", new_callable=AsyncMock,
               side_effect=RuntimeError("boom")):
        resp = client.get("/api/osint/github", params={"username": "octocat"})
    assert resp.status_code == 500
