"""
tests/test_instagram_osint.py — Instagram OSINT module (ghostig port).

Unit tests for ``backend/instagram_osint.py`` (all network I/O mocked at
``urllib.request.urlopen``) plus endpoint tests for ``POST /api/osint/instagram``
in ``main.py`` (module function patched via ``@patch("backend.instagram_osint
.get_instagram_profile")``).

IMPORTANT: every import uses the ``backend.`` package prefix — never
``from instagram_osint import ...`` (see AGENTS.md / TOMORROW.md § Postmortem).

Run:
    python -m pytest tests/test_instagram_osint.py -q --timeout=60 \
        --cov=backend.instagram_osint --cov-report=term-missing
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
from backend.instagram_osint import (  # noqa: E402
    DEFAULT_TIMEOUT,
    LOOKUP_URL,
    USER_AGENT,
    USER_INFO_URL,
    WEB_PROFILE_URL,
    LookupInsight,
    UserProfile,
    _fetch,
    _urlopen_sync,
    get_instagram_profile,
    instagram_lookup,
)

# ──────────────────────────────────────────────────────────────
#  Fakes
# ──────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal file-like response compatible with urllib usage."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        if n is None or n < 0:
            return self._body
        return self._body[:n]


def _router(responses: dict[str, tuple[int, object]]):
    """
    urlopen fake that routes on URL substrings.

    ``responses`` maps a URL substring to ``(status, payload)`` where
    payload is a JSON-serialisable object, a str (raw body) or an
    Exception instance (raised verbatim).  HTTP status >= 400 raises a
    real ``urllib.error.HTTPError`` like the production server does.
    """
    def fake(req, timeout=None):
        url = req.full_url
        for key in sorted(responses, key=len, reverse=True):
            if key in url:
                status, payload = responses[key]
                if isinstance(payload, Exception):
                    raise payload
                if isinstance(payload, str):
                    body = payload.encode("utf-8")
                else:
                    body = json.dumps(payload).encode("utf-8")
                if status >= 400:
                    raise urllib.error.HTTPError(url, status, "err", {}, io.BytesIO(body))
                return _FakeResp(body, status)
        raise AssertionError(f"no mock registered for {url}")
    return fake


# ──────────────────────────────────────────────────────────────
#  Fixtures + sample payloads
# ──────────────────────────────────────────────────────────────

SESSION = "test-session-abc123"


@pytest.fixture(autouse=True)
def _ig_env(monkeypatch):
    """Remove IG_SESSIONID so tests opt in explicitly via monkeypatch."""
    monkeypatch.delenv("IG_SESSIONID", raising=False)
    yield


@pytest.fixture(autouse=True)
def _patch_db_unavailable():
    """Neutralize Supabase during app startup handlers (as other suites do)."""
    with patch("backend.database.is_available", return_value=False), \
         patch("backend.database.get_client", return_value=None):
        yield


@pytest.fixture()
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as c:
        yield c


WEB_PROFILE_OK = {
    "data": {
        "user": {
            "id": "99999",
            "username": "testuser",
        }
    }
}

USER_INFO_OK = {
    "user": {
        "username": "testuser",
        "full_name": "Test User",
        "is_verified": True,
        "is_business": False,
        "is_private": True,
        "follower_count": 1234,
        "following_count": 567,
        "media_count": 89,
        "total_igtv_videos": 3,
        "biography": "Bio here",
        "external_url": "https://example.com",
        "is_whatsapp_linked": True,
        "is_memorialized": False,
        "is_new_to_instagram": True,
        "public_email": "pub@example.com",
        "public_phone_country_code": "34",
        "public_phone_number": "612345678",
        "hd_profile_pic_url_info": {"url": "https://cdn.example.com/pic.jpg"},
    }
}

LOOKUP_OK = {
    "message": "We found your account",
    "obfuscated_email": "t***@example.com",
    "obfuscated_phone": "+34 6** *** 78",
}

LOOKUP_EMPTY = {"message": None, "obfuscated_email": None, "obfuscated_phone": None}


# ════════════════════════════════════════════════════════════════
#  get_instagram_profile — happy paths
# ════════════════════════════════════════════════════════════════


async def test_profile_by_username_ok(monkeypatch):
    """2 requests (id + info) with fields mapped, incl. nested pic URL."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {
        "web_profile_info": (200, WEB_PROFILE_OK),
        "/info/": (200, USER_INFO_OK),
    }
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))) as m:
        result = await get_instagram_profile(username="testuser")

    assert result["ok"] is True
    assert result["session_configured"] is True
    assert m.call_count == 2

    profile = result["profile"]
    assert profile["username"] == "testuser"
    assert profile["user_id"] == "99999"
    assert profile["full_name"] == "Test User"
    assert profile["is_verified"] is True
    assert profile["is_business"] is False
    assert profile["is_private"] is True
    assert profile["follower_count"] == 1234
    assert profile["following_count"] == 567
    assert profile["media_count"] == 89
    assert profile["total_igtv_videos"] == 3
    assert profile["biography"] == "Bio here"
    assert profile["external_url"] == "https://example.com"
    assert profile["is_whatsapp_linked"] is True
    assert profile["is_memorialized"] is False
    assert profile["is_new_to_instagram"] is True
    assert profile["public_email"] == "pub@example.com"
    assert profile["public_phone_country_code"] == "34"
    assert profile["public_phone_number"] == "612345678"
    assert profile["hd_profile_pic_url"] == "https://cdn.example.com/pic.jpg"
    assert result["lookup"] is None

    # Cookie header must be attached to both requests.
    req0 = m.call_args_list[0][0][0]
    req1 = m.call_args_list[1][0][0]
    assert req0.get_header("Cookie") == f"sessionid={SESSION}"
    assert req1.get_header("Cookie") == f"sessionid={SESSION}"
    assert "x-ig-app-id" in {k.lower() for k in req0.headers} or \
        req0.get_header("x-ig-app-id") is not None
    # First request is the web_profile_info lookup for the username.
    assert "web_profile_info" in req0.full_url
    assert f"/users/99999/info/" in req1.full_url


async def test_profile_by_user_id_ok(monkeypatch):
    """user_id path: exactly 1 request (info), id normalised."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/info/": (200, USER_INFO_OK)}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))) as m:
        result = await get_instagram_profile(user_id="  99999 ")

    assert result["ok"] is True
    assert m.call_count == 1
    assert result["profile"]["user_id"] == "99999"
    assert result["profile"]["username"] == "testuser"
    assert "web_profile_info" not in m.call_args_list[0][0][0].full_url


async def test_profile_by_username_lookup_included(monkeypatch):
    """skip_lookup=False → 3 requests; obfuscated email/phone attached."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {
        "web_profile_info": (200, WEB_PROFILE_OK),
        "/info/": (200, USER_INFO_OK),
        "/lookup/": (200, LOOKUP_OK),
    }
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))) as m:
        result = await get_instagram_profile(username="testuser", skip_lookup=False)

    assert result["ok"] is True
    assert m.call_count == 3
    lookup = result["lookup"]
    assert lookup["message"] == "We found your account"
    assert lookup["obfuscated_email"] == "t***@example.com"
    assert lookup["obfuscated_phone"] == "+34 6** *** 78"

    req2 = m.call_args_list[2][0][0]
    assert req2.get_method() == "POST"
    assert req2.get_header("Cookie") == f"sessionid={SESSION}"
    assert b"signed_body=SIGNATURE." in req2.data
    assert b"testuser" in req2.data
    assert b"skip_recovery" in req2.data


async def test_profile_lookup_without_data_returns_none(monkeypatch):
    """Lookup payload without any field → lookup key is None."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {
        "web_profile_info": (200, WEB_PROFILE_OK),
        "/info/": (200, USER_INFO_OK),
        "/lookup/": (200, LOOKUP_EMPTY),
    }
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))) as m:
        result = await get_instagram_profile(username="testuser", skip_lookup=False)

    assert result["ok"] is True
    assert m.call_count == 3
    assert result["lookup"] is None


async def test_instagram_lookup_ok_explicit_session():
    """Direct lookup call with explicit session_id (no env needed)."""
    responses = {"/lookup/": (200, LOOKUP_OK)}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))) as m:
        result = await instagram_lookup("testuser", session_id=SESSION)

    assert result["ok"] is True
    assert result["lookup"]["obfuscated_email"] == "t***@example.com"
    assert result["session_configured"] is True
    req = m.call_args_list[0][0][0]
    assert req.get_method() == "POST"
    assert req.get_header("Cookie") == f"sessionid={SESSION}"


# ════════════════════════════════════════════════════════════════
#  get_instagram_profile / instagram_lookup — error paths
# ════════════════════════════════════════════════════════════════


async def test_profile_404_not_found(monkeypatch):
    """HTTP 404 on the info endpoint → not_found."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/info/": (404, {"message": "user not found"})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(user_id="99999")

    assert result["ok"] is False
    assert result["error"] == "User not found."
    assert result["code"] == "not_found"
    assert result["status"] == 404


async def test_profile_404_web_profile_not_found(monkeypatch):
    """HTTP 404 on the web_profile_info step → not_found."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"web_profile_info": (404, {"message": "user not found"})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(username="missing_user")

    assert result["ok"] is False
    assert result["code"] == "not_found"
    assert result["error"] == "User not found."


async def test_profile_429_rate_limited(monkeypatch):
    """HTTP 429 → rate_limited."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/info/": (429, {"message": "rate limited"})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(user_id="99999")

    assert result["ok"] is False
    assert result["error"] == "Rate limit reached."
    assert result["code"] == "rate_limited"
    assert result["status"] == 429


async def test_profile_http_400_generic(monkeypatch):
    """Any other >=400 status → HTTP {code}."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/info/": (403, {"message": "forbidden"})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(user_id="99999")

    assert result["ok"] is False
    assert result["error"] == "HTTP 403"
    assert result["code"] == "http_403"
    assert result["status"] == 403


async def test_profile_non_json_response_parse_error(monkeypatch):
    """200 with a non-JSON body → parse_error."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/info/": (200, "this is definitely not json")}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(user_id="99999")

    assert result["ok"] is False
    assert result["error"] == "Instagram API returned invalid JSON"
    assert result["code"] == "parse_error"


async def test_profile_empty_response_parse_error(monkeypatch):
    """200 with an empty body → parse_error (empty response)."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/info/": (200, "")}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(user_id="99999")

    assert result["ok"] is False
    assert result["error"] == "Instagram API returned an empty response"
    assert result["code"] == "parse_error"


async def test_profile_web_missing_user_id(monkeypatch):
    """web_profile_info without user.id → parse_error."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"web_profile_info": (200, {"data": {"user": {}}})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(username="testuser")

    assert result["ok"] is False
    assert result["error"] == "Instagram API did not return a user id"
    assert result["code"] == "parse_error"


async def test_profile_web_malformed_user_id(monkeypatch):
    """web_profile_info with a non-numeric id → parse_error."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"web_profile_info": (200, {"data": {"user": {"id": "abc"}}})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await get_instagram_profile(username="testuser")

    assert result["ok"] is False
    assert result["error"] == "Instagram API returned a malformed user id"
    assert result["code"] == "parse_error"


async def test_profile_invalid_user_id(monkeypatch):
    """Non-numeric user_id → invalid_input."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    with patch("urllib.request.urlopen", MagicMock()) as m:
        result = await get_instagram_profile(user_id="not-a-number")

    assert result["ok"] is False
    assert result["error"] == "Invalid user_id: must be numeric"
    assert result["code"] == "invalid_input"
    m.assert_not_called()


async def test_profile_both_username_and_user_id(monkeypatch):
    """username + user_id together → invalid_input, no network."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    with patch("urllib.request.urlopen", MagicMock()) as m:
        result = await get_instagram_profile(username="testuser", user_id="99999")

    assert result["ok"] is False
    assert result["error"] == "Provide either 'username' or 'user_id', not both."
    assert result["code"] == "invalid_input"
    m.assert_not_called()


async def test_profile_no_input():
    """No username and no user_id → invalid_input, no network."""
    with patch("urllib.request.urlopen", MagicMock()) as m:
        result = await get_instagram_profile()

    assert result["ok"] is False
    assert result["error"] == "Provide 'username' or 'user_id'"
    assert result["code"] == "invalid_input"
    m.assert_not_called()


async def test_profile_session_missing_without_env():
    """No IG_SESSIONID and no explicit session → session_missing."""
    with patch("urllib.request.urlopen", MagicMock()) as m:
        result = await get_instagram_profile(username="testuser")

    assert result["ok"] is False
    assert result["error"] == "IG_SESSIONID env var not configured"
    assert result["code"] == "session_missing"
    assert result["session_configured"] is False
    m.assert_not_called()


async def test_lookup_session_missing_without_env():
    """instagram_lookup without any session → session_missing."""
    with patch("urllib.request.urlopen", MagicMock()) as m:
        result = await instagram_lookup("testuser")

    assert result["ok"] is False
    assert result["code"] == "session_missing"
    m.assert_not_called()


async def test_lookup_no_username():
    """instagram_lookup with an empty username → invalid_input."""
    monkeypatch_session = SESSION
    responses = {"/lookup/": (200, LOOKUP_OK)}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))) as m:
        result = await instagram_lookup("", session_id=monkeypatch_session)

    assert result["ok"] is False
    assert result["error"] == "No username provided"
    assert result["code"] == "invalid_input"
    m.assert_not_called()


async def test_lookup_http_error(monkeypatch):
    """lookup HTTP 404 → not_found."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    responses = {"/lookup/": (404, {"message": "nope"})}
    with patch("urllib.request.urlopen", MagicMock(side_effect=_router(responses))):
        result = await instagram_lookup("testuser")

    assert result["ok"] is False
    assert result["code"] == "not_found"
    assert result["error"] == "User not found."


async def test_timeout_captured():
    """socket.timeout → clean timeout error, never raises."""
    with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
        result = await get_instagram_profile(user_id="99999", session_id=SESSION)

    assert result["ok"] is False
    assert "Timeout" in result["error"]


async def test_network_error_captured():
    """URLError (connection refused) → network error, never raises."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        result = await get_instagram_profile(user_id="99999", session_id=SESSION)

    assert result["ok"] is False
    assert "Network error" in result["error"]


async def test_generic_urlopen_exception_captured():
    """Unexpected urlopen exception → error dict, never raises."""
    with patch("urllib.request.urlopen", side_effect=ValueError("weird")):
        result = await get_instagram_profile(user_id="99999", session_id=SESSION)

    assert result["ok"] is False
    assert result["error"] == "weird"


async def test_profile_generic_exception_is_caught(monkeypatch):
    """_fetch blowing up entirely → ok=False, no raise (global guard)."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    with patch("backend.instagram_osint._fetch", new_callable=AsyncMock,
               side_effect=RuntimeError("boom")):
        result = await get_instagram_profile(username="testuser")

    assert result["ok"] is False
    assert result["error"] == "boom"


async def test_lookup_generic_exception_is_caught(monkeypatch):
    """instagram_lookup _fetch blowing up → ok=False, no raise."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    with patch("backend.instagram_osint._fetch", new_callable=AsyncMock,
               side_effect=RuntimeError("boom")):
        result = await instagram_lookup("testuser")

    assert result["ok"] is False
    assert result["error"] == "boom"


# ════════════════════════════════════════════════════════════════
#  _urlopen_sync / _fetch low-level branches
# ════════════════════════════════════════════════════════════════


async def test_fetch_ok_parses_json_and_sets_ua():
    """_fetch returns parsed JSON data and sends the MIRV User-Agent."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b'{"a": 1}', 200)) as m:
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is True
    assert resp["status"] == 200
    assert resp["data"] == {"a": 1}
    req = m.call_args[0][0]
    assert req.get_method() == "GET"
    assert "MIRV-OSINT" in (req.get_header("User-agent") or "")


async def test_fetch_http_error_returns_code():
    """_fetch maps HTTP errors to ok=False with status code."""
    with patch("urllib.request.urlopen", side_effect=_http_error(500, b"boom")):
        resp = await _fetch("https://example.com/x")
    assert resp["ok"] is False
    assert resp["status"] == 500
    assert resp["body"] == "boom"


def test_urlopen_sync_captures_everything():
    """_urlopen_sync never raises — HTTP/network/timeout/generic."""
    # HTTPError
    with patch("urllib.request.urlopen", side_effect=_http_error(404, b"nope")):
        out = _urlopen_sync("https://example.com/404", DEFAULT_TIMEOUT, {}, "GET", None)
    assert out["ok"] is False and out["status"] == 404
    # URLError
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
        out = _urlopen_sync("https://example.com/refused", DEFAULT_TIMEOUT, {}, "GET", None)
    assert out["ok"] is False and "Network error" in out["error"]
    # timeout
    with patch("urllib.request.urlopen", side_effect=socket.timeout("t")):
        out = _urlopen_sync("https://example.com/timeout", DEFAULT_TIMEOUT, {}, "GET", None)
    assert out["ok"] is False and "Timeout" in out["error"]
    # generic
    with patch("urllib.request.urlopen", side_effect=ValueError("weird")):
        out = _urlopen_sync("https://example.com/generic", DEFAULT_TIMEOUT, {}, "GET", None)
    assert out["ok"] is False and out["error"] == "weird"


def test_urlopen_sync_success_body():
    """_urlopen_sync success returns ok/status/body."""
    with patch("urllib.request.urlopen", return_value=_FakeResp(b'{"k": 2}', 200)):
        out = _urlopen_sync("https://example.com/ok", DEFAULT_TIMEOUT, {}, "GET", None)
    assert out["ok"] is True and out["status"] == 200
    assert out["body"] == b'{"k": 2}'


def test_urlopen_sync_http_error_read_failure():
    """HTTPError whose body read raises falls back to an empty body."""
    err = _http_error(500, b"x")
    err.read = lambda n=-1: (_ for _ in ()).throw(RuntimeError("read failed"))  # type: ignore[method-assign]
    with patch("urllib.request.urlopen", side_effect=err):
        out = _urlopen_sync("https://example.com/x", DEFAULT_TIMEOUT, {}, "GET", None)
    assert out["ok"] is False
    assert out["status"] == 500
    assert out["body"] == b""


# ════════════════════════════════════════════════════════════════
#  Dataclass units
# ════════════════════════════════════════════════════════════════


def test_user_profile_from_payload_defaults():
    """Missing optional payload fields fall back to safe defaults."""
    profile = UserProfile.from_payload({"username": "u"}, "42")
    assert profile.username == "u"
    assert profile.user_id == "42"
    assert profile.full_name == ""
    assert profile.biography == ""
    assert profile.hd_profile_pic_url is None
    assert profile.is_verified is False
    assert profile.follower_count == 0


def test_lookup_insight_has_data():
    """has_data() is True when any field is set, False otherwise."""
    assert LookupInsight.from_payload(LOOKUP_OK).has_data() is True
    assert LookupInsight.from_payload(LOOKUP_EMPTY).has_data() is False


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════


def _http_error(code: int, body: bytes = b""):
    """Build a real urllib HTTPError for _fetch/_urlopen_sync branches."""
    return urllib.error.HTTPError("http://example.invalid", code, "err", {}, io.BytesIO(body))


# ════════════════════════════════════════════════════════════════
#  POST /api/osint/instagram endpoint
# ════════════════════════════════════════════════════════════════


def test_endpoint_instagram_200(client, monkeypatch):
    """Endpoint returns profile data and forwards skip_lookup."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    result = {
        "ok": True,
        "profile": {"username": "testuser", "user_id": "99999", "full_name": "Test User"},
        "lookup": None,
        "session_configured": True,
    }
    with patch("backend.instagram_osint.get_instagram_profile", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.post("/api/osint/instagram", json={"username": "testuser", "skip_lookup": False})

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["profile"]["username"] == "testuser"
    assert body["session_configured"] is True
    m.assert_awaited_once_with(username="testuser", user_id="", skip_lookup=False)


def test_endpoint_instagram_200_default_skip_lookup(client, monkeypatch):
    """skip_lookup defaults to True when omitted."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    result = {"ok": True, "profile": {"username": "testuser", "user_id": "1"}, "lookup": None,
              "session_configured": True}
    with patch("backend.instagram_osint.get_instagram_profile", new_callable=AsyncMock) as m:
        m.return_value = result
        resp = client.post("/api/osint/instagram", json={"username": "testuser"})

    assert resp.status_code == 200
    m.assert_awaited_once_with(username="testuser", user_id="", skip_lookup=True)


def test_endpoint_instagram_session_missing_400(client):
    """IG_SESSIONID unset → 400 with session_missing code (no function call)."""
    with patch("backend.instagram_osint.get_instagram_profile", new_callable=AsyncMock) as m:
        resp = client.post("/api/osint/instagram", json={"username": "testuser"})

    assert resp.status_code == 400
    assert resp.json()["ok"] is False
    assert resp.json()["code"] == "session_missing"
    assert resp.json()["error"] == "IG_SESSIONID env var not configured"
    m.assert_not_awaited()


def test_endpoint_instagram_empty_body_422(client):
    """Both fields empty → 422."""
    resp = client.post("/api/osint/instagram", json={"username": "", "user_id": ""})
    assert resp.status_code == 422
    assert resp.json()["error"] == "Provide 'username' or 'user_id'"


def test_endpoint_instagram_both_fields_422(client):
    """username + user_id together → 422."""
    resp = client.post("/api/osint/instagram", json={"username": "a", "user_id": "1"})
    assert resp.status_code == 422
    assert resp.json()["error"] == "Provide either 'username' or 'user_id', not both"


def test_endpoint_instagram_no_body_422(client):
    """Missing body → Pydantic 422 (defaults, so manual check triggers)."""
    resp = client.post("/api/osint/instagram", json={})
    assert resp.status_code == 422


def test_endpoint_instagram_500(client, monkeypatch):
    """Module exception → 500 JSON error (H-008: input not leaked)."""
    monkeypatch.setenv("IG_SESSIONID", SESSION)
    with patch("backend.instagram_osint.get_instagram_profile", new_callable=AsyncMock,
               side_effect=RuntimeError("boom with secret input")):
        resp = client.post("/api/osint/instagram", json={"username": "testuser"})

    assert resp.status_code == 500
    assert resp.json()["ok"] is False
    # H-008: never echo the raw exception (which may contain user input /
    # secrets) — return a fixed generic message instead.
    assert resp.json()["error"] == "Internal error"
