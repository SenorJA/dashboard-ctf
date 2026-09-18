"""Tests for the opt-in API token guard (backend/api_auth.py + middleware)."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def no_token_env(monkeypatch):
    monkeypatch.delenv("MIRV_API_TOKEN", raising=False)
    monkeypatch.delenv("MIRV_API_TOKEN_FILE", raising=False)


@pytest.fixture()
def token_env(monkeypatch):
    monkeypatch.setenv("MIRV_API_TOKEN", "super-secret-token-123")
    monkeypatch.delenv("MIRV_API_TOKEN_FILE", raising=False)


def _guard_on(c):
    return c.get("/api/scheduler/status").status_code == 401


# ── Guard disabled by default (opt-in) ────────────────────────────────────

def test_disabled_by_default(no_token_env, client):
    assert _guard_on(client) is False
    r = client.get("/api/scheduler/status")
    assert r.status_code == 200


def test_disabled_status_endpoint(no_token_env, client):
    r = client.get("/api/auth/status")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["source"] == ""


# ── Guard enabled via env ──────────────────────────────────────────────────

def test_enabled_requires_token(token_env, client):
    r = client.get("/api/scheduler/status")
    assert r.status_code == 401
    body = r.json()
    assert body["ok"] is False
    assert "token" in (body["error"] or "")
    assert r.headers.get("www-authenticate") == "Bearer"
    assert r.headers.get("x-mirv-auth") == "required"


def test_bearer_header_accepted(token_env, client):
    r = client.get("/api/scheduler/status", headers={"Authorization": "Bearer super-secret-token-123"})
    assert r.status_code == 200


def test_bearer_case_insensitive_scheme(token_env, client):
    r = client.get("/api/scheduler/status", headers={"Authorization": "bearer super-secret-token-123"})
    assert r.status_code == 200


def test_x_mirv_token_header_accepted(token_env, client):
    r = client.get("/api/scheduler/status", headers={"X-MIRV-Token": "super-secret-token-123"})
    assert r.status_code == 200


def test_invalid_token_rejected(token_env, client):
    r = client.get("/api/scheduler/status", headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401
    r = client.get("/api/scheduler/status", headers={"X-MIRV-Token": "wrong-token"})
    assert r.status_code == 401


def test_cookie_auth_after_index(token_env, client):
    # GET / sets the httpOnly mirv_token cookie; TestClient replays it
    first = client.get("/")
    assert first.status_code == 200
    assert any(c.name == "mirv_token" and c.value == "super-secret-token-123" for c in first.cookies.jar)
    r = client.get("/api/scheduler/status")
    assert r.status_code == 200


def test_exempt_paths_open_while_enabled(token_env, client):
    assert client.get("/api/health").status_code == 200
    r = client.get("/api/auth/status")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["source"] == "env"
    assert body["masked_token"] == "supe•••-123"


def test_static_assets_not_guarded(token_env, client):
    assert client.get("/").status_code == 200
    assert client.get("/favicon.ico").status_code in (200, 404)
    assert client.get("/js/main.v2.js").status_code in (200, 404)


# ── File-based token ───────────────────────────────────────────────────────

def test_file_token(monkeypatch, client, tmp_path):
    token_file = tmp_path / "api_token.txt"
    token_file.write_text("  file-token-abc\nignored line\n", encoding="utf-8")
    monkeypatch.delenv("MIRV_API_TOKEN", raising=False)
    monkeypatch.setenv("MIRV_API_TOKEN_FILE", str(token_file))
    r = client.get("/api/scheduler/status", headers={"Authorization": "Bearer file-token-abc"})
    assert r.status_code == 200
    assert client.get("/api/scheduler/status").status_code == 401
    status = client.get("/api/auth/status").json()
    assert status["enabled"] is True
    assert status["source"] == "file"


def test_missing_file_disables_guard(monkeypatch, client, tmp_path):
    monkeypatch.delenv("MIRV_API_TOKEN", raising=False)
    monkeypatch.setenv("MIRV_API_TOKEN_FILE", str(tmp_path / "does-not-exist.txt"))
    assert client.get("/api/scheduler/status").status_code == 200


# ── Env wins over file ─────────────────────────────────────────────────────

def test_env_wins_over_file(monkeypatch, client, tmp_path):
    token_file = tmp_path / "api_token.txt"
    token_file.write_text("file-token", encoding="utf-8")
    monkeypatch.setenv("MIRV_API_TOKEN", "env-token")
    monkeypatch.setenv("MIRV_API_TOKEN_FILE", str(token_file))
    assert client.get("/api/scheduler/status", headers={"Authorization": "Bearer env-token"}).status_code == 200
    assert client.get("/api/scheduler/status", headers={"Authorization": "Bearer file-token"}).status_code == 401


def test_auth_token_endpoint_guarded(token_env, client):
    # without credentials → 401
    assert client.get("/api/auth/token").status_code == 401
    # with cookie (from /) or header → echoes the token
    client.get("/")
    body = client.get("/api/auth/token").json()
    assert body["ok"] is True
    assert body["enabled"] is True
    assert body["token"] == "super-secret-token-123"
    r = client.get("/api/auth/token", headers={"Authorization": "Bearer super-secret-token-123"})
    assert r.status_code == 200


def test_auth_token_endpoint_disabled(no_token_env, client):
    body = client.get("/api/auth/token").json()
    assert body["ok"] is True
    assert body["enabled"] is False
    assert body["token"] == ""


# ── Utilities ──────────────────────────────────────────────────────────────

def test_mask():
    from backend import api_auth as apiauth
    assert apiauth.mask("") == ""
    assert apiauth.mask("short") == "••••••••"
    token = "abcdefgh12345678"
    assert apiauth.mask(token) == "abcd•••5678"


def test_token_source(no_token_env):
    from backend import api_auth as apiauth
    assert apiauth.token_source() == ""
    assert apiauth.is_enabled() is False