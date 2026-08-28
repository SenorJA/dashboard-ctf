"""
tests/test_smoke_e2e.py — End-to-end smoke tests for MIRV critical flows.

Unlike the per-endpoint tests (``test_api_endpoints.py``, ``test_main_gaps.py``
…), this file exercises *complete flows* through the FastAPI ``TestClient``:
health → OSINT (with rate-limit enforcement) → reports CRUD → findings →
skills → settings round-trip → scope validation → static file serving.

All network/DB side-effects are mocked — no real Supabase, no real SSH, no
real HTTP to third-party OSINT providers. Imports follow the package-prefix
convention (``backend.X``) mandated by ``AGENTS.md`` to avoid the split-module
monkeypatch bug documented in ``TOMORROW.md`` § Postmortem.
"""

from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

# Make ``backend.*`` importable when running from ``backend/``.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402  -- imports the backend.* package tree


# ═══════════════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def client():
    """FastAPI TestClient around the shared app instance."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _patch_db_unavailable(monkeypatch):
    """Force the Supabase layer to report “not configured” for every test.

    Mirrors the convention used across the suite
    (``@patch("backend.database.is_available", return_value=False)``) so the
    smoke tests are deterministic regardless of whether ``SUPABASE_URL`` is
    set in the developer's environment. Per-test ``@patch`` overrides on the
    individual ``list_*``/``save_*`` helpers still take effect because they
    are applied after this autouse fixture.
    """
    from backend import database as db_mod
    monkeypatch.setattr(db_mod, "is_available", lambda: False)
    yield


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Wipe the process-wide OSINT rate limiter before & after each test.

    The limiter is a singleton shared across the whole session; without a
    reset, hits would accumulate and unrelated tests would start seeing 429s.
    (``conftest.py`` already does this via ``_reset_osint_rate_limiter`` — we
    repeat it here so the file is self-documenting and survives even if the
    shared fixture is later refactored.)
    """
    try:
        from backend.rate_limiter import reset_rate_limiter
        reset_rate_limiter()
    except Exception:
        pass
    yield
    try:
        from backend.rate_limiter import reset_rate_limiter
        reset_rate_limiter()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
#  1. Health check flow
# ═══════════════════════════════════════════════════════════════════════

class TestHealthFlow:
    """GET /api/health reports service status."""

    def test_health_returns_200_with_status(self, client: TestClient):
        """Health endpoint responds 200 and carries a status field."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        # “ok” (DB up) or “degraded” (DB down, our mocked case) — both valid.
        assert body["status"] in ("ok", "degraded", "healthy")
        assert "version" in body
        assert "uptime_seconds" in body


# ═══════════════════════════════════════════════════════════════════════
#  2. OSINT flow (passive recon, mocked providers) + rate limiting
# ═══════════════════════════════════════════════════════════════════════

class TestOsintFlow:
    """Passive OSINT endpoints with third-party calls mocked out."""

    def test_email_lookup_returns_200(self, client: TestClient):
        """POST /api/osint/email returns 200 with mocked breach/verify."""
        with patch("backend.osint_recon.check_email_breach",
                   new_callable=AsyncMock) as m_breach, \
             patch("backend.osint_recon.verify_email",
                   new_callable=AsyncMock) as m_verify:
            m_breach.return_value = {"ok": True, "found": False}
            m_verify.return_value = {"ok": True, "valid": True}
            resp = client.post("/api/osint/email",
                               json={"email": "test@example.com"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["email"] == "test@example.com"

    def test_correlate_returns_200(self, client: TestClient):
        """POST /api/osint/correlate fans out mocked sources → 200."""
        with patch("backend.osint_correlate.correlate_target",
                   new_callable=AsyncMock) as m_corr:
            m_corr.return_value = {
                "ok": True,
                "target_type": "email",
                "target": "test@example.com",
                "sources": {},
            }
            resp = client.post("/api/osint/correlate",
                               json={"target_type": "email",
                                     "target": "test@example.com"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_ip_geolocation_returns_200(self, client: TestClient):
        """GET /api/osint/ip returns 200 with mocked ipinfo result."""
        with patch("backend.osint_recon.ip_geolocation",
                   new_callable=AsyncMock) as m_geo:
            m_geo.return_value = {"ok": True, "ip": "8.8.8.8",
                                  "city": "Mountain View"}
            resp = client.get("/api/osint/ip", params={"ip": "8.8.8.8"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["ip"] == "8.8.8.8"

    def test_rate_limit_31st_call_returns_429_with_retry_after(
        self, client: TestClient
    ):
        """31 rapid calls to /api/osint/email → last one is 429 + Retry-After.

        The default bucket is 30 req/min (``rate_limiter._DEFAULT_LIMIT``).
        We mock the underlying recon functions so the first 30 succeed fast
        without touching the network; the 31st is rejected by the guard
        before the handler body runs.
        """
        with patch("backend.osint_recon.check_email_breach",
                   new_callable=AsyncMock) as m_breach, \
             patch("backend.osint_recon.verify_email",
                   new_callable=AsyncMock) as m_verify:
            m_breach.return_value = {"ok": True}
            m_verify.return_value = {"ok": True}
            statuses = []
            last_resp = None
            for i in range(31):
                last_resp = client.post(
                    "/api/osint/email",
                    json={"email": "test@example.com"},
                )
                statuses.append(last_resp.status_code)

        # First 30 must be allowed (200); the 31st hits the limiter.
        assert statuses[:30] == [200] * 30
        assert statuses[-1] == 429
        body = last_resp.json()
        assert body["ok"] is False
        assert "Rate limit" in body["error"]
        # Retry-After header is mandatory on 429.
        assert "Retry-After" in last_resp.headers
        assert int(last_resp.headers["Retry-After"]) >= 1


# ═══════════════════════════════════════════════════════════════════════
#  3. Reports CRUD flow
# ═══════════════════════════════════════════════════════════════════════

class TestReportsFlow:
    """List → create → delete a report, all with a mocked DB layer."""

    def test_list_reports_returns_200_empty(self, client: TestClient):
        """GET /api/reports returns 200 with an empty list when DB mocked."""
        with patch("backend.database.list_reports", return_value=[]):
            resp = client.get("/api/reports")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["data"] == []

    def test_create_report_returns_success(self, client: TestClient):
        """POST /api/reports with a valid body persists via mocked save."""
        saved = {"id": "r-1", "type": "nmap", "title": "scan",
                 "target": "10.0.0.1", "raw_output": "", "parsed_data": "{}",
                 "format": "md"}
        with patch("backend.database.save_report", return_value=saved):
            resp = client.post("/api/reports", json={
                "type": "nmap", "title": "scan", "target": "10.0.0.1",
                "raw_output": "", "parsed_data": {}, "format": "md",
            })
        # Handler uses _ok(..., 201); accept 200 or 201 defensively.
        assert resp.status_code in (200, 201)
        assert resp.json()["ok"] is True
        assert resp.json()["data"]["id"] == "r-1"

    def test_delete_report_returns_200(self, client: TestClient):
        """DELETE /api/reports/{id} → 200 when the mocked delete succeeds."""
        with patch("backend.database.delete_report", return_value=True):
            resp = client.delete("/api/reports/r-1")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


# ═══════════════════════════════════════════════════════════════════════
#  4. Findings flow
# ═══════════════════════════════════════════════════════════════════════

class TestFindingsFlow:
    """List, stats, and bulk-insert findings with a mocked DB."""

    def test_list_findings_returns_200(self, client: TestClient):
        """GET /api/findings returns 200 with the mocked list."""
        with patch("backend.database.list_findings", return_value=[]):
            resp = client.get("/api/findings")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["data"] == []

    def test_findings_stats_returns_200(self, client: TestClient):
        """GET /api/findings/stats returns 200 with aggregate counters."""
        with patch("backend.database.list_findings", return_value=[]):
            resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["count"] == 0
        assert body["tools"] == []
        assert body["targets"] == []

    def test_findings_bulk_returns_success(self, client: TestClient):
        """POST /api/findings/bulk persists an array via mocked save_bulk."""
        with patch("backend.database.save_findings_bulk", return_value=2):
            resp = client.post("/api/findings/bulk", json=[
                {"tool": "nmap", "target": "10.0.0.1", "severity": "low"},
                {"tool": "nikto", "target": "10.0.0.1", "severity": "high"},
            ])
        assert resp.status_code in (200, 201)
        body = resp.json()
        assert body["ok"] is True
        assert body["count"] == 2


# ═══════════════════════════════════════════════════════════════════════
#  5. Skills flow
# ═══════════════════════════════════════════════════════════════════════

class TestSkillsFlow:
    """Discover, inspect, and render built-in skill playbooks."""

    def test_list_skills_includes_osint_and_password_audit(
        self, client: TestClient
    ):
        """GET /api/skills lists the built-in osint & password-audit skills."""
        resp = client.get("/api/skills")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        names = {s["name"] for s in body["skills"]}
        assert "osint" in names
        assert "password-audit" in names

    def test_skill_info_osint_returns_200(self, client: TestClient):
        """GET /api/skills/osint returns detailed info for the skill."""
        resp = client.get("/api/skills/osint")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["skill"]["name"] == "osint"
        # Category is whatever the winning discovery dir declares — a
        # user-created ``~/.mirv/skills/osint`` template (category "custom")
        # overrides the built-in ``backend/skills/osint`` (category "osint")
        # per the "later wins" rule in AGENTS.md, so only assert non-empty.
        assert body["skill"]["category"]

    def test_skill_render_password_audit_returns_markdown(
        self, client: TestClient
    ):
        """GET /api/skills/password-audit/render returns the markdown body.

        ``render_skill_for_prompt`` returns ``""`` for disabled skills, so we
        first ``load`` the skill (which flips ``enabled=True``) and then
        render — exercising the real enable→render flow end-to-end.
        """
        load_resp = client.post("/api/skills/password-audit/load")
        assert load_resp.status_code == 200
        assert load_resp.json()["ok"] is True

        resp = client.get("/api/skills/password-audit/render")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["name"] == "password-audit"
        # When enabled, the body is non-empty markdown.
        assert body["enabled"] is True
        assert body["body"].strip() != ""
        assert "# Skill:" in body["body"]


# ═══════════════════════════════════════════════════════════════════════
#  6. Settings round-trip
# ═══════════════════════════════════════════════════════════════════════

class TestSettingsRoundTrip:
    """Write a setting then read it back through the mocked DB layer."""

    def test_settings_round_trip(self, client: TestClient):
        """POST /api/settings then GET /api/settings/{key} reflect the value.

        The real schema is ``SettingUpdate{key, value}`` (not a flat
        ``{theme, lang}`` object), so we round-trip a single key — the
        principle of the spec (write-then-read) is preserved.
        """
        store: dict = {}

        def _set(key, value):
            store[key] = value
            return value

        def _get(key):
            return store.get(key)

        with patch("backend.database.set_setting", side_effect=_set):
            resp = client.post("/api/settings",
                               json={"key": "theme", "value": "mono"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        with patch("backend.database.get_setting", side_effect=_get):
            resp = client.get("/api/settings/theme")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["key"] == "theme"
        assert body["value"] == "mono"


# ═══════════════════════════════════════════════════════════════════════
#  7. Scope validation flow
# ═══════════════════════════════════════════════════════════════════════

class TestScopeValidationFlow:
    """Validate commands against a mocked in-scope target list.

    The real endpoint returns ``{"ok": True, "blocked": bool}``. We map
    ``blocked == False`` → “valid” and ``blocked == True`` → “invalid”,
    which is the semantic the spec describes (``{"valid": true/false}``).
    """

    def _scoped_config(self):
        return {
            "enabled": True,
            "mode": "warn",
            "targets": ["192.168.1.1"],
            "block_private": False,
        }

    def test_in_scope_command_is_valid(self, client: TestClient):
        """A command targeting an in-scope IP is not blocked (valid)."""
        with patch("backend.scope_guard.get_config",
                   return_value=self._scoped_config()):
            resp = client.post("/api/scope/validate",
                               json={"command": "nmap 192.168.1.1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body.get("blocked") is False  # → valid

    def test_out_of_scope_command_is_invalid(self, client: TestClient):
        """A command targeting an out-of-scope IP is blocked (invalid)."""
        with patch("backend.scope_guard.get_config",
                   return_value=self._scoped_config()):
            resp = client.post("/api/scope/validate",
                               json={"command": "nmap 10.0.0.5"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body.get("blocked") is True  # → invalid
        assert "10.0.0.5" in body.get("targets", [])


# ═══════════════════════════════════════════════════════════════════════
#  8. Static files
# ═══════════════════════════════════════════════════════════════════════

class TestStaticFiles:
    """Frontend assets are served with the correct media types."""

    def test_root_serves_index_html(self, client: TestClient):
        """GET / returns the SPA shell as text/html."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        # index.html always defines the tab containers.
        assert b"tab-terminal" in resp.content or b"<!DOCTYPE html" in resp.content

    def test_css_style_css_served(self, client: TestClient):
        """GET /css/style.css returns 200 with a CSS content-type."""
        resp = client.get("/css/style.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers.get("content-type", "")
        assert len(resp.content) > 0

    def test_js_main_v2_served(self, client: TestClient):
        """GET /js/main.v2.js returns 200 with a JavaScript content-type."""
        resp = client.get("/js/main.v2.js")
        assert resp.status_code == 200
        ct = resp.headers.get("content-type", "")
        # Python's mimetypes may report text/javascript or application/javascript
        # depending on version/platform — accept either.
        assert "javascript" in ct, f"unexpected content-type: {ct}"
        assert len(resp.content) > 0
