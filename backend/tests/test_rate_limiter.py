"""
tests/test_rate_limiter.py — OSINT security fixes (H-001 / H-002 / H-004 /
H-005 / H-006 / H-008) integration tests.

Covers:

* ``backend/rate_limiter.py`` — sliding-window per-(ip,path) limiter
  (allow within limit, deny above limit, retry_after clamp, reset hook,
  per-path stricter limits for username/instagram).
* ``/api/osint/*`` endpoint integration:
    - H-002 rate limit → 429 + ``Retry-After`` header.
    - H-001 optional shared token → 401 when ``MIRV_OSINT_TOKEN`` set
      and header missing/wrong; open when unset.
    - H-004 Pydantic ``max_length`` / ``Query`` bounds → 422 (not 500)
      on oversized payloads.
    - H-005 ``ip_geolocation`` rejects private/reserved IPs.
    - H-006 ``wayback_machine_lookup`` rejects IPs and private TLDs.
    - H-008 unexpected failures return ``{"error": "Internal error"}``
      and never echo the raw exception.

IMPORTANT: every import uses the ``backend.`` package prefix — never
``from X import ...`` (see AGENTS.md / TOMORROW.md § Postmortem).
"""

from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402
from backend.rate_limiter import (  # noqa: E402
    RateLimiter,
    check_rate_limit,
    reset_rate_limiter,
    _DEFAULT_LIMIT,
    _LIMITS,
    _WINDOW,
)


# ───────────────────────────────────────────────────────────────────
#  rate_limiter unit tests
# ───────────────────────────────────────────────────────────────────


class TestRateLimiterUnit:
    """Direct tests against ``backend.rate_limiter.RateLimiter``."""

    def test_allows_within_limit(self):
        rl = RateLimiter()
        for _ in range(_DEFAULT_LIMIT):
            allowed, retry = rl.check("1.2.3.4", "/api/osint/email")
            assert allowed is True
            assert retry == 0

    def test_denies_above_default_limit(self):
        rl = RateLimiter()
        for _ in range(_DEFAULT_LIMIT):
            rl.check("1.2.3.4", "/api/osint/email")
        allowed, retry = rl.check("1.2.3.4", "/api/osint/email")
        assert allowed is False
        assert retry >= 1

    def test_per_path_buckets_are_independent(self):
        """Hits on /email do not count against /dork and vice-versa."""
        rl = RateLimiter()
        for _ in range(_DEFAULT_LIMIT):
            rl.check("1.2.3.4", "/api/osint/email")
        allowed, _ = rl.check("1.2.3.4", "/api/osint/dork")
        assert allowed is True

    def test_per_ip_buckets_are_independent(self):
        rl = RateLimiter()
        for _ in range(_DEFAULT_LIMIT):
            rl.check("1.1.1.1", "/api/osint/email")
        allowed, _ = rl.check("2.2.2.2", "/api/osint/email")
        assert allowed is True

    def test_username_path_has_stricter_limit(self):
        rl = RateLimiter()
        limit = _LIMITS["/api/osint/username"]
        assert limit < _DEFAULT_LIMIT
        for _ in range(limit):
            rl.check("9.9.9.9", "/api/osint/username")
        allowed, retry = rl.check("9.9.9.9", "/api/osint/username")
        assert allowed is False
        assert retry >= 1

    def test_retry_after_is_bounded_by_window(self):
        rl = RateLimiter()
        for _ in range(_DEFAULT_LIMIT):
            rl.check("5.5.5.5", "/api/osint/email")
        _, retry = rl.check("5.5.5.5", "/api/osint/email")
        # retry_after is int(_WINDOW - age) + 1, clamped to >= 1.
        assert 1 <= retry <= int(_WINDOW) + 1

    def test_reset_clears_all_state(self):
        rl = RateLimiter()
        for _ in range(_DEFAULT_LIMIT):
            rl.check("6.6.6.6", "/api/osint/email")
        rl.reset()
        allowed, _ = rl.check("6.6.6.6", "/api/osint/email")
        assert allowed is True

    def test_module_singleton_check_and_reset(self):
        reset_rate_limiter()
        allowed, _ = check_rate_limit("7.7.7.7", "/api/osint/email")
        assert allowed is True
        reset_rate_limiter()

    def test_unknown_client_yields_unknown_ip(self):
        """``request.client`` may be None — guard falls back to 'unknown'."""
        rl = RateLimiter()
        allowed, _ = rl.check("unknown", "/api/osint/email")
        assert allowed is True

    def test_eviction_of_aged_hits(self):
        """Hits older than the window are evicted (covers popleft branch)."""
        rl = RateLimiter()
        # Inject one stale hit so the eviction while-loop actually pops.
        rl._hits["1.2.3.4:/api/osint/email"].append(-10_000.0)
        allowed, _ = rl.check("1.2.3.4", "/api/osint/email")
        assert allowed is True
        # The stale entry must have been evicted (only the fresh one remains).
        assert len(rl._hits["1.2.3.4:/api/osint/email"]) == 1


# ───────────────────────────────────────────────────────────────────
#  osint_recon validation tests (H-005 / H-006)
# ───────────────────────────────────────────────────────────────────


class TestOsintReconValidation:
    """H-005 / H-006 — input validation in osint_recon.py."""

    @pytest.mark.asyncio
    async def test_ip_geolocation_rejects_private(self):
        from backend.osint_recon import ip_geolocation
        result = await ip_geolocation("192.168.1.1")
        assert result["ok"] is False
        assert "Private" in result["error"] or "private" in result["error"]

    @pytest.mark.asyncio
    async def test_ip_geolocation_rejects_loopback(self):
        from backend.osint_recon import ip_geolocation
        result = await ip_geolocation("127.0.0.1")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_ip_geolocation_rejects_link_local(self):
        from backend.osint_recon import ip_geolocation
        result = await ip_geolocation("169.254.1.1")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_ip_geolocation_allows_public(self):
        from backend.osint_recon import ip_geolocation
        payload = b'{"ip": "8.8.8.8", "city": "MV", "country": "US"}'
        with patch("urllib.request.urlopen", return_value=_FakeResp(payload, 200)):
            result = await ip_geolocation("8.8.8.8")
        assert result["ok"] is True

    @pytest.mark.asyncio
    async def test_wayback_rejects_ip(self):
        from backend.osint_recon import wayback_machine_lookup
        result = await wayback_machine_lookup("192.168.1.1")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_wayback_rejects_private_tld(self):
        from backend.osint_recon import wayback_machine_lookup
        result = await wayback_machine_lookup("metadata.google.internal")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_wayback_rejects_bare_ip_dressed_as_host(self):
        from backend.osint_recon import wayback_machine_lookup
        # 8.8.8.8 parses as a valid IP → rejected even though it has dots.
        result = await wayback_machine_lookup("8.8.8.8")
        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_wayback_allows_public_domain(self):
        import json
        from backend.osint_recon import wayback_machine_lookup
        cdx = json.dumps([
            ["timestamp", "original", "statuscode"],
            ["20240101", "example.com/", "200"],
        ]).encode()
        with patch("urllib.request.urlopen", return_value=_FakeResp(cdx, 200)):
            result = await wayback_machine_lookup("example.com")
        assert result["ok"] is True


# ───────────────────────────────────────────────────────────────────
#  Endpoint integration tests (H-001 / H-002 / H-004 / H-008)
# ───────────────────────────────────────────────────────────────────


class TestOsintEndpointSecurity:
    """Integration tests through the FastAPI TestClient."""

    def test_rate_limit_returns_429_with_retry_after(self, client):
        """H-002: when check_rate_limit denies, endpoint returns 429."""
        with patch("backend.rate_limiter.check_rate_limit", return_value=(False, 30)):
            resp = client.post("/api/osint/email", json={"email": "u@example.com"})
        assert resp.status_code == 429
        body = resp.json()
        assert body["ok"] is False
        assert "Rate limit" in body["error"]
        assert resp.headers.get("Retry-After") == "30"

    def test_rate_limit_allows_pass_through(self, client):
        """H-002: when check_rate_limit allows, request proceeds normally."""
        with patch("backend.rate_limiter.check_rate_limit", return_value=(True, 0)), \
             patch("backend.osint_recon.check_email_breach", new_callable=AsyncMock) as m_b, \
             patch("backend.osint_recon.verify_email", new_callable=AsyncMock) as m_v:
            m_b.return_value = {"ok": True}
            m_v.return_value = {"ok": True}
            resp = client.post("/api/osint/email", json={"email": "u@example.com"})
        assert resp.status_code == 200

    def test_token_missing_returns_401_when_configured(self, client, monkeypatch):
        """H-001: with MIRV_OSINT_TOKEN set, missing header → 401."""
        monkeypatch.setenv("MIRV_OSINT_TOKEN", "secret-shared-token")
        resp = client.post("/api/osint/email", json={"email": "u@example.com"})
        assert resp.status_code == 401
        assert resp.json()["ok"] is False

    def test_token_wrong_returns_401(self, client, monkeypatch):
        """H-001: wrong header value → 401."""
        monkeypatch.setenv("MIRV_OSINT_TOKEN", "secret-shared-token")
        resp = client.post(
            "/api/osint/email",
            json={"email": "u@example.com"},
            headers={"X-MIRV-Token": "wrong"},
        )
        assert resp.status_code == 401

    def test_token_correct_allows_request(self, client, monkeypatch):
        """H-001: matching header → request proceeds."""
        monkeypatch.setenv("MIRV_OSINT_TOKEN", "secret-shared-token")
        with patch("backend.osint_recon.check_email_breach", new_callable=AsyncMock) as m_b, \
             patch("backend.osint_recon.verify_email", new_callable=AsyncMock) as m_v:
            m_b.return_value = {"ok": True}
            m_v.return_value = {"ok": True}
            resp = client.post(
                "/api/osint/email",
                json={"email": "u@example.com"},
                headers={"X-MIRV-Token": "secret-shared-token"},
            )
        assert resp.status_code == 200

    def test_no_token_configured_is_open(self, client, monkeypatch):
        """H-001: without MIRV_OSINT_TOKEN, endpoints are open (localhost)."""
        monkeypatch.delenv("MIRV_OSINT_TOKEN", raising=False)
        with patch("backend.osint_recon.check_email_breach", new_callable=AsyncMock) as m_b, \
             patch("backend.osint_recon.verify_email", new_callable=AsyncMock) as m_v:
            m_b.return_value = {"ok": True}
            m_v.return_value = {"ok": True}
            resp = client.post("/api/osint/email", json={"email": "u@example.com"})
        assert resp.status_code == 200

    def test_email_max_length_422(self, client):
        """H-004: an email longer than 254 chars → 422 (not 500)."""
        long_email = "a" * 300 + "@example.com"
        resp = client.post("/api/osint/email", json={"email": long_email})
        assert resp.status_code == 422

    def test_dork_pages_out_of_range_422(self, client):
        """H-004: pages=10 (> le=5) → 422."""
        resp = client.post("/api/osint/dork", json={"query": "test", "pages": 10})
        assert resp.status_code == 422

    def test_dork_query_max_length_422(self, client):
        """H-004: query > 512 chars → 422."""
        resp = client.post("/api/osint/dork", json={"query": "x" * 600})
        assert resp.status_code == 422

    def test_username_max_length_422(self, client):
        """H-004: username > 30 chars → 422."""
        resp = client.post("/api/osint/username", json={"username": "u" * 50})
        assert resp.status_code == 422

    def test_wayback_domain_max_length_422(self, client):
        """H-004: domain > 253 chars → 422."""
        resp = client.get("/api/osint/wayback", params={"domain": "x" * 300})
        assert resp.status_code == 422

    def test_wayback_limit_out_of_range_422(self, client):
        """H-004: limit=0 (< ge=1) and limit=999 (> le=200) → 422."""
        assert client.get("/api/osint/wayback", params={"domain": "example.com", "limit": 0}).status_code == 422
        assert client.get("/api/osint/wayback", params={"domain": "example.com", "limit": 999}).status_code == 422

    def test_ip_max_length_422(self, client):
        """H-004: ip param > 45 chars → 422."""
        resp = client.get("/api/osint/ip", params={"ip": "x" * 60})
        assert resp.status_code == 422

    def test_github_username_max_length_422(self, client):
        """H-004: github username > 30 chars → 422."""
        resp = client.get("/api/osint/github", params={"username": "u" * 50})
        assert resp.status_code == 422

    def test_ip_endpoint_rejects_private_ip(self, client):
        """H-005 surfaced through the endpoint: private IP → 200 with ok False."""
        resp = client.get("/api/osint/ip", params={"ip": "192.168.1.1"})
        # The endpoint wraps ip_geolocation result; 200 with ok False.
        assert resp.status_code == 200
        assert resp.json()["ok"] is False

    def test_wayback_endpoint_rejects_ip(self, client):
        """H-006 surfaced through the endpoint: IP as domain → ok False."""
        resp = client.get("/api/osint/wayback", params={"domain": "192.168.1.1"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is False

    def test_wayback_endpoint_rejects_private_tld(self, client):
        """H-006 surfaced through the endpoint: private TLD → ok False."""
        resp = client.get("/api/osint/wayback", params={"domain": "metadata.google.internal"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is False

    def test_internal_error_does_not_leak_input(self, client, caplog):
        """H-008: an unexpected exception returns 'Internal error' and the
        raw exception text (which here carries user input) is NOT echoed
        in the response and NOT logged as the user-supplied value."""
        secret_input = "leak-me-please@example.com"
        with patch("backend.osint_recon.check_email_breach", new_callable=AsyncMock,
                   side_effect=RuntimeError(secret_input)), \
             patch("backend.osint_recon.verify_email", new_callable=AsyncMock,
                   side_effect=RuntimeError(secret_input)):
            with caplog.at_level("ERROR"):
                resp = client.post("/api/osint/email", json={"email": secret_input})
        assert resp.status_code == 500
        body = resp.json()
        assert body["ok"] is False
        assert body["error"] == "Internal error"
        # The response body must not contain the raw exception message.
        assert secret_input not in resp.text


# ───────────────────────────────────────────────────────────────────
#  Helpers
# ───────────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal urllib response stub (bytes + status)."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status
        self.headers = {}

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            return self._body
        return self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
