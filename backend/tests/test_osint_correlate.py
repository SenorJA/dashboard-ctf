"""
tests/test_osint_correlate.py — Parallel OSINT correlation engine.

Covers :mod:`backend.osint_correlate` (``correlate_target``) and the
``POST /api/osint/correlate`` endpoint. All underlying OSINT sources
are mocked (``AsyncMock``) — no network traffic is generated.

Covers:
  - email  → check_email_breach + verify_email in parallel
  - username → username_recon + github_recon in parallel
  - domain  → wayback_machine_lookup + scan_passive (SubdomainReport → dict)
  - phone   → phone_number_lookup (single source, structured for more)
  - unknown target_type → ok False / error envelope
  - global exception → ok False / error envelope
  - endpoint: 200 happy path, 422 (body + unknown type), 429 rate limit,
    401 token, 500 internal error
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, patch

import pytest

from backend.osint_correlate import (
    SUPPORTED_TARGET_TYPES,
    _subdomain_report_to_dict,
    correlate_target,
)
from backend.subdomain_scanner import SubdomainReport, SubdomainResult


# ── fakes ────────────────────────────────────────────────────────────────────


_BREACH = {"ok": True, "email": "u@example.com", "found": True, "breaches": [{"name": "Acme"}]}
_VERIFY = {"ok": True, "email": "u@example.com", "valid_format": True, "mx_records": ["mx.example.com"]}
_PLATFORMS = {"ok": True, "username": "target", "found": 3, "checked": 18, "profiles": []}
_GITHUB = {"ok": True, "username": "target", "profile": {"login": "target"}, "repos": []}
_WAYBACK = {"ok": True, "domain": "example.com", "total": 2, "snapshots": []}
_LOOKUP = {"ok": True, "phone": "+14155551234", "country": "United States", "carrier": None}


def _fake_subdomain_report() -> SubdomainReport:
    return SubdomainReport(
        domain="example.com",
        total_checked=5,
        found=2,
        results=[
            SubdomainResult(
                subdomain="www",
                domain="example.com",
                full_domain="www.example.com",
                resolved_ips=["1.2.3.4"],
                record_type="A",
                cname_target=None,
            ),
            SubdomainResult(
                subdomain="api",
                domain="example.com",
                full_domain="api.example.com",
                resolved_ips=[],
                record_type=None,
                cname_target=None,
            ),
        ],
        duration_seconds=0.42,
        sources=["crt.sh", "wayback"],
        errors=[],
    )


# ── unit: correlate_target ───────────────────────────────────────────────────


class TestCorrelateTarget:
    """Direct unit tests of the orchestrator (no HTTP, no network)."""

    @pytest.mark.asyncio
    async def test_email_runs_breach_and_verify_in_parallel(self):
        """email target → both sources invoked, results merged."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   return_value=_BREACH) as m_breach, \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY) as m_verify:
            result = await correlate_target("email", "u@example.com")
        assert result["ok"] is True
        assert result["target_type"] == "email"
        assert result["target"] == "u@example.com"
        assert result["results"]["breach"] == _BREACH
        assert result["results"]["verification"] == _VERIFY
        assert "duration_seconds" in result
        # Both sources were actually awaited (parallel fan-out).
        m_breach.assert_awaited_once()
        m_verify.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_email_parallelism_actually_concurrent(self):
        """Sources run concurrently (gather), not sequentially.

        If they were awaited one after the other the total wall time
        would be ~0.4s; in parallel it is ~0.2s.
        """
        async def slow(*a, **k):
            await asyncio.sleep(0.2)
            return {"ok": True}

        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   side_effect=slow), \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   side_effect=slow):
            result = await correlate_target("email", "u@example.com", timeout=5.0)
        assert result["ok"] is True
        # Parallel: ~0.2s. Add generous slack for slow CI runners.
        assert result["duration_seconds"] < 0.4

    @pytest.mark.asyncio
    async def test_username_runs_platforms_and_github_in_parallel(self):
        """username target → username_recon + github_recon invoked."""
        with patch("backend.osint_correlate.username_recon", new_callable=AsyncMock,
                   return_value=_PLATFORMS) as m_plat, \
             patch("backend.osint_correlate.github_recon", new_callable=AsyncMock,
                   return_value=_GITHUB) as m_gh:
            result = await correlate_target("username", "target")
        assert result["ok"] is True
        assert result["target_type"] == "username"
        assert result["results"]["platforms"] == _PLATFORMS
        assert result["results"]["github"] == _GITHUB
        m_plat.assert_awaited_once()
        m_gh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_domain_runs_wayback_and_subdomain_passive_in_parallel(self):
        """domain target → wayback + scan_passive, SubdomainReport → dict."""
        fake_report = _fake_subdomain_report()
        with patch("backend.osint_correlate.wayback_machine_lookup", new_callable=AsyncMock,
                   return_value=_WAYBACK) as m_way, \
             patch("backend.osint_correlate.scan_passive", new_callable=AsyncMock,
                   return_value=fake_report) as m_sub:
            result = await correlate_target("domain", "example.com")
        assert result["ok"] is True
        assert result["target_type"] == "domain"
        assert result["results"]["wayback"] == _WAYBACK
        sub = result["results"]["subdomains"]
        # SubdomainReport was converted to a plain JSON-serializable dict.
        assert isinstance(sub, dict)
        assert sub["domain"] == "example.com"
        assert sub["found"] == 2
        assert len(sub["results"]) == 2
        assert sub["results"][0]["full_domain"] == "www.example.com"
        assert sub["results"][0]["resolved_ips"] == ["1.2.3.4"]
        assert sub["sources"] == ["crt.sh", "wayback"]
        m_way.assert_awaited_once()
        m_sub.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_phone_runs_single_lookup(self):
        """phone target → phone_number_lookup, structured for more sources."""
        with patch("backend.osint_correlate.phone_number_lookup", new_callable=AsyncMock,
                   return_value=_LOOKUP) as m_ph:
            result = await correlate_target("phone", "+14155551234")
        assert result["ok"] is True
        assert result["target_type"] == "phone"
        assert result["results"]["lookup"] == _LOOKUP
        m_ph.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unknown_target_type_returns_error_envelope(self):
        """Unknown target_type → ok False + the canonical hint message."""
        result = await correlate_target("carrier-pigeon", "coo")
        assert result["ok"] is False
        assert "Unknown target_type" in result["error"]
        assert "email" in result["error"]
        assert "phone" in result["error"]

    @pytest.mark.asyncio
    async def test_target_type_is_case_insensitive(self):
        """EMAIL / Email / email all dispatch the same handler."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   return_value=_BREACH), \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY):
            for tt in ("EMAIL", "Email", "eMaIl"):
                result = await correlate_target(tt, "u@example.com")
        assert result["ok"] is True
        assert result["target_type"] == "email"

    @pytest.mark.asyncio
    async def test_source_exception_surfaces_as_ok_false(self):
        """If a source raises, the orchestrator never raises — returns ok False."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   side_effect=RuntimeError("boom")), \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY):
            result = await correlate_target("email", "u@example.com")
        assert result["ok"] is False
        assert result["error"] == "boom"

    @pytest.mark.asyncio
    async def test_strips_whitespace_and_empty_inputs(self):
        """Whitespace/None-ish inputs are tolerated (normalized)."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   return_value=_BREACH) as m_b, \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY) as m_v:
            result = await correlate_target("  email  ", "  u@example.com  ")
        assert result["ok"] is True
        assert result["target"] == "u@example.com"
        # The normalized target is forwarded to the sources.
        assert m_b.call_args.args[0] == "u@example.com"
        assert m_v.call_args.args[0] == "u@example.com"

    @pytest.mark.asyncio
    async def test_none_inputs_do_not_crash(self):
        """None target_type/target do not raise (defensive normalization)."""
        result = await correlate_target(None, None)  # type: ignore[arg-type]
        assert result["ok"] is False
        assert "Unknown target_type" in result["error"]

    @pytest.mark.asyncio
    async def test_supported_target_types_constant(self):
        """SUPPORTED_TARGET_TYPES enumerates every dispatched type."""
        assert set(SUPPORTED_TARGET_TYPES) == {"email", "username", "domain", "phone"}

    @pytest.mark.asyncio
    async def test_timeout_is_forwarded_to_sources(self):
        """The timeout kwarg is propagated to every source coroutine."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   return_value=_BREACH) as m_b, \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY) as m_v:
            await correlate_target("email", "u@example.com", timeout=3.5)
        assert m_b.call_args.kwargs["timeout"] == 3.5
        assert m_v.call_args.kwargs["timeout"] == 3.5


# ── unit: _subdomain_report_to_dict ──────────────────────────────────────────


class TestSubdomainReportSerialization:
    """Direct test of the dataclass→dict serializer."""

    def test_converts_nested_results(self):
        report = _fake_subdomain_report()
        d = _subdomain_report_to_dict(report)
        assert d["domain"] == "example.com"
        assert d["found"] == 2
        assert d["duration_seconds"] == 0.42
        assert d["sources"] == ["crt.sh", "wayback"]
        assert d["errors"] == []
        # Nested SubdomainResult also serialized.
        first = d["results"][0]
        assert first["full_domain"] == "www.example.com"
        assert first["resolved_ips"] == ["1.2.3.4"]
        assert first["record_type"] == "A"
        # JSON-serializable (no dataclass instances left behind).
        import json
        json.dumps(d)

    def test_empty_report(self):
        report = SubdomainReport(
            domain="x.example",
            total_checked=0,
            found=0,
            results=[],
            duration_seconds=0.0,
        )
        d = _subdomain_report_to_dict(report)
        assert d == {
            "domain": "x.example",
            "total_checked": 0,
            "found": 0,
            "results": [],
            "duration_seconds": 0.0,
            "sources": [],
            "errors": [],
        }


# ── endpoint integration ────────────────────────────────────────────────────


class TestOsintCorrelateEndpoint:
    """Integration tests through the FastAPI TestClient."""

    def test_email_happy_path(self, client):
        """200 with correlated results for a valid email target."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   return_value=_BREACH), \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY):
            resp = client.post(
                "/api/osint/correlate",
                json={"target_type": "email", "target": "u@example.com"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["target_type"] == "email"
        assert body["target"] == "u@example.com"
        assert body["results"]["breach"]["found"] is True
        assert body["results"]["verification"]["valid_format"] is True
        assert "duration_seconds" in body

    def test_domain_happy_path(self, client):
        """200 for a domain target — SubdomainReport serialized to dict."""
        with patch("backend.osint_correlate.wayback_machine_lookup", new_callable=AsyncMock,
                   return_value=_WAYBACK), \
             patch("backend.osint_correlate.scan_passive", new_callable=AsyncMock,
                   return_value=_fake_subdomain_report()):
            resp = client.post(
                "/api/osint/correlate",
                json={"target_type": "domain", "target": "example.com"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["results"]["wayback"]["domain"] == "example.com"
        assert body["results"]["subdomains"]["found"] == 2

    def test_phone_happy_path(self, client):
        with patch("backend.osint_correlate.phone_number_lookup", new_callable=AsyncMock,
                   return_value=_LOOKUP):
            resp = client.post(
                "/api/osint/correlate",
                json={"target_type": "phone", "target": "+14155551234"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["results"]["lookup"]["country"] == "United States"

    def test_422_on_invalid_body_missing_fields(self, client):
        """Missing required fields → 422 (Pydantic validation)."""
        resp = client.post("/api/osint/correlate", json={"target_type": "email"})
        assert resp.status_code == 422

    def test_422_on_target_too_long(self, client):
        """target longer than 254 chars → 422 (Field max_length)."""
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "email", "target": "x" * 300},
        )
        assert resp.status_code == 422

    def test_422_on_target_type_too_long(self, client):
        """target_type longer than 20 chars → 422."""
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "x" * 25, "target": "value"},
        )
        assert resp.status_code == 422

    def test_422_on_empty_target(self, client):
        """Empty target string → 422 from the route's explicit guard."""
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "email", "target": "   "},
        )
        assert resp.status_code == 422
        assert resp.json()["ok"] is False

    def test_422_on_unknown_target_type(self, client):
        """Unknown target_type → 422 with the canonical hint."""
        # Sources are NOT mocked — the dispatch must short-circuit before
        # touching them, proving the unknown-type branch is hit.
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "carrier-pigeon", "target": "coo"},
        )
        assert resp.status_code == 422
        body = resp.json()
        assert body["ok"] is False
        assert "Unknown target_type" in body["error"]

    def test_429_rate_limit(self, client):
        """H-002: rate-limit deny → 429 with Retry-After."""
        with patch("backend.rate_limiter.check_rate_limit", return_value=(False, 30)):
            resp = client.post(
                "/api/osint/correlate",
                json={"target_type": "phone", "target": "+14155551234"},
            )
        assert resp.status_code == 429
        body = resp.json()
        assert body["ok"] is False
        assert "Rate limit" in body["error"]
        assert resp.headers.get("Retry-After") == "30"

    def test_401_token_missing_when_configured(self, client, monkeypatch):
        """H-001: with MIRV_OSINT_TOKEN set, missing header → 401."""
        monkeypatch.setenv("MIRV_OSINT_TOKEN", "secret-shared-token")
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "email", "target": "u@example.com"},
        )
        assert resp.status_code == 401
        assert resp.json()["ok"] is False

    def test_401_token_wrong(self, client, monkeypatch):
        """H-001: wrong token value → 401."""
        monkeypatch.setenv("MIRV_OSINT_TOKEN", "secret-shared-token")
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "email", "target": "u@example.com"},
            headers={"X-MIRV-Token": "wrong"},
        )
        assert resp.status_code == 401

    def test_token_correct_allows_request(self, client, monkeypatch):
        """H-001: matching token → request proceeds normally."""
        monkeypatch.setenv("MIRV_OSINT_TOKEN", "secret-shared-token")
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   return_value=_BREACH), \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY):
            resp = client.post(
                "/api/osint/correlate",
                json={"target_type": "email", "target": "u@example.com"},
                headers={"X-MIRV-Token": "secret-shared-token"},
            )
        assert resp.status_code == 200

    def test_500_internal_error_does_not_leak(self, client, caplog):
        """H-008: an unexpected exception → 500 'Internal error', no leak."""
        secret = "leak-me-please@example.com"
        with patch("backend.osint_correlate.correlate_target", new_callable=AsyncMock,
                   side_effect=RuntimeError(secret)):
            with caplog.at_level("ERROR"):
                resp = client.post(
                    "/api/osint/correlate",
                    json={"target_type": "email", "target": secret},
                )
        assert resp.status_code == 500
        body = resp.json()
        assert body["ok"] is False
        assert body["error"] == "Internal error"
        # The raw exception message (carrying user input) is NOT echoed.
        assert secret not in resp.text

    def test_correlate_target_failure_propagated_as_200_envelope(self, client):
        """When correlate_target returns ok False (e.g. source raised),
        the endpoint forwards the envelope with 200 (not 500)."""
        with patch("backend.osint_correlate.check_email_breach", new_callable=AsyncMock,
                   side_effect=RuntimeError("boom")), \
             patch("backend.osint_correlate.verify_email", new_callable=AsyncMock,
                   return_value=_VERIFY):
            resp = client.post(
                "/api/osint/correlate",
                json={"target_type": "email", "target": "u@example.com"},
            )
        # Source-level failure is caught inside correlate_target → ok False;
        # the endpoint does not treat it as an internal error (no 500).
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["error"] == "boom"

    def test_correlate_target_unknown_type_returns_422(self, client):
        """correlate_target's own unknown-type envelope surfaces as 422."""
        resp = client.post(
            "/api/osint/correlate",
            json={"target_type": "unknown-thing", "target": "x"},
        )
        assert resp.status_code == 422
        assert "Unknown target_type" in resp.json()["error"]


# ── rate-limiter config sanity ───────────────────────────────────────────────


class TestRateLimiterConfig:
    """The 10/min bucket must be registered for the correlate route."""

    def test_correlate_limit_is_10_per_min(self):
        from backend.rate_limiter import _LIMITS
        assert _LIMITS["/api/osint/correlate"] == 10

    def test_correlate_bucket_actually_enforces(self):
        """After 10 hits in 60s the 11th must be denied."""
        from backend.rate_limiter import RateLimiter
        rl = RateLimiter()
        for _ in range(10):
            allowed, _ = rl.check("1.2.3.4", "/api/osint/correlate")
            assert allowed is True
        allowed, retry_after = rl.check("1.2.3.4", "/api/osint/correlate")
        assert allowed is False
        assert retry_after >= 1
