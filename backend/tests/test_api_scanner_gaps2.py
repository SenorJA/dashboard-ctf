"""
Coverage-gap tests for backend/api_scanner.py.

Covers _check_sensitive_data hits, the base-URL retry and unreachable
paths, sensitive-data / protected / redirect branches in scan(), and the
dangerous-methods OPTIONS check.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

import backend.api_scanner as ap


class TestCheckSensitiveData:
    def test_finds_keyword(self):
        assert ap._check_sensitive_data('"password": "hunter2"') == ["password"]

    def test_finds_none(self):
        assert ap._check_sensitive_data("just a normal body") == []


class _EP:
    def __init__(self, status=200, headers=None, body="", size=0, path="/x", method="GET"):
        self.path = path
        self.method = method
        self.status_code = status
        self.headers = headers or {}
        self.body_preview = body
        self.content_length = size


class TestScanUnreachable:
    @pytest.mark.asyncio
    async def test_base_retry_then_unreachable(self):
        # First probe ("/") fails, second probe ("") also fails -> report.
        with patch("backend.api_scanner._probe_endpoint", new=AsyncMock(return_value=None)) as probe:
            report = await ap.scan("http://example.com", paths=["/a"])
        assert probe.await_count == 2
        assert report.endpoints_scanned == 0
        assert report.issues[0].category == "connectivity"
        assert report.issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_base_retry_succeeds(self):
        # First probe ("/") fails, second probe ("") succeeds -> scan continues.
        base_ep = _EP(status=200, headers={"server": "nginx"})
        probe = AsyncMock(side_effect=[None, base_ep, None, None])
        with patch("backend.api_scanner._probe_endpoint", new=probe):
            report = await ap.scan("http://example.com", paths=["/a"], timeout=1)
        assert report.base_url == "http://example.com"
        assert report.endpoints_scanned == 0
        assert probe.await_count == 4  # "/", "", "/a", OPTIONS "/"

    @pytest.mark.asyncio
    async def test_sensitive_and_protected_and_redirect(self):
        base_ep = _EP(status=200, headers={})
        paths = ["/secret", "/admin", "/old", "/open"]
        open_ep = _EP(status=200, body='{"token":"abc"}', path="/open")
        results = [base_ep, base_ep, base_ep, open_ep]  # base + 3 probes
        # Order: base "/" + 3 paths + OPTIONS
        probe = AsyncMock(side_effect=[
            base_ep,            # base "/"
            _EP(status=200, body='{"token":"x"}', path="/secret"),
            _EP(status=401, headers={}, path="/admin"),
            _EP(status=302, headers={"location": "/login"}, path="/old"),
            _EP(status=200, headers={}, path="/open"),
            _EP(status=204, headers={"allow": "GET, PUT, DELETE"}, path="/"),
        ])
        with patch("backend.api_scanner._probe_endpoint", new=probe):
            report = await ap.scan("http://example.com", paths=paths, timeout=1)

        cats = {i.category for i in report.issues}
        assert "data_exposure" in cats
        assert "auth" in cats
        assert "config" in cats  # redirect issue
        assert any("Dangerous HTTP methods" in i.title for i in report.issues)
        assert report.cors_enabled is False

    @pytest.mark.asyncio
    async def test_redirect_without_location(self):
        base_ep = _EP(status=200, headers={})
        probe = AsyncMock(side_effect=[
            base_ep,
            _EP(status=308, headers={}, path="/moved"),
            _EP(status=200, headers={}, path="/x"),
            None,  # OPTIONS
        ])
        with patch("backend.api_scanner._probe_endpoint", new=probe):
            report = await ap.scan("http://example.com", paths=["/moved"], timeout=1)
        assert any(i.category == "config" and "Redirect" in i.title for i in report.issues)
