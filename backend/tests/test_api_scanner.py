"""
Unit tests for backend/api_scanner.py

Covers:
  - scan() against reachable real targets (httpbin.org, example.com)
  - scan() against an unreachable / invalid URL (graceful error handling)
  - report_to_mirv_findings() output schema validation
  - Missing security header detection
  - Response shape and dataclass field types
"""

from __future__ import annotations

import pytest

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api_scanner import (
    ApiScanReport,
    ApiIssue,
    ApiEndpoint,
    scan,
    report_to_mirv_findings,
)


# ===================================================================
# Helpers
# ===================================================================

FINDING_SCHEMA_KEYS = {"tool", "severity", "title", "detail", "target", "type"}
VALID_SEVERITIES = {"high", "medium", "low", "info"}
VALID_TYPES = {"vuln", "tech"}


def _assert_report_shape(report: ApiScanReport) -> None:
    """Assert every field on an ApiScanReport has the expected type."""
    assert isinstance(report, ApiScanReport)
    assert isinstance(report.base_url, str)
    assert report.base_url.startswith("https://")
    assert isinstance(report.endpoints_scanned, int)
    assert report.endpoints_scanned >= 0
    assert isinstance(report.issues, list)
    assert isinstance(report.open_endpoints, list)
    assert isinstance(report.duration_seconds, float)
    assert report.duration_seconds >= 0
    assert isinstance(report.cors_enabled, bool)
    assert isinstance(report.auth_required, bool)
    assert isinstance(report.missing_headers, list)
    assert isinstance(report.info_disclosures, list)

    for issue in report.issues:
        assert isinstance(issue, ApiIssue)
        assert issue.severity in VALID_SEVERITIES
        assert isinstance(issue.title, str)
        assert isinstance(issue.detail, str)
        assert isinstance(issue.category, str)

    for ep in report.open_endpoints:
        assert isinstance(ep, ApiEndpoint)
        assert isinstance(ep.path, str)
        assert isinstance(ep.method, str)
        assert isinstance(ep.status_code, int)
        assert isinstance(ep.content_length, int)
        assert isinstance(ep.response_time, float)


def _assert_finding_schema(finding: dict) -> None:
    """Assert a single MIRV finding dict has the required keys and types."""
    assert isinstance(finding, dict)
    missing = FINDING_SCHEMA_KEYS - set(finding.keys())
    assert not missing, f"Finding missing keys: {missing}"

    assert finding["tool"] == "api-scanner"
    assert isinstance(finding["severity"], str)
    assert finding["severity"] in VALID_SEVERITIES
    assert isinstance(finding["title"], str)
    assert len(finding["title"]) > 0
    assert isinstance(finding["detail"], str)
    assert len(finding["detail"]) > 0
    assert isinstance(finding["target"], str)
    assert isinstance(finding["type"], str)
    assert finding["type"] in VALID_TYPES

    # extra is optional but when present must be a dict
    if "extra" in finding:
        assert isinstance(finding["extra"], dict)


# ===================================================================
# 1. scan() against httpbin.org — real reachable target
# ===================================================================

class TestScanHttpbin:
    """Integration tests hitting https://httpbin.org."""

    @pytest.mark.asyncio
    async def test_scan_returns_report(self):
        """scan(httpbin.org) returns a well-formed ApiScanReport."""
        report = await scan("https://httpbin.org", timeout=15.0)
        _assert_report_shape(report)

    @pytest.mark.asyncio
    async def test_scan_probes_endpoints(self):
        """httpbin.org should respond to at least some common paths."""
        report = await scan("https://httpbin.org", timeout=15.0)
        assert report.endpoints_scanned > 0, (
            f"Expected at least 1 endpoint scanned, got {report.endpoints_scanned}"
        )

    @pytest.mark.asyncio
    async def test_scan_base_url_preserved(self):
        """The base_url in the report matches the input URL."""
        report = await scan("https://httpbin.org", timeout=15.0)
        assert report.base_url == "https://httpbin.org"

    @pytest.mark.asyncio
    async def test_scan_finds_issues_or_not(self):
        """Report may or may not find issues — but the list must be valid."""
        report = await scan("https://httpbin.org", timeout=15.0)
        assert isinstance(report.issues, list)
        for issue in report.issues:
            assert isinstance(issue, ApiIssue)
            assert issue.severity in VALID_SEVERITIES

    @pytest.mark.asyncio
    async def test_scan_mirv_findings_format(self):
        """report_to_mirv_findings produces valid finding dicts from httpbin scan."""
        report = await scan("https://httpbin.org", timeout=15.0)
        findings = report_to_mirv_findings(report)

        assert isinstance(findings, list)
        assert len(findings) >= 1, "Should have at least the summary finding"

        for f in findings:
            _assert_finding_schema(f)

    @pytest.mark.asyncio
    async def test_scan_first_finding_is_summary(self):
        """The first MIRV finding is always the summary entry."""
        report = await scan("https://httpbin.org", timeout=15.0)
        findings = report_to_mirv_findings(report)
        summary = findings[0]
        assert "API Scan:" in summary["title"]
        assert summary["severity"] == "info"
        assert summary["type"] == "tech"
        assert "extra" in summary
        assert "endpoints_scanned" in summary["extra"]
        assert "issues_count" in summary["extra"]

    @pytest.mark.asyncio
    async def test_scan_duration_positive(self):
        """Duration should be a positive number (the scan actually did work)."""
        report = await scan("https://httpbin.org", timeout=15.0)
        assert report.duration_seconds > 0


# ===================================================================
# 2. scan() with invalid / unreachable URL — graceful error handling
# ===================================================================

class TestScanInvalidUrl:
    """Verify scan() does not crash on unreachable targets."""

    @pytest.mark.asyncio
    async def test_unreachable_domain_returns_report(self):
        """A completely unreachable domain returns a report with 0 endpoints."""
        report = await scan("https://this-host-does-not-exist-xyz.invalid", timeout=5.0)
        _assert_report_shape(report)
        assert report.endpoints_scanned == 0
        assert len(report.issues) >= 1
        assert report.issues[0].severity == "high"
        assert "not reachable" in report.issues[0].title.lower() or "not respond" in report.issues[0].detail.lower()

    @pytest.mark.asyncio
    async def test_unreachable_report_has_connectivity_issue(self):
        """Unreachable URL should produce a connectivity-category issue."""
        report = await scan("https://this-host-does-not-exist-xyz.invalid", timeout=5.0)
        connectivity_issues = [i for i in report.issues if i.category == "connectivity"]
        assert len(connectivity_issues) >= 1

    @pytest.mark.asyncio
    async def test_unreachable_report_zero_endpoints(self):
        """No endpoints can be scanned if the host is unreachable."""
        report = await scan("https://this-host-does-not-exist-xyz.invalid", timeout=5.0)
        assert report.endpoints_scanned == 0
        assert len(report.open_endpoints) == 0

    @pytest.mark.asyncio
    async def test_bad_url_gets_normalized(self):
        """A URL without scheme gets https:// prepended and still runs."""
        report = await scan("this-host-does-not-exist-xyz.invalid", timeout=5.0)
        _assert_report_shape(report)
        assert report.base_url.startswith("https://")


# ===================================================================
# 3. report_to_mirv_findings() — schema validation
# ===================================================================

class TestMIRVFindingsSchema:
    """Ensure every finding from report_to_mirv_findings has correct schema."""

    @pytest.mark.asyncio
    async def test_all_findings_have_required_keys(self):
        """Every finding must contain tool, severity, title, detail, target, type."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        for f in findings:
            _assert_finding_schema(f)

    @pytest.mark.asyncio
    async def test_finding_severity_in_valid_set(self):
        """All severities must be one of: high, medium, low, info."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        for f in findings:
            assert f["severity"] in VALID_SEVERITIES, (
                f"Unexpected severity {f['severity']!r} in finding: {f['title']}"
            )

    @pytest.mark.asyncio
    async def test_finding_type_in_valid_set(self):
        """All types must be one of: vuln, tech."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        for f in findings:
            assert f["type"] in VALID_TYPES, (
                f"Unexpected type {f['type']!r} in finding: {f['title']}"
            )

    @pytest.mark.asyncio
    async def test_tool_field_always_api_scanner(self):
        """Every finding must be attributed to 'api-scanner' tool."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        for f in findings:
            assert f["tool"] == "api-scanner"

    @pytest.mark.asyncio
    async def test_target_matches_base_url(self):
        """Every finding's target must equal the report's base_url."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        for f in findings:
            assert f["target"] == report.base_url

    @pytest.mark.asyncio
    async def test_extra_contains_category_when_present(self):
        """Issue-based findings must include extra.category."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        # Skip the summary finding (index 0)
        issue_findings = findings[1:]
        for f in issue_findings:
            if "extra" in f:
                assert "category" in f["extra"], (
                    f"Finding {f['title']!r} has extra but no category"
                )


# ===================================================================
# 4. scan() against example.com — missing security headers
# ===================================================================

class TestScanExampleCom:
    """example.com is a minimal server that should lack security headers."""

    @pytest.mark.asyncio
    async def test_scan_returns_report(self):
        """example.com scan returns a valid report."""
        report = await scan("https://example.com", timeout=15.0)
        _assert_report_shape(report)

    @pytest.mark.asyncio
    async def test_scan_finds_missing_headers(self):
        """example.com should be missing at least some security headers."""
        report = await scan("https://example.com", timeout=15.0)
        assert len(report.missing_headers) > 0, (
            "Expected example.com to be missing security headers "
            f"but missing_headers={report.missing_headers}"
        )

    @pytest.mark.asyncio
    async def test_missing_headers_are_strings(self):
        """Each entry in missing_headers is a descriptive string."""
        report = await scan("https://example.com", timeout=15.0)
        for h in report.missing_headers:
            assert isinstance(h, str)
            assert len(h) > 0

    @pytest.mark.asyncio
    async def test_issues_include_header_category(self):
        """When headers are missing, at least one issue should have category=headers."""
        report = await scan("https://example.com", timeout=15.0)
        header_issues = [i for i in report.issues if i.category == "headers"]
        assert len(header_issues) >= 1, (
            "Expected at least one 'headers' category issue for example.com"
        )

    @pytest.mark.asyncio
    async def test_example_com_finds_hsts_missing(self):
        """example.com (plain HTTPS, no HSTS) should list HSTS as missing."""
        report = await scan("https://example.com", timeout=15.0)
        hsts_missing = any(
            "HSTS" in h for h in report.missing_headers
        )
        assert hsts_missing, (
            f"Expected HSTS in missing_headers, got: {report.missing_headers}"
        )

    @pytest.mark.asyncio
    async def test_example_com_finds_csp_missing(self):
        """example.com should have no Content-Security-Policy header."""
        report = await scan("https://example.com", timeout=15.0)
        csp_missing = any(
            "Content-Security-Policy" in h for h in report.missing_headers
        )
        assert csp_missing, (
            f"Expected CSP in missing_headers, got: {report.missing_headers}"
        )

    @pytest.mark.asyncio
    async def test_mirv_findings_from_example_com(self):
        """Convert example.com scan to MIRV findings and validate all."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        assert len(findings) > 1, "Should have summary + at least one issue"
        for f in findings:
            _assert_finding_schema(f)


# ===================================================================
# 5. Edge cases and unit-level logic
# ===================================================================

class TestEdgeCases:
    """Smaller targeted tests for edge-case behaviour."""

    @pytest.mark.asyncio
    async def test_scan_with_custom_paths(self):
        """Passing a short custom path list limits the scan scope."""
        custom_paths = ["/", "/does-not-exist-xyz"]
        report = await scan(
            "https://httpbin.org",
            paths=custom_paths,
            timeout=15.0,
        )
        # Only 2 paths were scanned (plus the base probe),
        # so endpoints_scanned <= 2
        assert report.endpoints_scanned <= 2
        _assert_report_shape(report)

    @pytest.mark.asyncio
    async def test_scan_concurrency_does_not_crash(self):
        """Low concurrency setting should still produce a valid report."""
        report = await scan("https://httpbin.org", concurrency=1, timeout=15.0)
        _assert_report_shape(report)

    def test_normalize_url_strips_trailing_slash(self):
        """_normalize_url should strip trailing slashes."""
        from api_scanner import _normalize_url
        assert _normalize_url("https://example.com/") == "https://example.com"
        assert _normalize_url("https://example.com//") == "https://example.com"

    def test_normalize_url_adds_scheme(self):
        """_normalize_url prepends https:// when scheme is missing."""
        from api_scanner import _normalize_url
        assert _normalize_url("example.com") == "https://example.com"

    def test_normalize_url_preserves_http(self):
        """_normalize_url keeps http:// if explicitly provided."""
        from api_scanner import _normalize_url
        assert _normalize_url("http://example.com") == "http://example.com"

    def test_issue_dataclass_fields(self):
        """ApiIssue dataclass accepts all documented fields."""
        issue = ApiIssue(
            severity="medium",
            title="Test Issue",
            detail="Some detail here",
            endpoint="/api/test",
            category="headers",
        )
        assert issue.severity == "medium"
        assert issue.title == "Test Issue"
        assert issue.endpoint == "/api/test"
        assert issue.category == "headers"

    def test_endpoint_dataclass_defaults(self):
        """ApiEndpoint default fields work correctly."""
        ep = ApiEndpoint(
            path="/test",
            method="GET",
            status_code=200,
            content_length=1024,
            response_time=0.123,
        )
        assert ep.headers == {}
        assert ep.body_preview == ""
        assert ep.authenticated is False
