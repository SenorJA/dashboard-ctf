"""
tests/test_subdomain_scanner.py — Tests for subdomain_scanner module.

Covers:
    1. scan() — example.com with default wordlist (real DNS)
    2. scan() — non-existent domain returns empty results gracefully
    3. scan() — URL-prefixed domain input is sanitised
    4. scan() — custom tiny subdomain list
    5. scan() — result shape: SubdomainReport has required fields
    6. report_to_mirv_findings() — populated report conversion
    7. report_to_mirv_findings() — empty report (zero found)
    8. report_to_mirv_findings() — every finding has required MIRV keys
    9. SubdomainResult / SubdomainReport dataclass contracts

NOTE: Tests 1-2 involve real DNS lookups and may be slow or
      flaky on networks with restricted DNS.  They are marked
      with ``@pytest.mark.timeout(120)`` for safety.
"""

from __future__ import annotations

import pytest

from subdomain_scanner import (
    COMMON_SUBDOMAINS,
    SubdomainReport,
    SubdomainResult,
    report_to_mirv_findings,
    scan,
)


# ──────────────────────────────────────────────
# 1. scan — example.com (real DNS, default wordlist)
# ──────────────────────────────────────────────
@pytest.mark.timeout(120)
@pytest.mark.asyncio
async def test_scan_example_com():
    """scan('example.com') should return a SubdomainReport with at least www."""
    report: SubdomainReport = await scan(
        domain="example.com",
        timeout=3.0,
        concurrency=50,
    )

    assert isinstance(report, SubdomainReport)
    assert report.domain == "example.com"
    assert report.total_checked == len(COMMON_SUBDOMAINS)
    assert report.duration_seconds > 0

    # example.com is well-known; www should resolve at minimum
    assert report.found >= 1, (
        f"Expected at least 1 subdomain for example.com, got {report.found}"
    )

    # Every result must be a SubdomainResult with correct shape
    for r in report.results:
        assert isinstance(r, SubdomainResult)
        assert r.domain == "example.com"
        assert len(r.resolved_ips) >= 1
        for ip in r.resolved_ips:
            octets = ip.split(".")
            assert len(octets) == 4, f"Expected IPv4, got {ip!r}"


# ──────────────────────────────────────────────
# 2. scan — non-existent domain (graceful handling)
# ──────────────────────────────────────────────
@pytest.mark.timeout(120)
@pytest.mark.asyncio
async def test_scan_nonexistent_domain():
    """scan for a domain that definitely does not exist returns zero found."""
    report: SubdomainReport = await scan(
        domain="this-domain-definitely-does-not-exist-xyz123.com",
        timeout=2.0,
        concurrency=20,
    )

    assert isinstance(report, SubdomainReport)
    assert report.domain == "this-domain-definitely-does-not-exist-xyz123.com"
    assert report.found == 0
    assert report.results == []
    assert report.duration_seconds >= 0


# ──────────────────────────────────────────────
# 3. scan — URL-prefixed domain is sanitised
# ──────────────────────────────────────────────
@pytest.mark.timeout(120)
@pytest.mark.asyncio
async def test_scan_url_prefix_stripped():
    """Passing 'https://example.com' should strip prefix and scan example.com."""
    report: SubdomainReport = await scan(
        domain="https://example.com/path?q=1",
        timeout=3.0,
        concurrency=20,
    )

    assert isinstance(report, SubdomainReport)
    # Domain should be cleaned: no protocol, no path, no port
    assert report.domain == "example.com"


# ──────────────────────────────────────────────
# 4. scan — custom tiny subdomain list
# ──────────────────────────────────────────────
@pytest.mark.timeout(60)
@pytest.mark.asyncio
async def test_scan_custom_subdomain_list():
    """Passing a custom 3-element list should only check those 3."""
    custom = ["www", "nonexistent12345", "alsofake67890"]
    report: SubdomainReport = await scan(
        domain="example.com",
        subdomains=custom,
        timeout=3.0,
        concurrency=10,
    )

    assert isinstance(report, SubdomainReport)
    assert report.total_checked == 3
    # www.example.com should still resolve
    assert report.found >= 1
    found_names = {r.subdomain for r in report.results}
    assert "www" in found_names


# ──────────────────────────────────────────────
# 5. scan — result shape (all required fields)
# ──────────────────────────────────────────────
@pytest.mark.timeout(60)
@pytest.mark.asyncio
async def test_scan_result_shape():
    """SubdomainReport has all expected fields regardless of domain."""
    report: SubdomainReport = await scan(
        domain="example.com",
        subdomains=["www", "nonexistent12345"],
        timeout=3.0,
        concurrency=10,
    )

    assert isinstance(report, SubdomainReport)
    # Required scalar fields
    assert hasattr(report, "domain")
    assert hasattr(report, "total_checked")
    assert hasattr(report, "found")
    assert hasattr(report, "results")
    assert hasattr(report, "duration_seconds")

    # Type checks
    assert isinstance(report.domain, str)
    assert isinstance(report.total_checked, int)
    assert isinstance(report.found, int)
    assert isinstance(report.results, list)
    assert isinstance(report.duration_seconds, float)


# ──────────────────────────────────────────────
# 6. report_to_mirv_findings — populated report
# ──────────────────────────────────────────────
@pytest.mark.timeout(60)
@pytest.mark.asyncio
async def test_report_to_mirv_findings_populated():
    """Convert a real scan into MIRV findings; expect per-subdomain + summary."""
    report: SubdomainReport = await scan(
        domain="example.com",
        subdomains=["www", "nonexistent12345"],
        timeout=3.0,
        concurrency=10,
    )

    findings = report_to_mirv_findings(report)

    assert isinstance(findings, list)
    # At least one per-result finding + one summary
    assert len(findings) >= 2, (
        f"Expected >=2 findings (result + summary), got {len(findings)}"
    )

    # Last finding is always the summary
    summary = findings[-1]
    assert summary["tool"] == "subdomain-scan"
    assert summary["type"] == "tech"
    assert summary["target"] == "example.com"
    assert "Scan complete" in summary["title"]


# ──────────────────────────────────────────────
# 7. report_to_mirv_findings — zero-found report
# ──────────────────────────────────────────────
def test_report_to_mirv_findings_empty():
    """An empty report should return exactly one 'No subdomains found' finding."""
    empty_report = SubdomainReport(
        domain="noexist.test",
        total_checked=500,
        found=0,
        results=[],
        duration_seconds=0.0,
    )

    findings = report_to_mirv_findings(empty_report)

    assert isinstance(findings, list)
    assert len(findings) == 1
    assert "No subdomains found" in findings[0]["title"]
    assert findings[0]["severity"] == "info"
    assert findings[0]["tool"] == "subdomain-scan"
    assert findings[0]["target"] == "noexist.test"
    assert findings[0]["type"] == "tech"


# ──────────────────────────────────────────────
# 8. report_to_mirv_findings — every finding has MIRV keys
# ──────────────────────────────────────────────
@pytest.mark.timeout(60)
@pytest.mark.asyncio
async def test_findings_have_mirv_keys():
    """Every finding dict must contain tool, severity, title, detail, target, type."""
    report: SubdomainReport = await scan(
        domain="example.com",
        subdomains=["www", "nonexistent12345"],
        timeout=3.0,
        concurrency=10,
    )

    findings = report_to_mirv_findings(report)
    required_keys = {"tool", "severity", "title", "detail", "target", "type"}

    for f in findings:
        assert required_keys.issubset(f.keys()), (
            f"Missing MIRV keys: {required_keys - f.keys()} in finding {f}"
        )
        assert f["tool"] == "subdomain-scan"
        assert f["severity"] in ("info", "low", "medium", "high", "critical")
        assert isinstance(f["title"], str) and len(f["title"]) > 0
        assert isinstance(f["detail"], str) and len(f["detail"]) > 0
        assert isinstance(f["target"], str) and len(f["target"]) > 0
        assert f["type"] == "tech"


# ──────────────────────────────────────────────
# 9. SubdomainResult dataclass contract
# ──────────────────────────────────────────────
def test_subdomain_result_dataclass():
    """SubdomainResult is a frozen dataclass with expected attributes."""
    r = SubdomainResult(
        subdomain="www",
        domain="example.com",
        full_domain="www.example.com",
        resolved_ips=["93.184.216.34"],
        record_type="A",
        cname_target=None,
    )

    assert r.subdomain == "www"
    assert r.domain == "example.com"
    assert r.full_domain == "www.example.com"
    assert r.resolved_ips == ["93.184.216.34"]
    assert r.record_type == "A"
    assert r.cname_target is None

    # Frozen: cannot mutate
    with pytest.raises(AttributeError):
        r.subdomain = "hacked"


# ──────────────────────────────────────────────
# 10. SubdomainReport dataclass contract
# ──────────────────────────────────────────────
def test_subdomain_report_dataclass():
    """SubdomainReport is a frozen dataclass with expected attributes."""
    report = SubdomainReport(
        domain="example.com",
        total_checked=700,
        found=3,
        results=[],
        duration_seconds=12.34,
    )

    assert report.domain == "example.com"
    assert report.total_checked == 700
    assert report.found == 3
    assert report.results == []
    assert report.duration_seconds == 12.34

    # Frozen: cannot mutate
    with pytest.raises(AttributeError):
        report.domain = "hacked.com"


# ──────────────────────────────────────────────
# 11. COMMON_SUBDOMAINS sanity
# ──────────────────────────────────────────────
def test_common_subdomains_not_empty():
    """The built-in wordlist should be populated with common entries."""
    assert len(COMMON_SUBDOMAINS) > 100, (
        f"Wordlist too small: {len(COMMON_SUBDOMAINS)} entries"
    )
    # Must include well-known prefixes
    must_have = {"www", "admin", "api", "mail", "dev", "test", "vpn", "ftp"}
    actual = set(COMMON_SUBDOMAINS)
    assert must_have.issubset(actual), (
        f"Missing critical prefixes: {must_have - actual}"
    )
