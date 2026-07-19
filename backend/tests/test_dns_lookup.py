"""
tests/test_dns_lookup.py — Tests for dns_lookup module.

Covers:
    1. lookup() — A records for example.com
    2. lookup() — MX records for example.com
    3. lookup() — NXDOMAIN handling for invalid domain
    4. reverse_lookup() — PTR for 8.8.8.8
    5. reverse_lookup() — error handling for invalid IP
    6. report_to_mirv_findings() — conversion logic
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from dns_lookup import (
    DNSRecord,
    DNSReport,
    lookup,
    report_to_mirv_findings,
    reverse_lookup,
)


# ──────────────────────────────────────────────
# 1. lookup — A records for example.com
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_lookup_domain_a_records():
    """lookup('example.com', ['A']) should return at least one A record."""
    report: DNSReport = await lookup(
        domain="example.com",
        record_types=["A"],
    )

    assert isinstance(report, DNSReport)
    assert report.domain == "example.com"
    assert report.duration_seconds > 0
    assert "A" in report.records, "Expected A records for example.com"
    assert len(report.records["A"]) >= 1, "Should have at least 1 A record"

    record = report.records["A"][0]
    assert isinstance(record, DNSRecord)
    assert record.type == "A"
    assert record.name.endswith("example.com")
    # Sanity: value should look like an IPv4 address
    octets = record.value.split(".")
    assert len(octets) == 4, f"Expected IPv4, got {record.value!r}"
    assert all(o.isdigit() and 0 <= int(o) <= 255 for o in octets)


# ──────────────────────────────────────────────
# 2. lookup — MX records for example.com
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_lookup_domain_mx_records():
    """lookup('example.com', ['MX']) should return MX records."""
    report: DNSReport = await lookup(
        domain="example.com",
        record_types=["MX"],
    )

    assert isinstance(report, DNSReport)
    assert report.domain == "example.com"
    assert report.duration_seconds > 0
    assert "MX" in report.records, "Expected MX records for example.com"
    assert len(report.records["MX"]) >= 1, "Should have at least 1 MX record"

    record = report.records["MX"][0]
    assert isinstance(record, DNSRecord)
    assert record.type == "MX"
    assert record.ttl >= 0
    # MX value should contain a mail server hostname
    assert "." in record.value, f"MX value looks invalid: {record.value!r}"


# ──────────────────────────────────────────────
# 3. lookup — NXDOMAIN handled gracefully
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_lookup_invalid_domain_nxdomain():
    """lookup for a non-existent domain should return an empty records dict."""
    report: DNSReport = await lookup(
        domain="invalid-domain-xyz.test",
        record_types=["A"],
    )

    assert isinstance(report, DNSReport)
    assert report.domain == "invalid-domain-xyz.test"
    # NXDOMAIN means no records — the module handles this gracefully
    assert report.records == {}, "NXDOMAIN should produce empty records"
    assert report.duration_seconds >= 0


# ──────────────────────────────────────────────
# 4. reverse_lookup — 8.8.8.8
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_reverse_lookup_valid_ip():
    """reverse_lookup('8.8.8.8') — may or may not resolve from container."""
    report: DNSReport = await reverse_lookup(ip="8.8.8.8")

    assert isinstance(report, DNSReport)
    assert report.domain == "8.8.8.8"
    assert report.duration_seconds >= 0
    # 8.8.8.8 may or may not resolve (depends on container DNS env)
    # Just verify the report structure is valid either way
    if report.reverse_dns is not None:
        assert isinstance(report.reverse_dns, str)
        assert len(report.reverse_dns) > 0
        assert "PTR" in report.records
    else:
        assert report.records == {} or "PTR" not in report.records


# ──────────────────────────────────────────────
# 5. reverse_lookup — invalid IP (error handling)
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_reverse_lookup_invalid_ip():
    """reverse_lookup with a garbage IP should not raise, just return empty."""
    report: DNSReport = await reverse_lookup(ip="not-an-ip")

    assert isinstance(report, DNSReport)
    assert report.domain == "not-an-ip"
    assert report.reverse_dns is None, "Invalid IP should yield no reverse DNS"
    assert report.records == {}, "Invalid IP should yield empty records"
    assert report.duration_seconds >= 0


@pytest.mark.asyncio
async def test_reverse_lookup_private_unresolvable():
    """reverse_lookup for a non-routable IP should handle gracefully."""
    report: DNSReport = await reverse_lookup(ip="192.0.2.1")

    assert isinstance(report, DNSReport)
    assert report.domain == "192.0.2.1"
    # May or may not resolve — but must not crash
    assert isinstance(report.reverse_dns, type(None)) or isinstance(
        report.reverse_dns, str
    )


# ──────────────────────────────────────────────
# 6. report_to_mirv_findings — conversion
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_report_to_mirv_findings_populated():
    """report_to_mirv_findings should convert a real lookup into findings."""
    report: DNSReport = await lookup(
        domain="example.com",
        record_types=["A"],
    )
    findings = report_to_mirv_findings(report, "example.com")

    assert isinstance(findings, list)
    assert len(findings) >= 2, "Should have per-record findings + summary"

    # Every finding must have the required MIRV keys
    for f in findings:
        assert "tool" in f
        assert "severity" in f
        assert "title" in f
        assert "detail" in f
        assert "target" in f
        assert "type" in f
        assert f["tool"] == "dns-lookup"
        assert f["target"] == "example.com"

    # Last finding is the summary
    summary = findings[-1]
    assert "records across" in summary["title"]


def test_report_to_mirv_findings_empty():
    """report_to_mirv_findings with no records should return a single info finding."""
    empty_report = DNSReport(
        domain="noexist.test",
        records={},
        reverse_dns=None,
        duration_seconds=0.0,
    )
    findings = report_to_mirv_findings(empty_report, "noexist.test")

    assert isinstance(findings, list)
    assert len(findings) == 1
    assert "No DNS records found" in findings[0]["title"]
    assert findings[0]["severity"] == "info"


# ──────────────────────────────────────────────
# 7. lookup — multiple record types at once
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_lookup_multiple_record_types():
    """lookup with multiple types should return a superset of record dicts."""
    report: DNSReport = await lookup(
        domain="example.com",
        record_types=["A", "NS"],
    )

    assert isinstance(report, DNSReport)
    assert "A" in report.records, "Expected A records"
    assert "NS" in report.records, "Expected NS records"
    assert report.duration_seconds > 0
