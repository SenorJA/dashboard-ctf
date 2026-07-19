"""
Unit + integration tests for backend/port_scanner.py

Covers:
  - Async TCP scan against a real public target (scanme.nmap.org)
  - Graceful error handling for unresolvable / unreachable hosts
  - Default port list when none is provided
  - ScanReport dataclass shape invariants
  - PortResult shape invariants
  - report_to_mirv_findings conversion
"""

from __future__ import annotations

import pytest
import socket

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from port_scanner import (
    COMMON_PORTS,
    PortResult,
    ScanReport,
    scan,
    report_to_mirv_findings,
)

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────
SCANME = "scanme.nmap.org"
SCANME_PORTS = [22, 80, 443, 8080]


# ===================================================================
# 1. ScanReport & PortResult shape invariants
# ===================================================================

class TestResponseShape:
    """Every scan() call must return a ScanReport with the required attributes
    and a results list whose elements are PortResult instances."""

    @pytest.mark.asyncio
    async def test_scan_report_has_required_attributes(self):
        """ScanReport returned by scan() must expose every expected field."""
        report = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)

        # Core identity fields
        assert isinstance(report, ScanReport)
        assert isinstance(report.target, str)
        assert isinstance(report.resolved_ip, str)

        # Numeric fields
        assert isinstance(report.ports_scanned, int)
        assert isinstance(report.open_ports, int)
        assert isinstance(report.duration_seconds, float)

        # Ports scanned must match what we asked for
        assert report.ports_scanned == len(SCANME_PORTS)
        assert report.target == SCANME

        # Duration must be non-negative
        assert report.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_results_are_port_result_instances(self):
        """Every item in report.results must be a PortResult dataclass."""
        report = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)

        assert isinstance(report.results, list)
        for pr in report.results:
            assert isinstance(pr, PortResult)
            assert isinstance(pr.port, int)
            assert isinstance(pr.service, str)
            assert pr.state in ("open", "closed", "filtered")
            # banner is optional (str or None)
            assert pr.banner is None or isinstance(pr.banner, str)

    @pytest.mark.asyncio
    async def test_open_ports_count_matches_results_length(self):
        """open_ports integer must equal the number of items in results."""
        report = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)
        assert report.open_ports == len(report.results)


# ===================================================================
# 2. Real scan against scanme.nmap.org
# ===================================================================

class TestScanScanmeNmap:
    """Integration tests that hit scanme.nmap.org — a target explicitly
    allowed by Nmap for scanning exercises."""

    @pytest.mark.asyncio
    async def test_scanme_has_open_ports(self):
        """scanme.nmap.org should have at least port 22 or 80 open."""
        report = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)

        assert report.ports_scanned == 4
        assert report.open_ports >= 1, (
            f"Expected at least 1 open port on {SCANME}, got {report.open_ports}"
        )

        open_port_numbers = {pr.port for pr in report.results}
        assert 22 in open_port_numbers or 80 in open_port_numbers, (
            f"Expected port 22 or 80 open on {SCANME}, found: {open_port_numbers}"
        )

    @pytest.mark.asyncio
    async def test_scanme_resolves_to_valid_ip(self):
        """The resolved_ip should be a valid dotted-quad address."""
        report = await scan(SCANME, ports=[22], timeout=10.0)

        # Should be able to parse it (may raise ValueError for invalid IPs)
        parts = report.resolved_ip.split(".")
        assert len(parts) == 4
        for part in parts:
            assert part.isdigit()
            assert 0 <= int(part) <= 255

    @pytest.mark.asyncio
    async def test_scanme_duration_is_reasonable(self):
        """Scanning 4 ports should complete well within 30 seconds."""
        report = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)
        assert report.duration_seconds < 30.0


# ===================================================================
# 3. Invalid / unresolvable target
# ===================================================================

class TestScanInvalidTarget:
    """Verify graceful handling when DNS resolution or connection fails."""

    @pytest.mark.asyncio
    async def test_nonexistent_domain_returns_no_open_ports(self):
        """A bogus domain that cannot resolve should produce zero open ports
        (not raise an exception — the module handles resolution errors)."""
        report = await scan(
            "this-host-definitely-does-not-exist-xyzzy.invalid",
            ports=[80],
            timeout=3.0,
        )
        assert isinstance(report, ScanReport)
        assert report.open_ports == 0
        assert report.results == []

    @pytest.mark.asyncio
    async def test_unreachable_private_ip_has_no_open_ports(self):
        """A non-routable IP should return zero open ports (timeouts → closed)."""
        # 192.0.2.1 is in TEST-NET, guaranteed non-routable per RFC 5737
        report = await scan("192.0.2.1", ports=[80], timeout=2.0)
        assert isinstance(report, ScanReport)
        assert report.open_ports == 0

    @pytest.mark.asyncio
    async def test_invalid_target_preserves_target_field(self):
        """Even on failure, ScanReport.target should reflect the original input."""
        report = await scan("no-such-host.example", ports=[80], timeout=3.0)
        assert report.target == "no-such-host.example"


# ===================================================================
# 4. Default port list (no ports specified)
# ===================================================================

class TestDefaultPortList:
    """When ports=None the scanner should use the full COMMON_PORTS list."""

    @pytest.mark.asyncio
    async def test_default_ports_uses_common_ports(self):
        """Passing no ports list should scan all COMMON_PORTS entries."""
        # Use a tiny timeout and a fast-failing host to keep this quick
        report = await scan(
            "192.0.2.1",  # TEST-NET — no ports open
            ports=None,
            timeout=1.0,
        )
        assert isinstance(report, ScanReport)
        assert report.ports_scanned == len(COMMON_PORTS)
        assert isinstance(report.results, list)

    @pytest.mark.asyncio
    async def test_default_ports_completes_in_reasonable_time(self):
        """Even with hundreds of ports, the scan should finish within 60 s
        at a 1 s timeout (concurrency keeps it fast)."""
        import time

        start = time.monotonic()
        report = await scan("192.0.2.1", ports=None, timeout=1.0)
        elapsed = time.monotonic() - start

        assert report.ports_scanned == len(COMMON_PORTS)
        assert elapsed < 60.0, f"Full-port scan took {elapsed:.1f}s — too slow"


# ===================================================================
# 5. report_to_mirv_findings conversion
# ===================================================================

class TestReportToMIRVFindings:
    """Verify that the MIRV finding conversion produces well-formed dicts."""

    @pytest.mark.asyncio
    async def test_findings_from_real_scan(self):
        """Scan scanme.nmap.org → report_to_mirv_findings should yield
        at least one finding with all required keys."""
        report = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)
        findings = report_to_mirv_findings(report)

        assert isinstance(findings, list)
        assert len(findings) >= 1

        required_keys = {"tool", "severity", "title", "detail", "target", "type"}
        for item in findings:
            assert isinstance(item, dict)
            assert required_keys.issubset(item.keys()), (
                f"Missing keys: {required_keys - item.keys()}"
            )
            assert item["tool"] == "port-scan"
            assert item["severity"] in ("info", "low", "medium", "high")
            assert item["target"] == SCANME

    def test_findings_for_empty_report(self):
        """Zero open ports → exactly one 'info' finding (no-open-ports notice)."""
        report = ScanReport(
            target="dead.host",
            resolved_ip="192.0.2.1",
            ports_scanned=10,
            open_ports=0,
            results=[],
            duration_seconds=0.01,
        )
        findings = report_to_mirv_findings(report)

        assert len(findings) == 1
        assert findings[0]["severity"] == "info"
        assert "No open ports" in findings[0]["title"]

    def test_findings_severity_mapping(self):
        """Port 22 → high, Port 80 → medium, Port 9999 → low."""
        report = ScanReport(
            target="test",
            resolved_ip="1.2.3.4",
            ports_scanned=3,
            open_ports=3,
            results=[
                PortResult(port=22, service="SSH", state="open"),
                PortResult(port=80, service="HTTP", state="open"),
                PortResult(port=9999, service="unknown", state="open"),
            ],
            duration_seconds=0.5,
        )
        findings = report_to_mirv_findings(report)
        # First 3 are per-port, last is summary
        per_port = findings[:-1]
        severities = {f["title"]: f["severity"] for f in per_port}

        assert severities["Port 22/SSH \u2014 OPEN"] == "high"
        assert severities["Port 80/HTTP \u2014 OPEN"] == "medium"
        assert severities["Port 9999/unknown \u2014 OPEN"] == "low"

    def test_summary_finding_is_last(self):
        """The final finding in the list should be the summary."""
        report = ScanReport(
            target="x",
            resolved_ip="1.1.1.1",
            ports_scanned=2,
            open_ports=2,
            results=[
                PortResult(port=22, service="SSH", state="open"),
                PortResult(port=80, service="HTTP", state="open"),
            ],
            duration_seconds=1.0,
        )
        findings = report_to_mirv_findings(report)
        summary = findings[-1]

        assert "Scan complete" in summary["title"]
        assert summary["severity"] == "info"
        assert summary["type"] == "tech"
        assert "open_ports" in summary.get("extra", {})


# ===================================================================
# 6. Edge cases
# ===================================================================

class TestEdgeCases:
    """Boundary and unusual-input tests."""

    @pytest.mark.asyncio
    async def test_single_port_scan(self):
        """Scanning exactly one port works without error."""
        report = await scan(SCANME, ports=[22], timeout=10.0)
        assert report.ports_scanned == 1
        assert isinstance(report.results, list)

    @pytest.mark.asyncio
    async def test_empty_port_list(self):
        """Passing an explicit empty list should yield zero ports scanned."""
        report = await scan(SCANME, ports=[], timeout=5.0)
        assert report.ports_scanned == 0
        assert report.open_ports == 0
        assert report.results == []

    @pytest.mark.asyncio
    async def test_scan_is_idempotent(self):
        """Two successive scans of the same target/ports should produce
        the same open_ports count (deterministic)."""
        r1 = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)
        r2 = await scan(SCANME, ports=SCANME_PORTS, timeout=10.0)
        assert r1.open_ports == r2.open_ports
        assert {p.port for p in r1.results} == {p.port for p in r2.results}
