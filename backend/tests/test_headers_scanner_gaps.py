"""
Coverage-gap tests for backend/headers_scanner.py.

Covers:
  - ScanReport.score: zero total (empty severity table)
  - report_to_mirv_findings: weak-status headers
"""

from unittest.mock import patch

from backend.headers_scanner import (
    _RULES,
    HeaderFinding,
    ScanReport,
    report_to_mirv_findings,
)


def _report_with_statuses(statuses):
    findings = []
    for i, st in enumerate(statuses):
        rule = _RULES[i % len(_RULES)]
        findings.append(HeaderFinding(
            rule=rule,
            status=st,
            actual_value="val" if st != "missing" else None,
            note="test",
        ))
    return ScanReport(
        url="https://test", final_url="https://test",
        status_code=200, findings=findings,
    )


class TestScoreZeroGaps:
    def test_zero_total_returns_zero(self):
        with patch("backend.headers_scanner._SEVERITY_POINTS", {}), \
             patch("backend.headers_scanner._RULES", []):
            report = _report_with_statuses([])
            assert report.score == 0


class TestReportToMirvWeakGaps:
    def test_weak_findings_marked_weak(self):
        report = _report_with_statuses(["weak"] * len(_RULES))
        mirv = report_to_mirv_findings(report)
        per_header = mirv[:-1]
        assert per_header
        for item in per_header:
            assert "WEAK" in item["title"]
            assert item["type"] == "vuln"
            assert item["severity"] in ("high", "medium", "low")
