"""
Unit tests for backend/headers_scanner.py

Covers:
  - ScanReport.grade property (A–F boundary mapping)
  - ScanReport.score property (weighted header scoring)
  - evaluate_header() rule evaluation logic
  - scan() async function against real and unreachable URLs
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, PropertyMock

import httpx

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from headers_scanner import (
    HeaderFinding,
    HeaderRule,
    ScanReport,
    evaluate_header,
    scan,
    report_to_mirv_findings,
    _RULES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(score: int) -> ScanReport:
    """Build a minimal ScanReport whose .score is patched to *score*."""
    return ScanReport(
        url="https://test.local",
        final_url="https://test.local",
        status_code=200,
        findings=[],
    )


def _patch_score(report: ScanReport, score: int):
    """Context manager that patches the .score property on *report*."""
    return patch.object(
        ScanReport, "score", new_callable=PropertyMock, return_value=score
    )


# ===================================================================
# 1. severity_grade equivalents — ScanReport.grade boundary tests
# ===================================================================

class TestGradeProperty:
    """The .grade property maps score → letter grade.

    Grade table (from source):
        A  → score >= 90
        B  → score >= 80
        C  → score >= 70
        D  → score >= 60
        F  → score <  60
    """

    @pytest.mark.parametrize(
        "score, expected",
        [
            (100, "A"),
            (90, "A"),       # lower boundary of A
            (89, "B"),       # just below A
            (80, "B"),       # lower boundary of B
            (79, "C"),       # just below B
            (70, "C"),       # lower boundary of C
            (69, "D"),       # just below C
            (60, "D"),       # lower boundary of D
            (59, "F"),       # just below D
            (0, "F"),        # absolute minimum
            (50, "F"),       # mid-range F
            (1, "F"),        # near-zero
        ],
        ids=[
            "perfect_100_A",
            "boundary_90_A",
            "just_below_A_89_B",
            "boundary_80_B",
            "just_below_B_79_C",
            "boundary_70_C",
            "just_below_C_69_D",
            "boundary_60_D",
            "just_below_D_59_F",
            "zero_F",
            "mid50_F",
            "near_zero_F",
        ],
    )
    def test_grade_boundaries(self, score: int, expected: str):
        report = _make_report(score)
        with _patch_score(report, score):
            assert report.grade == expected

    def test_grade_returns_only_valid_letters(self):
        """Every score 0-100 must map to exactly one of A/B/C/D/F."""
        report = _make_report(0)
        valid_grades = {"A", "B", "C", "D", "F"}
        for s in range(0, 101):
            with _patch_score(report, s):
                assert report.grade in valid_grades, (
                    f"score={s} produced unexpected grade {report.grade!r}"
                )

    def test_grade_no_e_grade(self):
        """Confirm there is no 'E' grade anywhere in the range."""
        report = _make_report(0)
        for s in range(0, 101):
            with _patch_score(report, s):
                assert report.grade != "E"


# ===================================================================
# 2. ScanReport.score property — weighted scoring logic
# ===================================================================

class TestScoreProperty:
    """Verify the score calculation with synthetic findings."""

    def _finding(self, rule_idx: int, status: str) -> HeaderFinding:
        """Create a HeaderFinding for _RULES[rule_idx] with a given status."""
        return HeaderFinding(
            rule=_RULES[rule_idx],
            status=status,  # type: ignore[arg-type]
            actual_value="test-value" if status != "missing" else None,
            note="test",
        )

    def test_all_ok_gives_perfect_score(self):
        findings = [self._finding(i, "ok") for i in range(len(_RULES))]
        report = ScanReport(
            url="https://x", final_url="https://x", status_code=200,
            findings=findings,
        )
        assert report.score == 100

    def test_all_missing_gives_zero(self):
        findings = [self._finding(i, "missing") for i in range(len(_RULES))]
        report = ScanReport(
            url="https://x", final_url="https://x", status_code=200,
            findings=findings,
        )
        assert report.score == 0

    def test_weak_gives_half_points(self):
        """A 'weak' finding earns half the full severity points."""
        findings = [self._finding(i, "ok") for i in range(len(_RULES))]
        # Make the first high-severity rule (30 pts) weak → earns 15
        findings[0] = self._finding(0, "weak")
        report = ScanReport(
            url="https://x", final_url="https://x", status_code=200,
            findings=findings,
        )
        # total = 100, earned = 85 (ok) + 15 (weak) = 85
        assert report.score == 85

    def test_score_is_integer_in_range(self):
        findings = [self._finding(i, "ok") for i in range(len(_RULES))]
        report = ScanReport(
            url="https://x", final_url="https://x", status_code=200,
            findings=findings,
        )
        score = report.score
        assert isinstance(score, int)
        assert 0 <= score <= 100


# ===================================================================
# 3. evaluate_header() — unit tests for rule evaluation
# ===================================================================

class TestEvaluateHeader:
    """Direct tests for the evaluate_header function."""

    def _rule(self, idx: int) -> HeaderRule:
        return _RULES[idx]

    def test_header_present_without_must_match(self):
        """Rule with must_match=None → ok if header exists."""
        # X-Frame-Options has must_match=None (idx 3)
        rule = self._rule(3)
        finding = evaluate_header(rule, {"X-Frame-Options": "DENY"})
        assert finding.status == "ok"
        assert finding.actual_value == "DENY"

    def test_header_missing(self):
        rule = self._rule(0)
        finding = evaluate_header(rule, {})
        assert finding.status == "missing"
        assert finding.actual_value is None

    def test_header_present_matching_must_match(self):
        """HSTS with valid max-age → ok."""
        rule = self._rule(0)  # Strict-Transport-Security
        finding = evaluate_header(rule, {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        })
        assert finding.status == "ok"

    def test_header_present_weak_must_match(self):
        """HSTS with max-age=0 → weak."""
        rule = self._rule(0)
        finding = evaluate_header(rule, {
            "Strict-Transport-Security": "max-age=0"
        })
        assert finding.status == "weak"
        assert "does not match" in finding.note

    def test_case_insensitive_header_name(self):
        """Header lookup should be case-insensitive."""
        rule = self._rule(2)  # X-Content-Type-Options
        finding = evaluate_header(rule, {"x-content-type-options": "nosniff"})
        assert finding.status == "ok"

    def test_x_content_type_nosniff_ok(self):
        rule = self._rule(2)
        finding = evaluate_header(rule, {"X-Content-Type-Options": "nosniff"})
        assert finding.status == "ok"
        assert finding.note == "Present and matches `nosniff`"

    def test_x_content_type_wrong_value_weak(self):
        rule = self._rule(2)
        finding = evaluate_header(rule, {"X-Content-Type-Options": "text/html"})
        assert finding.status == "weak"


# ===================================================================
# 4. scan() async — real URL
# ===================================================================

class TestScanRealUrl:
    """Integration tests that actually hit a remote URL."""

    @pytest.mark.asyncio
    async def test_scan_example_com(self):
        """Scan https://example.com and verify response shape."""
        report = await scan("https://example.com", timeout=15.0)

        # Type checks
        assert isinstance(report, ScanReport)
        assert isinstance(report.url, str)
        assert isinstance(report.status_code, int)
        assert isinstance(report.score, int)
        assert isinstance(report.grade, str)
        assert isinstance(report.findings, list)

        # Value checks
        assert report.url == "https://example.com"
        assert report.status_code == 200
        assert 0 <= report.score <= 100
        assert report.grade in ("A", "B", "C", "D", "F")

        # Findings list should have one entry per rule
        assert len(report.findings) == len(_RULES)
        for f in report.findings:
            assert isinstance(f, HeaderFinding)
            assert f.status in ("ok", "weak", "missing")
            assert isinstance(f.rule, HeaderRule)

    @pytest.mark.asyncio
    async def test_scan_example_com_mirv_format(self):
        """scan → report_to_mirv_findings produces well-formed dicts."""
        report = await scan("https://example.com", timeout=15.0)
        findings = report_to_mirv_findings(report)

        assert isinstance(findings, list)
        assert len(findings) > 0

        for item in findings:
            assert "tool" in item
            assert "severity" in item
            assert "title" in item
            assert "detail" in item
            assert "target" in item
            assert "type" in item
            assert item["tool"] == "headers-scan"

        # Last item is the summary
        summary = findings[-1]
        assert "Overall Grade" in summary["title"]


# ===================================================================
# 5. scan() async — invalid / unreachable URL
# ===================================================================

class TestScanInvalidUrl:
    """Verify graceful error handling for unreachable targets."""

    @pytest.mark.asyncio
    async def test_scan_unreachable_domain(self):
        """A non-existent domain should raise httpx.RequestError."""
        with pytest.raises(httpx.RequestError):
            await scan("https://nonexistent.invalid", timeout=5.0)

    @pytest.mark.asyncio
    async def test_scan_bad_scheme(self):
        """An unsupported scheme should raise an error (not crash)."""
        with pytest.raises(Exception):
            await scan("ftp://example.com", timeout=5.0)


# ===================================================================
# 6. report_to_mirv_findings — formatting helpers
# ===================================================================

class TestReportToMIRV:
    """Ensure MIRV-finding conversion works end-to-end."""

    def _report_with_statuses(self, statuses: list[str]) -> ScanReport:
        findings = []
        for i, st in enumerate(statuses):
            rule = _RULES[i % len(_RULES)]
            findings.append(HeaderFinding(
                rule=rule,
                status=st,  # type: ignore[arg-type]
                actual_value="val" if st != "missing" else None,
                note="test",
            ))
        return ScanReport(
            url="https://test", final_url="https://test",
            status_code=200, findings=findings,
        )

    def test_all_ok_findings_are_info_type(self):
        statuses = ["ok"] * len(_RULES)
        report = self._report_with_statuses(statuses)
        mirv = report_to_mirv_findings(report)
        # Per-header findings should be type "tech"
        for item in mirv[:-1]:
            assert item["type"] == "tech"
            assert item["severity"] == "info"

    def test_missing_finding_is_vuln_type(self):
        statuses = ["missing"] + ["ok"] * (len(_RULES) - 1)
        report = self._report_with_statuses(statuses)
        mirv = report_to_mirv_findings(report)
        vulns = [f for f in mirv if f["type"] == "vuln"]
        assert len(vulns) >= 1
        assert "MISSING" in vulns[0]["title"]

    def test_summary_present(self):
        statuses = ["ok"] * len(_RULES)
        report = self._report_with_statuses(statuses)
        mirv = report_to_mirv_findings(report)
        summary = mirv[-1]
        assert "Overall Grade" in summary["title"]
        assert summary["type"] == "tech"
