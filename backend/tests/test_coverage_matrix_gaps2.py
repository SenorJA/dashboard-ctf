"""
Coverage-gap tests for backend/coverage_matrix.py.

Covers edge branches in mark_coverage, list_coverage, untested_endpoints,
next_steps, clear_coverage, export_coverage and coverage_context_for_prompt.
"""

import pytest

import backend.coverage_matrix as cm
from backend.coverage_matrix import (
    ALLOWED_VULN_CLASSES,
    mark_coverage,
    list_coverage,
    untested_endpoints,
    next_steps,
    clear_coverage,
    save_session,
    export_coverage,
    coverage_context_for_prompt,
    reset_store_for_tests,
    _build_endpoint,
)


@pytest.fixture(autouse=True)
def clean_store():
    reset_store_for_tests()
    yield
    reset_store_for_tests()


class TestBuildEndpoint:
    def test_composes_canonical(self):
        assert _build_endpoint("get", "/API/X/") == "GET /api/x"


class TestMarkCoverage:
    def test_endpoint_without_method_prefix(self):
        res = mark_coverage("some/path", "POST", "/some/path", None, "xss", "tried")
        assert res["ok"] is True
        assert res["entry"]["endpoint"] == "POST some/path"
        assert res["entry"]["method"] == "POST"

    def test_empty_endpoint_falls_back_to_method_path(self):
        res = mark_coverage("", "GET", "/api/y", None, "sqli", "tried")
        assert res["ok"] is True
        assert res["entry"]["endpoint"] == "GET /api/y"

    def test_update_existing_session_id(self):
        mark_coverage("/api/x", "GET", "/api/x", None, "sqli", "failed", session_id="default")
        res = mark_coverage("/api/x", "GET", "/api/x", None, "sqli", "failed", session_id="s1")
        assert res["created"] is False
        assert res["entry"]["session_id"] == "s1"
        assert res["entry"]["count"] == 2


class TestListCoverage:
    def _seed(self):
        mark_coverage("/api/a", "GET", "/api/a", "p", "xss", "passed", session_id="s1")
        mark_coverage("/api/b", "GET", "/api/b", None, "sqli", "failed", session_id="s2")

    def test_limit_floor(self):
        self._seed()
        assert len(list_coverage(limit=0)) <= 200

    def test_limit_ceiling(self):
        self._seed()
        assert len(list_coverage(limit=99999)) <= 5000

    def test_status_filter_matches(self):
        self._seed()
        rows = list_coverage(status="passed")
        assert len(rows) == 1
        assert rows[0]["status"] == "passed"

    def test_vuln_class_filter_matches(self):
        self._seed()
        rows = list_coverage(vuln_class="sqli")
        assert len(rows) == 1
        assert rows[0]["vuln_class"] == "sqli"


class TestUntestedEndpoints:
    def test_invalid_candidate_skipped(self):
        res = untested_endpoints(candidates=[{"endpoint": "", "method": "GET"}])
        assert res == []

    def test_candidate_without_method_prefix(self):
        res = untested_endpoints(candidates=[
            {"endpoint": "/api/z", "method": "GET", "path": "/api/z", "param": None},
        ])
        assert any(r["endpoint"] == "GET /api/z" for r in res)


class TestNextSteps:
    def test_limit_floor(self):
        mark_coverage("/api/x", "GET", "/api/x", None, "sqli", "failed")
        # limit=0 falls back to the default (10) -> at least the failed row.
        assert len(next_steps(limit=0)) >= 1

    def test_limit_ceiling(self):
        mark_coverage("/api/x", "GET", "/api/x", None, "sqli", "failed")
        assert len(next_steps(limit=99999)) >= 1

    def test_dedupe_skips_duplicate_key(self):
        # A failed row (param=None) and an untested auto-sweep row for the
        # SAME (endpoint, param, vuln_class) must collapse into one.
        mark_coverage("GET /api/x", "GET", "/api/x", None, "sqli", "failed")
        steps = next_steps(limit=99999)
        keys = [(s["endpoint"], s.get("param"), s["vuln_class"]) for s in steps]
        assert len(keys) == len(set(keys))


class TestClearCoverage:
    def test_session_metadata_removed(self):
        save_session("s1")
        mark_coverage("/api/x", "GET", "/api/x", None, "sqli", "tried", session_id="s1")
        res = clear_coverage("s1")
        assert res["removed"] == 1
        assert cm.list_sessions() == []


class TestExportCoverage:
    def test_markdown_empty(self):
        assert "_No entries._" in export_coverage(format="md")

    def test_markdown_truncates_long_notes(self):
        mark_coverage("/api/x", "GET", "/api/x", None, "sqli", "tried",
                      notes="n" * 100)
        out = export_coverage(format="md")
        assert "..." in out


class TestCoverageContext:
    def test_empty_steps_returns_empty(self):
        # Mark every vuln class for the endpoint so auto-sweep finds no gaps.
        for vc in ALLOWED_VULN_CLASSES:
            mark_coverage("GET /api/full", "GET", "/api/full", None, vc, "passed")
        assert coverage_context_for_prompt() == ""
