"""
Tests for M.I.R.V. Coverage Tracking module.

Run:
    python -m pytest backend/tests/test_coverage.py -v --tb=short -q
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys

import pytest

# Path setup (mirrors the project's existing conftest style)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend import coverage as cov
from backend.coverage import (
    CoverageEntry,
    clear_coverage,
    coverage_context_for_prompt,
    coverage_summary,
    export_coverage,
    list_coverage,
    list_sessions,
    mark_coverage,
    next_steps,
    report_to_mirv_findings,
    reset_store_for_tests,
    save_session,
    untested_endpoints,
)


@pytest.fixture(autouse=True)
def _clean_store():
    """Each test starts with a pristine matrix."""
    reset_store_for_tests()
    yield
    reset_store_for_tests()


# ──────────────────────────────────────────────────────────────────
#  Basic mark / validation
# ──────────────────────────────────────────────────────────────────


def test_mark_valid_entry_returns_ok_and_entry():
    r = mark_coverage(
        endpoint="GET /api/v1/orders/{id}",
        method="GET",
        path="/api/v1/orders/1",
        param="id",
        vuln_class="idor",
        status="failed",
        notes="password reset leaks other users",
    )
    assert r["ok"] is True
    assert r.get("created") is True
    e = r["entry"]
    assert e["endpoint"].startswith("GET ")
    assert e["method"] == "GET"
    assert e["vuln_class"] == "idor"
    assert e["status"] == "failed"
    assert e["param"] == "id"
    assert e["count"] == 1
    assert e["notes"]
    assert e["session_id"] == "default"
    assert e["first_seen"]
    assert e["last_seen"]


def test_mark_invalid_vuln_class_returns_error():
    r = mark_coverage("GET /x", "GET", "/x", None, "xxe-not-listed", "failed")
    assert r["ok"] is False
    assert "Invalid vuln_class" in r["error"]


def test_mark_invalid_status_returns_error():
    r = mark_coverage("GET /x", "GET", "/x", None, "idor", "weird-status")
    assert r["ok"] is False
    assert "Invalid status" in r["error"]


def test_mark_secrets_never_stored_in_notes_or_log():
    """Sanity check: secrets passed as endpoint/id are not echoed elsewhere."""
    r = mark_coverage("GET /admin", "GET", "/admin?token=SECRET123", None, "auth", "failed", notes="password=Hunter2")
    assert r["ok"] is True
    assert "SECRET123" not in r["entry"]["path"]  # query stripped
    assert "Hunter2" in r["entry"]["notes"]       # notes are explicit observation logs


# ──────────────────────────────────────────────────────────────────
#  Normalisation + dedup
# ──────────────────────────────────────────────────────────────────


def test_path_normalization_strips_query_string():
    r = mark_coverage("GET /x?foo=bar", "GET", "/x?foo=bar", None, "sqli", "tried")
    assert r["entry"]["path"] == "/x"


def test_path_normalization_lowercases_path():
    r = mark_coverage("GET /Api/V1/Users", "GET", "/Api/V1/Users", None, "auth", "skipped")
    assert r["entry"]["endpoint"] == "GET /api/v1/users"
    assert r["entry"]["path"] == "/api/v1/users"


def test_path_normalization_trailing_slash_collapsed():
    r = mark_coverage("GET /api/orders/", "GET", "/api/orders/", None, "idor", "tried")
    assert r["entry"]["path"] == "/api/orders"


def test_mark_dedup_increments_count_and_updates_status():
    first = mark_coverage("GET /a", "GET", "/a", "q", "sqli", "tried")
    assert first["entry"]["count"] == 1
    second = mark_coverage("get /a", "GET", "/a?q=1", "Q", "sqli", "failed", notes="boom!")
    assert second["created"] is False
    assert second["entry"]["count"] == 2
    assert second["entry"]["status"] == "failed"
    assert second["entry"]["notes"] == "boom!"
    # Method normalisation means same-key dedup should treat GET == get
    assert list_coverage(limit=100).__len__() == 1


def test_mark_different_param_creates_separate_row():
    mark_coverage("GET /a", "GET", "/a", "q", "sqli", "tried")
    mark_coverage("GET /a", "GET", "/a", "id", "sqli", "tried")
    assert len(list_coverage()) == 2


# ──────────────────────────────────────────────────────────────────
#  Summary
# ──────────────────────────────────────────────────────────────────


def test_summary_counts_by_status_and_vuln_class():
    mark_coverage("GET /a", "GET", "/a", "q", "sqli", "passed")
    mark_coverage("GET /a", "GET", "/a", "q", "idor", "failed")
    mark_coverage("POST /b", "POST", "/b", None, "xss", "waf-blocked")
    s = coverage_summary()
    assert s["total"] == 3
    assert s["by_status"]["passed"] == 1
    assert s["by_status"]["failed"] == 1
    assert s["by_status"]["waf-blocked"] == 1
    assert s["by_vuln_class"]["sqli"] == 1
    assert s["by_vuln_class"]["idor"] == 1
    assert s["by_vuln_class"]["xss"] == 1
    assert s["unique_endpoints"] == 2
    assert s["pass_ratio"] == 0.5


def test_summary_filters_by_session_id():
    # Note: dedup is global by (endpoint, param, vuln_class) — session_id is
    # metadata on the entry, so two writes with the SAME combo collapse into
    # one. To verify session filtering we therefore use DIFFERENT endpoints.
    mark_coverage("GET /a", "GET", "/a", "q", "sqli", "passed", session_id="s1")
    mark_coverage("POST /b", "POST", "/b", "q", "sqli", "failed", session_id="s2")
    assert coverage_summary(session_id="s1")["total"] == 1
    assert coverage_summary(session_id="s2")["by_status"]["failed"] == 1
    assert coverage_summary(session_id="s1")["by_status"]["failed"] == 0


# ──────────────────────────────────────────────────────────────────
#  Untested sweep
# ──────────────────────────────────────────────────────────────────


def test_untested_with_provided_candidates():
    mark_coverage("GET /api/orders", "GET", "/api/orders", "id", "idor", "passed")
    cands = [
        {"endpoint": "GET /api/orders", "param": "id"},          # IDOR already marked → gap removed
        {"endpoint": "GET /api/orders", "param": "filter"},      # BRAND NEW param
        {"endpoint": "POST /api/users", "param": "name"},
    ]
    out = untested_endpoints(candidates=cands)
    # cand1 IDOR should be filtered; cand2 yields all 19 vuln classes; cand3 yields all 19 classes
    ep_counts = {c["endpoint"]: c["vuln_class"] for c in out}
    assert any(c["endpoint"] == "GET /api/orders" and c["param"] == "filter" for c in out)
    assert any(c["endpoint"] == "POST /api/users" for c in out)
    # IDOR on orders already covered → must not be suggested again
    assert not any(c["endpoint"] == "GET /api/orders" and c["param"] == "id" and c["vuln_class"] == "idor" for c in out)


def test_untested_auto_sweep_uses_existing_endpoints():
    mark_coverage("GET /api/orders", "GET", "/api/orders", None, "idor", "passed")
    out = untested_endpoints()
    eps = {c["endpoint"] for c in out}
    assert eps == {"GET /api/orders"}
    # Auto sweep includes every allowed class EXCEPT idor (already passed)
    classes = {c["vuln_class"] for c in out}
    assert "idor" not in classes
    assert "ssrf" in classes and "sqli" in classes
    assert len(classes) == len(cov.ALLOWED_VULN_CLASSES) - 1


def test_untested_empty_when_everything_marked():
    mark_coverage("GET /a", "GET", "/a", None, "info", "tried")
    # Manually fill all classes to make sweep clean
    for vc in cov.ALLOWED_VULN_CLASSES:
        if vc == "info":
            continue
        mark_coverage("GET /a", "GET", "/a", None, vc, "tried")
    out = untested_endpoints()
    assert out == []


# ──────────────────────────────────────────────────────────────────
#  next_steps ranking
# ──────────────────────────────────────────────────────────────────


def test_next_steps_failed_ranked_above_untested():
    mark_coverage("GET /failed", "GET", "/failed", None, "rce", "failed")
    mark_coverage("GET /passed", "GET", "/passed", None, "idor", "passed")
    steps = next_steps(limit=20)
    # First item must be the previously failed RCE row
    assert steps[0]["endpoint"] == "GET /failed"
    assert steps[0]["reason"] == "previously_failed_retry_with_variant"
    assert steps[0]["vuln_class"] == "rce"


def test_next_steps_waf_blocked_ranked_last():
    mark_coverage("GET /waf", "GET", "/waf", None, "sqli", "waf-blocked")
    steps = next_steps(limit=20)
    waf = [s for s in steps if s["status"] == "waf-blocked"]
    assert waf, "waf-blocked rows should appear in suggestions"
    # Find the position of the first waf row vs the first untested
    first_waf_idx = next(i for i, s in enumerate(steps) if s["status"] == "waf-blocked")
    first_untested_idx = next(i for i, s in enumerate(steps) if s.get("reason") == "auto_sweep")
    assert first_untested_idx < first_waf_idx, "untested must precede waf-blocked"


def test_next_steps_session_isolation():
    mark_coverage("GET /a", "GET", "/a", None, "rce", "failed", session_id="s1")
    steps_other = next_steps(session_id="s2", limit=20)
    assert not any(s["endpoint"] == "GET /a" for s in steps_other)


def test_next_steps_respects_limit():
    mark_coverage("GET /a", "GET", "/a", None, "rce", "failed")
    steps = next_steps(limit=3)
    assert len(steps) <= 3


# ──────────────────────────────────────────────────────────────────
#  Clear / sessions / export
# ──────────────────────────────────────────────────────────────────


def test_clear_all_wipes_everything():
    mark_coverage("GET /a", "GET", "/a", None, "rce", "failed", session_id="s1")
    mark_coverage("GET /b", "GET", "/b", None, "xss", "tried", session_id="s2")
    r = clear_coverage()
    assert r["ok"] is True
    assert r["removed"] == 2
    assert coverage_summary()["total"] == 0


def test_clear_session_keeps_others():
    mark_coverage("GET /a", "GET", "/a", None, "rce", "failed", session_id="s1")
    mark_coverage("GET /b", "GET", "/b", None, "xss", "tried", session_id="s2")
    r = clear_coverage(session_id="s1")
    assert r["removed"] == 1
    assert len(list_coverage()) == 1
    assert list_coverage()[0]["session_id"] == "s2"


def test_save_session_and_list_sessions():
    mark_coverage("GET /a", "GET", "/a", None, "rce", "failed", session_id="mission-7")
    r = save_session("mission-7", name="Acme Corp / Q3")
    assert r["ok"] is True
    assert r["session"]["name"] == "Acme Corp / Q3"
    assert r["session"]["entry_count"] == 1
    sessions = list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "mission-7"


def test_save_session_requires_id():
    r = save_session("", name="whoops")
    assert r["ok"] is False


def test_export_markdown_table_headers():
    mark_coverage("GET /api/x", "GET", "/api/x", "q", "sqli", "failed", notes="notice | pipe")
    out = export_coverage(format="md")
    assert "| Endpoint |" in out
    assert "Coverage Matrix" in out
    assert "\\|" in out  # pipe in notes escaped


def test_export_csv_parseable():
    mark_coverage("GET /api/x", "GET", "/api/x", "q", "sqli", "failed")
    mark_coverage("POST /api/y", "POST", "/api/y", None, "rce", "passed")
    csv_text = export_coverage(format="csv")
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["vuln_class"] in ("sqli", "rce")
    assert {"endpoint", "method", "status", "count", "notes"} <= set(rows[0].keys())


def test_export_json_round_trip():
    mark_coverage("GET /x", "GET", "/x", None, "info", "tried")
    payload = json.loads(export_coverage(format="json"))
    assert payload["ok"] is True
    assert payload["count"] == 1
    assert payload["entries"][0]["vuln_class"] == "info"


def test_export_unsupported_format_returns_error_json():
    out = export_coverage(format="xml")
    payload = json.loads(out)
    assert payload["ok"] is False
    assert "Unsupported format" in payload["error"]


# ──────────────────────────────────────────────────────────────────
#  report_to_mirv_findings severity mapping
# ──────────────────────────────────────────────────────────────────


def test_report_to_mirv_findings_failed_high():
    e = mark_coverage("GET /x", "GET", "/x", "q", "rce", "failed")["entry"]
    findings = report_to_mirv_findings(CoverageEntry(**e))
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["vuln_class"] == "rce"
    assert findings[0]["tool"] == "coverage-matrix"


def test_report_to_mirv_findings_waf_blocked_medium():
    e = mark_coverage("GET /x", "GET", "/x", "q", "sqli", "waf-blocked")["entry"]
    findings = report_to_mirv_findings(CoverageEntry(**e))
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_report_to_mirv_findings_passed_skipped_no_finding():
    for status in ("passed", "skipped", "tried"):
        e = mark_coverage("GET /x", "GET", "/x", "q", "idor", status)["entry"]
        assert report_to_mirv_findings(CoverageEntry(**e)) == [], f"unexpected findings for {status}"


def test_report_to_mirv_findings_bad_input():
    assert report_to_mirv_findings("not-a-CoverageEntry") == []  # type: ignore[arg-type]
    assert report_to_mirv_findings(None) == []                   # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────
#  coverage_context_for_prompt (feeds /api/suggest + Op Admiral)
# ──────────────────────────────────────────────────────────────────


def test_context_for_prompt_empty_when_no_entries():
    assert coverage_context_for_prompt() == ""


def test_context_for_prompt_contains_next_steps_and_summary():
    mark_coverage("GET /api/data", "GET", "/api/data", None, "sqli", "failed")
    block = coverage_context_for_prompt()
    assert "Coverage Matrix Context" in block
    assert "Pass ratio" in block
    assert "GET /api/data" in block


def test_context_for_prompt_is_ascii_safe():
    mark_coverage("GET /api/data", "GET", "/api/data", None, "sqli", "failed", notes="payload with Unicode: —")
    block = coverage_context_for_prompt()
    # `_clean_text` in main.py strips non-ASCII; the block must not contain it
    assert block.encode("ascii", errors="strict")