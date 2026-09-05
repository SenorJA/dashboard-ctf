"""Tests for backend/pc_analyzer.py -- health diagnostics + grade + suggestions."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend import pc_analyzer as pa
from backend.pc_analyzer import Check


def _chk(status: str, **kw) -> Check:
    return Check(
        id=kw.pop("id", status),
        name=kw.pop("name", status),
        category=kw.pop("category", "test"),
        status=status,
        message=kw.pop("message", status),
        details=kw.pop("details", ""),
        suggestion=kw.pop("suggestion", None),
    )


# ── grading / scoring ────────────────────────────────────────────────
def test_grade_all_ok_is_a():
    checks = [_chk("ok") for _ in range(5)]
    assert pa._grade(checks) == "A"


def test_grade_one_warn_is_b():
    assert pa._grade([_chk("ok"), _chk("ok"), _chk("warn")]) == "B"


def test_grade_two_warn_is_b():
    assert pa._grade([_chk("warn"), _chk("warn")]) == "B"


def test_grade_three_warn_is_c():
    assert pa._grade([_chk("warn"), _chk("warn"), _chk("warn")]) == "C"


def test_grade_one_critical_is_c():
    assert pa._grade([_chk("ok"), _chk("critical")]) == "C"


def test_grade_two_critical_is_d():
    assert pa._grade([_chk("critical"), _chk("critical")]) == "D"


def test_grade_three_critical_is_f():
    assert pa._grade([_chk("critical"), _chk("critical"), _chk("critical")]) == "F"


def test_grade_skips_ignored():
    assert pa._grade([_chk("ok"), _chk("skip"), _chk("skip")]) == "A"


def test_score_all_ok():
    assert pa._score([_chk("ok"), _chk("ok")]) == 100


def test_score_one_warn():
    assert pa._score([_chk("ok"), _chk("warn")]) == 94


def test_score_one_critical():
    assert pa._score([_chk("ok"), _chk("critical")]) == 80


def test_score_capped_at_zero():
    assert pa._score([_chk("critical")] * 20) == 0


def test_summary_variants():
    assert "critical" in pa._summary([_chk("critical"), _chk("warn")])
    assert "warning" in pa._summary([_chk("warn")])
    assert "healthy" in pa._summary([_chk("ok")])
    assert "skipped" in pa._summary([_chk("skip")])


# ── checks ───────────────────────────────────────────────────────────
def test_check_memory_warn():
    with patch.object(pa.sysmon, "memory", return_value={
        "percent": 80.0,
        "used": {"gb": 12.0}, "total": {"gb": 16.0},
    }):
        c = pa._check_memory()
    assert c.status == "warn"
    assert c.suggestion


def test_check_memory_critical():
    with patch.object(pa.sysmon, "memory", return_value={
        "percent": 95.0, "used": {"gb": 15.0}, "total": {"gb": 16.0},
    }):
        c = pa._check_memory()
    assert c.status == "critical"


def test_check_cpu_ok():
    with patch.object(pa.sysmon, "cpu", return_value={"percent": 10.0, "cores": 8}):
        c = pa._check_cpu()
    assert c.status == "ok"


def test_check_cpu_critical():
    with patch.object(pa.sysmon, "cpu", return_value={"percent": 95.0, "cores": 8}):
        c = pa._check_cpu()
    assert c.status == "critical"


def test_check_system_disk_skip_when_no_parts():
    with patch.object(pa.sysmon, "disk_partitions", return_value=[]):
        c = pa._check_system_disk()
    assert c.status == "skip"


def test_check_system_disk_warn():
    vol = {"mount": "C:\\", "total": {"bytes": 10**9, "gb": 1.0},
           "used": {}, "free": {"gb": 0.1}, "percent": 90.0}
    with patch.object(pa.sysmon, "disk_partitions", return_value=[vol]):
        with patch.object(pa, "_os_root", return_value="C:\\"):
            c = pa._check_system_disk()
    assert c.status == "warn"


def test_check_other_disks_tight():
    vol = {"mount": "D:\\", "total": {"bytes": 10**9, "gb": 1.0},
           "free": {"gb": 0.05}, "percent": 95.0}
    with patch.object(pa.sysmon, "disk_partitions", return_value=[vol]):
        with patch.object(pa, "_os_root", return_value="C:\\"):
            c = pa._check_other_disks()
    assert c.status == "critical"


def test_check_network_ok():
    with patch.object(pa.socket, "create_connection") as cc:
        cc.return_value.__enter__.return_value = None
        assert pa._check_network().status == "ok"


def test_check_network_warn():
    with patch.object(pa.socket, "create_connection", side_effect=OSError("no route")):
        c = pa._check_network()
    assert c.status == "warn"


def test_check_junk_warn():
    with patch.object(pa.sysmon, "scan_candidates", return_value=[
        type("C", (), {"category": "temp", "size_bytes": 3 * 1024**3, "label": "User Temp"})(),
    ]):
        c = pa._check_junk()
    assert c.status == "warn"


def test_check_uptime_ok_and_warn():
    with patch.object(pa.sysmon, "uptime", return_value={"seconds": 86400}):
        assert pa._check_uptime().status == "ok"
    with patch.object(pa.sysmon, "uptime", return_value={"seconds": 86400 * 90}):
        assert pa._check_uptime().status == "warn"


# ── analyze() shape ──────────────────────────────────────────────────
def test_analyze_shape():
    with patch.object(pa.sysmon, "platform_info", return_value={"os": "TestOS", "release": "1"}):
        r = pa.analyze()
    assert set(r) == {"grade", "score", "summary", "host", "generated_at", "checks", "suggestions"}
    assert r["host"]["os"] == "TestOS"
    assert r["checks"] and r["checks"][0]["id"] == "host"
    for c in r["checks"]:
        assert c["status"] in ("ok", "warn", "critical", "skip")
    assert isinstance(r["score"], int) and 0 <= r["score"] <= 100


def test_suggestions_only_for_actionable():
    checks = [
        _chk("warn", suggestion="do this"),
        _chk("warn", suggestion=None),
    ]
    with patch.object(pa, "run_checks", return_value=checks):
        r = pa.analyze()
    assert len(r["suggestions"]) == 1
    assert r["suggestions"][0]["action"] == "do this"


def test_run_checks_host_first():
    checks = pa.run_checks()
    assert checks and checks[0].id == "host"


# ── endpoint ─────────────────────────────────────────────────────────
def test_endpoint_pc_analyzer():
    from backend.main import app
    with TestClient(app) as client:
        r = client.get("/api/pc-analyzer")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "grade" in data and "score" in data and "checks" in data