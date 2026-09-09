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
    assert set(r) == {"grade", "score", "summary", "host", "generated_at", "checks", "suggestions", "fixes"}
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


# ── phase 2: event log ────────────────────────────────────────────────
def test_count_event_log_errors_non_windows_is_none():
    with patch.object(pa.os, "name", "posix"):
        assert pa._count_event_log_errors() is None


def test_count_event_log_errors_missing_wevtutil_is_none():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa.subprocess, "run", side_effect=OSError("missing")):
            assert pa._count_event_log_errors() is None


def test_count_event_log_errors_counts_error_lines():
    fake = type("Proc", (), {"stdout": "Level:     Error\nLevel: Error\nLevel:     Warning\nInfo: Error\n"})()
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa.subprocess, "run", return_value=fake):
            assert pa._count_event_log_errors() == 2


def test_check_eventlog_skip_off_windows():
    with patch.object(pa.os, "name", "posix"):
        c = pa._check_eventlog()
    assert c.status == "skip"
    assert c.id == "eventlog"


def test_check_eventlog_skip_when_unreadable():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa, "_count_event_log_errors", side_effect=[None, 0]):
            c = pa._check_eventlog()
    assert c.status == "skip"


def test_check_eventlog_warn_and_critical():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa, "_count_event_log_errors", side_effect=[3, 0]):
            assert pa._check_eventlog().status == "warn"
        with patch.object(pa, "_count_event_log_errors", side_effect=[11, 2]):
            assert pa._check_eventlog().status == "critical"


def test_check_eventlog_ok():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa, "_count_event_log_errors", side_effect=[0, 0]):
            assert pa._check_eventlog().status == "ok"


# ── phase 2: pending reboot / updates ────────────────────────────────
class _FakeKey:
    def __init__(self, path, values):
        self.path = path
        self._values = values or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeReg:
    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, keys):
        self._keys = dict(keys)

    def OpenKey(self, _root, path):
        if path in self._keys:
            return _FakeKey(path, self._keys[path])
        raise OSError("missing key")

    def QueryValueEx(self, key, name):
        if name in key._values:
            return key._values[name], 0
        raise OSError("missing value")


def test_pending_reboot_detail_windows_reboot_key():
    with patch.object(pa.os, "name", "nt"):
        reg = _FakeReg({pa._REG_REBOOT_REQUIRED: {}})
        assert pa._pending_reboot_detail(reg) == "Windows Update reboot required"


def test_pending_reboot_detail_windows_file_ops():
    with patch.object(pa.os, "name", "nt"):
        reg = _FakeReg({pa._REG_SESSION_MANAGER: {"PendingFileRenameOperations": ["a", "b", "c", "d"]}})
        d = pa._pending_reboot_detail(reg)
        assert d and "2" in d


def test_pending_reboot_detail_windows_clean():
    with patch.object(pa.os, "name", "nt"):
        assert pa._pending_reboot_detail(_FakeReg({})) == ""


def test_pending_reboot_detail_windows_no_registry():
    with patch.object(pa.os, "name", "nt"):
        assert pa._pending_reboot_detail(None) is None


def test_pending_reboot_detail_linux_marker():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa.os.path, "exists", return_value=True):
            assert "reboot-required" in pa._pending_reboot_detail(None)
        with patch.object(pa.os.path, "exists", return_value=False):
            assert pa._pending_reboot_detail(None) == ""


def test_windows_update_info_when_no_registry():
    with patch.object(pa.os, "name", "nt"):
        assert pa._windows_update_info(None) is None


def test_windows_update_info_pending_and_last():
    with patch.object(pa.os, "name", "nt"):
        reg = _FakeReg({
            pa._REG_REBOOT_REQUIRED: {},
            pa._REG_LAST_INSTALL: {"LastSuccessTime": "2026-09-01"},
        })
        info = pa._windows_update_info(reg)
        assert info["pending"] == ["Windows Update reboot required"]
        assert info["last_install"] == "2026-09-01"


def test_linux_pending_updates_windows_returns_none():
    with patch.object(pa.os, "name", "nt"):
        assert pa._linux_pending_updates() is None


def test_linux_pending_updates_counts():
    fake = type("Proc", (), {"stdout": "pkg/1 (upgradable)\npkg2/2 (upgradable)\n"})()
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa.subprocess, "run", return_value=fake):
            assert pa._linux_pending_updates() == 2


def test_check_updates_windows_pending_warns():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa, "_windows_update_info",
                          return_value={"pending": ["reboot"], "last_install": None}):
            assert pa._check_updates().status == "warn"


def test_check_updates_windows_clean():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa, "_windows_update_info",
                          return_value={"pending": [], "last_install": "2026-09-01"}):
            c = pa._check_updates()
    assert c.status == "ok"
    assert "2026-09-01" in c.details


def test_check_updates_windows_skip():
    with patch.object(pa.os, "name", "nt"):
        with patch.object(pa, "_windows_update_info", return_value=None):
            assert pa._check_updates().status == "skip"


def test_check_updates_linux_pending_warns():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa, "_linux_pending_updates", return_value=3):
            assert pa._check_updates().status == "warn"


def test_check_updates_linux_clean():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa, "_linux_pending_updates", return_value=0):
            assert pa._check_updates().status == "ok"


def test_check_updates_linux_skip_when_unknown():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa, "_linux_pending_updates", return_value=None):
            with patch.object(pa, "_pending_reboot_detail", return_value=None):
                assert pa._check_updates().status == "skip"


def test_check_updates_linux_reboot_only_warns():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa, "_linux_pending_updates", return_value=None):
            with patch.object(pa, "_pending_reboot_detail", return_value="reboot required"):
                c = pa._check_updates()
    assert c.status == "warn"
    assert "reboot required" in c.message or "Reboot" in c.message


def test_linux_pending_updates_apt_missing_returns_none():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa.subprocess, "run", side_effect=OSError("apt absent")):
            assert pa._linux_pending_updates() is None


def test_pending_reboot_detail_linux_oserror_returns_none():
    with patch.object(pa.os, "name", "posix"):
        with patch.object(pa.os.path, "exists", side_effect=OSError("denied")):
            assert pa._pending_reboot_detail(None) is None


def test_check_reboot_variants():
    with patch.object(pa, "_pending_reboot_detail", return_value="reboot required"):
        assert pa._check_reboot().status == "warn"
    with patch.object(pa, "_pending_reboot_detail", return_value=""):
        assert pa._check_reboot().status == "ok"
    with patch.object(pa, "_pending_reboot_detail", return_value=None):
        assert pa._check_reboot().status == "skip"


def test_run_checks_include_phase2():
    ids = [c.id for c in pa.run_checks()]
    assert "eventlog" in ids and "updates" in ids and "reboot" in ids


# ── phase 2: auto-fix ─────────────────────────────────────────────────
def test_apply_fix_unknown_action():
    r = pa.apply_fix("nuke", confirm=True)
    assert r["ok"] is False and "unknown" in r["error"]


def test_apply_fix_requires_confirm():
    r = pa.apply_fix("cleanup_junk", confirm=False)
    assert r["ok"] is False and r.get("confirm") is True


def test_apply_fix_cleanup_junk_happy_path():
    cand = type("C", (), {"category": "temp", "path": "/tmp/x", "label": "Tmp", "size_bytes": 100})()
    with patch.object(pa.sysmon, "scan_candidates", return_value=[cand]):
        with patch.object(pa.sysmon, "cleanup_candidate",
                          return_value={"ok": True, "freed_bytes": 100}):
            r = pa.apply_fix("cleanup_junk", confirm=True)
    assert r["ok"] is True
    assert r["count"] == 1 and r["freed_bytes"] == 100
    assert r["freed_human"] and r["deleted"][0]["path"] == "/tmp/x"


def test_apply_fix_cleanup_junk_reports_failures():
    cand = type("C", (), {"category": "cache", "path": "/tmp/y", "label": "C", "size_bytes": 1})()
    with patch.object(pa.sysmon, "scan_candidates", return_value=[cand]):
        with patch.object(pa.sysmon, "cleanup_candidate",
                          return_value={"ok": False, "error": "locked"}):
            r = pa.apply_fix("cleanup_junk", confirm=True)
    assert r["ok"] is True
    assert r["count"] == 0 and r["failed"][0]["error"] == "locked"


# ── endpoint ─────────────────────────────────────────────────────────
def test_endpoint_pc_analyzer():
    from backend.main import app
    with TestClient(app) as client:
        r = client.get("/api/pc-analyzer")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "grade" in data and "score" in data and "checks" in data


def test_endpoint_fix_requires_confirmation():
    from backend.main import app
    with TestClient(app) as client:
        r = client.post("/api/pc-analyzer/fix", json={"action": "cleanup_junk", "confirm": False})
    assert r.status_code == 409
    assert r.json()["confirm"] is True


def test_endpoint_fix_unknown_action():
    from backend.main import app
    with TestClient(app) as client:
        r = client.post("/api/pc-analyzer/fix", json={"action": "nuke", "confirm": True})
    assert r.status_code == 400


def test_endpoint_fix_confirmed_applies():
    from unittest.mock import patch as _patch
    from backend.main import app
    payload = {"ok": True, "action": "cleanup_junk", "count": 2, "freed_bytes": 512,
               "freed_human": "512 B"}
    with _patch("backend.main.pcan.apply_fix", return_value=payload):
        with TestClient(app) as client:
            r = client.post("/api/pc-analyzer/fix", json={"action": "cleanup_junk", "confirm": True})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True and data["count"] == 2