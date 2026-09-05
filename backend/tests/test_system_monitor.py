"""
Tests for system_monitor -- host resource & storage intelligence module.

Covers:
  - memory()/cpu()/uptime() (psutil fast-path, /proc and ctypes fallbacks)
  - disk_partitions() (real + mocked)
  - scan_candidates() (Windows/POSIX layout, explicit roots, sorting)
  - find_large_unused() (old big files)
  - cleanup_candidate() (ok, missing, dangerous-path safety, force)
  - summary() shape
  - REST endpoints (/api/system/stats, /disk, /cleanup GET, /cleanup POST)
"""

import os
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend import system_monitor as sm

# Make sure dangerous-path safety works regardless of CWD
_HERE = os.path.dirname(os.path.abspath(__file__))


# ── helpers / fixtures ─────────────────────────────────────────────
class _Ns:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def fake_mem(**_):
    return _Ns(total=16 * 1024**3, available=8 * 1024**3, used=8 * 1024**3)


@pytest.fixture(autouse=True)
def _clean_cache():
    with sm._LOCK:
        sm._CACHE.clear()
        sm._CPU_STATE.clear()
    yield


@pytest.fixture
def scanned_home(tmp_path):
    """Create a fake user-home with known clutter sizes."""
    home = tmp_path / "home"
    (home / "Downloads").mkdir(parents=True)
    (home / "Documents").mkdir()
    (home / "Desktop").mkdir()
    (home / "AppData" / "Local" / "Temp").mkdir(parents=True)
    (home / "AppData" / "Roaming").mkdir(parents=True)

    (home / "Downloads" / "big.iso").write_bytes(b"x" * (60 * 1024))
    (home / "Documents" / "notes.txt").write_bytes(b"y" * (10 * 1024))
    (home / "Desktop" / "file.txt").write_bytes(b"z" * (5 * 1024))
    (home / "AppData" / "Local" / "Temp" / "junk.tmp").write_bytes(b"t" * (3 * 1024))
    return home


# ── memory / cpu / uptime ──────────────────────────────────────────
class _FakePsutil:
    """Minimal stand-in for the optional psutil module in tests."""

    def __init__(self, **members):
        self.__dict__.update(members)


def test_memory_psutil_path():
    fake = _FakePsutil(virtual_memory=lambda: fake_mem())
    with patch.object(sm, "psutil", fake), patch.object(sm, "_HAVE_PSUTIL", True):
        m = sm.memory()
    assert m["percent"] == 50.0
    assert m["total"]["bytes"] == 16 * 1024**3
    assert m["used"]["gb"] == 8.0
    assert "available" in m


def test_memory_linux_fallback(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       16000000 kB\nMemFree:          2000000 kB\nMemAvailable:   8000000 kB\n")
    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "posix"):
        with patch("builtins.open", return_value=meminfo.open("r")):
            d = sm._mem_linux()
    assert d["total"] == 16000000 * 1024
    assert d["available"] == 8000000 * 1024


def test_cpu_linux_stale_returns_zero():
    import io
    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "posix"):
        with patch("builtins.open", create=True) as mo:
            mo.return_value.__enter__.return_value = io.StringIO("cpu  100 0 100 1000 0 0 0 0\n")
            assert sm.cpu()["percent"] == 0.0


def test_uptime_linux(tmp_path):
    up = tmp_path / "uptime"
    up.write_text("3600.0 1234.0\n")
    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "posix"):
        with patch("builtins.open", create=True) as mo:
            mo.return_value.__enter__.return_value = up.open("r")
            assert sm.uptime()["seconds"] == 3600.0


def test_uptime_linux_error_defaults_zero():
    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "posix"):
        with patch("builtins.open", side_effect=OSError("missing")):
            assert sm.uptime()["seconds"] == 0.0


# ── disk_partitions ────────────────────────────────────────────────
def test_disk_partitions_rejects_zero_total(tmp_path):
    parts = [
        type("P", (), {"mountpoint": "/mnt/empty", "device": "/dev/xx", "fstype": "ext4"})(),
    ]

    def fake_usage(p):
        raise OSError("unreadable")

    fake = _FakePsutil(disk_partitions=lambda all=True: parts)
    with patch.object(sm, "psutil", fake), patch.object(sm, "_HAVE_PSUTIL", True):
        with patch.object(sm.shutil, "disk_usage", side_effect=fake_usage):
            assert sm.disk_partitions() == []


def test_disk_partitions_psutil_paths():
    parts = [type("P", (), {"mountpoint": "/", "device": "/dev/sda1", "fstype": "ext4"})()]

    class U:
        total, used, free = 100, 30, 70

    fake = _FakePsutil(disk_partitions=lambda all=True: parts)
    with patch.object(sm, "psutil", fake), patch.object(sm, "_HAVE_PSUTIL", True):
        with patch.object(sm.shutil, "disk_usage", return_value=U()):
            out = sm.disk_partitions()
    assert len(out) == 1
    assert out[0]["percent"] == 30.0


def test_disk_partitions_windows_letters():
    class FakeDiskUsage:
        total, used, free = 500 * 1024**3, 100 * 1024**3, 400 * 1024**3

    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "nt"):
        with patch("os.path.exists", side_effect=lambda p: p == "C:\\"):
            with patch.object(sm.shutil, "disk_usage", return_value=FakeDiskUsage()):
                out = sm.disk_partitions()
    assert len(out) == 1
    assert out[0]["percent"] == 20.0


def test_disk_partitions_linux_mounts():
    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "posix"):
        with patch("builtins.open", create=True) as mo:
            mo.return_value.__enter__.return_value = [
                "/dev/sda1 / ext4 rw 0 0\n",
                "proc /proc proc rw 0 0\n",
            ]
            with patch.object(sm.shutil, "disk_usage", return_value=type("U", (), {"total": 100, "used": 30, "free": 70})()):
                out = sm.disk_partitions()
    assert len(out) == 1
    assert out[0]["mount"] == "/"


# ── scan_candidates ────────────────────────────────────────────────
def test_scan_candidates_no_home():
    with patch.object(sm, "_home_dir", return_value=None):
        assert sm.scan_candidates() == []


def test_scan_candidates_sorted_size_desc(scanned_home):
    with patch.object(sm, "os", sm.os):
        with patch.object(sm.os, "name", "posix"):
            # force POSIX layout against the windows-like fixture
            cands = sm.scan_candidates(str(scanned_home))
    sizes = [c.size_bytes for c in cands]
    assert sizes == sorted(sizes, reverse=True)
    labels = {c.label for c in cands}
    assert "Downloads" in labels
    assert ".cache" in labels  # POSIX branch present


def test_scan_candidates_windows_branch(scanned_home):
    with patch.object(sm.os, "name", "nt"):
        cands = sm.scan_candidates(str(scanned_home))
    labels = {c.label for c in cands}
    assert "User Temp" in labels
    assert "AppData\\Local" in labels


def test_scan_candidate_to_dict():
    c = sm.CleanCandidate("/x", "X", "temp", "safe", "reason", 2048)
    d = c.to_dict()
    assert d["size_bytes"] == 2048
    assert d["size_human"] == "2.0 KB"
    assert d["risk"] == "safe"


# ── find_large_unused ──────────────────────────────────────────────
def test_find_large_unused_old_file(tmp_path):
    old = tmp_path / "old_big.bin"
    old.write_bytes(b"x" * (60 * 1024 * 1024))
    old_time = time.time() - 200 * 86400
    os.utime(old, (old_time, old_time))
    with patch.object(sm, "_home_dir", return_value=str(tmp_path)):
        out = sm.find_large_unused(older_than_days=90)
    assert any(c.path == str(old) for c in out)


def test_find_large_unused_skips_small_and_fresh(tmp_path):
    small = tmp_path / "small.txt"
    small.write_bytes(b"x" * 1000)
    fresh = tmp_path / "fresh.bin"
    fresh.write_bytes(b"y" * (60 * 1024 * 1024))
    with patch.object(sm, "_home_dir", return_value=str(tmp_path)):
        out = sm.find_large_unused(older_than_days=90)
    assert all(c.path not in (str(small), str(fresh)) for c in out)


# ── cleanup_candidate ──────────────────────────────────────────────
def test_cleanup_missing_path():
    res = sm.cleanup_candidate("/nonexistent/nope")
    assert res["ok"] is False


def test_cleanup_empty_path():
    res = sm.cleanup_candidate("")
    assert res["ok"] is False


def test_cleanup_dangerous_path_refused():
    res = sm.cleanup_candidate("/")
    assert res["ok"] is False
    assert "dangerous" in res["error"]


def test_cleanup_dangerous_windows_refused():
    res = sm.cleanup_candidate("C:\\Windows\\System32")
    assert res["ok"] is False


def test_cleanup_dangerous_force_allows(tmp_path):
    # force bypasses the hard refuse, but path must still exist
    target = tmp_path / "will_fail"
    res = sm.cleanup_candidate(str(target), force=True)
    assert res["ok"] is False  # does not exist


def test_cleanup_file_ok(tmp_path):
    f = tmp_path / "file.tmp"
    f.write_bytes(b"x" * 1024)
    res = sm.cleanup_candidate(str(f))
    assert res["ok"] is True
    assert res["freed_bytes"] == 1024
    assert not f.exists()


def test_cleanup_dir_ok(tmp_path):
    d = tmp_path / "cachedir"
    d.mkdir()
    (d / "a.bin").write_bytes(b"y" * 4096)
    res = sm.cleanup_candidate(str(d))
    assert res["ok"] is True
    assert res["freed_bytes"] == 4096
    assert not d.exists()


def test_looks_dangerous_home():
    with patch.object(sm, "_home_dir", return_value="C:\\Users\\tester"):
        assert sm._looks_dangerous("C:\\Users\\tester") is True
        assert sm._looks_dangerous("C:\\Users\\tester2") is False


# ── summary shape ──────────────────────────────────────────────────
def test_summary_shape(tmp_path):
    with patch.object(sm, "_HAVE_PSUTIL", False), patch.object(sm.os, "name", "nt"):
        with patch("os.path.exists", return_value=False):
            with patch.object(sm, "memory", return_value={
                "total": {"bytes": 1, "gb": 0.0}, "used": {"bytes": 1, "gb": 0.0},
                "available": {"bytes": 0, "gb": 0.0}, "percent": 0.0,
            }), patch.object(sm, "cpu", return_value={"percent": 0.0, "cores": 1.0}):
                with patch.object(sm, "uptime", return_value={"seconds": 0.0}):
                    s = sm.summary()
    assert "platform" in s and "memory" in s and "cpu" in s and "disk" in s


# ── REST endpoints ────────────────────────────────────────────────
@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from backend.main import app
    with TestClient(app) as c:
        yield c


def test_api_stats(client):
    resp = client.get("/api/system/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert "stats" in body


def test_api_disk(client):
    resp = client.get("/api/system/disk")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_api_cleanup_list(client):
    resp = client.get("/api/system/cleanup")
    assert resp.status_code == 200
    assert "candidates" in resp.json()


def test_api_cleanup_delete_missing(client):
    resp = client.post("/api/system/cleanup", json={"path": "/nonexistent/nope"})
    assert resp.status_code == 400
    assert resp.json()["ok"] is False


def test_api_cleanup_delete_dangerous(client):
    resp = client.post("/api/system/cleanup", json={"path": "/"})
    assert resp.status_code == 400
    assert "dangerous" in resp.json()["error"]