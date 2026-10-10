"""Pack 19 — Wireless audit host-only bridge (backend/wireless_analyzer.py + /api/wireless/*).

Hermetic: the physical Kali host is never contacted. `_ssh_client` is patched and
the registry is reset per test. Endpoints are exercised through `TestClient(app)`.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from backend import wireless_analyzer as wa
from backend.main import app
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _clean_registry():
    wa.registry.clear()
    yield
    wa.registry.clear()


def _client():
    return TestClient(app)


# ════════════════════════════════════════════════════════════════
#  Registry
# ════════════════════════════════════════════════════════════════

class TestRegistry:
    def test_create_returns_session(self):
        s = wa.registry.create()
        assert s.sid
        assert s.status == "ready"
        assert s.interface == "wlan0mon"
        assert wa.registry.get(s.sid) is s

    def test_get_missing_returns_none(self):
        assert wa.registry.get("nope") is None

    def test_list_and_clear(self):
        a = wa.registry.create()
        b = wa.registry.create()
        rows = wa.registry.list()
        assert {r["sid"] for r in rows} == {a.sid, b.sid}
        assert wa.registry.clear() == 2
        assert wa.registry.list() == []

    def test_list_returns_copies(self):
        s = wa.registry.create()
        wa.registry.list()[0]["status"] = "tampered"
        assert wa.registry.get(s.sid).status == "ready"


# ════════════════════════════════════════════════════════════════
#  run_host_cmd
# ════════════════════════════════════════════════════════════════

class TestRunHostCmd:
    def test_not_configured_returns_graceful_error(self, monkeypatch):
        monkeypatch.delenv("MIRV_WIRELESS_HOST", raising=False)
        out, err, rc = wa.run_host_cmd("iw dev")
        assert rc == 1
        assert "not configured" in err

    def test_success_path(self):
        fake_stdout = MagicMock()
        fake_stdout.read.return_value = b"ok\n"
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_stderr = MagicMock()
        fake_stderr.read.return_value = b""
        fake_client = MagicMock()
        fake_client.exec_command.return_value = (MagicMock(), fake_stdout, fake_stderr)

        with patch.object(wa, "_ssh_client", return_value=fake_client):
            out, err, rc = wa.run_host_cmd("which airmon-ng")
        assert out == "ok\n"
        assert err == ""
        assert rc == 0
        fake_client.close.assert_called_once()

    def test_exception_path_returns_rc1(self):
        fake_client = MagicMock()
        fake_client.exec_command.side_effect = RuntimeError("boom")
        with patch.object(wa, "_ssh_client", return_value=fake_client):
            out, err, rc = wa.run_host_cmd("x")
        assert out == ""
        assert "boom" in err
        assert rc == 1

    def test_close_errors_are_swallowed(self):
        fake_stdout = MagicMock()
        fake_stdout.read.return_value = b""
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_stderr = MagicMock()
        fake_stderr.read.return_value = b""
        fake_client = MagicMock()
        fake_client.exec_command.return_value = (MagicMock(), fake_stdout, fake_stderr)
        fake_client.close.side_effect = RuntimeError("close fail")
        with patch.object(wa, "_ssh_client", return_value=fake_client):
            out, err, rc = wa.run_host_cmd("x")
        assert rc == 0


class TestSshClient:
    def test_none_when_paramiko_missing(self, monkeypatch):
        monkeypatch.setattr(wa, "paramiko", None)
        assert wa._ssh_client() is None

    def test_none_when_host_unset(self, monkeypatch):
        monkeypatch.delenv("MIRV_WIRELESS_HOST", raising=False)
        assert wa._ssh_client() is None


# ════════════════════════════════════════════════════════════════
#  Endpoints (/api/wireless/*)
# ════════════════════════════════════════════════════════════════

class TestWirelessEndpoints:
    def test_list_empty(self):
        with _client() as c:
            r = c.get("/api/wireless/sessions")
        assert r.status_code == 200
        assert r.json()["sessions"] == []

    def test_create_and_get(self):
        with _client() as c:
            r = c.post("/api/wireless/sessions")
            assert r.status_code == 200
            sid = r.json()["session"]["sid"]
            g = c.get(f"/api/wireless/sessions/{sid}")
        assert g.status_code == 200
        assert g.json()["session"]["sid"] == sid

    def test_get_missing_404(self):
        with _client() as c:
            r = c.get("/api/wireless/sessions/doesnotexist")
        assert r.status_code == 404

    def test_host_check_not_configured(self, monkeypatch):
        monkeypatch.delenv("MIRV_WIRELESS_HOST", raising=False)
        with _client() as c:
            r = c.post("/api/wireless/host/check")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["rc"] == 1
        assert "ERR:" in body["output"] or "not configured" in body["output"]

    def test_host_check_reports_err(self):
        with patch.object(wa, "run_host_cmd", return_value=("tools", "warning", 0)):
            with _client() as c:
                r = c.post("/api/wireless/host/check")
        body = r.json()
        assert body["output"] == "tools\nERR:warning"
        assert body["rc"] == 0

    def test_host_exec_ok(self):
        with patch.object(wa, "run_host_cmd", return_value=("scanning", "", 0)):
            with _client() as c:
                r = c.post("/api/wireless/host/exec", json={"cmd": "airodump-ng wlan0mon"})
        assert r.status_code == 200
        assert r.json()["output"] == "scanning"

    def test_host_exec_rejects_empty(self):
        with _client() as c:
            r = c.post("/api/wireless/host/exec", json={"cmd": ""})
        assert r.status_code == 400

    def test_host_exec_rejects_oversize(self):
        with _client() as c:
            r = c.post("/api/wireless/host/exec", json={"cmd": "a" * 5000})
        assert r.status_code == 400

    def test_endpoints_degrade_when_module_unavailable(self):
        with patch("backend.main.wla", None):
            with _client() as c:
                assert c.get("/api/wireless/sessions").status_code == 500
                assert c.post("/api/wireless/sessions").status_code == 500
                assert c.get("/api/wireless/sessions/x").status_code == 500
                assert c.post("/api/wireless/host/check").status_code == 500
                assert c.post("/api/wireless/host/exec", json={"cmd": "x"}).status_code == 500
