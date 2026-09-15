"""
Tests for the server-side scheduler daemon (Feature A).

Covers:
  - _TOOL_COMMANDS mapping sanity (templates contain {target})
  - get_command() substitution + ValueError for unmapped tools
  - _exec_tool_command() success/failure paths (mocked SSH)
  - _count_findings_in_output() heuristics per tool family
  - _scheduler_loop() single cycle: dispatch, record_run, unmapped/skipped paths
  - GET /api/scheduler/status endpoint
"""

import os
import sys
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import AsyncMock, Mock, patch

from backend.scheduler import get_command, _TOOL_COMMANDS, reset_jobs, due_jobs
import backend.main as main_mod


@pytest.fixture(autouse=True)
def _clean_state():
    reset_jobs()
    yield
    reset_jobs()


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from main import app
    with TestClient(app) as c:
        yield c


# ── get_command / mapping ──

class TestToolCommands:
    def test_mapping_contains_expected_tools(self):
        for tool in ("nmap", "whatweb", "gobuster", "nikto", "wpscan", "enum4linux", "smbclient"):
            assert tool in _TOOL_COMMANDS, tool

    def test_every_template_has_target_placeholder(self):
        for tool, tmpl in _TOOL_COMMANDS.items():
            assert "{target}" in tmpl, f"{tool} template lacks {{target}}"

    def test_get_command_substitutes_target(self):
        assert get_command("nmap", "10.0.0.5") == (
            "nmap -p- -sV -sC -O -A --min-rate=1000 -T4 10.0.0.5"
        )

    def test_get_command_gobuster(self):
        cmd = get_command("gobuster", "example.com")
        assert "http://example.com" in cmd

    def test_get_command_unknown_raises(self):
        with pytest.raises(ValueError):
            get_command("hydra", "10.0.0.5")


# ── _exec_tool_command ──

class TestExecToolCommand:
    def test_success_drains_stdout(self, monkeypatch):
        mock_ssh_client(monkeypatch)
        res = asyncio.run(main_mod._exec_tool_command("nmap", "10.0.0.9", timeout=30))
        assert res["ok"] is True
        assert res["tool"] == "nmap"
        assert res["target"] == "10.0.0.9"
        assert "Nmap scan report" in res["out"]
        assert res["duration_ms"] >= 0

    def test_truncation_flag(self, monkeypatch):
        mock_ssh_client(monkeypatch, big_out=True)
        res = asyncio.run(main_mod._exec_tool_command("nmap", "10.0.0.9", timeout=30))
        assert res["ok"] is True
        assert res["truncated_out"] is True
        assert len(res["out"]) <= 8192

    def test_no_ssh_connection(self, monkeypatch):
        async def no_conn(*a, **kw):
            return None
        monkeypatch.setattr(main_mod, "_ensure_ssh_connection", no_conn)
        res = asyncio.run(main_mod._exec_tool_command("whatweb", "x.test"))
        assert res["ok"] is False
        assert "no shared SSH" in res["error"]

    def test_exec_failure(self, monkeypatch):
        def failing_run(_cmd, timeout=None, get_pty=None):
            raise OSError("boom")
        client = mock_ssh_client(monkeypatch)
        client.exec_command = failing_run
        res = asyncio.run(main_mod._exec_tool_command("nikto", "x.test"))
        assert res["ok"] is False
        assert res["error"] == "boom"


def mock_ssh_client(monkeypatch, big_out=False):
    """Install a fake shared SSH client; returns it for extra stubbing."""
    client = Mock()

    class _FakeChan:
        def recv_exit_status(self):
            return 0

    _chan = _FakeChan()

    class _FakeStdStream:
        def __init__(self, text):
            self._text = text
            self.channel = _chan

        def read(self):
            return self._text

    out_text = ("Nmap scan report for 10.0.0.9\nopen 80/tcp http\n") if not big_out else ("x" * 20000)
    client.exec_command = Mock(return_value=(
        _FakeStdStream(b""),
        _FakeStdStream(out_text.encode()),
        _FakeStdStream(b""),
    ))

    async def _ensure(*a, **kw):
        return client

    monkeypatch.setattr(main_mod, "_ensure_ssh_connection", _ensure)
    return client


# ── _count_findings_in_output ──

class TestCountFindings:
    def test_nmap_open_ports(self):
        out = "open 80/tcp\nopen 443/tcp\nclosed 22/tcp\nNmap done"
        assert main_mod._count_findings_in_output(out, "nmap") == 2

    def test_gobuster_paths(self):
        out = "200 /admin (GET)\n403 /config (GET)\n404 /404\n301 /old"
        assert main_mod._count_findings_in_output(out, "gobuster") == 4

    def test_nikto_markers(self):
        out = "[!] OSVDB-3092: /admin\n+ Server: Apache\nInfo: No CGI"
        assert main_mod._count_findings_in_output(out, "nikto") == 3

    def test_enum4linux_found(self):
        out = "user 'admin' found\n3 found\nnone"
        assert main_mod._count_findings_in_output(out, "enum4linux") == 2

    def test_smbclient_shares(self):
        out = "Sharename       Type\n---------       ----\nC$              Disk\nIPC$            IPC\nADMIN$          Disk"
        assert main_mod._count_findings_in_output(out, "smbclient") == 3

    def test_whatweb_single_line(self):
        assert main_mod._count_findings_in_output("http://x.test [200 OK] Apache", "whatweb") == 1

    def test_unknown_tool_generic(self):
        out = "SERVICE  VULNERABLE  HIGH  FINDING"
        assert main_mod._count_findings_in_output(out, "tool-x") >= 2


# ── _scheduler_loop ──

class TestSchedulerLoop:
    def test_loop_dispatches_and_records(self, monkeypatch):
        from backend.scheduler import create_job, get_job, MIN_INTERVAL_SECONDS
        j_nmap = create_job("N", "nmap", MIN_INTERVAL_SECONDS, target="10.0.0.1")
        j_unknown = create_job("U", "unknown-tool", MIN_INTERVAL_SECONDS, target="10.0.0.2")
        j_empty = create_job("E", "whatweb", MIN_INTERVAL_SECONDS, target="")

        def fake_due(now=None, include_tools=None, require_target=False):
            if not fake_due.called:
                fake_due.called = True
                return [j_nmap.to_dict()]
            return []
        fake_due.called = False

        calls = []

        async def fake_exec(tool_id, target, timeout=90):
            calls.append((tool_id, target))
            return {"ok": True, "tool": tool_id, "target": target, "command": "",
                    "duration_ms": 100, "exit_code": 0, "truncated_out": False,
                    "out": "open 80/tcp\nopen 443/tcp\nNmap done", "err": ""}

        monkeypatch.setattr(main_mod.sched, "due_jobs", fake_due)
        monkeypatch.setattr(main_mod, "_exec_tool_command", fake_exec)

        async def run_once():
            task = asyncio.create_task(main_mod._scheduler_loop(interval_seconds=5.0))
            for _ in range(100):
                await asyncio.sleep(0.01)
                if len(calls) >= 1:
                    break
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run_once())

        assert any(t == "nmap" for t, _ in calls)
        nmap_job = get_job(j_nmap.id)
        assert nmap_job["last_result"] == "success"
        assert nmap_job["last_findings"] == 2
        # Server-unmapped and target-less jobs are left to the browser poll:
        # the daemon must NOT advance or record them.
        unknown_job = get_job(j_unknown.id)
        assert unknown_job["last_result"] == ""
        assert unknown_job["last_error"] == ""
        empty_job = get_job(j_empty.id)
        assert empty_job["last_result"] == ""

    def test_loop_records_failure(self, monkeypatch):
        from backend.scheduler import create_job, get_job, MIN_INTERVAL_SECONDS
        j_nmap = create_job("N2", "nmap", MIN_INTERVAL_SECONDS, target="10.0.0.1")

        def fake_due(now=None, include_tools=None, require_target=False):
            if not fake_due.called:
                fake_due.called = True
                return [j_nmap.to_dict()]
            return []
        fake_due.called = False

        async def fake_exec(tool_id, target, timeout=90):
            return {"ok": False, "tool": tool_id, "target": target, "command": "",
                    "duration_ms": 10, "error": "Kali unreachable"}

        monkeypatch.setattr(main_mod.sched, "due_jobs", fake_due)
        monkeypatch.setattr(main_mod, "_exec_tool_command", fake_exec)

        async def run_once():
            task = asyncio.create_task(main_mod._scheduler_loop(interval_seconds=5.0))
            for _ in range(100):
                await asyncio.sleep(0.01)
                if main_mod.sched.get_job(j_nmap.id)["last_result"] == "error":
                    break
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run_once())
        job = get_job(j_nmap.id)
        assert job["last_result"] == "error"
        assert job["last_error"] == "Kali unreachable"


class TestDueJobsFilters:
    def test_include_tools_leaves_others_due(self):
        from backend.scheduler import create_job, get_job, advance_to_now, MIN_INTERVAL_SECONDS
        j_map = create_job("A", "nmap", 60, target="10.0.0.1")
        j_other = create_job("B", "wafw00f", 60, target="10.0.0.2")
        advance_to_now(j_map.id)
        advance_to_now(j_other.id)
        out = due_jobs(include_tools={"nmap"})
        assert [j["tool_id"] for j in out] == ["nmap"]
        # other job was not advanced by the filtered poll
        assert get_job(j_other.id)["last_result"] == ""
        # but it is still due for the unfiltered consumer
        out2 = due_jobs()
        assert [j["tool_id"] for j in out2] == ["wafw00f"]

    def test_require_target_skips_empty(self):
        from backend.scheduler import create_job, advance_to_now, MIN_INTERVAL_SECONDS
        j_t = create_job("C", "whatweb", 60, target="10.0.0.5")
        j_nt = create_job("D", "whatweb", 60, target="")
        advance_to_now(j_t.id)
        advance_to_now(j_nt.id)
        assert [j["id"] for j in due_jobs(require_target=True)] == [j_t.id]
        assert due_jobs()  # empty-target job still due for browser consumers

    def test_status_endpoint(self, client):
        r = client.get("/api/scheduler/status")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "daemon_running" in data
        assert "nmap" in data["mapped_tools"]