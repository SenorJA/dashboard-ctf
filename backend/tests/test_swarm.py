"""
Tests for backend/swarm.py — Multi-operator Swarm Coordinator.

Covers:
    - SwarmCoordinator.__init__() basic setup, defaults, uuid
    - add_log() timestamped, add_finding(), get_operator_findings(), get_all_findings()
    - to_dict() serialization, logs truncation, operators list
    - cancel() state change
    - get_session(), list_sessions() from global store
    - run_pipeline() SSH failure, cancel mid-pipeline, success
    - connect_ssh() success and failure
    - close_ssh()
"""

import pytest
import sys
import os
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import swarm
from swarm import (
    SwarmCoordinator,
    get_session,
    list_sessions,
    _sessions,
)


@pytest.fixture(autouse=True)
def reset_sessions():
    """Clear global session store between tests."""
    _sessions.clear()
    yield
    _sessions.clear()


@pytest.fixture
def coordinator():
    """Create a SwarmCoordinator instance."""
    return SwarmCoordinator(
        target="10.0.0.1",
        ssh_ip="192.168.1.100",
        ssh_user="kali",
        ssh_pass="kali123",
        ssh_port=22,
    )


# ════════════════════════════════════════════════════════════════
#  __init__()
# ════════════════════════════════════════════════════════════════

class TestSwarmInit:
    def test_session_id_is_string(self, coordinator):
        assert isinstance(coordinator.session_id, str)
        assert len(coordinator.session_id) > 0

    def test_target_stored(self, coordinator):
        assert coordinator.target == "10.0.0.1"

    def test_ssh_config(self, coordinator):
        assert coordinator.ssh_config["ip"] == "192.168.1.100"
        assert coordinator.ssh_config["user"] == "kali"
        assert coordinator.ssh_config["pass"] == "kali123"
        assert coordinator.ssh_config["port"] == 22

    def test_initial_status(self, coordinator):
        assert coordinator.status == "pending"

    def test_initial_progress(self, coordinator):
        assert coordinator.progress == 0

    def test_initial_operator(self, coordinator):
        assert coordinator.current_operator is None

    def test_created_at_is_string(self, coordinator):
        assert isinstance(coordinator.created_at, str)

    def test_logs_empty(self, coordinator):
        assert coordinator.logs == []

    def test_findings_empty(self, coordinator):
        assert coordinator.findings == []

    def test_ssh_none(self, coordinator):
        assert coordinator.ssh is None

    def test_cancel_flag_false(self, coordinator):
        assert coordinator._cancel is False

    def test_unique_session_ids(self):
        c1 = SwarmCoordinator("10.0.0.1", "ip", "u", "p")
        c2 = SwarmCoordinator("10.0.0.2", "ip", "u", "p")
        assert c1.session_id != c2.session_id

    def test_custom_port(self):
        c = SwarmCoordinator("10.0.0.1", "ip", "u", "p", ssh_port=2222)
        assert c.ssh_config["port"] == 2222


# ════════════════════════════════════════════════════════════════
#  Logging & Findings
# ════════════════════════════════════════════════════════════════

class TestLoggingFindings:
    def test_add_log(self, coordinator):
        coordinator.add_log("test message")
        assert len(coordinator.logs) == 1
        assert "test message" in coordinator.logs[0]

    def test_log_has_timestamp(self, coordinator):
        coordinator.add_log("msg")
        assert coordinator.logs[0].startswith("[")

    def test_add_finding(self, coordinator):
        finding = {"tool": "nmap", "severity": "high", "title": "Open port"}
        coordinator.add_finding(finding)
        assert len(coordinator.findings) == 1

    def test_get_all_findings(self, coordinator):
        coordinator.add_finding({"tool": "nmap"})
        coordinator.add_finding({"tool": "nikto"})
        all_f = coordinator.get_all_findings()
        assert len(all_f) == 2

    def test_get_operator_findings(self, coordinator):
        coordinator.add_finding({"tool": "nmap", "source": "swarm:Recon"})
        coordinator.add_finding({"tool": "nikto", "source": "swarm:Scanner"})
        recon_f = coordinator.get_operator_findings("Recon")
        assert len(recon_f) == 1

    def test_get_operator_findings_empty(self, coordinator):
        coordinator.add_finding({"tool": "nmap", "source": "swarm:Recon"})
        scanner_f = coordinator.get_operator_findings("Scanner")
        assert len(scanner_f) == 0


# ════════════════════════════════════════════════════════════════
#  to_dict()
# ════════════════════════════════════════════════════════════════

class TestToDict:
    def test_basic_fields(self, coordinator):
        d = coordinator.to_dict()
        assert "session_id" in d
        assert d["target"] == "10.0.0.1"
        assert "status" in d
        assert "progress" in d

    def test_operators_list(self, coordinator):
        d = coordinator.to_dict()
        assert "operators" in d
        assert isinstance(d["operators"], list)

    def test_logs_in_dict(self, coordinator):
        coordinator.add_log("test")
        d = coordinator.to_dict()
        assert len(d["logs"]) == 1

    def test_findings_in_dict(self, coordinator):
        coordinator.add_finding({"tool": "nmap"})
        d = coordinator.to_dict()
        assert len(d["findings"]) == 1

    def test_logs_truncated(self, coordinator):
        for i in range(250):
            coordinator.add_log(f"msg {i}")
        d = coordinator.to_dict()
        assert len(d["logs"]) <= 200


# ════════════════════════════════════════════════════════════════
#  cancel()
# ════════════════════════════════════════════════════════════════

class TestCancel:
    def test_cancel_sets_flag(self, coordinator):
        coordinator.cancel()
        assert coordinator._cancel is True
        assert coordinator.status == "cancelled"


# ════════════════════════════════════════════════════════════════
#  Session management
# ════════════════════════════════════════════════════════════════

class TestSessionManagement:
    def test_get_session_existing(self, coordinator):
        _sessions[coordinator.session_id] = coordinator
        result = get_session(coordinator.session_id)
        assert result is coordinator

    def test_get_session_nonexistent(self):
        result = get_session("nonexistent-id")
        assert result is None

    def test_list_sessions_empty(self):
        assert list_sessions() == []

    def test_list_sessions_populated(self, coordinator):
        _sessions[coordinator.session_id] = coordinator
        sessions = list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == coordinator.session_id
        assert sessions[0]["target"] == "10.0.0.1"
        assert sessions[0]["status"] == "pending"

    def test_list_sessions_multiple(self):
        c1 = SwarmCoordinator("10.0.0.1", "ip", "u", "p")
        c2 = SwarmCoordinator("10.0.0.2", "ip", "u", "p")
        _sessions[c1.session_id] = c1
        _sessions[c2.session_id] = c2
        sessions = list_sessions()
        assert len(sessions) == 2


# ════════════════════════════════════════════════════════════════
#  connect_ssh()
# ════════════════════════════════════════════════════════════════

class TestConnectSsh:
    @pytest.mark.asyncio
    async def test_connect_success(self, coordinator):
        mock_ssh = MagicMock()
        with patch("swarm.paramiko") as mock_paramiko:
            mock_paramiko.SSHClient.return_value = mock_ssh
            mock_paramiko.AutoAddPolicy.return_value = MagicMock()
            with patch("swarm.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                result = await coordinator.connect_ssh()
                assert result is True
                assert coordinator.ssh is mock_ssh

    @pytest.mark.asyncio
    async def test_connect_failure(self, coordinator):
        with patch("swarm.paramiko") as mock_paramiko:
            mock_paramiko.SSHClient.return_value = MagicMock()
            mock_paramiko.AutoAddPolicy.return_value = MagicMock()
            with patch("swarm.asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
                mock_thread.side_effect = RuntimeError("Connection refused")
                result = await coordinator.connect_ssh()
                assert result is False
                assert coordinator.status == "error"

    @pytest.mark.asyncio
    async def test_connect_logs(self, coordinator):
        with patch("swarm.paramiko") as mock_paramiko:
            mock_paramiko.SSHClient.return_value = MagicMock()
            mock_paramiko.AutoAddPolicy.return_value = MagicMock()
            with patch("swarm.asyncio.to_thread", new_callable=AsyncMock):
                await coordinator.connect_ssh()
                assert any("Connecting" in log for log in coordinator.logs)
                assert any("connected successfully" in log for log in coordinator.logs)


# ════════════════════════════════════════════════════════════════
#  close_ssh()
# ════════════════════════════════════════════════════════════════

class TestCloseSsh:
    @pytest.mark.asyncio
    async def test_close_ssh(self, coordinator):
        # Save the mock first — close_ssh() sets self.ssh = None,
        # so we need a separate reference to assert on the close call.
        mock_ssh = MagicMock()
        coordinator.ssh = mock_ssh
        await coordinator.close_ssh()
        mock_ssh.close.assert_called_once()
        assert coordinator.ssh is None

    @pytest.mark.asyncio
    async def test_close_ssh_none(self, coordinator):
        coordinator.ssh = None
        await coordinator.close_ssh()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_ssh_exception(self, coordinator):
        coordinator.ssh = MagicMock()
        coordinator.ssh.close.side_effect = RuntimeError("already closed")
        await coordinator.close_ssh()  # Should not raise
        assert coordinator.ssh is None


# ════════════════════════════════════════════════════════════════
#  run_pipeline()
# ════════════════════════════════════════════════════════════════

class TestRunPipeline:
    @pytest.mark.asyncio
    async def test_ssh_failure_sets_error(self, coordinator):
        # Mimic the real connect_ssh() which sets status="error" on failure.
        async def _fail_connect():
            coordinator.status = "error"
            return False

        with patch.object(coordinator, "connect_ssh", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = _fail_connect
            await coordinator.run_pipeline()
            assert coordinator.status == "error"

    @pytest.mark.asyncio
    async def test_already_running_does_nothing(self, coordinator):
        coordinator.status = "running"
        await coordinator.run_pipeline()
        assert coordinator.status == "running"

    @pytest.mark.asyncio
    async def test_cancel_stops_pipeline(self, coordinator):
        # run_pipeline() resets ``_cancel`` at the start, so the cancel
        # flag must be set AFTER the reset — i.e. during connect_ssh().
        async def _connect_then_cancel():
            coordinator._cancel = True
            return True

        with patch.object(coordinator, "connect_ssh", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = _connect_then_cancel
            await coordinator.run_pipeline()
            assert coordinator.status == "cancelled"

    @pytest.mark.asyncio
    async def test_pipeline_closes_ssh(self, coordinator):
        with patch.object(coordinator, "connect_ssh", new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = True
            coordinator.ssh = MagicMock()
            with patch.object(coordinator, "close_ssh", new_callable=AsyncMock) as mock_close:
                # Simulate pipeline error
                with patch("swarm.ReconOperator") as mock_recon:
                    mock_recon.side_effect = RuntimeError("op error")
                    await coordinator.run_pipeline()
                    mock_close.assert_called()


# ════════════════════════════════════════════════════════════════
#  start()
# ════════════════════════════════════════════════════════════════

class TestStart:
    def test_start_creates_task(self, coordinator):
        with patch("swarm.asyncio.create_task") as mock_task:
            coordinator.start()
            mock_task.assert_called_once()
            assert coordinator.session_id in _sessions

    def test_start_registers_session(self, coordinator):
        with patch("swarm.asyncio.create_task"):
            coordinator.start()
            assert get_session(coordinator.session_id) is coordinator
