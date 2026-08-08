"""
Gap tests for main.py websocket SSH proxy (/ws).

These run in a separate process from test_main_gaps.py to avoid
TestClient resource contention when many clients are spun up.
"""
import asyncio
import json
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient
import main
import paramiko


def _ws_channel():
    """Build a mock paramiko channel for the websocket SSH proxy."""
    ch = MagicMock()
    ch.recv_ready.return_value = False
    ch.recv.return_value = b"shell output\n"
    ch.setblocking.return_value = None
    ch.send.return_value = None
    ch.close.return_value = None
    ch.resize_pty.return_value = None
    return ch


def _ws_ssh(channel=None):
    """Build a mock paramiko SSHClient."""
    ssh = MagicMock()
    ssh.invoke_shell.return_value = channel or _ws_channel()
    ssh.connect.return_value = None
    ssh.close.return_value = None

    def fake_exec(cmd):
        if "vfshell" in cmd:
            out = b"12345\n"
        elif cmd.startswith("readlink"):
            out = b"/home/user\n"
        elif "compgen" in cmd:
            out = b"pi pip pip3\n"
        else:
            out = b"12345\n"
        stdout = MagicMock()
        stdout.read.return_value = out
        return (MagicMock(), stdout, MagicMock())

    ssh.exec_command.side_effect = fake_exec
    return ssh


def _patches(ssh=None):
    ssh = ssh or _ws_ssh()
    stack = ExitStack()
    stack.enter_context(patch("main.paramiko.SSHClient", return_value=ssh))
    stack.enter_context(patch("main.paramiko.AutoAddPolicy", return_value=MagicMock()))
    return stack


class TestWebSocketAuthErrors:
    def test_bad_json(self, client: TestClient):
        with _patches():
            with client.websocket_connect("/ws") as ws:
                assert "Awaiting authentication" in ws.receive_text()
                ws.send_text("this is not json")
                msg = ws.receive_text()
                assert "error" in msg
                with pytest.raises(Exception):
                    ws.receive_text()

    def test_wrong_type(self, client: TestClient):
        with _patches():
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "hello"})
                msg = ws.receive_text()
                assert "auth" in msg
                with pytest.raises(Exception):
                    ws.receive_text()

    def test_missing_creds(self, client: TestClient):
        with _patches():
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "", "user": "", "pass": ""})
                msg = ws.receive_text()
                assert "ip, user, and pass" in msg
                with pytest.raises(Exception):
                    ws.receive_text()


class TestWebSocketSsh:
    def test_authentication_error(self, client: TestClient):
        ssh = _ws_ssh()
        ssh.connect.side_effect = paramiko.AuthenticationException("bad creds")
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                msg = ws.receive_text()
                assert "authentication failed" in msg.lower()
        ssh.close.assert_called()

    def test_ssh_exception(self, client: TestClient):
        ssh = _ws_ssh()
        ssh.connect.side_effect = paramiko.SSHException("conn error")
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                msg = ws.receive_text()
                assert "SSH connection error" in msg
        ssh.close.assert_called()

    def test_generic_error(self, client: TestClient):
        ssh = _ws_ssh()
        ssh.connect.side_effect = RuntimeError("boom")
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                msg = ws.receive_text()
                assert "Error" in msg
        ssh.close.assert_called()

    def test_full_session(self, client: TestClient):
        ch = _ws_channel()
        ch.recv_ready.side_effect = [True, False]
        ssh = _ws_ssh(ch)
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                assert "Awaiting authentication" in ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "port": 22, "user": "u", "pass": "p"})
                assert "connected" in ws.receive_text()
                assert "Connecting to u@1.2.3.4:22" in ws.receive_text()
                assert "Connected to u@1.2.3.4" in ws.receive_text()
                out = ws.receive_text()
                assert "shell output" in out

                ws.send_text("ls -la")
                ws.send_text("sudo apt update")
                ws.send_json({"type": "interrupt"})
                msg = ws.receive_text()
                assert "interrupted" in msg
                ws.send_json({"type": "resize", "width": 80, "height": 30})
                ch.resize_pty.assert_called_once()

                ws.send_json({"type": "tab_complete", "text": "pi", "is_command": True})
                msg = ws.receive_text()
                data = json.loads(msg)
                assert data["type"] == "tab_result"
                assert data["completions"] == ["pi", "pip", "pip3"]

                ws.send_json({"type": "auth", "ip": "9.9.9.9", "user": "u2", "pass": "p2"})
                msg = ws.receive_text()
                assert "Re-connected as u2@9.9.9.9" in msg
                ws.send_text("p10k disable")
        ssh.close.assert_called()

    def test_tab_complete_fallback(self, client: TestClient):
        ssh = _ws_ssh()
        ssh.exec_command.side_effect = None
        stdout = MagicMock()
        stdout.read.return_value = b""
        ssh.exec_command.return_value = (MagicMock(), stdout, MagicMock())
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_json({"type": "tab_complete", "text": "pi", "is_command": False})
                msg = ws.receive_text()
                assert '"tab_result"' in msg
        ssh.exec_command.assert_called()

    def test_tab_complete_error(self, client: TestClient):
        ssh = _ws_ssh()
        ssh.exec_command.side_effect = RuntimeError("boom")
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_json({"type": "tab_complete", "text": "pi", "is_command": True})
                msg = ws.receive_text()
                data = json.loads(msg)
                assert data["type"] == "tab_result"
                assert data["completions"] == []
                assert "boom" in data["error"]

    def test_scope_block(self, client: TestClient):
        ssh = _ws_ssh()
        with _patches(ssh), \
             patch("backend.scope_guard.validate_command", return_value={
                 "mode": "block", "message": "Out of scope", "targets": ["x"]
             }) as vc, \
             patch("backend.scope_guard.log_block", return_value=None):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_text("evil-command")
                msg = ws.receive_text()
                assert "scope_block" in msg
                msg2 = ws.receive_text()
                assert "BLOCKED" in msg2
        vc.assert_called()

    def test_scope_warn(self, client: TestClient):
        ch = _ws_channel()
        ssh = _ws_ssh(ch)
        with _patches(ssh), \
             patch("backend.scope_guard.validate_command", return_value={
                 "mode": "warn", "message": "Careful", "targets": []
             }):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_text("nmap -sV target")
                msg = ws.receive_text()
                assert "Scope Warning" in msg
                ch.send.assert_called()
        ch.close.assert_called()

    def test_recv_oserror_breaks_reader(self, client: TestClient):
        ch = _ws_channel()
        ch.recv_ready.side_effect = [True]
        ch.recv.side_effect = OSError("closed")
        ssh = _ws_ssh(ch)
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_text("echo hi")
        ssh.close.assert_called()

    def test_tab_complete_empty_cwd(self, client: TestClient):
        ssh = _ws_ssh()

        def fake_exec(cmd):
            if "vfshell" in cmd:
                out = b"12345\n"
            elif cmd.startswith("readlink"):
                out = b"\n"
            elif "compgen" in cmd:
                out = b"pi\n"
            else:
                out = b"\n"
            stdout = MagicMock()
            stdout.read.return_value = out
            return (MagicMock(), stdout, MagicMock())

        ssh.exec_command.side_effect = fake_exec
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_json({"type": "tab_complete", "text": "pi", "is_command": True})
                msg = ws.receive_text()
                data = json.loads(msg)
                assert data["type"] == "tab_result"
                assert data["completions"] == ["pi"]
        ssh.exec_command.assert_called()

    def test_channel_close_raises(self, client: TestClient):
        ch = _ws_channel()
        ch.close.side_effect = OSError("already closed")
        ssh = _ws_ssh(ch)
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_text("echo hi")
        ssh.close.assert_called()

    def test_ssh_close_raises(self, client: TestClient):
        ssh = _ws_ssh()
        ssh.close.side_effect = OSError("already closed")
        with _patches(ssh):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
                ws.send_json({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"})
                ws.receive_text()
                ws.receive_text()
                ws.receive_text()
                ws.send_text("echo hi")
        ssh.close.assert_called()


    def test_client_disconnect_before_auth(self, client: TestClient):
        with _patches():
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()

    def test_read_shell_break_direct(self):
        from starlette.websockets import WebSocketDisconnect

        ch = _ws_channel()
        ch.recv_ready.return_value = True
        ch.recv.side_effect = OSError("channel closed")
        ssh = _ws_ssh(ch)

        replies = [
            json.dumps({"type": "auth", "ip": "1.2.3.4", "user": "u", "pass": "p"}),
            "echo hi",
        ]

        ws = MagicMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        ws.close = AsyncMock()

        async def fake_receive():
            if replies:
                return replies.pop(0)
            raise WebSocketDisconnect()

        ws.receive_text = fake_receive

        with _patches(ssh):
            asyncio.run(main.websocket_endpoint(ws))
        ssh.close.assert_called()


class TestFavicon:
    def test_svg_fallback(self):
        with patch("main.os.path.isfile", side_effect=lambda p: p.endswith("favicon.svg")):
            resp = asyncio.run(main.favicon())
        assert resp.status_code == 200

    def test_not_found(self):
        with patch("main.os.path.isfile", return_value=False):
            resp = asyncio.run(main.favicon())
        assert resp.status_code == 404
