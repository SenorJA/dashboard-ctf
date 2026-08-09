"""Tests for backend/mcp_server.py — MCP JSON-RPC protocol + tool handlers.

All SSH-dependent paths are mocked; no real network is used.
"""
import asyncio
import io
import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import backend.mcp_server as mcp


@pytest.fixture(autouse=True)
def _clean_findings():
    """Reset the global session findings store between tests."""
    mcp._session_findings = []
    yield
    mcp._session_findings = []


@pytest.fixture(autouse=True)
def _clean_ssh():
    """Ensure SSH singleton is None before/after tests."""
    mcp._ssh_client = None
    yield
    mcp._ssh_client = None


# ════════════════════════════════════════════════════════════════
#  TOOL DEFINITIONS
# ════════════════════════════════════════════════════════════════

def test_tools_defined_with_expected_schema():
    names = [t["name"] for t in mcp.TOOLS]
    assert names == [
        "vulnforge_recon",
        "vulnforge_port_scan",
        "vulnforge_web_scan",
        "vulnforge_exploit_search",
        "vulnforge_scope_check",
        "vulnforge_run_command",
        "vulnforge_findings_list",
        "vulnforge_browser_import",
        "vulnforge_browser_list_sessions",
        "vulnforge_browser_get_session",
        "vulnforge_browser_analyze",
        "vulnforge_browser_get_analysis",
        "vulnforge_browser_create_findings",
        "vulnforge_browser_stats",
    ]
    for tool in mcp.TOOLS:
        assert tool["description"]
        assert tool["inputSchema"]["type"] == "object"
        assert tool["inputSchema"]["properties"]


def test_tools_have_required_target():
    for name in ("vulnforge_recon", "vulnforge_port_scan", "vulnforge_web_scan",
                 "vulnforge_exploit_search", "vulnforge_scope_check"):
        tool = next(t for t in mcp.TOOLS if t["name"] == name)
        assert "target" in tool["inputSchema"]["required"] or "service" in tool["inputSchema"]["required"]


# ════════════════════════════════════════════════════════════════
#  JSON-RPC PROTOCOL
# ════════════════════════════════════════════════════════════════

def test_handle_message_initialize():
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    resp = asyncio.run(mcp.handle_message(msg))
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == "2024-11-05"
    assert resp["result"]["serverInfo"]["name"] == "vulnforge-mcp"
    assert resp["result"]["capabilities"] == mcp.CAPABILITIES


def test_handle_message_tools_list():
    msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    resp = asyncio.run(mcp.handle_message(msg))
    assert resp["id"] == 2
    assert resp["result"]["tools"] == mcp.TOOLS


def test_handle_message_ping():
    msg = {"jsonrpc": "2.0", "id": 3, "method": "ping"}
    resp = asyncio.run(mcp.handle_message(msg))
    assert resp == {"jsonrpc": "2.0", "id": 3, "result": {}}


def test_handle_message_method_not_found():
    msg = {"jsonrpc": "2.0", "id": 4, "method": "bogus/method"}
    resp = asyncio.run(mcp.handle_message(msg))
    assert resp["error"]["code"] == -32601
    assert "bogus/method" in resp["error"]["message"]


def test_handle_message_notification_returns_none():
    msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert asyncio.run(mcp.handle_message(msg)) is None


def test_handle_message_tools_call_returns_text_content():
    msg = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "vulnforge_findings_list", "arguments": {}},
    }
    resp = asyncio.run(mcp.handle_message(msg))
    assert resp["id"] == 5
    assert resp["result"]["isError"] is False
    assert resp["result"]["content"][0]["type"] == "text"
    assert "No findings yet" in resp["result"]["content"][0]["text"]


def test_handle_message_tools_call_error_captured():
    msg = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {"name": "vulnforge_scope_check", "arguments": {"target": "10.0.0.1"}},
    }
    with patch("backend.mcp_server._tool_scope_check", side_effect=RuntimeError("boom")):
        resp = asyncio.run(mcp.handle_message(msg))
    assert resp["error"]["code"] == -32603
    assert "boom" in resp["error"]["message"]


# ════════════════════════════════════════════════════════════════
#  HANDLER ROUTING + FINDINGS STORE
# ════════════════════════════════════════════════════════════════

def test_handle_tool_call_unknown_tool():
    assert asyncio.run(mcp.handle_tool_call("nope", {})) == "Unknown tool: nope"


def test_add_finding_stores_record():
    mcp._add_finding("nmap", "high", "Open port", "detail here", "10.0.0.1")
    assert len(mcp._session_findings) == 1
    f = mcp._session_findings[0]
    assert f["tool"] == "nmap"
    assert f["severity"] == "high"
    assert f["title"] == "Open port"
    assert f["detail"] == "detail here"
    assert f["target"] == "10.0.0.1"
    assert "timestamp" in f


def test_add_finding_truncates_detail():
    mcp._add_finding("nmap", "info", "t", "x" * 2000)
    assert len(mcp._session_findings[0]["detail"]) == 500


def test_findings_list_filters():
    mcp._session_findings = [
        {"tool": "nmap", "severity": "high", "title": "A", "detail": "d1", "target": "t1"},
        {"tool": "nikto", "severity": "info", "title": "B", "detail": "d2", "target": "t2"},
        {"tool": "nmap", "severity": "info", "title": "C", "detail": "d3", "target": "t3"},
    ]
    text = asyncio.run(mcp._tool_findings_list({"severity": "info", "tool": ""}))
    assert "📊 Findings: 2 total" in text
    assert "B" in text and "C" in text and "A" not in text

    text2 = asyncio.run(mcp._tool_findings_list({"severity": "", "tool": "nmap"}))
    assert "📊 Findings: 2 total" in text2
    assert "A" in text2 and "C" in text2 and "B" not in text2


# ════════════════════════════════════════════════════════════════
#  SCOPE CHECK
# ════════════════════════════════════════════════════════════════

def test_tool_scope_check_in_scope():
    with patch("backend.scope_guard.is_in_scope", return_value=True):
        text = asyncio.run(mcp._tool_scope_check({"target": "10.0.0.1"}))
    assert "IN SCOPE" in text


def test_tool_scope_check_out_of_scope():
    with patch("backend.scope_guard.is_in_scope", return_value=False):
        text = asyncio.run(mcp._tool_scope_check({"target": "10.0.0.1"}))
    assert "OUT OF SCOPE" in text


def test_tool_scope_check_unavailable():
    # scope_guard import succeeds but raises at runtime → except branch
    with patch("backend.scope_guard.is_in_scope", side_effect=RuntimeError("no scope")):
        text = asyncio.run(mcp._tool_scope_check({"target": "10.0.0.1"}))
    assert "not available" in text.lower()


# ════════════════════════════════════════════════════════════════
#  RUN COMMAND (safety filtering)
# ════════════════════════════════════════════════════════════════

def test_tool_run_command_blocks_dangerous():
    blocked = ["rm -rf /", "dd if=/dev/zero", "mkfs.ext4 /dev/sda", "> /dev/sda"]
    for cmd in blocked:
        text = asyncio.run(mcp._tool_run_command({"command": cmd, "timeout": 10}))
        assert "BLOCKED" in text
    assert mcp._session_findings == []


def test_tool_run_command_executes_and_clamps_timeout():
    with patch("backend.mcp_server.exec_command", new=AsyncMock(return_value="nmap output")) as ex:
        text = asyncio.run(mcp._tool_run_command({"command": "nmap -sV 10.0.0.1", "timeout": 9999}))
        ex.assert_awaited_once()
        # timeout clamped to 300
        assert ex.await_args.args[1] == 300
    assert "nmap output" in text
    assert "$ nmap -sV 10.0.0.1" in text


# ════════════════════════════════════════════════════════════════
#  TOOL HANDLERS (exec_command mocked)
# ════════════════════════════════════════════════════════════════

def test_tool_recon_parses_ports_dns_and_whatweb():
    nmap_out = (
        "22/tcp   open  ssh     OpenSSH 8.9p1\n"
        "80/tcp   open  http    nginx 1.18\n"
        "8080/tcp open  http    Apache\n"
    )

    async def fake_exec(cmd, timeout=120):
        if "nmap" in cmd:
            return nmap_out
        if "whatweb" in cmd:
            return "http://example.com [200 OK] Nginx[1.18]"
        return "10.0.0.1 has address 10.0.0.1"

    with patch("backend.mcp_server.exec_command", new=AsyncMock(side_effect=fake_exec)):
        text = asyncio.run(mcp._tool_recon({"target": "example.com"}))

    assert "Reconnaissance against example.com" in text
    assert "nmap port scan" in text
    assert "whatweb" in text
    assert "DNS enumeration" in text
    assert "Recon complete" in text

    tools = {f["tool"] for f in mcp._session_findings}
    assert tools == {"nmap", "whatweb", "dns"}
    # ssh/finger open ports get 'medium' severity
    assert any(f["severity"] == "medium" and "22/tcp" in f["title"] for f in mcp._session_findings)


def test_tool_recon_ip_skips_dns():
    async def fake_exec(cmd, timeout=120):
        return "22/tcp open ssh OpenSSH"

    with patch("backend.mcp_server.exec_command", new=AsyncMock(side_effect=fake_exec)):
        text = asyncio.run(mcp._tool_recon({"target": "192.168.1.10"}))
    assert "DNS enumeration" not in text
    assert "192.168.1.10" in text


def test_tool_port_scan_with_ports():
    out = "22/tcp open ssh OpenSSH\n443/tcp open https nginx"

    async def fake_exec(cmd, timeout=120):
        assert "-p22,80,443" in cmd
        return out

    with patch("backend.mcp_server.exec_command", new=AsyncMock(side_effect=fake_exec)):
        text = asyncio.run(mcp._tool_port_scan({"target": "10.0.0.1", "ports": "22,80,443"}))
    assert "Port scan: 10.0.0.1" in text
    assert len(mcp._session_findings) == 2


def test_tool_port_scan_top_ports_default():
    async def fake_exec(cmd, timeout=120):
        assert "--top-ports 1000" in cmd
        return ""

    with patch("backend.mcp_server.exec_command", new=AsyncMock(side_effect=fake_exec)):
        text = asyncio.run(mcp._tool_port_scan({"target": "10.0.0.1"}))
    assert "--top-ports 1000" in text
    assert mcp._session_findings == []


def test_tool_web_scan_parses_nikto_and_dirb():
    nikto_out = (
        "+ Server: nginx\n"
        "+ /admin/: Admin login page found.\n"
    )
    dirb_out = (
        "+ http://10.0.0.1/admin/ (CODE:200|SIZE:1024)\n"
        "+ http://10.0.0.1/robots.txt (CODE:200|SIZE:200)\n"
    )

    async def fake_exec(cmd, timeout=120):
        if "nikto" in cmd:
            return nikto_out
        return dirb_out

    with patch("backend.mcp_server.exec_command", new=AsyncMock(side_effect=fake_exec)):
        text = asyncio.run(mcp._tool_web_scan({"target": "10.0.0.1", "use_ssl": True}))

    assert "Web scan: https://10.0.0.1" in text
    assert "nikto" in text
    assert "dirb" in text
    tools = {f["tool"] for f in mcp._session_findings}
    assert "nikto" in tools and "dirb" in tools
    assert any(f["tool"] == "nikto" and f["severity"] == "medium" for f in mcp._session_findings)


def test_tool_web_scan_http_default():
    async def fake_exec(cmd, timeout=120):
        return ""

    with patch("backend.mcp_server.exec_command", new=AsyncMock(side_effect=fake_exec)):
        text = asyncio.run(mcp._tool_web_scan({"target": "10.0.0.1"}))
    assert "Web scan: http://10.0.0.1" in text


def test_tool_exploit_search_parses_results():
    out = (
        "Exploits: No Result\n"
        "---------------------------------------------------------------\n"
        " Path | Title\n"
        "---------------------------------------------------------------\n"
        "exploits/linux/remote/1234.py | Apache 2.4.49 - Path Traversal | 2021-08-09\n"
        "exploits/linux/webapps/5678.py | Apache 2.4.49 - RCE | 2021-09-02\n"
    )

    with patch("backend.mcp_server.exec_command", new=AsyncMock(return_value=out)):
        text = asyncio.run(mcp._tool_exploit_search({"service": "apache", "version": "2.4.49"}))

    assert "Exploit search: apache 2.4.49" in text
    assert "Found 2 potential exploits" in text
    assert all(f["tool"] == "searchsploit" and f["severity"] == "high" for f in mcp._session_findings)
    assert "Path Traversal" in mcp._session_findings[0]["title"]


def test_tool_exploit_search_none_found():
    out = "Exploits: No Result\n"

    with patch("backend.mcp_server.exec_command", new=AsyncMock(return_value=out)):
        text = asyncio.run(mcp._tool_exploit_search({"service": "apache"}))

    assert "No public exploits found" in text
    assert mcp._session_findings == []


# ════════════════════════════════════════════════════════════════
#  SSH LAYER
# ════════════════════════════════════════════════════════════════

def test_get_ssh_creates_connection():
    fake_client = MagicMock()
    fake_client.get_transport.return_value = None

    with patch("backend.mcp_server.paramiko.SSHClient", return_value=fake_client):
        client = asyncio.run(mcp.get_ssh())

    assert client is fake_client
    fake_client.connect.assert_called_once()
    assert mcp._ssh_client is fake_client


def test_get_ssh_reuses_active_connection():
    transport = MagicMock()
    transport.is_active.return_value = True
    existing = MagicMock()
    existing.get_transport.return_value = transport

    mcp._ssh_client = existing
    with patch("backend.mcp_server.paramiko.SSHClient") as ssh_cls:
        client = asyncio.run(mcp.get_ssh())

    assert client is existing
    ssh_cls.assert_not_called()


def test_get_ssh_reconnects_when_inactive():
    transport = MagicMock()
    transport.is_active.return_value = False
    stale = MagicMock()
    stale.get_transport.return_value = transport
    fresh = MagicMock()
    fresh.get_transport.return_value = None

    mcp._ssh_client = stale
    with patch("backend.mcp_server.paramiko.SSHClient", return_value=fresh):
        client = asyncio.run(mcp.get_ssh())

    assert client is fresh
    fresh.connect.assert_called_once()


def test_exec_command_success():
    ssh = MagicMock()
    out = MagicMock()
    out.read.return_value = b"stdout data"
    err = MagicMock()
    err.read.return_value = b""
    ssh.exec_command.return_value = (MagicMock(), out, err)

    with patch("backend.mcp_server.get_ssh", new=AsyncMock(return_value=ssh)):
        result = asyncio.run(mcp.exec_command("whoami", timeout=5))

    assert result == "stdout data"
    ssh.exec_command.assert_called_once_with("whoami", timeout=5)


def test_exec_command_includes_stderr_and_truncates():
    ssh = MagicMock()
    out = MagicMock()
    out.read.return_value = b"x" * 20000
    err = MagicMock()
    err.read.return_value = b"ERR"
    ssh.exec_command.return_value = (MagicMock(), out, err)

    with patch("backend.mcp_server.get_ssh", new=AsyncMock(return_value=ssh)):
        result = asyncio.run(mcp.exec_command("cmd"))

    # Output truncated to 10000 chars; stderr only appears if it fits in the slice
    assert len(result) == 10000
    assert result.startswith("x" * 10000)


def test_exec_command_appends_stderr_when_space_allows():
    ssh = MagicMock()
    out = MagicMock()
    out.read.return_value = b"stdout data"
    err = MagicMock()
    err.read.return_value = b"ERR"
    ssh.exec_command.return_value = (MagicMock(), out, err)

    with patch("backend.mcp_server.get_ssh", new=AsyncMock(return_value=ssh)):
        result = asyncio.run(mcp.exec_command("cmd"))

    assert result == "stdout data\nERR"


def test_exec_command_returns_error_string_on_exception():
    ssh = MagicMock()
    ssh.exec_command.side_effect = ConnectionError("down")

    with patch("backend.mcp_server.get_ssh", new=AsyncMock(return_value=ssh)):
        result = asyncio.run(mcp.exec_command("cmd"))
    assert result.startswith("ERROR:") and "down" in result


def test_close_ssh():
    client = MagicMock()
    mcp._ssh_client = client
    mcp.close_ssh()
    client.close.assert_called_once()
    assert mcp._ssh_client is None


def test_close_ssh_none_is_safe():
    mcp._ssh_client = None
    mcp.close_ssh()  # should not raise


def test_close_ssh_tolerates_close_error():
    client = MagicMock()
    client.close.side_effect = Exception("close failed")
    mcp._ssh_client = client
    mcp.close_ssh()  # should not raise
    assert mcp._ssh_client is None


# ════════════════════════════════════════════════════════════════
#  MAIN LOOP (stdio JSON-RPC)
# ════════════════════════════════════════════════════════════════

class FakeStdout(io.StringIO):
    def reconfigure(self, *args, **kwargs):
        pass


def test_main_loop_processes_messages_and_shuts_down():
    lines = (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        '{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
        '{"jsonrpc":"2.0","id":3,"method":"tools/call",'
        '"params":{"name":"vulnforge_findings_list","arguments":{}}}\n'
    )

    class FakeStdin(io.StringIO):
        def reconfigure(self, *args, **kwargs):
            pass

    fake_stdout = FakeStdout()
    with patch.object(mcp, "sys") as fake_sys:
        fake_sys.stdin = FakeStdin(lines)
        fake_sys.stdout = fake_stdout
        fake_sys.stderr = io.StringIO()
        with patch("backend.mcp_server.close_ssh") as close_mock:
            asyncio.run(mcp.main())

    close_mock.assert_called_once()
    responses = [json.loads(l) for l in fake_stdout.getvalue().strip().splitlines()]
    assert len(responses) == 3
    assert responses[0]["result"]["serverInfo"]["name"] == "vulnforge-mcp"
    assert responses[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}
    assert "No findings yet" in responses[2]["result"]["content"][0]["text"]
