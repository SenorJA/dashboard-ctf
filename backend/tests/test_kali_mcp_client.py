"""
Tests for backend/kali_mcp_client.py — Kali Tools Container Client.

Covers:
    - Module-level constants (IS_KALI_CONTAINER, KALI_MCP_URL)
    - is_available() all modes: container, MCP URL, neither
    - execute_command() all modes: container SSH, MCP HTTP, neither
    - nmap_scan(), gobuster_dir(), nikto_scan(), whatweb_scan()
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import kali_mcp_client
from kali_mcp_client import (
    IS_KALI_CONTAINER,
    KALI_MCP_URL,
    is_available,
    execute_command,
    nmap_scan,
    gobuster_dir,
    nikto_scan,
    whatweb_scan,
)


@pytest.fixture(autouse=True)
def reset_env():
    """Reset module-level env vars between tests."""
    original_is_container = kali_mcp_client.IS_KALI_CONTAINER
    original_mcp_url = kali_mcp_client.KALI_MCP_URL
    yield
    kali_mcp_client.IS_KALI_CONTAINER = original_is_container
    kali_mcp_client.KALI_MCP_URL = original_mcp_url


# ════════════════════════════════════════════════════════════════
#  Module Constants
# ════════════════════════════════════════════════════════════════

class TestModuleConstants:
    def test_is_container_is_bool(self):
        assert isinstance(IS_KALI_CONTAINER, bool)

    def test_mcp_url_is_string(self):
        assert isinstance(KALI_MCP_URL, str)


# ════════════════════════════════════════════════════════════════
#  is_available()
# ════════════════════════════════════════════════════════════════

class TestIsAvailable:
    def test_container_mode_available(self):
        kali_mcp_client.IS_KALI_CONTAINER = True
        assert is_available() is True

    def test_no_container_no_mcp(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = ""
        assert is_available() is False

    def test_mcp_url_healthy(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_httpx = MagicMock()
        mock_httpx.get.return_value = MagicMock(status_code=200)
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            assert is_available() is True
            mock_httpx.get.assert_called_once()

    def test_mcp_url_unhealthy(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_httpx = MagicMock()
        mock_httpx.get.return_value = MagicMock(status_code=500)
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            assert is_available() is False

    def test_mcp_url_connection_error(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_httpx = MagicMock()
        mock_httpx.get.side_effect = ConnectionError("refused")
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            assert is_available() is False

    def test_mcp_health_url_replaces_mcp(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_httpx = MagicMock()
        mock_httpx.get.return_value = MagicMock(status_code=200)
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            is_available()
            called_url = mock_httpx.get.call_args[0][0]
            assert "/health" in called_url
            assert "/mcp" not in called_url


# ════════════════════════════════════════════════════════════════
#  execute_command()
# ════════════════════════════════════════════════════════════════

class TestExecuteCommand:
    @pytest.mark.asyncio
    async def test_no_mcp_no_container(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = ""
        result = await execute_command("ls")
        assert "ERROR" in result
        assert "No Kali" in result

    @pytest.mark.asyncio
    async def test_container_no_ssh(self):
        kali_mcp_client.IS_KALI_CONTAINER = True
        kali_mcp_client.KALI_MCP_URL = ""
        fake_main = MagicMock()
        fake_main.get_active_ssh_client.return_value = None
        fake_main._ensure_ssh_connection = AsyncMock(return_value=None)
        with patch.dict("sys.modules", {"backend.main": fake_main}):
            result = await execute_command("ls")
            assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_container_ssh_success(self):
        kali_mcp_client.IS_KALI_CONTAINER = True
        kali_mcp_client.KALI_MCP_URL = ""
        mock_ssh = MagicMock()
        transport = MagicMock()
        transport.is_active.return_value = True
        mock_chan = MagicMock()
        mock_chan.recv.return_value = b"file1.txt\nfile2.txt\n"
        mock_chan.recv_stderr.return_value = b""
        transport.open_session.return_value = mock_chan
        mock_ssh.get_transport.return_value = transport

        fake_main = MagicMock()
        fake_main.get_active_ssh_client.return_value = mock_ssh
        with patch.dict("sys.modules", {"backend.main": fake_main}):
            result = await execute_command("ls /tmp")
            assert "file1.txt" in result

    @pytest.mark.asyncio
    async def test_container_ssh_transport_inactive(self):
        kali_mcp_client.IS_KALI_CONTAINER = True
        kali_mcp_client.KALI_MCP_URL = ""
        mock_ssh = MagicMock()
        transport = MagicMock()
        transport.is_active.return_value = False
        mock_ssh.get_transport.return_value = transport

        fake_main = MagicMock()
        fake_main.get_active_ssh_client.return_value = mock_ssh
        with patch.dict("sys.modules", {"backend.main": fake_main}):
            result = await execute_command("ls")
            assert "ERROR" in result
            assert "not active" in result

    @pytest.mark.asyncio
    async def test_container_ssh_exception(self):
        kali_mcp_client.IS_KALI_CONTAINER = True
        kali_mcp_client.KALI_MCP_URL = ""
        mock_ssh = MagicMock()
        transport = MagicMock()
        transport.is_active.return_value = True
        transport.open_session.side_effect = RuntimeError("chan error")
        mock_ssh.get_transport.return_value = transport

        fake_main = MagicMock()
        fake_main.get_active_ssh_client.return_value = mock_ssh
        with patch.dict("sys.modules", {"backend.main": fake_main}):
            result = await execute_command("ls")
            assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_mcp_url_success(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {"content": [{"text": "nmap output\n"}]}
        }
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await execute_command("nmap -sV 10.0.0.1")
            assert "nmap output" in result

    @pytest.mark.asyncio
    async def test_mcp_url_empty_content(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_response = MagicMock()
        mock_response.json.return_value = {"result": {"content": []}}
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await execute_command("ls")
            assert result == ""

    @pytest.mark.asyncio
    async def test_mcp_url_error(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_client = AsyncMock()
        mock_client.post.side_effect = ConnectionError("refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await execute_command("ls")
            assert "ERROR" in result

    @pytest.mark.asyncio
    async def test_mcp_url_non_text_content_items(self):
        kali_mcp_client.IS_KALI_CONTAINER = False
        kali_mcp_client.KALI_MCP_URL = "http://kali:8080/mcp"
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "result": {"content": [{"type": "image", "data": "abc"}, 42, {"text": "valid"}]}
        }
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        mock_httpx = MagicMock()
        mock_httpx.AsyncClient.return_value = mock_client
        with patch.dict("sys.modules", {"httpx": mock_httpx}):
            result = await execute_command("ls")
            assert "valid" in result


# ════════════════════════════════════════════════════════════════
#  Convenience wrappers
# ════════════════════════════════════════════════════════════════

class TestConvenienceWrappers:
    @pytest.mark.asyncio
    async def test_nmap_scan(self):
        with patch("kali_mcp_client.execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "nmap output"
            result = await nmap_scan("10.0.0.1")
            mock_exec.assert_called_once_with("nmap -sV -sC -Pn 10.0.0.1")

    @pytest.mark.asyncio
    async def test_nmap_scan_custom_args(self):
        with patch("kali_mcp_client.execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "nmap output"
            result = await nmap_scan("10.0.0.1", "-sS -T2")
            mock_exec.assert_called_once_with("nmap -sS -T2 10.0.0.1")

    @pytest.mark.asyncio
    async def test_gobuster_dir(self):
        with patch("kali_mcp_client.execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "gobuster output"
            result = await gobuster_dir("http://10.0.0.1")
            assert "gobuster dir" in mock_exec.call_args[0][0]
            assert "http://10.0.0.1" in mock_exec.call_args[0][0]

    @pytest.mark.asyncio
    async def test_gobuster_custom_wordlist(self):
        with patch("kali_mcp_client.execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "gobuster output"
            result = await gobuster_dir("http://10.0.0.1", wordlist="/custom/wl.txt")
            assert "/custom/wl.txt" in mock_exec.call_args[0][0]

    @pytest.mark.asyncio
    async def test_nikto_scan(self):
        with patch("kali_mcp_client.execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "nikto output"
            result = await nikto_scan("http://10.0.0.1")
            assert "nikto" in mock_exec.call_args[0][0]
            assert "http://10.0.0.1" in mock_exec.call_args[0][0]

    @pytest.mark.asyncio
    async def test_whatweb_scan(self):
        with patch("kali_mcp_client.execute_command", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = "whatweb output"
            result = await whatweb_scan("http://10.0.0.1")
            assert "whatweb" in mock_exec.call_args[0][0]
            assert "http://10.0.0.1" in mock_exec.call_args[0][0]
