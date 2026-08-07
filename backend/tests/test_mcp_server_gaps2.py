"""
Coverage-gap tests for backend/mcp_server.py.

Covers the optional MCP SDK import path, the whatweb "no technologies"
branch of _tool_recon and the stdio main-loop error handling.
"""

import importlib
import sys
import types
from unittest.mock import patch

import pytest

import backend.mcp_server as ms


@pytest.fixture()
def mcp_sdk_enabled():
    """Fake the official MCP SDK modules and reload mcp_server."""
    mcp_pkg = types.ModuleType("mcp")
    mcp_pkg.Server = type("Server", (), {})
    mcp_pkg.NotificationOptions = object
    server_mod = types.ModuleType("mcp.server")
    server_mod.Server = mcp_pkg.Server
    server_mod.NotificationOptions = object
    models_mod = types.ModuleType("mcp.server.models")
    models_mod.InitializationOptions = object
    types_mod = types.ModuleType("mcp.types")
    types_mod.Tool = object
    types_mod.TextContent = object
    types_mod.CallToolResult = object
    types_mod.ListToolsResult = object

    original = {name: sys.modules.get(name) for name in
                ("mcp", "mcp.server", "mcp.server.models", "mcp.types")}
    sys.modules["mcp"] = mcp_pkg
    sys.modules["mcp.server"] = server_mod
    sys.modules["mcp.server.models"] = models_mod
    sys.modules["mcp.types"] = types_mod
    importlib.reload(ms)
    assert ms.HAS_MCP_SDK is True
    try:
        yield
    finally:
        for name, mod in original.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        importlib.reload(ms)
        assert ms.HAS_MCP_SDK is False


class TestSdkImport:
    def test_sdk_import_succeeds(self, mcp_sdk_enabled):
        from mcp.server import Server  # noqa: F401
        assert ms.Server is Server


class TestToolRecon:
    @pytest.mark.asyncio
    async def test_whatweb_no_technologies(self):
        def fake_exec(cmd, timeout=None):
            if cmd.startswith("whatweb"):
                return "ERROR: unable to connect"
            return ""
        with patch("backend.mcp_server.exec_command", side_effect=fake_exec):
            out = await ms._tool_recon({"target": "10.0.0.1"})
        assert "(no web technologies detected)" in out


class _FakeStdin:
    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self):
        return self._lines.pop(0) if self._lines else ""

    def reconfigure(self, **kwargs):
        pass


class _FakeStdout:
    def __init__(self):
        self.writes = []

    def write(self, s):
        self.writes.append(s)

    def flush(self):
        pass

    def reconfigure(self, **kwargs):
        pass


class _ExplodingStdin(_FakeStdin):
    def __init__(self, exc):
        super().__init__([])
        self._exc = exc

    def readline(self):
        raise self._exc


class TestMainLoop:
    @pytest.mark.asyncio
    async def test_incomplete_json_waits_then_eof(self, monkeypatch):
        # First line holds valid JSON + trailing garbage (JSONDecodeError),
        # second line is EOF -> clean shutdown.
        monkeypatch.setattr(sys, "stdin", _FakeStdin([
            '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"} trailing',
            "",
        ]))
        monkeypatch.setattr(sys, "stdout", _FakeStdout())
        with patch("backend.mcp_server.handle_message", return_value=None):
            await ms.main()

    @pytest.mark.asyncio
    async def test_eof_error_breaks(self, monkeypatch):
        monkeypatch.setattr(sys, "stdin", _ExplodingStdin(EOFError("closed")))
        monkeypatch.setattr(sys, "stdout", _FakeStdout())
        await ms.main()

    @pytest.mark.asyncio
    async def test_exception_breaks(self, monkeypatch):
        monkeypatch.setattr(sys, "stdin", _ExplodingStdin(RuntimeError("io failure")))
        monkeypatch.setattr(sys, "stdout", _FakeStdout())
        await ms.main()


class TestEntryPoint:
    def test_asyncio_run_entrypoint(self, monkeypatch):
        """Re-run the module as __main__ (EOF on stdin -> clean shutdown)."""
        import runpy
        monkeypatch.setattr(sys, "stdin", _FakeStdin([""]))
        monkeypatch.setattr(sys, "stdout", _FakeStdout())
        runpy.run_module("backend.mcp_server", run_name="__main__", alter_sys=True)
