@echo off
title VulnForge MCP Test
cd /d "%~dp0.."

echo ════════════════════════════════════════════
echo   VulnForge MCP Server — Test
echo ════════════════════════════════════════════
echo.

:: Option 1: Run the MCP server standalone (for testing with MCP Inspector)
:: npx @anthropic/mcp-inspector python backend/mcp_server.py

:: Option 2: Quick protocol test (sends initialize, tools/list, then shutdown)
echo [*] Testing MCP protocol handshake...
echo {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}
echo {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
echo {"jsonrpc":"2.0","id":3,"method":"shutdown","params":{}}
) | python backend/mcp_server.py

echo.
echo [*] Test complete.
echo.
echo To use with Claude Desktop, copy scripts/mcp_config.example.json
echo to %%APPDATA%%\Claude\claude_desktop_config.json
echo.
echo To test interactively:
echo   npx @anthropic/mcp-inspector python backend/mcp_server.py
echo.

pause
