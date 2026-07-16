"""
M.I.R.V. — kali-mcp Client.

Bridge between MIRV backend and kali-mcp Docker container.
When KALI_MCP_URL is set, MIRV can optionally delegate tool execution
to kali-mcp instead of SSH, enabling Docker-based Kali access.

Protocol: MCP Streamable HTTP (JSON-RPC over HTTP)
Docs: https://modelcontextprotocol.io
"""

import os
import json
import logging
from typing import Optional

logger = logging.getLogger("mirv.kali_mcp")

KALI_MCP_URL = os.getenv("KALI_MCP_URL", "")


def is_available() -> bool:
    """Check if kali-mcp is configured and reachable."""
    if not KALI_MCP_URL:
        return False
    try:
        import httpx
        r = httpx.get(KALI_MCP_URL.replace("/mcp", "/health"), timeout=2)
        return r.status_code == 200
    except Exception:
        return False


async def call_tool(tool_name: str, args: dict = None) -> dict:
    """
    Call a tool on kali-mcp via MCP protocol.

    Args:
        tool_name: Name of the MCP tool (e.g. 'execute_command', 'nmap_scan')
        args: Tool arguments as dict

    Returns:
        Response dict with 'content' list or 'error'
    """
    if not KALI_MCP_URL:
        return {"error": "KALI_MCP_URL not configured"}

    import httpx

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args or {}
        }
    }

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(KALI_MCP_URL, json=payload)
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.error("kali-mcp call failed: %s", e)
        return {"error": str(e)}


async def execute_command(command: str) -> str:
    """
    Execute an arbitrary command on kali-mcp and return stdout.
    This is the primary integration point — wraps execute_command MCP tool.
    """
    result = await call_tool("execute_command", {"command": command})
    if "error" in result:
        return f"ERROR: {result['error']}"

    content = result.get("content", [])
    output = ""
    for item in content:
        if isinstance(item, dict) and "text" in item:
            output += item["text"]
        elif isinstance(item, str):
            output += item
    return output.strip()


# ── Tool-specific wrappers ────────────────────────────────

async def nmap_scan(target: str, args: str = "-sV -sC -Pn") -> str:
    """Port scan via kali-mcp."""
    return await execute_command(f"nmap {args} {target}")


async def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt") -> str:
    """Directory enumeration via kali-mcp."""
    return await execute_command(f"gobuster dir -u {url} -w {wordlist} -t 30 -q")


async def nikto_scan(url: str) -> str:
    """Web vuln scan via kali-mcp."""
    return await execute_command(f"nikto -h {url} -maxtime 120s")


async def whatweb_scan(url: str) -> str:
    """Web tech detection via kali-mcp."""
    return await execute_command(f"whatweb -a 3 {url}")


async def list_available_tools() -> list:
    """List all tools available on kali-mcp."""
    if not KALI_MCP_URL:
        return []

    import httpx

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(KALI_MCP_URL, json=payload)
            data = r.json()
            return data.get("result", {}).get("tools", [])
    except Exception as e:
        logger.error("Failed to list kali-mcp tools: %s", e)
        return []
