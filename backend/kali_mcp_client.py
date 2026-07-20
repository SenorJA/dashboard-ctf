"""
M.I.R.V. — Kali Tools Container Client.

Bridge between MIRV backend and the kali-tools Docker container.
When KALI_MCP_URL is set (legacy MCP mode) or KALI_IP=kali-tools
(Docker Compose mode), MIRV can execute commands inside the container.

In Docker Compose mode, MIRV connects via SSH to the container
(which runs an SSH server) — same as connecting to any Kali VM.
"""

import os
import json
import logging
from typing import Optional

logger = logging.getLogger("mirv.kali_tools")

# Detect if we're running inside Docker Compose with kali-tools
KALI_CONTAINER_HOST = os.getenv("KALI_IP", "")
IS_KALI_CONTAINER = KALI_CONTAINER_HOST == "kali-tools"

# Legacy MCP mode (for external kali-mcp instances)
KALI_MCP_URL = os.getenv("KALI_MCP_URL", "")


def is_available() -> bool:
    """Check if kali-tools container is reachable."""
    # In Docker Compose mode, rely on container health check
    if IS_KALI_CONTAINER:
        return True

    # Legacy MCP mode
    if KALI_MCP_URL:
        try:
            import httpx
            health_url = KALI_MCP_URL.replace("/mcp", "/health")
            r = httpx.get(health_url, timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    return False


async def execute_command(command: str) -> str:
    """
    Execute an arbitrary command on the Kali container.

    In Docker Compose mode, this uses the already-established SSH connection.
    In legacy MCP mode, it calls the MCP endpoint.
    """
    if IS_KALI_CONTAINER:
        # SSH connection is handled by the main module's _ensure_ssh_connection
        # which auto-connects to KALI_IP=kali-tools
        from backend.main import get_active_ssh_client, _ensure_ssh_connection
        client = get_active_ssh_client()
        if not client:
            # Try to auto-connect — env vars are set in docker-compose
            client = await _ensure_ssh_connection()
        if not client:
            return "ERROR: No SSH connection to kali-tools container"

        try:
            transport = client.get_transport()
            if not transport or not transport.is_active():
                return "ERROR: SSH transport is not active"
            chan = transport.open_session()
            chan.settimeout(120)
            chan.exec_command(command)
            stdout = chan.recv(65536).decode("utf-8", errors="replace")
            stderr = chan.recv_stderr(65536).decode("utf-8", errors="replace")
            chan.close()
            return (stdout + stderr).strip()
        except Exception as e:
            logger.error("kali-tools exec failed: %s", e)
            return f"ERROR: {e}"

    # Legacy MCP mode
    if KALI_MCP_URL:
        import httpx
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {"command": command}
            }
        }
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.post(KALI_MCP_URL, json=payload)
                data = r.json()
                content = data.get("result", {}).get("content", [])
                output = ""
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        output += item["text"]
                return output.strip()
        except Exception as e:
            return f"ERROR: {e}"

    return "ERROR: No Kali container or MCP URL configured"


async def nmap_scan(target: str, args: str = "-sV -sC -Pn") -> str:
    """Port scan via Kali container."""
    return await execute_command(f"nmap {args} {target}")


async def list_available_tools() -> list:
    """List the tools exposed by the kali-mcp endpoint (legacy MCP mode).

    Returns a list of tool name strings. In Docker Compose mode (or when the
    MCP endpoint is not configured / unreachable) returns an empty list.
    """
    if not KALI_MCP_URL:
        return []
    try:
        import httpx
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(KALI_MCP_URL, json=payload)
            data = r.json()
            tools = []
            for item in data.get("result", {}).get("tools", []):
                name = item.get("name") if isinstance(item, dict) else None
                if name:
                    tools.append(name)
            return tools
    except Exception as e:
        logger.error("list_available_tools failed: %s", e)
        return []


async def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt") -> str:
    """Directory enumeration via Kali container."""
    return await execute_command(f"gobuster dir -u {url} -w {wordlist} -t 30 -q")


async def nikto_scan(url: str) -> str:
    """Web vuln scan via Kali container."""
    return await execute_command(f"nikto -h {url} -maxtime 120s")


async def whatweb_scan(url: str) -> str:
    """Web tech detection via Kali container."""
    return await execute_command(f"whatweb -a 3 {url}")
