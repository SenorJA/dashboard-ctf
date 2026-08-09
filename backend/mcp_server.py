#!/usr/bin/env python3
"""
VulnForge — MCP Server (Model Context Protocol)

Exposes VulnForge's security tools as MCP tools for AI agents
(Claude Code, Cursor, Cline, etc.)

Protocol: JSON-RPC 2.0 over stdio
Spec: https://modelcontextprotocol.io/

Usage:
    pip install mcp  (optional — uses manual JSON-RPC if not available)
    python backend/mcp_server.py

Environment:
    KALI_IP=192.168.214.142
    KALI_USER=javi
    KALI_PASS=javi
"""

import json
import os
import sys
import re
import asyncio
import logging
from datetime import datetime
from typing import Any

# ════════════════════════════════════════════════════════════════
#  TRY OFFICIAL MCP SDK FIRST
# ════════════════════════════════════════════════════════════════

try:
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
    from mcp.types import (
        Tool,
        TextContent,
        CallToolResult,
        ListToolsResult,
    )
    HAS_MCP_SDK = True
except ImportError:
    HAS_MCP_SDK = False

# ════════════════════════════════════════════════════════════════
#  SSH CONNECTION (shared with swarm.py pattern)
# ════════════════════════════════════════════════════════════════

import paramiko

_ssh_client = None
_ssh_lock = asyncio.Lock()

KALI_IP = os.getenv("KALI_IP", "192.168.214.142")
KALI_USER = os.getenv("KALI_USER", "javi")
KALI_PASS = os.getenv("KALI_PASS", "javi")
KALI_PORT = int(os.getenv("KALI_PORT", "22"))


async def get_ssh():
    """Get or create SSH connection (lazy, singleton)."""
    global _ssh_client
    async with _ssh_lock:
        if _ssh_client is None or not _ssh_client.get_transport() or not _ssh_client.get_transport().is_active():
            _ssh_client = paramiko.SSHClient()
            _ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            await asyncio.to_thread(
                _ssh_client.connect,
                KALI_IP,
                port=KALI_PORT,
                username=KALI_USER,
                password=KALI_PASS,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
    return _ssh_client


async def exec_command(command: str, timeout: int = 120) -> str:
    """Execute a command via SSH and return output."""
    ssh = await get_ssh()
    try:
        stdin, stdout, stderr = await asyncio.to_thread(
            ssh.exec_command, command, timeout=timeout
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        full = out + ("\n" + err if err else "")
        return full[:10000]  # Truncate for MCP response size
    except Exception as e:
        return f"ERROR: {e}"


def close_ssh():
    """Close SSH connection."""
    global _ssh_client
    if _ssh_client:
        try:
            _ssh_client.close()
        except Exception:
            pass
        _ssh_client = None


# ════════════════════════════════════════════════════════════════
#  TOOL DEFINITIONS
# ════════════════════════════════════════════════════════════════

TOOLS = [
    {
        "name": "vulnforge_recon",
        "description": "Full reconnaissance against a target: nmap port scan + service detection + whatweb technology fingerprinting + DNS enumeration",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or domain (e.g., 192.168.1.1 or example.com)",
                }
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnforge_port_scan",
        "description": "Quick port scan using nmap with service version detection",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or domain",
                },
                "ports": {
                    "type": "string",
                    "description": "Port range to scan (e.g., '1-1000', '22,80,443', or empty for top 1000)",
                    "default": "",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnforge_web_scan",
        "description": "Web vulnerability scan: nikto + directory busting (dirb) + nuclei (if available)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or IP (e.g., http://example.com or 192.168.1.1)",
                },
                "use_ssl": {
                    "type": "boolean",
                    "description": "Use HTTPS instead of HTTP",
                    "default": False,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnforge_exploit_search",
        "description": "Search for public exploits matching a service and version using searchsploit",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name (e.g., 'apache', 'openssh', 'nginx', 'mysql')",
                },
                "version": {
                    "type": "string",
                    "description": "Version number (e.g., '2.4.49', '8.9p1'). Optional but recommended.",
                    "default": "",
                },
            },
            "required": ["service"],
        },
    },
    {
        "name": "vulnforge_scope_check",
        "description": "Check if a target is within the allowed scope for testing",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP or domain to validate",
                }
            },
            "required": ["target"],
        },
    },
    {
        "name": "vulnforge_run_command",
        "description": "Execute a security tool command on Kali Linux and return the output. Only use for authorized security testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Full command to execute (e.g., 'nmap -sV 192.168.1.1', 'whois example.com')",
                },
                "timeout": {
                    "type": "number",
                    "description": "Command timeout in seconds (max 300)",
                    "default": 60,
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "vulnforge_findings_list",
        "description": "List all findings discovered during the current session, optionally filtered by severity or tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info", ""],
                    "description": "Filter by severity level (empty = all)",
                    "default": "",
                },
                "tool": {
                    "type": "string",
                    "description": "Filter by tool name (e.g., 'nmap', 'nikto')",
                    "default": "",
                },
            },
        },
    },
    {
        "name": "vulnforge_browser_import",
        "description": "Import a full HAR 1.2 JSON capture into the in-memory browser traffic store and create a session for later analysis",
        "inputSchema": {
            "type": "object",
            "properties": {
                "har_content": {
                    "type": "string",
                    "description": "Full HAR JSON as a string (log.version 1.x, log.entries[] with request/response pairs)",
                },
                "filename": {
                    "type": "string",
                    "description": "Original filename used to name the session",
                    "default": "har_capture.har",
                },
            },
            "required": ["har_content"],
        },
    },
    {
        "name": "vulnforge_browser_list_sessions",
        "description": "List browser capture sessions (id, name, target, request count, analysis status, created_at)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max sessions to return",
                    "default": 50,
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset",
                    "default": 0,
                },
            },
        },
    },
    {
        "name": "vulnforge_browser_get_session",
        "description": "Get a single browser capture session by id (metadata, request count, analysis status)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Browser capture session id",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "vulnforge_browser_analyze",
        "description": "Run the 10-check security analysis on a browser capture session and register each issue as a session finding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Browser capture session id to analyze",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "vulnforge_browser_get_analysis",
        "description": "Get the full stored security analysis for a browser capture session (issues with check_id/severity/detail, categories, risk score, recommendations)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Browser capture session id (must be analyzed first)",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "vulnforge_browser_create_findings",
        "description": "Convert the security issues of an analyzed browser capture session into MIRV session findings (browser-capture tool)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Browser capture session id (must be analyzed first)",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "vulnforge_browser_stats",
        "description": "Get in-memory browser capture store statistics (sessions, total requests, analyses, limits)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "verbose": {
                    "type": "boolean",
                    "description": "Include store limits (max sessions, max body) in the output",
                    "default": True,
                },
            },
        },
    },
]

# In-memory findings store (accumulated during the MCP session)
_session_findings = []


# ════════════════════════════════════════════════════════════════
#  TOOL HANDLERS
# ════════════════════════════════════════════════════════════════

async def handle_tool_call(name: str, arguments: dict) -> str:
    """Route tool calls to their handlers."""
    handlers = {
        "vulnforge_recon": _tool_recon,
        "vulnforge_port_scan": _tool_port_scan,
        "vulnforge_web_scan": _tool_web_scan,
        "vulnforge_exploit_search": _tool_exploit_search,
        "vulnforge_scope_check": _tool_scope_check,
        "vulnforge_run_command": _tool_run_command,
        "vulnforge_findings_list": _tool_findings_list,
        "vulnforge_browser_import": _tool_browser_import,
        "vulnforge_browser_list_sessions": _tool_browser_list_sessions,
        "vulnforge_browser_get_session": _tool_browser_get_session,
        "vulnforge_browser_analyze": _tool_browser_analyze,
        "vulnforge_browser_get_analysis": _tool_browser_get_analysis,
        "vulnforge_browser_create_findings": _tool_browser_create_findings,
        "vulnforge_browser_stats": _tool_browser_stats,
    }
    handler = handlers.get(name)
    if not handler:
        return f"Unknown tool: {name}"
    return await handler(arguments)


def _add_finding(tool: str, severity: str, title: str, detail: str = "", target: str = ""):
    """Store a finding in the session."""
    _session_findings.append({
        "tool": tool,
        "severity": severity,
        "title": title,
        "detail": detail[:500],
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
    })


async def _tool_recon(args: dict) -> str:
    """Full recon: nmap + whatweb + DNS."""
    target = args["target"]
    output_parts = [f"🔍 Reconnaissance against {target}", "=" * 40, ""]

    # Step 1: nmap scan
    output_parts.append("[*] Running nmap port scan...")
    nmap_cmd = f"nmap -sV -sC -T4 --min-rate=1000 {target} 2>/dev/null"
    nmap_out = await exec_command(nmap_cmd, timeout=180)
    output_parts.append(nmap_out[:3000])
    output_parts.append("")

    # Parse ports for findings
    for line in nmap_out.split("\n"):
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$", line)
        if m:
            _add_finding("nmap", "medium" if m.group(3).lower() in ("ssh", "telnet", "ftp") else "info",
                         f"Open port {m.group(1)}/{m.group(2)}: {m.group(3)}",
                         m.group(4).strip(), target)

    # Step 2: whatweb (if HTTP/HTTPS likely)
    output_parts.append("[*] Running whatweb (technology detection)...")
    web_cmd = f"whatweb -a 1 {target} 2>/dev/null"
    web_out = await exec_command(web_cmd, timeout=60)
    if web_out.strip() and "ERROR" not in web_out:
        output_parts.append(web_out[:2000])
        _add_finding("whatweb", "info", f"Web technologies: {web_out.strip()[:200]}", web_out.strip()[:500], target)
    else:
        output_parts.append("(no web technologies detected)")
    output_parts.append("")

    # Step 3: DNS if domain
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        domain = target.split("/")[0]
        output_parts.append(f"[*] Running DNS enumeration on {domain}...")
        dns_cmd = f"host {domain} 2>/dev/null || nslookup {domain} 2>/dev/null"
        dns_out = await exec_command(dns_cmd, timeout=30)
        if dns_out.strip():
            output_parts.append(dns_out[:2000])
            _add_finding("dns", "info", f"DNS records for {domain}", dns_out.strip()[:300], target)

    output_parts.append(f"\n✅ Recon complete. Found {sum(1 for f in _session_findings if f['tool'] in ('nmap', 'whatweb', 'dns'))} findings.")
    return "\n".join(output_parts)


async def _tool_port_scan(args: dict) -> str:
    """Port scan with nmap."""
    target = args["target"]
    ports = args.get("ports", "")
    output_parts = [f"🔌 Port scan: {target}", "=" * 40, ""]

    if ports:
        cmd = f"nmap -sV -p{ports} -T4 {target} 2>/dev/null"
    else:
        cmd = f"nmap -sV --top-ports 1000 -T4 {target} 2>/dev/null"

    output_parts.append(f"$ {cmd}")
    output = await exec_command(cmd, timeout=180)
    output_parts.append(output[:5000])

    # Parse findings
    for line in output.split("\n"):
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$", line)
        if m:
            _add_finding("nmap", "info",
                         f"Port {m.group(1)}/{m.group(2)}: {m.group(3)}",
                         m.group(4).strip(), target)

    return "\n".join(output_parts)


async def _tool_web_scan(args: dict) -> str:
    """Web vulnerability scan."""
    target = args["target"]
    use_ssl = args.get("use_ssl", False)
    protocol = "https" if use_ssl else "http"
    output_parts = [f"🕸️ Web scan: {protocol}://{target}", "=" * 40, ""]

    # nikto
    output_parts.append("[*] Running nikto...")
    nikto_cmd = f"nikto -h {protocol}://{target} -ssl -Tuning 123456789 2>/dev/null | head -80"
    nikto_out = await exec_command(nikto_cmd, timeout=120)
    output_parts.append(nikto_out[:3000])

    for line in nikto_out.split("\n"):
        if line.startswith("+ "):
            _add_finding("nikto", "medium", line[2:].strip()[:150], line[2:].strip()[:400], target)

    output_parts.append("")

    # dirb
    output_parts.append("[*] Running directory busting (dirb)...")
    dirb_cmd = f"dirb {protocol}://{target} /usr/share/wordlists/dirb/common.txt 2>/dev/null | head -40"
    dirb_out = await exec_command(dirb_cmd, timeout=90)
    output_parts.append(dirb_out[:2000])

    for line in dirb_out.split("\n"):
        if "+ http" in line.lower() and "code" in line.lower():
            _add_finding("dirb", "info", f"Directory discovered: {line.strip()[:100]}", line.strip()[:300], target)

    output_parts.append(f"\n✅ Web scan complete.")
    return "\n".join(output_parts)


async def _tool_exploit_search(args: dict) -> str:
    """Search for exploits using searchsploit."""
    service = args["service"]
    version = args.get("version", "")
    output_parts = [f"💥 Exploit search: {service} {version}", "=" * 40, ""]

    search_term = f"{service} {version}".strip()
    cmd = f"searchsploit {search_term} 2>/dev/null | head -40"
    output_parts.append(f"$ {cmd}")
    output = await exec_command(cmd, timeout=30)
    output_parts.append(output[:4000])

    # Parse results
    lines = output.split("\n")
    header_found = False
    exploit_count = 0
    for line in lines:
        if "----" in line and "-------" in line:
            header_found = True
            continue
        if header_found and line.strip() and "|" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3:
                exploit_count += 1
                _add_finding("searchsploit", "high",
                             f"Exploit: {parts[1][:100] if len(parts) > 1 else line[:100]}",
                             f"Path: {parts[0]}", service)

    if exploit_count == 0:
        output_parts.append("\nℹ️ No public exploits found for this service/version.")
    else:
        output_parts.append(f"\n✅ Found {exploit_count} potential exploits.")

    return "\n".join(output_parts)


async def _tool_scope_check(args: dict) -> str:
    """Check if target is in scope."""
    target = args["target"]
    try:
        from backend.scope_guard import is_in_scope
        in_scope = is_in_scope(target)
        if in_scope:
            return f"✅ {target} is IN SCOPE — authorized for testing."
        else:
            return f"🔒 {target} is OUT OF SCOPE — do not test without authorization."
    except Exception:
        return f"⚠️ Scope guard not available. Ensure {target} is authorized before testing."


async def _tool_run_command(args: dict) -> str:
    """Execute an arbitrary security tool command."""
    command = args["command"]
    timeout = min(int(args.get("timeout", 60)), 300)

    # Basic safety: reject destructive commands
    dangerous = ["rm -rf", "dd if=", "mkfs.", "format", "> /dev/", "wireless", "airodump"]
    for d in dangerous:
        if d in command.lower():
            return f"🔒 BLOCKED: Command contains dangerous pattern: '{d}'"

    output_parts = [f"$ {command}", "=" * 40, ""]
    output = await exec_command(command, timeout)
    output_parts.append(output[:8000])

    return "\n".join(output_parts)


async def _tool_findings_list(args: dict) -> str:
    """List accumulated findings."""
    severity_filter = args.get("severity", "")
    tool_filter = args.get("tool", "")

    filtered = _session_findings
    if severity_filter:
        filtered = [f for f in filtered if f["severity"] == severity_filter]
    if tool_filter:
        filtered = [f for f in filtered if f["tool"] == tool_filter]

    if not filtered:
        return "No findings yet. Run a recon or scan tool first."

    output_parts = [f"📊 Findings: {len(filtered)} total", "=" * 40, ""]
    for i, f in enumerate(filtered, 1):
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(
            f["severity"], "ℹ️"
        )
        output_parts.append(f"{sev_icon} [{f['severity'].upper()}] {f['tool']}: {f['title']}")
        if f.get("detail"):
            output_parts.append(f"   {f['detail'][:200]}")

    return "\n".join(output_parts)


# ════════════════════════════════════════════════════════════════
#  BROWSER CAPTURE TOOLS (HAR import / analysis / findings)
# ════════════════════════════════════════════════════════════════

async def _tool_browser_import(args: dict) -> str:
    """Import a HAR capture into the browser capture store."""
    from backend import browser_capture

    har_content = args.get("har_content", "")
    filename = args.get("filename", "har_capture.har")

    try:
        result = browser_capture.import_har(har_content.encode("utf-8"), filename)
    except Exception as e:
        return f"❌ Import failed: {e}"

    if not result.get("ok"):
        return f"❌ Import failed: {result.get('error', 'unknown error')}"

    session = result.get("session", {})
    output_parts = [
        "📥 HAR imported",
        "=" * 40,
        f"session_id:  {session.get('id', '')}",
        f"target:      {session.get('target', 'unknown')}",
        f"requests:    {session.get('request_count', 0)}",
        f"har_version: {session.get('har_version', '')}",
    ]
    return "\n".join(output_parts)


async def _tool_browser_list_sessions(args: dict) -> str:
    """List browser capture sessions."""
    from backend import browser_capture

    limit = int(args.get("limit", 50))
    offset = int(args.get("offset", 0))

    try:
        sessions = browser_capture.list_sessions(limit, offset)
    except Exception as e:
        return f"❌ Error listing sessions: {e}"

    if not sessions:
        return "(no sessions)"

    output_parts = [f"📥 Browser sessions ({len(sessions)} shown)", "=" * 40]
    for s in sessions:
        status = "analyzed" if s.get("analysis") else "not analyzed"
        output_parts.append(
            f"- id={s.get('id', '')} | {s.get('name', '')} | target={s.get('target', '')} "
            f"| {s.get('request_count', 0)} reqs | {status} | {s.get('created_at', '')}"
        )
    return "\n".join(output_parts)


async def _tool_browser_get_session(args: dict) -> str:
    """Get a single browser capture session by id."""
    from backend import browser_capture

    session_id = args.get("session_id", "")

    try:
        session = browser_capture.get_session(session_id)
    except Exception as e:
        return f"❌ Error getting session: {e}"

    if session is None:
        return f"Session not found: {session_id}"

    status = "analyzed" if session.get("analysis") else "not analyzed"
    output_parts = [
        f"📦 Session: {session_id}",
        "=" * 40,
        f"name:          {session.get('name', '')}",
        f"target:        {session.get('target', '')}",
        f"request_count: {session.get('request_count', 0)}",
        f"har_version:   {session.get('har_version', '')}",
        f"status:        {status}",
        f"created_at:    {session.get('created_at', '')}",
        f"tags:          {', '.join(session.get('tags', [])) or '-'}",
    ]
    return "\n".join(output_parts)


async def _tool_browser_analyze(args: dict) -> str:
    """Run the 10-check security analysis on a browser capture session."""
    from backend import browser_capture

    session_id = args.get("session_id", "")

    try:
        analysis = browser_capture.analyze_session(session_id)
    except Exception as e:
        return f"❌ Analysis failed: {e}"

    if analysis is None:
        return f"Session not found: {session_id}"

    # Register each issue as a session finding (reuses stored analysis if present)
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in analysis.security_issues:
        sev = issue.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        _add_finding(
            "browser-capture",
            sev,
            issue.get("title", "Security issue"),
            issue.get("detail", ""),
            issue.get("url", ""),
        )

    output_parts = [
        f"🔬 Analysis complete: {session_id}",
        "=" * 40,
        f"risk_score: {analysis.risk_score:.1f}",
        f"issues:     {len(analysis.security_issues)} total",
        f"  critical: {counts['critical']}",
        f"  high:     {counts['high']}",
        f"  medium:   {counts['medium']}",
        f"  low:      {counts['low']}",
        f"  info:     {counts['info']}",
    ]

    recs = analysis.recommendations or []
    if recs:
        output_parts.append("")
        output_parts.append("Top recommendations:")
        for i, rec in enumerate(recs[:5], 1):
            output_parts.append(f"  {i}. {rec}")

    return "\n".join(output_parts)[:4000]


async def _tool_browser_get_analysis(args: dict) -> str:
    """Get the full stored security analysis for a browser capture session."""
    from backend import browser_capture

    session_id = args.get("session_id", "")

    try:
        session = browser_capture.get_session(session_id)
    except Exception as e:
        return f"❌ Error getting analysis: {e}"

    if session is None:
        return f"Session not found: {session_id}"

    analysis = session.get("analysis")
    if not analysis:
        return (
            f"No analysis found for session {session_id}. "
            "Call vulnforge_browser_analyze first."
        )

    output_parts = [
        f"📋 Analysis: {session_id}",
        "=" * 40,
        f"session_id:     {analysis.get('session_id', session_id)}",
        f"analyzed_at:    {analysis.get('analyzed_at', '')}",
        f"total_requests: {analysis.get('total_requests', 0)}",
        f"risk_score:     {analysis.get('risk_score', 0.0)}",
        f"findings_count: {analysis.get('findings_count', {})}",
    ]

    # Category buckets (non-empty only)
    category_buckets = [
        ("mixed_content", "mixed_content"),
        ("sensitive_in_urls", "sensitive_urls"),
        ("insecure_redirects", "insecure_redirects"),
        ("missing_auth", "missing_auth"),
        ("cors_issues", "cors"),
        ("info_leakage", "info_leakage"),
        ("large_responses", "large_responses"),
        ("websocket_issues", "websocket"),
    ]
    categories = []
    for key, label in category_buckets:
        bucket = analysis.get(key) or []
        if bucket:
            categories.append(f"{label}={len(bucket)}")
    if categories:
        output_parts.append(f"categories:     {', '.join(categories)}")

    output_parts.append("")
    issues = analysis.get("security_issues", [])
    if issues:
        output_parts.append(f"Security issues ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            output_parts.append(
                f"  {i}. [{issue.get('severity', 'info').upper()}] {issue.get('title', '')}"
            )
            output_parts.append(f"     check_id: {issue.get('check_id', '')}")
            output_parts.append(f"     url:      {issue.get('url', '')}")
            output_parts.append(f"     detail:   {issue.get('detail', '')}")
            output_parts.append(f"     fix:      {issue.get('recommendation', '')}")
    else:
        output_parts.append("No security issues detected.")

    recs = analysis.get("recommendations", [])
    if recs:
        output_parts.append("")
        output_parts.append("Recommendations:")
        for i, rec in enumerate(recs, 1):
            output_parts.append(f"  {i}. {rec}")

    return "\n".join(output_parts)[:6000]


async def _tool_browser_create_findings(args: dict) -> str:
    """Convert analyzed browser capture issues into MIRV session findings."""
    from backend import browser_capture

    session_id = args.get("session_id", "")

    try:
        session = browser_capture.get_session(session_id)
    except Exception as e:
        return f"❌ Error: {e}"

    if session is None:
        return f"Session not found: {session_id}"

    if not session.get("analysis"):
        return (
            f"No analysis found for session {session_id}. "
            "Call vulnforge_browser_analyze first."
        )

    analysis = browser_capture.analyze_session(session_id)
    if analysis is None:
        return f"Session not found: {session_id}"

    findings = browser_capture.report_to_mirv_findings(analysis)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        _add_finding(
            f["tool"],
            f["severity"],
            f["title"],
            f["detail"],
            f["target"],
        )

    output_parts = [
        f"🧩 Findings created: {len(findings)} total",
        "=" * 40,
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            output_parts.append(f"  {sev}: {counts[sev]}")
    return "\n".join(output_parts)


async def _tool_browser_stats(args: dict) -> str:
    """Get browser capture store statistics."""
    from backend import browser_capture

    try:
        st = browser_capture.status()
    except Exception as e:
        return f"❌ Error getting stats: {e}"

    output_parts = [
        "📊 Browser capture stats",
        "=" * 40,
        f"sessions:            {st.get('sessions', 0)}",
        f"total_requests:      {st.get('total_requests', 0)}",
        f"analyses:            {st.get('analyses', 0)}",
    ]
    if args.get("verbose", True):
        output_parts.append(f"max_sessions:        {st.get('max_sessions', 0)}")
        output_parts.append(f"max_requests/session:{st.get('max_requests_per_session', 0)}")
        output_parts.append(f"max_body:            {st.get('max_body', 0)}")
    return "\n".join(output_parts)


# ════════════════════════════════════════════════════════════════
#  MCP PROTOCOL (Manual JSON-RPC over stdio)
# ════════════════════════════════════════════════════════════════

SERVER_INFO = {
    "name": "vulnforge-mcp",
    "version": "1.0.0",
}

CAPABILITIES = {
    "tools": {},  # Signal that tools are supported
}


async def handle_message(msg: dict) -> dict | None:
    """Process a single JSON-RPC message."""
    msg_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params", {})

    # No id = notification (fire and forget)
    if msg_id is None:
        if method == "notifications/initialized":
            pass  # Client is ready
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": CAPABILITIES,
                "serverInfo": SERVER_INFO,
            },
        }

    elif method == "tools/list":
        # MCP spec: return { tools: [...] }
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS},
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        try:
            result_text = await handle_tool_call(tool_name, tool_args)
            # MCP spec: CallToolResult with content array
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text,
                        }
                    ],
                    "isError": False,
                },
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": f"Tool execution error: {e}",
                },
            }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    else:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }


async def main():
    """Main loop: read JSON-RPC from stdin, write to stdout."""
    # Log to stderr so we don't interfere with MCP stdio protocol
    logging.basicConfig(
        level=logging.INFO,
        format="[MCP] %(message)s",
        stream=sys.stderr,
    )
    log = logging.getLogger("mcp")

    log.info(f"VulnForge MCP Server v{SERVER_INFO['version']}")
    log.info(f"SSH target: {KALI_USER}@{KALI_IP}:{KALI_PORT}")
    log.info("Reading JSON-RPC from stdin...")

    # Ensure line-buffered stdout for MCP protocol
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    buffer = ""
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                log.info("stdin closed, shutting down")
                break

            buffer += line
            # Try to parse complete messages (MCP uses newline-delimited JSON)
            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break

                try:
                    msg, idx = json.JSONDecoder().raw_decode(buffer)
                    buffer = buffer[idx:].lstrip()
                except json.JSONDecodeError:
                    # Incomplete message, wait for more data
                    break

                result = await handle_message(msg)
                if result is not None:
                    response = json.dumps(result) + "\n"
                    sys.stdout.write(response)
                    sys.stdout.flush()

        except EOFError:
            break
        except Exception as e:
            log.error(f"Error: {e}")
            break

    close_ssh()
    log.info("MCP Server shut down")


if __name__ == "__main__":
    asyncio.run(main())
