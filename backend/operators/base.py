"""
Base operator for the VulnForge Swarm.
Each operator runs a specific phase of the attack pipeline.
"""

import re
import json
from datetime import datetime


class BaseOperator:
    """Base class for all swarm operators."""

    def __init__(self, name: str, display_name: str):
        self.name = name
        self.display_name = display_name
        self.status = "pending"  # pending | running | completed | error
        self.commands_run = []
        self.findings = []
        self.error = None

    async def run(self, swarm) -> list:
        """
        Execute this operator's phase.
        Must be overridden by subclasses.
        Returns a list of findings dicts.
        """
        raise NotImplementedError

    async def exec(self, swarm, command: str, timeout: int = 60) -> str:
        """Execute a command via SSH and return full stdout+stderr."""
        self.commands_run.append(command)
        swarm.add_log(f"[{self.name}] $ {command}")
        try:
            stdin, stdout, stderr = await swarm.exec_command(command, timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            full = out + ("\n" + err if err else "")
            if len(full) > 50000:
                full = full[:50000] + "\n[... TRUNCATED ...]"
            return full
        except Exception as e:
            swarm.add_log(f"[{self.name}] ⚠ Command error: {e}")
            return f"ERROR: {e}"

    def add_finding(self, swarm, tool: str, severity: str, title: str,
                    detail: str = "", port: str = "", path: str = "",
                    extra: dict = None):
        """Create a structured finding and add it to the store."""
        finding = {
            "tool": tool,
            "severity": severity,
            "title": title,
            "detail": detail,
            "port": port,
            "path": path,
            "target": swarm.target,
            "extra": extra or {},
            "source": f"swarm:{self.name}",
            "created_at": datetime.utcnow().isoformat(),
        }
        self.findings.append(finding)
        swarm.add_finding(finding)
        swarm.add_log(f"[{self.name}] ✓ Finding: {title}")
        return finding

    def parse_nmap_output(self, output: str) -> list:
        """Parse nmap output into findings."""
        findings = []
        current_port = ""
        current_service = ""

        for line in output.split("\n"):
            # Detect port lines like "22/tcp   open  ssh     OpenSSH 8.9p1"
            port_match = re.match(
                r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$", line
            )
            if port_match:
                port = port_match.group(1)
                proto = port_match.group(2)
                service = port_match.group(3)
                version = port_match.group(4).strip()
                current_port = f"{port}/{proto}"
                current_service = service

                # Determine severity based on service
                sev = "info"
                risky_services = ["ssh", "telnet", "ftp", "smtp", "rdp", "vnc",
                                  "ms-sql-s", "mysql", "postgresql", "redis",
                                  "mongodb", "elasticsearch"]
                if service.lower() in risky_services:
                    sev = "medium"
                if "http" in service.lower():
                    sev = "medium"

                findings.append({
                    "tool": "nmap",
                    "severity": sev,
                    "title": f"Open port: {port}/{proto} — {service}",
                    "detail": version,
                    "port": current_port,
                    "path": "",
                })

            # OS detection
            os_match = re.search(r"OS details:\s*(.+?)(?:\n|$)", output)
            if os_match:
                findings.append({
                    "tool": "nmap",
                    "severity": "info",
                    "title": f"OS detected: {os_match.group(1).strip()}",
                    "detail": os_match.group(1).strip(),
                    "port": "",
                    "path": "",
                })

        return findings

    def parse_whatweb_output(self, output: str) -> list:
        """Parse WhatWeb output into findings."""
        findings = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("WhatWeb") or line.startswith("Report"):
                continue
            # Look for "http://..." or "https://..." lines
            if line.startswith("http://") or line.startswith("https://"):
                # Extract technologies after the URL
                parts = line.split(", ", 1)
                if len(parts) > 1:
                    techs = parts[1]
                    findings.append({
                        "tool": "whatweb",
                        "severity": "info",
                        "title": "Web technologies detected",
                        "detail": techs[:300],
                        "port": "80/443",
                        "path": "",
                    })
        return findings

    def parse_nikto_output(self, output: str) -> list:
        """Parse Nikto output into findings."""
        findings = []
        for line in output.split("\n"):
            # Nikto findings typically start with "+ "
            if line.startswith("+ "):
                content = line[2:].strip()
                # Determine severity
                sev = "medium"
                low_risk = ["cookie", "warning", "info", "allowed"]
                high_risk = ["vulnerable", "exploit", "directory listing",
                             "backdoor", "shell", "upload"]
                if any(kw in content.lower() for kw in high_risk):
                    sev = "high"
                elif any(kw in content.lower() for kw in low_risk):
                    sev = "low"

                findings.append({
                    "tool": "nikto",
                    "severity": sev,
                    "title": content[:120],
                    "detail": content[:500],
                    "port": "80/443",
                    "path": "",
                })
        return findings

    def parse_searchsploit_output(self, output: str) -> list:
        """Parse searchsploit output into findings."""
        findings = []
        # searchsploit output has a table with | separators
        lines = output.split("\n")
        header_found = False
        for line in lines:
            if "----" in line and "-------" in line:
                header_found = True
                continue
            if header_found and line.strip() and "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    exploit_path = parts[0]
                    title = parts[1] if len(parts) > 1 else ""
                    findings.append({
                        "tool": "searchsploit",
                        "severity": "high",
                        "title": f"Exploit: {title[:100]}",
                        "detail": f"Path: {exploit_path} — {title}",
                        "port": "",
                        "path": "",
                    })
        return findings
