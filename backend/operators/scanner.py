"""
Scanner Operator — Phase 2 of the Swarm pipeline.
Runs vulnerability scanners (nikto, wpscan, nuclei) based on recon findings.
"""

import json
import re
from .base import BaseOperator


class ScannerOperator(BaseOperator):
    """Vulnerability scanning: runs appropriate scanners based on recon findings."""

    def __init__(self):
        super().__init__("scanner", "🛡️ Vulnerability Scanner")

    async def run(self, swarm) -> list:
        self.status = "running"
        target = swarm.target
        recon_findings = swarm.get_operator_findings("recon")
        findings = []

        # Detect services from recon findings
        open_ports = set()
        has_http = False
        has_wordpress = False
        for f in recon_findings:
            port = f.get("port", "")
            if port:
                open_ports.add(port.split("/")[0])
            title = (f.get("title", "") + " " + f.get("detail", "")).lower()
            if "http" in title or "80" in port or "443" in port or "8080" in port or "8443" in port:
                has_http = True
            if "wordpress" in title or "wp" in title:
                has_wordpress = True

        swarm.add_log(f"[scanner] Recon data: {len(open_ports)} ports, http={has_http}, wp={has_wordpress}")

        # ── 1. Nikto (if HTTP) ──
        if has_http:
            swarm.add_log("[scanner] Running nikto...")
            nikto_cmd = f"nikto -h {target} -ssl -Tuning 123456789 2>/dev/null | head -100"
            nikto_out = await self.exec(swarm, nikto_cmd, timeout=120)

            nikto_findings = self.parse_nikto_output(nikto_out)
            if not nikto_findings and nikto_out.strip() and "ERROR" not in nikto_out:
                # Raw output if parser fails
                self.add_finding(swarm, "nikto", "info",
                                 "Nikto scan raw output",
                                 nikto_out.strip()[:500], "80/443", "")
            else:
                for f in nikto_findings:
                    self.add_finding(swarm, f["tool"], f["severity"],
                                     f["title"], f["detail"], f["port"], f["path"])

            swarm.add_log(f"[scanner] nikto: {len(nikto_findings) or 'raw'} findings")

        # ── 2. WPScan (if WordPress detected) ──
        if has_wordpress:
            swarm.add_log("[scanner] WordPress detected — running wpscan...")
            wp_cmd = f"wpscan --url {target} --no-banner --disable-tls-checks 2>/dev/null | head -80"
            wp_out = await self.exec(swarm, wp_cmd, timeout=120)
            if wp_out.strip() and "ERROR" not in wp_out:
                # Extract vulnerabilities from wpscan output
                vuln_found = False
                for line in wp_out.split("\n"):
                    if any(kw in line.lower() for kw in ["[!]", "vulnerability", "critical", "high"]):
                        self.add_finding(swarm, "wpscan", "high",
                                         f"WordPress: {line.strip()[:120]}",
                                         line.strip()[:400], "80/443", "")
                        vuln_found = True
                if not vuln_found:
                    self.add_finding(swarm, "wpscan", "info",
                                     "WordPress scan complete — no obvious vulnerabilities",
                                     wp_out.strip()[:500], "80/443", "")

        # ── 3. Check for common vulnerable services ──
        vuln_services = {
            "21": ("FTP", "ftp anonymous login", "Anonymous FTP access may be enabled"),
            "23": ("Telnet", "telnet", "Telnet is unencrypted"),
            "445": ("SMB", "smb", "SMB may be exploitable via EternalBlue"),
            "3306": ("MySQL", "mysql default creds", "MySQL default credentials may work"),
            "3389": ("RDP", "rdp", "RDP may be vulnerable to BlueKeep"),
            "5900": ("VNC", "vnc no auth", "VNC may have no authentication"),
            "6379": ("Redis", "redis no auth", "Redis may have no authentication"),
            "27017": ("MongoDB", "mongo no auth", "MongoDB may have no authentication"),
        }

        for port, (name, tag, desc) in vuln_services.items():
            if port in open_ports:
                self.add_finding(swarm, "scanner", "medium",
                                 f"{name} (port {port}) — potential target",
                                 desc, port, "")

        # ── 4. Try nuclei for fast vuln detection ──
        swarm.add_log("[scanner] Running nuclei (quick scan)...")
        nuclei_cmd = f"nuclei -u {target} -severity low,medium,high,critical -json 2>/dev/null | tail -20"
        nuclei_out = await self.exec(swarm, nuclei_cmd, timeout=90)

        if nuclei_out.strip() and "ERROR" not in nuclei_out:
            # Try to parse JSON lines
            findings_added = 0
            for line in nuclei_out.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    sev = data.get("info", {}).get("severity", "medium")
                    name = data.get("info", {}).get("name", "Nuclei finding")
                    desc = data.get("matched-at", "") + " — " + (data.get("info", {}).get("description", "") or "")
                    self.add_finding(swarm, "nuclei", sev, name[:150], desc[:400])
                    findings_added += 1
                except (json.JSONDecodeError, Exception):
                    continue
            if findings_added == 0:
                self.add_finding(swarm, "nuclei", "info",
                                 "Nuclei scan output",
                                 nuclei_out.strip()[:500], "", "")

        self.status = "completed"
        swarm.add_log(f"[scanner] ✅ Complete — {len(self.findings)} findings")
        return self.findings
