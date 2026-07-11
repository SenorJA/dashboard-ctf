"""
Recon Operator — Phase 1 of the Swarm pipeline.
Runs nmap, whatweb, and DNS enumeration against the target.
"""

import re
from .base import BaseOperator


class ReconOperator(BaseOperator):
    """Initial reconnaissance: port scanning, web tech detection, DNS enumeration."""

    def __init__(self):
        super().__init__("recon", "🔍 Reconnaissance")
        self.scan_results = {}

    async def run(self, swarm) -> list:
        self.status = "running"
        target = swarm.target
        findings = []

        # ── Store the target as a finding ──
        self.add_finding(swarm, "swarm", "info",
                         f"Swarm target: {target}",
                         f"Starting swarm reconnaissance against {target}")

        # ── 1. Quick nmap scan ──
        swarm.add_log("[recon] Starting nmap scan...")
        nmap_cmd = f"nmap -sV -sC -T4 --min-rate=1000 {target} 2>/dev/null"
        nmap_out = await self.exec(swarm, nmap_cmd, timeout=120)

        nmap_findings = self.parse_nmap_output(nmap_out)
        for f in nmap_findings:
            self.add_finding(swarm, f["tool"], f["severity"],
                             f["title"], f["detail"], f["port"], f["path"])

        swarm.add_log(f"[recon] nmap: {len(nmap_findings)} findings")

        # ── 2. WhatWeb (if HTTP/HTTPS detected) ──
        has_web = any("http" in f.get("port", "").lower() or
                      f.get("title", "").lower().find("http") >= 0 or
                      f.get("detail", "").lower().find("80") >= 0 or
                      f.get("detail", "").lower().find("443") >= 0
                      for f in nmap_findings)

        if has_web:
            swarm.add_log("[recon] Web services detected — running whatweb...")
            whatweb_cmd = f"whatweb -a 1 {target} 2>/dev/null"
            whatweb_out = await self.exec(swarm, whatweb_cmd, timeout=60)

            ww_findings = self.parse_whatweb_output(whatweb_out)
            # If parser got nothing, add raw output as a finding
            if not ww_findings and whatweb_out.strip():
                self.add_finding(swarm, "whatweb", "info",
                                 "Web technologies (raw)",
                                 whatweb_out.strip()[:500], "80/443", "")
            else:
                for f in ww_findings:
                    self.add_finding(swarm, f["tool"], f["severity"],
                                     f["title"], f["detail"], f["port"], f["path"])

            swarm.add_log(f"[recon] whatweb: {len(ww_findings) or 'raw'} findings")
        else:
            swarm.add_log("[recon] No web services detected — skipping whatweb")

        # ── 3. DNS enumeration if target looks like a domain ──
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            swarm.add_log(f"[recon] Target appears to be a domain — running dnsrecon on {domain}...")
            dns_cmd = f"dnsrecon -d {domain} 2>/dev/null || host {domain} 2>/dev/null"
            dns_out = await self.exec(swarm, dns_cmd, timeout=30)
            if dns_out.strip() and "ERROR" not in dns_out:
                self.add_finding(swarm, "dnsrecon", "info",
                                 f"DNS records for {domain}",
                                 dns_out.strip()[:500], "", "")

        # ── 4. Quick directory discovery (if HTTP/HTTPS) ──
        if has_web:
            swarm.add_log("[recon] Running quick directory discovery with feroxbuster...")
            # Try dirb as fallback (more commonly available)
            dir_cmd = f"dirb http://{target} /usr/share/wordlists/dirb/common.txt 2>/dev/null | head -50"
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                dir_cmd = f"dirb http://{target} /usr/share/wordlists/dirb/common.txt 2>/dev/null | head -50"
            else:
                dir_cmd = f"dirb https://{domain} /usr/share/wordlists/dirb/common.txt 2>/dev/null | head -50"

            dir_out = await self.exec(swarm, dir_cmd, timeout=90)
            # Parse dirb output for discovered directories
            for line in dir_out.split("\n"):
                if "+ http" in line.lower() and "code" in line.lower():
                    self.add_finding(swarm, "dirb", "info",
                                     f"Discovered: {line.strip()[:100]}",
                                     line.strip()[:300], "80/443", "")

        self.status = "completed"
        swarm.add_log(f"[recon] ✅ Complete — {len(self.findings)} findings")
        return self.findings
