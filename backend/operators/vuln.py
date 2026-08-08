"""
Vuln Operator — Known vulnerability research and matching.

Leverages versions fingerprinted by earlier operators (web/recon/scanner) to
look up public exploits with searchsploit, runs the vulners NSE script against
web ports only (80/443/8080, IP targets), and a limited silent nuclei pass.

No destructive or mass scanning: nmap is restricted to three web ports.
"""

import json
import re
from typing import Dict, List, Set, Tuple

from .base import BaseOperator


class VulnOperator(BaseOperator):
    """Known-vuln research: searchsploit, nmap vulners, limited nuclei."""

    icon = "🧨"
    description = "Known vulnerability research and matching"

    # Tools probed in a single `command -v` round-trip before anything runs.
    TOOLS = ["searchsploit", "nmap", "nuclei", "curl"]

    # Only these ports are ever touched by nmap --script vulners (web ports).
    VULNERS_PORTS = "80,443,8080"

    def __init__(self) -> None:
        super().__init__("vuln", "🧨 Vuln Researcher")

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _cancel_requested(swarm) -> bool:
        return bool(getattr(swarm, "_cancel", False)) or bool(
            getattr(swarm, "_cancelled", False)
        )

    async def _check_tools(self, swarm, tools: List[str]) -> Set[str]:
        if not tools:
            return set()
        probe = "; ".join(
            f'command -v {t} >/dev/null 2>&1 && echo "{t}:yes" || echo "{t}:no"'
            for t in tools
        )
        out = await self.exec(swarm, probe, timeout=15)
        available = set()
        for line in out.split("\n"):
            m = re.match(r"^([^:]+):(yes|no)$", line.strip())
            if m and m.group(2) == "yes":
                available.add(m.group(1))
        return available

    @staticmethod
    def _tool_output_ok(output: str) -> bool:
        return bool(output.strip()) and not output.strip().startswith("ERROR:")

    @staticmethod
    def _is_ip(target: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))

    def _collect_versions(self, swarm) -> Dict[str, Set[str]]:
        """
        Harvest (service/product → versions) from earlier operator findings.

        Sources: web, recon, scanner operators (already run in the pipeline).
        """
        versions: Dict[str, Set[str]] = {}
        for f in swarm.get_all_findings():
            text = (f.get("title", "") + " " + f.get("detail", "")).lower()
            # Product:version patterns, e.g. Apache/2.4.41, nginx 1.18.0,
            # OpenSSH 8.9p1, PHP 7.4.3, WordPress 6.0.
            for m in re.finditer(
                r"(?P<prod>apache|nginx|iis|openssh|ssh|php|wordpress|mysql|"
                r"postgresql|redis|tomcat|vsftpd|proftpd|drupal|joomla|"
                r"exim|bind|openssl|gitlab|grafana|jenkins|jupyter)[a-z0-9_\-]*"
                r"[/\s]*(?P<ver>v?\d+\.\d+(?:\.\d+)?[a-z0-9\-]*)",
                text,
            ):
                prod = m.group("prod")
                versions.setdefault(prod, set()).add(m.group("ver"))
        return versions

    def _pick_web_protocol(self, swarm, host: str) -> str:
        for f in swarm.get_operator_findings("recon"):
            port = f.get("port", "")
            if port.startswith("80"):
                return "http"
            if port.startswith("443") or port.startswith("8443"):
                return "https"
        return "https"

    # ── Parsers ────────────────────────────────────────────────────────

    def _parse_vulners(self, out: str) -> List[dict]:
        """Parse nmap --script vulners output into CVE finding dicts."""
        findings = []
        current_port = ""
        for line in out.split("\n"):
            port_match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
            if port_match:
                current_port = f"{port_match.group(1)}/tcp"
                continue
            m = re.match(r"^\|\s+(CVE-\d{4}-\d+)\s+(\S+)\s+([\d.]+)\s+", line)
            if m:
                cve, link, score = m.group(1), m.group(2), m.group(3)
                try:
                    cvss = float(score)
                except ValueError:
                    cvss = 0.0
                sev = "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
                findings.append({
                    "tool": "nmap",
                    "severity": sev,
                    "title": f"{cve} — CVSS {score}",
                    "detail": f"{cve} on {current_port} ({link}). NVD: "
                              f"https://nvd.nist.gov/vuln/detail/{cve}",
                    "port": current_port,
                    "path": "",
                })
        return findings

    def _parse_nuclei(self, out: str) -> List[dict]:
        """Parse `nuclei -silent` output lines into finding dicts."""
        findings = []
        for line in out.split("\n"):
            line = line.strip()
            if not line or line.startswith("ERROR:"):
                continue
            # Lines look like: [http-missing-security-headers] [low] url
            m = re.match(r"^\[([^\]]+)\]\s*\[([^\]]+)\]\s+(\S+)", line)
            if m:
                name, sev, matched = m.group(1), m.group(2).lower(), m.group(3)
                if sev not in ("low", "medium", "high", "critical", "info"):
                    sev = "medium"
                findings.append({
                    "tool": "nuclei",
                    "severity": sev,
                    "title": f"Nuclei: {name[:120]}",
                    "detail": f"{name} matched at {matched}",
                    "port": "80/443",
                    "path": "",
                })
        return findings

    # ── Main entry point ───────────────────────────────────────────────

    async def run(self, swarm) -> list:
        self.status = "running"
        target = swarm.target
        host = target.strip().lower()
        host = host.replace("http://", "").replace("https://", "")
        host = host.split("/")[0].split(":")[0].rstrip(".")
        is_ip = self._is_ip(host)

        versions = self._collect_versions(swarm)
        swarm.add_log(f"[vuln] Versions detected by prior operators: {versions or 'none'}")

        try:
            available = await self._check_tools(swarm, self.TOOLS)
        except Exception as e:
            swarm.add_log(f"[vuln] ⚠ Tool probe failed: {e}")
            available = set()
        swarm.add_log(f"[vuln] Available tools: {sorted(available) or 'none'}")

        # ── 1. searchsploit on fingerprinted versions ──
        if "searchsploit" in available and versions:
            searched = 0
            for prod in sorted(versions)[:5]:
                for ver in sorted(versions[prod])[:3]:
                    if self._cancel_requested(swarm):
                        return self._finish(swarm)
                    searched += 1
                    term = f"{prod} {ver}"
                    swarm.add_log(f"[vuln] searchsploit {term}...")
                    out = await self.exec(
                        swarm,
                        f"searchsploit {term} 2>/dev/null | head -30",
                        timeout=30,
                    )
                    sploit_findings = self.parse_searchsploit_output(out)
                    if sploit_findings:
                        for f in sploit_findings:
                            self.add_finding(swarm, f["tool"], f["severity"],
                                             f["title"], f["detail"], f["port"], f["path"])
                        swarm.add_log(
                            f"[vuln] searchsploit ({term}): {len(sploit_findings)} exploits"
                        )
                    else:
                        self.add_finding(
                            swarm, "searchsploit", "info",
                            f"No public exploits for {term}",
                            f"searchsploit returned no direct matches for {term}.",
                            "", "",
                        )
            swarm.add_log(f"[vuln] searchsploit: {searched} version queries executed")

        # ── 2. nmap --script vulners (web ports only, IP targets) ──
        if "nmap" in available and is_ip:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log(
                f"[vuln] Running nmap --script vulners on ports {self.VULNERS_PORTS}..."
            )
            out = await self.exec(
                swarm,
                f"nmap -sV --script vulners -p {self.VULNERS_PORTS} "
                f"{host} 2>/dev/null | head -120",
                timeout=120,
            )
            if self._tool_output_ok(out):
                vuln_findings = self._parse_vulners(out)
                for f in vuln_findings:
                    self.add_finding(swarm, f["tool"], f["severity"],
                                     f["title"], f["detail"], f["port"], f["path"])
                swarm.add_log(f"[vuln] nmap vulners: {len(vuln_findings)} CVEs matched")

        # ── 3. nuclei (limited, silent) ──
        if "nuclei" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            protocol = self._pick_web_protocol(swarm, host)
            url = f"{protocol}://{host}/"
            swarm.add_log("[vuln] Running nuclei (limited silent scan)...")
            out = await self.exec(
                swarm,
                f"nuclei -u {url} -silent -severity low,medium,high,critical "
                f"-headless-opt 0 2>/dev/null | head -40",
                timeout=90,
            )
            if self._tool_output_ok(out):
                nuc_findings = self._parse_nuclei(out)
                for f in nuc_findings:
                    self.add_finding(swarm, f["tool"], f["severity"],
                                     f["title"], f["detail"], f["port"], f["path"])
                if not nuc_findings:
                    self.add_finding(
                        swarm, "nuclei", "info",
                        "Nuclei scan completed — no template matches",
                        f"nuclei -silent found no matches for {url}.",
                        "80/443", "",
                    )
                swarm.add_log(f"[vuln] nuclei: {len(nuc_findings)} matches")

        # ── 4. Summary finding ──
        high = [f for f in self.findings if f.get("severity") in ("high", "critical")]
        medium = [f for f in self.findings if f.get("severity") == "medium"]
        if high or medium:
            self.add_finding(
                swarm, "vuln",
                "high" if high else "medium",
                f"Vuln research summary: {len(high)} high, {len(medium)} medium",
                f"Target {target} has {len(high)} high/critical and {len(medium)} "
                f"medium-severity known-vulnerability matches. Prioritise manual "
                f"verification of high-severity CVEs before exploitation.",
                "", "",
            )

        return self._finish(swarm)

    def _finish(self, swarm) -> list:
        self.status = "completed"
        swarm.add_log(f"[vuln] ✅ Complete — {len(self.findings)} findings")
        return self.findings
