"""
Web Operator — Web application fingerprinting and content discovery.

Runs whatweb, nikto, wafw00f, dirb/feroxbuster/gobuster (limited, dirb
common wordlist only) and curl header/robots.txt checks against the target.

Tolerance rule: if a tool is missing or fails, the operator logs it and
continues with the remaining tools — it never aborts the pipeline.
"""

import re
from typing import List, Set, Tuple

from .base import BaseOperator


class WebOperator(BaseOperator):
    """Web fingerprinting: tech stack, server, WAF, discovered paths, headers."""

    icon = "🕸️"
    description = "Web application fingerprinting and content discovery"

    # Tools probed in a single `command -v` round-trip before anything runs.
    TOOLS = ["whatweb", "nikto", "wafw00f", "dirb", "feroxbuster", "gobuster", "curl"]

    # Words that hint at juicy/risky paths worth flagging above plain info.
    RISKY_PATHS = (
        ".git", ".env", "backup", "admin", "phpmyadmin", "manager",
        "config", "shell", "upload", "api", "swagger", "console", "wp-admin",
    )

    def __init__(self) -> None:
        super().__init__("web", "🕸️ Web App Scanner")

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

    def _web_url(self, swarm, target: str) -> Tuple[str, str]:
        """Return (url, protocol) — https by default, http fallback via recon data."""
        host = target.strip().lower()
        host = host.replace("http://", "").replace("https://", "")
        host = host.split("/")[0].split(":")[0].rstrip(".")
        protocol = "https"
        for f in swarm.get_operator_findings("recon"):
            port = f.get("port", "")
            if port.startswith("80"):
                protocol = "http"
                break
            if port.startswith("443") or port.startswith("8443"):
                protocol = "https"
                break
        return f"{protocol}://{host}", protocol

    @staticmethod
    def _path_severity(path: str, status: str) -> str:
        """Classify a discovered path: risky → medium, else low/info."""
        pl = path.lower()
        if any(kw in pl for kw in WebOperator.RISKY_PATHS):
            return "medium"
        if status and status.startswith(("401", "403")):
            return "low"
        return "info"

    def _parse_dirb(self, out: str) -> List[Tuple[str, str, str]]:
        """Parse dirb output → list of (url, status_code, size)."""
        results = []
        for line in out.split("\n"):
            if "+ http" not in line.lower():
                continue
            m = re.search(r"(\+ https?://\S+)(?:\s+\((CODE:(\d+))?([^)]*)\))?", line)
            if m:
                url = m.group(1).replace("+ ", "").strip()
                status = m.group(3) or ""
                # dirb groups extras with a leading "|" separator, e.g. "|SIZE:512"
                results.append((url, status, (m.group(4) or "").lstrip("|")))
        return results

    def _parse_gobuster(self, out: str) -> List[Tuple[str, str, str]]:
        """Parse gobuster dir output → list of (path, status_code, size)."""
        results = []
        for line in out.split("\n"):
            # Size sits *outside* the (Status: NNN) parens: "/admin (Status: 200) [Size: 512]"
            m = re.match(
                r"^(\S+)\s+\(Status:\s*(\d{3})\)\s*(?:\[Size:\s*(\d+)\])?",
                line.strip(),
            )
            if m:
                results.append((m.group(1), m.group(2), m.group(3) or ""))
        return results

    def _parse_feroxbuster(self, out: str) -> List[Tuple[str, str, str]]:
        """Parse feroxbuster output → list of (path, status_code, size)."""
        results = []
        for line in out.split("\n"):
            # "/admin 200 512l 1.2k" — size token may be the last column.
            m = re.match(r"^(\S+)\s+(\d{3})\s+(\S+)", line.strip())
            if m:
                results.append((m.group(1), m.group(2), m.group(3)))
        return results

    # ── Main entry point ───────────────────────────────────────────────

    async def run(self, swarm) -> list:
        self.status = "running"
        target = swarm.target
        url, protocol = self._web_url(swarm, target)
        host = url.split("://")[1]

        swarm.add_log(f"[web] Target web URL: {url}")

        try:
            available = await self._check_tools(swarm, self.TOOLS)
        except Exception as e:
            swarm.add_log(f"[web] ⚠ Tool probe failed: {e}")
            available = set()
        swarm.add_log(f"[web] Available tools: {sorted(available) or 'none'}")

        # ── 1. whatweb (tech stack) ──
        if "whatweb" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log("[web] Running whatweb...")
            out = await self.exec(
                swarm, f"whatweb -a 3 {url} 2>/dev/null | head -40", timeout=45
            )
            if self._tool_output_ok(out):
                ww_findings = self.parse_whatweb_output(out)
                if ww_findings:
                    for f in ww_findings:
                        self.add_finding(swarm, f["tool"], f["severity"],
                                         f["title"], f["detail"], f["port"], f["path"])
                    # Emit one finding per technology for better searchability.
                    techs = ww_findings[0]["detail"].split(", ") if ww_findings else []
                    for tech in techs[:20]:
                        self.add_finding(
                            swarm, "whatweb", "info",
                            f"Technology: {tech.strip()[:120]}",
                            f"{url} fingerprint: {tech.strip()[:200]}.",
                            "80/443", "",
                        )
                else:
                    self.add_finding(swarm, "whatweb", "info",
                                     "Web technologies (raw)",
                                     out.strip()[:500], "80/443", "")
                swarm.add_log(f"[web] whatweb: {len(ww_findings) or 'raw'} results")

        # ── 2. wafw00f (WAF detection) ──
        if "wafw00f" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log("[web] Running wafw00f...")
            out = await self.exec(
                swarm, f"wafw00f {url} 2>/dev/null | head -40", timeout=45
            )
            if self._tool_output_ok(out):
                waf_match = re.search(r"is behind\s+(.+?)(?:\n|$)", out, re.IGNORECASE)
                if waf_match:
                    self.add_finding(
                        swarm, "wafw00f", "info",
                        f"WAF detected: {waf_match.group(1).strip()[:120]}",
                        f"{url} is protected by {waf_match.group(1).strip()[:200]}.",
                        "80/443", "",
                    )
                    swarm.add_log("[web] wafw00f: WAF identified")
                else:
                    self.add_finding(
                        swarm, "wafw00f", "low",
                        "No WAF detected",
                        "wafw00f did not identify a WAF in front of the target.",
                        "80/443", "",
                    )

        # ── 3. nikto (web vuln scan, tuning-limited) ──
        if "nikto" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log("[web] Running nikto (tuning-limited)...")
            out = await self.exec(
                swarm,
                f"nikto -h {url} -Tuning 123456789 -nointeractive 2>/dev/null | head -80",
                timeout=90,
            )
            if self._tool_output_ok(out):
                nikto_findings = self.parse_nikto_output(out)
                if nikto_findings:
                    for f in nikto_findings:
                        self.add_finding(swarm, f["tool"], f["severity"],
                                         f["title"], f["detail"], f["port"], f["path"])
                else:
                    self.add_finding(swarm, "nikto", "info",
                                     "Nikto scan raw output",
                                     out.strip()[:500], "80/443", "")
                swarm.add_log(f"[web] nikto: {len(nikto_findings) or 'raw'} findings")

        # ── 4. Content discovery (dirb → feroxbuster → gobuster) ──
        discovered = []
        discovery_tool = "dirb"
        if "dirb" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log("[web] Running dirb (common.txt, limited)...")
            out = await self.exec(
                swarm,
                f"dirb {url} /usr/share/wordlists/dirb/common.txt 2>/dev/null | head -60",
                timeout=90,
            )
            discovered = self._parse_dirb(out)
            if not discovered and self._tool_output_ok(out) and "ERROR:" not in out:
                swarm.add_log("[web] dirb produced no parseable paths")
        elif "feroxbuster" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            discovery_tool = "feroxbuster"
            swarm.add_log("[web] dirb missing — trying feroxbuster...")
            out = await self.exec(
                swarm,
                f"feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt "
                f"-d 1 -q 2>/dev/null | head -60",
                timeout=90,
            )
            discovered = self._parse_feroxbuster(out)
        elif "gobuster" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            discovery_tool = "gobuster"
            swarm.add_log("[web] dirb/feroxbuster missing — trying gobuster...")
            out = await self.exec(
                swarm,
                f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt "
                f"-t 20 -q 2>/dev/null | head -60",
                timeout=90,
            )
            discovered = self._parse_gobuster(out)

        for path, status, size in discovered[:30]:
            sev = self._path_severity(path, status)
            self.add_finding(
                swarm, discovery_tool, sev,
                f"Discovered path: {path}",
                f"{path} (status {status or '?'}, size {size or '?'}).",
                "80/443", path,
            )
        swarm.add_log(f"[web] content discovery: {len(discovered)} paths")

        # ── 5. curl: headers + robots.txt ──
        if "curl" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log("[web] Fetching HTTP headers and robots.txt...")
            head_out = await self.exec(
                swarm, f"curl -sI --max-time 15 {url}/ 2>/dev/null | head -30", timeout=20
            )
            self._record_headers(swarm, url, head_out)

            robots_out = await self.exec(
                swarm, f"curl -s --max-time 15 {url}/robots.txt 2>/dev/null | head -40",
                timeout=20,
            )
            if self._tool_output_ok(robots_out) and "curl: (" not in robots_out:
                disallows = [
                    ln.split(":", 1)[1].strip()
                    for ln in robots_out.split("\n")
                    if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip()
                ]
                for d in disallows[:20]:
                    sev = self._path_severity(d, "")
                    self.add_finding(
                        swarm, "curl", sev,
                        f"robots.txt Disallow: {d}",
                        f"{url}/robots.txt blocks crawling of {d}.",
                        "80/443", d,
                    )
                swarm.add_log(f"[web] robots.txt: {len(disallows)} disallowed paths")

        return self._finish(swarm)

    # ── Header helpers ─────────────────────────────────────────────────

    def _record_headers(self, swarm, url: str, raw: str) -> None:
        """Parse curl -sI output into server/tech/security header findings."""
        if not self._tool_output_ok(raw) or "curl: (" in raw:
            swarm.add_log("[web] curl header fetch failed — skipping header checks")
            return

        headers = {}
        for line in raw.split("\n"):
            if ":" in line and not line.startswith(" "):
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        if "server" in headers:
            self.add_finding(
                swarm, "curl", "info",
                f"Web server: {headers['server'][:80]}",
                f"Server header disclosed by {url}.",
                "80/443", "",
            )
        if "x-powered-by" in headers:
            self.add_finding(
                swarm, "curl", "low",
                f"X-Powered-By disclosure: {headers['x-powered-by'][:80]}",
                "Technology fingerprint exposed via X-Powered-By header.",
                "80/443", "",
            )

        security_headers = {
            "strict-transport-security": "Strict-Transport-Security (HSTS)",
            "content-security-policy": "Content-Security-Policy",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
        }
        for key, label in security_headers.items():
            if key not in headers:
                self.add_finding(
                    swarm, "curl", "low",
                    f"Missing security header: {label}",
                    f"{url} does not send the {label} header.",
                    "80/443", "",
                )

    def _finish(self, swarm) -> list:
        self.status = "completed"
        swarm.add_log(f"[web] ✅ Complete — {len(self.findings)} findings")
        return self.findings
