"""
OSINT Operator — Passive Open Source Intelligence gathering.

Runs purely passive reconnaissance tools (theHarvester, whois, dig/host,
subfinder, dnsrecon, curl) against a target.

IMPORTANT: this operator performs NO active port scanning and NO fuzzing.
It only queries public DNS, WHOIS and web server headers.
"""

import asyncio
import re
from typing import List, Set, Tuple

from .base import BaseOperator


class OSINTOperator(BaseOperator):
    """Passive OSINT: emails, subdomains, DNS records, NS servers, security headers."""

    icon = "🌐"
    description = "Passive Open Source Intelligence gathering"

    # Tools probed in a single `command -v` round-trip before anything runs.
    TOOLS = ["theHarvester", "whois", "host", "dig", "subfinder", "dnsrecon", "curl"]

    def __init__(self) -> None:
        super().__init__("osint", "🌐 OSINT Recon")

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_target(target: str) -> Tuple[str, bool, str]:
        """
        Normalize the swarm target into (host, is_ip, base_domain).

        ``base_domain`` is the registrable-looking root (2nd-level label) so
        subdomain findings can be matched against it.
        """
        host = target.strip().lower()
        host = host.replace("http://", "").replace("https://", "")
        host = host.split("/")[0].split(":")[0].rstrip(".")
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
        base_domain = host
        if not is_ip and "." in host:
            labels = host.split(".")
            # Keep the last two labels as the base domain (a.b → b, a.b.c → b.c)
            base_domain = ".".join(labels[-2:]) if len(labels) > 2 else host
        return host, is_ip, base_domain

    @staticmethod
    def _cancel_requested(swarm) -> bool:
        """Check the coordinator's cancellation flag (also guards _cancelled)."""
        return bool(getattr(swarm, "_cancel", False)) or bool(
            getattr(swarm, "_cancelled", False)
        )

    async def _check_tools(self, swarm, tools: List[str]) -> Set[str]:
        """Return the subset of ``tools`` available on the remote host."""
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
    def _extract_emails(text: str) -> List[str]:
        """Extract unique e-mail addresses from raw tool output."""
        emails = re.findall(
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", text
        )
        # Drop known placeholder patterns tools print in docs/examples.
        seen, out = set(), []
        for e in emails:
            e = e.strip(".,;<>()")
            if e.lower() in seen or "@2x" in e:
                continue
            seen.add(e.lower())
            out.append(e)
        return out

    @staticmethod
    def _extract_subdomains(text: str, base_domain: str) -> List[str]:
        """Extract subdomains of ``base_domain`` from raw tool output."""
        if not base_domain:
            return []
        pattern = re.compile(
            r"(?<![\w.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
            + re.escape(base_domain) + r")(?![\w.\-])",
            re.IGNORECASE,
        )
        seen, out = set(), []
        for m in pattern.finditer(text):
            sub = m.group(1).lower().strip(".,;()")
            if sub in seen:
                continue
            seen.add(sub)
            out.append(sub)
        return out

    def _tool_output_ok(self, output: str) -> bool:
        """True when tool output is usable (not an error/empty result)."""
        return bool(output.strip()) and not output.strip().startswith("ERROR:")

    # ── Main entry point ───────────────────────────────────────────────

    async def run(self, swarm) -> list:
        self.status = "running"
        target = swarm.target
        host, is_ip, base_domain = self._normalize_target(target)

        swarm.add_log(f"[osint] Target {host} — ip={is_ip} base_domain={base_domain}")

        # Passive nature marker.
        self.add_finding(
            swarm, "osint", "info",
            f"Passive OSINT recon started for {host}",
            "Only passive sources used: DNS, WHOIS, public subdomain/email "
            "harvesting and HTTP headers. No active port scanning or fuzzing.",
            "", "",
        )

        try:
            available = await self._check_tools(swarm, self.TOOLS)
        except Exception as e:
            swarm.add_log(f"[osint] ⚠ Tool probe failed: {e}")
            available = set()
        swarm.add_log(f"[osint] Available tools: {sorted(available) or 'none'}")

        # ── 1. theHarvester (emails + hosts) ──
        if not is_ip and "theHarvester" in available and base_domain:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log(f"[osint] Running theHarvester against {base_domain}...")
            out = await self.exec(
                swarm,
                f"theHarvester -d {base_domain} -b all -l 50 2>/dev/null | tail -60",
                timeout=45,
            )
            if self._tool_output_ok(out):
                emails = self._extract_emails(out)
                for email in emails[:50]:
                    self.add_finding(
                        swarm, "theHarvester", "info",
                        f"Email found: {email}",
                        f"Publicly indexed e-mail associated with {base_domain}.",
                        "", "",
                    )
                subs = self._extract_subdomains(out, base_domain)
                for sub in subs[:50]:
                    self.add_finding(
                        swarm, "theHarvester", "info",
                        f"Subdomain: {sub}",
                        f"Subdomain of {base_domain} discovered via public search engines.",
                        "", "",
                    )
                swarm.add_log(
                    f"[osint] theHarvester: {len(emails)} emails, {len(subs)} subdomains"
                )
            else:
                swarm.add_log("[osint] theHarvester returned no usable output")

        # ── 2. WHOIS ──
        if "whois" in available and not is_ip:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log(f"[osint] Running whois on {base_domain}...")
            out = await self.exec(
                swarm, f"whois {base_domain} 2>/dev/null | head -60", timeout=20
            )
            if self._tool_output_ok(out):
                fields = {}
                for key in ("Registrar", "Creation Date", "Name Server", "Registrant Organization"):
                    m = re.search(
                        rf"^{re.escape(key)}:\s*(.+)$", out, re.MULTILINE | re.IGNORECASE
                    )
                    if m:
                        fields[key] = m.group(1).strip()
                if fields:
                    detail = "; ".join(f"{k}: {v}" for k, v in fields.items())
                    self.add_finding(
                        swarm, "whois", "info",
                        f"WHOIS record for {base_domain}",
                        detail[:500], "", "",
                    )
                    # NS servers → separate finding.
                    ns = fields.get("Name Server")
                    if ns:
                        self.add_finding(
                            swarm, "whois", "info",
                            f"Nameserver: {ns}",
                            f"Authoritative nameserver for {base_domain}.",
                            "", "",
                        )
                else:
                    self.add_finding(
                        swarm, "whois", "info",
                        f"WHOIS record for {base_domain}",
                        out.strip()[:500], "", "",
                    )
                swarm.add_log(f"[osint] whois: record captured for {base_domain}")

        # ── 3. DNS records (dig A/NS/MX, host fallback) ──
        if not is_ip:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            if "dig" in available:
                swarm.add_log(f"[osint] Enumerating DNS records for {base_domain}...")
                for rtype, label in (("A", "A records"), ("NS", "Nameservers"), ("MX", "Mail servers")):
                    out = await self.exec(
                        swarm,
                        f"dig +short {rtype} {base_domain} 2>/dev/null | head -15",
                        timeout=20,
                    )
                    if self._tool_output_ok(out):
                        values = [
                            ln.strip() for ln in out.split("\n")
                            if ln.strip() and not ln.strip().startswith("ERROR:")
                        ]
                        for v in values[:15]:
                            self.add_finding(
                                swarm, "dig", "info",
                                f"{label[:-1]}: {v}",
                                f"DNS {rtype} record for {base_domain}.",
                                "", "",
                            )
                        swarm.add_log(f"[osint] dig {rtype}: {len(values)} records")
            elif "host" in available:
                swarm.add_log(f"[osint] dig missing — falling back to host for {base_domain}...")
                for rtype, flag in (("A", "-t A"), ("NS", "-t NS"), ("MX", "-t MX")):
                    out = await self.exec(
                        swarm,
                        f"host {flag} {base_domain} 2>/dev/null | head -15",
                        timeout=20,
                    )
                    if self._tool_output_ok(out):
                        values = [
                            ln.strip() for ln in out.split("\n")
                            if ln.strip() and not ln.strip().startswith("ERROR:")
                        ]
                        for v in values[:15]:
                            self.add_finding(
                                swarm, "host", "info",
                                f"DNS {rtype}: {v}",
                                f"DNS {rtype} record for {base_domain} (host fallback).",
                                "", "",
                            )

        # ── 4. subfinder (subdomains) ──
        if not is_ip and "subfinder" in available and base_domain:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log(f"[osint] Running subfinder on {base_domain}...")
            out = await self.exec(
                swarm,
                f"subfinder -d {base_domain} -silent 2>/dev/null | head -50",
                timeout=45,
            )
            if self._tool_output_ok(out):
                subs = [
                    ln.strip().lower() for ln in out.split("\n")
                    if ln.strip() and not ln.strip().startswith("ERROR:")
                ]
                for sub in subs[:50]:
                    self.add_finding(
                        swarm, "subfinder", "info",
                        f"Subdomain: {sub}",
                        f"Subdomain of {base_domain} found via passive subfinder sources.",
                        "", "",
                    )
                swarm.add_log(f"[osint] subfinder: {len(subs)} subdomains")

        # ── 5. dnsrecon (standard enumeration) ──
        if not is_ip and "dnsrecon" in available and base_domain:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            swarm.add_log(f"[osint] Running dnsrecon on {base_domain}...")
            out = await self.exec(
                swarm,
                f"dnsrecon -d {base_domain} -t std 2>/dev/null | head -60",
                timeout=45,
            )
            if self._tool_output_ok(out):
                self.add_finding(
                    swarm, "dnsrecon", "info",
                    f"DNS enumeration for {base_domain}",
                    out.strip()[:500], "", "",
                )
                swarm.add_log("[osint] dnsrecon: raw record dump captured")

        # ── 6. Security headers (curl -sI) — passive, no payloads ──
        if "curl" in available:
            if self._cancel_requested(swarm):
                return self._finish(swarm)
            protocol = self._pick_web_protocol(swarm, host)
            swarm.add_log(f"[osint] Fetching security headers from {protocol}://{host}/...")
            out = await self.exec(
                swarm,
                f"curl -sI --max-time 15 {protocol}://{host}/ 2>/dev/null | head -30",
                timeout=20,
            )
            self._record_headers(swarm, host, out, protocol)

        return self._finish(swarm)

    # ── Web header helpers ─────────────────────────────────────────────

    def _pick_web_protocol(self, swarm, host: str) -> str:
        """Prefer https, fall back to http. Consults prior recon findings."""
        # If recon already saw an HTTP listener on a web port, honour it.
        for f in swarm.get_operator_findings("recon"):
            port = f.get("port", "")
            title = ((f.get("title", "") or "") + " " + (f.get("detail", "") or "")).lower()
            if port.startswith("80") or "http" in title or "443" in port:
                break
        else:
            return "https"
        return "http" if "443" not in port and "8443" not in port else "https"

    def _record_headers(self, swarm, host: str, raw: str, protocol: str) -> None:
        """Parse curl -sI output into header findings (info) + missing-header flags (low)."""
        if not self._tool_output_ok(raw) or "curl: (" in raw:
            swarm.add_log("[osint] curl header fetch failed — skipping header checks")
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
                f"Server header disclosed by {protocol}://{host}/.",
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
            "permissions-policy": "Permissions-Policy",
        }
        for key, label in security_headers.items():
            if key in headers:
                self.add_finding(
                    swarm, "curl", "info",
                    f"{label} present",
                    f"{label}: {headers[key][:120]}",
                    "80/443", "",
                )
            else:
                self.add_finding(
                    swarm, "curl", "low",
                    f"Missing security header: {label}",
                    f"{protocol}://{host}/ does not send the {label} header.",
                    "80/443", "",
                )

    def _finish(self, swarm) -> list:
        self.status = "completed"
        swarm.add_log(f"[osint] ✅ Complete — {len(self.findings)} findings")
        return self.findings
