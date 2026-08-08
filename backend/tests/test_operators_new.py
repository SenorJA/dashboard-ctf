"""
Unit tests for the three new swarm operators:
  - backend/operators/osint.py  → OSINTOperator
  - backend/operators/web.py    → WebOperator
  - backend/operators/vuln.py   → VulnOperator

Pattern: a FakeSwarm stub exposes the same surface the operators use
(add_log / add_finding / get_operator_findings / get_all_findings /
exec_command) so the real BaseOperator.exec pipeline (stdout/stderr
decode + truncation) is exercised end-to-end without a live SSH host.

Run with:
    python -m pytest tests/test_operators_new.py -q
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.operators.osint import OSINTOperator
from backend.operators.web import WebOperator
from backend.operators.vuln import VulnOperator


class _IO:
    """Minimal file-like object standing in for a paramiko channel stream."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeSwarm:
    """
    Stub coordinator for operator unit tests.

    ``exec_command`` resolves canned outputs by keyword found in the
    command string. The tool probe (``command -v ... && echo "t:yes"``)
    is answered from ``available_tools``.
    """

    def __init__(self, target="example.com", available_tools=None, outputs=None):
        self.target = target
        self._cancel = False
        self._cancelled = False
        self.logs = []
        self.findings = []
        self.cmds = []
        self.available_tools = set(available_tools or [])
        self.outputs = outputs or {}
        # Recon findings the operator may consult (get_operator_findings("recon")).
        self.recon_findings = []
        self.raise_on_exec = False

    # ── Coordinator surface ──

    def add_log(self, message: str):
        self.logs.append(message)

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def get_operator_findings(self, name: str) -> list:
        if name == "recon":
            return list(self.recon_findings)
        return [f for f in self.findings if f.get("source", "").endswith(f":{name}")]

    def get_all_findings(self) -> list:
        return list(self.findings)

    # ── SSH surface ──

    async def exec_command(self, command: str, timeout: int = 60):
        if self.raise_on_exec:
            raise RuntimeError("boom")
        self.cmds.append(command)
        out = self._resolve(command)
        return _IO(b""), _IO(out.encode("utf-8")), _IO(b"")

    def _resolve(self, command: str) -> str:
        low = command.lower()
        if "command -v" in command:
            return self._probe_response(command)
        for keyword in (
            "theharvester", "whois", "dig +short", "subfinder", "dnsrecon",
            "whatweb", "wafw00f", "nikto", "robots", "dirb", "gobuster",
            "feroxbuster", "searchsploit", "nmap", "nuclei", "curl",
        ):
            if keyword in low:
                out = self.outputs.get(keyword, "")
                # Values may be callables for command-dependent responses.
                return out(command) if callable(out) else out
        return ""

    def _probe_response(self, command: str) -> str:
        """Reconstruct the tool probe answer from the command itself."""
        names = re.findall(r'echo "([^"]+):(?:yes|no)"', command)
        return "\n".join(
            f"{name}:yes" if name in self.available_tools else f"{name}:no"
            for name in names
        )


def exec_cmds(swarm):
    """Commands sent to the SSH side, excluding the `command -v` tool probe."""
    return [c for c in swarm.cmds if "command -v" not in c]


# ═════════════════════════════════════════════════════════════════════
#  Shared fixtures
# ═════════════════════════════════════════════════════════════════════

ALL_TOOLS = {
    "theHarvester", "whois", "host", "dig", "subfinder", "dnsrecon", "curl",
    "whatweb", "nikto", "wafw00f", "dirb", "feroxbuster", "gobuster",
    "searchsploit", "nmap", "nuclei",
}

DEFAULT_OUTPUTS = {
    "theharvester": (
        "[+] Emails found:\n------------------\n"
        "admin@example.com\nsupport@example.com\n"
        "[+] Hosts found:\n------------------\n"
        "www.example.com\napi.example.com"
    ),
    "whois": (
        "Registrar: Example Registrar LLC\n"
        "Creation Date: 2010-01-01T00:00:00Z\n"
        "Name Server: ns1.example-reg.com"
    ),
    "dig +short": "93.184.216.34\nns1.example-reg.com.",
    "subfinder": "www.example.com\napi.example.com\nstaging.example.com",
    "dnsrecon": "[*] A Records: example.com 93.184.216.34",
    "whatweb": "https://example.com/ [200 OK] nginx[1.18.0], PHP[7.4.3]",
    "wafw00f": "Checking: https://example.com/\nThe site is behind Cloudflare WAF.",
    "nikto": "+ Server: nginx/1.18.0\n+ /admin/: Admin login page/section found.",
    "dirb": (
        "+ http://example.com/admin/ (CODE:200|SIZE:512)\n"
        "+ http://example.com/robots.txt (CODE:200|SIZE:45)"
    ),
    "robots": "User-agent: *\nDisallow: /admin/\nDisallow: /config/",
    "searchsploit": (
        "-----------------------------------------------\n"
        " Exploit Title                              |  Path\n"
        "-----------------------------------------------\n"
        " nginx 1.18 RCE (PoC)                       | linux/remote/50510.py"
    ),
    "nmap": (
        "80/tcp open http nginx 1.18.0\n"
        "| vulners:\n"
        "|   CVE-2021-23017  https://vulners.com 8.1  https://nvd.nist.gov/vuln/detail/CVE-2021-23017\n"
        "|   CVE-2021-3618   https://vulners.com 4.3  https://nvd.nist.gov/vuln/detail/CVE-2021-3618"
    ),
    "nuclei": (
        "[http-missing-security-headers] [low] https://example.com/\n"
        "[ssl-dns-names] [info] https://example.com/"
    ),
    "curl": "HTTP/2 200\nserver: nginx/1.18.0\ncontent-type: text/html",
}


def make_swarm(target="example.com", available_tools=None, outputs=None,
               recon_findings=None):
    """Build a FakeSwarm pre-loaded with the default fixtures."""
    swarm = FakeSwarm(
        target=target,
        available_tools=available_tools if available_tools is not None else set(ALL_TOOLS),
        outputs=outputs if outputs is not None else dict(DEFAULT_OUTPUTS),
    )
    swarm.recon_findings = list(recon_findings or [])
    return swarm


# ═════════════════════════════════════════════════════════════════════
#  OSINTOperator
# ═════════════════════════════════════════════════════════════════════

class TestOSINTOperatorHelpers:

    def test_normalize_target_domain(self):
        host, is_ip, base = OSINTOperator._normalize_target(
            "https://www.example.com/path?x=1"
        )
        assert host == "www.example.com"
        assert is_ip is False
        assert base == "example.com"

    def test_normalize_target_ip(self):
        host, is_ip, base = OSINTOperator._normalize_target("10.0.0.1")
        assert host == "10.0.0.1"
        assert is_ip is True

    def test_normalize_target_ip_with_port(self):
        host, is_ip, base = OSINTOperator._normalize_target("10.0.0.5:8080")
        assert host == "10.0.0.5"
        assert is_ip is True

    def test_extract_emails_dedupes(self):
        sample = "a@example.com b@example.com c@example.com a@example.com"
        emails = OSINTOperator._extract_emails(sample)
        assert set(emails) == {"a@example.com", "b@example.com", "c@example.com"}

    def test_extract_emails_filters_placeholder(self):
        sample = "real@example.com spacer@2x.png"
        emails = OSINTOperator._extract_emails(sample)
        assert emails == ["real@example.com"]

    def test_extract_subdomains(self):
        sample = "www.example.com\napi.example.com\nmail.example.com\nwww.example.com"
        subs = OSINTOperator._extract_subdomains(sample, "example.com")
        assert set(subs) == {"www.example.com", "api.example.com", "mail.example.com"}

    def test_extract_subdomains_no_match(self):
        assert OSINTOperator._extract_subdomains("other.org\nfoo.net", "example.com") == []

    async def test_check_tools_parses_yes_no(self):
        swarm = make_swarm(available_tools={"whois", "dig"})
        op = OSINTOperator()
        available = await op._check_tools(swarm, ["theHarvester", "whois", "dig", "curl"])
        assert available == {"whois", "dig"}

    async def test_check_tools_survives_ssh_error(self):
        swarm = make_swarm()
        swarm.raise_on_exec = True
        op = OSINTOperator()
        available = await op._check_tools(swarm, ["whois"])
        assert available == set()


class TestOSINTOperatorRun:

    async def test_run_produces_findings(self):
        swarm = make_swarm()
        op = OSINTOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        titles = [f["title"] for f in findings]

        assert any("Passive OSINT recon started" in t for t in titles)
        assert "Email found: admin@example.com" in titles
        assert "Email found: support@example.com" in titles
        assert "Subdomain: www.example.com" in titles
        assert "Subdomain: staging.example.com" in titles  # subfinder
        assert "WHOIS record for example.com" in titles
        assert "Nameserver: ns1.example-reg.com" in titles
        assert any("A record: 93.184.216.34" in t for t in titles)
        assert "Web server: nginx/1.18.0" in titles
        assert "Missing security header: Content-Security-Policy" in titles
        # all findings carry the swarm source tag
        assert all(f["source"] == "swarm:osint" for f in findings)

    async def test_run_with_no_tools_ends_with_only_intro(self):
        swarm = make_swarm(available_tools=set())
        op = OSINTOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        assert len(findings) == 1
        assert findings[0]["title"] == "Passive OSINT recon started for example.com"

    async def test_run_respects_cancellation(self):
        swarm = make_swarm()
        swarm._cancel = True
        op = OSINTOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        assert len(findings) == 1  # only the intro finding, then cancel-checked out

    async def test_run_ip_target_skips_domain_tools(self):
        swarm = make_swarm(target="10.0.0.1")
        op = OSINTOperator()
        findings = await op.run(swarm)

        # Probe lists every tool regardless of target — only *executions* count.
        joined = " ".join(exec_cmds(swarm)).lower()
        assert "theharvester" not in joined
        assert "subfinder" not in joined
        assert "dig" not in joined
        assert "dnsrecon" not in joined
        assert "curl" in joined  # header check still runs for IPs
        assert op.status == "completed"
        assert any("Web server: nginx/1.18.0" in f["title"] for f in findings)


# ═════════════════════════════════════════════════════════════════════
#  WebOperator
# ═════════════════════════════════════════════════════════════════════

class TestWebOperatorHelpers:

    def test_web_url_https_by_default(self):
        swarm = make_swarm(recon_findings=[])
        url, protocol = WebOperator()._web_url(swarm, "example.com")
        assert url == "https://example.com"
        assert protocol == "https"

    def test_web_url_fallback_http_from_recon(self):
        swarm = make_swarm(recon_findings=[
            {"port": "80/tcp", "title": "Open port: 80/tcp — http", "detail": ""},
        ])
        url, protocol = WebOperator()._web_url(swarm, "example.com")
        assert url == "http://example.com"
        assert protocol == "http"

    def test_web_url_keeps_https_for_443_recon(self):
        swarm = make_swarm(recon_findings=[
            {"port": "443/tcp", "title": "Open port: 443/tcp — ssl/http", "detail": ""},
        ])
        url, protocol = WebOperator()._web_url(swarm, "example.com")
        assert url == "https://example.com"
        assert protocol == "https"

    def test_path_severity(self):
        assert WebOperator._path_severity("/.env", "200") == "medium"
        assert WebOperator._path_severity("/.git/config", "200") == "medium"
        assert WebOperator._path_severity("/admin/", "200") == "medium"
        assert WebOperator._path_severity("/private/", "403") == "low"
        assert WebOperator._path_severity("/index.html", "200") == "info"

    def test_parse_dirb(self):
        out = (
            "+ http://10.0.0.1/admin/ (CODE:200|SIZE:512)\n"
            "+ http://10.0.0.1/robots.txt (CODE:200|SIZE:45)"
        )
        results = WebOperator()._parse_dirb(out)
        assert len(results) == 2
        assert results[0][0] == "http://10.0.0.1/admin/"
        assert results[0][1] == "200"
        assert results[0][2] == "SIZE:512"

    def test_parse_gobuster(self):
        out = "/admin (Status: 200) [Size: 512]\n/login (Status: 200)"
        results = WebOperator()._parse_gobuster(out)
        assert len(results) == 2
        assert results[0] == ("/admin", "200", "512")

    def test_parse_feroxbuster(self):
        out = "/admin 200 512l 1.2k\n/login 301 10l"
        results = WebOperator()._parse_feroxbuster(out)
        assert len(results) == 2
        assert results[0][0] == "/admin"
        assert results[0][1] == "200"

    def test_parse_dirb_no_matches(self):
        assert WebOperator()._parse_dirb("Starting dirb...\ndone") == []


class TestWebOperatorRun:

    async def test_run_produces_findings(self):
        swarm = make_swarm()
        op = WebOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        titles = " | ".join(f["title"] for f in findings)

        assert "Technology:" in titles  # whatweb fingerprint
        assert "WAF detected: Cloudflare WAF." in titles
        assert "Server: nginx/1.18.0" in titles  # nikto
        assert "Discovered path: http://example.com/admin/" in titles
        assert "Web server: nginx/1.18.0" in titles  # curl headers
        assert "robots.txt Disallow: /admin/" in titles
        assert all(f["source"] == "swarm:web" for f in findings)

    async def test_run_no_tools_produces_no_findings(self):
        swarm = make_swarm(available_tools=set())
        op = WebOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        assert findings == []

    async def test_run_partial_tools_continues(self):
        """Missing tools do not abort the remaining pipeline."""
        swarm = make_swarm(available_tools={"whatweb", "curl"})
        op = WebOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        titles = " | ".join(f["title"] for f in findings)
        assert "Technology:" in titles  # whatweb ran
        assert "WAF detected" not in titles  # wafw00f absent
        assert "Discovered path" not in titles  # dirb absent

    async def test_run_skips_content_discovery_when_dirb_absent(self):
        swarm = make_swarm(available_tools=ALL_TOOLS - {"dirb", "feroxbuster", "gobuster"})
        op = WebOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        # Probe names the tools even when absent — only *executions* must skip them.
        joined = " ".join(exec_cmds(swarm)).lower()
        assert "dirb" not in joined
        assert "feroxbuster" not in joined
        assert "gobuster" not in joined


# ═════════════════════════════════════════════════════════════════════
#  VulnOperator
# ═════════════════════════════════════════════════════════════════════

class TestVulnOperatorHelpers:

    def test_is_ip(self):
        assert VulnOperator._is_ip("10.0.0.1") is True
        assert VulnOperator._is_ip("192.168.1.100") is True
        assert VulnOperator._is_ip("example.com") is False

    def test_collect_versions(self):
        swarm = make_swarm()
        swarm.findings = [
            {"title": "Web technologies detected", "detail": "Apache/2.4.41, PHP 7.4.3",
             "port": "80/443"},
            {"title": "Open port: 22/tcp — ssh", "detail": "OpenSSH 8.9p1", "port": "22/tcp"},
        ]
        versions = VulnOperator()._collect_versions(swarm)
        assert "apache" in versions and "2.4.41" in versions["apache"]
        assert "php" in versions and "7.4.3" in versions["php"]
        assert "openssh" in versions and any(v.startswith("8.9") for v in versions["openssh"])

    def test_parse_vulners_high_when_cvss_ge_7(self):
        out = (
            "80/tcp open http Apache httpd 2.4.41\n"
            "| vulners:\n"
            "|   CVE-2021-41773  https://vulners.com 7.5  https://nvd.nist.gov/vuln/detail/CVE-2021-41773\n"
            "|   CVE-2019-0211   https://vulners.com 8.1  https://nvd.nist.gov/vuln/detail/CVE-2019-0211\n"
            "|   CVE-2017-15715  https://vulners.com 4.3  https://nvd.nist.gov/vuln/detail/CVE-2017-15715"
        )
        findings = VulnOperator()._parse_vulners(out)
        by_cve = {f["title"].split(" ")[0]: f["severity"] for f in findings}
        assert by_cve["CVE-2021-41773"] == "high"
        assert by_cve["CVE-2019-0211"] == "high"
        assert by_cve["CVE-2017-15715"] == "medium"
        assert findings[0]["tool"] == "nmap"
        assert findings[0]["port"] == "80/tcp"

    def test_parse_nuclei(self):
        out = (
            "[http-missing-security-headers] [low] https://example.com/\n"
            "[ssl-dns-names] [info] https://example.com/"
        )
        findings = VulnOperator()._parse_nuclei(out)
        assert len(findings) == 2
        assert findings[0]["tool"] == "nuclei"
        assert findings[0]["severity"] == "low"
        assert findings[1]["severity"] == "info"

    def test_parse_nuclei_skips_errors(self):
        assert VulnOperator()._parse_nuclei("ERROR: something\n") == []


class TestVulnOperatorRun:

    def _seed_versions(self, swarm):
        swarm.findings = [
            {"tool": "whatweb", "severity": "info",
             "title": "Web technologies detected",
             "detail": "nginx/1.18.0, PHP 7.4.3", "port": "80/443",
             "source": "swarm:web"},
            {"tool": "recon", "severity": "medium",
             "title": "Open port: 80/tcp — http",
             "detail": "nginx 1.18.0", "port": "80/tcp",
             "source": "swarm:recon"},
        ]

    async def test_run_searchsploit_from_versions(self):
        # searchsploit answers per query: nginx has an exploit, php has none.
        def sploit_output(cmd):
            return DEFAULT_OUTPUTS["searchsploit"] if "nginx" in cmd.lower() else ""

        swarm = make_swarm(outputs={"searchsploit": sploit_output})
        self._seed_versions(swarm)
        op = VulnOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        exploit_findings = [f for f in findings if f["tool"] == "searchsploit"]
        assert exploit_findings, [f["tool"] for f in findings]
        titles = " ".join(f["title"] for f in exploit_findings)
        assert "Exploit: nginx 1.18 RCE (PoC)" in titles
        assert exploit_findings[0]["severity"] == "high"
        # "No public exploits" info entries for version queries without matches
        assert any(f["severity"] == "info" for f in exploit_findings)
        assert "No public exploits for php 7.4.3" in titles

    async def test_run_vulners_high_for_ip_target(self):
        swarm = make_swarm(target="10.0.0.1")
        op = VulnOperator()
        findings = await op.run(swarm)

        cve_findings = [f for f in findings if f["tool"] == "nmap"]
        assert cve_findings
        assert "CVE-2021-23017" in cve_findings[0]["title"]
        assert cve_findings[0]["severity"] == "high"  # CVSS 8.1
        assert any(f["tool"] == "nuclei" for f in findings)

    async def test_run_nuclei_findings(self):
        swarm = make_swarm()
        op = VulnOperator()
        findings = await op.run(swarm)

        nuclei = [f for f in findings if f["tool"] == "nuclei"]
        assert len(nuclei) == 2
        assert nuclei[0]["title"] == "Nuclei: http-missing-security-headers"
        assert nuclei[0]["severity"] == "low"
        assert all(f["source"] == "swarm:vuln" for f in findings)

    async def test_run_no_tools_produces_no_findings(self):
        swarm = make_swarm(available_tools=set())
        self._seed_versions(swarm)
        op = VulnOperator()
        findings = await op.run(swarm)

        assert op.status == "completed"
        assert findings == []

    async def test_run_skips_searchsploit_without_versions(self):
        swarm = make_swarm()  # no seeded findings → no versions
        op = VulnOperator()
        await op.run(swarm)

        assert op.status == "completed"
        # Probe names the tool, but no searchsploit *execution* may happen.
        joined = " ".join(exec_cmds(swarm)).lower()
        assert "searchsploit" not in joined
