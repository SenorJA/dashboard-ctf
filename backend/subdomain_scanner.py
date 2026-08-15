"""
subdomain_scanner.py — MIRV Module

Asynchronous subdomain enumerator via DNS resolution + passive OSINT.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects
Passive sources (crt.sh + Wayback Machine CDX) inspired by
https://github.com/fawadqureshi007/ShadowEnum.

* ``scan``          — active brute-force DNS resolution against a built-in
                      wordlist of common subdomain prefixes.
* ``scan_passive``  — passive discovery via certificate transparency
                      (crt.sh) and archive crawling (Wayback CDX), with
                      bounded best-effort DNS validation.
* ``scan_combined`` — active + passive sweep, deduplicated.
"""

import asyncio
import json
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Literal

# User-Agent sent to passive sources (crt.sh / web.archive.org).
_USER_AGENT = "MIRV-SubdomainScanner/1.0 (security auditing; contact: local operator)"


# ── Common subdomain prefixes (security-relevant) ──
# Sourced from common security wordlists (SecLists, subdomains-top1million, etc.)

COMMON_SUBDOMAINS: list[str] = [
    # Web / admin
    "www", "ww w", "wwww", "web", "webserver", "websrv",
    "admin", "administrator", "adm", "adminer",
    "dashboard", "panel", "cpanel", "whm", "plesk",
    "manager", "management", "manage",
    "portal", "gateway", "intranet", "extranet",
    "console", "operator",
    # Dev / staging
    "dev", "development", "develop", "staging", "stage",
    "test", "testing", "tests", "qa", "uat",
    "beta", "alpha", "demo", "sandbox", "lab",
    "pre", "preprod", "preproduction",
    "release", "rc", "nightly", "canary",
    # API / services
    "api", "api2", "api3", "v1", "v2", "v3",
    "rest", "graphql", "soap", "xmlrpc",
    "ws", "wss", "websocket",
    "rpc", "grpc", "webhook", "callback",
    "service", "services", "svc",
    "backend", "backoffice", "back",
    "frontend", "front",
    # Authentication
    "auth", "login", "signin", "signup", "register",
    "sso", "oauth", "oauth2", "oidc", "saml",
    "okta", "keycloak",
    "forgot", "reset", "password", "recover",
    "verify", "validation",
    # Email
    "mail", "email", "smtp", "imap", "pop3", "exchange",
    "mail2", "mail3", "webmail", "webmail2",
    "mx", "mx1", "mx2",
    "outlook", "owa", "ecp", "autodiscover",
    # Security
    "security", "secure", "sec",
    "vpn", "vpn2", "openvpn", "wireguard",
    "proxy", "squid", "tor",
    "firewall", "fw", "ids", "ips",
    "waf", "nginx", "cloudflare",
    "ssl", "tls", "cert", "certificate",
    "pki", "ca", "crl", "ocsp",
    "hsm", "vault",
    # Monitoring
    "monitor", "monitoring", "mon",
    "grafana", "prometheus", "kibana", "elastic",
    "nagios", "zabbix", "cacti", "munin",
    "stats", "statistics", "metrics",
    "status", "uptime", "health", "healthcheck",
    "alerts", "alertmanager", "logs", "log",
    # Database
    "db", "database", "mysql", "mariadb", "psql",
    "postgres", "postgresql", "mongo", "mongodb",
    "redis", "elasticsearch", "es",
    "cassandra", "couchdb", "cockroach",
    "sql", "phpmyadmin", "phpadmin",
    "adminer", "adminer4",
    # Cloud / infra
    "cloud", "aws", "azure", "gcp",
    "s3", "bucket", "storage",
    "cdn", "static", "static2",
    "assets", "media", "images", "img",
    "upload", "download", "files",
    "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2", "ns",
    # CI/CD / VCS
    "git", "github", "gitlab", "bitbucket",
    "ci", "cd", "jenkins", "travis",
    "circleci", "runner", "build", "builder",
    "artifact", "artifacts", "nexus",
    "jira", "confluence", "wiki",
    "sonar", "sonarqube", "codequality",
    # Common apps
    "app", "app1", "app2", "apps",
    "my", "the", "go",
    "shop", "store", "cart", "checkout",
    "blog", "news", "press", "media",
    "forum", "community", "chat",
    "support", "help", "faq", "docs",
    "wiki", "kb", "knowledgebase",
    "calendar", "meet", "zoom",
    "drive", "files", "share", "upload",
    "remote", "remote2", "access",
    "rdp", "vnc", "teamviewer", "anydesk",
    # Editors / CMS
    "wordpress", "wp", "wp-admin", "wp-content",
    "joomla", "drupal", "moodle",
    "ghost", "medium", "hubspot",
    "site", "website", "homepage",
    "landing", "landingpage", "lp",
    # Miscellaneous
    "cdn", "cdn2", "static",
    "img", "image", "images", "photo", "photos",
    "video", "videos", "tv",
    "stream", "live", "player",
    "radio", "music", "audio",
    "download", "dl", "downloads",
    "upload", "uploads",
    "ftp", "sftp", "ftps",
    "ssh", "ssh2", "bastion", "jump", "jumpserver",
    "ldap", "ad", "active-directory", "dc",
    "radius", "tacacs",
    "phone", "call", "voip", "sip",
    "print", "printer", "ipp",
    "time", "ntp", "chrony",
    "docker", "k8s", "kubernetes",
    "kube", "kubectl", "cluster",
    "registry", "harbor",
    "config", "configuration",
    "setup", "install", "update",
    "sync", "backup", "backups",
    "recovery", "disaster",
    "docs", "documentation",
    "legal", "privacy", "terms",
    "partners", "partner", "affiliate",
    "careers", "jobs", "hr",
    "recruitment", "apply",
    "events", "event",
    "feedback", "survey",
    "newsletter", "notify", "notification",
    "track", "tracking", "analytics",
    "pixel", "ads", "adserver",
    "cdn", "edge",
    "pwa", "m", "mobile",
    "amp", "accelerator",
    "redirect", "redirects",
    "shortlink", "short",
    "proxy", "proxy2",
    "tunnel", "ngrok",
    "internet", "external",
    "corp", "corporate",
    "office", "office365", "365",
    "sharepoint", "teams",
    "skype", "lync", "sfb",
    "pulse", "pulsesecure",
    "citrix", "xen", "xenapp",
    "vmware", "vsphere", "esxi", "vcenter",
    "hyperv", "hyper-v",
    "sccm", "scom", "scvmm",
    "oracle", "ebs", "e-business",
    "sap", "erp", "crm",
    "odoo", "sugarcrm", "suitecrm",
    "magento", "shopify", "woocommerce",
    "prestashop", "opencart",
    "bigcommerce", "salesforce",
    "zendesk", "freshdesk", "servicedesk",
    "sentry", "rollbar", "bugsnag",
    "newrelic", "datadog",
    "pagerduty", "opsgenie",
    "puppet", "ansible", "chef",
    "salt", "terraform",
    "docker", "portainer",
    "rancher", "nomad", "consul",
    "vault", "vault1", "vault2",
    "maven", "gradle", "npm",
    "pypi", "rubygems",
    "artifactory", "jfrog",
    "sonatype", "nexus",
    "code", "codereview",
    "review", "peer-review",
    "lint", "linter",
    "coverage", "codecov",
    "benchmark", "perf", "performance",
]


@dataclass(frozen=True, slots=True)
class SubdomainResult:
    subdomain: str
    domain: str
    full_domain: str
    resolved_ips: list[str]
    record_type: str | None = None  # "A", "AAAA", "CNAME"
    cname_target: str | None = None


@dataclass(frozen=True, slots=True)
class SubdomainReport:
    domain: str
    total_checked: int
    found: int
    results: list[SubdomainResult]
    duration_seconds: float
    # Passive metadata (defaults keep brute-force callers 100% compatible)
    sources: list[str] = field(default_factory=list)  # e.g. ["crt.sh", "wayback"]
    errors: list[str] = field(default_factory=list)   # per-source failure notes


# ── Domain / subdomain normalization ─────────────────────────────────────────

def _clean_domain(domain: str) -> str:
    """Normalize a target domain: lowercase + strip scheme/path/port/query."""
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.split("?")[0]
    return domain.strip().rstrip(".")


def _normalize_subdomain(raw: str, domain: str) -> str | None:
    """
    Normalize a raw host string into a clean FQDN under ``domain``.

    Strips leading wildcards (``*.``), scheme, path, query and fragment,
    lowercases the result and returns ``None`` when the host does not
    belong to ``domain`` (prevents look-alike pollution such as
    ``fakeexample.com`` leaking into an ``example.com`` scan).
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/")[0]
    raw = raw.split("?")[0].split("#")[0]
    raw = raw.lstrip("*.").strip().lower().rstrip(".")
    if raw == domain or raw.endswith("." + domain):
        return raw
    return None


# ── Passive source fetchers (blocking, stdlib-only; run via to_thread) ──────

def _http_get_json(url: str, timeout: float = 10.0) -> list | dict | None:
    """
    Blocking HTTP GET returning parsed JSON.

    Raises on any transport / HTTP / JSON error — callers wrap it.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    if not body:
        return None
    return json.loads(body.decode("utf-8", errors="replace"))


def _fetch_crtsh(domain: str, timeout: float) -> tuple[set[str], str | None]:
    """
    Query crt.sh certificate-transparency logs.

    Returns (unique subdomains, error-or-None).  A source failure never
    raises — it degrades to an error note so the caller can keep going.
    """
    q = urllib.parse.quote(f"%25.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    try:
        data = _http_get_json(url, timeout)
    except Exception as exc:  # network / HTTP / JSON errors
        return set(), f"crt.sh: {exc}"
    subs: set[str] = set()
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            nv = item.get("name_value") or item.get("common_name") or ""
            for line in str(nv).splitlines():
                name = _normalize_subdomain(line, domain)
                if name:
                    subs.add(name)
    return subs, None


def _fetch_wayback(domain: str, timeout: float) -> tuple[set[str], str | None]:
    """
    Query the Wayback Machine CDX API (collapse=urlkey, capped at 500 rows).

    Returns (unique subdomains, error-or-None).  A source failure never
    raises — it degrades to an error note so the caller can keep going.
    """
    url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        f"&output=json&fl=original&collapse=urlkey&limit=500"
    )
    try:
        data = _http_get_json(url, timeout)
    except Exception as exc:  # network / HTTP / JSON errors
        return set(), f"wayback: {exc}"
    subs: set[str] = set()
    if isinstance(data, list):
        # Row 0 is the CDX column header (["original"]); rows are lists.
        for row in data[1:]:
            if not isinstance(row, list) or not row:
                continue
            name = _normalize_subdomain(str(row[0]), domain)
            if name:
                subs.add(name)
    return subs, None


async def _resolve_subdomain(
    full_domain: str,
    timeout: float = 3.0,
) -> SubdomainResult | None:
    """Try to resolve a full domain name."""
    subdomain_part = full_domain.split(".", 1)[0]
    domain_part = full_domain.split(".", 1)[1] if "." in full_domain else ""

    try:
        # Try A record
        ips = []
        try:
            info = await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(full_domain, 80),
                timeout=timeout,
            )
            ips = list(set(
                addr[4][0] for addr in info
                if addr[4][0] and not addr[4][0].startswith("127.")
            ))
        except Exception:
            pass

        # Try CNAME
        cname = None
        try:
            cname_result = await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(full_domain, 80, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
            # getaddrinfo doesn't give CNAME directly, so we fall back to socket
        except Exception:
            pass

        if ips:
            return SubdomainResult(
                subdomain=subdomain_part,
                domain=domain_part,
                full_domain=full_domain,
                resolved_ips=ips,
                record_type="A",
                cname_target=cname,
            )

        # Try just gethostbyname as fallback
        try:
            ip = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyname, full_domain),
                timeout=timeout,
            )
            if ip and not ip.startswith("127."):
                return SubdomainResult(
                    subdomain=subdomain_part,
                    domain=domain_part,
                    full_domain=full_domain,
                    resolved_ips=[ip],
                    record_type="A",
                )
        except Exception:
            pass

        return None
    except Exception:
        return None


async def scan(
    domain: str,
    subdomains: list[str] | None = None,
    *,
    timeout: float = 3.0,
    concurrency: int = 50,
) -> SubdomainReport:
    """
    Enumerate subdomains of a given domain using DNS resolution.

    Args:
        domain: Domain to scan (e.g. "example.com").
        subdomains: Custom subdomain list. If None, uses built-in COMMON_SUBDOMAINS.
        timeout: Seconds per DNS query.
        concurrency: Max simultaneous DNS lookups.

    Returns a SubdomainReport with all found subdomains.
    """
    if subdomains is None:
        subdomains = COMMON_SUBDOMAINS

    # Clean domain (shared with scan_passive / scan_combined)
    domain = _clean_domain(domain)

    semaphore = asyncio.Semaphore(concurrency)
    start = asyncio.get_event_loop().time()

    async def _limited(sub: str) -> SubdomainResult | None:
        async with semaphore:
            full = f"{sub}.{domain}"
            return await _resolve_subdomain(full, timeout=timeout)

    tasks = [_limited(s) for s in subdomains]
    raw_results = await asyncio.gather(*tasks)

    duration = asyncio.get_event_loop().time() - start
    found = [r for r in raw_results if r is not None]

    return SubdomainReport(
        domain=domain,
        total_checked=len(subdomains),
        found=len(found),
        results=found,
        duration_seconds=round(duration, 2),
    )


async def scan_passive(
    domain: str,
    timeout: float = 10.0,
    *,
    max_resolve: int = 200,
    resolve_concurrency: int = 30,
    resolve_timeout: float = 3.0,
) -> SubdomainReport:
    """
    Passively enumerate subdomains from public sources.

    Queries crt.sh (certificate transparency) and the Wayback Machine CDX
    API in parallel, normalizes + deduplicates the discovered hostnames,
    then validates up to ``max_resolve`` of them via DNS resolution
    (``_resolve_subdomain``, bounded by ``resolve_concurrency``).

    Source independence: if one source fails, the other still contributes
    and the failure is recorded in ``report.errors`` — this function never
    raises.  Hosts that fail DNS validation (or fall past ``max_resolve``)
    are still reported as passive findings with ``resolved_ips=[]`` and
    ``record_type=None``.

    Args:
        domain: Domain to scan (e.g. "example.com").
        timeout: Per-source HTTP timeout.
        max_resolve: Cap on how many discovered hosts get DNS validation.
        resolve_concurrency: Max simultaneous DNS lookups.
        resolve_timeout: Seconds per DNS query.

    Returns a SubdomainReport with all passively discovered subdomains.
    """
    domain = _clean_domain(domain)
    loop = asyncio.get_running_loop()
    start = loop.time()

    # Each source fails independently: a broken source degrades to an
    # error note instead of aborting the whole scan.
    crtsh_subs, crtsh_err = await asyncio.to_thread(_fetch_crtsh, domain, timeout)
    wayback_subs, wayback_err = await asyncio.to_thread(_fetch_wayback, domain, timeout)

    sources: list[str] = []
    errors: list[str] = []
    if crtsh_err is None:
        sources.append("crt.sh")
    else:
        errors.append(crtsh_err)
    if wayback_err is None:
        sources.append("wayback")
    else:
        errors.append(wayback_err)

    discovered = sorted(crtsh_subs | wayback_subs)

    # Bounded, concurrent DNS validation of the discovered hostnames.
    semaphore = asyncio.Semaphore(resolve_concurrency)

    async def _limited(name: str) -> SubdomainResult | None:
        async with semaphore:
            return await _resolve_subdomain(name, timeout=resolve_timeout)

    to_resolve = discovered[:max_resolve]
    raw = await asyncio.gather(*(_limited(n) for n in to_resolve))
    resolved = {r.full_domain: r for r in raw if r is not None}

    # Everything discovered is a valid passive finding; resolution is
    # best-effort metadata only.
    results: list[SubdomainResult] = []
    for name in discovered:
        r = resolved.get(name)
        if r is not None:
            results.append(r)
        else:
            results.append(SubdomainResult(
                subdomain=name.split(".", 1)[0],
                domain=domain,
                full_domain=name,
                resolved_ips=[],
                record_type=None,
            ))

    duration = loop.time() - start
    return SubdomainReport(
        domain=domain,
        total_checked=len(discovered),
        found=len(discovered),
        results=results,
        duration_seconds=round(duration, 2),
        sources=sources,
        errors=errors,
    )


async def scan_combined(
    domain: str,
    subdomains: list[str] | None = None,
    *,
    timeout: float = 3.0,
    concurrency: int = 50,
    passive_timeout: float = 10.0,
) -> SubdomainReport:
    """
    Active brute-force + passive OSINT sweep, merged and deduplicated.

    Runs ``scan`` (DNS brute-force) and ``scan_passive`` concurrently,
    then merges the results by ``full_domain``.  When a host was found by
    both, the result carrying resolved IPs wins (active results almost
    always have them; passive fallbacks for unresolved hosts never
    overwrite a resolved hit).

    Args:
        domain: Domain to scan (e.g. "example.com").
        subdomains: Custom brute-force wordlist. If None, uses the built-in
            COMMON_SUBDOMAINS.
        timeout / concurrency: Brute-force DNS parameters (see ``scan``).
        passive_timeout: Per-source HTTP timeout for the passive pass.

    Returns a merged SubdomainReport. ``total_checked`` = brute checks +
    passively discovered hosts the brute pass missed; ``found`` = unique
    merged total. ``sources``/``errors`` propagate from the passive pass.
    """
    domain = _clean_domain(domain)
    loop = asyncio.get_running_loop()
    start = loop.time()

    brute, passive = await asyncio.gather(
        scan(domain, subdomains=subdomains, timeout=timeout, concurrency=concurrency),
        scan_passive(domain, timeout=passive_timeout),
    )

    # Merge by full_domain, prioritizing the result with resolved IPs.
    merged: dict[str, SubdomainResult] = {}
    for r in brute.results:
        merged[r.full_domain] = r

    new_passive = 0
    for r in passive.results:
        existing = merged.get(r.full_domain)
        if existing is None:
            merged[r.full_domain] = r
            new_passive += 1
        elif not existing.resolved_ips and r.resolved_ips:
            merged[r.full_domain] = r

    results = sorted(merged.values(), key=lambda x: x.full_domain)
    duration = loop.time() - start

    return SubdomainReport(
        domain=domain,
        total_checked=brute.total_checked + new_passive,
        found=len(results),
        results=results,
        duration_seconds=round(duration, 2),
        sources=list(passive.sources),
        errors=list(passive.errors),
    )


def report_to_mirv_findings(report: SubdomainReport) -> list[dict]:
    """Convert a SubdomainReport into MIRV findings list."""
    if report.found == 0:
        return [{
            "tool": "subdomain-scan",
            "severity": "info",
            "title": f"No subdomains found for {report.domain}",
            "detail": (
                f"Domain: {report.domain}\n"
                f"Subdomains checked: {report.total_checked}\n"
                f"Duration: {report.duration_seconds}s"
            ),
            "target": report.domain,
            "type": "tech",
        }]

    findings = []
    for r in sorted(report.results, key=lambda x: x.subdomain):
        ips_str = ", ".join(r.resolved_ips)
        cname_info = f"\nCNAME: {r.cname_target}" if r.cname_target else ""
        findings.append({
            "tool": "subdomain-scan",
            "severity": "info",
            "title": f"{r.full_domain} — {ips_str}",
            "detail": (
                f"Subdomain: {r.subdomain}\n"
                f"Full: {r.full_domain}\n"
                f"IPs: {ips_str}{cname_info}"
            ),
            "target": report.domain,
            "type": "tech",
            "extra": {
                "subdomain": r.subdomain,
                "ips": r.resolved_ips,
                "cname": r.cname_target,
            },
        })

    # Summary
    findings.append({
        "tool": "subdomain-scan",
        "severity": "info",
        "title": f"Scan complete — {report.found} subdomains found of {report.total_checked} checked",
        "detail": (
            f"Domain: {report.domain}\n"
            f"Subdomains checked: {report.total_checked}\n"
            f"Found: {report.found}\n"
            f"Duration: {report.duration_seconds}s"
        ),
        "target": report.domain,
        "type": "tech",
        "extra": {
            "found": report.found,
            "checked": report.total_checked,
            "duration": report.duration_seconds,
        },
    })

    return findings
