"""
subdomain_scanner.py — MIRV Module

Asynchronous subdomain enumerator via DNS resolution.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects

Uses asyncio + concurrent DNS lookups against a built-in wordlist
of common subdomain prefixes.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Literal


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

    # Clean domain
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

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
