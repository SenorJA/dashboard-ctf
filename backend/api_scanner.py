"""
api_scanner.py — MIRV Module

API Security Scanner — probes REST API endpoints for common
misconfigurations, missing security headers, CORS issues,
information disclosure, and common sensitive paths.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects
"""

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

# ── Common API paths to probe ──

COMMON_API_PATHS: list[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/v1/users",
    "/api/admin", "/api/v1/admin",
    "/api/health", "/health", "/api/healthz",
    "/api/status", "/status",
    "/api/config", "/api/v1/config",
    "/api/auth", "/api/v1/auth",
    "/api/login", "/api/v1/login",
    "/api/token", "/api/v1/token",
    "/api/keys", "/api/v1/keys",
    "/api/secret", "/api/v1/secret",
    "/api/info", "/api/v1/info",
    "/api/version", "/version",
    "/api/swagger", "/swagger", "/api/docs", "/docs",
    "/api/openapi.json", "/openapi.json",
    "/api/graphql", "/graphql",
    "/api/debug", "/api/v1/debug",
    "/api/logs", "/api/v1/logs",
    "/api/backup", "/api/v1/backup",
    "/api/dump", "/api/v1/dump",
    "/.env", "/api/.env",
    "/robots.txt", "/sitemap.xml",
    "/.git/config", "/api/.git/config",
    "/actuator", "/actuator/health", "/actuator/info",  # Spring Boot
    "/api/graphql?query={__schema{types{name}}}",  # GraphQL introspection
]

# ── Common paths to check for public access ──

SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "api_key", "apikey",
    "auth", "jwt", "bearer", "session", "cookie",
]

MISSING_SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security (HSTS)"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-xss-protection", "X-XSS-Protection"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
]

INFO_DISCLOSURE_HEADERS = [
    ("server", "Server version disclosure"),
    ("x-powered-by", "X-Powered-By disclosure"),
    ("x-aspnet-version", "ASP.NET version"),
    ("x-aspnetmvc-version", "ASP.NET MVC version"),
]


# ── Data classes ──

@dataclass(frozen=True, slots=True)
class ApiEndpoint:
    path: str
    method: str
    status_code: int
    content_length: int
    response_time: float
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    authenticated: bool = False  # whether it seems to require auth


@dataclass(frozen=True, slots=True)
class ApiIssue:
    severity: str  # high, medium, low, info
    title: str
    detail: str
    endpoint: str | None = None
    category: str = "config"


@dataclass(frozen=True, slots=True)
class ApiScanReport:
    base_url: str
    endpoints_scanned: int
    issues: list[ApiIssue]
    open_endpoints: list[ApiEndpoint]  # endpoints that returned 200
    duration_seconds: float
    cors_enabled: bool = False
    auth_required: bool = False
    missing_headers: list[str] = field(default_factory=list)
    info_disclosures: list[str] = field(default_factory=list)


# ── Helpers ──

def _normalize_url(url: str) -> str:
    """Normalize a URL to have a scheme and no trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def _check_security_headers(headers: dict) -> tuple[list[str], list[str]]:
    """Check response headers for security issues."""
    missing = []
    disclosures = []
    for h, name in MISSING_SECURITY_HEADERS:
        if h not in {k.lower() for k in headers}:
            missing.append(name)
    for h, name in INFO_DISCLOSURE_HEADERS:
        val = next((v for k, v in headers.items() if k.lower() == h), None)
        if val:
            disclosures.append(f"{name}: {val}")
    return missing, disclosures


def _check_cors(headers: dict) -> bool:
    """Check if CORS allows all origins."""
    acao = next((v for k, v in headers.items() if k.lower() == "access-control-allow-origin"), None)
    return acao == "*"


def _check_sensitive_data(body: str) -> list[str]:
    """Check response body for sensitive data patterns."""
    found = []
    body_lower = body.lower()
    for kw in SENSITIVE_KEYWORDS:
        if kw in body_lower:
            found.append(kw)
    return found


# ── Scan logic ──

async def _probe_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    method: str = "GET",
    timeout: float = 10.0,
) -> ApiEndpoint | None:
    """Probe a single API endpoint."""
    url = urljoin(base_url, path)
    try:
        start = time.monotonic()
        resp = await client.request(method, url, timeout=timeout, follow_redirects=False)
        elapsed = time.monotonic() - start
        body = resp.text[:500] if resp.text else ""

        # Check if body has auth-related content
        # (not a perfect heuristic, but useful)
        return ApiEndpoint(
            path=path,
            method=method,
            status_code=resp.status_code,
            content_length=len(resp.content),
            response_time=round(elapsed, 3),
            headers=dict(resp.headers),
            body_preview=body,
        )
    except httpx.TimeoutException:
        return None
    except Exception:
        return None


async def scan(
    url: str,
    *,
    paths: list[str] | None = None,
    timeout: float = 10.0,
    concurrency: int = 10,
) -> ApiScanReport:
    """
    Scan an API endpoint for security issues.

    Args:
        url: Base URL of the API (e.g., "https://example.com/api").
        paths: Custom paths to scan (defaults to COMMON_API_PATHS).
        timeout: HTTP timeout per request.
        concurrency: Max concurrent requests.

    Returns an ApiScanReport.
    """
    start = time.monotonic()
    base_url = _normalize_url(url)
    scan_paths = paths or COMMON_API_PATHS
    issues: list[ApiIssue] = []
    open_endpoints: list[ApiEndpoint] = []

    # Initial probe to check base URL connectivity + security headers
    async with httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
    ) as client:
        # 1. Probe base URL
        base_result = await _probe_endpoint(client, base_url, "/", "GET", timeout)
        if base_result is None:
            base_result = await _probe_endpoint(client, base_url, "", "GET", timeout)

        if base_result is None:
            return ApiScanReport(
                base_url=base_url,
                endpoints_scanned=0,
                issues=[ApiIssue(
                    severity="high",
                    title="API not reachable",
                    detail=f"The base URL {base_url} did not respond within {timeout}s",
                    category="connectivity",
                )],
                open_endpoints=[],
                duration_seconds=0.0,
            )

        # Check base headers
        missing_h, disclosures = _check_security_headers(base_result.headers)
        cors_all = _check_cors(base_result.headers)

        if missing_h:
            issues.append(ApiIssue(
                severity="medium",
                title="Missing security headers",
                detail=f"The following {len(missing_h)} security headers are missing:\n" + "\n".join(f"  - {h}" for h in missing_h),
                endpoint="/",
                category="headers",
            ))

        for d in disclosures:
            issues.append(ApiIssue(
                severity="low",
                title=d,
                detail=f"The response header reveals: {d}",
                endpoint="/",
                category="disclosure",
            ))

        if cors_all:
            issues.append(ApiIssue(
                severity="medium",
                title="CORS allows all origins (*)",
                detail="The API returns Access-Control-Allow-Origin: *, allowing any website to make cross-origin requests.",
                endpoint="/",
                category="cors",
            ))

        # 2. Probe common paths
        sem = asyncio.Semaphore(concurrency)

        async def _probe_with_sem(p: str) -> ApiEndpoint | None:
            async with sem:
                return await _probe_endpoint(client, base_url, p, "GET", timeout)

        tasks = [_probe_with_sem(p) for p in scan_paths]
        results = await asyncio.gather(*tasks)

        endpoints_scanned = 0
        for path, result in zip(scan_paths, results):
            if result is None:
                continue
            endpoints_scanned += 1
            if result.status_code == 200:
                open_endpoints.append(result)
                # Check for sensitive data
                sensitive = _check_sensitive_data(result.body_preview)
                if sensitive:
                    issues.append(ApiIssue(
                        severity="high",
                        title=f"Sensitive data exposed at {path}",
                        detail=f"Keywords found in response: {', '.join(sensitive)}\nResponse preview: {result.body_preview[:200]}",
                        endpoint=path,
                        category="data_exposure",
                    ))
                else:
                    issues.append(ApiIssue(
                        severity="medium",
                        title=f"Open endpoint: {result.method} {path} → {result.status_code}",
                        detail=f"Path returned {result.status_code} ({result.content_length} bytes). This may expose information.",
                        endpoint=path,
                        category="exposure",
                    ))

            elif result.status_code in (401, 403):
                issues.append(ApiIssue(
                    severity="info",
                    title=f"Protected endpoint: {path} → {result.status_code}",
                    detail=f"Path returns {result.status_code} — authentication required.",
                    endpoint=path,
                    category="auth",
                ))

            elif result.status_code in (301, 302, 307, 308):
                loc = result.headers.get("location", "")
                issues.append(ApiIssue(
                    severity="low",
                    title=f"Redirect: {path} → {result.status_code} to {loc}",
                    detail=f"Path redirects to {loc}",
                    endpoint=path,
                    category="config",
                ))

        # 3. Try OPTIONS on base to check allowed methods
        options_result = await _probe_endpoint(client, base_url, "/", "OPTIONS", timeout)
        if options_result and options_result.status_code in (200, 204):
            allow = options_result.headers.get("allow", "")
            if "PUT" in allow and "DELETE" in allow:
                issues.append(ApiIssue(
                    severity="medium",
                    title="Dangerous HTTP methods enabled",
                    detail=f"OPTIONS reveals: Allow: {allow}. PUT and DELETE should be restricted.",
                    endpoint="/",
                    category="config",
                ))

    # Sort open endpoints by path
    open_endpoints.sort(key=lambda e: e.path)

    # Deduplicate similar issues
    seen_issues = set()
    unique_issues = []
    for issue in issues:
        key = (issue.category, issue.title)
        if key not in seen_issues:
            seen_issues.add(key)
            unique_issues.append(issue)

    duration = time.monotonic() - start

    return ApiScanReport(
        base_url=base_url,
        endpoints_scanned=endpoints_scanned,
        issues=unique_issues,
        open_endpoints=open_endpoints,
        duration_seconds=round(duration, 2),
        cors_enabled=cors_all,
        auth_required=any(i.category == "auth" for i in unique_issues),
        missing_headers=missing_h,
        info_disclosures=disclosures,
    )


def report_to_mirv_findings(report: ApiScanReport) -> list[dict]:
    """Convert ApiScanReport into MIRV findings list."""
    findings = []

    # Summary
    findings.append({
        "tool": "api-scanner",
        "severity": "info",
        "title": f"API Scan: {report.endpoints_scanned} endpoints, {len(report.issues)} issues in {report.duration_seconds}s",
        "detail": (
            f"Base URL: {report.base_url}\n"
            f"Endpoints scanned: {report.endpoints_scanned}\n"
            f"Issues found: {len(report.issues)}\n"
            f"Open endpoints: {len(report.open_endpoints)}\n"
            f"CORS all origins: {'Yes' if report.cors_enabled else 'No'}\n"
            f"Duration: {report.duration_seconds}s"
        ),
        "target": report.base_url,
        "type": "tech",
        "extra": {
            "endpoints_scanned": report.endpoints_scanned,
            "issues_count": len(report.issues),
            "open_endpoints": len(report.open_endpoints),
            "cors_enabled": report.cors_enabled,
        },
    })

    # Open endpoints
    for ep in report.open_endpoints:
        findings.append({
            "tool": "api-scanner",
            "severity": "medium",
            "title": f"Open: {ep.method} {ep.path} → {ep.status_code}",
            "detail": (
                f"Path: {ep.path}\n"
                f"Method: {ep.method}\n"
                f"Status: {ep.status_code}\n"
                f"Size: {ep.content_length} bytes\n"
                f"Time: {ep.response_time}s"
            ),
            "target": report.base_url,
            "type": "vuln",
            "extra": {
                "path": ep.path,
                "method": ep.method,
                "status": ep.status_code,
                "content_length": ep.content_length,
            },
        })

    # Issues
    for issue in report.issues:
        findings.append({
            "tool": "api-scanner",
            "severity": issue.severity,
            "title": issue.title,
            "detail": issue.detail,
            "target": report.base_url,
            "type": "vuln" if issue.severity in ("high", "medium") else "tech",
            "extra": {
                "category": issue.category,
                "endpoint": issue.endpoint,
            },
        })

    return findings
