"""
http_headers_scanner.py — MIRV Module

Grades HTTP security headers A–F, adapted from:
https://github.com/CarterPerez-dev/Cybersecurity-Projects

Checks: Strict-Transport-Security, Content-Security-Policy,
X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
Permissions-Policy.

Each rule returns a finding with severity (high/medium/low) and
status (ok/weak/missing). Score is weighted 0–100.
"""

import re
from dataclasses import dataclass, field
from typing import Literal

import httpx

# ── Types ──

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]


# ── Data classes ──

@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        total = sum(_SEVERITY_POINTS[r.severity] for r in _RULES)
        if total == 0:
            return 0
        earned = 0.0
        for f in self.findings:
            full = _SEVERITY_POINTS[f.rule.severity]
            if f.status == "ok":
                earned += full
            elif f.status == "weak":
                earned += full / 2
        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 60:
            return "D"
        return "F"


# ── Rules table ──

_RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Tells the browser to ONLY connect over HTTPS for the next N seconds, defeating SSL-stripping attacks",
        recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        must_match=r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Controls which scripts, styles, frames, and connections the browser may load — the strongest XSS defense",
        recommendation="Add a Content-Security-Policy that disallows 'unsafe-inline' and limits sources to trusted origins",
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description="Stops browsers from second-guessing the Content-Type — defeats MIME-sniffing",
        recommendation="Add: X-Content-Type-Options: nosniff",
        must_match="nosniff",
    ),
    HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description="Prevents another site from embedding this page in an iframe, defeating clickjacking attacks",
        recommendation="Add: X-Frame-Options: DENY (or use Content-Security-Policy: frame-ancestors 'none')",
    ),
    HeaderRule(
        header="Referrer-Policy",
        severity="low",
        description="Limits how much of the current URL leaks to other sites when the user clicks an outbound link",
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="low",
        description="Disables browser features the page does not use (camera, microphone, geolocation, etc.)",
        recommendation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
]

_SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}

_USER_AGENT = "MIRV-HeadersScanner/1.0 (+https://github.com/SenorJA/dashboard-ctf)"


# ── Evaluation ──

def evaluate_header(rule: HeaderRule, response_headers: dict[str, str]) -> HeaderFinding:
    """Apply a single HeaderRule to a set of response headers."""
    target = rule.header.lower()
    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule=rule, status="missing", actual_value=None,
            note=f"Header `{rule.header}` is not set",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule, status="ok", actual_value=actual_value,
            note="Present",
        )

    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule=rule, status="ok", actual_value=actual_value,
            note=f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule=rule, status="weak", actual_value=actual_value,
        note=f"Present but does not match `{rule.must_match}` (got `{actual_value}`)",
    )


# ── Scan ──

async def scan(url: str, *, timeout: float = 10.0) -> ScanReport:
    """
    Fetch URL and grade its response headers.

    Returns ScanReport with findings, score, and grade.
    Raises httpx.RequestError on network failure.
    """
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(url, headers={"User-Agent": _USER_AGENT})

    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in _RULES]

    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
    )


# ── Format findings for MIRV ──

def report_to_mirv_findings(report: ScanReport) -> list[dict]:
    """Convert a ScanReport into MIRV findings list."""
    SEV_MAP = {"high": "high", "medium": "medium", "low": "low"}
    findings = []
    for f in report.findings:
        mirv_sev = SEV_MAP[f.rule.severity]
        title = f"{f.rule.header}"
        if f.status == "missing":
            title += " — MISSING"
            mirv_sev = f.rule.severity
        elif f.status == "weak":
            title += " — WEAK"
            mirv_sev = f.rule.severity
        else:
            title += " — OK"
            mirv_sev = "info"

        detail = f.rule.description
        if f.note and f.note != "Present":
            detail += f" | {f.note}"
        if f.status != "ok":
            detail += f"\nRecommendation: {f.rule.recommendation}"

        findings.append({
            "tool": "headers-scan",
            "severity": mirv_sev,
            "title": title,
            "detail": detail,
            "target": report.final_url,
            "type": "vuln" if f.status != "ok" else "tech",
            "extra": {
                "header": f.rule.header,
                "status": f.status,
                "actual_value": f.actual_value,
                "score": report.score,
                "grade": report.grade,
            },
        })

    # Add a summary finding with the overall grade
    findings.append({
        "tool": "headers-scan",
        "severity": "info",
        "title": f"Overall Grade: {report.grade} (Score: {report.score}/100)",
        "detail": (
            f"URL: {report.final_url}\n"
            f"HTTP Status: {report.status_code}\n"
            f"Score: {report.score}/100 — Grade: {report.grade}\n"
            f"Headers checked: {len(_RULES)}"
        ),
        "target": report.final_url,
        "type": "tech",
        "extra": {"score": report.score, "grade": report.grade},
    })

    return findings
