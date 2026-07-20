"""
dlp_scanner.py — MIRV Module

Data Loss Prevention / PII Detection Scanner.

Scans text, files, and URLs for personally identifiable information (PII),
financial data, credentials, and other sensitive patterns. Returns structured
reports with risk scoring for integration into MIRV findings.

Patterns cover: credit cards (Luhn-validated), SSNs, emails, phones,
IP addresses, API keys, passports, and IBANs.
"""

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Literal

import httpx

# ── Logger ──
logger = logging.getLogger("vulnforge.dlp")


# ── Data classes ──

@dataclass
class DLPFinding:
    """A single DLP / PII detection."""
    pattern_name: str     # e.g. "credit-card", "ssn", "email"
    severity: str         # "high" | "medium" | "low"
    value: str            # The matched text (truncated for display)
    line: int             # Line number (1-based)
    column: int           # Column position (0-based offset within line)
    context: str          # Surrounding text (~50 chars before/after)
    recommendation: str   # What to do


@dataclass
class DLPReport:
    """Full DLP scan report."""
    source: str           # "text" | "file" | "url"
    source_name: str      # filename or URL or "raw_input"
    content_length: int
    lines_scanned: int
    findings: list[DLPFinding]
    duration_seconds: float
    risk_score: float     # 0.0 to 100.0


# ── Regex Patterns ──
# (name, regex, severity, recommendation)
# Sorted by severity (high → medium → low).

PATTERNS: list[tuple[str, str, str, str]] = [
    # ── HIGH ──────────────────────────────────────────────────
    (
        "credit-card",
        r'\b(?:\d[ -]*?){13,16}\b',
        "high",
        "Credit card numbers must be encrypted or masked. PCI-DSS compliance required.",
    ),
    (
        "ssn",
        r'\b\d{3}-\d{2}-\d{4}\b',
        "high",
        "Social Security Numbers must be removed or tokenized.",
    ),
    (
        "api-key",
        r'(?i)(?:sk|pk|api[_-]?key|secret|token|password)[\s:=]+[''"]?[\w\-]{16,}[''"]?',
        "high",
        "Hardcoded API keys/secrets are a security risk.",
    ),
    (
        "passport",
        r'\b[A-Z]{1,2}\d{6,9}\b',
        "high",
        "Passport numbers are sensitive PII.",
    ),

    # ── MEDIUM ────────────────────────────────────────────────
    (
        "email",
        r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b',
        "medium",
        "Email addresses may be subject to GDPR/CCPA regulations.",
    ),
    (
        "phone",
        r'\b(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        "medium",
        "Phone numbers are PII under most regulations.",
    ),
    (
        "iban",
        r'\b[A-Z]{2}\d{2}[\s-]?[\dA-Z]{4,30}\b',
        "medium",
        "Bank account numbers (IBAN) are financial PII.",
    ),

    # ── LOW ───────────────────────────────────────────────────
    (
        "ipv4",
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "low",
        "Internal IP addresses may leak network topology.",
    ),
]

# Pre-compile all patterns
_COMPILED: list[tuple[str, re.Pattern, str, str]] = [
    (name, re.compile(regex, re.MULTILINE), severity, rec)
    for name, regex, severity, rec in PATTERNS
]


# ── Private IP ranges ──

_PRIVATE_IP_RE = re.compile(
    r'^(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'         # 10.0.0.0/8
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'  # 172.16.0.0/12
    r'|192\.168\.\d{1,3}\.\d{1,3}'             # 192.168.0.0/16
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'        # 127.0.0.0/8 (loopback)
    r'|0\.\d{1,3}\.\d{1,3}\.\d{1,3}'          # 0.0.0.0/8
    r')$'
)


# ── Helpers ──

def _luhn_check(num: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm.

    Args:
        num: Digits only (spaces/dashes stripped automatically).

    Returns:
        True if the number passes the Luhn check.
    """
    digits = re.sub(r'[\s\-]', '', num)
    if not digits.isdigit() or len(digits) < 13:
        return False

    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _get_context(text: str, start: int, end: int, window: int = 50) -> str:
    """
    Extract surrounding context around a match.

    Args:
        text: Full content string.
        start: Match start index.
        end: Match end index.
        window: Characters before/after to include.

    Returns:
        Trimmed context string with newlines collapsed.
    """
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    ctx = text[ctx_start:ctx_end]
    # Collapse newlines for single-line context
    ctx = re.sub(r'\s*\n\s*', ' ', ctx).strip()
    return ctx


def _is_valid_match(pattern_name: str, value: str) -> bool:
    """
    Post-match validation for patterns that need extra checks.

    - credit-card: must pass Luhn
    - ipv4: must have each octet in 0-255
    """
    if pattern_name == "credit-card":
        return _luhn_check(value)

    if pattern_name == "ipv4":
        octets = value.split('.')
        for octet in octets:
            try:
                if int(octet) > 255:
                    return False
            except ValueError:
                return False
        return True

    return True


def _adjust_severity(pattern_name: str, severity: str, value: str) -> str:
    """
    Adjust severity for specific patterns based on context.

    - IPv4 in private ranges → downgrade to "info"
    """
    if pattern_name == "ipv4" and _PRIVATE_IP_RE.match(value):
        return "info"
    return severity


def _calculate_risk_score(findings: list[DLPFinding]) -> float:
    """
    Calculate a risk score from 0.0 to 100.0 based on findings.

    Scoring: high = 10 pts, medium = 5 pts, low = 1 pt, info = 0 pts.
    Score is capped at 100.0.
    """
    weights = {"high": 10, "medium": 5, "low": 1, "info": 0}
    score = sum(weights.get(f.severity, 0) for f in findings)
    return min(float(score), 100.0)


def _strings_like(data: bytes, min_length: int = 4) -> str:
    """
    Extract printable ASCII strings from binary data (like Unix `strings`).

    Args:
        data: Raw bytes.
        min_length: Minimum string length to extract.

    Returns:
        Newline-separated printable strings.
    """
    result = []
    current: list[int] = []
    for byte in data:
        if 32 <= byte <= 126 or byte in (9, 10, 13):  # printable + whitespace
            current.append(byte)
        else:
            if len(current) >= min_length:
                result.append(bytes(current).decode('ascii', errors='ignore'))
            current = []
    if len(current) >= min_length:
        result.append(bytes(current).decode('ascii', errors='ignore'))
    return '\n'.join(result)


# ── Core scanning functions ──

def scan_text(text: str, source: str = "raw_input") -> DLPReport:
    """
    Scan plain text for PII / sensitive data patterns.

    Args:
        text: The text content to scan.
        source: Source label ("raw_input", filename, or URL).

    Returns:
        DLPReport with all findings and risk score.
    """
    start_time = time.time()
    lines = text.split('\n')
    findings: list[DLPFinding] = []
    seen: set[tuple[str, int]] = set()  # (pattern_name, line) dedup

    for line_idx, line in enumerate(lines):
        line_num = line_idx + 1
        for pattern_name, compiled_re, severity, recommendation in _COMPILED:
            for match in compiled_re.finditer(line):
                value = match.group(0)

                # Dedup: same pattern + same line = skip
                dedup_key = (pattern_name, line_num, value)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                # Post-match validation
                if not _is_valid_match(pattern_name, value):
                    continue

                # Adjust severity
                final_severity = _adjust_severity(pattern_name, severity, value)

                # Context: 50 chars before/after within the line
                col = match.start()
                ctx_start = max(0, col - 50)
                ctx_end = min(len(line), match.end() + 50)
                context = line[ctx_start:ctx_end].strip()

                findings.append(DLPFinding(
                    pattern_name=pattern_name,
                    severity=final_severity,
                    value=value[:128],  # truncate long matches
                    line=line_num,
                    column=col,
                    context=context,
                    recommendation=recommendation,
                ))

    duration = time.time() - start_time
    risk_score = _calculate_risk_score(findings)

    logger.info(
        "DLP scan complete: source=%s lines=%d findings=%d risk=%.1f duration=%.3fs",
        source, len(lines), len(findings), risk_score, duration,
    )

    return DLPReport(
        source="text",
        source_name=source,
        content_length=len(text),
        lines_scanned=len(lines),
        findings=findings,
        duration_seconds=round(duration, 4),
        risk_score=risk_score,
    )


def scan_file(file_bytes: bytes, filename: str) -> DLPReport:
    """
    Scan a file's contents for PII / sensitive data.

    Tries UTF-8 decoding first. Falls back to extracting readable strings
    from binary data.

    Args:
        file_bytes: Raw file bytes.
        filename: Original filename for reporting.

    Returns:
        DLPReport with findings.
    """
    start_time = time.time()

    # Try UTF-8 first
    try:
        text = file_bytes.decode('utf-8')
    except (UnicodeDecodeError, ValueError):
        # Try latin-1 as fallback (never fails on bytes)
        try:
            text = file_bytes.decode('latin-1')
        except Exception:
            # Last resort: extract strings from binary
            text = _strings_like(file_bytes)

    report = scan_text(text, source=filename)
    # Override source type
    report.source = "file"
    # Recalculate duration including decode time
    report.duration_seconds = round(time.time() - start_time, 4)

    return report


async def scan_url(url: str) -> DLPReport:
    """
    Download a URL and scan its content for PII / sensitive data.

    Args:
        url: The URL to fetch and scan.

    Returns:
        DLPReport with findings.

    Raises:
        httpx.RequestError: On network/HTTP failure.
        ValueError: On empty or oversized response.
    """
    start_time = time.time()
    max_bytes = 5 * 1024 * 1024  # 5 MB

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=5),
    ) as client:
        response = await client.get(
            url,
            headers={"User-Agent": "MIRV-DLP-Scanner/1.0"},
        )
        response.raise_for_status()

        # Check size
        content = response.content
        if len(content) > max_bytes:
            # Truncate to max size
            content = content[:max_bytes]

        text = content.decode('utf-8', errors='replace')

    report = scan_text(text, source=url)
    report.source = "url"
    report.duration_seconds = round(time.time() - start_time, 4)

    return report


# ── MIRV integration ──

def report_to_mirv_findings(report: DLPReport) -> list[dict]:
    """
    Convert a DLPReport into MIRV-compatible findings list.

    Each DLPFinding becomes a dict with tool, severity, title, detail,
    target, type, and extra metadata. Results are sorted by severity
    (high first).

    Args:
        report: The DLP scan report.

    Returns:
        List of MIRV finding dicts.
    """
    SEV_MAP = {"high": "high", "medium": "medium", "low": "low", "info": "info"}
    findings: list[dict] = []

    for f in report.findings:
        mirv_sev = SEV_MAP.get(f.severity, "info")
        # Mask the actual value for display — show only first/4 last chars
        masked = f.value[:4] + "..." + f.value[-4:] if len(f.value) > 12 else f.value[:4] + "..."

        findings.append({
            "tool": "dlp-scan",
            "severity": mirv_sev,
            "title": f"🛡️ {f.pattern_name.replace('-', ' ').title()} — line {f.line}",
            "detail": (
                f"Pattern: {f.pattern_name}\n"
                f"Severity: {f.severity}\n"
                f"Value (masked): {masked}\n"
                f"Line: {f.line}, Column: {f.column}\n"
                f"Recommendation: {f.recommendation}\n"
                f"Context:\n```\n{f.context}\n```"
            ),
            "target": report.source_name,
            "type": "vuln" if mirv_sev in ("high", "medium") else "info",
            "extra": {
                "pattern": f.pattern_name,
                "line": f.line,
                "column": f.column,
                "risk_score": report.risk_score,
            },
        })

    # Sort by severity (high first)
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 99))

    return findings
