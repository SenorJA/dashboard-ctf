"""
secrets_scanner.py — MIRV Module

Scans text/URLs for hardcoded secrets, API keys, tokens, and credentials.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects

Regex patterns are based on the open-source secret-detection community
(truffleHog, gitleaks, detect-secrets) — all publicly documented for
defensive auditing and educational purposes.

Severity: high for critical credentials, medium for less-critical tokens,
low for informational findings (e.g. JWTs, generic high-entropy strings).
"""

import re
import json
from dataclasses import dataclass, field
from typing import Literal

import httpx

# ── Types ──

Severity = Literal["high", "medium", "low", "info"]
Status = Literal["ok", "exposed"]


# ── Data classes ──

@dataclass(frozen=True, slots=True)
class SecretPattern:
    name: str
    severity: Severity
    description: str
    recommendation: str
    regex: str
    group: int = 1  # which regex capture group holds the secret


@dataclass(frozen=True, slots=True)
class SecretFinding:
    pattern: SecretPattern
    line: int
    match: str
    context: str
    note: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    source: str
    content_length: int
    lines_scanned: int
    findings: list[SecretFinding]


# ── Patterns table ──
# Sorted by severity (high first), then alphabetically.
# Each regex targets the *value* of the secret, not the key, to minimise
# false positives on variable names like `aws_secret_access_key = ""`.

_PATTERNS: list[SecretPattern] = [
    # ── HIGH ──────────────────────────────────────────────────
    SecretPattern(
        name="AWS Access Key ID",
        severity="high",
        description="Amazon Web Services access key ID — grants programmatic AWS API access",
        recommendation="Rotate the key immediately in IAM and remove it from the source. Use environment variables or a secrets manager (AWS Secrets Manager, Vault).",
        regex=r'(?i)aws_access_key_id[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\'\s]',
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        severity="high",
        description="Amazon Web Services secret key — paired with access key ID, grants full API access",
        recommendation="Rotate immediately. Revoke the key in IAM and replace with a temporary role or Secrets Manager reference.",
        regex=r'(?i)aws_secret_access_key[=:]\s*["\']?([A-Za-z0-9/\+=]{40})["\'\s]',
    ),
    SecretPattern(
        name="Azure Service Principal Secret",
        severity="high",
        description="Azure service principal client secret — authenticates automation to Azure resources",
        recommendation="Rotate the secret in Azure AD and use Managed Identity or Key Vault references instead.",
        regex=r'(?i)(AZURE_CLIENT_SECRET|client_secret|ClientSecret)[=:]\s*["\']?([A-Za-z0-9._~\-]{34})["\'\s]',
    ),
    SecretPattern(
        name="Discord Bot Token",
        severity="high",
        description="Discord bot token — allows full control of a Discord bot account",
        recommendation="Regenerate the bot token in Discord Developer Portal and update to use environment variables.",
        regex=r'(?:discord|discord_bot|discordbot)[_\s]?t(?:oken|k)?[=:]\s*["\']?([A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})["\'\s]',
    ),
    SecretPattern(
        name="Facebook OAuth / Access Token",
        severity="high",
        description="Facebook / Meta OAuth access token — grants access to Facebook Graph API",
        recommendation="Rotate the token in Meta Developer console. Use short-lived tokens or server-side exchanges.",
        regex=r'(?i)(?:facebook|fb)[_\s]?(?:access|oauth)?[_\s]?t(?:oken|k)?[=:]\s*["\']?(EAACEdEose0cBA[0-9A-Za-z]+)["\'\s]',
    ),
    SecretPattern(
        name="GitHub Personal Access Token",
        severity="high",
        description="GitHub token — grants access to repositories and API as the owning user",
        recommendation="Revoke the token in GitHub Settings → Developer Settings. Replace with a fine-grained token with minimal scopes or use GitHub Actions secrets.",
        regex=r'(?i)(?:github|gh)[_\s]?(?:token|pat|access_token|api_key)[=:]\s*["\']?(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{82})["\'\s]',
    ),
    SecretPattern(
        name="GitHub OAuth Access Token",
        severity="high",
        description="GitHub OAuth token — used by OAuth apps to access GitHub API on behalf of a user",
        recommendation="Revoke the OAuth app token in GitHub Settings. Replace with a short-lived device flow or PAT with limited scope.",
        regex=r'(?:gho|ghu|ghs)_[0-9a-zA-Z]{36}',
    ),
    SecretPattern(
        name="Google API Key",
        severity="high",
        description="Google Cloud API key — authenticates requests to Google APIs without a service account",
        recommendation="Restrict the key by HTTP referrer, IP, or API in Google Cloud Console. Better yet, use a service account with IAM.",
        regex=r'(?i)AIza[0-9A-Za-z\-_]{35}',
    ),
    SecretPattern(
        name="Heroku API Key",
        severity="high",
        description="Heroku platform API key — full access to Heroku account and apps",
        recommendation="Rotate the key in Heroku Dashboard. Use environment variables or Heroku Config Vars.",
        regex=r'(?i)heroku[_\s]?(?:api[_\s]?)?key[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\'\s]',
    ),
    SecretPattern(
        name="Private SSH / GPG Key",
        severity="high",
        description="Private cryptographic key (SSH or GPG) — if exposed, allows impersonation and decryption",
        recommendation="Revoke the public key from all authorised servers. Generate a new key pair immediately. Never store private keys in source code.",
        regex=r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|GPG)\s+PRIVATE\s+KEY-----',
    ),
    SecretPattern(
        name="Slack Bot / User Token",
        severity="high",
        description="Slack token (xoxb-/xoxp-) — allows access to Slack workspace APIs",
        recommendation="Rotate the token in Slack API Dashboard. Use granular OAuth scopes and never hardcode.",
        regex=r'(xoxb|xoxp|xoxa|xoxr|xoxe|xoxs)[0-9\-]{10,}(?:-[0-9a-zA-Z]{10,})+',
    ),
    SecretPattern(
        name="Telegram Bot Token",
        severity="high",
        description="Telegram Bot API token — full control over a Telegram bot",
        recommendation="Revoke the token via BotFather on Telegram. Store in environment variables.",
        regex=r'(?i)(?:telegram|tg)[_\s]?(?:bot[_\s]?)?token[=:]\s*["\']?([0-9]{8,10}:[0-9A-Za-z_-]{35})["\'\s]',
    ),
    SecretPattern(
        name="Twilio API Key / Secret",
        severity="high",
        description="Twilio API credentials — allows sending SMS, voice, and WhatsApp via Twilio",
        recommendation="Rotate the API key in Twilio Console. Use environment variables and restrict IP ranges.",
        regex=r'(?i)(?:twilio|account_sid|auth_token)[=:]\s*["\']?(AC[0-9a-f]{32}|SK[0-9a-f]{32})["\'\s]',
    ),

    # ── MEDIUM ────────────────────────────────────────────────
    SecretPattern(
        name="Basic Auth Credential (URL)",
        severity="medium",
        description="Inline username:password in URL — sent in cleartext on every request",
        recommendation="Remove credentials from the URL. Use HTTP headers (Authorization: Basic) or a secrets manager.",
        regex=r'https?://[^:/\s]+:([^@/\s]+)@',
    ),
    SecretPattern(
        name="Generic API Key",
        severity="medium",
        description="Generic high-entropy string that looks like an API key in config context",
        recommendation="Verify the key's purpose. Move to environment variables or a vault. If it maps to any service, rotate it.",
        regex=r'(?i)(?:api[_\s]?key|apikey|api[_\s]?secret|secret[_\s]?key)[=:]\s*["\']?([A-Za-z0-9_\-.!@#$%^&*()=+]{20,})["\'\s]',
    ),
    SecretPattern(
        name="Google OAuth Client ID",
        severity="medium",
        description="Google OAuth 2.0 client ID — identifies the app to Google's OAuth servers",
        recommendation="If this is a client-side app, the client ID is public by design. If server-side, restrict to authorised referrers.",
        regex=r'[0-9]{12,}\.apps\.googleusercontent\.com',
    ),
    SecretPattern(
        name="JWT Token (suspected)",
        severity="medium",
        description="JSON Web Token — if a valid signed token leaks, it may grant access to APIs",
        recommendation="Verify the token's validity. If valid, revoke it and re-issue. Never store JWT secrets in source code.",
        regex=r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
    ),
    SecretPattern(
        name="Mailchimp / Mandrill API Key",
        severity="medium",
        description="Mailchimp or Mandrill API key — allows sending emails and managing campaigns",
        recommendation="Rotate the key in Mailchimp Account → Extras → API Keys. Use environment variables.",
        regex=r'(?i)(?:mailchimp|mandrill)[_\s]?(?:api[_\s]?)?key[=:]\s*["\']?([0-9a-f]{32}[-_]?[A-Za-z0-9]{8,16})["\'\s]',
    ),
    SecretPattern(
        name="NPM / Node Auth Token",
        severity="medium",
        description="NPM registry authentication token — allows publishing/installing packages as the user",
        recommendation="Revoke the token in npmjs.com → Access Tokens. Use npm token in .npmrc only locally.",
        regex=r'(?i)(?:npm|node)[_\s]?(?:auth|token|registry)[_\s]?(?:token|key)?[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\'\s]',
    ),
    SecretPattern(
        name="PayPal / Braintree Token",
        severity="medium",
        description="PayPal or Braintree API credentials — allows payment processing",
        recommendation="Rotate the credentials in PayPal Developer Dashboard. Use environment variables and restrict to production IPs.",
        regex=r'(?i)(?:paypal|braintree)[_\s]?(?:access|api)?[_\s]?(?:token|key|secret)[=:]\s*["\']?([A-Za-z0-9_\-.]{20,})["\'\s]',
    ),
    SecretPattern(
        name="PGP / GPG Public Key Block",
        severity="medium",
        description="PGP public key block — not secret itself, but signals nearby private keys or signed data",
        recommendation="Verify no private keys are in the same file. Public keys are safe but should be verified via key servers.",
        regex=r'-----BEGIN\s+PGP\s+(?:PUBLIC|SIGNED)\s+KEY\s*BLOCK-----',
    ),
    SecretPattern(
        name="SendGrid API Key",
        severity="medium",
        description="SendGrid API key — allows sending email via Twilio SendGrid",
        recommendation="Rotate the key in SendGrid Dashboard. Use environment variables and restrict by IP.",
        regex=r'(?i)SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
    ),
    SecretPattern(
        name="Stripe API Key",
        severity="medium",
        description="Stripe API key (sk_live / pk_live / sk_test / pk_test) — payment processing access",
        recommendation="If a live key, rotate immediately in Stripe Dashboard. Use restricted keys and environment variables. Test keys are safe but should not be in source.",
        regex=r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
    ),

    # ── LOW ───────────────────────────────────────────────────
    SecretPattern(
        name="Docker / Compose Env Variable",
        severity="low",
        description="Explicit environment variable assignment in config that might contain secrets",
        recommendation="Replace inline values with ${VAR_NAME} references and supply them via .env file or secrets manager.",
        regex=r'(?i)^\s*[A-Z_]{3,}(?:_KEY|_SECRET|_TOKEN|_PASS|_PASSWORD|_APIKEY)\s*=\s*["\']?.+["\']?\s*$',
    ),
    SecretPattern(
        name="Generic Private Key Header",
        severity="low",
        description="Generic BEGIN PRIVATE KEY header — standard PKCS#8 private key",
        recommendation="If this is a production key, rotate and store in a vault. Never commit private keys to repositories.",
        regex=r'-----BEGIN\s+PRIVATE\s+KEY-----',
    ),
    SecretPattern(
        name="High-Entropy String (64+ chars alphanumeric)",
        severity="low",
        description="Long alphanumeric string that may be a secret or session token",
        recommendation="Verify if the string is a token or simply a hash/identifier. If it grants access, rotate it.",
        regex=r'(?<![A-Za-z0-9])([A-Za-z0-9\-_=+/]{64,100})(?![A-Za-z0-9])',
    ),
    SecretPattern(
        name="Password Field in Code",
        severity="low",
        description="Variable or field named 'password' with a non-empty literal value",
        recommendation="Move to environment variables or a vault. Never hardcode passwords.",
        regex=r'(?i)(?:password|passwd|pwd)[=:]\s*["\']([^"\'\s]{4,})["\']',
    ),
]

# ── Compile all regexes once ──

_COMPILED: list[tuple[SecretPattern, re.Pattern]] = [
    (p, re.compile(p.regex, re.MULTILINE)) for p in _PATTERNS
]


# ── Scanning ──

def scan_text(content: str, source: str = "unknown") -> ScanReport:
    """
    Scan plain text for secret patterns.

    Args:
        content: The text to scan.
        source: A label for the source (e.g. URL, filename).

    Returns a ScanReport with all matches.
    """
    lines = content.split("\n")
    findings: list[SecretFinding] = []

    for pattern, compiled in _COMPILED:
        for match in compiled.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            secret_value = match.group(pattern.group) if (match.lastindex is not None and pattern.group <= match.lastindex) else match.group(0)
            # Capture surrounding context (one line before/after)
            start_line = max(0, line_num - 2)
            end_line = min(len(lines), line_num + 1)
            context_lines = lines[start_line:end_line]
            context = "\n".join(context_lines)

            # Avoid showing the full secret in the finding — show first/last 4 chars
            truncated = secret_value[:4] + "..." + secret_value[-4:] if len(secret_value) > 16 else secret_value[:4] + "..."
            note = f"Found on line {line_num}: `{truncated}`"

            findings.append(SecretFinding(
                pattern=pattern,
                line=line_num,
                match=secret_value,
                context=context.strip(),
                note=note,
            ))

    return ScanReport(
        source=source,
        content_length=len(content),
        lines_scanned=len(lines),
        findings=findings,
    )


async def scan_url(url: str, *, timeout: float = 10.0) -> ScanReport:
    """
    Fetch a URL and scan its HTML/text content for secrets.

    Raises httpx.RequestError on network failure.
    """
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(url, headers={"User-Agent": "MIRV-SecretsScanner/1.0"})
    text = response.text
    return scan_text(text, source=url)


# ── Format findings for MIRV ──

def report_to_mirv_findings(report: ScanReport) -> list[dict]:
    """Convert a ScanReport into MIRV findings list."""
    SEV_MAP = {"high": "high", "medium": "medium", "low": "low", "info": "info"}
    findings = []

    for f in report.findings:
        mirv_sev = SEV_MAP.get(f.pattern.severity, "info")
        findings.append({
            "tool": "secrets-scan",
            "severity": mirv_sev,
            "title": f"🔑 {f.pattern.name} — exposed on line {f.line}",
            "detail": (
                f"Pattern: {f.pattern.name}\n"
                f"Severity: {f.pattern.severity}\n"
                f"Description: {f.pattern.description}\n"
                f"Recommendation: {f.pattern.recommendation}\n"
                f"Context:\n```\n{f.context}\n```"
            ),
            "target": report.source,
            "type": "vuln" if mirv_sev in ("high", "medium") else "tech",
            "extra": {
                "pattern": f.pattern.name,
                "line": f.line,
                "match_truncated": f.note,
            },
        })

    # Sort by severity (high first)
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 99))

    return findings
