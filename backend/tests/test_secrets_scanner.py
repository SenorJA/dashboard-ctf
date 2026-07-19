"""
Unit tests for backend/secrets_scanner.py

Covers:
  - scan_text() with known secret patterns (AWS, Stripe, GitHub, SSH keys, etc.)
  - scan_text() with clean text (no findings expected)
  - scan_url() async — valid URL response shape
  - scan_url() async — invalid / unreachable URL error handling
"""

from __future__ import annotations

import pytest
import httpx

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secrets_scanner import (
    scan_text,
    scan_url,
    ScanReport,
    SecretFinding,
    SecretPattern,
    report_to_mirv_findings,
    _PATTERNS,
)


# ===================================================================
# 1. scan_text — known high-severity patterns
# ===================================================================

class TestScanTextHighSeverity:
    """Each test injects a realistic secret string and verifies detection.

    NOTE: The module's regex patterns require ``[=:]`` **immediately**
    after the identifier (no space before the delimiter).  Test strings
    therefore use ``key="value"`` or ``key:value`` format.
    """

    def test_stripe_api_key(self):
        """sk_test_ prefix triggers the Stripe API Key pattern (standalone)."""
        key = "sk_test_DUMMYKEY_DUMMYKEY_DUMMY"
        text = f"payment_key={key}"
        report = scan_text(text, source="test")

        assert isinstance(report, ScanReport)
        assert report.source == "test"
        assert report.lines_scanned == 1
        assert report.content_length == len(text)

        names = [f.pattern.name for f in report.findings]
        assert "Stripe API Key" in names

        stripe_finding = next(f for f in report.findings if f.pattern.name == "Stripe API Key")
        assert stripe_finding.line == 1
        assert stripe_finding.match == key
        assert stripe_finding.context == text
        assert stripe_finding.pattern.severity == "medium"

    def test_aws_access_key_id(self):
        """AKIA prefix inside aws_access_key_id= triggers detection."""
        text = 'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"'
        report = scan_text(text, source="config.yaml")

        names = [f.pattern.name for f in report.findings]
        assert "AWS Access Key ID" in names

        aws_finding = next(f for f in report.findings if f.pattern.name == "AWS Access Key ID")
        assert aws_finding.match == "AKIAIOSFODNN7EXAMPLE"
        assert aws_finding.pattern.severity == "high"
        assert aws_finding.line == 1

    def test_aws_secret_access_key(self):
        """A 40-char base64 value after aws_secret_access_key= should match."""
        secret_value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f'aws_secret_access_key="{secret_value}"'
        report = scan_text(text, source="config.yaml")

        names = [f.pattern.name for f in report.findings]
        assert "AWS Secret Access Key" in names

        finding = next(f for f in report.findings if f.pattern.name == "AWS Secret Access Key")
        assert finding.pattern.severity == "high"
        assert finding.match == secret_value

    def test_github_personal_access_token(self):
        """github_token= with ghp_ prefix (36 chars after ghp_) triggers detection."""
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"  # 36 chars after ghp_
        text = f'github_token="{token}"'
        report = scan_text(text, source="env.sh")

        names = [f.pattern.name for f in report.findings]
        assert "GitHub Personal Access Token" in names

        finding = next(f for f in report.findings if f.pattern.name == "GitHub Personal Access Token")
        assert finding.match == token
        assert finding.pattern.severity == "high"

    def test_private_rsa_key_header(self):
        """-----BEGIN RSA PRIVATE KEY----- should be detected immediately."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hqlYMd4Prn7dOt
GnLr3W+N3X+0tL4Y8Z6r9a8sDfGhJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqR
-----END RSA PRIVATE KEY-----"""
        report = scan_text(text, source="id_rsa")

        names = [f.pattern.name for f in report.findings]
        assert "Private SSH / GPG Key" in names

        finding = next(f for f in report.findings if f.pattern.name == "Private SSH / GPG Key")
        assert finding.pattern.severity == "high"
        assert "RSA PRIVATE KEY" in finding.match
        assert finding.line == 1

    def test_slack_bot_token(self):
        """xoxb- prefix triggers Slack Bot Token detection (standalone pattern)."""
        text = "SLACK_TOKEN=xoxb-DUMMYTOKEN_DUMMYTOKEN_DUMMY"
        report = scan_text(text, source=".env")

        names = [f.pattern.name for f in report.findings]
        assert "Slack Bot / User Token" in names

    def test_discord_bot_token(self):
        """discord_token= with 24.6.27 segment format triggers detection."""
        part1 = "A" * 24
        part2 = "B" * 6
        part3 = "C" * 27
        token = f"{part1}.{part2}.{part3}"
        text = f'discord_token="{token}"'
        report = scan_text(text, source="config.json")

        names = [f.pattern.name for f in report.findings]
        assert "Discord Bot Token" in names

        finding = next(f for f in report.findings if f.pattern.name == "Discord Bot Token")
        assert finding.pattern.severity == "high"
        assert finding.match == token

    def test_google_api_key(self):
        """AIza prefix followed by 35 alphanumeric chars triggers detection."""
        # AIza + exactly 35 chars from [0-9A-Za-z\-_]
        key = "AIzaSyD-exampleKey1234567890abcdefghijk"
        assert len(key) == 39  # AIza(4) + 35
        report = scan_text(key, source="config.yaml")

        names = [f.pattern.name for f in report.findings]
        assert "Google API Key" in names

        finding = next(f for f in report.findings if f.pattern.name == "Google API Key")
        assert finding.match == key
        assert finding.pattern.severity == "high"

    def test_password_field_in_code(self):
        """password=<quoted-value> triggers Password Field detection."""
        text = 'password="SuperSecret123!"'
        report = scan_text(text, source="config.py")

        names = [f.pattern.name for f in report.findings]
        assert "Password Field in Code" in names

        finding = next(f for f in report.findings if f.pattern.name == "Password Field in Code")
        assert finding.match == "SuperSecret123!"
        assert finding.pattern.severity == "low"

    def test_heroku_api_key(self):
        """heroku_api_key= with UUID format triggers detection."""
        uuid_key = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        text = f'heroku_api_key="{uuid_key}"'
        report = scan_text(text, source="deploy.sh")

        names = [f.pattern.name for f in report.findings]
        assert "Heroku API Key" in names

        finding = next(f for f in report.findings if f.pattern.name == "Heroku API Key")
        assert finding.match == uuid_key
        assert finding.pattern.severity == "high"


# ===================================================================
# 2. scan_text — medium-severity patterns
# ===================================================================

class TestScanTextMediumSeverity:

    def test_sendgrid_api_key(self):
        """SG. prefix triggers SendGrid detection."""
        key = "SG.DUMMYKEY.DUMMYKEY_DUMMYKEY_DUMMY"
        text = f'SENDGRID_KEY="{key}"'
        report = scan_text(text, source="env")

        names = [f.pattern.name for f in report.findings]
        assert "SendGrid API Key" in names

        finding = next(f for f in report.findings if f.pattern.name == "SendGrid API Key")
        assert finding.pattern.severity == "medium"

    def test_jwt_token(self):
        """eyJ prefix segments trigger JWT detection."""
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f'token="{jwt}"'
        report = scan_text(text, source="api.py")

        names = [f.pattern.name for f in report.findings]
        assert "JWT Token (suspected)" in names

    def test_basic_auth_in_url(self):
        """user:pass@host pattern triggers Basic Auth Credential detection."""
        text = 'endpoint="https://admin:Hunter2@example.com/api/data"'
        report = scan_text(text, source="config.yaml")

        names = [f.pattern.name for f in report.findings]
        assert "Basic Auth Credential (URL)" in names

        finding = next(f for f in report.findings if f.pattern.name == "Basic Auth Credential (URL)")
        assert finding.pattern.severity == "medium"

    def test_generic_api_key(self):
        """api_key=<20+ chars> triggers Generic API Key detection."""
        text = 'api_key="abcdefghijklmnopqrstuvwx"'
        report = scan_text(text, source="settings.py")

        names = [f.pattern.name for f in report.findings]
        assert "Generic API Key" in names

    def test_paypal_braintree_token(self):
        """paypal_token=<20+ chars> triggers PayPal/Braintree detection."""
        text = 'paypal_token="AeA1b2C3d4E5f6G7h8I9j0kLm"'
        report = scan_text(text, source="payment.py")

        names = [f.pattern.name for f in report.findings]
        assert "PayPal / Braintree Token" in names


# ===================================================================
# 3. scan_text — multiple findings in one scan
# ===================================================================

class TestScanTextMultipleFindings:

    def test_multiple_secrets_in_config(self):
        """A realistic config file should trigger multiple pattern matches."""
        text = (
            'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"\n'
            'aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            'payment_key="sk_test_DUMMYKEY_DUMMYKEY_DUMMY"\n'
            'password="admin12345"\n'
            'github_token="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"\n'
        )
        report = scan_text(text, source="config_dump.txt")

        names = {f.pattern.name for f in report.findings}
        assert len(report.findings) >= 4
        assert "AWS Access Key ID" in names
        assert "AWS Secret Access Key" in names
        assert "Stripe API Key" in names
        assert "Password Field in Code" in names

        severity_counts = {}
        for f in report.findings:
            severity_counts[f.pattern.severity] = severity_counts.get(f.pattern.severity, 0) + 1
        assert severity_counts.get("high", 0) >= 2  # AWS keys are high

    def test_findings_contain_correct_line_numbers(self):
        """Findings should have line numbers corresponding to their position."""
        text = 'api_key="abcdefghijklmnopqrstuvwx"\npassword="secret1234"'
        report = scan_text(text, source="multi")

        lines = [f.line for f in report.findings]
        assert 1 in lines
        assert 2 in lines


# ===================================================================
# 4. scan_text — clean text (no findings)
# ===================================================================

class TestScanTextClean:

    def test_plain_english_text(self):
        """Normal prose should produce zero findings."""
        text = (
            "This is a perfectly normal configuration file.\n"
            "The application runs on port 8080 and connects to the database\n"
            "at localhost:5432. No secrets here, just documentation."
        )
        report = scan_text(text, source="readme.txt")

        assert len(report.findings) == 0
        assert report.findings == []

    def test_empty_string(self):
        """Empty input should produce an empty report with no errors."""
        report = scan_text("", source="empty.txt")

        assert isinstance(report, ScanReport)
        assert len(report.findings) == 0
        assert report.lines_scanned == 1  # split("\n") on "" gives [""]
        assert report.content_length == 0

    def test_code_with_no_secrets(self):
        """Source code that only contains benign patterns."""
        text = (
            "def calculate_sum(a, b):\n"
            "    return a + b\n"
            "\n"
            "# This is a comment about the database connection\n"
            'DB_HOST = "localhost"\n'
            "DB_PORT = 5432\n"
        )
        report = scan_text(text, source="utils.py")

        assert len(report.findings) == 0

    def test_partial_pattern_no_match(self):
        """Incomplete patterns (e.g. 'sk_test' without enough suffix) should not match."""
        # sk_test_ needs 24+ alphanumeric chars after it
        text = 'key="sk_test_short"'
        report = scan_text(text, source="partial.py")

        stripe_matches = [f for f in report.findings if f.pattern.name == "Stripe API Key"]
        assert len(stripe_matches) == 0


# ===================================================================
# 5. scan_text — ScanReport structure validation
# ===================================================================

class TestScanTextReportShape:

    def test_report_attributes(self):
        """ScanReport should have all expected fields populated."""
        text = 'password="testpassword"'
        report = scan_text(text, source="unit_test")

        assert hasattr(report, "source")
        assert hasattr(report, "content_length")
        assert hasattr(report, "lines_scanned")
        assert hasattr(report, "findings")
        assert report.source == "unit_test"
        assert isinstance(report.findings, list)

    def test_finding_attributes(self):
        """Each SecretFinding should have pattern, line, match, context, note."""
        text = 'password="hunter2222"'
        report = scan_text(text, source="test")

        assert len(report.findings) >= 1
        finding = report.findings[0]

        assert isinstance(finding, SecretFinding)
        assert isinstance(finding.pattern, SecretPattern)
        assert isinstance(finding.line, int) and finding.line >= 1
        assert isinstance(finding.match, str) and len(finding.match) > 0
        assert isinstance(finding.context, str)
        assert isinstance(finding.note, str)
        assert "line" in finding.note  # note should mention line number

    def test_finding_severity_is_valid(self):
        """All finding severities must be one of the valid literals."""
        valid_severities = {"high", "medium", "low", "info"}
        text = 'password="test"\napi_key="abcdefghijklmnopqrstuvwx"'
        report = scan_text(text, source="test")

        for finding in report.findings:
            assert finding.pattern.severity in valid_severities


# ===================================================================
# 6. scan_url — valid URL (async)
# ===================================================================

class TestScanUrlValid:

    @pytest.mark.asyncio
    async def test_scan_url_example_com(self):
        """Scanning a known public URL should return a valid ScanReport."""
        report = await scan_url("https://example.com", timeout=15.0)

        assert isinstance(report, ScanReport)
        assert isinstance(report.source, str)
        assert report.source == "https://example.com"
        assert isinstance(report.content_length, int)
        assert report.content_length > 0
        assert isinstance(report.lines_scanned, int)
        assert report.lines_scanned >= 1
        assert isinstance(report.findings, list)

    @pytest.mark.asyncio
    async def test_scan_url_report_to_mirv(self):
        """report_to_mirv_findings should work on a URL scan result."""
        report = await scan_url("https://example.com", timeout=15.0)
        mirv_findings = report_to_mirv_findings(report)

        assert isinstance(mirv_findings, list)
        # Each finding should have the MIRV schema keys
        for item in mirv_findings:
            assert "tool" in item
            assert "severity" in item
            assert "title" in item
            assert "detail" in item
            assert "target" in item
            assert "type" in item
            assert item["tool"] == "secrets-scan"
            assert item["target"] == "https://example.com"


# ===================================================================
# 7. scan_url — invalid / unreachable URL (async)
# ===================================================================

class TestScanUrlInvalid:

    @pytest.mark.asyncio
    async def test_scan_url_unreachable_domain(self):
        """A non-existent domain should raise httpx.RequestError."""
        with pytest.raises(httpx.RequestError):
            await scan_url("https://this-domain-definitely-does-not-exist-xyz.invalid", timeout=5.0)

    @pytest.mark.asyncio
    async def test_scan_url_connection_refused(self):
        """A localhost URL with no server should raise an error."""
        with pytest.raises((httpx.RequestError, httpx.ConnectError)):
            await scan_url("http://127.0.0.1:19999/secret-test", timeout=3.0)

    @pytest.mark.asyncio
    async def test_scan_url_bad_scheme(self):
        """An unsupported scheme should raise an error, not crash."""
        with pytest.raises(Exception):
            await scan_url("ftp://example.com", timeout=5.0)


# ===================================================================
# 8. report_to_mirv_findings — formatting validation
# ===================================================================

class TestReportToMIRVFindings:

    def test_mirv_finding_structure(self):
        """Each MIRV finding dict should contain required keys and valid values."""
        text = (
            'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"\n'
            'password="hunter2222"\n'
        )
        report = scan_text(text, source="mirv_test")
        mirv = report_to_mirv_findings(report)

        assert isinstance(mirv, list)
        assert len(mirv) >= 2

        for item in mirv:
            assert isinstance(item, dict)
            assert item["tool"] == "secrets-scan"
            assert item["severity"] in ("high", "medium", "low", "info")
            assert isinstance(item["title"], str) and len(item["title"]) > 0
            assert isinstance(item["detail"], str)
            assert "Pattern:" in item["detail"]
            assert "Recommendation:" in item["detail"]
            assert item["target"] == "mirv_test"
            assert item["type"] in ("vuln", "tech")

    def test_high_severity_findings_are_vuln_type(self):
        """High and medium severity findings should be type 'vuln'."""
        # Use a high-severity pattern (AWS key) so type maps to "vuln".
        # password= is severity "low" → maps to "tech", so we use AWS here.
        text = 'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"'
        report = scan_text(text, source="test_vuln")
        mirv = report_to_mirv_findings(report)

        vuln_findings = [f for f in mirv if f["type"] == "vuln"]
        assert len(vuln_findings) >= 1
        assert vuln_findings[0]["severity"] == "high"

    def test_mirv_findings_empty_report(self):
        """An empty report should produce an empty MIRV findings list."""
        text = "Nothing to see here."
        report = scan_text(text, source="clean")
        mirv = report_to_mirv_findings(report)

        assert mirv == []

    def test_mirv_findings_sorted_by_severity(self):
        """MIRV findings should be sorted with high severity first."""
        text = (
            'password="hunter2222"\n'
            'api_key="abcdefghijklmnopqrstuvwx"\n'
            'aws_access_key_id="AKIAIOSFODNN7EXAMPLE"\n'
        )
        report = scan_text(text, source="sort_test")
        mirv = report_to_mirv_findings(report)

        sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        severities = [sev_order.get(f["severity"], 99) for f in mirv]
        assert severities == sorted(severities), "Findings should be sorted high -> low"
