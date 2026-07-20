"""
Tests for dlp_scanner — Data Loss Prevention / PII detection.

Covers:
  - Credit card detection with Luhn validation
  - SSN, email, phone, IPv4, API key, passport, IBAN patterns
  - Clean text (no false positives)
  - Risk score calculation
  - Findings format in MIRV style
  - File scanning
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from dlp_scanner import (
    scan_text, scan_file, scan_url,
    report_to_mirv_findings,
    _luhn_check,
)

# ──────────────────────────────────────────────
# 1. Luhn algorithm
# ──────────────────────────────────────────────


def test_luhn_valid_card():
    assert _luhn_check("4111111111111111") is True


def test_luhn_invalid_card():
    assert _luhn_check("1234567890123456") is False


def test_luhn_visa():
    assert _luhn_check("4000056655665556") is True


def test_luhn_mastercard():
    assert _luhn_check("5555555555554444") is True


def test_luhn_amex():
    assert _luhn_check("378282246310005") is True


def test_luhn_empty():
    assert _luhn_check("") is False


# ──────────────────────────────────────────────
# 2. Pattern detection
# ──────────────────────────────────────────────


def test_detect_credit_card():
    r = scan_text("My card is 4111-1111-1111-1111")
    cc = [f for f in r.findings if f.pattern_name == "credit-card"]
    assert len(cc) == 1
    assert "4111" in cc[0].value


def test_detect_ssn():
    r = scan_text("SSN: 123-45-6789")
    ssn = [f for f in r.findings if f.pattern_name == "ssn"]
    assert len(ssn) == 1


def test_detect_email():
    r = scan_text("Contact: user@example.com")
    email = [f for f in r.findings if f.pattern_name == "email"]
    assert len(email) == 1


def test_detect_api_key():
    r = scan_text('API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456')
    keys = [f for f in r.findings if f.pattern_name == "api-key"]
    assert len(keys) == 1


def test_detect_multiple_patterns():
    r = scan_text("Email: a@b.com, SSN: 123-45-6789, Card: 4111-1111-1111-1111")
    assert len(r.findings) >= 3


# ──────────────────────────────────────────────
# 3. Clean text
# ──────────────────────────────────────────────


def test_clean_text_no_findings():
    r = scan_text("Hello world, this is just normal text.")
    assert len(r.findings) == 0


def test_clean_text_risk_zero():
    r = scan_text("Just a normal conversation about weather.")
    assert r.risk_score == 0.0


# ──────────────────────────────────────────────
# 4. Risk score
# ──────────────────────────────────────────────


def test_risk_score_high():
    r = scan_text("Card: 4111-1111-1111-1111, SSN: 123-45-6789")
    assert r.risk_score > 0


def test_risk_score_clean():
    r = scan_text("Nothing here")
    assert r.risk_score == 0.0


# ──────────────────────────────────────────────
# 5. Report metadata
# ──────────────────────────────────────────────


def test_report_source_name():
    r = scan_text("hello", "custom_source")
    assert r.source_name == "custom_source"
    assert r.source == "text"


def test_report_lines_scanned():
    r = scan_text("line1\nline2\nline3")
    assert r.lines_scanned >= 3


def test_report_content_length():
    r = scan_text("hello")
    assert r.content_length == len("hello")


# ──────────────────────────────────────────────
# 6. Findings format
# ──────────────────────────────────────────────


def test_findings_mirv_format():
    r = scan_text("card: 4111-1111-1111-1111, email: test@test.com")
    findings = report_to_mirv_findings(r)
    assert len(findings) > 0
    for f in findings:
        assert f["tool"] == "dlp-scan"
        assert "severity" in f
        assert "title" in f
        assert "detail" in f
        assert "extra" in f


def test_findings_sorted_by_severity():
    r = scan_text("card: 4111-1111-1111-1111, email: test@test.com")
    findings = report_to_mirv_findings(r)
    sev = [f["severity"] for f in findings]
    # high should come before medium
    high_idx = sev.index("high") if "high" in sev else 999
    med_idx = sev.index("medium") if "medium" in sev else 999
    assert high_idx < med_idx


# ──────────────────────────────────────────────
# 7. File scanning
# ──────────────────────────────────────────────


def test_scan_file_text():
    content = b"Email: test@example.com"
    r = scan_file(content, "test.txt")
    assert r.source == "file"
    assert r.source_name == "test.txt"
    assert len(r.findings) >= 1


def test_scan_file_empty():
    r = scan_file(b"", "empty.txt")
    assert len(r.findings) == 0


# ──────────────────────────────────────────────
# 8. Edge cases
# ──────────────────────────────────────────────


def test_detect_phone():
    r = scan_text("Call +1 (555) 123-4567")
    phones = [f for f in r.findings if f.pattern_name == "phone"]
    assert len(phones) >= 1


def test_detect_passport():
    r = scan_text("Passport: AB1234567")
    pp = [f for f in r.findings if f.pattern_name == "passport"]
    assert len(pp) >= 1


def test_detect_iban():
    r = scan_text("IBAN: ES12 3456 7890 1234 5678")
    iban = [f for f in r.findings if f.pattern_name == "iban"]
    assert len(iban) >= 1
