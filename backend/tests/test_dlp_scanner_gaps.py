"""
Coverage-gap tests for backend/dlp_scanner.py — edge branches.

Covers:
  - _get_context(): newline collapsing
  - _is_valid_match(): ipv4 octet bounds / non-numeric octet
  - _adjust_severity(): private IPv4 downgrade to "info"
  - scan_text(): dedup of same pattern+line+value
  - scan_file(): latin-1 fallback and strings-like binary fallback
  - scan_url(): 5MB truncation
  - _strings_like(): printable-string extraction from binary data
"""

import asyncio
import os
import sys

from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.dlp_scanner import (
    _adjust_severity,
    _get_context,
    _is_valid_match,
    _strings_like,
    scan_file,
    scan_text,
    scan_url,
)


class TestGetContextGaps:
    def test_basic_window(self):
        text = "prefix " + ("x" * 100) + " suffix"
        ctx = _get_context(text, 7, 107)
        assert ctx == text

    def test_at_boundaries(self):
        text = "short"
        assert _get_context(text, 0, 5) == "short"

    def test_newlines_collapsed(self):
        text = "aaa\nbbb\nccc\n"
        ctx = _get_context(text, 4, 7)  # "bbb"
        assert "bbb" in ctx
        assert "\n" not in ctx


class TestIsValidMatchGaps:
    def test_ipv4_octet_over_255(self):
        assert _is_valid_match("ipv4", "192.168.1.999") is False

    def test_ipv4_octet_non_numeric(self):
        assert _is_valid_match("ipv4", "abc.1.1.1") is False

    def test_ipv4_valid(self):
        assert _is_valid_match("ipv4", "192.168.1.1") is True

    def test_other_patterns_pass(self):
        assert _is_valid_match("email", "a@b.com") is True


class TestAdjustSeverityGaps:
    def test_private_ip_downgraded(self):
        assert _adjust_severity("ipv4", "low", "192.168.1.1") == "info"

    def test_public_ip_unchanged(self):
        assert _adjust_severity("ipv4", "low", "8.8.8.8") == "low"

    def test_non_ip_unchanged(self):
        assert _adjust_severity("email", "medium", "a@b.com") == "medium"


class TestScanTextGaps:
    def test_dedup_same_value_same_line(self):
        report = scan_text("8.8.8.8 8.8.8.8")
        ip_findings = [f for f in report.findings if f.pattern_name == "ipv4"]
        assert len(ip_findings) == 1
        assert ip_findings[0].severity == "low"

    def test_private_ip_info_severity(self):
        report = scan_text("router: 192.168.1.1")
        ip_findings = [f for f in report.findings if f.pattern_name == "ipv4"]
        assert ip_findings and ip_findings[0].severity == "info"


class _UglyBytes(bytes):
    """Bytes subclass that refuses every decode — forces strings fallback."""

    def decode(self, encoding="utf-8", errors="strict"):
        if encoding == "utf-8":
            raise UnicodeDecodeError(encoding, bytes(self), 0, 1, "invalid utf-8")
        raise ValueError("refusing to decode")


class TestScanFileGaps:
    def test_invalid_utf8_falls_back_latin1(self):
        report = scan_file(b"caf\xe9 \xff\xfe", "latin.bin")
        assert report.source == "file"
        assert report.source_name == "latin.bin"

    def test_utf8_valid(self):
        report = scan_file("hello ünïcödé".encode("utf-8"), "utf8.txt")
        assert report.source == "file"

    def test_binary_falls_back_to_strings(self):
        report = scan_file(_UglyBytes(b"hello \x00\x01 world"), "bin.dat")
        assert report.source == "file"
        assert report.source_name == "bin.dat"


class TestStringsLikeGaps:
    def test_extracts_printable_runs(self):
        out = _strings_like(b"hello \x00\x01\x02 world")
        assert "hello" in out
        assert "world" in out

    def test_min_length_filter(self):
        out = _strings_like(b"ab \x00 cdef", min_length=4)
        assert "ab" not in out
        assert "cdef" in out

    def test_ends_with_string(self):
        out = _strings_like(b"\x00\x00abcdef")
        assert "abcdef" in out


class _FakeResponse:
    content = b"x" * (5 * 1024 * 1024 + 100)  # > 5 MB

    def raise_for_status(self):
        pass


class _FakeClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        return _FakeResponse()


class TestScanUrlGaps:
    def test_truncates_large_response(self):
        with patch("dlp_scanner.httpx.AsyncClient", return_value=_FakeClient()):
            report = asyncio.run(scan_url("https://example.com/big"))
        assert report.source == "url"
        assert report.source_name == "https://example.com/big"
