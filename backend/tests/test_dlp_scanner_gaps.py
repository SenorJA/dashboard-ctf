"""
Coverage-gap tests for backend/dlp_scanner.py.

Targets the branches NOT exercised by test_dlp_scanner.py:

  - _get_context() ............ lines 173-178  (window clamp + newline collapse)
  - _is_valid_match("ipv4") ... lines 192-199  (octet >255, non-numeric, valid)
  - _adjust_severity("ipv4") .. line  211      (private range -> "info")
  - scan_text() dedup ......... line  279      (same pattern+line+value skipped)
  - scan_text() invalid match . line  284      (post-validation `continue`)
  - _strings_like() ............ lines 238-249 (printable runs, min_length)
  - scan_file() ................ lines 343-349 (latin-1 fallback, strings last resort)
  - scan_url() ................. lines 374-400 (small OK, 5MB truncation, error propagation)

No network access: httpx.AsyncClient is patched with a fake async client.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
import pytest
from unittest.mock import MagicMock, patch

from backend.dlp_scanner import (
    _adjust_severity,
    _get_context,
    _is_valid_match,
    _strings_like,
    scan_file,
    scan_text,
    scan_url,
)


# ── 1. _get_context (dlp_scanner.py:173-178) ──────────────────────────────

class TestGetContextGaps:
    def test_middle_match_applies_window(self):
        """Covers dlp_scanner.py:173-175 — symmetric window around a middle match."""
        text = "a" * 100 + "TARGET" + "b" * 100
        ctx = _get_context(text, 100, 106, window=50)
        assert ctx == text[50:156]

    def test_match_at_start_clamps_ctx_start(self):
        """Covers dlp_scanner.py:173 — max(0, start - window) clamps to 0."""
        text = "TARGET" + "x" * 30
        ctx = _get_context(text, 0, 6, window=50)
        assert ctx == text

    def test_match_at_end_clamps_ctx_end(self):
        """Covers dlp_scanner.py:174 — min(len(text), end + window) clamps to len."""
        text = "x" * 30 + "TARGET"
        ctx = _get_context(text, 30, 36, window=50)
        assert ctx == text

    def test_newlines_collapsed(self):
        """Covers dlp_scanner.py:177 — re.sub collapses newlines + strip."""
        ctx = _get_context("line1\nline2\nline3", 6, 11, window=50)
        assert ctx == "line1 line2 line3"
        assert "\n" not in ctx


# ── 2. _is_valid_match ipv4 (dlp_scanner.py:192-199) ──────────────────────

class TestIsValidMatchIpv4Gaps:
    def test_octet_over_255_rejected(self):
        """Covers dlp_scanner.py:195-196 — int(octet) > 255 -> False."""
        assert _is_valid_match("ipv4", "192.168.1.999") is False

    def test_non_numeric_octet_rejected(self):
        """Covers dlp_scanner.py:197-198 — int(octet) raises ValueError -> False."""
        assert _is_valid_match("ipv4", "abc.1.1.1") is False

    def test_valid_ipv4_accepted(self):
        """Covers dlp_scanner.py:199 — all octets in 0-255 -> True."""
        assert _is_valid_match("ipv4", "8.8.8.8") is True

    def test_non_ipv4_pattern_passes(self):
        """Covers dlp_scanner.py:201 — default fallback returns True."""
        assert _is_valid_match("email", "a@b.com") is True


# ── 3. _adjust_severity (dlp_scanner.py:211) ───────────────────────────────

class TestAdjustSeverityGaps:
    def test_private_ipv4_downgraded_to_info(self):
        """Covers dlp_scanner.py:210-211 — 192.168.x.x private range -> 'info'."""
        assert _adjust_severity("ipv4", "low", "192.168.1.1") == "info"

    def test_public_ipv4_keeps_severity(self):
        """Covers dlp_scanner.py:212 — public IP returns the original severity."""
        assert _adjust_severity("ipv4", "low", "8.8.8.8") == "low"

    def test_other_pattern_unchanged(self):
        """Covers dlp_scanner.py:212 — non-ipv4 pattern is never adjusted."""
        assert _adjust_severity("email", "medium", "a@b.com") == "medium"


# ── 4. scan_text dedup / invalid-match skip (dlp_scanner.py:279, 284) ──────

class TestScanTextGaps:
    def test_duplicate_email_same_line_deduped(self):
        """Covers dlp_scanner.py:279 — (pattern, line, value) already seen -> skip.

        'a@b.com' appears twice on the same line; the second match must be
        dropped so only ONE finding is produced.
        """
        report = scan_text("email: a@b.com y a@b.com")
        emails = [f for f in report.findings if f.pattern_name == "email"]
        assert len(emails) == 1
        assert emails[0].value == "a@b.com"

    def test_invalid_ipv4_skipped_by_post_validation(self):
        """Covers dlp_scanner.py:284 — _is_valid_match False -> `continue`."""
        report = scan_text("999.999.999.999")
        assert [f for f in report.findings if f.pattern_name == "ipv4"] == []

    def test_private_ip_finding_severity_info(self):
        """Integration: private IP through the full scan pipeline -> 'info' severity."""
        report = scan_text("router: 192.168.1.1")
        ips = [f for f in report.findings if f.pattern_name == "ipv4"]
        assert len(ips) == 1
        assert ips[0].severity == "info"


# ── 5. _strings_like (dlp_scanner.py:238-249) ──────────────────────────────

class TestStringsLikeGaps:
    def test_printable_run_extracted(self):
        """Covers dlp_scanner.py:241-246 — printable run >= min_length appended."""
        out = _strings_like(b"hello world\x00\x01\x02")
        assert out == "hello world"

    def test_short_run_discarded(self):
        """Covers dlp_scanner.py:244 — run shorter than min_length dropped."""
        out = _strings_like(b"ab\x00cdef")
        assert "ab" not in out
        assert "cdef" in out

    def test_non_printable_byte_separates_runs(self):
        """Covers dlp_scanner.py:244-246 — non-printable byte flushes the run."""
        out = _strings_like(b"abcd\x00efgh")
        assert out.split("\n") == ["abcd", "efgh"]

    def test_trailing_run_included(self):
        """Covers dlp_scanner.py:247-248 — final flush at end of data."""
        out = _strings_like(b"\x00\x01\x02abcd")
        assert out == "abcd"

    def test_custom_min_length(self):
        """Covers dlp_scanner.py:244-248 — custom min_length parameter."""
        out = _strings_like(b"abcde\x00fghij", min_length=5)
        assert out.split("\n") == ["abcde", "fghij"]


# ── 6. scan_file decode fallbacks (dlp_scanner.py:343-349) ─────────────────

class _UglyBytes(bytes):
    """bytes subclass whose decode() ALWAYS raises -> forces _strings_like.

    Plain bytes can never reach the _strings_like fallback because latin-1
    decoding never fails; a refusing subclass is required to exercise the
    last-resort branch.
    """

    def decode(self, encoding="utf-8", errors="strict"):
        if encoding == "utf-8":
            raise UnicodeDecodeError(encoding, bytes(self), 0, 1, "invalid utf-8")
        raise ValueError(f"refusing to decode: {encoding}")


class TestScanFileGaps:
    def test_invalid_utf8_falls_back_to_latin1(self):
        """Covers dlp_scanner.py:343-346 — UTF-8 fails -> latin-1 ('café ólé')."""
        report = scan_file(b"caf\xe9\x20\xf3l\xe9", "cafe.txt")
        assert report.source == "file"
        assert report.source_name == "cafe.txt"

    def test_binary_bytes_decoded_as_latin1(self):
        """Covers dlp_scanner.py:346 — latin-1 never fails on real bytes."""
        report = scan_file(b"\x00\x01\x02\xff\xfeabcde\x00\xff", "bin.dat")
        assert report.source == "file"
        assert report.source_name == "bin.dat"

    def test_refusing_bytes_force_strings_like_fallback(self):
        """Covers dlp_scanner.py:348-349 — last-resort _strings_like extraction."""
        report = scan_file(_UglyBytes(b"secret\x00\x01token\xff"), "bin.dat")
        assert report.source == "file"
        assert report.source_name == "bin.dat"


# ── 7. scan_url (dlp_scanner.py:374-400) ───────────────────────────────────

class _FakeResp:
    """Stand-in for an httpx.Response with configurable status."""

    def __init__(self, content=b"", status_code=200, reason="OK"):
        self.content = content
        self.status_code = status_code
        self.reason_phrase = reason
        self._raise = None
        if status_code >= 400:
            self._raise = httpx.HTTPStatusError(
                f"HTTP {status_code}",
                request=MagicMock(),
                response=MagicMock(status_code=status_code, reason_phrase=reason),
            )

    def raise_for_status(self):
        if self._raise:
            raise self._raise


class _FakeClient:
    """Fake httpx.AsyncClient: async context manager whose get() returns a
    canned response or raises a canned exception."""

    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        if self._exc:
            raise self._exc
        return self._resp


class TestScanUrlGaps:
    @pytest.mark.asyncio
    async def test_success_small_content(self):
        """Covers dlp_scanner.py:377-386 + 394-400 — happy path, source 'url'."""
        resp = _FakeResp(content=b"Contact: user@example.com")
        with patch("backend.dlp_scanner.httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            report = await scan_url("https://example.com/leak.txt")
        assert report.source == "url"
        assert report.source_name == "https://example.com/leak.txt"
        assert report.content_length == len("Contact: user@example.com")

    @pytest.mark.asyncio
    async def test_large_content_truncated_to_5mb(self):
        """Covers dlp_scanner.py:389-392 — >5MB content truncated to max_bytes."""
        max_bytes = 5 * 1024 * 1024
        resp = _FakeResp(content=b"x" * (max_bytes + 100))
        with patch("backend.dlp_scanner.httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            report = await scan_url("https://example.com/big")
        assert report.source == "url"
        assert report.content_length <= max_bytes

    @pytest.mark.asyncio
    async def test_http_status_error_propagates(self):
        """Covers dlp_scanner.py:386 — raise_for_status HTTPStatusError propagates."""
        resp = _FakeResp(status_code=404, reason="Not Found")
        with patch("backend.dlp_scanner.httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            with pytest.raises(httpx.HTTPStatusError):
                await scan_url("https://example.com/missing")

    @pytest.mark.asyncio
    async def test_timeout_propagates(self):
        """Covers dlp_scanner.py:383 — TimeoutException from get() propagates."""
        with patch("backend.dlp_scanner.httpx.AsyncClient",
                   return_value=_FakeClient(exc=httpx.TimeoutException("slow"))):
            with pytest.raises(httpx.TimeoutException):
                await scan_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_request_error_propagates(self):
        """Covers dlp_scanner.py:383 — RequestError propagates (no try/except)."""
        exc = httpx.RequestError("connection refused", request=MagicMock())
        with patch("backend.dlp_scanner.httpx.AsyncClient", return_value=_FakeClient(exc=exc)):
            with pytest.raises(httpx.RequestError):
                await scan_url("https://example.com/img.jpg")
