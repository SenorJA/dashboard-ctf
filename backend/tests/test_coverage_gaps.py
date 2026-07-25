"""
Tests for coverage gaps — untested functions across 4 modules.

Covers:
  - SIEM: toggle_rule, resolve_alert
  - EXIF OSINT: analyze_url, reverse_geocode
  - DLP Scanner: scan_url, _strings_like
  - Intelligence: collect_certificate
"""

import sys
import os
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from PIL import Image
import io


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════


def _make_jpeg_bytes(width: int = 10, height: int = 10) -> bytes:
    """Create a minimal valid JPEG for testing."""
    img = Image.new("RGB", (width, height), color=(128, 128, 128))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _build_httpx_mock(response_content=b"", raise_error=None, json_data=None):
    """Build a mock httpx.AsyncClient context manager.

    Returns (mock_cm, mock_client) so callers can inspect calls if needed.
    """
    mock_resp = MagicMock()
    mock_resp.content = response_content
    mock_resp.raise_for_status = MagicMock()
    if raise_error is not None:
        mock_resp.raise_for_status = MagicMock(side_effect=raise_error)
    if json_data is not None:
        mock_resp.json.return_value = json_data

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_cm


# ════════════════════════════════════════════════════════════════
#  1. SIEM Tests — toggle_rule, resolve_alert
# ════════════════════════════════════════════════════════════════

from siem import (
    toggle_rule,
    resolve_alert,
    ingest_event,
    get_alerts,
    get_rules,
    reset,
)


class TestSIEMGaps:
    """Tests for untested SIEM functions: toggle_rule, resolve_alert."""

    @pytest.fixture(autouse=True)
    def clean(self):
        reset()
        yield
        reset()

    # ── toggle_rule ──

    def test_toggle_rule_off_then_on(self):
        """Toggle a default rule OFF then back ON; verify enabled field."""
        result = toggle_rule("rule-brute-force", False)
        assert result is not None
        assert result.id == "rule-brute-force"
        assert result.enabled is False

        result2 = toggle_rule("rule-brute-force", True)
        assert result2 is not None
        assert result2.enabled is True

    def test_toggle_rule_nonexistent_returns_none(self):
        """Toggle a rule that does not exist should return None."""
        result = toggle_rule("rule-fake-id-999", True)
        assert result is None

    def test_toggle_all_default_rules(self):
        """Toggling every default rule off then on should work."""
        rules = get_rules()
        for r in rules:
            result = toggle_rule(r["id"], False)
            assert result is not None
            assert result.enabled is False

        for r in rules:
            result = toggle_rule(r["id"], True)
            assert result is not None
            assert result.enabled is True

    # ── resolve_alert ──

    def test_resolve_alert_found(self):
        """Resolve an existing alert and verify resolved flag."""
        # Trigger a canary alert
        ingest_event(
            "canary", "critical",
            "Canary triggered", "Token accessed",
            tags=["canary-activation"],
            ip="10.0.0.1",
        )
        alerts = get_alerts()
        assert len(alerts) >= 1

        alert_id = alerts[0]["id"]
        result = resolve_alert(alert_id)
        assert result is True

        # Verify resolved in store
        alerts_after = get_alerts()
        resolved = [a for a in alerts_after if a["id"] == alert_id]
        assert len(resolved) == 1
        assert resolved[0]["resolved"] is True

    def test_resolve_alert_not_found(self):
        """Resolve a nonexistent alert should return False."""
        assert resolve_alert("nonexistent-alert-id") is False

    def test_resolve_already_resolved(self):
        """Resolving an already-resolved alert should still return True."""
        ingest_event(
            "canary", "critical",
            "Canary triggered", "Token accessed",
            tags=["canary-activation"],
            ip="10.0.0.1",
        )
        alerts = get_alerts()
        alert_id = alerts[0]["id"]

        assert resolve_alert(alert_id) is True
        assert resolve_alert(alert_id) is True


# ════════════════════════════════════════════════════════════════
#  2. EXIF OSINT Tests — analyze_url, reverse_geocode
# ════════════════════════════════════════════════════════════════

from exif_osint import analyze_url, reverse_geocode, EXIFResult


class TestEXIFGaps:
    """Tests for untested EXIF functions: analyze_url, reverse_geocode."""

    # ── analyze_url ──

    @pytest.mark.asyncio
    async def test_analyze_url_success(self):
        """Successful download + analysis from URL."""
        fake_jpeg = _make_jpeg_bytes()
        mock_cm = _build_httpx_mock(response_content=fake_jpeg)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            result = await analyze_url("https://example.com/photo.jpg")

        assert isinstance(result, EXIFResult)
        assert result.image.width == 10
        assert result.image.height == 10
        assert result.image.format == "JPEG"
        assert result.filename == "photo.jpg"

    @pytest.mark.asyncio
    async def test_analyze_url_sets_source_url(self):
        """analyze_url should annotate the result with the source URL."""
        fake_jpeg = _make_jpeg_bytes()
        mock_cm = _build_httpx_mock(response_content=fake_jpeg)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            result = await analyze_url("https://example.com/img/test.png")

        assert getattr(result, "_source_url", None) == "https://example.com/img/test.png"

    @pytest.mark.asyncio
    async def test_analyze_url_http_404(self):
        """HTTP 404 should raise ValueError."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.reason_phrase = "Not Found"
        error = httpx.HTTPStatusError(
            "404 Not Found",
            request=MagicMock(),
            response=mock_resp,
        )
        mock_cm = _build_httpx_mock(raise_error=error)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(ValueError, match="HTTP 404"):
                await analyze_url("https://example.com/missing.jpg")

    @pytest.mark.asyncio
    async def test_analyze_url_timeout(self):
        """Timeout should raise ValueError."""
        mock_cm = _build_httpx_mock(raise_error=httpx.TimeoutException("timed out"))

        with patch("httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(ValueError, match="Timeout"):
                await analyze_url("https://example.com/slow.jpg")

    @pytest.mark.asyncio
    async def test_analyze_url_file_too_large(self):
        """Downloaded file exceeding 20 MB limit should raise ValueError."""
        # _MAX_FILE_SIZE = 20 * 1024 * 1024
        oversized = b"\x00" * (21 * 1024 * 1024)
        mock_cm = _build_httpx_mock(response_content=oversized)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(ValueError, match="exceed"):
                await analyze_url("https://example.com/huge.jpg")

    # ── reverse_geocode ──

    @pytest.mark.asyncio
    async def test_reverse_geocode_success(self):
        """Successful geocoding returns address fields."""
        fake_nominatim = {
            "lat": "40.4168",
            "lon": "-3.7038",
            "display_name": "Puerta del Sol, Madrid, Spain",
            "address": {
                "house_number": "1",
                "road": "Puerta del Sol",
                "city": "Madrid",
                "state": "Madrid",
                "country": "Spain",
                "country_code": "es",
                "postcode": "28013",
            },
        }
        mock_cm = _build_httpx_mock(json_data=fake_nominatim)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            result = await reverse_geocode(40.4168, -3.7038)

        assert result is not None
        assert result["country"] == "Spain"
        assert result["country_code"] == "es"
        assert result["city"] == "Madrid"
        assert result["road"] == "Puerta del Sol"
        assert result["house_number"] == "1"
        assert result["postcode"] == "28013"
        assert result["display_name"] == "Puerta del Sol, Madrid, Spain"
        assert result["lat"] == "40.4168"
        assert result["lon"] == "-3.7038"

    @pytest.mark.asyncio
    async def test_reverse_geocode_failure_returns_none(self):
        """Connection failure should return None."""
        mock_cm = _build_httpx_mock(raise_error=Exception("connection failed"))

        with patch("httpx.AsyncClient", return_value=mock_cm):
            result = await reverse_geocode(0.0, 0.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_reverse_geocode_town_fallback(self):
        """If 'city' is missing but 'town' exists, it should fall back."""
        fake_nominatim = {
            "lat": "51.5",
            "lon": "-0.1",
            "display_name": "Some Place",
            "address": {
                "town": "Smallville",
                "state": "Oxfordshire",
                "country": "UK",
                "country_code": "gb",
            },
        }
        mock_cm = _build_httpx_mock(json_data=fake_nominatim)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            result = await reverse_geocode(51.5, -0.1)

        assert result is not None
        assert result["city"] == "Smallville"

    @pytest.mark.asyncio
    async def test_reverse_geocode_village_fallback(self):
        """If 'city' and 'town' are missing but 'village' exists, it should fall back."""
        fake_nominatim = {
            "lat": "48.8",
            "lon": "2.3",
            "display_name": "Rural Area",
            "address": {
                "village": "Petitbourg",
                "country": "France",
                "country_code": "fr",
            },
        }
        mock_cm = _build_httpx_mock(json_data=fake_nominatim)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            result = await reverse_geocode(48.8, 2.3)

        assert result is not None
        assert result["city"] == "Petitbourg"


# ════════════════════════════════════════════════════════════════
#  3. DLP Scanner Tests — scan_url, _strings_like
# ════════════════════════════════════════════════════════════════

from dlp_scanner import scan_url, _strings_like


class TestDLPGaps:
    """Tests for untested DLP functions: scan_url, _strings_like."""

    # ── scan_url ──

    @pytest.mark.asyncio
    async def test_scan_url_success(self):
        """Successful URL fetch + scan should find PII in content."""
        content = b"Email: user@test.com\nSSN: 123-45-6789"
        mock_cm = _build_httpx_mock(response_content=content)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            report = await scan_url("https://example.com/data.txt")

        assert report.source == "url"
        assert report.source_name == "https://example.com/data.txt"
        assert len(report.findings) >= 2
        pattern_names = [f.pattern_name for f in report.findings]
        assert "email" in pattern_names
        assert "ssn" in pattern_names

    @pytest.mark.asyncio
    async def test_scan_url_clean_content(self):
        """URL with no PII should return empty findings."""
        content = b"Hello, this is just normal text with no PII."
        mock_cm = _build_httpx_mock(response_content=content)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            report = await scan_url("https://example.com/safe.txt")

        assert report.source == "url"
        assert len(report.findings) == 0
        assert report.risk_score == 0.0

    @pytest.mark.asyncio
    async def test_scan_url_http_error(self):
        """HTTP error should propagate as exception."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.reason_phrase = "Internal Server Error"
        error = httpx.HTTPStatusError(
            "500",
            request=MagicMock(),
            response=mock_resp,
        )
        mock_cm = _build_httpx_mock(raise_error=error)

        with patch("httpx.AsyncClient", return_value=mock_cm):
            with pytest.raises(httpx.HTTPStatusError):
                await scan_url("https://example.com/error.txt")

    # ── _strings_like ──

    def test_strings_like_extracts_long_strings(self):
        """Binary data with embedded ASCII should extract strings >= min_length."""
        data = b"\x00\x00AB\x00\x00\x00HELLO WORLD\x00\x00\x00XX\x00\x00"
        result = _strings_like(data, min_length=4)
        assert "HELLO WORLD" in result
        assert "AB" not in result
        assert "XX" not in result

    def test_strings_like_no_strings_above_min(self):
        """If no strings meet min_length, result should be empty."""
        data = b"\x00\x00AB\x00\x00CD\x00\x00"
        result = _strings_like(data, min_length=5)
        assert result == ""

    def test_strings_like_with_whitespace_chars(self):
        """Tab (9), newline (10), carriage return (13) should be included."""
        data = b"hello\tworld\nfoo\rbar\x00"
        result = _strings_like(data, min_length=4)
        lines = result.split("\n")
        assert any("hello" in line for line in lines)

    def test_strings_like_empty_data(self):
        """Empty bytes should return empty string."""
        assert _strings_like(b"", min_length=4) == ""

    def test_strings_like_all_printable(self):
        """Entire input is printable — should extract everything if long enough."""
        data = b"This is a fully printable ASCII string."
        result = _strings_like(data, min_length=4)
        assert "This is a fully printable ASCII string." in result

    def test_strings_like_single_byte_min_length(self):
        """min_length=1 should extract every printable run of 1+ chars."""
        data = b"A\x00B\x00C\x00"
        result = _strings_like(data, min_length=1)
        lines = result.strip().split("\n")
        assert "A" in lines
        assert "B" in lines
        assert "C" in lines


# ════════════════════════════════════════════════════════════════
#  4. Intelligence Tests — collect_certificate
# ════════════════════════════════════════════════════════════════

from backend.intelligence import collect_certificate, reset as intel_reset


class TestIntelGaps:
    """Tests for untested Intelligence collector: collect_certificate."""

    @pytest.fixture(autouse=True)
    def clean(self):
        intel_reset()
        yield
        intel_reset()

    def test_collect_certificate_success(self, monkeypatch):
        """Successful certificate collection returns parsed cert fields."""
        fake_cert = {
            "issuer": ((("organizationName", "Let's Encrypt"),),),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT",
            "serialNumber": "ABC123DEF456",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }

        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_socket.getpeercert.return_value = fake_cert

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_socket

        monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
        monkeypatch.setattr("socket.socket", lambda: MagicMock())

        result = collect_certificate("https://example.com")

        assert result["issuer"] == "Let's Encrypt"
        assert result["subject"] == "example.com"
        assert result["not_before"] == "Jan  1 00:00:00 2025 GMT"
        assert result["not_after"] == "Dec 31 23:59:59 2025 GMT"
        assert result["serial_number"] == "ABC123DEF456"
        assert "example.com" in result["san"]
        assert "www.example.com" in result["san"]
        assert "error" not in result
        assert "collected_at" in result

    def test_collect_certificate_failure_returns_error(self, monkeypatch):
        """Connection failure returns error dict with empty fields."""
        def fail_context():
            raise ConnectionError("connection refused")

        monkeypatch.setattr("ssl.create_default_context", fail_context)

        result = collect_certificate("https://down.example.com")

        assert result["issuer"] == ""
        assert result["subject"] == "down.example.com"
        assert result["not_before"] == ""
        assert result["not_after"] == ""
        assert result["serial_number"] == ""
        assert result["san"] == []
        assert "error" in result
        assert "collected_at" in result

    def test_collect_certificate_strips_http_prefix(self, monkeypatch):
        """URL prefixes (http://, https://) should be stripped to extract hostname."""
        fake_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "",
            "notAfter": "",
            "serialNumber": "",
        }

        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_socket.getpeercert.return_value = fake_cert

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_socket

        monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
        monkeypatch.setattr("socket.socket", lambda: MagicMock())

        result = collect_certificate("http://example.com:8443/path")

        assert result["subject"] == "example.com"
        assert result["issuer"] == "Example CA"
        assert "error" not in result

    def test_collect_certificate_no_san(self, monkeypatch):
        """Certificate without SAN should return empty SAN list."""
        fake_cert = {
            "subject": ((("commonName", "nosan.example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "",
            "notAfter": "",
            "serialNumber": "123",
            # No subjectAltName key
        }

        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_socket.getpeercert.return_value = fake_cert

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_socket

        monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
        monkeypatch.setattr("socket.socket", lambda: MagicMock())

        result = collect_certificate("https://nosan.example.com")

        assert result["san"] == []
        assert result["subject"] == "nosan.example.com"

    def test_collect_certificate_issuer_cn_fallback(self, monkeypatch):
        """When organizationName is missing, fall back to commonName for issuer."""
        fake_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Fallback CA"),),),
            "notBefore": "",
            "notAfter": "",
            "serialNumber": "",
        }

        mock_socket = MagicMock()
        mock_socket.__enter__ = MagicMock(return_value=mock_socket)
        mock_socket.__exit__ = MagicMock(return_value=False)
        mock_socket.getpeercert.return_value = fake_cert

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_socket

        monkeypatch.setattr("ssl.create_default_context", lambda: mock_ctx)
        monkeypatch.setattr("socket.socket", lambda: MagicMock())

        result = collect_certificate("https://example.com")

        # No organizationName in issuer → falls back to commonName
        assert result["issuer"] == "Fallback CA"
