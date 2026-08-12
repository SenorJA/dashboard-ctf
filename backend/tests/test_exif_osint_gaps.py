"""
Coverage-gap tests for backend/exif_osint.py.

Targets the branches NOT exercised by test_exif_osint.py:

  - _parse_exif_sync() Image.open failure ... lines 259-261  (fallback EXIFResult)
  - _parse_exif_sync() tuple conversion ..... lines 337-340  (non-Rational tuple)
  - _parse_exif_sync() defensive thumbnail .. line  425      (has_thumb but thumb_info None)
  - analyze_url() ............................ lines 510-543  (success / timeout /
                                             HTTP status / network error / size limit)
  - reverse_geocode() ........................ lines 563-598  (success / failure)

No network access: httpx.AsyncClient is patched with a fake async client.

NOTE: analyze_url()/reverse_geocode() execute `import httpx` *inside* the
function body, so the module never exposes a `backend.exif_osint.httpx`
attribute; the global `httpx.AsyncClient` is patched instead (the function
resolves `httpx` through sys.modules to the same module object).
"""

import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
import pytest
from PIL import Image
from unittest.mock import MagicMock, patch

import backend.exif_osint as eo
from backend.exif_osint import analyze_url, reverse_geocode


class _FakeImage:
    """Minimal duck-typed Pillow Image for _parse_exif_sync."""

    def __init__(self, exif_data=None, info=None):
        self.format = "PNG"
        self.width = 10
        self.height = 10
        self.info = info or {}
        self._exif = exif_data

    def getexif(self):
        return {}

    def _getexif(self):
        return self._exif


# ── 1. _parse_exif_sync — Image.open failure (exif_osint.py:259-261) ───────

class TestParseExifSyncImageOpenFailure:
    def test_image_open_exception_returns_fallback_result(self):
        """Covers exif_osint.py:259-261 — Image.open raises -> EXIFResult fallback."""
        with patch("PIL.Image.open", side_effect=Exception("corrupt image")):
            result = eo._parse_exif_sync(b"x" * 100, "fake.jpg")
        assert result.has_exif is False
        assert result.severity == "info"
        assert result.filename == "fake.jpg"
        assert result.image.format == "unknown"

    def test_real_pil_rejects_garbage_bytes(self):
        """Covers exif_osint.py:259-261 — real PIL UnidentifiedImageError path."""
        result = eo._parse_exif_sync(b"this is definitely not an image at all", "garbage.jpg")
        assert result.has_exif is False
        assert result.severity == "info"
        assert result.filename == "garbage.jpg"


# ── 2. _parse_exif_sync — tuple value conversion (exif_osint.py:337-340) ───

class TestParseExifSyncTupleConversion:
    def test_tuple_of_three_becomes_list_of_strings(self):
        """Covers exif_osint.py:337-338 — tuple len != 2 -> [str(v) for v in value]."""
        img = _FakeImage(exif_data={0x010F: (1, 2, 3)})
        with patch("PIL.Image.open", return_value=img):
            result = eo._parse_exif_sync(b"x" * 100, "t.jpg")
        assert result.raw_tags.get("Make") == ["1", "2", "3"]

    def test_tuple_conversion_exception_falls_back_to_str(self):
        """Covers exif_osint.py:339-340 — conversion exception -> str(value)."""
        class _ExplodingTuple(tuple):
            def __getitem__(self, idx):
                raise RuntimeError("boom")

        img = _FakeImage(exif_data={0x010F: _ExplodingTuple((1, 2))})
        with patch("PIL.Image.open", return_value=img):
            result = eo._parse_exif_sync(b"x" * 100, "t.jpg")
        assert result.has_exif is True
        assert "Make" in result.raw_tags


# ── 3. _parse_exif_sync — defensive thumbnail (exif_osint.py:424-425) ──────

class TestParseExifSyncThumbnailDefensive:
    def test_thumbnail_len_failure_triggers_defensive_branch(self):
        """Covers exif_osint.py:425 — has_thumb=True but thumb_info is None.

        A bytes subclass whose __len__ raises makes the `has_thumb = True`
        assignment succeed but the subsequent `len(thumb_data)` call raise,
        so the try block exits via `except Exception: pass` with thumb_info
        still None — the defensive fallback at line 425 then fills it in.
        """
        class _ThumbWithBadLen(bytes):
            def __bool__(self):
                return True

            def __len__(self):
                raise RuntimeError("len unavailable")

        img = MagicMock()
        img.format = "PNG"
        img.width = 10
        img.height = 10
        img.info = {"thumbnail": _ThumbWithBadLen(b"thumb")}
        img._getexif.return_value = {0x010F: "Canon"}
        with patch("PIL.Image.open", return_value=img):
            result = eo._parse_exif_sync(b"x" * 100, "t.jpg")
        assert result.thumbnail == {"has": True, "size_bytes": 0}
        assert result.image.has_thumbnail is True


# ── 4. analyze_url (exif_osint.py:510-543) ─────────────────────────────────

class _FakeResp:
    """Stand-in for an httpx.Response with configurable status."""

    def __init__(self, content=b"", json_data=None, status_code=200, reason="OK"):
        self.content = content
        self.status_code = status_code
        self.reason_phrase = reason
        self._json = json_data
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

    def json(self):
        return self._json or {}


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

    async def get(self, *args, **kwargs):
        if self._exc:
            raise self._exc
        return self._resp


class TestAnalyzeUrl:
    @pytest.mark.asyncio
    async def test_empty_url_raises(self):
        """Covers exif_osint.py:510-511 — empty URL -> ValueError."""
        with pytest.raises(ValueError, match="empty"):
            await analyze_url("")

    @pytest.mark.asyncio
    async def test_bad_scheme_raises(self):
        """Covers exif_osint.py:514-515 — non-http(s) scheme -> ValueError."""
        with pytest.raises(ValueError, match="http"):
            await analyze_url("ftp://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_success_downloads_and_analyzes_image(self):
        """Covers exif_osint.py:517-543 — happy path with a real generated JPEG.

        Filename is extracted from the URL path and _source_url is annotated.
        """
        img = Image.new("RGB", (10, 10), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        resp = _FakeResp(content=buf.getvalue())
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            result = await analyze_url("https://example.com/images/photo.jpg")
        assert result.filename == "photo.jpg"
        assert result._source_url == "https://example.com/images/photo.jpg"
        assert result.image.format == "JPEG"
        assert result.image.width == 10
        assert result.has_exif is False  # plain JPEG carries no EXIF block

    @pytest.mark.asyncio
    async def test_timeout_raises_value_error(self):
        """Covers exif_osint.py:525-526 — TimeoutException -> ValueError 'Timeout'."""
        with patch("httpx.AsyncClient",
                   return_value=_FakeClient(exc=httpx.TimeoutException("slow"))):
            with pytest.raises(ValueError, match="Timeout"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_http_status_error_raises_value_error(self):
        """Covers exif_osint.py:527-528 — HTTPStatusError -> ValueError 'HTTP'."""
        resp = _FakeResp(status_code=404, reason="Not Found")
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            with pytest.raises(ValueError, match="HTTP 404"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_request_error_raises_value_error(self):
        """Covers exif_osint.py:529-530 — RequestError -> ValueError 'Network error'."""
        exc = httpx.RequestError("connection refused", request=MagicMock())
        with patch("httpx.AsyncClient", return_value=_FakeClient(exc=exc)):
            with pytest.raises(ValueError, match="Network error"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_content_exceeds_max_file_size(self):
        """Covers exif_osint.py:534-535 — oversized download -> ValueError 'exceeds'."""
        resp = _FakeResp(content=b"\x00" * 100)
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)), \
             patch.object(eo, "_MAX_FILE_SIZE", 10):
            with pytest.raises(ValueError, match="exceeds"):
                await analyze_url("https://example.com/img.jpg")


# ── 5. reverse_geocode (exif_osint.py:563-598) ─────────────────────────────

class TestReverseGeocode:
    @pytest.mark.asyncio
    async def test_success_prefers_city(self):
        """Covers exif_osint.py:577-598 — full result dict; city wins over town/village."""
        resp = _FakeResp(json_data={
            "address": {
                "country": "Spain",
                "country_code": "es",
                "city": "Madrid",
                "town": "IgnoredTown",
                "village": "IgnoredVillage",
                "state": "Community of Madrid",
                "road": "Gran Via",
                "house_number": "1",
                "postcode": "28013",
            },
            "display_name": "Gran Via, Madrid, Spain",
            "lat": "40.4",
            "lon": "-3.7",
        })
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            out = await reverse_geocode(40.4168, -3.7038)
        assert out is not None
        assert out["country"] == "Spain"
        assert out["country_code"] == "es"
        assert out["city"] == "Madrid"
        assert out["state"] == "Community of Madrid"
        assert out["road"] == "Gran Via"
        assert out["house_number"] == "1"
        assert out["postcode"] == "28013"
        assert out["display_name"] == "Gran Via, Madrid, Spain"
        assert out["lat"] == "40.4"
        assert out["lon"] == "-3.7"

    @pytest.mark.asyncio
    async def test_success_town_fallback_when_no_city(self):
        """Covers exif_osint.py:590 — city or town or village fallback chain."""
        resp = _FakeResp(json_data={
            "address": {"town": "Pinto", "country": "Spain"},
            "display_name": "Pinto, Spain",
        })
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            out = await reverse_geocode(40.25, -3.7)
        assert out is not None
        assert out["city"] == "Pinto"

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        """Covers exif_osint.py:582-584 — raise_for_status failure -> None."""
        resp = _FakeResp(status_code=503, reason="Service Unavailable")
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            out = await reverse_geocode(40.0, -3.0)
        assert out is None

    @pytest.mark.asyncio
    async def test_network_error_returns_none(self):
        """Covers exif_osint.py:582-584 — generic exception from get() -> None."""
        with patch("httpx.AsyncClient",
                   return_value=_FakeClient(exc=httpx.TimeoutException("slow"))):
            out = await reverse_geocode(40.0, -3.0)
        assert out is None
