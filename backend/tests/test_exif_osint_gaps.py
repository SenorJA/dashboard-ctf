"""
Coverage-gap tests for exif_osint.py.

Covers Image.open failure, tuple-value conversion exception, analyze_url
success/timeout/HTTP error/network error/size-limit paths, and
reverse_geocode success/failure.

NOTE: imports the module as plain `exif_osint` (same name as the existing
suite) to avoid a second module instance.
"""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.exif_osint as eo
from backend.exif_osint import analyze_url, reverse_geocode


class _FakeImage:
    """Duck-typed Pillow Image for _parse_exif_sync."""

    def __init__(self, exif_data=None, info=None, thumb_raises=False):
        self.format = "JPEG"
        self.width = 10
        self.height = 10
        self.info = info or {}
        self._exif = exif_data
        self.thumb_raises = thumb_raises

    def getexif(self):
        return _FakeExif({})

    def _getexif(self):
        return self._exif


class _FakeExif:
    def __init__(self, data):
        self._data = data

    def get(self, key, default=None):
        return self._data.get(key, default)


class TestParseExifSync:
    def test_image_open_failure(self):
        with patch("PIL.Image.open", side_effect=Exception("corrupt")):
            result = eo._parse_exif_sync(b"\xff\xd8\xff\xd9", "broken.jpg")
        assert result.has_exif is False
        assert result.filename == "broken.jpg"

    def test_tuple_value_conversion_exception(self):
        class ExplodingTuple(tuple):
            def __getitem__(self, idx):
                raise RuntimeError("boom")

        exif_data = {0x010F: ExplodingTuple((1, 2))}
        img = _FakeImage(exif_data=exif_data)
        with patch("PIL.Image.open", return_value=img):
            result = eo._parse_exif_sync(b"x", "t.jpg")
        # Conversion fell back to str(value) -> raw tag present.
        assert result.has_exif is True
        assert "Make" in result.raw_tags

    def test_rational_and_list_values(self):
        exif_data = {0x011A: (300, 1), 0x010E: ("a", "b")}
        img = _FakeImage(exif_data=exif_data)
        with patch("PIL.Image.open", return_value=img):
            result = eo._parse_exif_sync(b"x", "t.jpg")
        assert result.raw_tags.get("XResolution") == "300/1"
        assert result.raw_tags.get("ImageDescription") == ["a", "b"]


class _FakeResp:
    def __init__(self, content=b"", json_data=None, status_code=200, reason="OK"):
        self.content = content
        self._json = json_data
        self.status_code = status_code
        self.reason_phrase = reason

    def raise_for_status(self):
        if self.status_code >= 400:
            from httpx import HTTPStatusError
            raise HTTPStatusError(
                f"Error {self.status_code}",
                request=MagicMock(),
                response=MagicMock(status_code=self.status_code, reason_phrase=self.reason_phrase),
            )

    def json(self):
        return self._json or {}


class _FakeClient:
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
    async def test_success(self):
        # Non-image bytes -> Image.open fails -> EXIFResult fallback,
        # but the download path (incl. filename extraction) is covered.
        resp = _FakeResp(content=b"\xff\xd8\xff\xd9" + b"\x00" * 100)
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            result = await analyze_url("https://example.com/img/photo.jpg")
        assert result.filename == "photo.jpg"
        assert result.has_exif is False
        assert result._source_url == "https://example.com/img/photo.jpg"

    @pytest.mark.asyncio
    async def test_timeout(self):
        from httpx import TimeoutException
        with patch("httpx.AsyncClient", return_value=_FakeClient(exc=TimeoutException("slow"))):
            with pytest.raises(ValueError, match="Timeout"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_http_status_error(self):
        resp = _FakeResp(status_code=404, reason="Not Found")
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            with pytest.raises(ValueError, match="HTTP 404"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_request_error(self):
        from httpx import RequestError
        exc = RequestError("boom", request=MagicMock())
        with patch("httpx.AsyncClient", return_value=_FakeClient(exc=exc)):
            with pytest.raises(ValueError, match="Network error"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_size_limit(self):
        resp = _FakeResp(content=b"\x00" * 100)
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)), \
             patch.object(eo, "_MAX_FILE_SIZE", 10):
            with pytest.raises(ValueError, match="exceeds"):
                await analyze_url("https://example.com/img.jpg")

    @pytest.mark.asyncio
    async def test_invalid_url(self):
        with pytest.raises(ValueError, match="http"):
            await analyze_url("ftp://example.com/img.jpg")


class TestReverseGeocode:
    @pytest.mark.asyncio
    async def test_success(self):
        resp = _FakeResp(json_data={
            "address": {
                "country": "Spain",
                "country_code": "es",
                "city": "Madrid",
                "state": "Community of Madrid",
                "road": "Gran Via",
                "house_number": "1",
                "postcode": "28013",
            }
        })
        with patch("httpx.AsyncClient", return_value=_FakeClient(resp=resp)):
            out = await reverse_geocode(40.4168, -3.7038)
        assert out is not None
        assert out["country"] == "Spain"
        assert out["city"] == "Madrid"

    @pytest.mark.asyncio
    async def test_failure(self):
        with patch("httpx.AsyncClient", return_value=_FakeClient(exc=RuntimeError("net down"))):
            out = await reverse_geocode(40.0, -3.0)
        assert out is None
