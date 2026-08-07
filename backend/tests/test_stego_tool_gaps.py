"""
Coverage-gap tests for backend/stego_tool.py — internal branches.

Covers:
  - _parse_png(): bad signature, truncated chunk, no IHDR
  - _extract_lsb_from_raw(): bit→byte conversion + printable text decode
  - _try_decode_as_text(): short data, non-printable, UTF-8 failure → ASCII
  - _examine_trailing_data(): truncated PNG walk
  - _analyze_image_data(): BMP too small
  - analyze(): URL fetch path, PNG LSB message, PNG without IDAT,
    PNG corrupt IDAT, BMP LSB message, BMP LSB error
  - report_to_mirv_findings(): LSB non-printable (low), anomaly w/ error (medium)
"""

import struct
import sys
import os
import zlib

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stego_tool import (
    ImageInfo,
    StegoResult,
    analyze,
    _analyze_image_data,
    _examine_trailing_data,
    _extract_lsb_from_raw,
    _parse_png,
    _try_decode_as_text,
    report_to_mirv_findings,
)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png_chunk(ctype, cdata):
    return (
        struct.pack(">I", len(cdata))
        + ctype
        + cdata
        + struct.pack(">I", zlib.crc32(ctype + cdata))
    )


def _png_ihdr(width=8, height=8, bit_depth=8, color_type=2):
    return struct.pack(">IIBBBBB", width, height, bit_depth, color_type, 0, 0, 0)


def _png_with_raw(raw, color_type=2):
    return (
        PNG_SIG
        + _png_chunk(b"IHDR", _png_ihdr(8, 8, 8, color_type))
        + _png_chunk(b"IDAT", zlib.compress(raw))
        + _png_chunk(b"IEND", b"")
    )


def _lsb_bytes(msg: bytes) -> bytes:
    """Build bytes whose LSB stream equals the message bit stream."""
    bits = []
    for ch in msg:
        for i in range(7, -1, -1):
            bits.append((ch >> i) & 1)
    return bytes(bits)


def _bmp_with_lsb(msg: bytes, bpp: int = 8) -> bytes:
    """8x8 BMP whose first pixel bytes carry an LSB message.

    The stego LSB extractor only handles bit_depth == 8, so the fixture
    defaults to an 8-bit indexed BMP (no palette validation is done by
    the parser — it only reads the header fields it needs).
    """
    pixel = _lsb_bytes(msg)
    row_size = 8 * bpp // 8
    padded_row = ((row_size + 3) // 4) * 4
    image_size = padded_row * 8
    data = bytearray(54 + image_size)
    data[0:2] = b"BM"
    struct.pack_into("<I", data, 2, len(data))
    struct.pack_into("<I", data, 10, 54)   # pixel offset
    struct.pack_into("<I", data, 14, 40)   # DIB header size
    struct.pack_into("<i", data, 18, 8)    # width
    struct.pack_into("<i", data, 22, 8)    # height
    struct.pack_into("<H", data, 26, 1)    # planes
    struct.pack_into("<H", data, 28, bpp)  # bits per pixel
    struct.pack_into("<I", data, 30, 0)    # compression
    struct.pack_into("<I", data, 34, image_size)
    data[54 : 54 + len(pixel)] = pixel
    return bytes(data)


# ════════════════════════════════════════════════════
#  _parse_png() internal branches
# ════════════════════════════════════════════════════

class TestParsePngBranches:
    def test_bad_signature_raises(self):
        with pytest.raises(ValueError, match="signature"):
            _parse_png(b"not a png file at all")

    def test_truncated_after_ihdr_breaks(self):
        # Valid IHDR then truncated tail → walk hits pos+8 > len(data)
        png = PNG_SIG + _png_chunk(b"IHDR", _png_ihdr()) + b"\x00\x00"
        info, idat = _parse_png(png)
        assert info.format == "png"
        assert info.width == 8
        assert idat == []

    def test_no_ihdr_raises(self):
        data = PNG_SIG + b"\x00" * 60
        with pytest.raises(ValueError, match="IHDR"):
            _parse_png(data)

    def test_rgba_alpha_flag(self):
        png = _png_with_raw(b"\x00" * 200, color_type=6)
        info, _ = _parse_png(png)
        assert info.has_alpha is True


# ════════════════════════════════════════════════════
#  _extract_lsb_from_raw / _try_decode_as_text
# ════════════════════════════════════════════════════

class TestLsbExtractionBranches:
    def test_extract_printable_message(self):
        raw = _lsb_bytes(b"HELLO")
        extracted, message = _extract_lsb_from_raw(raw, 8, 8, 3, 8)
        assert extracted == [72, 69, 76, 76, 79]
        assert message == "HELLO"

    def test_extract_non_8bit_returns_empty(self):
        extracted, message = _extract_lsb_from_raw(b"\x01\x02", 8, 8, 3, 16)
        assert extracted == []
        assert message is None

    def test_try_decode_short_data_returns_none(self):
        assert _try_decode_as_text([65, 66]) is None

    def test_try_decode_non_printable_returns_none(self):
        assert _try_decode_as_text([0, 0, 0, 0, 0, 0, 0, 0]) is None

    def test_try_decode_invalid_utf8_returns_none(self):
        # 0xFF is invalid in both UTF-8 and ASCII → both excepts run
        assert _try_decode_as_text([0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) is None


# ════════════════════════════════════════════════════
#  _examine_trailing_data / _analyze_image_data
# ════════════════════════════════════════════════════

class TestTrailingAndFormatBranches:
    def test_examine_truncated_png_breaks(self):
        # Walk hits pos+8 > len(data) before any IEND → no trailing data
        data = PNG_SIG + b"\x00\x00"
        found, size, preview = _examine_trailing_data(data, "png")
        assert found is False
        assert size == 0

    def test_bmp_too_small_raises(self):
        with pytest.raises(ValueError, match="too small"):
            _analyze_image_data(b"BM" + b"\x00" * 10)


# ════════════════════════════════════════════════════
#  analyze() — URL fetch + LSB paths
# ════════════════════════════════════════════════════

class TestAnalyzePaths:
    @pytest.mark.asyncio
    async def test_analyze_from_url(self, sample_png):
        class _FakeResp:
            content = sample_png

            def raise_for_status(self):
                pass

        class _FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, url):
                return _FakeResp()

        import httpx

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(httpx, "AsyncClient", _FakeClient)
            result = await analyze(url="http://example.com/img.png")
        assert result.image_info.format == "png"
        assert result.image_info.file_size == len(sample_png)

    @pytest.mark.asyncio
    async def test_png_lsb_message_detected(self):
        png = _png_with_raw(_lsb_bytes(b"HELLO"))
        result = await analyze(data=png)
        assert result.lsb_message == "HELLO"
        assert any("LSB-encoded" in a for a in result.anomalies)
        assert result.lsb_suspicious is True

    @pytest.mark.asyncio
    async def test_png_without_idat_anomaly(self):
        png = (
            PNG_SIG
            + _png_chunk(b"IHDR", _png_ihdr())
            + _png_chunk(b"tEXt", b"Comment=buffer")
            + _png_chunk(b"IEND", b"")
        )
        result = await analyze(data=png)
        assert any("No IDAT chunks" in a for a in result.anomalies)

    @pytest.mark.asyncio
    async def test_png_corrupt_idat_anomaly(self):
        png = (
            PNG_SIG
            + _png_chunk(b"IHDR", _png_ihdr())
            + _png_chunk(b"IDAT", b"not zlib data at all")
            + _png_chunk(b"IEND", b"")
        )
        result = await analyze(data=png)
        assert any("LSB analysis error" in a for a in result.anomalies)

    @pytest.mark.asyncio
    async def test_bmp_lsb_message_detected(self):
        bmp = _bmp_with_lsb(b"OSINT!")
        result = await analyze(data=bmp, lsb_length=48)
        assert result.lsb_message == "OSINT!"
        assert any("BMP" in a for a in result.anomalies)
        assert result.lsb_suspicious is True

    @pytest.mark.asyncio
    async def test_bmp_lsb_error_anomaly(self, sample_bmp):
        from unittest.mock import patch

        with patch(
            "stego_tool._extract_lsb_from_raw",
            side_effect=RuntimeError("bmp boom"),
        ):
            result = await analyze(data=sample_bmp)
        assert any("BMP LSB analysis error" in a for a in result.anomalies)


# ════════════════════════════════════════════════════
#  report_to_mirv_findings() — remaining branches
# ════════════════════════════════════════════════════

class TestReportBranches:
    def test_lsb_extracted_not_printable_low_finding(self):
        info = ImageInfo(width=8, height=8, bit_depth=8, color_type=2,
                         format="png", file_size=100)
        res = StegoResult(
            image_info=info,
            lsb_suspicious=False,
            trailing_data_found=False,
            lsb_message=None,
            lsb_bytes=[0x12, 0x34],
            lsb_extracted_length=10,
        )
        findings = report_to_mirv_findings(res)
        assert any(f["severity"] == "low" for f in findings)

    def test_anomaly_with_error_medium_finding(self):
        info = ImageInfo(width=8, height=8, bit_depth=8, color_type=2,
                         format="png", file_size=100)
        res = StegoResult(
            image_info=info,
            lsb_suspicious=False,
            trailing_data_found=False,
            anomalies=["LSB analysis error: something went wrong"],
        )
        findings = report_to_mirv_findings(res)
        assert any(f["severity"] == "medium" for f in findings)
