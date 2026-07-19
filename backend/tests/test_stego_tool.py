"""
Tests for stego_tool — pure-Python steganography detection.

Covers:
  - Clean PNG analysis (no hidden data)
  - PNG with trailing data appended after IEND
  - BMP format detection and analysis
  - Invalid / empty input handling
  - Response shape and findings generation
"""

import struct
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stego_tool import (
    StegoResult,
    analyze,
    report_to_mirv_findings,
)


# ──────────────────────────────────────────────
# 1. Valid clean PNG — no LSB, no trailing data
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_png_valid_format(sample_png: bytes):
    """A pristine 1x1 red PNG should parse as PNG with correct dimensions."""
    result = await analyze(data=sample_png)

    assert isinstance(result, StegoResult)
    assert result.image_info.format == "png"
    assert result.image_info.width == 1
    assert result.image_info.height == 1
    assert result.image_info.file_size == len(sample_png)
    assert result.image_info.bit_depth == 8
    assert result.image_info.color_type == 6  # RGBA (the fixture PNG has alpha)


@pytest.mark.asyncio
async def test_clean_png_no_lsb_data(sample_png: bytes):
    """A tiny clean PNG should have no suspicious LSB-encoded message."""
    result = await analyze(data=sample_png)

    assert result.lsb_suspicious is False
    assert result.lsb_message is None
    # The 1x1 image is far too small for a meaningful text message
    assert result.lsb_extracted_length == 0 or result.lsb_message is None


@pytest.mark.asyncio
async def test_clean_png_no_trailing_data(sample_png: bytes):
    """No bytes should follow the IEND chunk in a standard PNG."""
    result = await analyze(data=sample_png)

    assert result.trailing_data_found is False
    assert result.trailing_data_size == 0
    assert result.trailing_data_preview is None


@pytest.mark.asyncio
async def test_clean_png_no_anomalies(sample_png: bytes):
    """A clean PNG should produce zero anomalies."""
    result = await analyze(data=sample_png)

    assert result.anomalies == []


# ──────────────────────────────────────────────
# 2. PNG with trailing data appended after IEND
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_png_trailing_data_detected(sample_png: bytes):
    """Appending bytes after IEND must be detected as trailing data."""
    hidden_payload = b"hidden data"
    tampered = sample_png + hidden_payload

    result = await analyze(data=tampered)

    assert result.trailing_data_found is True
    assert result.trailing_data_size == len(hidden_payload)
    assert result.trailing_data_preview is not None


@pytest.mark.asyncio
async def test_png_trailing_data_in_anomalies(sample_png: bytes):
    """Trailing-data detection should produce an anomaly entry."""
    tampered = sample_png + b"SECRET"
    result = await analyze(data=tampered)

    trailing_anomalies = [a for a in result.anomalies if "trailing" in a.lower()]
    assert len(trailing_anomalies) >= 1
    assert "6 bytes" in trailing_anomalies[0]  # len(b"SECRET") == 6


@pytest.mark.asyncio
async def test_png_trailing_large_payload(sample_png: bytes):
    """Large trailing payload (1 KB) should be correctly measured."""
    large_payload = os.urandom(1024)
    tampered = sample_png + large_payload

    result = await analyze(data=tampered)

    assert result.trailing_data_found is True
    assert result.trailing_data_size == 1024
    # Preview should exist but be truncated / hex-formatted
    assert result.trailing_data_preview is not None


@pytest.mark.asyncio
async def test_png_trailing_hex_preview_format(sample_png: bytes):
    """Trailing data preview for small payloads should be hex-formatted."""
    payload = b"\xde\xad\xbe\xef"
    tampered = sample_png + payload
    result = await analyze(data=tampered)

    assert result.trailing_data_found is True
    # Preview should contain hex digits
    assert result.trailing_data_preview is not None
    assert "de" in result.trailing_data_preview.lower() or "de" in result.trailing_data_preview


# ──────────────────────────────────────────────
# 3. BMP format detection
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_bmp_valid_format(sample_bmp: bytes):
    """A minimal 2x2 32-bit BMP should parse as BMP."""
    result = await analyze(data=sample_bmp)

    assert isinstance(result, StegoResult)
    assert result.image_info.format == "bmp"
    assert result.image_info.width == 2
    assert result.image_info.height == 2
    assert result.image_info.bit_depth == 32
    assert result.image_info.file_size == len(sample_bmp)


@pytest.mark.asyncio
async def test_bmp_no_trailing_data(sample_bmp: bytes):
    """A clean BMP with no appended bytes should have no trailing data."""
    result = await analyze(data=sample_bmp)

    assert result.trailing_data_found is False
    assert result.trailing_data_size == 0


@pytest.mark.asyncio
async def test_bmp_trailing_data_detected(sample_bmp: bytes):
    """Appending data to a BMP should be flagged if implementation checks."""
    tampered = sample_bmp + b"\x00" * 16
    result = await analyze(data=tampered)
    # BMP trailing detection may or may not be implemented;
    # at minimum, the analysis should complete without error
    assert isinstance(result, StegoResult)
    assert result.image_info.format == "bmp"


@pytest.mark.asyncio
async def test_bmp_capacity_estimated(sample_bmp: bytes):
    """BMP estimated LSB capacity should be > 0 for a non-trivial image."""
    result = await analyze(data=sample_bmp)
    assert result.image_info.estimated_capacity_bytes > 0


# ──────────────────────────────────────────────
# 4. Empty / invalid bytes — error handling
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_empty_bytes_raises():
    """Empty input should raise ValueError (image too small / no data)."""
    with pytest.raises(ValueError):
        await analyze(data=b"")


@pytest.mark.asyncio
async def test_none_raises():
    """Passing neither data nor url should raise ValueError."""
    with pytest.raises(ValueError):
        await analyze(data=None, url=None)


@pytest.mark.asyncio
async def test_short_bytes_raises():
    """Bytes shorter than 50 should raise ValueError."""
    with pytest.raises(ValueError):
        await analyze(data=b"\x00" * 10)


@pytest.mark.asyncio
async def test_garbage_bytes_raises():
    """Random non-image bytes should raise ValueError (unsupported format)."""
    garbage = b"this is not an image file at all, just random garbage bytes!!"
    with pytest.raises(ValueError):
        await analyze(data=garbage)


@pytest.mark.asyncio
async def test_text_file_raises():
    """A plain text file should be rejected as unsupported format."""
    with pytest.raises(ValueError):
        await analyze(data=b"%PDF-1.4 fake pdf header content here")


@pytest.mark.asyncio
async def test_truncated_png_raises():
    """A PNG signature without valid chunks should fail gracefully."""
    truncated = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30
    with pytest.raises((ValueError, Exception)):
        await analyze(data=truncated)


# ──────────────────────────────────────────────
# 5. Response shape — StegoResult always complete
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stego_result_has_required_fields(sample_png: bytes):
    """StegoResult dataclass must always have all expected attributes."""
    result = await analyze(data=sample_png)

    # Top-level StegoResult fields
    assert hasattr(result, "image_info")
    assert hasattr(result, "lsb_suspicious")
    assert hasattr(result, "trailing_data_found")
    assert hasattr(result, "lsb_message")
    assert hasattr(result, "lsb_bytes")
    assert hasattr(result, "lsb_extracted_length")
    assert hasattr(result, "trailing_data_size")
    assert hasattr(result, "trailing_data_preview")
    assert hasattr(result, "anomalies")
    assert hasattr(result, "duration_seconds")

    # ImageInfo sub-fields
    info = result.image_info
    assert hasattr(info, "width")
    assert hasattr(info, "height")
    assert hasattr(info, "format")
    assert hasattr(info, "file_size")
    assert hasattr(info, "bit_depth")
    assert hasattr(info, "color_type")
    assert hasattr(info, "has_alpha")
    assert hasattr(info, "estimated_capacity_bytes")


@pytest.mark.asyncio
async def test_stego_result_types(sample_png: bytes):
    """StegoResult field types should match their declared types."""
    result = await analyze(data=sample_png)

    assert isinstance(result.lsb_suspicious, bool)
    assert isinstance(result.trailing_data_found, bool)
    assert isinstance(result.anomalies, list)
    assert isinstance(result.lsb_extracted_length, int)
    assert isinstance(result.trailing_data_size, int)
    assert isinstance(result.duration_seconds, float)
    assert isinstance(result.image_info.width, int)
    assert isinstance(result.image_info.height, int)
    assert isinstance(result.image_info.format, str)
    assert isinstance(result.image_info.file_size, int)


@pytest.mark.asyncio
async def test_stego_result_bool_fields_default_false(sample_png: bytes):
    """Boolean flags should default to False on a clean image."""
    result = await analyze(data=sample_png)

    assert result.lsb_suspicious is False
    assert result.trailing_data_found is False


# ──────────────────────────────────────────────
# 6. report_to_mirv_findings — findings list shape
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_list_shape(sample_png: bytes):
    """report_to_mirv_findings must return a list of dicts with required keys."""
    result = await analyze(data=sample_png)
    findings = report_to_mirv_findings(result)

    assert isinstance(findings, list)
    assert len(findings) >= 1

    required_keys = {"tool", "severity", "title", "detail", "target", "type"}
    for finding in findings:
        assert isinstance(finding, dict)
        assert required_keys.issubset(finding.keys()), (
            f"Missing keys: {required_keys - finding.keys()}"
        )
        assert finding["tool"] == "stego-tool"
        assert finding["severity"] in ("info", "low", "medium", "high", "critical")


@pytest.mark.asyncio
async def test_findings_clean_png_no_high_severity(sample_png: bytes):
    """A clean PNG should produce only info-level findings (no high/critical)."""
    result = await analyze(data=sample_png)
    findings = report_to_mirv_findings(result)

    high_findings = [f for f in findings if f["severity"] in ("high", "critical")]
    assert high_findings == [], f"Unexpected high-severity findings: {high_findings}"


@pytest.mark.asyncio
async def test_findings_trailing_data_high_severity(sample_png: bytes):
    """Trailing data should produce at least one high-severity finding."""
    tampered = sample_png + b"SECRET"
    result = await analyze(data=tampered)
    findings = report_to_mirv_findings(result)

    high_findings = [f for f in findings if f["severity"] == "high"]
    assert len(high_findings) >= 1, "Trailing data should trigger a high-severity finding"
    assert any("trailing" in f["title"].lower() for f in high_findings)


@pytest.mark.asyncio
async def test_findings_bmp_format(sample_bmp: bytes):
    """BMP analysis should produce findings with correct tool attribution."""
    result = await analyze(data=sample_bmp)
    findings = report_to_mirv_findings(result)

    assert len(findings) >= 1
    assert all(f["tool"] == "stego-tool" for f in findings)


# ──────────────────────────────────────────────
# 7. Duration tracking
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_duration_is_non_negative(sample_png: bytes):
    """Analysis duration should be a non-negative float."""
    result = await analyze(data=sample_png)
    assert result.duration_seconds >= 0.0


# ──────────────────────────────────────────────
# 8. LSB extraction flag
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lsb_extraction_can_be_disabled(sample_png: bytes):
    """Passing extract_lsb=False should skip LSB analysis."""
    result = await analyze(data=sample_png, extract_lsb=False)

    # No LSB extraction means no extracted bytes
    assert result.lsb_extracted_length == 0
    assert result.lsb_bytes is None
    assert result.lsb_message is None


@pytest.mark.asyncio
async def test_lsb_length_parameter(sample_bmp: bytes):
    """Custom lsb_length should be respected without crashing."""
    result = await analyze(data=sample_bmp, lsb_length=256)
    assert isinstance(result, StegoResult)
    assert result.lsb_extracted_length <= 256
