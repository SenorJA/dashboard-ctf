"""
Tests for exif_osint — EXIF metadata extraction and analysis.

Covers:
  - JPEG image with full EXIF data (including GPS)
  - Image without EXIF metadata
  - Invalid / empty input handling
  - Severity calculation
  - Findings generation in MIRV format
  - GPS DMS-to-decimal conversion
"""

import io
import struct
import sys
import os

import pytest
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from exif_osint import (
    EXIFResult,
    analyze_image,
    report_to_mirv_findings,
)


# ── Fixtures ──


@pytest.fixture
def jpeg_with_full_exif() -> bytes:
    """Generate a JPEG with complete EXIF data including GPS coordinates."""
    img = Image.new("RGB", (200, 150), color=(73, 109, 137))
    exif_data = img.getexif()

    # Camera info
    exif_data[0x010F] = "Apple"               # Make
    exif_data[0x0110] = "iPhone 15 Pro"       # Model
    exif_data[0x0131] = "17.0.3"              # Software
    exif_data[0x0132] = "2024:06:15 14:30:00" # DateTime
    exif_data[0x010E] = "Test Image Description"  # ImageDescription
    exif_data[0x013B] = "John Doe"            # Artist
    exif_data[0x8298] = "John Doe"            # Copyright
    exif_data[0xA002] = 4032                  # PixelXDimension
    exif_data[0xA003] = 3024                  # PixelYDimension
    exif_data[0x8827] = 1.0                   # ISO
    exif_data[0x920A] = (50, 10)              # FocalLength (5.0mm)
    exif_data[0x829D] = (1, 30)               # FNumber (1/30 → 0.033...)
    exif_data[0x829A] = (1, 120)              # ExposureTime (1/120s)

    # GPS data — Madrid (40.4168, -3.7038)
    gps_ifd = {
        0: b'\x02\x03\x00\x00',  # GPSLatitudeRef: "N"
        1: ((40, 1), (25, 1), (48, 100)),  # GPSLatitude: 40° 25' 0.48"
        2: b'\x03\x03\x00\x00',  # GPSLongitudeRef: "W"
        3: ((3, 1), (42, 1), (13, 100)),    # GPSLongitude: 3° 42' 0.13"
        4: b'\x00',              # GPSAltitudeRef: above sea level
        5: (650, 1),             # GPSAltitude: 650m
        6: b'\x00\x00\x00\x00',  # GPSTimeStamp (skip for simplicity)
        7: b'\x00\x00\x00\x00',  # GPSSatellites
        29: b'\x00\x00\x00\x00', # GPSDateStamp
    }
    exif_data[0x8825] = gps_ifd  # GPSInfo

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_data.tobytes())
    return buf.getvalue()


@pytest.fixture
def jpeg_without_exif() -> bytes:
    """Generate a plain JPEG with absolutely no EXIF data."""
    img = Image.new("RGB", (100, 100), color=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture
def png_without_exif() -> bytes:
    """Generate a plain PNG (EXIF not native to PNG)."""
    img = Image.new("RGBA", (50, 50), color=(255, 0, 0, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ──────────────────────────────────────────────
# 1. Basic analysis — valid image with full EXIF
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_full_exif_returns_result(jpeg_with_full_exif: bytes):
    """Analysis of JPEG with EXIF should return EXIFResult."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")

    assert isinstance(result, EXIFResult)
    assert result.filename == "test.jpg"
    assert result.has_exif is True
    assert result.duration_seconds >= 0


@pytest.mark.asyncio
async def test_analyze_full_exif_image_info(jpeg_with_full_exif: bytes):
    """Check image metadata dimensions and format."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")

    assert result.image.format == "JPEG"
    assert result.image.width == 200
    assert result.image.height == 150
    assert result.image.file_size == len(jpeg_with_full_exif)


@pytest.mark.asyncio
async def test_analyze_full_exif_camera_info(jpeg_with_full_exif: bytes):
    """Check camera metadata extraction."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")

    assert result.camera is not None
    assert result.camera.make == "Apple"
    assert result.camera.model == "iPhone 15 Pro"
    assert result.camera.software == "17.0.3"
    assert result.camera.iso == "1.0"
    assert result.camera.focal_length == "5.0 mm"


@pytest.mark.asyncio
async def test_analyze_full_exif_gps_coordinates(jpeg_with_full_exif: bytes):
    """Check GPS coordinate extraction and DMS→decimal conversion."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")

    assert result.gps is not None
    # Madrid: 40.4168° N, -3.7038° W
    assert abs(result.gps.lat - 40.4168) < 0.01  # ~40°25'0.48"N
    assert abs(result.gps.lon - (-3.7038)) < 0.01  # ~3°42'0.13"W
    assert abs(result.gps.altitude - 650.0) < 1.0  # 650m


@pytest.mark.asyncio
async def test_analyze_full_exif_metadata(jpeg_with_full_exif: bytes):
    """Check general metadata extraction."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")

    assert result.metadata is not None
    assert result.metadata.artist == "John Doe"
    assert result.metadata.copyright == "John Doe"
    assert result.metadata.description == "Test Image Description"


@pytest.mark.asyncio
async def test_analyze_full_exif_map_urls(jpeg_with_full_exif: bytes):
    """Check that GPS map URLs are generated correctly."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")

    assert result.gps is not None
    assert "openstreetmap.org" in result.gps.map_url
    assert str(round(result.gps.lat, 4)) in result.gps.map_url
    assert "google.com/maps" in result.gps.google_maps_url
    assert str(round(result.gps.lat, 4)) in result.gps.google_maps_url


# ──────────────────────────────────────────────
# 2. Severity calculation
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_severity_high_with_gps(jpeg_with_full_exif: bytes):
    """GPS data should result in HIGH severity."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")
    assert result.severity == "high"


@pytest.mark.asyncio
async def test_severity_medium_camera_only():
    """Camera info without GPS should result in MEDIUM severity."""
    img = Image.new("RGB", (100, 100), color=(0, 100, 200))
    exif_data = img.getexif()
    exif_data[0x010F] = "Canon"
    exif_data[0x0110] = "EOS R5"

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_data.tobytes())
    result = await analyze_image(buf.getvalue(), "camera.jpg")

    assert result.severity == "medium"
    assert result.gps is None


@pytest.mark.asyncio
async def test_severity_low_software_only():
    """Only software/artist metadata should result in LOW severity."""
    img = Image.new("RGB", (100, 100), color=(100, 0, 0))
    exif_data = img.getexif()
    exif_data[0x0131] = "Photoshop 2024"

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_data.tobytes())
    result = await analyze_image(buf.getvalue(), "edited.jpg")

    assert result.severity == "low"
    assert result.gps is None
    assert result.camera is None


@pytest.mark.asyncio
async def test_severity_info_no_exif(jpeg_without_exif: bytes):
    """No EXIF data should result in INFO severity."""
    result = await analyze_image(jpeg_without_exif, "noexif.jpg")
    assert result.severity == "info"
    assert result.has_exif is False
    assert result.gps is None
    assert result.camera is None
    assert result.metadata is None


# ──────────────────────────────────────────────
# 3. Images without EXIF data
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_analyze_no_exif_still_returns_image_info(jpeg_without_exif: bytes):
    """Image without EXIF should still return basic image info."""
    result = await analyze_image(jpeg_without_exif, "noexif.jpg")

    assert result.image.format == "JPEG"
    assert result.image.width == 100
    assert result.image.height == 100
    assert result.has_exif is False
    assert result.raw_tags == {}


@pytest.mark.asyncio
async def test_analyze_png_no_exif(png_without_exif: bytes):
    """PNG without EXIF should still analyze correctly."""
    result = await analyze_image(png_without_exif, "test.png")

    assert result.image.format == "PNG"
    assert result.has_exif is False
    assert result.severity == "info"


# ──────────────────────────────────────────────
# 4. Invalid / edge-case inputs
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_empty_bytes_raises_error():
    """Empty bytes should raise a ValueError."""
    with pytest.raises(ValueError, match="Empty"):
        await analyze_image(b"", "empty.jpg")


@pytest.mark.asyncio
async def test_invalid_bytes_raises_error():
    """Corrupt/non-image bytes should raise a ValueError."""
    with pytest.raises((ValueError, Exception)):
        await analyze_image(b"this is not an image file at all", "fake.jpg")


@pytest.mark.asyncio
async def test_very_small_valid_image():
    """Tiny valid image should still process."""
    img = Image.new("RGB", (1, 1), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    result = await analyze_image(buf.getvalue(), "tiny.jpg")

    assert result.image.width == 1
    assert result.image.height == 1


# ──────────────────────────────────────────────
# 5. Findings generation (report_to_mirv_findings)
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_findings_format(jpeg_with_full_exif: bytes):
    """report_to_mirv_findings should return a list of dicts in MIRV format."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")
    findings = report_to_mirv_findings(result)

    assert isinstance(findings, list)
    assert len(findings) > 0

    for f in findings:
        assert "tool" in f
        assert f["tool"] == "exif-osint"
        assert "severity" in f
        assert f["severity"] in ("high", "medium", "low", "info")
        assert "title" in f
        assert "detail" in f
        assert "type" in f
        assert f["type"] in ("vuln", "tech")
        assert "extra" in f


@pytest.mark.asyncio
async def test_findings_include_gps_high(jpeg_with_full_exif: bytes):
    """Findings should include a HIGH severity entry for GPS."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")
    findings = report_to_mirv_findings(result)

    gps_findings = [f for f in findings if f["severity"] == "high"]
    assert len(gps_findings) >= 1
    assert "GPS" in gps_findings[0]["title"]


@pytest.mark.asyncio
async def test_findings_include_image_info(jpeg_with_full_exif: bytes):
    """Findings should include an INFO entry for basic image info."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")
    findings = report_to_mirv_findings(result)

    info_findings = [f for f in findings if f["severity"] == "info"]
    assert len(info_findings) >= 1
    assert "200x150" in info_findings[0]["title"] or "JPEG" in info_findings[0]["title"]


@pytest.mark.asyncio
async def test_findings_empty_when_no_exif(jpeg_without_exif: bytes):
    """No EXIF should still produce at least the image info finding."""
    result = await analyze_image(jpeg_without_exif, "noexif.jpg")
    findings = report_to_mirv_findings(result)

    assert len(findings) >= 1  # at least image info
    assert all(f["severity"] == "info" for f in findings)


# ──────────────────────────────────────────────
# 6. Raw tags
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_raw_tags_contains_make(jpeg_with_full_exif: bytes):
    """Raw tags should include Make."""
    result = await analyze_image(jpeg_with_full_exif, "test.jpg")
    assert "Make" in result.raw_tags
    assert result.raw_tags["Make"] == "Apple"


@pytest.mark.asyncio
async def test_raw_tags_empty_no_exif(jpeg_without_exif: bytes):
    """No EXIF image should have empty raw_tags."""
    result = await analyze_image(jpeg_without_exif, "noexif.jpg")
    assert result.raw_tags == {}
