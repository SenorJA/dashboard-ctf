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

import base64
import io
import sys
import os

import pytest
from PIL import Image
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from exif_osint import (
    EXIFResult,
    analyze_image,
    report_to_mirv_findings,
)


# ── Fixtures ──


@pytest.fixture
def jpeg_with_full_exif() -> bytes:
    """A pre-built JPEG with EXIF including GPS (Madrid 40.4168, -3.7038).
    
    Generated with piexif to avoid Pillow 11 IFD serialization bugs.
    Contains: Make=Apple, Model=iPhone 15 Pro, Software=17.0.3,
    Artist=John Doe, GPS coords, ISO=100, FocalLength=5.0mm, etc.
    """
    return base64.b64decode(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/4QGqRXhpZgAATU0AKgAAAAgACQEOAAIAAAAXAAAAegEP"
        "AAIAAAAGAAAAkQEQAAIAAAAOAAAAlwExAAIAAAAHAAAApQEyAAIAAAAUAAAArAE7AAIAAAAJ"
        "AAAAwIKYAAIAAAAJAAAAyYdpAAQAAAABAAAA0oglAAQAAAABAAABIAAAAABUZXN0IEltYWdl"
        "IERlc2NyaXB0aW9uAEFwcGxlAGlQaG9uZSAxNSBQcm8AMTcuMC4zADIwMjQ6MDY6MTUgMTQ6"
        "MzA6MDAASm9obiBEb2UASm9obiBEb2UAAAWCmgAFAAAAAQAAARCIJwADAAAAAQBkAACSCgAF"
        "AAAAAQAAARigAgAEAAAAAQAAAMigAwAEAAAAAQAAAJYAAAABAAAAeAAAADIAAAAKAAYAAQAC"
        "AAAAAk4AAAAAAgAFAAAAAwAAAWoAAwACAAAAAlcAAAAABAAFAAAAAwAAAYIABQABAAAAAQAA"
        "AAAABgAFAAAAAQAAAZoAAAAoAAAAAQAAABkAAAABAAAAMAAAAGQAAAADAAAAAQAAACoAAAAB"
        "AAAADQAAAGQAAAKKAAAAAf/bAEMACAYGBwYFCAcHBwkJCAoMFA0MCwsMGRITDxQdGh8eHRoc"
        "HCAkLicgIiwjHBwoNyksMDE0NDQfJzk9ODI8LjM0Mv/bAEMBCQkJDAsMGA0NGDIhHCEyMjIy"
        "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMv/AABEIAJYA"
        "yAMBIgACEQEDEQH/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMD"
        "AQIDBQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZ"
        "GiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoOEhYaHiImK"
        "kpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5+jp"
        "6vHy8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAAAAQIDBAUGBwgJCgv/xAC1EQACAQIE"
        "BAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXx"
        "FxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoiI"
        "iYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo"
        "6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/AMSiiivSPNCiiigAooooAKKKKACiiigAooooAKKK"
        "KACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigA"
        "ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKK"
        "KACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigA"
        "ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKK"
        "KACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigA"
        "ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKK"
        "KACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigA"
        "ooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKK"
        "KACiiigAooooAKKKKACiiigAooooAKKKKAP/2Q=="
    )


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
    assert result.camera.iso == 100
    assert result.camera.focal_length == "5.0mm"


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
    # CameraInfo is created but only software is set; make/model should be None
    assert result.camera is not None
    assert result.camera.make is None
    assert result.camera.model is None


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
    with pytest.raises(ValueError, match="too small"):
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


# ──────────────────────────────────────────────
# 7. Helpers — lazy PIL tags, DMS conversion, GPS parsing
# ──────────────────────────────────────────────

from exif_osint import (
    _extract_gps,
    _dms_to_decimal,
    _load_pil_tags,
    _safe_float,
    _safe_str,
    _parse_exif_sync,
    analyze_url,
    GPSInfo,
    CameraInfo,
    ImageInfo,
    MetadataInfo,
)

# Minimal GPS tag maps (mirrors PIL ExifTags.GPSTAGS)
_GPS_TAGS = {
    0: "GPSLatitudeRef", 1: "GPSLatitude",
    2: "GPSLongitudeRef", 3: "GPSLongitude",
    4: "GPSAltitudeRef", 5: "GPSAltitude",
    6: "GPSTimeStamp",
}


def test_load_pil_tags_returns_tags():
    tags, gps_tags = _load_pil_tags()
    assert tags and gps_tags
    # Lazy-load is idempotent — second call returns same objects
    tags2, gps2 = _load_pil_tags()
    assert tags2 is tags and gps2 is gps_tags


def test_dms_to_decimal_zero_denominator():
    # (1/0, 0, 0) — division guard returns 0.0 for degree
    assert _dms_to_decimal(((1, 0), 0, 0), "N") == 0.0


def test_dms_to_decimal_south_negative():
    result = _dms_to_decimal(((40, 1), (25, 1), (0, 1)), "S")
    assert result < 0
    assert abs(result + 40.416667) < 0.001


def test_extract_gps_empty_dict_returns_none():
    assert _extract_gps({}, {}) is None


def test_extract_gps_missing_latitude_returns_none():
    raw = {0: "N"}  # has ref but no latitude value
    assert _extract_gps(raw, _GPS_TAGS) is None


def test_extract_gps_missing_longitude_returns_none():
    raw = {
        0: "N", 1: (40, 1),          # latitude complete
        2: "W",                       # longitude ref but no value
    }
    assert _extract_gps(raw, _GPS_TAGS) is None


def test_extract_gps_conversion_error_returns_none():
    raw = {
        0: "N", 1: "not-a-number",   # ValueError in _to_float
        2: "W", 3: (3, 1),
    }
    with patch("exif_osint.logger") as mock_logger:
        result = _extract_gps(raw, _GPS_TAGS)
    assert result is None
    mock_logger.debug.assert_called_once()


def test_extract_gps_altitude_below_sea_level():
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        4: 1, 5: (100, 1),
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps is not None
    assert gps.altitude == -100.0
    assert gps.altitude_ref == 1


def test_extract_gps_altitude_zero_denominator_none():
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        5: (5, 0),
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps.altitude is None


def test_extract_gps_altitude_plain_float():
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        5: 12.5,
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps.altitude == 12.5


def test_extract_gps_timestamp():
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        6: (10, 30, 45),  # GPSTimeStamp as plain int tuple
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps.gps_timestamp == "10:30:45"


def test_extract_gps_bad_timestamp_ignored():
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        6: (1, 2),  # short tuple, format falls back
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps.gps_timestamp is not None


def test_safe_float_rational_and_exception():
    assert _safe_float((3, 4)) == 0.75
    assert _safe_float(3.0) == 3.0
    assert _safe_float((1, 0)) is None  # zero denominator
    assert _safe_float("not-a-number") is None
    assert _safe_float(None) is None


def test_safe_str_strips_and_none():
    assert _safe_str(None) is None
    assert _safe_str("  hello  ") == "hello"
    assert _safe_str("") is None


# ──────────────────────────────────────────────
# 8. _parse_exif_sync — branch coverage via mocked PIL image
# ──────────────────────────────────────────────

def _mock_image(exif_data=None, thumbnail=None, color_space=None,
                orientation=None, getexif_raises=False):
    """Build a MagicMock standing in for a PIL Image."""
    img = MagicMock()
    img.format = "JPEG"
    img.width = 640
    img.height = 480
    img.info = {}
    if thumbnail is not None:
        img.info["thumbnail"] = thumbnail
    exif = MagicMock()
    exif.get.return_value = orientation
    img.getexif.return_value = exif
    if getexif_raises:
        img._getexif.side_effect = RuntimeError("exif unavailable")
    else:
        img._getexif.return_value = exif_data
    return img


def _run_parse_sync(img):
    with patch("PIL.Image.open", return_value=img):
        return _parse_exif_sync(b"fake-jpeg-bytes", "mock.jpg")


def test_parse_sync_orientation_and_color_space_srgb():
    img = _mock_image(
        exif_data={0xA001: 1},
        orientation=6,
    )
    result = _run_parse_sync(img)
    assert result.image.orientation == 6
    assert result.image.color_space == "sRGB"


def test_parse_sync_color_space_adobe():
    img = _mock_image(exif_data={0xA001: 2})
    result = _run_parse_sync(img)
    assert result.image.color_space == "Adobe RGB"


def test_parse_sync_color_space_other_tag():
    img = _mock_image(exif_data={0xA001: 5})
    result = _run_parse_sync(img)
    assert result.image.color_space == "Tag(5)"


def test_parse_sync_getexif_raises_early_return():
    img = _mock_image(getexif_raises=True)
    result = _run_parse_sync(img)
    assert result.has_exif is False
    assert result.severity == "info"
    assert result.image.width == 640


def test_parse_sync_thumbnail_bytes():
    img = _mock_image(exif_data=None, thumbnail=b"thumb-bytes")
    result = _run_parse_sync(img)
    assert result.image.has_thumbnail is True


def test_parse_sync_thumbnail_non_bytes():
    img = _mock_image(exif_data=None, thumbnail="string-thumb")
    result = _run_parse_sync(img)
    assert result.image.has_thumbnail is True


def test_parse_sync_raw_tags_rational():
    img = _mock_image(exif_data={0x010F: (3, 4)})  # Make as rational
    result = _run_parse_sync(img)
    assert result.raw_tags.get("Make") == "3/4"


def test_parse_sync_raw_tags_tuple_list():
    img = _mock_image(exif_data={0x010F: (1, 2, 3)})
    result = _run_parse_sync(img)
    assert result.raw_tags.get("Make") == ["1", "2", "3"]


def test_parse_sync_raw_tags_bytes():
    img = _mock_image(exif_data={0x010F: b"canon"})
    result = _run_parse_sync(img)
    assert result.raw_tags.get("Make") == "canon"


def test_parse_sync_lens_tuple_takes_first():
    img = _mock_image(exif_data={0x010F: "Canon", 0x0110: "EOS", 0xA434: ("RF 24-70mm", "extra")})
    result = _run_parse_sync(img)
    assert result.camera.lens == "RF 24-70mm"


def test_parse_sync_focal_fnumber_exposure_flash():
    img = _mock_image(exif_data={
        0x010F: "Canon", 0x0110: "EOS R5",
        0x920A: (50, 1),      # FocalLength 50mm
        0x829D: (28, 10),     # FNumber f/2.8
        0x8827: 400,          # ISO
        0x829A: (1, 125),     # ExposureTime 1/125
        0x9209: 1,            # Flash fired
    })
    result = _run_parse_sync(img)
    cam = result.camera
    assert cam.focal_length == "50.0mm"
    assert cam.fnumber == "f/2.8"
    assert cam.iso == 400
    assert cam.exposure_time == "1/125"
    assert cam.flash == "Flash fired"


def test_parse_sync_exposure_impossible_fraction():
    img = _mock_image(exif_data={0x829A: (5, 2)})
    result = _run_parse_sync(img)
    assert result.camera.exposure_time == "5/2"


def test_parse_sync_flash_unknown_code():
    img = _mock_image(exif_data={0x9209: 99})
    result = _run_parse_sync(img)
    assert result.camera.flash == "Code 99"


def test_parse_sync_metadata_and_gps():
    img = _mock_image(exif_data={
        0x010F: "Apple", 0x0110: "iPhone",
        0x9003: "2024:06:15 14:30:00",
        0x13B: "John Doe",
        0x8825: {
            1: "N", 2: (40, 25, 0), 3: "W", 4: (3, 42, 0),
        },
    })
    result = _run_parse_sync(img)
    assert result.gps is not None
    assert abs(result.gps.lat - 40.4167) < 0.01
    assert abs(result.gps.lon - (-3.7)) < 0.02
    assert result.metadata.datetime_original == "2024:06:15 14:30:00"
    assert result.severity == "high"


# ──────────────────────────────────────────────
# 9. analyze_url — validation
# ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_url_empty_raises():
    with pytest.raises(ValueError, match="empty"):
        await analyze_url("")


@pytest.mark.asyncio
async def test_analyze_url_bad_scheme_raises():
    with pytest.raises(ValueError, match="http"):
        await analyze_url("ftp://example.com/img.jpg")


@pytest.mark.asyncio
async def test_analyze_image_too_large_raises():
    with patch("exif_osint._MAX_FILE_SIZE", 100):
        with pytest.raises(ValueError, match="exceeds"):
            await analyze_image(b"x" * 200, "big.jpg")


# ──────────────────────────────────────────────
# 10. report_to_mirv_findings — detail branches
# ──────────────────────────────────────────────

def _make_result(**overrides) -> EXIFResult:
    base = EXIFResult(
        gps=None,
        camera=CameraInfo(make="Canon", model="EOS R5"),
        image=ImageInfo(width=100, height=100, format="JPEG", file_size=1234),
        metadata=MetadataInfo(),
        has_exif=True,
        raw_tags={},
        severity="medium",
        duration_seconds=0.1,
        filename="test.jpg",
    )
    for k, v in overrides.items():
        setattr(base, k, v)
    return base


def test_findings_gps_with_geocoding_and_timestamp():
    result = _make_result(
        gps=GPSInfo(lat=40.4168, lon=-3.7038, altitude=650.0, altitude_ref=0,
                    gps_timestamp="12:00:00", map_url="osm-url", google_maps_url="gmaps-url"),
        severity="high",
        geocoding={
            "house_number": "10", "road": "Calle Mayor",
            "city": "Madrid", "state": "Comunidad de Madrid", "country": "Spain",
        },
    )
    result._source_url = "http://example.com/img.jpg"
    findings = report_to_mirv_findings(result)
    gps_finding = next(f for f in findings if f["severity"] == "high")
    detail = gps_finding["detail"]
    assert "10 Calle Mayor" in detail
    assert "Madrid" in detail
    assert "Spain" in detail
    assert "GPS Timestamp: 12:00:00" in detail
    assert "Location:" in detail
    assert gps_finding["target"] == "http://example.com/img.jpg"


def test_findings_gps_geocoding_road_only():
    result = _make_result(
        gps=GPSInfo(lat=40.4, lon=-3.7),
        severity="high",
        geocoding={"road": "Avenida", "country": "Spain"},
    )
    findings = report_to_mirv_findings(result)
    detail = next(f for f in findings if f["severity"] == "high")["detail"]
    assert "Avenida" in detail


def test_findings_camera_full_details():
    result = _make_result(
        camera=CameraInfo(
            make="Canon", model="EOS R5", lens="RF 24-70mm",
            focal_length="24.0mm", fnumber="f/2.8", iso=100,
            exposure_time="1/125", flash="No flash", software="Lightroom",
        ),
    )
    findings = report_to_mirv_findings(result)
    med = next(f for f in findings if f["severity"] == "medium")
    assert "Lens: RF 24-70mm" in med["detail"]
    assert "Aperture: f/2.8" in med["detail"]
    assert "ISO: 100" in med["detail"]
    assert "Flash: No flash" in med["detail"]
    assert "Exposure: 1/125s" in med["detail"]


def test_findings_software_only_produces_low_finding():
    result = _make_result(
        camera=CameraInfo(software="Photoshop 2024"),
        severity="low",
    )
    findings = report_to_mirv_findings(result)
    low = [f for f in findings if f["severity"] == "low"]
    assert any("Software fingerprint" in f["title"] for f in low)


def test_findings_timestamp_low():
    result = _make_result(
        metadata=MetadataInfo(datetime_original="2024:06:15 14:30:00",
                              datetime_digitized="2024:06:15 14:30:00"),
        severity="low",
    )
    findings = report_to_mirv_findings(result)
    assert any("Timestamp extracted" in f["title"] for f in findings)


def test_findings_author_info_low():
    result = _make_result(
        metadata=MetadataInfo(artist="Jane", copyright="2024 Jane", description="A photo"),
        severity="low",
    )
    findings = report_to_mirv_findings(result)
    author = [f for f in findings if f["severity"] == "low" and f["title"].startswith("Author info")]
    assert len(author) == 1
    assert "Artist: Jane" in author[0]["detail"]
    assert "Copyright: 2024 Jane" in author[0]["detail"]
    assert "Description: A photo" in author[0]["detail"]


# ──────────────────────────────────────────────
# 9. Remaining defensive branches in _extract_gps / _parse_exif_sync
# ──────────────────────────────────────────────

def test_extract_gps_altitude_div_zero():
    """GPSAltitude (1, 0) → ZeroDivisionError → altitude stays None."""
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        4: 1,          # GPSAltitudeRef: below sea level
        5: (1, 0),     # GPSAltitude: zero denominator
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps.altitude is None
    assert gps.altitude_ref == 1


def test_extract_gps_timestamp_type_error():
    """GPSTimeStamp values that cannot be int()-converted → None."""
    raw = {
        0: "N", 1: (40, 1), 2: "W", 3: (3, 1),
        6: ("a", "b", "c"),
    }
    gps = _extract_gps(raw, _GPS_TAGS)
    assert gps.gps_timestamp is None


def test_parse_sync_getexif_and_thumbnail_errors():
    """getexif() and thumbnail .get() raising → defensive except branches."""
    img = MagicMock()
    img.format = "JPEG"
    img.width = 640
    img.height = 480
    img.info.get.side_effect = RuntimeError("thumbnail unavailable")
    img.getexif.side_effect = RuntimeError("exif unavailable")
    img._getexif.return_value = None
    result = _run_parse_sync(img)
    assert result.has_exif is False
    assert result.image.has_thumbnail is False


class _BadBytes(bytes):
    """bytes subclass whose decode() raises — exercises bytes-decode except."""

    def decode(self, *args, **kwargs):
        raise RuntimeError("undecodable")


def test_parse_sync_raw_tags_bad_bytes_decode():
    img = _mock_image(exif_data={0x010F: _BadBytes(b"\xff\xfe\x00")})
    result = _run_parse_sync(img)
    assert result.raw_tags.get("Make") == "<bytes:3>"


def test_parse_sync_fnumber_plain_float():
    img = _mock_image(exif_data={0x010F: "Canon", 0x829D: 2.8})
    result = _run_parse_sync(img)
    assert result.camera.fnumber == "f/2.8"


