"""
exif_osint.py — MIRV Module

EXIF metadata extraction and OSINT intelligence gathering from images.

Extracts:
  - GPS coordinates with decimal conversion and map URLs
  - Camera make, model, lens, settings (ISO, aperture, etc.)
  - Image dimensions, format, color space, orientation
  - Date/time, artist, copyright, software fingerprints
  - Embedded thumbnail detection
  - Reverse geocoding via Nominatim (OpenStreetMap)
  - Severity classification based on intelligence value

Severity:
  - high: GPS coordinates found (geolocation intel)
  - medium: Camera make/model identified (device fingerprinting)
  - low: Software/artist/copyright metadata found (operator intel)
  - info: No EXIF data or minimal tags
"""

import io
import time
import struct
import logging
from dataclasses import dataclass, field
from typing import Literal, Any

# ── Logger ──
logger = logging.getLogger("vulnforge.exif")

# ── Constants ──
_MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
_NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"
_NOMINATIM_USER_AGENT = "MIRV-EXIF-OSINT/1.0 (security-audit-tool)"
_NOMINATIM_TIMEOUT = 10.0

# Pillow tag name resolution — imported lazily for safety
_PIL_TAGS = None
_PIL_GPS_TAGS = None


def _load_pil_tags():
    """Lazy-load PIL.ExifTags to avoid import errors if Pillow is missing."""
    global _PIL_TAGS, _PIL_GPS_TAGS
    if _PIL_TAGS is None:
        from PIL import ExifTags
        _PIL_TAGS = ExifTags.TAGS
        _PIL_GPS_TAGS = ExifTags.GPSTAGS
    return _PIL_TAGS, _PIL_GPS_TAGS


# ── Severity literal ──
Severity = Literal["high", "medium", "low", "info"]


# ════════════════════════════════════════════════════════════════
#  Data classes
# ════════════════════════════════════════════════════════════════

@dataclass
class GPSInfo:
    """Parsed GPS coordinates from EXIF."""
    lat: float
    lon: float
    altitude: float | None = None
    altitude_ref: int | None = None  # 0=above sea level, 1=below
    gps_timestamp: str | None = None
    map_url: str = ""
    google_maps_url: str = ""


@dataclass
class CameraInfo:
    """Camera/device identification from EXIF."""
    make: str | None = None
    model: str | None = None
    lens: str | None = None
    focal_length: str | None = None
    fnumber: str | None = None
    iso: int | None = None
    exposure_time: str | None = None
    flash: str | None = None
    software: str | None = None


@dataclass
class ImageInfo:
    """Basic image file information."""
    width: int = 0
    height: int = 0
    format: str = "unknown"
    color_space: str | None = None
    orientation: int | None = None
    file_size: int = 0
    has_thumbnail: bool = False


@dataclass
class MetadataInfo:
    """Date, author, and resolution metadata."""
    datetime_original: str | None = None
    datetime_digitized: str | None = None
    artist: str | None = None
    copyright: str | None = None
    description: str | None = None
    x_resolution: float | None = None
    y_resolution: float | None = None


@dataclass
class EXIFResult:
    """Complete EXIF analysis result."""
    gps: GPSInfo | None = None
    camera: CameraInfo | None = None
    image: ImageInfo = field(default_factory=ImageInfo)
    metadata: MetadataInfo | None = None
    thumbnail: dict | None = None
    has_exif: bool = False
    raw_tags: dict = field(default_factory=dict)
    severity: Severity = "info"
    geocoding: dict | None = None
    duration_seconds: float = 0.0
    filename: str = ""


# ════════════════════════════════════════════════════════════════
#  GPS helpers
# ════════════════════════════════════════════════════════════════

def _dms_to_decimal(dms_values: tuple, ref: str) -> float:
    """
    Convert GPS DMS (degrees, minutes, seconds) to decimal degrees.

    Args:
        dms_values: Tuple of (degrees, minutes, seconds) — each can be
                    an int, float, or tuple of (numerator, denominator)
                    (Rational from Pillow EXIF).
        ref: Hemisphere reference string — 'N', 'S', 'E', or 'W'.
    """
    def _to_float(v):
        """Convert Rational or tuple to float."""
        if isinstance(v, tuple) and len(v) == 2:
            return v[0] / v[1] if v[1] != 0 else 0.0
        return float(v)

    degrees = _to_float(dms_values[0])
    minutes = _to_float(dms_values[1])
    seconds = _to_float(dms_values[2]) if len(dms_values) > 2 else 0.0

    decimal = degrees + minutes / 60.0 + seconds / 3600.0

    # South and West are negative
    if ref in ("S", "W"):
        decimal = -decimal

    return round(decimal, 6)


def _build_map_urls(lat: float, lon: float) -> tuple[str, str]:
    """Build OpenStreetMap and Google Maps URLs from decimal coordinates."""
    osm_url = (
        f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15"
    )
    gmaps_url = (
        f"https://www.google.com/maps?q={lat},{lon}"
    )
    return osm_url, gmaps_url


def _extract_gps(raw_gps: dict, gps_tags: dict) -> GPSInfo | None:
    """
    Parse raw GPS IFD tags into a GPSInfo dataclass.

    Args:
        raw_gps: Dictionary of GPS IFD tag values (integer keys → values).
        gps_tags: PIL ExifTags.GPSTAGS mapping (tag_id → name).

    Returns:
        GPSInfo if valid coordinates found, None otherwise.
    """
    if not raw_gps:
        return None

    # Map tag IDs to human-readable names
    named = {}
    for tag_id, value in raw_gps.items():
        tag_name = gps_tags.get(tag_id, str(tag_id))
        named[tag_name] = value

    # Latitude requires GPSLatitude + GPSLatitudeRef
    if "GPSLatitude" not in named or "GPSLatitudeRef" not in named:
        return None
    if "GPSLongitude" not in named or "GPSLongitudeRef" not in named:
        return None

    try:
        lat = _dms_to_decimal(named["GPSLatitude"], named["GPSLatitudeRef"])
        lon = _dms_to_decimal(named["GPSLongitude"], named["GPSLongitudeRef"])
    except (TypeError, ValueError, IndexError, ZeroDivisionError) as e:
        logger.debug("GPS DMS conversion failed: %s", e)
        return None

    osm_url, gmaps_url = _build_map_urls(lat, lon)

    altitude = None
    altitude_ref = None
    if "GPSAltitude" in named:
        try:
            alt_val = named["GPSAltitude"]
            if isinstance(alt_val, tuple) and len(alt_val) == 2:
                altitude = round(alt_val[0] / alt_val[1], 1) if alt_val[1] != 0 else None
            else:
                altitude = round(float(alt_val), 1)
            altitude_ref = named.get("GPSAltitudeRef", 0)
            if altitude_ref == 1:
                altitude = -altitude  # Below sea level
        except (TypeError, ValueError, ZeroDivisionError):
            pass

    gps_ts = None
    if "GPSTimeStamp" in named:
        try:
            ts = named["GPSTimeStamp"]
            gps_ts = f"{int(ts[0]):02d}:{int(ts[1]):02d}:{int(ts[2]):02d}" if len(ts) >= 3 else str(ts)
        except (TypeError, IndexError, ValueError):
            pass

    return GPSInfo(
        lat=lat,
        lon=lon,
        altitude=altitude,
        altitude_ref=altitude_ref,
        gps_timestamp=gps_ts,
        map_url=osm_url,
        google_maps_url=gmaps_url,
    )


# ════════════════════════════════════════════════════════════════
#  EXIF parsing (CPU-bound — call via asyncio.to_thread)
# ════════════════════════════════════════════════════════════════

def _parse_exif_sync(file_bytes: bytes, filename: str) -> EXIFResult:
    """
    Synchronous EXIF extraction using Pillow.

    This function performs CPU-bound work and MUST be called
    via asyncio.to_thread() from async route handlers.
    """
    start = time.perf_counter()

    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS

    # Open the image
    try:
        img = Image.open(io.BytesIO(file_bytes))
    except Exception as e:
        logger.warning("Failed to open image '%s': %s", filename, e)
        return EXIFResult(
            has_exif=False,
            severity="info",
            filename=filename,
            duration_seconds=round(time.perf_counter() - start, 4),
        )

    # Basic image info (always available)
    img_format = (img.format or "unknown").upper()
    img_info = ImageInfo(
        width=img.width,
        height=img.height,
        format=img_format,
        file_size=len(file_bytes),
    )

    # Orientation
    try:
        img_info.orientation = img.getexif().get(0x0112, None) if hasattr(img, 'getexif') else None
    except Exception:
        pass

    # Thumbnail info
    has_thumb = False
    thumb_info = None
    try:
        thumb_data = img.info.get("thumbnail", None)
        if thumb_data and isinstance(thumb_data, (bytes, bytearray)):
            has_thumb = True
            thumb_info = {"has": True, "size_bytes": len(thumb_data)}
        elif thumb_data:
            has_thumb = True
            thumb_info = {"has": True, "size_bytes": 0}
    except Exception:
        pass
    img_info.has_thumbnail = has_thumb

    # Color space detection
    try:
        exif_data = img._getexif()
        if exif_data:
            color_space_tag = exif_data.get(0xA001)  # ColorSpace tag
            if color_space_tag == 1:
                img_info.color_space = "sRGB"
            elif color_space_tag == 2:
                img_info.color_space = "Adobe RGB"
            else:
                img_info.color_space = f"Tag({color_space_tag})" if color_space_tag else None
    except Exception:
        exif_data = None

    # No EXIF → early return
    if not exif_data:
        return EXIFResult(
            image=img_info,
            has_exif=False,
            severity="info",
            filename=filename,
            duration_seconds=round(time.perf_counter() - start, 4),
        )

    # ── Build raw_tags dict ──
    raw_tags: dict[str, Any] = {}
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, str(tag_id))
        # Convert non-serializable types
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                value = f"<bytes:{len(value)}>"
        elif isinstance(value, tuple):
            # Check for Rational tuples
            try:
                if len(value) == 2 and isinstance(value[0], int) and isinstance(value[1], int):
                    value = f"{value[0]}/{value[1]}" if value[1] != 0 else str(value[0])
                else:
                    value = [str(v) for v in value]
            except Exception:
                value = str(value)
        raw_tags[tag_name] = value

    # ── GPS extraction ──
    gps = None
    gps_data = exif_data.get(0x8825)  # GPSInfo tag
    if gps_data and isinstance(gps_data, dict):
        gps = _extract_gps(gps_data, GPSTAGS)

    # ── Camera info ──
    camera = CameraInfo(
        make=exif_data.get(0x010F),      # Make
        model=exif_data.get(0x0110),     # Model
        software=exif_data.get(0x0131),  # Software
    )

    # Lens info (multiple possible tags)
    lens = exif_data.get(0xA434) or exif_data.get(0x0150)  # LensModel or LensInfo
    if isinstance(lens, (list, tuple)):
        camera.lens = str(lens[0]) if lens else None
    else:
        camera.lens = str(lens) if lens else None

    # Focal length
    fl = exif_data.get(0x920A)  # FocalLength
    if fl:
        if isinstance(fl, tuple) and len(fl) == 2 and fl[1] != 0:
            camera.focal_length = f"{fl[0]/fl[1]:.1f}mm"
        else:
            camera.focal_length = f"{fl}mm"

    # F-number
    fnum = exif_data.get(0x829D)  # FNumber
    if fnum:
        if isinstance(fnum, tuple) and len(fnum) == 2 and fnum[1] != 0:
            camera.fnumber = f"f/{fnum[0]/fnum[1]:.1f}"
        else:
            camera.fnumber = f"f/{fnum}"

    # ISO
    iso_val = exif_data.get(0x8827)  # ISOSpeedRatings
    if iso_val:
        camera.iso = int(iso_val) if isinstance(iso_val, (int, float)) else None

    # Exposure time
    et = exif_data.get(0x829A)  # ExposureTime
    if et:
        if isinstance(et, tuple) and len(et) == 2:
            if et[1] >= et[0]:
                camera.exposure_time = f"1/{et[1]//et[0]}" if et[0] > 0 else str(et)
            else:
                camera.exposure_time = f"{et[0]}/{et[1]}"
        else:
            camera.exposure_time = str(et)

    # Flash
    flash_val = exif_data.get(0x9209)  # Flash
    if flash_val is not None:
        flash_map = {
            0: "No flash",
            1: "Flash fired",
            5: "Flash fired (no reflector)",
            7: "Flash fired (compulsory)",
            16: "No flash (compulsory)",
            24: "No flash (auto)",
            25: "Flash fired (auto)",
            27: "Flash fired (auto, no reflector)",
            29: "Flash fired (auto, compulsory)",
            31: "Flash fired (auto, compulsory, no reflector)",
        }
        camera.flash = flash_map.get(int(flash_val), f"Code {flash_val}")

    # ── Metadata ──
    metadata = MetadataInfo(
        datetime_original=_safe_str(exif_data.get(0x9003)),      # DateTimeOriginal
        datetime_digitized=_safe_str(exif_data.get(0x9004)),    # DateTimeDigitized
        artist=_safe_str(exif_data.get(0x13B)),                  # Artist
        copyright=_safe_str(exif_data.get(0x8298)),              # Copyright
        description=_safe_str(exif_data.get(0x010E)),            # ImageDescription
        x_resolution=_safe_float(exif_data.get(0x011A)),         # XResolution
        y_resolution=_safe_float(exif_data.get(0x011B)),         # YResolution
    )

    # ── Thumbnail embedded data ──
    if has_thumb and thumb_info is None:
        thumb_info = {"has": True, "size_bytes": 0}

    # ── Severity classification ──
    severity: Severity = "info"
    if gps is not None:
        severity = "high"
    elif camera.make or camera.model:
        severity = "medium"
    elif camera.software or metadata.artist or metadata.copyright:
        severity = "low"

    duration = round(time.perf_counter() - start, 4)

    return EXIFResult(
        gps=gps,
        camera=camera,
        image=img_info,
        metadata=metadata,
        thumbnail=thumb_info,
        has_exif=True,
        raw_tags=raw_tags,
        severity=severity,
        duration_seconds=duration,
        filename=filename,
    )


def _safe_str(val: Any) -> str | None:
    """Safely convert an EXIF value to string, return None if empty."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


def _safe_float(val: Any) -> float | None:
    """Safely convert EXIF Rational/number to float."""
    if val is None:
        return None
    try:
        if isinstance(val, tuple) and len(val) == 2 and val[1] != 0:
            return round(val[0] / val[1], 2)
        return round(float(val), 2)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


# ════════════════════════════════════════════════════════════════
#  Public async functions
# ════════════════════════════════════════════════════════════════

async def analyze_image(file_bytes: bytes, filename: str = "unknown") -> EXIFResult:
    """
    Analyze image bytes for EXIF metadata.

    Args:
        file_bytes: Raw image file bytes.
        filename: Original filename for reporting.

    Returns:
        EXIFResult with all extracted metadata.
    """
    if not file_bytes or len(file_bytes) < 50:
        raise ValueError("Image data too small (< 50 bytes) or empty")

    if len(file_bytes) > _MAX_FILE_SIZE:
        raise ValueError(f"File exceeds maximum size of {_MAX_FILE_SIZE // (1024*1024)}MB")

    # Run CPU-bound Pillow work in a thread pool
    result = await asyncio.to_thread(_parse_exif_sync, file_bytes, filename)
    return result


async def analyze_url(url: str) -> EXIFResult:
    """
    Download an image from a URL and analyze its EXIF metadata.

    Args:
        url: HTTP/HTTPS URL of the image.

    Returns:
        EXIFResult with source URL annotated.
    """
    import httpx

    if not url or not url.strip():
        raise ValueError("URL must not be empty")

    url = url.strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=30.0,
        headers={"User-Agent": _NOMINATIM_USER_AGENT},
    ) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except httpx.TimeoutException:
            raise ValueError(f"Timeout downloading image from URL (30s limit)")
        except httpx.HTTPStatusError as e:
            raise ValueError(f"HTTP {e.response.status_code} downloading image: {e.response.reason_phrase}")
        except httpx.RequestError as e:
            raise ValueError(f"Network error downloading image: {str(e)}")

        content = resp.content

    if len(content) > _MAX_FILE_SIZE:
        raise ValueError(f"Downloaded file exceeds {_MAX_FILE_SIZE // (1024*1024)}MB limit")

    # Extract filename from URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    filename = parsed.path.split("/")[-1] or "remote_image"

    result = await analyze_image(content, filename)
    result._source_url = url  # type: ignore[attr-defined]
    return result


# ════════════════════════════════════════════════════════════════
#  Reverse geocoding (Nominatim / OpenStreetMap)
# ════════════════════════════════════════════════════════════════

async def reverse_geocode(lat: float, lon: float) -> dict | None:
    """
    Perform reverse geocoding using Nominatim (OpenStreetMap).

    Args:
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.

    Returns:
        Dict with country, city, road, house_number, display_name,
        or None on failure.
    """
    import httpx

    params = {
        "lat": lat,
        "lon": lon,
        "format": "jsonv2",
        "addressdetails": 1,
        "zoom": 18,
    }
    headers = {
        "User-Agent": _NOMINATIM_USER_AGENT,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=_NOMINATIM_TIMEOUT) as client:
            resp = await client.get(_NOMINATIM_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.debug("Nominatim reverse geocode failed for (%s, %s): %s", lat, lon, e)
        return None

    address = data.get("address", {})
    return {
        "country": address.get("country"),
        "country_code": address.get("country_code"),
        "city": address.get("city") or address.get("town") or address.get("village"),
        "state": address.get("state"),
        "road": address.get("road"),
        "house_number": address.get("house_number"),
        "postcode": address.get("postcode"),
        "display_name": data.get("display_name"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }


# ════════════════════════════════════════════════════════════════
#  MIRV Findings conversion
# ════════════════════════════════════════════════════════════════

def report_to_mirv_findings(result: EXIFResult) -> list[dict]:
    """
    Convert an EXIFResult into MIRV findings list.

    Findings are sorted by severity (high → low → info).
    """
    findings: list[dict] = []
    target = getattr(result, '_source_url', None) or result.filename or "exif-analysis"

    # ── 1. Image info finding (always present) ──
    img = result.image
    findings.append({
        "tool": "exif-osint",
        "severity": "info",
        "title": f"Image analyzed: {img.width}x{img.height} {img.format} ({img.file_size:,} bytes)",
        "detail": (
            f"Format: {img.format}\n"
            f"Dimensions: {img.width}x{img.height}\n"
            f"File size: {img.file_size:,} bytes\n"
            f"Color space: {img.color_space or 'Unknown'}\n"
            f"Orientation: {img.orientation or 'Normal'}\n"
            f"Has EXIF: {'Yes' if result.has_exif else 'No'}\n"
            f"Thumbnail embedded: {'Yes' if img.has_thumbnail else 'No'}\n"
            f"Analysis time: {result.duration_seconds}s"
        ),
        "target": target,
        "type": "tech",
        "extra": {
            "width": img.width,
            "height": img.height,
            "format": img.format,
            "file_size": img.file_size,
            "color_space": img.color_space,
            "has_thumbnail": img.has_thumbnail,
        },
    })

    # ── 2. GPS / geolocation finding (HIGH) ──
    if result.gps is not None:
        gps = result.gps
        geo = result.geocoding
        location_text = ""
        if geo:
            parts = []
            if geo.get("house_number") and geo.get("road"):
                parts.append(f"{geo['house_number']} {geo['road']}")
            elif geo.get("road"):
                parts.append(geo["road"])
            if geo.get("city"):
                parts.append(geo["city"])
            if geo.get("state"):
                parts.append(geo["state"])
            if geo.get("country"):
                parts.append(geo["country"])
            location_text = ", ".join(parts)

        detail_lines = [
            f"Latitude: {gps.lat}",
            f"Longitude: {gps.lon}",
        ]
        if gps.altitude is not None:
            detail_lines.append(f"Altitude: {gps.altitude}m ({'below' if gps.altitude_ref == 1 else 'above'} sea level)")
        if gps.gps_timestamp:
            detail_lines.append(f"GPS Timestamp: {gps.gps_timestamp}")
        if location_text:
            detail_lines.append(f"Location: {location_text}")
        detail_lines.extend([
            f"",
            f"OpenStreetMap: {gps.map_url}",
            f"Google Maps: {gps.google_maps_url}",
        ])

        findings.append({
            "tool": "exif-osint",
            "severity": "high",
            "title": f"GPS coordinates embedded: {gps.lat}, {gps.lon}",
            "detail": "\n".join(detail_lines),
            "target": target,
            "type": "vuln",
            "extra": {
                "lat": gps.lat,
                "lon": gps.lon,
                "altitude": gps.altitude,
                "map_url": gps.map_url,
                "google_maps_url": gps.google_maps_url,
                "geocoding": geo,
            },
        })

    # ── 3. Camera / device fingerprinting (MEDIUM) ──
    if result.camera is not None:
        cam = result.camera
        parts = []
        if cam.make:
            parts.append(f"Make: {cam.make}")
        if cam.model:
            parts.append(f"Model: {cam.model}")
        if cam.lens:
            parts.append(f"Lens: {cam.lens}")
        if cam.focal_length:
            parts.append(f"Focal length: {cam.focal_length}")
        if cam.fnumber:
            parts.append(f"Aperture: {cam.fnumber}")
        if cam.iso:
            parts.append(f"ISO: {cam.iso}")
        if cam.exposure_time:
            parts.append(f"Exposure: {cam.exposure_time}s")
        if cam.flash:
            parts.append(f"Flash: {cam.flash}")
        if cam.software:
            parts.append(f"Software: {cam.software}")

        # Only create finding if we have meaningful device info
        device_parts = [cam.make, cam.model]
        if any(device_parts):
            findings.append({
                "tool": "exif-osint",
                "severity": "medium",
                "title": f"Device identified: {cam.make or '?'} {cam.model or '?'}".strip(),
                "detail": "\n".join(parts),
                "target": target,
                "type": "vuln",
                "extra": {
                    "make": cam.make,
                    "model": cam.model,
                    "lens": cam.lens,
                    "focal_length": cam.focal_length,
                    "fnumber": cam.fnumber,
                    "iso": cam.iso,
                    "exposure_time": cam.exposure_time,
                    "flash": cam.flash,
                },
            })

        # Software fingerprint — separate LOW finding
        if cam.software and not any(device_parts):
            # Only if there's no make/model (otherwise it's part of the medium finding above)
            findings.append({
                "tool": "exif-osint",
                "severity": "low",
                "title": f"Software fingerprint: {cam.software}",
                "detail": (
                    f"Software detected in EXIF: {cam.software}\n\n"
                    f"This can reveal the image editing tool, firmware version, "
                    f"or post-processing pipeline used on the image."
                ),
                "target": target,
                "type": "tech",
                "extra": {"software": cam.software},
            })

    # ── 4. Metadata findings (LOW) ──
    if result.metadata is not None:
        meta = result.metadata

        # DateTime finding
        if meta.datetime_original:
            findings.append({
                "tool": "exif-osint",
                "severity": "low",
                "title": f"Timestamp extracted: {meta.datetime_original}",
                "detail": (
                    f"Date/Time Original: {meta.datetime_original}\n"
                    f"Date/Time Digitized: {meta.datetime_digitized or 'N/A'}"
                ),
                "target": target,
                "type": "tech",
                "extra": {
                    "datetime_original": meta.datetime_original,
                    "datetime_digitized": meta.datetime_digitized,
                },
            })

        # Artist / Copyright finding
        if meta.artist or meta.copyright:
            parts = []
            if meta.artist:
                parts.append(f"Artist: {meta.artist}")
            if meta.copyright:
                parts.append(f"Copyright: {meta.copyright}")
            if meta.description:
                parts.append(f"Description: {meta.description}")

            findings.append({
                "tool": "exif-osint",
                "severity": "low",
                "title": f"Author info: {meta.artist or meta.copyright or 'found'}",
                "detail": "\n".join(parts),
                "target": target,
                "type": "tech",
                "extra": {
                    "artist": meta.artist,
                    "copyright": meta.copyright,
                    "description": meta.description,
                },
            })

    # Sort by severity
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 99))

    return findings


# ════════════════════════════════════════════════════════════════
#  Module-level import of asyncio (used by async functions)
# ════════════════════════════════════════════════════════════════
import asyncio
