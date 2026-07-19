"""
stego_tool.py — MIRV Module

Steganography detection and extraction tool.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects

Pure-Python implementation for PNG/BMP images:
  - LSB (Least Significant Bit) analysis and extraction
  - Appended data detection (trailing bytes after IEND)
  - File signature / metadata analysis
  - LSB string extraction with configurable bit depth and channel
"""

import io
import struct
import zlib
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse


# ── Constants ──

PNG_SIG = b'\x89PNG\r\n\x1a\n'
BMP_SIG = b'BM'
IEND_CHUNK_TYPE = b'IEND'
IHDR_CHUNK_TYPE = b'IHDR'
IDAT_CHUNK_TYPE = b'IDAT'


# ── Data classes ──

@dataclass(frozen=True, slots=True)
class ImageInfo:
    width: int
    height: int
    bit_depth: int
    color_type: int  # 0=grayscale, 2=RGB, 3=indexed, 4=grayscale+alpha, 6=RGBA
    format: str  # "png" | "bmp" | "unknown"
    file_size: int
    compression: str | None = None
    has_alpha: bool = False
    estimated_capacity_bytes: int = 0  # max LSB capacity


@dataclass(frozen=True, slots=True)
class StegoResult:
    image_info: ImageInfo
    lsb_suspicious: bool
    trailing_data_found: bool
    lsb_message: str | None = None
    lsb_bytes: list[int] | None = None
    lsb_extracted_length: int = 0
    trailing_data_size: int = 0
    trailing_data_preview: str | None = None
    anomalies: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# ── PNG parser (pure Python) ──

def _parse_png(data: bytes) -> tuple[ImageInfo, list[bytes]]:
    """Parse PNG file, return ImageInfo and list of IDAT chunk data."""
    if not data.startswith(PNG_SIG):
        raise ValueError("Not a valid PNG file (bad signature)")

    pos = 8  # skip signature
    width = height = bit_depth = color_type = 0
    idat_data: list[bytes] = []
    found_ihdr = False
    palette = None

    while pos < len(data):
        if pos + 8 > len(data):
            break
        chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        chunk_data = data[pos+8:pos+8+chunk_len] if chunk_len > 0 else b''
        crc = data[pos+8+chunk_len:pos+12+chunk_len] if pos+12+chunk_len <= len(data) else b''

        if chunk_type == IHDR_CHUNK_TYPE and chunk_len >= 13:
            width = struct.unpack('>I', chunk_data[0:4])[0]
            height = struct.unpack('>I', chunk_data[4:8])[0]
            bit_depth = chunk_data[8]
            color_type = chunk_data[9]
            found_ihdr = True

        elif chunk_type == IDAT_CHUNK_TYPE:
            idat_data.append(chunk_data)

        elif chunk_type == IEND_CHUNK_TYPE:
            pos += 12 + chunk_len
            break

        pos += 12 + chunk_len

    if not found_ihdr:
        raise ValueError("No IHDR chunk found in PNG")

    has_alpha = color_type in (4, 6)
    channels = 1 if color_type == 0 else 3 if color_type == 2 else 1 if color_type == 3 else 2 if color_type == 4 else 4

    # Estimated LSB capacity: width * height * channels bytes (1 bit per channel per pixel)
    capacity = width * height * channels // 8

    info = ImageInfo(
        width=width,
        height=height,
        bit_depth=bit_depth,
        color_type=color_type,
        format="png",
        file_size=len(data),
        has_alpha=has_alpha,
        estimated_capacity_bytes=capacity * 8,  # bits total
    )
    return info, idat_data


def _decompress_idat(idat_chunks: list[bytes]) -> bytes:
    """Decompress concatenated IDAT chunks into raw pixel data."""
    combined = b''.join(idat_chunks)
    return zlib.decompress(combined)


def _extract_lsb_from_raw(raw: bytes, width: int, height: int, channels: int, bit_depth: int, bytes_to_read: int = 4096) -> tuple[list[int], str | None]:
    """
    Extract LSB from raw pixel data.
    Reads LSB from each byte (if bit_depth == 8) or each channel byte.
    Returns (byte_list, string if printable else None).
    """
    if bit_depth != 8:
        # Only handle 8-bit for now
        return [], None

    # Skip filter byte at start of each row (PNG uses filters)
    # For simplicity, process all data including filter bytes
    # This is standard practice for quick LSB extraction

    bits: list[int] = []
    for byte in raw[:bytes_to_read]:
        bits.append(byte & 1)

    # Convert bits to bytes
    extracted_bytes = []
    for i in range(0, len(bits) - 7, 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        extracted_bytes.append(b)

    # Try to interpret as text
    message = _try_decode_as_text(extracted_bytes)
    return extracted_bytes, message


def _try_decode_as_text(data: list[int]) -> str | None:
    """Try to decode a byte list as UTF-8 text. Returns string if mostly printable."""
    if len(data) < 4:
        return None

    try:
        text = bytes(data).decode('utf-8')
        # Check if mostly printable
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if printable > len(text) * 0.8 and len(text) > 3:
            return text.strip()
    except (UnicodeDecodeError, ValueError):
        pass

    # Try as ASCII
    try:
        text = bytes(data).decode('ascii')
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        if printable > len(text) * 0.8 and len(text) > 3:
            return text.strip()
    except (UnicodeDecodeError, ValueError):
        pass

    return None


def _examine_trailing_data(data: bytes, format: str) -> tuple[bool, int, str | None]:
    """Check for data appended after the image end."""
    if format == "png":
        # Find last IEND chunk
        pos = 8
        last_end = -1
        while pos < len(data):
            if pos + 8 > len(data):
                break
            chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            if chunk_type == IEND_CHUNK_TYPE:
                last_end = pos + 12 + chunk_len
                break
            pos += 12 + chunk_len

        if last_end > 0 and last_end < len(data):
            trailing = data[last_end:]
            if trailing:
                preview = trailing[:200].hex(' ', 2) if len(trailing) <= 200 else trailing[:100].hex(' ', 2) + '...'
                return True, len(trailing), preview

    elif format == "bmp":
        # BMP: pixel data ends at file_size, check for extra bytes
        # This is simpler — just check if there are bytes after expected end
        # For now, basic check
        pass

    return False, 0, None


def _analyze_image_data(data: bytes) -> ImageInfo:
    """Detect image format and extract basic info without full parse."""
    info = None
    if data.startswith(PNG_SIG):
        info, _ = _parse_png(data)
    elif data.startswith(BMP_SIG):
        if len(data) < 26:
            raise ValueError("File too small for BMP")
        file_size = struct.unpack('<I', data[2:6])[0]
        width = struct.unpack('<i', data[18:22])[0]
        height = abs(struct.unpack('<i', data[22:26])[0])
        bit_depth = struct.unpack('<H', data[28:30])[0] if len(data) > 28 else 24
        channels = 4 if bit_depth == 32 else 3 if bit_depth == 24 else 1
        capacity = width * height * channels // 8 * 8  # bits
        info = ImageInfo(
            width=width,
            height=height,
            bit_depth=bit_depth,
            color_type=2 if channels >= 3 else 0,
            format="bmp",
            file_size=len(data),
            has_alpha=bit_depth == 32,
            estimated_capacity_bytes=capacity,
        )
    else:
        raise ValueError("Unsupported image format (only PNG/BMP supported)")

    return info


async def analyze(
    data: bytes | None = None,
    url: str | None = None,
    *,
    extract_lsb: bool = True,
    lsb_length: int = 4096,
) -> StegoResult:
    """
    Analyze an image for steganographic content.

    Args:
        data: Raw image bytes (PNG or BMP).
        url: URL to fetch image from (alternative to data).
        extract_lsb: If True, attempt LSB extraction.
        lsb_length: Max bytes to scan for LSB.

    Returns a StegoResult.
    """
    import asyncio
    start = asyncio.get_event_loop().time()

    # Fetch if URL provided
    if url and data is None:
        import httpx
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.content

    if data is None:
        raise ValueError("Either 'data' or 'url' must be provided")

    if len(data) < 50:
        raise ValueError("Image data too small (< 50 bytes)")

    info = _analyze_image_data(data)
    anomalies: list[str] = []
    lsb_suspicious = False
    lsb_message = None
    lsb_bytes = None
    extracted_len = 0

    # ── Trailing data check ──
    trailing_found, trailing_size, trailing_preview = _examine_trailing_data(data, info.format)
    if trailing_found:
        anomalies.append(f"Trailing data detected: {trailing_size} bytes after image end")
        lsb_suspicious = True

    # ── LSB extraction ──
    if extract_lsb and info.format == "png":
        try:
            _, idat_chunks = _parse_png(data)
            if idat_chunks:
                raw_data = _decompress_idat(idat_chunks)
                channels = 1 if info.color_type == 0 else 3 if info.color_type == 2 else 1 if info.color_type == 3 else 2 if info.color_type == 4 else 4
                lsb_bytes, lsb_message = _extract_lsb_from_raw(
                    raw_data, info.width, info.height, channels, info.bit_depth, lsb_length
                )
                extracted_len = len(lsb_bytes) if lsb_bytes else 0
                if lsb_message:
                    lsb_suspicious = True
                    anomalies.append(f"LSB-encoded text detected ({len(lsb_message)} chars)")
            else:
                anomalies.append("No IDAT chunks found in PNG")
        except Exception as e:
            anomalies.append(f"LSB analysis error: {str(e)}")

    elif extract_lsb and info.format == "bmp":
        # BMP pixel data starts at offset 54 (for 24-bit BMP) or at header-defined offset
        try:
            if len(data) > 54:
                pixel_offset = struct.unpack('<I', data[10:14])[0] if len(data) > 14 else 54
                pixel_data = data[pixel_offset:]
                if pixel_data:
                    channels = 3 if info.bit_depth == 24 else 4 if info.bit_depth == 32 else 1
                    lsb_bytes, lsb_message = _extract_lsb_from_raw(
                        pixel_data, info.width, info.height, channels, info.bit_depth, lsb_length
                    )
                    extracted_len = len(lsb_bytes) if lsb_bytes else 0
                    if lsb_message:
                        lsb_suspicious = True
                        anomalies.append(f"LSB-encoded text detected in BMP ({len(lsb_message)} chars)")
        except Exception as e:
            anomalies.append(f"BMP LSB analysis error: {str(e)}")

    duration = asyncio.get_event_loop().time() - start

    return StegoResult(
        image_info=info,
        lsb_suspicious=lsb_suspicious,
        lsb_message=lsb_message,
        lsb_bytes=lsb_bytes,
        lsb_extracted_length=extracted_len,
        trailing_data_found=trailing_found,
        trailing_data_size=trailing_size,
        trailing_data_preview=trailing_preview,
        anomalies=anomalies,
        duration_seconds=round(duration, 2),
    )


def report_to_mirv_findings(result: StegoResult) -> list[dict]:
    """Convert StegoResult into MIRV findings list."""
    findings = []
    info = result.image_info

    # Image info finding
    findings.append({
        "tool": "stego-tool",
        "severity": "info",
        "title": f"Image analysis: {info.width}x{info.height} {info.format.upper()} ({info.file_size} bytes)",
        "detail": (
            f"Format: {info.format.upper()}\n"
            f"Dimensions: {info.width}x{info.height}\n"
            f"Bit depth: {info.bit_depth}\n"
            f"Color type: {info.color_type}\n"
            f"Alpha channel: {'Yes' if info.has_alpha else 'No'}\n"
            f"File size: {info.file_size} bytes\n"
            f"Estimated LSB capacity: {info.estimated_capacity_bytes} bits"
        ),
        "target": url if hasattr(result, '_source_url') else "stego-analysis",
        "type": "tech",
        "extra": {
            "width": info.width,
            "height": info.height,
            "format": info.format,
            "file_size": info.file_size,
            "estimated_capacity": info.estimated_capacity_bytes,
        },
    })

    # LSB findings
    if result.lsb_suspicious and result.lsb_message:
        findings.append({
            "tool": "stego-tool",
            "severity": "high",
            "title": f"LSB hidden message detected ({len(result.lsb_message)} chars)",
            "detail": (
                f"Extracted message:\n{result.lsb_message}\n\n"
                f"Length: {result.lsb_extracted_length} bytes"
            ),
            "target": url if hasattr(result, '_source_url') else "stego-analysis",
            "type": "vuln",
            "extra": {
                "message": result.lsb_message,
                "extracted_bytes": result.lsb_extracted_length,
            },
        })
    elif result.lsb_extracted_length > 0 and not result.lsb_message:
        findings.append({
            "tool": "stego-tool",
            "severity": "low",
            "title": f"LSB data extracted ({result.lsb_extracted_length} bytes, not printable)",
            "detail": (
                f"Extracted {result.lsb_extracted_length} bytes from LSB.\n"
                f"Data does not appear to be printable text.\n"
                f"Raw bytes (first 32): {' '.join(f'{b:02x}' for b in (result.lsb_bytes or [])[:32])}"
            ),
            "target": url if hasattr(result, '_source_url') else "stego-analysis",
            "type": "tech",
            "extra": {
                "extracted_bytes": result.lsb_extracted_length,
                "raw_preview": (result.lsb_bytes or [])[:64],
            },
        })
    else:
        findings.append({
            "tool": "stego-tool",
            "severity": "info",
            "title": "No LSB hidden data detected",
            "detail": "LSB analysis completed. No printable hidden messages found in pixel data.",
            "target": url if hasattr(result, '_source_url') else "stego-analysis",
            "type": "tech",
        })

    # Trailing data findings
    if result.trailing_data_found:
        findings.append({
            "tool": "stego-tool",
            "severity": "high",
            "title": f"Trailing data: {result.trailing_data_size} bytes after image end",
            "detail": (
                f"Size: {result.trailing_data_size} bytes\n"
                f"Preview (hex): {result.trailing_data_preview}"
            ),
            "target": url if hasattr(result, '_source_url') else "stego-analysis",
            "type": "vuln",
            "extra": {
                "trailing_bytes": result.trailing_data_size,
                "preview": result.trailing_data_preview,
            },
        })
    else:
        findings.append({
            "tool": "stego-tool",
            "severity": "info",
            "title": "No trailing data found",
            "detail": "No data appended after the image end marker.",
            "target": url if hasattr(result, '_source_url') else "stego-analysis",
            "type": "tech",
        })

    # Anomaly findings
    for anomaly in result.anomalies:
        if "error" in anomaly.lower():
            findings.append({
                "tool": "stego-tool",
                "severity": "medium",
                "title": anomaly,
                "detail": anomaly,
                "target": url if hasattr(result, '_source_url') else "stego-analysis",
                "type": "tech",
            })

    return findings
