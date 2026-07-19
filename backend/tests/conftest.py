"""
Shared fixtures for MIRV API tests.
"""
import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import app


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def sample_png():
    """A minimal 1x1 red PNG for stego tests."""
    import base64
    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
        "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    )


@pytest.fixture
def sample_bmp():
    """A minimal 2x2 black BMP for stego tests."""
    import struct
    # BMP file header (14 bytes) + DIB header (40 bytes) + pixel data
    file_size = 14 + 40 + 4 * 4  # 4 bytes per pixel * 4 pixels
    data = bytearray(file_size)
    # File header
    data[0:2] = b'BM'
    struct.pack_into('<I', data, 2, file_size)
    struct.pack_into('<I', data, 10, 14 + 40)  # pixel offset
    # DIB header
    struct.pack_into('<I', data, 14, 40)  # header size
    struct.pack_into('<i', data, 18, 2)   # width
    struct.pack_into('<i', data, 22, 2)   # height
    struct.pack_into('<H', data, 26, 1)   # planes
    struct.pack_into('<H', data, 28, 32)  # bpp
    # Pixel data (black BGRA)
    for i in range(4):
        offset = 14 + 40 + i * 4
        data[offset:offset+4] = b'\x00\x00\x00\xff'
    return bytes(data)
