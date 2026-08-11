"""
Shared fixtures for MIRV API tests.
"""
import importlib
import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import app  # noqa: E402  -- imports backend.* package tree first

# ───────────────────────────────────────────────────────────────────
#  Module-identity aliasing -- prevent "split-module" monkeypatch bugs
# ───────────────────────────────────────────────────────────────────
#
# The application imports ``backend.X`` (e.g. ``from backend.audit_log
# import audit``). When a test file historically did ``from X import``
# (without the ``backend.`` prefix), Python loaded the same .py file
# under *two* distinct module names -- top-level ``X`` and package
# ``backend.X`` -- with separate global state and *incompatible*
# ``isinstance`` checks. That split broke fixtures
# (handler-cleanup-by-isinstance silently matched nothing) and monkey
# patches (``@patch("X.attr")`` patched the wrong module while the
# production code path used ``backend.X.attr``). This was the root cause
# of the CI #47/#48 audit-log recursion (see TOMORROW.md § Postmortem).
#
# Solution (defence-in-depth): tests now import with the ``backend.``
# prefix (style rule) AND this aliasing in conftest guarantees that any
# legacy ``@patch("X.attr")`` string-based patches still resolve to the
# *same* module object that production code uses, by aliasing
# ``sys.modules["X"]`` to ``backend.X``.
_BACKEND_MODULES_TO_ALIAS = [
    "audit_log", "siem", "database", "redact", "opsec",
    "coverage_matrix", "mission_store", "browser_capture", "burp_bridge",
    "finding_poc", "scope_guard", "knowledgebase", "exif_osint",
    "canary_tokens", "dlp_scanner", "mobile_analyzer", "adb_controller",
    "forensics", "swarm", "intelligence", "mcp_server", "pdf_engine",
    "kali_mcp_client", "news_scraper", "api_scanner", "headers_scanner",
    "secrets_scanner", "port_scanner", "subdomain_scanner", "dns_lookup",
    "hash_cracker", "stego_tool", "plugin_manager", "skill_playbooks",
]
for _name in _BACKEND_MODULES_TO_ALIAS:
    try:
        sys.modules.setdefault(_name,
                               importlib.import_module(f"backend.{_name}"))
    except (ImportError, ModuleNotFoundError):
        # If a module is renamed/removed later, ignore silently so the
        # whole test collection doesn't break on import.
        pass


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
