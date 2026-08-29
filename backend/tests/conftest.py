"""
Shared fixtures for MIRV API tests.
"""
import importlib
import types
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
    "rate_limiter", "osint_recon", "instagram_osint",
    "episodic_memory", "orchestrator",
]
for _name in _BACKEND_MODULES_TO_ALIAS:
    try:
        sys.modules.setdefault(_name,
                               importlib.import_module(f"backend.{_name}"))
    except (ImportError, ModuleNotFoundError):
        # If a module is renamed/removed later, ignore silently so the
        # whole test collection doesn't break on import.
        pass


# ───────────────────────────────────────────────────────────────────
#  Neutralize real `watchdog` for the whole suite (force polling fallback)
# ───────────────────────────────────────────────────────────────────
#
# ``backend/plugin_manager.py`` does ``try: from watchdog.observers
# import Observer``. When the real ``watchdog`` is installed (which it
# IS on CI Linux because `requirements.txt` includes it), ``HAS_WATCHDOG``
# ends up True and ``start_watcher()`` uses the Observer-based backend
# (assigning ``_watcher_observer``) instead of the polling thread
# (assigning ``_watcher_thread``). The catch: dozens of tests in
# ``test_plugin_watcher.py`` (and one in ``test_plugin_manager_gaps.py``)
# were written assuming the POLLING path -- they assert on
# ``pm._watcher_thread``/``pm._watcher_started``/threading semantics
# that simply do not exist on the Observer branch. The mismatch
# produced the ~11 failures unmasked after the watchdog_gaps fix.
#
# Fix: replace the three watchdog modules in sys.modules with EMPTY
# stubs whose `Observer`/`FileSystemEventHandler` attributes are
# missing (or None), then reload ``backend.plugin_manager`` so it
# re-evaluates the try/except import and falls through to
# ``HAS_WATCHDOG = False``. Tests in
# ``test_plugin_manager_watchdog_gaps.py`` are unaffected because
# they inject their OWN fakes inside their `watchdog_enabled`
# fixture and reload the module themselves; their teardown now sees
# ``original_has_watchdog == False`` (which this neutralization set),
# so the ordering invariant ("restore to original") still holds.
#
# The stubs must NOT raise on attribute access (importlib.reload would
# surface unrelated AttributeErrors); they just need to lack the two
# symbols so `from watchdog.observers import Observer` raises
# ImportError cleanly, which the plugin_manager try/except catches.
def _neutralize_watchdog() -> None:
    pkg = types.ModuleType("watchdog")
    obs = types.ModuleType("watchdog.observers")
    # `hasattr(obs, "Observer")` is False → `from … import Observer`
    # raises ImportError, caught by plugin_manager's try/except.
    events = types.ModuleType("watchdog.events")
    sys.modules["watchdog"] = pkg
    sys.modules["watchdog.observers"] = obs
    sys.modules["watchdog.events"] = events
    try:
        pm = importlib.import_module("backend.plugin_manager")
        importlib.reload(pm)
    except Exception:
        # Defensive: never blow up test collection.
        pass


_neutralize_watchdog()


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_osint_rate_limiter():
    """Wipe the per-IP OSINT rate limiter before every test.

    The limiter is a process-wide singleton; without a reset, tests that
    hit ``/api/osint/*`` would accumulate hits across the whole session
    and start seeing 429s unrelated to the case under test.
    """
    try:
        from backend.rate_limiter import reset_rate_limiter
        reset_rate_limiter()
    except Exception:
        pass
    yield
    try:
        from backend.rate_limiter import reset_rate_limiter
        reset_rate_limiter()
    except Exception:
        pass


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
