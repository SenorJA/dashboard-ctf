"""
Tests for the hot-reload file-system watcher in ``plugin_manager.py``.

Covers:
  - ``start_watcher`` idempotency & thread safety
  - ``stop_watcher`` cleanup semantics
  - New plugin dir auto-discovery
  - Loaded plugin's main.py modification → auto-reload
  - 250 ms debounce collapses bursty changes into ONE reload
  - ``list_watch_events`` ring buffer (max 50, FIFO eviction)
  - ``auto_load_new`` False/True behaviour (security default)
  - Graceful handling when ``PLUGINS_DIR`` does not exist
  - Endpoint smoke tests for start/stop/events/status
  - Watch event schema (timestamp / plugin_name / action / detail)

The tests exercise the polling fallback (``watchdog`` not installed in CI),
which shares the same debounce + reload pipeline as the watchdog backend.
"""

import os
import sys
import json
import shutil
import time
import threading

import pytest

# Ensure `backend` package importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# IMPORTANT: import the SAME module object that the FastAPI app uses so that
# patching module state actually affects what the server sees.
import backend.plugin_manager as pm
from unittest.mock import patch


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

_PLUGIN_JSON_TEMPLATE = (
    '{{'
    '"name":"{name}",'
    '"version":"1.0.0",'
    '"author":"test",'
    '"description":"test plugin",'
    '"hooks":["on_startup","on_shutdown"],'
    '"dependencies":[],'
    '"config_schema":{{}}'
    '}}'
)
_MAIN_PY_TEMPLATE = (
    "call_counter = {counter}\n"
    "\n"
    "def on_startup():\n"
    "    return {{'plugin': '{name}', 'counter': call_counter}}\n"
    "\n"
    "def on_shutdown():\n"
    "    return {{'plugin': '{name}'}}\n"
)


def _make_plugin_dir(plugins_root, dir_name, counter=1):
    d = plugins_root / dir_name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.json").write_text(
        _PLUGIN_JSON_TEMPLATE.format(name=dir_name, ), encoding="utf-8"
    )
    (d / "main.py").write_text(
        _MAIN_PY_TEMPLATE.format(name=dir_name, counter=counter), encoding="utf-8"
    )
    return d


def _bump_main_py(plugin_dir, counter):
    """Write new content to force a stat change (mtime/size)."""
    name = plugin_dir.name
    (plugin_dir / "main.py").write_text(
        _MAIN_PY_TEMPLATE.format(name=name, counter=counter), encoding="utf-8"
    )


def _wait_for(predicate, timeout=8.0, interval=0.1):
    """Poll-time helper. Returns True if predicate becomes truthy in time."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def _find_event(action=None, plugin_name=None, since_index=0):
    for ev in pm.list_watch_events()[since_index:]:
        if action and ev.get("action") != action:
            continue
        if plugin_name and ev.get("plugin_name") != plugin_name:
            continue
        return ev
    return None


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_state():
    """Reset watcher + plugin state before AND after each test."""
    pm.reset()
    pm._clear_watch_events()
    # Fast polling for responsive tests.
    pm._POLL_INTERVAL = 0.15
    pm._DEBOUNCE_SECONDS = 0.25
    yield
    try:
        pm.stop_watcher()
    except Exception:
        pass
    pm.reset()
    pm._clear_watch_events()
    pm._POLL_INTERVAL = 2.0
    pm._DEBOUNCE_SECONDS = 0.25


@pytest.fixture
def watcher_with_tmp(tmp_path):
    """Create a temp plugins dir and patch the plugin_manager to use it."""
    tmp_plugins = tmp_path / "plugins"
    tmp_plugins.mkdir()
    # seed one plugin so discover has a baseline.
    _make_plugin_dir(tmp_plugins, "seed-plugin", counter=1)
    with patch.object(pm, '_PLUGINS_DIR', tmp_plugins):
        yield tmp_plugins


@pytest.fixture
def watcher_with_empty_tmp(tmp_path):
    """Temp plugins dir that starts empty (to test new-plugin-discovery)."""
    tmp_plugins = tmp_path / "plugins"
    tmp_plugins.mkdir()
    with patch.object(pm, '_PLUGINS_DIR', tmp_plugins):
        yield tmp_plugins


# ════════════════════════════════════════════════════════
#  start_watcher / stop_watcher semantics
# ════════════════════════════════════════════════════════

def test_start_watcher_is_idempotent(watcher_with_tmp):
    """Calling start_watcher() twice must NOT start a second thread/observer."""
    pm.start_watcher()
    first_object = pm._watcher_thread
    assert pm._watcher_started is True
    assert first_object is not None

    pm.start_watcher()
    # Same single thread — start_watcher is a no-op the second time.
    assert pm._watcher_thread is first_object

    alive = [t for t in threading.enumerate() if t.name == "plugin-watcher"]
    assert len(alive) == 1


def test_stop_watcher_clears_flag(watcher_with_tmp):
    """stop_watcher() must set _watcher_started=False and exit the thread."""
    pm.start_watcher()
    assert pm._watcher_started is True
    thread = pm._watcher_thread

    pm.stop_watcher()
    assert pm._watcher_started is False
    # Thread exits within 2s window.
    thread.join(timeout=3.0)
    assert thread.is_alive() is False
    assert pm._watcher_thread is None


def test_stop_watcher_thread_exits_cleanly(watcher_with_tmp):
    pm.start_watcher()
    thread = pm._watcher_thread
    pm.stop_watcher()
    thread.join(timeout=3.0)
    assert not thread.is_alive()


def test_start_watcher_on_nonexistent_dir_is_graceful(tmp_path):
    """Starting watcher with a missing PLUGINS_DIR must not raise."""
    bogus = tmp_path / "does_not_exist"
    with patch.object(pm, '_PLUGINS_DIR', bogus):
        # Should NOT raise — graceful warning + error event.
        pm.start_watcher()
        assert pm._watcher_started is False
        # No watcher thread should have been started.
        assert pm._watcher_thread is None
        # An error event must have been logged to the ring buffer.
        ev = _find_event(action="error", plugin_name="<root>")
        assert ev is not None
        assert "not found" in ev["detail"]


def test_concurrent_start_watcher_calls(watcher_with_tmp):
    """Multiple threads racing start_watcher() → exactly one watcher thread."""
    barrier = threading.Barrier(8)
    errors = []

    def _racer():
        try:
            barrier.wait(timeout=2.0)
            pm.start_watcher()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_racer, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert errors == []
    assert pm._watcher_started is True
    alive = [t for t in threading.enumerate() if t.name == "plugin-watcher"]
    assert len(alive) == 1


# ════════════════════════════════════════════════════════
#  Real discovery / reload via the poller
# ════════════════════════════════════════════════════════

def test_new_plugin_dir_triggers_discover_event(watcher_with_empty_tmp):
    """Creating a new plugin dir + plugin.json triggers an auto-discover event."""
    pm.start_watcher(auto_load_new=False)
    # Sanity: nothing in events yet about new plugin
    _make_plugin_dir(watcher_with_empty_tmp, "newcomer", counter=1)

    found = _wait_for(
        lambda: _find_event(action="discovered", plugin_name="newcomer")
                and pm.get_plugin_info("newcomer") is not None,
        timeout=6.0,
    )
    assert found, "poller did not discover new plugin dir within timeout"
    info = pm.get_plugin_info("newcomer")
    assert info is not None
    # auto_load_new=False → just registered, not loaded.
    assert info["status"] == "discovered"


def test_modify_loaded_plugin_triggers_auto_reload(watcher_with_tmp):
    """Modifying a loaded plugin's main.py triggers an auto-reload."""
    pm.start_watcher(auto_load_new=False)
    pm.discover_plugins()
    pdir = watcher_with_tmp / "seed-plugin"
    res = pm.load_plugin("seed-plugin")
    assert res["ok"], f"seed plugin must load cleanly, got: {res}"
    assert pm.get_plugin_info("seed-plugin")["status"] == "loaded"

    # bump main.py 3 times → debounced single reload
    for i in range(2, 5):
        _bump_main_py(pdir, counter=i)
        time.sleep(0.05)

    found = _wait_for(
        lambda: _find_event(action="reloaded", plugin_name="seed-plugin"),
        timeout=6.0,
    )
    assert found, "poller did not detect modify→reload for seed-plugin"
    assert pm.get_plugin_info("seed-plugin")["status"] == "loaded"


def test_debounce_collapses_bursty_changes(watcher_with_tmp):
    """Rapid successive changes within 250ms result in only ONE reload."""
    pm.start_watcher(auto_load_new=False)
    pm.discover_plugins()
    pm.load_plugin("seed-plugin")
    pdir = watcher_with_tmp / "seed-plugin"

    calls = {"count": 0}

    real_process_change = pm._process_change

    def _wrapped(name):
        calls["count"] += 1
        return real_process_change(name)

    with patch.object(pm, "_process_change", _wrapped):
        # 4 writes ~30ms apart all within 250ms window.
        for i in range(10, 14):
            _bump_main_py(pdir, counter=i)
            time.sleep(0.03)
        # wait long enough for the single debounce timer to fire.
        _wait_for(lambda: calls["count"] >= 1, timeout=4.0)
        time.sleep(1.0)  # extra window to be sure no second timer fires

    assert calls["count"] == 1, f"expected exactly ONE reload, got {calls['count']}"


def test_auto_load_new_false_discovered_not_loaded(watcher_with_empty_tmp):
    """auto_load_new=False → newly added plugin is discovered but NOT loaded."""
    pm.start_watcher(auto_load_new=False)
    _make_plugin_dir(watcher_with_empty_tmp, "ghost", counter=1)
    found = _wait_for(
        lambda: pm.get_plugin_info("ghost") is not None, timeout=6.0,
    )
    assert found
    info = pm.get_plugin_info("ghost")
    assert info["status"] == "discovered"
    # explicitly NOT loaded — no hooks from 'ghost' in on_startup
    results = pm.call_hook("on_startup")
    assert all(r.get("plugin") != "ghost" for r in results if isinstance(r, dict))


def test_auto_load_new_true_loads_new(watcher_with_empty_tmp):
    """auto_load_new=True → newly added plugin is discovered AND loaded."""
    pm.start_watcher(auto_load_new=True)
    _make_plugin_dir(watcher_with_empty_tmp, "autoload", counter=42)
    found = _wait_for(
        lambda: pm.get_plugin_info("autoload") is not None,
        timeout=6.0,
    )
    assert found
    found_loaded = _wait_for(
        lambda: (info := pm.get_plugin_info("autoload")) and info["status"] == "loaded",
        timeout=4.0,
    )
    assert found_loaded, "auto_load_new=True should have loaded 'autoload'"
    # the on_startup hook from autoload fires, returning counter=42
    results = pm.call_hook("on_startup")
    assert any(
        isinstance(r, dict) and r.get("plugin") == "autoload" and r.get("counter") == 42
        for r in results
    )


# ════════════════════════════════════════════════════════
#  Ring buffer semantics
# ════════════════════════════════════════════════════════

def test_list_watch_events_max_50():
    """_push_event must cap the ring buffer at _MAX_EVENTS (50)."""
    pm._clear_watch_events()
    for i in range(70):
        pm._push_event("discovered", f"plugin-{i}", f"detail-{i}")
    events = pm.list_watch_events()
    assert len(events) == pm._MAX_EVENTS == 50
    # the LAST 50 should be retained (FIFO eviction).
    assert events[0]["plugin_name"] == "plugin-20"
    assert events[-1]["plugin_name"] == "plugin-69"


def test_ring_buffer_evicts_oldest():
    """Oldest events are evicted once the buffer exceeds _MAX_EVENTS."""
    pm._clear_watch_events()
    pm._push_event("discovered", "oldest", "first")
    for i in range(pm._MAX_EVENTS + 4):
        pm._push_event("discovered", f"later-{i}", "x")
    events = pm.list_watch_events()
    assert len(events) == pm._MAX_EVENTS
    assert all(e["plugin_name"] != "oldest" for e in events)


def test_watch_event_has_required_fields():
    """Every event dict must have timestamp / plugin_name / action / detail."""
    pm._clear_watch_events()
    pm._push_event("reloaded", "demo-plugin", "test detail")
    ev = pm.list_watch_events()[0]
    for field in ("timestamp", "plugin_name", "action", "detail"):
        assert field in ev, f"missing field: {field}"
    assert ev["action"] == "reloaded"
    assert ev["plugin_name"] == "demo-plugin"
    assert ev["detail"] == "test detail"


def test_watcher_start_emits_baseline_event(watcher_with_tmp):
    """start_watcher itself records a 'watcher started' baseline event."""
    pm._clear_watch_events()
    pm.start_watcher(auto_load_new=False)
    found = _wait_for(
        lambda: any(
            e["plugin_name"] == "<root>" and "started" in e["detail"]
            for e in pm.list_watch_events()
        ),
        timeout=2.0,
    )
    assert found


# ════════════════════════════════════════════════════════
#  FastAPI endpoints
# ════════════════════════════════════════════════════════

def test_endpoint_start_stop_events_status(client):
    """POST start, POST stop, GET events, GET status all return 200 + structured JSON."""
    # POST /api/plugins/watcher/start
    body = {"auto_load_new": False}
    r = client.post("/api/plugins/watcher/start", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    assert "status" in data
    assert set(("watching", "plugin_count", "auto_load_new", "backend")) <= set(data["status"])
    assert data["status"]["watching"] is True
    assert data["status"]["auto_load_new"] is False

    # POST /api/plugins/watcher/stop
    r = client.post("/api/plugins/watcher/stop")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    assert data["status"]["watching"] is False

    # GET /api/plugins/watcher/events
    r = client.get("/api/plugins/watcher/events")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    assert isinstance(data["events"], list)
    # events should contain our 'watcher stopped' baseline at least
    assert any(
        e.get("action") in ("discovered", "error", "reloaded")
        for e in data["events"]
    )

    # GET /api/plugins/watcher/status
    r = client.get("/api/plugins/watcher/status")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True
    assert data["status"]["watching"] is False
    assert "plugin_count" in data["status"]
    assert data["status"]["auto_load_new"] is False


def test_endpoint_start_with_auto_load_new(client):
    """POST /api/plugins/watcher/start persists auto_load_new in the status."""
    r = client.post("/api/plugins/watcher/start", json={"auto_load_new": True})
    assert r.status_code == 200
    data = r.json()
    assert data["status"]["auto_load_new"] is True


def test_endpoint_events_returns_at_most_50(client):
    """GET events must never exceed the ring buffer cap (50)."""
    pm._clear_watch_events()
    # spam a bunch of events via internal API then read endpoint.
    for i in range(80):
        pm._push_event("discovered", "x", "y")
    r = client.get("/api/plugins/watcher/events")
    assert r.status_code == 200
    data = r.json()
    assert len(data["events"]) <= pm._MAX_EVENTS


def test_endpoint_events_schema(client):
    """Each event returned by the endpoint must carry required fields."""
    pm._clear_watch_events()
    pm._push_event("reloaded", "schema-test", "schema detail")
    r = client.get("/api/plugins/watcher/events")
    data = r.json()
    sample = next(e for e in data["events"] if e.get("plugin_name") == "schema-test")
    for field in ("timestamp", "plugin_name", "action", "detail"):
        assert field in sample