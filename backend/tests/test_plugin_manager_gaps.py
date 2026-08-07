"""
Coverage-gap tests for backend/plugin_manager.py — internal branches.

Covers (all with `watchdog` NOT installed → polling fallback path):
  - discover_plugins(): missing dir, invalid manifest JSON
  - load_plugin(): missing manifest/entrypoint, invalid manifest,
    missing required field, spec None, import error
  - _register_hook(): duplicate registration skip
  - unload_plugin(): on_shutdown exception swallowed
  - reload_plugin(): unload error propagation
  - call_hook(): disabled plugin skip
  - reset(): stop_watcher / on_shutdown exceptions swallowed
  - _plugin_dir_name_to_registry_name(): no match / TypeError
  - _schedule_reload(): debounce cancels previous timer
  - _process_change(): discover failure, manifest-not-found,
    reload failure, auto-load failure, generic exception
  - _DirPoller(): plugins_dir override, missing dir, iterdir OSError,
    stat OSError, diff detects deleted key, run() diff exception
  - start_watcher(): thread start failure rollback
  - stop_watcher(): observer/thread/timer error branches
"""

import os
import sys
import json
from pathlib import Path

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# IMPORTANT: import the SAME module object that the FastAPI app uses.
import backend.plugin_manager as pm


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

_VALID_MANIFEST = (
    '{"name":"demo","version":"1.0.0","author":"t","description":"d",'
    '"hooks":[],"dependencies":[],"config_schema":{}}'
)
_MAIN_PY = 'def on_startup():\n    return {}\n'


def _make_plugin_dir(root, name, manifest=_VALID_MANIFEST, main=_MAIN_PY):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.json").write_text(manifest, encoding="utf-8")
    (d / "main.py").write_text(main, encoding="utf-8")
    return d


def _register(name, manifest=None, module_dir="/tmp", status="discovered", enabled=True):
    info = pm.PluginInfo(
        name=name,
        manifest=manifest,
        module_dir=module_dir,
        status=status,
        enabled=enabled,
    )
    with pm._lock:
        pm._registry[name] = info
    return info


@pytest.fixture(autouse=True)
def clean_state():
    """Reset plugin + watcher state before AND after each test."""
    pm.reset()
    pm._clear_watch_events()
    # Keep debounce long so timers do not fire during unit tests.
    pm._DEBOUNCE_SECONDS = 60
    yield
    try:
        pm.stop_watcher()
    except Exception:
        pass
    pm.reset()
    pm._clear_watch_events()
    pm._DEBOUNCE_SECONDS = 0.25


# ════════════════════════════════════════════════════
#  discover_plugins()
# ════════════════════════════════════════════════════

class TestDiscoverGaps:
    def test_missing_dir_returns_empty(self, tmp_path, monkeypatch):
        bogus = tmp_path / "does_not_exist"
        monkeypatch.setattr(pm, "_PLUGINS_DIR", bogus)
        assert pm.discover_plugins() == []

    def test_invalid_manifest_skipped(self, tmp_path, monkeypatch):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        bad = plugins_dir / "bad"
        bad.mkdir()
        (bad / "plugin.json").write_text("{invalid json", encoding="utf-8")
        monkeypatch.setattr(pm, "_PLUGINS_DIR", plugins_dir)
        assert pm.discover_plugins() == []


# ════════════════════════════════════════════════════
#  load_plugin() validation branches
# ════════════════════════════════════════════════════

class TestLoadPluginValidation:
    def test_missing_manifest(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        d = _make_plugin_dir(plugins_dir, "demo")
        (d / "plugin.json").unlink()
        with patch.object(pm, "_PLUGINS_DIR", plugins_dir):
            _register("demo", module_dir=str(d))
            res = pm.load_plugin("demo")
        assert res["ok"] is False
        assert "plugin.json" in res["error"]

    def test_missing_entrypoint(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        d = _make_plugin_dir(plugins_dir, "demo")
        (d / "main.py").unlink()
        with patch.object(pm, "_PLUGINS_DIR", plugins_dir):
            _register("demo", module_dir=str(d))
            res = pm.load_plugin("demo")
        assert res["ok"] is False
        assert "main.py" in res["error"]

    def test_invalid_manifest_json(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _make_plugin_dir(plugins_dir, "demo", manifest="{nope")
        with patch.object(pm, "_PLUGINS_DIR", plugins_dir):
            _register("demo", module_dir=str(plugins_dir / "demo"))
            res = pm.load_plugin("demo")
        assert res["ok"] is False
        assert "Invalid manifest" in res["error"]

    def test_missing_required_field(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _make_plugin_dir(plugins_dir, "demo", manifest='{"name":"demo"}')
        with patch.object(pm, "_PLUGINS_DIR", plugins_dir):
            _register("demo", module_dir=str(plugins_dir / "demo"))
            res = pm.load_plugin("demo")
        assert res["ok"] is False
        assert "required field" in res["error"]

    def test_spec_none(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _make_plugin_dir(plugins_dir, "demo")
        with patch.object(pm, "_PLUGINS_DIR", plugins_dir), \
             patch.object(pm.importlib.util, "spec_from_file_location", return_value=None):
            _register("demo", module_dir=str(plugins_dir / "demo"))
            res = pm.load_plugin("demo")
        assert res["ok"] is False
        assert "spec" in res["error"]

    def test_import_error_sets_status_error(self, tmp_path):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        _make_plugin_dir(plugins_dir, "demo")
        spec = MagicMock()
        spec.loader.exec_module.side_effect = RuntimeError("import boom")
        with patch.object(pm, "_PLUGINS_DIR", plugins_dir), \
             patch.object(pm.importlib.util, "spec_from_file_location", return_value=spec):
            _register("demo", module_dir=str(plugins_dir / "demo"))
            res = pm.load_plugin("demo")
        assert res["ok"] is False
        assert "Import error" in res["error"]
        assert pm.get_plugin_info("demo")["status"] == "error"


# ════════════════════════════════════════════════════
#  _register_hook / unload_plugin / reload_plugin / call_hook
# ════════════════════════════════════════════════════

class TestHookLifecycleGaps:
    def test_register_hook_duplicate_skipped(self):
        fn = lambda: None  # noqa: E731
        pm._register_hook("demo", "on_startup", fn)
        pm._register_hook("demo", "on_startup", fn)
        with pm._lock:
            assert len(pm._hooks["on_startup"]) == 1

    def test_unload_swallows_on_shutdown_exception(self, tmp_path):
        d = _make_plugin_dir(tmp_path, "demo")
        _register("demo", module_dir=str(d), status="loaded")
        with patch.object(pm, "call_hook", side_effect=RuntimeError("shutdown boom")):
            res = pm.unload_plugin("demo")
        assert res["ok"] is True

    def test_reload_propagates_unload_error(self):
        with patch.object(
            pm, "unload_plugin",
            return_value={"ok": False, "plugin": "x", "error": "some error"},
        ):
            res = pm.reload_plugin("x")
        assert res["ok"] is False

    def test_call_hook_skips_disabled_plugin(self):
        fn = MagicMock(return_value="value")
        pm._register_hook("demo", "on_startup", fn)
        _register("demo", module_dir="/tmp", enabled=False)
        results = pm.call_hook("on_startup")
        fn.assert_not_called()
        assert results == []

    def test_reset_swallows_stop_watcher_exception(self):
        with patch.object(pm, "stop_watcher", side_effect=RuntimeError("stop boom")):
            pm.reset()

    def test_reset_swallows_on_shutdown_exception(self):
        _register("demo", module_dir="/tmp", status="loaded")
        with patch.object(pm, "call_hook", side_effect=RuntimeError("shutdown boom")):
            pm.reset()


# ════════════════════════════════════════════════════
#  _plugin_dir_name_to_registry_name
# ════════════════════════════════════════════════════

class TestDirNameToRegistryName:
    def test_match_returns_name(self):
        _register("demo", module_dir=str(Path("x") / "demo"))
        assert pm._plugin_dir_name_to_registry_name("demo") == "demo"

    def test_no_match_returns_none(self):
        # module_dir=123 → Path() raises TypeError inside try → except continue
        _register("weird", module_dir=123)
        assert pm._plugin_dir_name_to_registry_name("nope") is None


# ════════════════════════════════════════════════════
#  _schedule_reload / _process_change
# ════════════════════════════════════════════════════

class TestProcessChangeGaps:
    def test_schedule_reload_cancels_previous(self):
        pm._schedule_reload("demo")
        with pm._debounce_lock:
            first = pm._debounce_timers.get("demo")
        assert first is not None
        pm._schedule_reload("demo")
        with pm._debounce_lock:
            second = pm._debounce_timers.get("demo")
        assert second is not None
        assert second is not first

    def test_discover_failure_then_manifest_not_found(self):
        # discover raises (726-727) AND registry has no match (732-733)
        with patch.object(pm, "discover_plugins", side_effect=RuntimeError("discover boom")):
            pm._process_change("ghost")
        evs = pm.list_watch_events()
        assert any(e["action"] == "discovered" and e["plugin_name"] == "ghost" for e in evs)

    def test_reload_failure_pushes_error(self, tmp_path):
        d = _make_plugin_dir(tmp_path, "demo")
        _register("demo", module_dir=str(d), status="loaded")
        with patch.object(pm, "load_plugin", return_value={"ok": False, "error": "boom"}):
            pm._process_change("demo")
        evs = pm.list_watch_events()
        assert any(e["action"] == "error" and e["plugin_name"] == "demo" for e in evs)

    def test_auto_load_failure_pushes_error(self, tmp_path):
        d = _make_plugin_dir(tmp_path, "demo")
        _register("demo", module_dir=str(d), status="discovered")
        pm._auto_load_new = True
        try:
            with patch.object(pm, "load_plugin", return_value={"ok": False, "error": "boom"}):
                pm._process_change("demo")
        finally:
            pm._auto_load_new = False
        evs = pm.list_watch_events()
        assert any(e["action"] == "error" and e["plugin_name"] == "demo" for e in evs)

    def test_generic_exception_pushes_error(self):
        with patch.object(pm, "discover_plugins"), \
             patch.object(pm, "_plugin_dir_name_to_registry_name",
                          side_effect=RuntimeError("generic boom")):
            pm._process_change("demo")
        evs = pm.list_watch_events()
        assert any(e["action"] == "error" and e["plugin_name"] == "demo" for e in evs)


# ════════════════════════════════════════════════════
#  _DirPoller
# ════════════════════════════════════════════════════

class TestDirPollerGaps:
    def test_plugins_dir_override(self, tmp_path):
        poller = pm._DirPoller(plugins_dir=tmp_path)
        assert poller._plugins_dir() == Path(tmp_path)

    def test_scan_missing_dir_returns_empty(self, tmp_path):
        poller = pm._DirPoller(plugins_dir=tmp_path / "nope")
        assert poller._scan() == {}

    def test_scan_iterdir_oserror_returns_empty(self):
        class _FakeDir:
            def is_dir(self):
                return True

            def iterdir(self):
                raise OSError("permission denied")

        poller = pm._DirPoller(plugins_dir="/x")
        with patch.object(poller, "_plugins_dir", return_value=_FakeDir()):
            assert poller._scan() == {}

    def test_scan_stat_oserror_skipped(self):
        class _FakeFile:
            def is_file(self):
                return True

            def stat(self):
                raise OSError("stat failed")

        class _FakeEntry:
            name = "demo"

            def is_dir(self):
                return True

            def __truediv__(self, fname):
                return _FakeFile()

        class _FakeDir:
            def is_dir(self):
                return True

            def iterdir(self):
                return iter([_FakeEntry()])

        poller = pm._DirPoller(plugins_dir="/x")
        with patch.object(poller, "_plugins_dir", return_value=_FakeDir()):
            assert poller._scan() == {}

    def test_diff_detects_deleted_key(self):
        poller = pm._DirPoller(plugins_dir="/x")
        poller._state = {"demo/plugin.json": (1.0, 2)}
        with patch.object(poller, "_scan", return_value={}), \
             patch.object(pm, "_schedule_reload") as mock_sched:
            poller._diff()
        mock_sched.assert_called_once_with("demo")

    def test_run_swallows_diff_exception(self):
        poller = pm._DirPoller(plugins_dir="/x")
        poller._stop_evt.wait = MagicMock(side_effect=[False, True])
        with patch.object(poller, "_snapshot"), \
             patch.object(poller, "_diff", side_effect=[RuntimeError("diff boom"), None]):
            poller.run()  # must not raise


# ════════════════════════════════════════════════════
#  start_watcher / stop_watcher error branches
# ════════════════════════════════════════════════════

class TestWatcherErrorBranches:
    def test_start_watcher_thread_start_fails(self, tmp_path, monkeypatch):
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        monkeypatch.setattr(pm, "_PLUGINS_DIR", plugins_dir)
        with patch.object(pm, "_DirPoller") as mock_poller:
            mock_poller.return_value.start.side_effect = RuntimeError("start boom")
            pm.start_watcher()
        assert pm._watcher_started is False
        assert pm._watcher_thread is None
        evs = pm.list_watch_events()
        assert any(e["action"] == "error" and e["plugin_name"] == "<root>" for e in evs)

    def test_stop_watcher_observer_stop_error(self):
        class _FakeObs:
            def stop(self):
                raise RuntimeError("stop boom")

            def join(self, timeout):
                pass

        pm._watcher_started = True
        pm._watcher_observer = _FakeObs()
        pm.stop_watcher()
        assert pm._watcher_started is False
        assert pm._watcher_observer is None

    def test_stop_watcher_observer_join_error(self):
        class _FakeObs:
            def stop(self):
                pass

            def join(self, timeout):
                raise RuntimeError("join boom")

        pm._watcher_started = True
        pm._watcher_observer = _FakeObs()
        pm.stop_watcher()
        assert pm._watcher_started is False
        assert pm._watcher_observer is None

    def test_stop_watcher_thread_stop_and_join_errors(self):
        class _FakeThread:
            def stop(self):
                raise RuntimeError("stop boom")

            def join(self, timeout):
                raise RuntimeError("join boom")

        pm._watcher_started = True
        pm._watcher_thread = _FakeThread()
        pm.stop_watcher()
        assert pm._watcher_started is False
        assert pm._watcher_thread is None

    def test_stop_watcher_timer_cancel_error(self):
        class _FakeTimer:
            def cancel(self):
                raise RuntimeError("cancel boom")

        with pm._debounce_lock:
            pm._debounce_timers["demo"] = _FakeTimer()
        pm._watcher_started = True
        pm.stop_watcher()
        with pm._debounce_lock:
            assert "demo" not in pm._debounce_timers
