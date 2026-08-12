"""
Coverage-gap tests for backend/plugin_manager.py — watchdog backend.

``watchdog`` is an optional dependency that is NOT installed in the test
environment, so the whole ``if HAS_WATCHDOG:`` block (handler class + Observer
startup) is unreachable. These tests fake the two watchdog modules in
``sys.modules`` and reload ``backend.plugin_manager`` so that the import
succeeds and ``HAS_WATCHDOG`` flips to True, then exercise the observer
backend. A clean reload (no fakes) restores the original polling state.

Covers:
  - module import success when watchdog modules exist (37-38)
  - _PluginFSHandler event handlers: on_modified/created/deleted/moved
  - _maybe_schedule: empty path, Path failure, pycache/pyc skip,
    outside-base relative_to failure, base itself, normal scheduling
  - start_watcher() watchdog branch: Observer.schedule/start called,
    _watcher_observer assigned, watcher marked started
"""

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import backend.plugin_manager as pm


class FakeObserver:
    """Minimal watchdog.observers.Observer stand-in."""

    def __init__(self):
        self.scheduled = []
        self.started = False

    def schedule(self, handler, path, recursive=False):
        self.scheduled.append((handler, path, recursive))

    def start(self):
        self.started = True


class FakeFileSystemEventHandler:
    """Minimal watchdog.events.FileSystemEventHandler stand-in."""


class _FakeEvent:
    def __init__(self, src_path=None, is_directory=False, dest_path=None):
        self.src_path = src_path
        self.is_directory = is_directory
        self.dest_path = dest_path


@pytest.fixture()
def watchdog_enabled():
    """Inject fake watchdog modules and reload plugin_manager.

    After the test the module is reloaded cleanly so the original globals
    are restored. Whether ``HAS_WATCHDOG`` returns to True or False depends
    on whether the real ``watchdog`` package is importable in this
    environment (it is in CI Linux where requirements.txt installs it,
    it is not on some dev machines) -- so we capture the ORIGINAL value
    before injecting fakes and assert the teardown restores it exactly.
    """
    watchdog_pkg = types.ModuleType("watchdog")
    observers_mod = types.ModuleType("watchdog.observers")
    observers_mod.Observer = FakeObserver
    events_mod = types.ModuleType("watchdog.events")
    events_mod.FileSystemEventHandler = FakeFileSystemEventHandler

    # Capture the pre-existing watchdog modules (real ones if installed,
    # None if not). Used to restore on teardown.
    original = {name: sys.modules.get(name) for name in
                ("watchdog", "watchdog.observers", "watchdog.events")}
    # Capture the pre-existing HAS_WATCHDOG flag. Whether True or False
    # depends on the environment (watchdog installed or not), and the
    # teardown must restore whichever value was there originally.
    original_has_watchdog = pm.HAS_WATCHDOG

    sys.modules["watchdog"] = watchdog_pkg
    sys.modules["watchdog.observers"] = observers_mod
    sys.modules["watchdog.events"] = events_mod

    importlib.reload(pm)
    # With fakes injected, HAS_WATCHDOG must now be True regardless of
    # whether the real watchdog was previously installed or not.
    assert pm.HAS_WATCHDOG is True
    try:
        yield
    finally:
        # Restore original modules (or remove the fakes) and reload cleanly.
        for name, mod in original.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        importlib.reload(pm)
        # The teardown must restore HAS_WATCHDOG to whatever it was BEFORE
        # we injected fakes. Do NOT hard-assert False: on CI Linux,
        # requirements.txt installs the real ``watchdog`` package, so the
        # original value is True; on minimal dev setups without watchdog,
        # the original is False. Asserting the pre-existing value keeps
        # the suite green in both environments.
        assert pm.HAS_WATCHDOG is original_has_watchdog


def _make_handler(tmp_path):
    base = Path(tmp_path)
    return pm._PluginFSHandler(base)


class TestModuleImportWithWatchdog:
    def test_watchdog_imports_resolve(self, watchdog_enabled):
        assert pm.Observer is FakeObserver
        assert pm.FileSystemEventHandler is FakeFileSystemEventHandler


class TestFSHandlerEvents:
    def test_init_resolve_failure_falls_back(self, watchdog_enabled):
        class _BadResolve:
            def resolve(self):
                raise OSError("boom")

        bad = _BadResolve()
        h = pm._PluginFSHandler(bad)
        assert h._base is bad

    def test_on_modified_directory_ignored(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h.on_modified(_FakeEvent(src_path=str(tmp_path / "p"), is_directory=True))
        mock_sched.assert_not_called()

    def test_on_modified_file_schedules(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        (tmp_path / "demo").mkdir(exist_ok=True)
        (tmp_path / "demo" / "plugin.json").write_text("{}", encoding="utf-8")
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h.on_modified(_FakeEvent(src_path=str(tmp_path / "demo" / "plugin.json")))
        mock_sched.assert_called_once_with("demo")

    def test_on_created_schedules(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h.on_created(_FakeEvent(src_path=str(tmp_path / "demo2")))
        mock_sched.assert_called_once_with("demo2")

    def test_on_deleted_schedules(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h.on_deleted(_FakeEvent(src_path=str(tmp_path / "demo3")))
        mock_sched.assert_called_once_with("demo3")

    def test_on_moved_uses_dest_path(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h.on_moved(_FakeEvent(dest_path=str(tmp_path / "demo4")))
        mock_sched.assert_called_once_with("demo4")

    def test_on_moved_without_dest(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h.on_moved(_FakeEvent())  # no dest_path attribute fallback -> None
        mock_sched.assert_not_called()


class TestMaybeSchedule:
    def test_empty_path_returns(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h._maybe_schedule("")
            h._maybe_schedule(None)
        mock_sched.assert_not_called()

    def test_path_constructor_exception(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)

        class _ExplodingStr:
            def __str__(self):
                raise RuntimeError("boom")

        with patch.object(pm, "_schedule_reload") as mock_sched:
            h._maybe_schedule(_ExplodingStr())
        mock_sched.assert_not_called()

    def test_parts_exception_returns(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)

        class _BadParts:
            @property
            def parts(self):
                raise RuntimeError("boom")

        with patch("backend.plugin_manager.Path", lambda src: _BadParts()), \
             patch.object(pm, "_schedule_reload") as mock_sched:
            h._maybe_schedule("anything")
        mock_sched.assert_not_called()

    def test_pycache_skipped(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        (tmp_path / "demo" / "__pycache__").mkdir(parents=True, exist_ok=True)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h._maybe_schedule(str(tmp_path / "demo" / "__pycache__" / "x.pyc"))
        mock_sched.assert_not_called()

    def test_pyc_skipped(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            h._maybe_schedule(str(tmp_path / "demo" / "mod.pyc"))
        mock_sched.assert_not_called()

    def test_outside_base_skipped(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            # tmp_path itself is inside the base -> relative_to(base) fails
            h._maybe_schedule(str(tmp_path.parent / "outside.txt"))
        mock_sched.assert_not_called()

    def test_base_itself_skipped(self, watchdog_enabled, tmp_path):
        h = _make_handler(tmp_path)
        with patch.object(pm, "_schedule_reload") as mock_sched:
            # resolving to the base dir yields an empty relative path.
            h._maybe_schedule(str(tmp_path))
        mock_sched.assert_not_called()


class TestStartWatcherWatchdogBranch:
    def test_observer_started_and_scheduled(self, watchdog_enabled, tmp_path):
        with patch.object(pm, "_PLUGINS_DIR", Path(tmp_path)):
            pm.start_watcher()
        try:
            assert pm._watcher_started is True
            assert isinstance(pm._watcher_observer, FakeObserver)
            obs = pm._watcher_observer
            assert obs.started is True
            assert len(obs.scheduled) == 1
            handler, path, recursive = obs.scheduled[0]
            assert isinstance(handler, pm._PluginFSHandler)
            assert path == str(Path(tmp_path))
            assert recursive is True
        finally:
            pm.stop_watcher()
