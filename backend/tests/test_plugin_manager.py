"""
Tests for plugin_manager — MIRV Plugin System.

Covers:
  - Plugin discovery from filesystem
  - Loading, unloading, reloading plugins
  - Hook registration and invocation with timeout
  - Enable/disable affecting hook execution
  - Error handling (missing plugin, bad manifest, import errors)
  - Thread safety under concurrent access
  - Config default extraction
"""

import os
import sys
import json
import time
import types
import threading
import importlib

import pytest

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import plugin_manager as pm


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_plugin_state():
    """Reset plugin state before every test."""
    pm.reset()
    yield
    pm.reset()


@pytest.fixture
def example_plugin_name():
    return "example-plugin"


# ──────────────────────────────────────────────
# 1. discover_plugins
# ──────────────────────────────────────────────

class TestDiscoverPlugins:
    def test_discovers_example_plugin(self):
        discovered = pm.discover_plugins()
        assert "example-plugin" in discovered

    def test_discovery_populates_registry(self):
        pm.discover_plugins()
        info = pm.get_plugin_info("example-plugin")
        assert info is not None
        assert info["name"] == "example-plugin"

    def test_discovery_returns_list_of_strings(self):
        discovered = pm.discover_plugins()
        assert isinstance(discovered, list)
        for name in discovered:
            assert isinstance(name, str)

    def test_discovery_idempotent(self):
        """Calling discover twice doesn't duplicate entries."""
        d1 = pm.discover_plugins()
        d2 = pm.discover_plugins()
        assert d1 == d2
        # Registry should still have exactly one entry
        plugins = pm.list_plugins()
        names = [p["name"] for p in plugins]
        assert names.count("example-plugin") == 1


# ──────────────────────────────────────────────
# 2. load_plugin
# ──────────────────────────────────────────────

class TestLoadPlugin:
    def test_load_example_plugin(self, example_plugin_name):
        result = pm.load_plugin(example_plugin_name)
        assert result["ok"] is True
        assert result["error"] is None
        assert result["plugin"] is not None

    def test_load_sets_status_loaded(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert info["status"] == "loaded"

    def test_load_sets_loaded_at(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert info["loaded_at"] is not None

    def test_load_nonexistent_plugin(self):
        result = pm.load_plugin("no-such-plugin-xyz")
        assert result["ok"] is False
        assert result["error"] is not None

    def test_load_registers_hooks(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert "on_startup" in info["hooks"]
        assert "on_shutdown" in info["hooks"]
        assert "on_tool_result" in info["hooks"]
        assert "on_finding" in info["hooks"]
        assert "on_event" in info["hooks"]

    def test_load_manifest_metadata(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert info["version"] == "1.0.0"
        assert info["author"] == "MIRV"
        assert "Example" in info["description"]


# ──────────────────────────────────────────────
# 3. get_plugin_info
# ──────────────────────────────────────────────

class TestGetPluginInfo:
    def test_info_for_loaded_plugin(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert info is not None
        assert info["name"] == example_plugin_name

    def test_info_returns_none_for_unknown(self):
        assert pm.get_plugin_info("ghost-plugin") is None

    def test_info_dict_has_required_keys(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        expected_keys = {"name", "version", "author", "description",
                         "status", "enabled", "loaded_at", "error",
                         "config", "hooks", "module_dir"}
        assert expected_keys.issubset(set(info.keys()))


# ──────────────────────────────────────────────
# 4. list_plugins
# ──────────────────────────────────────────────

class TestListPlugins:
    def test_list_includes_discovered(self):
        pm.discover_plugins()
        plugins = pm.list_plugins()
        names = [p["name"] for p in plugins]
        assert "example-plugin" in names

    def test_list_includes_loaded(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        plugins = pm.list_plugins()
        loaded = [p for p in plugins if p["name"] == example_plugin_name]
        assert len(loaded) == 1
        assert loaded[0]["status"] == "loaded"

    def test_list_returns_list_of_dicts(self):
        plugins = pm.list_plugins()
        assert isinstance(plugins, list)
        for p in plugins:
            assert isinstance(p, dict)


# ──────────────────────────────────────────────
# 5. call_hook — on_startup
# ──────────────────────────────────────────────

class TestCallHookStartup:
    def test_on_startup_executes(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        results = pm.call_hook("on_startup")
        assert isinstance(results, list)
        assert len(results) >= 1
        # The example plugin returns a dict
        assert any(isinstance(r, dict) and r.get("plugin") == "example-plugin" for r in results)

    def test_call_hook_unknown_hook_returns_empty(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        results = pm.call_hook("on_nonexistent_hook_xyz")
        assert results == []


# ──────────────────────────────────────────────
# 6. call_hook — on_finding (modifies finding)
# ──────────────────────────────────────────────

class TestCallHookFinding:
    def test_on_finding_enriches_finding(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        finding = {"title": "XSS in /search", "severity": "high"}
        results = pm.call_hook("on_finding", finding)
        assert len(results) >= 1
        # The plugin mutates the finding dict directly
        assert finding.get("plugin") == "example-plugin"

    def test_on_finding_passes_through(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        finding = {"title": "Test finding"}
        results = pm.call_hook("on_finding", finding)
        # Result should be the same dict (plugin returns it)
        assert results[0] is finding


# ──────────────────────────────────────────────
# 7. call_hook — on_tool_result
# ──────────────────────────────────────────────

class TestCallHookToolResult:
    def test_on_tool_result_executes(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        results = pm.call_hook("on_tool_result", "nmap", "10.0.0.1", "PORT STATE\n22/tcp open")
        assert len(results) >= 1
        assert results[0]["tool"] == "nmap"


# ──────────────────────────────────────────────
# 8. call_hook — on_event
# ──────────────────────────────────────────────

class TestCallHookEvent:
    def test_on_event_executes(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        results = pm.call_hook("on_event", {"type": "connection", "ip": "10.0.0.1"})
        assert len(results) >= 1


# ──────────────────────────────────────────────
# 9. unload_plugin
# ──────────────────────────────────────────────

class TestUnloadPlugin:
    def test_unload_removes_hooks(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.unload_plugin(example_plugin_name)
        # Hooks should no longer fire
        results = pm.call_hook("on_startup")
        assert results == []

    def test_unload_sets_status(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.unload_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert info["status"] == "unloaded"

    def test_unload_nonexistent_returns_error(self):
        result = pm.unload_plugin("ghost-plugin")
        assert result["ok"] is False

    def test_unload_cleans_sys_modules(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        module_fqn = f"backend.plugins.{example_plugin_name}.main"
        assert module_fqn in sys.modules
        pm.unload_plugin(example_plugin_name)
        assert module_fqn not in sys.modules


# ──────────────────────────────────────────────
# 10. reload_plugin
# ──────────────────────────────────────────────

class TestReloadPlugin:
    def test_reload_returns_ok(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        result = pm.reload_plugin(example_plugin_name)
        assert result["ok"] is True

    def test_reload_restores_hooks(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.reload_plugin(example_plugin_name)
        results = pm.call_hook("on_startup")
        assert len(results) >= 1

    def test_reload_updates_loaded_at(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        info_before = pm.get_plugin_info(example_plugin_name)
        time.sleep(0.05)
        pm.reload_plugin(example_plugin_name)
        info_after = pm.get_plugin_info(example_plugin_name)
        assert info_after["loaded_at"] >= info_before["loaded_at"]


# ──────────────────────────────────────────────
# 11. enable / disable
# ──────────────────────────────────────────────

class TestEnableDisable:
    def test_disable_stops_hooks(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.disable_plugin(example_plugin_name)
        results = pm.call_hook("on_startup")
        assert results == []

    def test_enable_resumes_hooks(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.disable_plugin(example_plugin_name)
        pm.enable_plugin(example_plugin_name)
        results = pm.call_hook("on_startup")
        assert len(results) >= 1

    def test_disable_nonexistent_returns_error(self):
        result = pm.disable_plugin("ghost-plugin")
        assert result["ok"] is False

    def test_enable_nonexistent_returns_error(self):
        result = pm.enable_plugin("ghost-plugin")
        assert result["ok"] is False

    def test_disable_plugin_info_status(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.disable_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        # enabled flag should be False (status stays "loaded")
        assert info["enabled"] is False

    def test_enable_plugin_info_status(self, example_plugin_name):
        pm.load_plugin(example_plugin_name)
        pm.disable_plugin(example_plugin_name)
        pm.enable_plugin(example_plugin_name)
        info = pm.get_plugin_info(example_plugin_name)
        assert info["enabled"] is True


# ──────────────────────────────────────────────
# 12. Error handling
# ──────────────────────────────────────────────

class TestErrorHandling:
    def test_load_missing_plugin_dir(self):
        """Plugin name with no directory."""
        result = pm.load_plugin("nonexistent-dir-plugin")
        assert result["ok"] is False
        assert "not found" in result["error"].lower() or "not found" in result["error"]

    def test_list_after_discover_only(self):
        """list_plugins returns entries even without loading."""
        pm.discover_plugins()
        plugins = pm.list_plugins()
        ep = [p for p in plugins if p["name"] == "example-plugin"]
        assert len(ep) == 1
        assert ep[0]["status"] in ("discovered", "loaded")

    def test_hook_exception_doesnt_crash_others(self):
        """One bad hook shouldn't prevent other hooks from running."""
        # Register a good hook
        def good_hook():
            return "good_result"

        pm._hooks.setdefault("test_crash_hook", [])
        pm._hooks["test_crash_hook"].append({
            "plugin_name": "bad_plugin",
            "fn": lambda: (_ for _ in ()).throw(ValueError("boom")),
            "enabled": True,
        })
        pm._hooks["test_crash_hook"].append({
            "plugin_name": "good_plugin",
            "fn": good_hook,
            "enabled": True,
        })

        results = pm.call_hook("test_crash_hook")
        # The good hook should still have run
        assert "good_result" in results

        # Cleanup
        del pm._hooks["test_crash_hook"]


# ──────────────────────────────────────────────
# 13. call_hook with timeout
# ──────────────────────────────────────────────

class TestHookTimeout:
    def test_slow_hook_times_out(self):
        """A hook that takes longer than _HOOK_TIMEOUT should be skipped."""
        def slow_hook():
            time.sleep(pm._HOOK_TIMEOUT + 5)
            return "should_not_reach"

        pm._hooks["slow_hook_test"] = [{
            "plugin_name": "slow_plugin",
            "fn": slow_hook,
            "enabled": True,
        }]

        start = time.time()
        results = pm.call_hook("slow_hook_test")
        elapsed = time.time() - start

        assert results == []
        # Should complete in roughly _HOOK_TIMEOUT, not hang forever
        assert elapsed < pm._HOOK_TIMEOUT + 10

        del pm._hooks["slow_hook_test"]


# ──────────────────────────────────────────────
# 14. Thread safety
# ──────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_discover(self):
        """Multiple threads calling discover_plugins simultaneously."""
        results = []
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            d = pm.discover_plugins()
            results.append(d)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(results) == 5
        for r in results:
            assert "example-plugin" in r

    def test_concurrent_call_hook(self):
        """Multiple threads calling call_hook simultaneously."""
        pm.load_plugin("example-plugin")
        results_lock = threading.Lock()
        all_results = []
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            r = pm.call_hook("on_startup")
            with results_lock:
                all_results.append(r)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert len(all_results) == 10
        for r in all_results:
            assert len(r) >= 1


# ──────────────────────────────────────────────
# 15. install_plugin_from_github (stub)
# ──────────────────────────────────────────────

class TestGithubStub:
    def test_returns_not_implemented(self):
        result = pm.install_plugin_from_github("https://github.com/test/repo")
        assert result["ok"] is False
        assert "not implemented" in result["error"].lower()


# ──────────────────────────────────────────────
# 16. reset
# ──────────────────────────────────────────────

class TestReset:
    def test_reset_clears_registry(self):
        pm.discover_plugins()
        pm.reset()
        assert pm.list_plugins() == []

    def test_reset_clears_hooks(self):
        pm.load_plugin("example-plugin")
        assert len(pm._hooks) > 0
        pm.reset()
        assert len(pm._hooks) == 0


# ──────────────────────────────────────────────
# 17. _defaults_from_schema
# ──────────────────────────────────────────────

class TestDefaultsFromSchema:
    def test_extracts_defaults(self):
        schema = {
            "enabled": {"type": "boolean", "default": True},
            "prefix": {"type": "string", "default": "[TEST]"},
            "no_default": {"type": "integer"},
        }
        defaults = pm._defaults_from_schema(schema)
        assert defaults["enabled"] is True
        assert defaults["prefix"] == "[TEST]"
        assert "no_default" not in defaults

    def test_empty_schema(self):
        assert pm._defaults_from_schema({}) == {}


# ──────────────────────────────────────────────
# 18. Integration: full lifecycle
# ──────────────────────────────────────────────

class TestFullLifecycle:
    def test_discover_load_hook_unload(self, example_plugin_name):
        """Full lifecycle: discover → load → call hooks → unload."""
        # Discover
        discovered = pm.discover_plugins()
        assert example_plugin_name in discovered

        # Load
        result = pm.load_plugin(example_plugin_name)
        assert result["ok"] is True

        # Call hooks
        startup = pm.call_hook("on_startup")
        assert len(startup) >= 1

        finding = {"title": "Test"}
        pm.call_hook("on_finding", finding)
        assert finding.get("plugin") == "example-plugin"

        # Unload
        result = pm.unload_plugin(example_plugin_name)
        assert result["ok"] is True

        # Verify hooks gone
        assert pm.call_hook("on_startup") == []
