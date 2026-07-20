"""
plugin_manager.py — MIRV Plugin System

Loads, manages, and executes external plugins via a hook-based architecture.
Each plugin lives in ``backend/plugins/<name>/`` and must ship a
``plugin.json`` manifest plus a ``main.py`` entry-point.

Hook contract:
  - Plugin functions are plain callables (no decorator required).
  - Discovered by name convention: ``on_*`` or via the ``hooks`` list
    in the manifest.
  - Each function receives whatever arguments the caller passes to
    ``call_hook()``.
"""

import os
import sys
import json
import types
import importlib
import importlib.util
import inspect
import threading
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

# ── Logger ──
_logger = logging.getLogger("vulnforge.plugins")

# ── Paths ──
_BACKEND_DIR = Path(__file__).resolve().parent          # backend/
_PLUGINS_DIR = _BACKEND_DIR / "plugins"                  # backend/plugins/
_MANIFEST_FILENAME = "plugin.json"
_ENTRYPOINT_FILENAME = "main.py"
_HOOK_TIMEOUT = 30  # seconds per single hook invocation


# ════════════════════════════════════════════════════════════════
#  Dataclasses
# ════════════════════════════════════════════════════════════════

@dataclass
class PluginManifest:
    """Structured representation of ``plugin.json``."""
    name: str
    version: str
    author: str
    description: str
    hooks: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict = field(default_factory=dict)


@dataclass
class PluginInfo:
    """Runtime state for a single loaded (or discovered) plugin."""
    name: str
    manifest: PluginManifest | None
    module_dir: str
    status: str = "discovered"      # discovered | loaded | unloaded | error | disabled
    enabled: bool = True
    loaded_at: str | None = None
    error: str | None = None
    config: dict = field(default_factory=dict)


# ════════════════════════════════════════════════════════════════
#  Internal registries (module-level)
# ════════════════════════════════════════════════════════════════

_hooks: dict[str, list[dict]] = {}      # hook_name → [{plugin_name, fn, enabled}]
_registry: dict[str, PluginInfo] = {}   # plugin_name → PluginInfo
_lock = threading.Lock()


# ════════════════════════════════════════════════════════════════
#  1. discover_plugins
# ════════════════════════════════════════════════════════════════

def discover_plugins() -> list[str]:
    """
    Scan ``backend/plugins/`` for subdirectories containing ``plugin.json``.
    Populates ``_registry`` with *discovered* (not-yet-loaded) entries.

    Returns
    -------
    list[str] : Names of discovered plugins.
    """
    discovered: list[str] = []

    if not _PLUGINS_DIR.is_dir():
        _logger.debug("Plugins directory does not exist: %s", _PLUGINS_DIR)
        return discovered

    for entry in sorted(_PLUGINS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        manifest_path = entry / _MANIFEST_FILENAME
        if not manifest_path.is_file():
            continue

        try:
            raw = manifest_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            name = data.get("name", entry.name)

            manifest = PluginManifest(
                name=name,
                version=data.get("version", "0.0.0"),
                author=data.get("author", "unknown"),
                description=data.get("description", ""),
                hooks=data.get("hooks", []),
                dependencies=data.get("dependencies", []),
                config_schema=data.get("config_schema", {}),
            )

            with _lock:
                if name not in _registry:
                    _registry[name] = PluginInfo(
                        name=name,
                        manifest=manifest,
                        module_dir=str(entry),
                        status="discovered",
                        enabled=True,
                        config=_defaults_from_schema(manifest.config_schema),
                    )
                else:
                    # Update manifest if re-discovered
                    _registry[name].manifest = manifest
                    _registry[name].module_dir = str(entry)

            discovered.append(name)
            _logger.debug("Discovered plugin: %s", name)

        except Exception as exc:
            _logger.warning("Failed to read manifest at %s: %s", manifest_path, exc)

    return discovered


def _defaults_from_schema(schema: dict) -> dict:
    """Extract default values from a JSON-schema-like dict."""
    defaults: dict = {}
    for key, spec in schema.items():
        if isinstance(spec, dict) and "default" in spec:
            defaults[key] = spec["default"]
    return defaults


# ════════════════════════════════════════════════════════════════
#  2. load_plugin
# ════════════════════════════════════════════════════════════════

def load_plugin(name: str) -> dict:
    """
    Load a plugin by name.

    1. Read & validate ``plugin.json``.
    2. Import ``main.py`` from the plugin directory.
    3. Inspect for ``on_*`` functions and register them as hooks.
    4. Call ``on_startup`` if present.

    Returns
    -------
    dict : ``{"ok": bool, "plugin": dict, "error": str | None}``
    """
    with _lock:
        info = _registry.get(name)

    if info is None:
        # Attempt discovery first
        discover_plugins()
        with _lock:
            info = _registry.get(name)

    if info is None:
        return {"ok": False, "plugin": name, "error": f"Plugin '{name}' not found in {_PLUGINS_DIR}"}

    plugin_dir = Path(info.module_dir)
    manifest_path = plugin_dir / _MANIFEST_FILENAME
    entrypoint = plugin_dir / _ENTRYPOINT_FILENAME

    # ── Validate manifest ──
    if not manifest_path.is_file():
        return {"ok": False, "plugin": name, "error": f"Missing {_MANIFEST_FILENAME}"}
    if not entrypoint.is_file():
        return {"ok": False, "plugin": name, "error": f"Missing {_ENTRYPOINT_FILENAME}"}

    try:
        raw = manifest_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        return {"ok": False, "plugin": name, "error": f"Invalid manifest: {exc}"}

    required_fields = ("name", "version", "author", "description")
    for fld in required_fields:
        if fld not in data:
            return {"ok": False, "plugin": name, "error": f"Manifest missing required field: '{fld}'"}

    # ── Import entrypoint module ──
    module_fqn = f"backend.plugins.{name}.main"
    try:
        # Inject plugin config as a module attribute so the plugin can read it
        config_module_name = f"backend.plugins.{name}._plugin_config"
        sys.modules[config_module_name] = types.ModuleType(config_module_name)
        sys.modules[config_module_name].get = lambda key, default=None: info.config.get(key, default)  # type: ignore
        # Also expose as a plain dict-like attribute
        sys.modules[config_module_name].__dict__["_plugin_config"] = info.config  # type: ignore

        spec = importlib.util.spec_from_file_location(module_fqn, str(entrypoint))
        if spec is None or spec.loader is None:
            return {"ok": False, "plugin": name, "error": "Cannot create module spec"}

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_fqn] = module
        spec.loader.exec_module(module)
    except Exception as exc:
        _logger.error("Failed to import plugin '%s': %s", name, exc)
        with _lock:
            info.status = "error"
            info.error = str(exc)
        return {"ok": False, "plugin": name, "error": f"Import error: {exc}"}

    # ── Discover hook functions ──
    hooks_found = 0
    manifest_hooks = set(info.manifest.hooks) if info.manifest else set()

    for attr_name in dir(module):
        obj = getattr(module, attr_name)
        if not callable(obj):
            continue
        # Accept: explicitly listed in manifest OR follows on_* naming
        if attr_name in manifest_hooks or attr_name.startswith("on_"):
            _register_hook(name, attr_name, obj)
            hooks_found += 1

    # ── Update registry ──
    with _lock:
        info.status = "loaded"
        info.error = None
        info.loaded_at = _now_iso()

    _logger.info("Loaded plugin '%s' — %d hooks registered", name, hooks_found)

    # ── Call on_startup if present ──
    startup_results = call_hook("on_startup")
    _logger.debug("on_startup results for '%s': %s", name, startup_results)

    return {"ok": True, "plugin": _info_dict(info), "error": None}


def _register_hook(plugin_name: str, hook_name: str, fn: Any) -> None:
    """Add a hook registration (thread-safe)."""
    with _lock:
        if hook_name not in _hooks:
            _hooks[hook_name] = []
        # Avoid duplicate registrations
        for entry in _hooks[hook_name]:
            if entry["plugin_name"] == plugin_name and entry["fn"] is fn:
                return
        _hooks[hook_name].append({
            "plugin_name": plugin_name,
            "fn": fn,
            "enabled": True,
        })


def _now_iso() -> str:
    """ISO-8601 timestamp for loaded_at."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ════════════════════════════════════════════════════════════════
#  3. unload_plugin
# ════════════════════════════════════════════════════════════════

def unload_plugin(name: str) -> dict:
    """
    Unload a plugin: call on_shutdown, remove hooks, clean sys.modules.

    Returns
    -------
    dict : ``{"ok": bool, "plugin": str, "error": str | None}``
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        return {"ok": False, "plugin": name, "error": "Plugin not registered"}

    # ── Call on_shutdown first ──
    try:
        call_hook("on_shutdown")
    except Exception as exc:
        _logger.warning("on_shutdown failed for '%s': %s", name, exc)

    # ── Remove hook registrations ──
    with _lock:
        for hook_name in list(_hooks.keys()):
            _hooks[hook_name] = [
                entry for entry in _hooks[hook_name]
                if entry["plugin_name"] != name
            ]
            # Clean up empty hook lists
            if not _hooks[hook_name]:
                del _hooks[hook_name]

        info.status = "unloaded"
        info.loaded_at = None

    # ── Remove from sys.modules ──
    module_fqn = f"backend.plugins.{name}.main"
    config_fqn = f"backend.plugins.{name}._plugin_config"
    for mod_key in list(sys.modules.keys()):
        if mod_key == module_fqn or mod_key == config_fqn or mod_key.startswith(f"backend.plugins.{name}."):
            del sys.modules[mod_key]

    _logger.info("Unloaded plugin '%s'", name)
    return {"ok": True, "plugin": name, "error": None}


# ════════════════════════════════════════════════════════════════
#  4. reload_plugin
# ════════════════════════════════════════════════════════════════

def reload_plugin(name: str) -> dict:
    """
    Unload then re-load a plugin.

    Returns
    -------
    dict : ``{"ok": bool, "plugin": str, "error": str | None}``
    """
    _logger.info("Reloading plugin '%s'", name)
    unload_result = unload_plugin(name)
    if not unload_result["ok"] and "not registered" not in str(unload_result.get("error", "")):
        # Only propagate unload errors that aren't "not registered"
        return unload_result
    return load_plugin(name)


# ════════════════════════════════════════════════════════════════
#  5. get_plugin_info
# ════════════════════════════════════════════════════════════════

def get_plugin_info(name: str) -> dict | None:
    """
    Return plugin info as a dict, or ``None`` if not found.
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        return None
    return _info_dict(info)


# ════════════════════════════════════════════════════════════════
#  6. list_plugins
# ════════════════════════════════════════════════════════════════

def list_plugins() -> list[dict]:
    """
    Return all registered plugins (discovered + loaded + error).
    """
    with _lock:
        snapshot = list(_registry.values())
    # Build info dicts OUTSIDE the lock to avoid deadlock with _info_dict
    return [_info_dict(info) for info in snapshot]


# ════════════════════════════════════════════════════════════════
#  7. enable_plugin
# ════════════════════════════════════════════════════════════════

def enable_plugin(name: str) -> dict:
    """
    Enable a plugin — its hooks will be called by ``call_hook``.

    Returns
    -------
    dict : ``{"ok": bool, "plugin": str, "error": str | None}``
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        return {"ok": False, "plugin": name, "error": "Plugin not found"}

    info.enabled = True
    # Re-enable all hook entries for this plugin
    with _lock:
        for hook_entries in _hooks.values():
            for entry in hook_entries:
                if entry["plugin_name"] == name:
                    entry["enabled"] = True
    _logger.info("Enabled plugin '%s'", name)
    return {"ok": True, "plugin": name, "error": None}


# ════════════════════════════════════════════════════════════════
#  8. disable_plugin
# ════════════════════════════════════════════════════════════════

def disable_plugin(name: str) -> dict:
    """
    Disable a plugin — its hooks will be skipped by ``call_hook``.

    Returns
    -------
    dict : ``{"ok": bool, "plugin": str, "error": str | None}``
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        return {"ok": False, "plugin": name, "error": "Plugin not found"}

    info.enabled = False
    with _lock:
        for hook_entries in _hooks.values():
            for entry in hook_entries:
                if entry["plugin_name"] == name:
                    entry["enabled"] = False
    _logger.info("Disabled plugin '%s'", name)
    return {"ok": True, "plugin": name, "error": None}


# ════════════════════════════════════════════════════════════════
#  9. call_hook
# ════════════════════════════════════════════════════════════════

def call_hook(hook_name: str, *args: Any, **kwargs: Any) -> list[Any]:
    """
    Invoke all enabled hook functions registered under *hook_name*.

    Each function is executed in a separate thread with a hard timeout
    of ``_HOOK_TIMEOUT`` seconds.  Exceptions in one plugin do NOT
    affect others.

    Returns
    -------
    list[Any] : One result per successful invocation.
    """
    _logger.debug("call_hook('%s') — args=%d, kwargs=%d", hook_name, len(args), len(kwargs))

    with _lock:
        entries = list(_hooks.get(hook_name, []))

    results: list[Any] = []

    for entry in entries:
        if not entry["enabled"]:
            continue

        plugin_name = entry["plugin_name"]
        fn = entry["fn"]

        # Check if the plugin itself is enabled
        with _lock:
            info = _registry.get(plugin_name)
        if info and not info.enabled:
            continue

        result_container: dict[str, Any] = {}
        exception_container: list[Exception] = []

        def _target():
            try:
                result_container["value"] = fn(*args, **kwargs)
            except Exception as exc:
                exception_container.append(exc)

        thread = threading.Thread(target=_target, daemon=True)
        thread.start()
        thread.join(timeout=_HOOK_TIMEOUT)

        if thread.is_alive():
            _logger.warning(
                "Hook '%s' from plugin '%s' timed out after %ds",
                hook_name, plugin_name, _HOOK_TIMEOUT,
            )
            continue

        if exception_container:
            _logger.error(
                "Hook '%s' from plugin '%s' raised: %s",
                hook_name, plugin_name, exception_container[0],
            )
            continue

        if "value" in result_container:
            results.append(result_container["value"])

    return results


# ════════════════════════════════════════════════════════════════
#  10. install_plugin_from_github (stub)
# ════════════════════════════════════════════════════════════════

def install_plugin_from_github(repo_url: str) -> dict:
    """
    Placeholder for future GitHub-based plugin installation.

    Returns
    -------
    dict : Always ``{"ok": False, "error": "Not implemented yet"}``
    """
    _logger.info("install_plugin_from_github called (stub): %s", repo_url)
    return {"ok": False, "error": "Not implemented yet"}


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

def _info_dict(info: PluginInfo) -> dict:
    """Convert a PluginInfo dataclass to a JSON-safe dict."""
    hooks_for_plugin: list[str] = []
    with _lock:
        for hook_name, entries in _hooks.items():
            for entry in entries:
                if entry["plugin_name"] == info.name:
                    hooks_for_plugin.append(hook_name)
                    break

    return {
        "name": info.name,
        "version": info.manifest.version if info.manifest else "unknown",
        "author": info.manifest.author if info.manifest else "unknown",
        "description": info.manifest.description if info.manifest else "",
        "status": info.status,
        "enabled": info.enabled,
        "loaded_at": info.loaded_at,
        "error": info.error,
        "config": info.config,
        "hooks": hooks_for_plugin,
        "module_dir": info.module_dir,
    }


def reset() -> None:
    """
    Reset all plugin state.  Primarily for testing.

    Calls on_shutdown for every loaded plugin, then clears registries.
    """
    with _lock:
        loaded_names = [
            name for name, info in _registry.items()
            if info.status == "loaded"
        ]

    for name in loaded_names:
        try:
            call_hook("on_shutdown")
        except Exception:
            pass

    with _lock:
        _hooks.clear()
        _registry.clear()

    # Clean sys.modules
    for mod_key in list(sys.modules.keys()):
        if mod_key.startswith("backend.plugins.") and mod_key != "backend.plugins":
            del sys.modules[mod_key]


# ════════════════════════════════════════════════════════════════
#  Automatic discovery on import
# ════════════════════════════════════════════════════════════════
_discovered = discover_plugins()
