"""
example_plugin/main.py — MIRV Example Plugin

Demonstrates all available plugin hooks.  Each hook simply logs its
invocation through the standard logging system.  The ``on_finding``
hook injects a ``plugin`` tag into the finding dict so downstream
consumers can identify plugin-enriched data.
"""

import logging

logger = logging.getLogger("vulnforge.plugins.example")

# ── Config injected by plugin_manager before import ──
# Falls back to safe defaults if the manager hasn't set them yet.
try:
    from backend.plugins.example_plugin import _plugin_config as _cfg  # type: ignore
    PREFIX = _cfg.get("prefix", "[EXAMPLE]")
except Exception:
    PREFIX = "[EXAMPLE]"


def on_startup() -> dict:
    """Called once when the plugin is loaded."""
    logger.info("%s Example plugin started", PREFIX)
    return {"plugin": "example-plugin", "event": "startup"}


def on_shutdown() -> dict:
    """Called when the plugin is unloaded."""
    logger.info("%s Example plugin stopped", PREFIX)
    return {"plugin": "example-plugin", "event": "shutdown"}


def on_tool_result(tool: str, target: str, output: str) -> dict:
    """Called after a tool finishes execution."""
    logger.info(
        "%s Tool '%s' finished against %s (%d chars output)",
        PREFIX, tool, target, len(output) if output else 0,
    )
    return {"plugin": "example-plugin", "tool": tool, "target": target}


def on_finding(finding: dict) -> dict:
    """Called for each finding.  Enriches the dict with a plugin tag."""
    logger.info("%s New finding: %s", PREFIX, finding.get("title", "untitled"))
    finding["plugin"] = "example-plugin"
    return finding


def on_event(event: dict) -> dict:
    """Called for general events (SIEM, connection, etc.)."""
    logger.info("%s Event received: %s", PREFIX, event.get("type", "unknown"))
    return {"plugin": "example-plugin", "event": event.get("type", "unknown")}
