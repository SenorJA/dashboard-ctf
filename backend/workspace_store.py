"""
workspace_store.py -- MIRV Module

Best-effort, opt-in persistence for in-memory registries (assessments,
scheduler). The in-memory registry stays authoritative; this store snapshots
the whole registry as JSON in a single ``workspace_state`` row (key) so it
survives backend restarts.

Opt-in gating:
  * Environment ``MIRV_PERSIST_WORKSPACE=1`` (or ``true``/``yes``).
  * Supabase must be available (``database.is_available()``).

Fails silently everywhere (try/except + logging) so persistence problems
never break a live session. Tests keep registries hermetic because the env
var is unset by default.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, List, Optional

from backend import database

_logger = logging.getLogger("vulnforge.workspace_store")

_ENABLE_KEY = "MIRV_PERSIST_WORKSPACE"
_CACHE: Dict[str, List[dict]] = {}


def is_enabled() -> bool:
    """Persistence is enabled only when the flag is set AND Supabase exists."""
    flag = os.getenv(_ENABLE_KEY, "").strip().lower()
    return flag in ("1", "true", "yes") and database.is_available()


def upsert(key: str, data: List[dict]) -> bool:
    """Snapshot a registry. Returns True when persisted, False otherwise."""
    if not is_enabled():
        return False
    try:
        client = database.get_client()
        client.table("workspace_state").upsert(
            {"key": key, "value": json.dumps(data)},
            on_conflict="key",
        ).execute()
        _CACHE[key] = data
        return True
    except Exception as exc:  # pragma: no cover - defensive
        _logger.warning("workspace_store upsert '%s' failed: %s", key, exc)
        return False


def load(key: str) -> Optional[List[dict]]:
    """Return the last snapshot for a registry, or None if not persisted."""
    if key in _CACHE:
        return list(_CACHE[key])
    if not is_enabled():
        return None
    try:
        client = database.get_client()
        res = (
            client.table("workspace_state")
            .select("value")
            .eq("key", key)
            .limit(1)
            .execute()
        )
        rows = res.data
        if not rows:
            return None
        payload = json.loads(rows[0]["value"])
        _CACHE[key] = payload
        return list(payload)
    except Exception as exc:  # pragma: no cover - defensive
        _logger.warning("workspace_store load '%s' failed: %s", key, exc)
        return None


def clear_cache(key: Optional[str] = None) -> None:
    """Drop the in-process snapshot cache (used by tests)."""
    if key:
        _CACHE.pop(key, None)
    else:
        _CACHE.clear()