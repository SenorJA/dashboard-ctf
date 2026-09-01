"""
M.I.R.V. — Episodic Memory Store
=================================
SQLite-backed episodic memory for the orchestrator. After each specialist
interaction, key decisions are extracted and stored locally so the
next session can recall what was recommended previously.

Inspired by OpenExecutive's episodic memory pattern (SQLite + haiku
background pass), adapted for MIRV's security workflows.

Design:
- **Local SQLite** (stdlib sqlite3, no new deps): ``backend/data/episodic_memory.db``
- **Auto-create**: table created on first use if file doesn't exist
- **Thread-safe**: ``threading.Lock`` around all writes
- **Capped**: max 500 entries (LRU eviction by timestamp)
- **Offline-first**: always works, no external dependency
- **Redacted**: all text redacted via ``redact.redact_string`` before storage
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

# ════════════════════════════════════════════════════════════════
#  Constants & logger
# ════════════════════════════════════════════════════════════════

_logger = logging.getLogger("vulnforge.episodic")

_DB_PATH = Path(__file__).parent / "data" / "episodic_memory.db"
_MAX_ENTRIES = 500
_EVICT_BATCH = 50

_lock = threading.Lock()

# Heuristic markers used to auto-extract "key decisions" from a raw
# LLM response when the caller did not pass an explicit ``key_decisions``.
_DECISION_MARKERS = (
    "recommend",
    "suggest",
    "next step",
    "important",
    "key finding",
)


# ════════════════════════════════════════════════════════════════
#  Internal helpers
# ════════════════════════════════════════════════════════════════

def _init_db() -> None:
    """Create the ``data/`` directory and ``episodic_memory`` table if missing.

    Idempotent and safe to call on every write — SQLite's ``CREATE TABLE IF
    NOT EXISTS`` is a cheap no-op once the schema exists.
    """
    try:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[episodic] mkdir failed: %s", exc)

    try:
        conn = sqlite3.connect(str(_DB_PATH), timeout=10.0)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS episodic_memory (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id    TEXT,
                    specialist    TEXT,
                    task          TEXT,
                    key_decisions TEXT,
                    timestamp     TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_episodic_session "
                "ON episodic_memory(session_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_episodic_ts "
                "ON episodic_memory(timestamp)"
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:  # pragma: no cover — defensive
        _logger.warning("[episodic] _init_db failed: %s", exc)


def _redact(text: str) -> str:
    """Best-effort redaction — never raises, returns the input on failure."""
    try:
        from backend.redact import redact_string
        return redact_string(text or "")
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[episodic] redact unavailable: %s", exc)
        return text or ""


def _extract_key_decisions(response: str) -> str:
    """Heuristic extraction of the most relevant lines from ``response``.

    No LLM is used — we simply keep the first 5 lines containing one of the
    ``_DECISION_MARKERS`` keywords (case-insensitive). Returns a newline-
    joined string. Empty string if nothing matches.
    """
    if not response:
        return ""
    picked: list[str] = []
    for line in response.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if any(marker in low for marker in _DECISION_MARKERS):
            picked.append(stripped)
            if len(picked) >= 5:
                break
    if picked:
        return "\n".join(picked)

    # Fallback: the LLM often returns a JSON array of steps (e.g.
    # {"description": "..."}). Extract up to 3 step descriptions so the
    # episodic memory still has useful content when no marker keywords
    # appear in the raw text.
    try:
        import json as _json
        from backend.redact import redact_string as _redact
        data = _json.loads(response)
        if isinstance(data, list):
            steps: list[str] = []
            for item in data:
                if isinstance(item, dict):
                    desc = item.get("description") or item.get("title") or ""
                    if isinstance(desc, str) and desc.strip():
                        steps.append(desc.strip())
                if len(steps) >= 3:
                    break
            if steps:
                return _redact("\n".join(steps))
    except Exception:
        pass
    return ""


# ════════════════════════════════════════════════════════════════
#  Public API
# ════════════════════════════════════════════════════════════════

def save_episodic_memory(
    session_id: str,
    specialist: str,
    task: str,
    response: str,
    key_decisions: str = "",
) -> dict:
    """Persist one episodic-memory entry after a specialist interaction.

    * ``task`` and ``key_decisions`` are **redacted** before storage.
    * If ``key_decisions`` is empty, a heuristic extractor pulls the most
      relevant lines out of ``response`` (no LLM call).
    * Enforces an LRU cap of ``_MAX_ENTRIES`` rows: when exceeded, the
      oldest ``_EVICT_BATCH`` rows are deleted.
    * Never raises — returns ``{"ok": False, "error": ...}`` on failure.
    """
    try:
        _init_db()

        safe_task = _redact(task or "")

        if key_decisions:
            decisions = _redact(key_decisions)
        else:
            # Heuristic extraction from raw response (no LLM). The raw
            # response is NOT stored verbatim — only the extracted
            # decision lines are persisted, and they are redacted too.
            decisions = _redact(_extract_key_decisions(response or ""))

        ts = datetime.now(timezone.utc).isoformat()

        with _lock:
            conn = sqlite3.connect(str(_DB_PATH), timeout=10.0)
            try:
                cur = conn.execute(
                    """
                    INSERT INTO episodic_memory
                        (session_id, specialist, task, key_decisions, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (session_id or "", specialist or "", safe_task, decisions, ts),
                )
                rowid = cur.lastrowid

                # LRU eviction: count rows, evict oldest batch if over cap.
                count_row = conn.execute(
                    "SELECT COUNT(*) FROM episodic_memory"
                ).fetchone()
                total = count_row[0] if count_row else 0
                if total > _MAX_ENTRIES:
                    conn.execute(
                        f"""
                        DELETE FROM episodic_memory
                        WHERE id IN (
                            SELECT id FROM episodic_memory
                            ORDER BY timestamp ASC
                            LIMIT {_EVICT_BATCH}
                        )
                        """
                    )
                conn.commit()
            finally:
                conn.close()

        return {
            "ok": True,
            "id": rowid,
            "session_id": session_id or "",
            "key_decisions": decisions,
        }
    except Exception as exc:
        _logger.warning("[episodic] save failed: %s", exc, exc_info=False)
        return {"ok": False, "error": str(exc)}


def get_episodic_memory(session_id: str = "", limit: int = 20) -> dict:
    """Retrieve recent episodic-memory entries.

    * ``session_id`` empty → latest ``limit`` entries across all sessions.
    * ``session_id`` set  → latest ``limit`` entries for that session only.
    * ``limit`` is clamped to ``[0, 500]`` to avoid pathological queries.

    Returns ``{"ok": True, "memories": [...]}`` — each memory is a dict
    with ``id``, ``session_id``, ``specialist``, ``task``, ``key_decisions``
    and ``timestamp``. Never raises.
    """
    try:
        _init_db()
        safe_limit = max(0, min(int(limit), _MAX_ENTRIES))

        with _lock:
            conn = sqlite3.connect(str(_DB_PATH), timeout=10.0)
            try:
                conn.row_factory = sqlite3.Row
                if session_id:
                    rows = conn.execute(
                        """
                        SELECT id, session_id, specialist, task, key_decisions, timestamp
                        FROM episodic_memory
                        WHERE session_id = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (session_id, safe_limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT id, session_id, specialist, task, key_decisions, timestamp
                        FROM episodic_memory
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (safe_limit,),
                    ).fetchall()
                memories = [dict(r) for r in rows]
            finally:
                conn.close()

        return {"ok": True, "memories": memories}
    except Exception as exc:
        _logger.warning("[episodic] get failed: %s", exc, exc_info=False)
        return {"ok": False, "error": str(exc), "memories": []}


def clear_episodic_memory(session_id: str = "") -> dict:
    """Delete episodic-memory entries.

    * ``session_id`` empty → wipe the whole table.
    * ``session_id`` set  → wipe only that session's entries.

    Returns ``{"ok": True, "cleared": <int>}`` with the row count removed.
    Never raises.
    """
    try:
        _init_db()
        with _lock:
            conn = sqlite3.connect(str(_DB_PATH), timeout=10.0)
            try:
                if session_id:
                    cur = conn.execute(
                        "DELETE FROM episodic_memory WHERE session_id = ?",
                        (session_id,),
                    )
                else:
                    cur = conn.execute("DELETE FROM episodic_memory")
                cleared = cur.rowcount or 0
                conn.commit()
            finally:
                conn.close()
        return {"ok": True, "cleared": cleared}
    except Exception as exc:
        _logger.warning("[episodic] clear failed: %s", exc, exc_info=False)
        return {"ok": False, "error": str(exc), "cleared": 0}


def get_episodic_context(session_id: str = "") -> str:
    """Build a prompt-injectable summary of past decisions.

    Format::

        <past_decisions>
        - [recon] task1: key_decisions1
        - [webvuln] task2: key_decisions2
        </past_decisions>

    Returns ``""`` when there is nothing to recall (empty DB or empty
    session). Never raises.
    """
    try:
        # Pull a reasonable window of recent memories.
        result = get_episodic_memory(session_id=session_id, limit=20)
        if not result.get("ok"):
            return ""
        memories = result.get("memories") or []
        if not memories:
            return ""

        lines: list[str] = []
        for m in memories:
            spec = m.get("specialist") or "?"
            task_txt = (m.get("task") or "").strip().replace("\n", " ")
            dec = (m.get("key_decisions") or "").strip().replace("\n", " ")
            if dec:
                lines.append(f"- [{spec}] {task_txt}: {dec}" if task_txt else f"- [{spec}] {dec}")
            elif task_txt:
                lines.append(f"- [{spec}] {task_txt}")
        if not lines:
            return ""
        return "<past_decisions>\n" + "\n".join(lines) + "\n</past_decisions>"
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[episodic] context render failed: %s", exc)
        return ""
