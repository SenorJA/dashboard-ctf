"""
audit_log.py -- MIRV Structured JSON-lines Audit Logger with rotation
=====================================================================

A structured audit logger inspired by PentesterFlow's ``pino`` JSON-lines
logger:

- Writes one JSON object per line (JSONL format)
- Rotates when the active file reaches ``MIRV_AUDIT_MAX_BYTES`` (default 4 MB)
- Keeps ``MIRV_AUDIT_GENERATIONS`` (default 3) generations:
    ``audit.jsonl`` -> ``audit.jsonl.1`` -> ``audit.jsonl.2`` -> ``audit.jsonl.3``
- Auto-redacts secrets in messages and structured ``details`` via the
  existing :mod:`backend.redact` primitives (so passwords / API keys /
  JWTs never land on disk in cleartext)
- Forwards every entry at or above ``MIRV_AUDIT_SIEM_LEVEL`` (default
  WARNING) to the in-memory SIEM engine (:mod:`backend.siem`) as a
  security event -- a single audit() call therefore feeds both the
  long-term JSONL trail and the short-term correlation engine
- Thread-safe (module-level :class:`threading.Lock`)
- Exposes a queryable in-process API + three REST endpoints in main.py

Design notes
------------
- The module is **import-safe**: importing it does NOT create any file
  nor write any log. Callers (main.py startup) must call
  :func:`init_audit_log` to activate the logger.
- :func:`audit` is lenient: an invalid level returns
  ``{"ok": False, "error": ...}`` rather than raising -- log helpers
  should never crash their callers.
- :func:`get_audit_logger` returns a standard :class:`logging.Logger`
  wired to a :class:`AuditLogHandler` so existing ``logger.info(...)``
  calls across the codebase also produce structured JSONL entries.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── Local deps (import lazily so tests can monkeypatch) ──
from backend.redact import redact_string, redact_dict
from backend import siem

logger = logging.getLogger("vulnforge.audit")


# ══════════════════════════════════════════════════════════════════
#  AuditEvent dataclass
# ══════════════════════════════════════════════════════════════════

@dataclass
class AuditEvent:
    """A single structured audit log entry (one JSONL line on disk)."""
    timestamp: str          # ISO-8601 with timezone (UTC)
    level: str             # DEBUG | INFO | WARNING | ERROR | CRITICAL
    category: str          # auth | tool | finding | report | plugin | siem | system | api | ws | docker | scope
    event: str             # short event name e.g. "tool_executed"
    message: str           # human-readable message (already redacted)
    user: Optional[str] = None
    ip: Optional[str] = None
    target: Optional[str] = None
    session_id: Optional[str] = None
    details: dict = field(default_factory=dict)   # already redacted
    redacted: bool = False


# ══════════════════════════════════════════════════════════════════
#  Module-level configuration (configurable via env on first init)
# ══════════════════════════════════════════════════════════════════

_lock: threading.Lock = threading.Lock()

_BACKEND_DIR = Path(__file__).resolve().parent
_log_path: Path = _BACKEND_DIR / "logs" / "audit.jsonl"
_max_bytes: int = 4 * 1024 * 1024   # 4 MB default
_generations: int = 3
_min_level: str = "INFO"
_siem_min_level: str = "WARNING"
_initialized: bool = False

_levels: dict[str, int] = {
    "DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50,
}

# Audit categories the frontend is allowed to filter by. Logging an
# unknown category is *not* an error (forward-compat for plugins) -- this
# set is only used by the manual ``POST /api/audit`` endpoint to validate
# caller-supplied input.
CATEGORIES: set[str] = {
    "auth", "tool", "finding", "report", "plugin", "siem",
    "system", "api", "ws", "docker", "scope",
}


# ══════════════════════════════════════════════════════════════════
#  Initialisation
# ══════════════════════════════════════════════════════════════════

def init_audit_log(
    path: Optional[str] = None,
    max_bytes: Optional[int] = None,
    generations: Optional[int] = None,
    level: Optional[str] = None,
    siem_min_level: Optional[str] = None,
) -> None:
    """
    Configure the audit logger. Idempotent -- subsequent calls only
    re-apply when the supplied configuration actually changes.

    Environment overrides (read once on first init):
        MIRV_AUDIT_MAX_BYTES   -- rotate threshold in bytes (default 4194304)
        MIRV_AUDIT_GENERATIONS -- rotated files to keep    (default 3)
        MIRV_AUDIT_LEVEL       -- minimum level to log     (default INFO)
        MIRV_AUDIT_SIEM_LEVEL  -- minimum level to forward to SIEM
                                   (default WARNING)

    Ensures the parent directory exists. Does NOT throw on bad input;
    falls back to the documented defaults.
    """
    global _log_path, _max_bytes, _generations, _min_level
    global _siem_min_level, _initialized

    # ── Resolve env defaults the first time we init ──
    env_bytes = os.getenv("MIRV_AUDIT_MAX_BYTES")
    env_gens = os.getenv("MIRV_AUDIT_GENERATIONS")
    env_level = os.getenv("MIRV_AUDIT_LEVEL")
    env_siem = os.getenv("MIRV_AUDIT_SIEM_LEVEL")

    new_path = Path(path) if path else _log_path
    new_max = int(max_bytes) if max_bytes is not None else (
        int(env_bytes) if env_bytes and env_bytes.isdigit() else _max_bytes
    )
    new_gens = int(generations) if generations is not None else (
        int(env_gens) if env_gens and env_gens.isdigit() else _generations
    )
    new_level = (level or env_level or _min_level).upper()
    new_siem = (siem_min_level or env_siem or _siem_min_level).upper()

    # Validate levels (fall back to defaults on garbage input)
    if new_level not in _levels:
        new_level = _min_level
    if new_siem not in _levels:
        new_siem = _siem_min_level
    if new_max < 1:
        new_max = _max_bytes
    if new_gens < 1:
        new_gens = _generations

    with _lock:
        # Idempotent guard: only re-apply if something actually changed
        if _initialized and (
            new_path == _log_path
            and new_max == _max_bytes
            and new_gens == _generations
            and new_level == _min_level
            and new_siem == _siem_min_level
        ):
            return

        _log_path = new_path
        _max_bytes = new_max
        _generations = new_gens
        _min_level = new_level
        _siem_min_level = new_siem
        _initialized = True

    # Ensure parent dir exists (outside the lock -- mkdir is cheap and
    # only races with itself, which is harmless).
    try:
        _log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("audit_log: could not create log dir %s: %s",
                       _log_path.parent, exc)


def _ensure_initialized() -> None:
    """Auto-init with defaults if the caller forgot to call init."""
    if not _initialized:
        init_audit_log()


# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def _now_iso() -> str:
    """Current UTC time as ISO-8601 with timezone."""
    return datetime.now(timezone.utc).isoformat()


def _level_to_siem_severity(level: str) -> str:
    """Map a Python logging level to a SIEM severity."""
    level = level.upper()
    if level in ("CRITICAL", "ERROR"):
        return "critical"
    if level == "WARNING":
        return "high"
    if level == "INFO":
        return "low"
    return "info"   # DEBUG


def _event_to_dict(ev: AuditEvent) -> dict:
    """Serialise an AuditEvent to a JSON-safe dict, dropping None fields
    to keep the JSONL payload compact."""
    d = asdict(ev)
    # Omit null fields (keeps lines short, matches PentesterFlow pino style)
    return {k: v for k, v in d.items() if v is not None}


# ══════════════════════════════════════════════════════════════════
#  Writer (thread-safe)
# ══════════════════════════════════════════════════════════════════

def _log_writer(line: str) -> None:
    """Thread-safe append of a single line to the active log file.

    Opens the file in append-binary mode, writes the line + newline,
    and closes immediately -- this guarantees durability per event and
    lets rotation remap the path safely between writes.
    """
    with _lock:
        try:
            with open(_log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.write("\n")
        except OSError as exc:
            # Never let the audit logger crash its caller.
            logger.error("audit_log: write failed to %s: %s", _log_path, exc)


# ══════════════════════════════════════════════════════════════════
#  Rotation
# ══════════════════════════════════════════════════════════════════

def rotate_if_needed() -> bool:
    """
    Rotate the active log file when it exceeds ``_max_bytes``.

    Rotation keeps ``_generations`` archive copies:
        delete ``audit.jsonl.<_generations>``  (oldest)
        rename ``audit.jsonl.<_generations-1>`` -> ``.<_generations>``
        ...
        rename ``audit.jsonl`` -> ``audit.jsonl.1``

    Returns True if rotation was performed, False otherwise.
    Thread-safe (holds ``_lock`` for the whole rename cascade).
    """
    with _lock:
        try:
            if not _log_path.exists():
                return False
            if _log_path.stat().st_size < _max_bytes:
                return False
        except OSError:
            return False

        # Delete the oldest generation (if present) then shift down.
        oldest = _log_path.with_suffix(_log_path.suffix + f".{_generations}")
        try:
            if oldest.exists():
                oldest.unlink()
        except OSError as exc:
            logger.warning("audit_log: could not delete %s: %s", oldest, exc)

        # Shift generations: .{n-1} -> .{n} for n in [generations .. 2]
        # then finally rotate the active file to .1
        for n in range(_generations, 1, -1):
            src = _log_path.with_suffix(_log_path.suffix + f".{n - 1}")
            dst = _log_path.with_suffix(_log_path.suffix + f".{n}")
            try:
                if src.exists():
                    # On Windows, replace() handles overwrite atomically.
                    src.replace(dst)
            except OSError as exc:
                logger.warning("audit_log: rotate %s -> %s failed: %s",
                               src, dst, exc)

        # Active -> .1
        archive = _log_path.with_suffix(_log_path.suffix + ".1")
        try:
            _log_path.replace(archive)
        except OSError as exc:
            logger.warning("audit_log: rotate active -> %s failed: %s",
                           archive, exc)

        return True


# ══════════════════════════════════════════════════════════════════
#  Core: audit()
# ══════════════════════════════════════════════════════════════════

def audit(
    level: str,
    category: str,
    event: str,
    message: str = "",
    user: Optional[str] = None,
    ip: Optional[str] = None,
    target: Optional[str] = None,
    session_id: Optional[str] = None,
    details: Optional[dict] = None,
) -> dict:
    """
    Emit a structured audit event.

    Steps:
        1. Validate level (return ``{"ok": False, ...}`` on bad input).
        2. Skip entirely if level below the configured minimum.
        3. Redact the message and the structured ``details`` dict.
        4. Build an :class:`AuditEvent`, serialise it, append one line.
        5. Rotate the log file if it now exceeds ``_max_bytes``.
        6. If level >= ``_siem_min_level``, forward a copy to the SIEM
           engine as a security event (best-effort -- never raises).

    Returns ``{"ok": True, "event": <dict>}`` on success, or
    ``{"ok": False, "error": "..."}`` on invalid input. Never raises.
    """
    _ensure_initialized()

    level_u = (level or "").upper()
    if level_u not in _levels:
        return {"ok": False, "error": f"Invalid level '{level}'"}

    # Level gate
    if _levels[level_u] < _levels[_min_level]:
        return {"ok": True, "skipped": True, "reason": "below_min_level"}

    # ── Redaction ──
    redacted = False
    safe_message = message or ""
    if safe_message:
        r = redact_string(safe_message)
        if r != safe_message:
            redacted = True
        safe_message = r

    safe_details: dict = {}
    if isinstance(details, dict) and details:
        safe_details = redact_dict(dict(details))
        # Heuristic: redaction touched some string value
        if _dict_contains_redaction_token(safe_details):
            redacted = True
        elif safe_details != details:
            redacted = True

    # ── Build the event ──
    ev = AuditEvent(
        timestamp=_now_iso(),
        level=level_u,
        category=category or "system",
        event=event or "unnamed",
        message=safe_message,
        user=user,
        ip=ip,
        target=target,
        session_id=session_id,
        details=safe_details,
        redacted=redacted,
    )
    payload = _event_to_dict(ev)
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    # ── Persist ──
    _log_writer(line)
    try:
        rotate_if_needed()
    except Exception as exc:  # pragma: no cover -- defensive
        logger.warning("audit_log: rotation failed: %s", exc)

    # ── Forward to SIEM (best-effort) ──
    if _levels[level_u] >= _levels[_siem_min_level]:
        try:
            siem.ingest_event(
                source="system",
                severity=_level_to_siem_severity(level_u),
                title=event or "audit_event",
                detail=safe_message or event,
                raw_data=safe_details,
                tags=[category] if category else [],
                ip=ip,
            )
        except Exception as exc:
            # SIEM ingestion must never break audit logging.
            logger.warning("audit_log: SIEM forward failed: %s", exc)

    return {"ok": True, "event": payload}


_REDACTION_TOKENS = ("[REDACTED]", "[AWS_KEY]", "[OPENAI_KEY]", "[GITHUB_TOKEN]",
                     "[GOOGLE_KEY]", "[SLACK_TOKEN]", "[STRIPE_KEY]",
                     "[BEARER]", "[JWT]", "[PRIVATE_KEY]", "[LONG_TOKEN]",
                     "[CREDIT_CARD]", "[COOKIE]")

def _dict_contains_redaction_token(d: Any) -> bool:
    """Return True if any string in ``d`` holds a known redaction marker."""
    if isinstance(d, str):
        return any(tok in d for tok in _REDACTION_TOKENS)
    if isinstance(d, dict):
        return any(_dict_contains_redaction_token(v) for v in d.values())
    if isinstance(d, list):
        return any(_dict_contains_redaction_token(v) for v in d)
    return False


# ══════════════════════════════════════════════════════════════════
#  Query API
# ══════════════════════════════════════════════════════════════════

def _read_jsonl(path: Path) -> list[dict]:
    """Parse a JSONL file into a list of dicts, skipping malformed lines."""
    out: list[dict] = []
    if not path.exists():
        return out
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except (ValueError, TypeError):
                    continue  # skip invalid JSON lines
                if isinstance(obj, dict):
                    out.append(obj)
    except OSError as exc:
        logger.warning("audit_log: read failed %s: %s", path, exc)
    return out


def get_recent_logs(
    limit: int = 200,
    level: Optional[str] = None,
    category: Optional[str] = None,
    event: Optional[str] = None,
    since: Optional[str] = None,
) -> list[dict]:
    """
    Return recent audit events sorted newest-first.

    Reads the active ``audit.jsonl`` first, then spills into
    ``audit.jsonl.1`` if more rows are needed to satisfy ``limit``.
    Filters (all optional, case-insensitive where applicable):
        level     -- exact level match (e.g. "WARNING")
        category  -- exact category match
        event     -- exact event name match
        since     -- ISO timestamp; only events at or after this are kept
    """
    _ensure_initialized()
    limit = max(1, min(int(limit), 5000))

    # Read active + first archive, newest-first is applied at the end.
    rows = _read_jsonl(_log_path)
    if len(rows) < limit:
        archive = _log_path.with_suffix(_log_path.suffix + ".1")
        rows = rows + _read_jsonl(archive)

    # ── Filters ──
    if level:
        level_u = level.upper()
        rows = [r for r in rows if str(r.get("level", "")).upper() == level_u]
    if category:
        rows = [r for r in rows if r.get("category") == category]
    if event:
        rows = [r for r in rows if r.get("event") == event]
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            kept = []
            for r in rows:
                ts = r.get("timestamp")
                if not ts:
                    continue
                try:
                    if datetime.fromisoformat(ts) >= since_dt:
                        kept.append(r)
                except (ValueError, TypeError):
                    continue
            rows = kept
        except (ValueError, TypeError):
            pass  # ignore invalid since

    # Sort newest first
    rows.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return rows[:limit]


def get_log_stats() -> dict:
    """
    Return aggregate statistics about the on-disk audit log:
        total_events, by_level, by_category, file_size_bytes,
        generations_present, log_path, max_bytes, generations_config,
        min_level, siem_min_level.
    """
    _ensure_initialized()
    rows = _read_jsonl(_log_path)

    by_level: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for r in rows:
        lvl = str(r.get("level", "?"))
        cat = str(r.get("category", "?"))
        by_level[lvl] = by_level.get(lvl, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1

    file_size = 0
    try:
        if _log_path.exists():
            file_size = _log_path.stat().st_size
    except OSError:
        pass

    gens_present: list[str] = []
    for n in range(1, _generations + 1):
        p = _log_path.with_suffix(_log_path.suffix + f".{n}")
        if p.exists():
            gens_present.append(p.name)

    return {
        "ok": True,
        "total_events": len(rows),
        "by_level": by_level,
        "by_category": by_category,
        "file_size_bytes": file_size,
        "generations_present": gens_present,
        "log_path": str(_log_path),
        "max_bytes": _max_bytes,
        "generations_config": _generations,
        "min_level": _min_level,
        "siem_min_level": _siem_min_level,
    }


# ══════════════════════════════════════════════════════════════════
#  Standard logging adapter
# ══════════════════════════════════════════════════════════════════

class AuditLogHandler(logging.Handler):
    """
    A :class:`logging.Handler` that converts standard :class:`LogRecord`
    instances into structured :class:`AuditEvent` entries.

    Attaching this handler to any logger makes its ``.info()`` /
    ``.warning()`` / ``.error()`` calls also produce JSONL audit lines,
    with the record's module + line number captured in ``details``.

    ``emit()`` swallows all exceptions -- a logging handler must never
    crash the code that called ``logger.info(...)``.
    """

    def __init__(self, category: str = "system"):
        super().__init__()
        self._category = category

    def emit(self, record: logging.LogRecord) -> None:
        try:
            audit(
                level=record.levelname,
                category=self._category,
                event=record.name,
                message=record.getMessage(),
                details={
                    "module": record.module,
                    "line": record.lineno,
                    "func": record.funcName,
                },
            )
        except Exception:  # pragma: no cover -- defensive
            pass


def get_audit_logger(name: str = "vulnforge",
                      category: str = "system") -> logging.Logger:
    """
    Return a standard :class:`logging.Logger` pre-wired with an
    :class:`AuditLogHandler` so vanilla ``logger.info(...)`` calls are
    mirrored into the structured JSONL audit trail.

    The handler is added exactly once per logger (idempotent).
    """
    log = logging.getLogger(name)
    # Avoid duplicate handlers if called twice.
    has = any(isinstance(h, AuditLogHandler) for h in log.handlers)
    if not has:
        log.addHandler(AuditLogHandler(category=category))
    return log


# ══════════════════════════════════════════════════════════════════
#  Test-only helpers (not part of the public API)
# ══════════════════════════════════════════════════════════════════

def _reset_state_for_tests() -> None:
    """Reset module config + initialised flag. Tests only -- not public."""
    global _log_path, _max_bytes, _generations, _min_level
    global _siem_min_level, _initialized
    with _lock:
        _log_path = _BACKEND_DIR / "logs" / "audit.jsonl"
        _max_bytes = 4 * 1024 * 1024
        _generations = 3
        _min_level = "INFO"
        _siem_min_level = "WARNING"
        _initialized = False


__all__ = [
    "AuditEvent",
    "AuditLogHandler",
    "CATEGORIES",
    "audit",
    "init_audit_log",
    "rotate_if_needed",
    "get_recent_logs",
    "get_log_stats",
    "get_audit_logger",
    "_level_to_siem_severity",
    "_reset_state_for_tests",
]