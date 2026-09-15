"""
scheduler.py -- MIRV Module

Scheduled scans — a lightweight in-app cron store that decides *when* a tool
group should run. The frontend polls ``GET /api/scheduler/due``; due jobs
are auto-advanced (last_run = now, next_run = now + interval) and returned so
the UI can launch the tool through the live WebSocket SSH session.

Design decisions:
  * Times are epoch seconds (float) — trivially comparable/diffable.
  * ``due_jobs()`` auto-advances jobs it returns, so any poll that sees a job
    is the one and only trigger for that cycle (even if the launch fails,
    the job simply waits for the next interval).
  * Pausing = ``enabled=False``; resuming keeps the original cadence.
  * ``record_run()`` stores the outcome (output summary, duration, finding
    count, error) that the frontend reports after launching the tool.
  * Built on stdlib + ``threading.Lock``; persistence is best-effort and
    opt-in via ``MIRV_PERSIST_WORKSPACE=1`` (``workspace_store``), with the
    in-memory registry always authoritative.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

try:
    from backend import workspace_store as _store
except ImportError:  # pragma: no cover
    _store = None  # type: ignore[assignment]

_logger = logging.getLogger("vulnforge.scheduler")

MIN_INTERVAL_SECONDS = 10  # small enough for tests, sane enough for prod
MAX_INTERVAL_SECONDS = 7 * 24 * 3600  # 7 days
MAX_JOBS = 100


def _now() -> float:
    return time.time()


@dataclass
class Job:
    """A scheduled tool run."""

    id: str
    name: str
    tool_id: str
    interval_seconds: int
    enabled: bool = True
    target: str = ""
    last_run: Optional[float] = None
    next_run: float = field(default_factory=_now)
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)
    run_count: int = 0
    last_result: str = ""
    last_duration: Optional[float] = None
    last_findings: int = 0
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["due"] = self.enabled and self.next_run <= _now()
        d["seconds_until_next"] = max(0, self.next_run - _now())
        return d


_lock = threading.Lock()
_jobs: Dict[str, Job] = {}


def _validate_interval(seconds: int) -> Optional[str]:
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        return "interval_seconds must be an integer"
    if seconds < MIN_INTERVAL_SECONDS or seconds > MAX_INTERVAL_SECONDS:
        return (
            f"interval_seconds out of range "
            f"[{MIN_INTERVAL_SECONDS}, {MAX_INTERVAL_SECONDS}]"
        )
    return None


def _clean_target(target: str) -> str:
    return (target or "").strip().rstrip("/")


def create_job(
    name: str,
    tool_id: str,
    interval_seconds: int,
    target: str = "",
    enabled: bool = True,
    start_offset_seconds: Optional[int] = None,
) -> Job:
    """Create a job. Raises ValueError on invalid input."""
    name = (name or "").strip()
    tool_id = (tool_id or "").strip()
    if not name:
        raise ValueError("job name is required")
    if not tool_id:
        raise ValueError("tool_id is required")
    err = _validate_interval(interval_seconds)
    if err:
        raise ValueError(err)
    with _lock:
        if len(_jobs) >= MAX_JOBS:
            raise ValueError(f"max {MAX_JOBS} jobs reached")
        now = _now()
        # When a campaign offset is given it overrides the first-run time
        # (offset 0 = fire on the next due poll). Without one, the job's
        # first run is one full interval after creation (historical default).
        if start_offset_seconds is None:
            first_run = now + interval_seconds
        else:
            first_run = now + max(0, int(start_offset_seconds))
        job = Job(
            id=uuid.uuid4().hex[:12],
            name=name,
            tool_id=tool_id,
            interval_seconds=interval_seconds,
            enabled=bool(enabled),
            target=_clean_target(target),
            next_run=first_run,
            created_at=now,
            updated_at=now,
        )
        _jobs[job.id] = job
    _persist()
    return job


def list_jobs() -> List[Dict[str, Any]]:
    with _lock:
        jobs = [_jobs[k].to_dict() for k in sorted(_jobs.keys())]
    return jobs


def get_job(jid: str) -> Optional[Dict[str, Any]]:
    with _lock:
        j = _jobs.get(jid)
        return j.to_dict() if j else None


def update_job(
    jid: str,
    name: Optional[str] = None,
    tool_id: Optional[str] = None,
    interval_seconds: Optional[int] = None,
    target: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    """Update fields. Returns updated dict or None if not found/invalid."""
    with _lock:
        j = _jobs.get(jid)
        if not j:
            return None
        if name is not None:
            n = (name or "").strip()
            if not n:
                return None
            j.name = n
        if tool_id is not None:
            t = (tool_id or "").strip()
            if not t:
                return None
            j.tool_id = t
        if interval_seconds is not None:
            err = _validate_interval(interval_seconds)
            if err:
                return None
            j.interval_seconds = interval_seconds
        if target is not None:
            j.target = _clean_target(target)
        if enabled is not None:
            j.enabled = bool(enabled)
        j.updated_at = _now()
        result = j.to_dict()
    _persist()
    return result


def delete_job(jid: str) -> bool:
    with _lock:
        deleted = _jobs.pop(jid, None) is not None
    if deleted:
        _persist()
    return deleted


def toggle_job(jid: str, enabled: bool) -> Optional[Dict[str, Any]]:
    """Enable/disable a job without resetting its schedule."""
    return update_job(jid, enabled=bool(enabled))


def advance_to_now(jid: str) -> Optional[Dict[str, Any]]:
    """Pull a job's next_run to 'now' so the next due_jobs() poll fires it.

    Returns the updated job dict, or None if the job doesn't exist or is
    disabled (disabled jobs are never run, even via "run now").
    """
    with _lock:
        j = _jobs.get(jid)
        if not j or not j.enabled:
            return None
        j.next_run = _now()
        j.updated_at = _now()
        result = j.to_dict()
    _persist()
    return result


def due_jobs(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Return enabled jobs whose time has come, auto-advancing each one.

    Each returned job gets ``last_run = now`` and ``next_run = now +
    interval_seconds`` so a poll is the single trigger for its cycle.
    """
    ref = now if now is not None else _now()
    out: List[Dict[str, Any]] = []
    with _lock:
        for j in _jobs.values():
            if not j.enabled or j.next_run > ref:
                continue
            j.last_run = ref
            j.next_run = ref + j.interval_seconds
            j.updated_at = ref
            out.append(j.to_dict())
    if out:
        _persist()
    return out


def reset_jobs() -> None:
    """Clear the registry (used by tests)."""
    with _lock:
        _jobs.clear()
    if _store and _store.is_enabled():
        _store.clear_cache("scheduler_jobs")


def _persist() -> None:
    """Best-effort snapshot of the whole registry to Supabase."""
    if not _store or not _store.is_enabled():
        return
    try:
        with _lock:
            payload = [_jobs[k].to_dict() for k in _jobs.keys()]
        _store.upsert("scheduler_jobs", payload)
    except Exception as exc:  # pragma: no cover
        _logger.warning("scheduler persist failed: %s", exc)


def load_from_store() -> None:
    """Hydrate the in-memory registry from the persisted snapshot (startup)."""
    if not _store:
        return
    rows = _store.load("scheduler_jobs")
    if not rows:
        return
    with _lock:
        _jobs.clear()
        now = _now()
        for row in rows:
            try:
                j = Job(
                    id=row["id"],
                    name=row["name"],
                    tool_id=row["tool_id"],
                    interval_seconds=int(row["interval_seconds"]),
                    enabled=bool(row.get("enabled", True)),
                    target=row.get("target", ""),
                    last_run=row.get("last_run"),
                    next_run=float(row.get("next_run", now)),
                    created_at=float(row.get("created_at", now)),
                    updated_at=float(row.get("updated_at", now)),
                    run_count=int(row.get("run_count", 0)),
                    last_result=row.get("last_result", ""),
                    last_duration=row.get("last_duration"),
                    last_findings=int(row.get("last_findings", 0)),
                    last_error=row.get("last_error", ""),
                )
                if j.enabled and j.next_run <= now:
                    j.next_run = now + j.interval_seconds
                _jobs[j.id] = j
            except Exception as exc:  # pragma: no cover
                _logger.warning("scheduler load row failed: %s", exc)
    _logger.info("scheduler: loaded %d jobs from store", len(_jobs))


def record_run(
    jid: str,
    result: str = "",
    findings: int = 0,
    duration: Optional[float] = None,
    error: str = "",
) -> Optional[Dict[str, Any]]:
    """Store the outcome of a scheduled run (frontend reports it back)."""
    with _lock:
        j = _jobs.get(jid)
        if not j:
            return None
        j.run_count += 1
        j.last_result = (result or "")[:4000]
        j.last_findings = findings if findings is not None else 0
        if duration is not None:
            j.last_duration = round(duration, 2)
        j.last_error = (error or "")[:2000]
        j.updated_at = _now()
        result_dict = j.to_dict()
    _persist()
    return result_dict


def export_state() -> List[Dict[str, Any]]:
    """Full serializable state (without computed due/seconds_until_next)."""
    with _lock:
        out = []
        for k in sorted(_jobs.keys()):
            d = asdict(_jobs[k])
            d.pop("due", None)
            d.pop("seconds_until_next", None)
            out.append(d)
    return out


def import_state(
    rows: List[Dict[str, Any]],
    replace: bool = False,
) -> Dict[str, Any]:
    """Restore jobs from JSON. ``replace=True`` clears first.

    Validates every row (id/name/tool_id, interval range) and skips invalid
    ones. Returns a summary dict.
    """
    if not isinstance(rows, list):
        raise ValueError("debe ser una lista de jobs")
    imported, skipped, rejected = 0, 0, 0
    with _lock:
        if replace:
            _jobs.clear()
        for row in rows:
            if not isinstance(row, dict):
                rejected += 1
                continue
            name = (row.get("name") or "").strip()
            tool_id = (row.get("tool_id") or "").strip()
            interval = row.get("interval_seconds")
            if not name or not tool_id or _validate_interval(interval):
                skipped += 1
                continue
            jid = row.get("id") or uuid.uuid4().hex[:12]
            if jid in _jobs and not replace:
                continue
            now = _now()
            _jobs[jid] = Job(
                id=jid,
                name=name,
                tool_id=tool_id,
                interval_seconds=interval,
                enabled=bool(row.get("enabled", True)),
                target=row.get("target", ""),
                last_run=row.get("last_run"),
                next_run=row.get("next_run", now),
                created_at=row.get("created_at", now),
                updated_at=row.get("updated_at", now),
                run_count=int(row.get("run_count", 0)),
                last_result=row.get("last_result", ""),
                last_duration=row.get("last_duration"),
                last_findings=int(row.get("last_findings", 0)),
                last_error=row.get("last_error", ""),
            )
            imported += 1
    if imported:
        _persist()
    return {
        "imported": imported,
        "skipped": skipped,
        "rejected": rejected,
        "total": len(_jobs),
    }


def summary() -> Dict[str, Any]:
    with _lock:
        enabled = sum(1 for j in _jobs.values() if j.enabled)
        due_now = sum(1 for j in _jobs.values() if j.enabled and j.next_run <= _now())
        return {"total": len(_jobs), "enabled": enabled, "due_now": due_now}