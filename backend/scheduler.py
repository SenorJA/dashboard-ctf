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
  * Pure stdlib + ``threading.Lock``; registry is in-memory (tests reset it).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

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
        job = Job(
            id=uuid.uuid4().hex[:12],
            name=name,
            tool_id=tool_id,
            interval_seconds=interval_seconds,
            enabled=bool(enabled),
            target=_clean_target(target),
            next_run=now + interval_seconds,
            created_at=now,
            updated_at=now,
        )
        _jobs[job.id] = job
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
        return j.to_dict()


def delete_job(jid: str) -> bool:
    with _lock:
        return _jobs.pop(jid, None) is not None


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
        return j.to_dict()


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
    return out


def reset_jobs() -> None:
    """Clear the registry (used by tests)."""
    with _lock:
        _jobs.clear()


def summary() -> Dict[str, Any]:
    with _lock:
        enabled = sum(1 for j in _jobs.values() if j.enabled)
        due_now = sum(1 for j in _jobs.values() if j.enabled and j.next_run <= _now())
        return {"total": len(_jobs), "enabled": enabled, "due_now": due_now}