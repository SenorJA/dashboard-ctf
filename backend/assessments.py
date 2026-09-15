"""
assessments.py -- MIRV Module

Workspace / Assessments — organize targets into named assessments with
status, notes, and tags. Keeps an in-memory registry (thread-safe) plus a
human-readable summary per assessment.

Persistence: best-effort, opt-in via ``MIRV_PERSIST_WORKSPACE=1``.
When enabled, each mutation snapshots the whole registry as JSON to the
``workspace_state`` Supabase table so it survives backend restarts.
The in-memory registry always stays authoritative.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from backend import workspace_store as _store
except ImportError:  # pragma: no cover
    _store = None  # type: ignore[assignment]

_logger = logging.getLogger("vulnforge.assessments")

VALID_STATUSES = frozenset({"planning", "in-scope", "in-progress", "done", "archived"})

MAX_ASSESSMENTS = 200
MAX_TARGETS_PER_ASSESSMENT = 100
MAX_NOTES_LENGTH = 4000


def _now_iso() -> str:
    """UTC ISO-8601 timestamp with Z suffix (stable, sortable)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Assessment:
    """A named workspace grouping multiple targets together."""

    id: str
    name: str
    description: str = ""
    status: str = "planning"
    targets: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["target_count"] = len(self.targets)
        return d


# -- Module-level registry (thread-safe) -----------------------------------
_lock = threading.Lock()
_assessments: Dict[str, Assessment] = {}


def _validate_status(status: str) -> Optional[str]:
    if status not in VALID_STATUSES:
        return f"invalid status '{status}'. Allowed: {', '.join(sorted(VALID_STATUSES))}"
    return None


def create_assessment(
    name: str,
    description: str = "",
    status: str = "planning",
    targets: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    notes: str = "",
) -> Assessment:
    """Create a new assessment. Returns the created object.

    Raises ValueError on invalid status or empty name.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("assessment name is required")
    err = _validate_status(status)
    if err:
        raise ValueError(err)
    with _lock:
        if len(_assessments) >= MAX_ASSESSMENTS:
            raise ValueError(f"max {MAX_ASSESSMENTS} assessments reached")
        a = Assessment(
            id=uuid.uuid4().hex[:12],
            name=name,
            description=(description or "").strip(),
            status=status,
            targets=_clean_targets(targets)[:MAX_TARGETS_PER_ASSESSMENT],
            tags=_clean_tags(tags),
            notes=(notes or "").strip()[:MAX_NOTES_LENGTH],
        )
        _assessments[a.id] = a
    _persist()
    return a


def _clean_targets(targets: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for t in targets or []:
        t = (t or "").strip().rstrip("/")
        if t and t not in out and len(out) < MAX_TARGETS_PER_ASSESSMENT:
            out.append(t)
    return out


def _clean_tags(tags: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for t in tags or []:
        t = (t or "").strip()
        if t and t not in out:
            out.append(t)
    return out[:20]


def list_assessments() -> List[Dict[str, Any]]:
    """Return all assessments, newest first, with target_count."""
    with _lock:
        items = [a.to_dict() for a in _assessments.values()]
    items.sort(key=lambda d: d["updated_at"], reverse=True)
    return items


def get_assessment(aid: str) -> Optional[Dict[str, Any]]:
    with _lock:
        a = _assessments.get(aid)
        return a.to_dict() if a else None


def update_assessment(
    aid: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    targets: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    notes: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Update an assessment. Returns updated dict, None if not found."""
    with _lock:
        a = _assessments.get(aid)
        if not a:
            return None
        if name is not None:
            name = (name or "").strip()
            if not name:
                return None
            a.name = name
        if description is not None:
            a.description = (description or "").strip()
        if status is not None:
            err = _validate_status(status)
            if err:
                return None
            a.status = status
        if targets is not None:
            a.targets = _clean_targets(targets)
        if tags is not None:
            a.tags = _clean_tags(tags)
        if notes is not None:
            a.notes = (notes or "").strip()[:MAX_NOTES_LENGTH]
        a.updated_at = _now_iso()
        result = a.to_dict()
    _persist()
    return result


def delete_assessment(aid: str) -> bool:
    with _lock:
        deleted = _assessments.pop(aid, None) is not None
    if deleted:
        _persist()
    return deleted


def add_target(aid: str, target: str) -> Optional[Dict[str, Any]]:
    """Add (or reorder-dedupe) a target. Returns updated dict or None."""
    updated = None
    with _lock:
        a = _assessments.get(aid)
        if not a:
            return None
        t = (target or "").strip().rstrip("/")
        if not t:
            return None
        if t in a.targets:
            a.updated_at = _now_iso()
            updated = a.to_dict()
        elif len(a.targets) >= MAX_TARGETS_PER_ASSESSMENT:
            return None
        else:
            a.targets.append(t)
            a.updated_at = _now_iso()
            updated = a.to_dict()
    _persist()
    return updated


def remove_target(aid: str, target: str) -> Optional[Dict[str, Any]]:
    with _lock:
        a = _assessments.get(aid)
        if not a:
            return None
        t = (target or "").strip().rstrip("/")
        a.targets = [x for x in a.targets if x != t]
        a.updated_at = _now_iso()
        result = a.to_dict()
    _persist()
    return result


def assessments_by_target(target: str) -> List[Dict[str, Any]]:
    """Return every assessment containing a given target (dedup form)."""
    t = (target or "").strip().rstrip("/")
    if not t:
        return []
    with _lock:
        items = [a.to_dict() for a in _assessments.values() if t in a.targets]
    items.sort(key=lambda d: d["updated_at"], reverse=True)
    return items


def reset_assessments() -> None:
    """Clear the registry (used by tests)."""
    with _lock:
        _assessments.clear()
    if _store and _store.is_enabled():
        _store.clear_cache("assessments")


def _persist() -> None:
    """Best-effort snapshot of the whole registry to Supabase."""
    if not _store or not _store.is_enabled():
        return
    try:
        with _lock:
            payload = [a.to_dict() for a in _assessments.values()]
        _store.upsert("assessments", payload)
    except Exception as exc:  # pragma: no cover
        _logger.warning("assessments persist failed: %s", exc)


def load_from_store() -> None:
    """Hydrate the in-memory registry from the persisted snapshot (startup)."""
    if not _store:
        return
    rows = _store.load("assessments")
    if not rows:
        return
    with _lock:
        _assessments.clear()
        for row in rows:
            try:
                a = Assessment(
                    id=row["id"],
                    name=row["name"],
                    description=row.get("description", ""),
                    status=row.get("status", "planning"),
                    targets=row.get("targets", []),
                    tags=row.get("tags", []),
                    notes=row.get("notes", ""),
                    created_at=row.get("created_at", _now_iso()),
                    updated_at=row.get("updated_at", _now_iso()),
                )
                _assessments[a.id] = a
            except Exception as exc:  # pragma: no cover
                _logger.warning("assessments load row failed: %s", exc)
    _logger.info("assessments: loaded %d from store", len(_assessments))


def summary() -> Dict[str, Any]:
    """Aggregate counts useful for a dashboard card."""
    with _lock:
        total = len(_assessments)
        by_status: Dict[str, int] = {}
        target_set: set = set()
        for a in _assessments.values():
            by_status[a.status] = by_status.get(a.status, 0) + 1
            target_set.update(a.targets)
        return {
            "total": total,
            "by_status": by_status,
            "unique_targets": len(target_set),
        }


def export_state() -> List[Dict[str, Any]]:
    """Full serializable state (without derived target_count)."""
    with _lock:
        out = []
        for a in _assessments.values():
            d = asdict(a)
            d.pop("target_count", None)
            out.append(d)
    out.sort(key=lambda d: d["created_at"])
    return out


def import_state(
    rows: List[Dict[str, Any]],
    replace: bool = False,
) -> Dict[str, Any]:
    """Restore assessments from JSON. ``replace=True`` clears first.

    Validates every row (id/name/status, targets/tags lists, bounds) and
    skips invalid ones. Returns a summary dict.
    """
    if not isinstance(rows, list):
        raise ValueError("debe ser una lista de assessments")
    imported, skipped, rejected = 0, 0, 0
    with _lock:
        if replace:
            _assessments.clear()
        for row in rows:
            if not isinstance(row, dict):
                rejected += 1
                continue
            name = (row.get("name") or "").strip()
            status = row.get("status") or "planning"
            if not name or _validate_status(status):
                skipped += 1
                continue
            aid = (row.get("id") or uuid.uuid4().hex[:12])
            if aid in _assessments and not replace:
                continue
            _assessments[aid] = Assessment(
                id=aid,
                name=name,
                description=row.get("description", ""),
                status=status,
                targets=_clean_targets(row.get("targets") or [])[:MAX_TARGETS_PER_ASSESSMENT],
                tags=_clean_tags(row.get("tags") or []),
                notes=(row.get("notes") or "")[:MAX_NOTES_LENGTH],
                created_at=row.get("created_at", _now_iso()),
                updated_at=row.get("updated_at", _now_iso()),
            )
            imported += 1
    if imported:
        _persist()
    return {
        "imported": imported,
        "skipped": skipped,
        "rejected": rejected,
        "total": len(_assessments),
    }