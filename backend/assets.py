"""
assets.py -- MIRV Module

Asset inventory per engagement (assessment). Hosts, domains, services and
endpoints discovered over time, deduplicated by ``(assessment_id, kind,
address)``, with open ports, tech stack, status, tags and a running
findings count. Auto-populated from findings via :func:`ingest_findings`
and merged manually through the REST API.

Persistence: best-effort, opt-in via ``MIRV_PERSIST_WORKSPACE=1``
(workspace_state key ``assets``). The in-memory registry stays
authoritative.
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from backend import workspace_store as _store
except ImportError:  # pragma: no cover
    _store = None  # type: ignore[assignment]

_logger = logging.getLogger("vulnforge.assets")

VALID_KINDS = frozenset({"host", "domain", "service", "endpoint", "other"})
VALID_STATUSES = frozenset({"active", "potential", "out-of-scope", "infrastructure", "compromised"})
VALID_SOURCES = frozenset({"manual", "tool"})

MAX_ASSETS = 2000
MAX_PORTS_PER_ASSET = 64
MAX_SERVICES_PER_ASSET = 32
MAX_TAGS = 20
MAX_NOTES_LENGTH = 4000

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PORTC = re.compile(r"^\d+$")


def _now_iso() -> str:
    """UTC ISO-8601 timestamp with Z suffix (stable, sortable)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_kind(kind: str) -> Optional[str]:
    if kind not in VALID_KINDS:
        return f"invalid kind '{kind}'. Allowed: {', '.join(sorted(VALID_KINDS))}"
    return None


def _validate_status(status: str) -> Optional[str]:
    if status not in VALID_STATUSES:
        return f"invalid status '{status}'. Allowed: {', '.join(sorted(VALID_STATUSES))}"
    return None


def _validate_status_opt(status: str) -> Optional[str]:
    """Raise-friendly variant returning an error message (used by update)."""
    return _validate_status(status)


@dataclass
class Asset:
    """A discovered asset belonging to an assessment (engagement)."""

    id: str
    assessment_id: str
    kind: str  # host | domain | service | endpoint | other
    address: str  # hostname/IP/domain/URL — dedup key component
    label: str = ""
    status: str = "active"
    ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    findings_count: int = 0
    source: str = "manual"  # manual | tool
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["port_count"] = len(self.ports)
        d["service_count"] = len(self.services)
        return d


# -- Module-level registry (thread-safe) -----------------------------------
_lock = threading.Lock()
_assets: Dict[str, Asset] = {}
_index: Dict[Tuple[str, str, str], str] = {}  # (assessment_id, kind, address) -> id


def _clean_address(address: str) -> str:
    if not address:
        return ""
    a = (address or "").strip()
    if not a:
        return ""
    if a.startswith("http://") or a.startswith("https://"):
        parsed = urlparse(a)
        host = parsed.hostname or ""
        return (host + (f":{parsed.port}" if parsed.port else "")).lower()
    return a.rstrip("/").lower()


def _classify_address(address: str) -> str:
    """Heuristic kind for a bare target: IPv4/IPv6 -> host, otherwise domain."""
    a = _clean_address(address)
    if not a:
        return "other"
    if _IPV4_RE.match(a) or ":" in a:
        return "host"
    return "domain"


def _key(assessment_id: str, kind: str, address: str) -> Tuple[str, str, str]:
    return (assessment_id, kind, address)


def _split_port_entry(port: Any) -> Optional[Dict[str, Any]]:
    """Normalize a port value (int or '443/tcp') into a port dict."""
    if port is None:
        return None
    s = str(port)
    if "/" in s:
        p, _, proto = s.partition("/")
    else:
        p, proto = s, "tcp"
    p = p.strip()
    if p and _PORTC.match(p):
        return {"port": int(p), "protocol": proto or "tcp", "service": "", "version": ""}
    return None


def create_asset(
    assessment_id: str,
    kind: str,
    address: str,
    label: str = "",
    status: str = "active",
    tags: Optional[List[str]] = None,
    notes: str = "",
    source: str = "manual",
    existed: bool = False,
) -> Asset:
    """Create (or merge into an existing) asset for an assessment.

    Dedup key is ``(assessment_id, kind, address)``. Merging preserves open
    ports/services and simply refreshes metadata + updated_at. Raises
    ValueError on invalid kind/status/address.
    """
    from backend import assessments as _assess

    assessment_id = (assessment_id or "").strip()
    address = _clean_address(address)
    if not assessment_id or not address:
        raise ValueError("assessment_id and address are required")
    if _assess.get_assessment(assessment_id) is None:
        raise ValueError(f"assessment '{assessment_id}' not found")
    if kind not in VALID_KINDS:
        err = _validate_kind(kind)
        raise ValueError(err)
    if status not in VALID_STATUSES:
        err = _validate_status(status)
        raise ValueError(err)
    if source not in VALID_SOURCES:
        source = "manual"

    with _lock:
        k = _key(assessment_id, kind, address)
        existing_id = _index.get(k)
        if existing_id:
            a = _assets.get(existing_id)
            if a:
                if label:
                    a.label = label
                a.status = status
                if tags is not None:
                    a.tags = _clean_tags(tags)
                a.notes = (notes or "").strip()[:MAX_NOTES_LENGTH]
                if source == "manual":
                    a.source = source
                a.updated_at = _now_iso()
                return a
        if len(_assets) >= MAX_ASSETS:
            raise ValueError(f"max {MAX_ASSETS} assets reached")
        a = Asset(
            id=uuid.uuid4().hex[:12],
            assessment_id=assessment_id,
            kind=kind,
            address=address,
            label=(label or "").strip()[:200],
            status=status,
            tags=_clean_tags(tags),
            notes=(notes or "").strip()[:MAX_NOTES_LENGTH],
            source=source,
        )
        _assets[a.id] = a
        _index[k] = a.id
    return a


def _clean_tags(tags: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for t in tags or []:
        t = (t or "").strip()
        if t and t not in out:
            out.append(t)
    return out[:MAX_TAGS]


def list_assets(
    assessment_id: Optional[str] = None,
    kind: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return assets, newest-first by updated_at."""
    with _lock:
        items = [a.to_dict() for a in _assets.values()]
    if assessment_id:
        items = [d for d in items if d["assessment_id"] == assessment_id]
    if kind:
        items = [d for d in items if d["kind"] == kind]
    if status:
        items = [d for d in items if d["status"] == status]
    items.sort(key=lambda d: d["updated_at"], reverse=True)
    return items


def get_asset(aid: str) -> Optional[Dict[str, Any]]:
    with _lock:
        a = _assets.get(aid)
        return a.to_dict() if a else None


def update_asset(
    aid: str,
    label: Optional[str] = None,
    status: Optional[str] = None,
    tags: Optional[List[str]] = None,
    notes: Optional[str] = None,
    kind: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Update an asset (whitelist). Returns updated dict, None if not found."""
    with _lock:
        a = _assets.get(aid)
        if not a:
            return None
        if label is not None:
            a.label = (label or "").strip()[:200]
        if status is not None:
            err = _validate_status_opt(status)
            if err:
                return None
            a.status = status
        if tags is not None:
            a.tags = _clean_tags(tags)
        if notes is not None:
            a.notes = (notes or "").strip()[:MAX_NOTES_LENGTH]
        if kind is not None:
            err = _validate_kind(kind)
            if err:
                return None
            old_key = _key(a.assessment_id, a.kind, a.address)
            _index.pop(old_key, None)
            a.kind = kind
            _index[_key(a.assessment_id, a.kind, a.address)] = a.id
        a.updated_at = _now_iso()
        result = a.to_dict()
    _persist()
    return result


def delete_asset(aid: str) -> bool:
    with _lock:
        a = _assets.pop(aid, None)
        if a:
            _index.pop(_key(a.assessment_id, a.kind, a.address), None)
    if a is not None:
        _persist()
    return a is not None


def _add_port_to_asset(a: Asset, port_entry: Dict[str, Any]) -> None:
    """Add a port dict, dedup by (port, protocol); cap at MAX_PORTS."""
    existing = {(p.get("port"), p.get("protocol")) for p in a.ports}
    pk = (port_entry["port"], port_entry.get("protocol") or "tcp")
    if pk in existing:
        for p in a.ports:
            if (p.get("port"), p.get("protocol")) == pk:
                if port_entry.get("service") and not p.get("service"):
                    p["service"] = port_entry["service"]
                if port_entry.get("version") and not p.get("version"):
                    p["version"] = port_entry["version"]
                break
        return
    if len(a.ports) < MAX_PORTS_PER_ASSET:
        a.ports.append(port_entry)


def _add_service_to_asset(a: Asset, service: str) -> None:
    s = (service or "").strip()
    if s and s not in a.services and len(a.services) < MAX_SERVICES_PER_ASSET:
        a.services.append(s)


def ingest_findings(
    assessment_id: str,
    findings: List[Dict[str, Any]],
    source: str = "tool",
) -> Dict[str, Any]:
    """Auto-populate the asset inventory from tool findings.

    * each distinct ``findings[i].target`` becomes a host/domain asset;
    * findings with a numeric ``port`` attach an open-port entry;
    * findings with a ``service``/``version`` enrich the tech stack;
    * findings with a ``path`` create/merge an endpoint asset.

    Returns ``{created, updated, skipped, ports, services, errors}``.
    """
    from backend import assessments as _assess

    assessment_id = (assessment_id or "").strip()
    if not assessment_id:
        raise ValueError("assessment_id is required")
    if _assess.get_assessment(assessment_id) is None:
        raise ValueError(f"assessment '{assessment_id}' not found")

    created = updated = skipped = ports_added = services_added = 0
    errors = 0

    for f in findings or []:
        if not isinstance(f, dict):
            errors += 1
            continue
        target = (f.get("target") or "").strip()
        if not target:
            skipped += 1
            continue
        kind = _classify_address(target)
        address = _clean_address(target)
        try:
            a = create_asset(
                assessment_id,
                kind,
                address,
                source=source,
                existed=True,
            )
        except (ValueError, Exception):  # keep ingest resilient per finding
            errors += 1
            continue
        if not a:
            errors += 1
            continue

        touched = False
        # Open port entries
        port = f.get("port")
        if port is not None and str(port) not in ("", "0"):
            entry = _split_port_entry(port)
            if entry:
                entry["service"] = f.get("service", "")
                entry["version"] = f.get("version", "")
                _add_port_to_asset(a, entry)
                ports_added += 1
                touched = True
        # Tech / service enrichment
        service = f.get("service") or ""
        version = f.get("version") or ""
        if service or version:
            if service:
                _add_service_to_asset(a, f"{service} {version}".strip() if version else service)
                services_added += 1
                touched = True
        # Endpoint assets for findings with a path (web vulns/dirs)
        path = (f.get("path") or "").strip()
        if path and path not in ("/", "/ "):
            try:
                ep = create_asset(
                    assessment_id,
                    "endpoint",
                    f"{address}{path}",
                    label="endpoint",
                    source=source,
                    existed=True,
                )
                if ep:
                    ep.findings_count += 1
                    ep.updated_at = _now_iso()
            except (ValueError, Exception):
                pass

        created += 1
        a.findings_count += 1
        a.updated_at = _now_iso()
        if touched:
            updated += 1

    with _lock:
        _assets_modded = created > 0 or updated > 0
    if _assets_modded:
        _persist()
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "ports": ports_added,
        "services": services_added,
        "errors": errors,
    }


def delete_assets_for_assessment(assessment_id: str) -> int:
    """Remove every asset bound to an assessment (used on assessment delete)."""
    with _lock:
        ids = [a.id for a in _assets.values() if a.assessment_id == assessment_id]
        for aid in ids:
            a = _assets.pop(aid, None)
            if a:
                _index.pop(_key(a.assessment_id, a.kind, a.address), None)
    if ids:
        _persist()
    return len(ids)


def reset_assets() -> None:
    """Clear the registry (used by tests)."""
    with _lock:
        _assets.clear()
        _index.clear()
    if _store and _store.is_enabled():
        _store.clear_cache("assets")


def summary(assessment_id: Optional[str] = None) -> Dict[str, Any]:
    """Aggregate counts (optionally scoped to one assessment)."""
    with _lock:
        items = [a for a in _assets.values()]
    if assessment_id:
        items = [a for a in items if a.assessment_id == assessment_id]
    by_kind: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    ports_total = services_total = 0
    for a in items:
        by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
        by_status[a.status] = by_status.get(a.status, 0) + 1
        ports_total += len(a.ports)
        services_total += len(a.services)
    return {
        "total": len(items),
        "by_kind": by_kind,
        "by_status": by_status,
        "ports_total": ports_total,
        "services_total": services_total,
    }


def export_state() -> List[Dict[str, Any]]:
    with _lock:
        out = [asdict(a) for a in _assets.values()]
    out.sort(key=lambda d: d["created_at"])
    return out


def import_state(rows: List[Dict[str, Any]], replace: bool = False) -> Dict[str, Any]:
    """Restore assets from JSON. ``replace=True`` clears first."""
    if not isinstance(rows, list):
        raise ValueError("debe ser una lista de assets")
    imported, skipped, rejected = 0, 0, 0
    with _lock:
        if replace:
            _assets.clear()
            _index.clear()
        for row in rows:
            if not isinstance(row, dict):
                rejected += 1
                continue
            assessment_id = (row.get("assessment_id") or "").strip()
            kind = row.get("kind") or ""
            address = _clean_address(row.get("address"))
            if not assessment_id or not address or _validate_kind(kind):
                skipped += 1
                continue
            status = row.get("status") or "active"
            if _validate_status(status):
                skipped += 1
                continue
            k = _key(assessment_id, kind, address)
            if k in _index and not replace:
                continue
            tgt = None
            for existing in _assets.values():
                if _key(existing.assessment_id, existing.kind, existing.address) == k:
                    tgt = existing
                    break
            if tgt is not None and not replace:
                continue
            aid = row.get("id") or uuid.uuid4().hex[:12]
            asset = Asset(
                id=aid,
                assessment_id=assessment_id,
                kind=kind,
                address=address,
                label=(row.get("label") or "")[:200],
                status=status,
                ports=[p for p in row.get("ports") or [] if isinstance(p, dict)][:MAX_PORTS_PER_ASSET],
                services=[s for s in row.get("services") or [] if isinstance(s, str)][:MAX_SERVICES_PER_ASSET],
                tags=_clean_tags(row.get("tags") or []),
                notes=(row.get("notes") or "")[:MAX_NOTES_LENGTH],
                findings_count=int(row.get("findings_count") or 0),
                source=row.get("source") if row.get("source") in VALID_SOURCES else "manual",
                created_at=row.get("created_at", _now_iso()),
                updated_at=row.get("updated_at", _now_iso()),
            )
            _assets[asset.id] = asset
            _index[k] = asset.id
            imported += 1
    if imported:
        _persist()
    return {
        "imported": imported,
        "skipped": skipped,
        "rejected": rejected,
        "total": len(_assets),
    }


def _persist() -> None:
    """Best-effort snapshot of the whole registry to Supabase."""
    if not _store or not _store.is_enabled():
        return
    try:
        with _lock:
            payload = [asdict(a) for a in _assets.values()]
        _store.upsert("assets", payload)
    except Exception as exc:  # pragma: no cover
        _logger.warning("assets persist failed: %s", exc)


def load_from_store() -> None:
    """Hydrate the in-memory registry from the persisted snapshot (startup)."""
    if not _store:
        return
    rows = _store.load("assets")
    if not rows:
        return
    with _lock:
        _assets.clear()
        _index.clear()
        for row in rows:
            try:
                kind = row.get("kind") or "other"
                address = _clean_address(row.get("address"))
                if not address or _validate_kind(kind):
                    continue
                a = Asset(
                    id=row["id"],
                    assessment_id=row["assessment_id"],
                    kind=kind,
                    address=address,
                    label=row.get("label", ""),
                    status=row.get("status", "active"),
                    ports=[p for p in row.get("ports") or [] if isinstance(p, dict)][:MAX_PORTS_PER_ASSET],
                    services=[s for s in row.get("services") or [] if isinstance(s, str)][:MAX_SERVICES_PER_ASSET],
                    tags=row.get("tags", []),
                    notes=row.get("notes", ""),
                    findings_count=int(row.get("findings_count") or 0),
                    source=row.get("source", "manual"),
                    created_at=row.get("created_at", _now_iso()),
                    updated_at=row.get("updated_at", _now_iso()),
                )
                _assets[a.id] = a
                _index[_key(a.assessment_id, a.kind, a.address)] = a.id
            except Exception as exc:  # pragma: no cover
                _logger.warning("assets load row failed: %s", exc)
    _logger.info("assets: loaded %d from store", len(_assets))