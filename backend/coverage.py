"""
M.I.R.V. — Coverage Tracking Module
====================================

Inspired by PentesterFlow's coverage matrix: tracks a 3-dimensional grid of
``(endpoint, param, vuln_class)`` with a discrete ``status`` so an operator
can answer "what have I tested, what failed, and what is still missing?".

The state lives in-memory at module level (process-scoped). A thin API in
``main.py`` exposes it over REST and feeds ``/api/suggest`` + Op Admiral
with prioritized "next steps".

Design tenets
-------------
* **No secrets**: never stores IPs, passwords or tokens — only structural
  metadata about tested attack surfaces.
* **Thread-safe**: a single ``threading.Lock`` guards the in-memory maps so
  the FastAPI worker pool can mutate entries concurrently without races.
* **Deterministic dedupe**: the tuple ``(endpoint, param, vuln_class)``
  uniquely identifies a coverage row; re-marking updates the status and
  bumps ``count``/``last_seen`` instead of creating duplicates.
* **Never crash**: every public function catches its own validation errors
  and returns a structured ``{"ok": False, "error": ...}`` dict — callers
  can forward it straight to JSON responses.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

# ────────────────────────────────────────────────────────────────────
#  Constants — controlled vocabularies enforced on every write
# ────────────────────────────────────────────────────────────────────

ALLOWED_VULN_CLASSES: list[str] = [
    "idor", "ssrf", "ssti", "sqli", "xss", "jwt", "auth", "race",
    "takeover", "graphql", "deserialize", "rce", "lfi", "rfi",
    "open-redirect", "csrf", "business-logic", "info", "other",
]

ALLOWED_STATUSES: list[str] = [
    "tried", "passed", "failed", "waf-blocked", "skipped",
]

ALLOWED_METHODS: tuple[str, ...] = (
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
)

# Human-readable titles for markdown/CSV exports + frontend selects
VULN_CLASS_LABELS: dict[str, str] = {
    "idor": "IDOR",
    "ssrf": "SSRF",
    "ssti": "SSTI",
    "sqli": "SQLi",
    "xss": "XSS",
    "jwt": "JWT",
    "auth": "Auth",
    "race": "Race Condition",
    "takeover": "Subdomain Takeover",
    "graphql": "GraphQL",
    "deserialize": "Deserialization",
    "rce": "RCE",
    "lfi": "LFI",
    "rfi": "RFI",
    "open-redirect": "Open Redirect",
    "csrf": "CSRF",
    "business-logic": "Business Logic",
    "info": "Information Disclosure",
    "other": "Other",
}

STATUS_LABELS: dict[str, str] = {
    "tried": "Tried",
    "passed": "Passed",
    "failed": "Failed",
    "waf-blocked": "WAF-Blocked",
    "skipped": "Skipped",
}

# Severity mapping used by ``report_to_mirv_findings`` (see spec)
STATUS_SEVERITY: dict[str, str] = {
    "failed": "high",
    "waf-blocked": "medium",
    "tried": "low",
    "passed": "info",
    "skipped": "info",
}


logger = logging.getLogger("vulnforge.coverage")

# ────────────────────────────────────────────────────────────────────
#  Data model
# ────────────────────────────────────────────────────────────────────


@dataclass
class CoverageEntry:
    """A single (endpoint, param, vuln_class, status) observation row."""

    id: str
    endpoint: str
    method: str
    path: str
    param: Optional[str]
    vuln_class: str
    status: str
    notes: str = ""
    first_seen: str = ""
    last_seen: str = ""
    count: int = 1
    session_id: str = "default"


# ────────────────────────────────────────────────────────────────────
#  In-process store (modules are singletons → safe to keep maps here)
# ────────────────────────────────────────────────────────────────────

_entries: dict[str, CoverageEntry] = {}
_sessions: dict[str, dict] = {}
_lock = threading.Lock()


# ────────────────────────────────────────────────────────────────────
#  Internal helpers
# ────────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    """Timezone-aware ISO timestamp (UTC)."""
    return datetime.now(timezone.utc).isoformat()


def _normalize_method(method: str) -> str:
    return (method or "GET").strip().upper()


def _normalize_path(path: str) -> tuple[str, str]:
    """Strip the query-string and lowercase the bare path.

    Returns ``(normalized_path, normalized_endpoint)`` where ``endpoint``
    is the canonical ``"METHOD /path"`` form used for deduplication.
    """
    raw = (path or "").strip()
    # Cut query string / fragment
    for sep in ("#", "?"):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    # Collapse trailing slashes (but keep root "/")
    if len(raw) > 1:
        raw = raw.rstrip("/")
    normalized = raw.lower() or "/"
    return normalized, normalized


def _build_endpoint(method: str, path: str) -> str:
    """Compose the canonical endpoint string ``"METHOD /path"``."""
    m = _normalize_method(method)
    _, norm_path = _normalize_path(path)
    return f"{m} {norm_path}"


def _entry_key(endpoint: str, param: Optional[str], vuln_class: str) -> str:
    """Tuple-encoded dedup key (param None → literal "" to stay hashable)."""
    p = (param or "").strip().lower()
    return f"{endpoint.strip().lower()}|{p}|{vuln_class.strip().lower()}"


def _to_dict(entry: CoverageEntry) -> dict[str, Any]:
    return asdict(entry)


def _validate_vuln_class(value: str) -> Optional[str]:
    v = (value or "").strip().lower()
    return v if v in ALLOWED_VULN_CLASSES else None


def _validate_status(value: str) -> Optional[str]:
    v = (value or "").strip().lower()
    return v if v in ALLOWED_STATUSES else None


# ────────────────────────────────────────────────────────────────────
#  Public API
# ────────────────────────────────────────────────────────────────────


def mark_coverage(
    endpoint: str,
    method: str,
    path: str,
    param: Optional[str],
    vuln_class: str,
    status: str,
    notes: str = "",
    session_id: str = "default",
) -> dict[str, Any]:
    """Insert or update a coverage row.

    Validation is intentional and explicit so an invalid request from the
    frontend can never corrupt the matrix. Returns ``{"ok": True, "entry":
    {...}}`` on success or ``{"ok": False, "error": ...}`` on bad input.
    """
    vc = _validate_vuln_class(vuln_class)
    if vc is None:
        return {"ok": False, "error": f"Invalid vuln_class '{vuln_class}'. Allowed: {ALLOWED_VULN_CLASSES}"}

    st = _validate_status(status)
    if st is None:
        return {"ok": False, "error": f"Invalid status '{status}'. Allowed: {ALLOWED_STATUSES}"}

    method = _normalize_method(method)
    norm_path, _ = _normalize_path(path)

    # Build canonical endpoint string: "METHOD /path" (path lowercased,
    # method uppercased). If the caller passed an endpoint already
    # containing a method prefix in any case ("GET /x" or "get /x") we
    # respect that method and normalise the path part.
    ep_input = (endpoint or "").strip()
    if ep_input:
        parts = ep_input.split(" ", 1)
        if len(parts) == 2 and parts[0].upper() in ALLOWED_METHODS:
            ep_method = parts[0].upper()
            ep_path_raw = parts[1] or "/"
        else:
            ep_method = method
            ep_path_raw = ep_input
        ep_path_norm, _ = _normalize_path(ep_path_raw)
        canonical_endpoint = f"{ep_method} {ep_path_norm}".strip()
        method = ep_method
    else:
        canonical_endpoint = f"{method} {norm_path}".strip()

    clean_param: Optional[str] = (param or "").strip().lower() if (param or "").strip() else None
    key = _entry_key(canonical_endpoint, clean_param, vc)

    now = _now_iso()
    with _lock:
        existing = _entries.get(key)
        if existing:
            existing.status = st
            existing.method = method
            existing.path = norm_path
            existing.notes = notes if notes else existing.notes
            existing.last_seen = now
            existing.count += 1
            if session_id and session_id != "default":
                existing.session_id = session_id
            return {"ok": True, "entry": _to_dict(existing), "created": False}

        entry = CoverageEntry(
            id=str(uuid.uuid4()),
            endpoint=canonical_endpoint,
            method=method,
            path=norm_path,
            param=clean_param,
            vuln_class=vc,
            status=st,
            notes=notes or "",
            first_seen=now,
            last_seen=now,
            count=1,
            session_id=session_id or "default",
        )
        _entries[key] = entry
        return {"ok": True, "entry": _to_dict(entry), "created": True}


def list_coverage(
    session_id: Optional[str] = None,
    status: Optional[str] = None,
    vuln_class: Optional[str] = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return filtered coverage rows as plain dicts (newest first)."""
    if limit is None or limit < 1:
        limit = 200
    if limit > 5000:
        limit = 5000
    wanted_status = _validate_status(status) if status else None
    wanted_vc = _validate_vuln_class(vuln_class) if vuln_class else None

    out: list[dict[str, Any]] = []
    with _lock:
        for entry in _entries.values():
            if session_id and entry.session_id != session_id:
                continue
            if wanted_status and entry.status != wanted_status:
                continue
            if wanted_vc and entry.vuln_class != wanted_vc:
                continue
            out.append(_to_dict(entry))
    out.sort(key=lambda d: d.get("last_seen", ""), reverse=True)
    return out[:limit]


def coverage_summary(session_id: Optional[str] = None) -> dict[str, Any]:
    """Roll up totals + breakdowns for the requested session (or all)."""
    total = 0
    by_status: dict[str, int] = {s: 0 for s in ALLOWED_STATUSES}
    by_vuln: dict[str, int] = {v: 0 for v in ALLOWED_VULN_CLASSES}
    endpoints_seen: set[str] = set()
    tested_passed = 0
    tested_failed = 0
    tested_total = 0  # passed + failed (the ones with a binary verdict)

    with _lock:
        for entry in _entries.values():
            if session_id and entry.session_id != session_id:
                continue
            total += 1
            by_status[entry.status] = by_status.get(entry.status, 0) + 1
            by_vuln[entry.vuln_class] = by_vuln.get(entry.vuln_class, 0) + 1
            endpoints_seen.add(entry.endpoint)
            if entry.status == "passed":
                tested_passed += 1
                tested_total += 1
            elif entry.status == "failed":
                tested_failed += 1
                tested_total += 1

    pass_ratio = (tested_passed / tested_total) if tested_total else 0.0
    return {
        "total": total,
        "by_status": by_status,
        "by_vuln_class": by_vuln,
        "unique_endpoints": len(endpoints_seen),
        "passed": tested_passed,
        "failed": tested_failed,
        "pass_ratio": round(pass_ratio, 4),
        "session_id": session_id,
    }


def untested_endpoints(
    session_id: Optional[str] = None,
    candidates: Optional[list[dict]] = None,
) -> list[dict[str, Any]]:
    """Cross-reference known endpoints × vuln classes to find gaps.

    * If ``candidates`` is provided, each item must carry ``endpoint``
      (and optionally ``method``, ``path``, ``param``); we keep only the
      combos ``(endpoint, param, vuln_class)`` that are NOT already marked.
    * If ``candidates`` is empty/None, we auto-sweep: harvest every unique
      endpoint already in the matrix and enumerate ALL allowed vuln
      classes for it, returning the missing ones.
    """
    # Snapshot existing keys for the relevant session
    existing_keys: set[str] = set()
    known_endpoints: set[str] = set()

    with _lock:
        for entry in _entries.values():
            if session_id and entry.session_id != session_id:
                continue
            existing_keys.add(_entry_key(entry.endpoint, entry.param, entry.vuln_class))
            known_endpoints.add(entry.endpoint)

    results: list[dict[str, Any]] = []

    if candidates:
        for cand in candidates:
            if not isinstance(cand, dict) or not cand.get("endpoint"):
                continue
            c_method = _normalize_method(cand.get("method", "GET"))
            c_path = (cand.get("path") or "").strip().split("?")[0].split("#")[0].lower()
            c_endpoint = cand["endpoint"].strip()
            if not c_endpoint.startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ")):
                c_endpoint = f"{c_method} {c_endpoint}".strip()
            c_param = (cand.get("param") or "").strip().lower() or None
            for vc in ALLOWED_VULN_CLASSES:
                key = _entry_key(c_endpoint, c_param, vc)
                if key not in existing_keys:
                    results.append({
                        "endpoint": c_endpoint,
                        "method": c_method,
                        "path": c_path,
                        "param": c_param,
                        "vuln_class": vc,
                        "vuln_class_label": VULN_CLASS_LABELS.get(vc, vc),
                        "reason": "candidate_not_marked",
                    })
    else:
        for ep in sorted(known_endpoints):
            method = ep.split(" ", 1)[0] if " " in ep else "GET"
            path = ep.split(" ", 1)[1] if " " in ep else ep
            for vc in ALLOWED_VULN_CLASSES:
                # Sweep with param=None only — sweep per-param would explode
                key = _entry_key(ep, None, vc)
                if key not in existing_keys:
                    results.append({
                        "endpoint": ep,
                        "method": method,
                        "path": path,
                        "param": None,
                        "vuln_class": vc,
                        "vuln_class_label": VULN_CLASS_LABELS.get(vc, vc),
                        "reason": "auto_sweep",
                    })

    return results


def next_steps(session_id: Optional[str] = None, limit: int = 10) -> list[dict[str, Any]]:
    """Rank the most valuable next tests: failed > untested > waf-blocked.

    Each suggestion carries a ``reason`` so the UI can color-code it and
    so ``/api/suggest`` can hand the LLM structured context.
    """
    if limit is None or limit < 1:
        limit = 10
    if limit > 200:
        limit = 200

    failed_rows: list[dict[str, Any]] = []
    waf_rows: list[dict[str, Any]] = []

    with _lock:
        for entry in _entries.values():
            if session_id and entry.session_id != session_id:
                continue
            row = {
                "endpoint": entry.endpoint,
                "method": entry.method,
                "path": entry.path,
                "param": entry.param,
                "vuln_class": entry.vuln_class,
                "vuln_class_label": VULN_CLASS_LABELS.get(entry.vuln_class, entry.vuln_class),
                "status": entry.status,
                "last_seen": entry.last_seen,
                "count": entry.count,
                "notes": entry.notes,
            }
            if entry.status == "failed":
                row["reason"] = "previously_failed_retry_with_variant"
                failed_rows.append(row)
            elif entry.status == "waf-blocked":
                row["reason"] = "waf_blocked_try_evasion"
                waf_rows.append(row)

    # Cap the untested sweep so we don't dominate the suggestions
    untested_rows = untested_endpoints(session_id=session_id)[: max(limit * 3, 30)]
    # Untested rows have no real "status" yet — tag them so the frontend
    # and any callers iterating `s["status"]` don't blow up with KeyError.
    for r in untested_rows:
        r["status"] = "untested"
        r["count"] = 0

    ranked: list[dict[str, Any]] = []
    ranked.extend(sorted(failed_rows, key=lambda r: r.get("last_seen", ""), reverse=True))
    ranked.extend(untested_rows)
    ranked.extend(sorted(waf_rows, key=lambda r: r.get("last_seen", ""), reverse=True))

    # Dedupe by (endpoint, param, vuln_class) keeping first occurrence
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for r in ranked:
        key = _entry_key(r["endpoint"], r.get("param"), r["vuln_class"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    return deduped[:limit]


def clear_coverage(session_id: Optional[str] = None) -> dict[str, Any]:
    """Wipe all entries (or just one session). Returns the removed count."""
    with _lock:
        if not session_id:
            removed = len(_entries)
            _entries.clear()
            if not _sessions.get(session_id):
                pass
            return {"ok": True, "removed": removed, "scope": "all"}
        keys_to_drop = [k for k, e in _entries.items() if e.session_id == session_id]
        for k in keys_to_drop:
            del _entries[k]
        # Also drop the session metadata entry
        if session_id in _sessions:
            del _sessions[session_id]
        return {"ok": True, "removed": len(keys_to_drop), "scope": "session"}


def save_session(session_id: str, name: Optional[str] = None) -> dict[str, Any]:
    """Persist metadata for a session (name + entry count + timestamp)."""
    if not session_id or not session_id.strip():
        return {"ok": False, "error": "session_id is required"}
    with _lock:
        existing = _sessions.get(session_id)
        created_at = existing.get("created_at") if existing else _now_iso()
        entry_count = sum(1 for e in _entries.values() if e.session_id == session_id)
        _sessions[session_id] = {
            "session_id": session_id,
            "name": name or existing.get("name") if existing else name or session_id,
            "created_at": created_at,
            "updated_at": _now_iso(),
            "entry_count": entry_count,
        }
        return {"ok": True, "session": dict(_sessions[session_id])}


def list_sessions() -> list[dict[str, Any]]:
    with _lock:
        return [dict(s) for s in _sessions.values()]


def export_coverage(
    session_id: Optional[str] = None,
    format: str = "json",
) -> str:
    """Serialise the matrix as ``json`` | ``csv`` | markdown (``md``)."""
    rows = list_coverage(session_id=session_id, limit=5000)
    fmt = (format or "json").strip().lower()

    if fmt == "json":
        return json.dumps({"ok": True, "session_id": session_id, "count": len(rows), "entries": rows}, indent=2, default=str)

    if fmt in ("csv",):
        buf = io.StringIO()
        fieldnames = [
            "id", "endpoint", "method", "path", "param", "vuln_class",
            "status", "first_seen", "last_seen", "count", "session_id", "notes",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
        return buf.getvalue()

    if fmt in ("md", "markdown"):
        if not rows:
            return "## Coverage Matrix\n\n_No entries._\n"
        out_lines = [
            "## Coverage Matrix",
            "",
            f"_Total: {len(rows)} entries_",
            "",
            "| Endpoint | Method | Param | Vuln Class | Status | Count | Last Seen | Notes |",
            "|----------|--------|-------|------------|--------|-------|-----------|-------|",
        ]
        for r in rows:
            notes = (r.get("notes") or "").replace("|", "\\|").replace("\n", " ").strip()
            if len(notes) > 80:
                notes = notes[:77] + "..."
            out_lines.append(
                "| {ep} | {m} | {p} | {vc} | {st} | {c} | {ls} | {n} |".format(
                    ep=r.get("endpoint", ""),
                    m=r.get("method", ""),
                    p=r.get("param") or "-",
                    vc=VULN_CLASS_LABELS.get(r.get("vuln_class", ""), r.get("vuln_class", "")),
                    st=STATUS_LABELS.get(r.get("status", ""), r.get("status", "")),
                    c=r.get("count", 0),
                    ls=r.get("last_seen", "")[:19],
                    n=notes,
                )
            )
        return "\n".join(out_lines) + "\n"

    return json.dumps({"ok": False, "error": f"Unsupported format '{format}'. Use json|csv|md."})


def report_to_mirv_findings(entry: CoverageEntry) -> list[dict[str, Any]]:
    """Translate a coverage row into one or more MIRV finding dicts.

    A ``failed`` status → 1 high-severity finding; ``waf-blocked`` → 1
    medium finding; any other status does NOT yield a vulnerability
    finding (return an empty list) because nothing was confirmed.
    """
    if not isinstance(entry, CoverageEntry):
        return []

    severity = STATUS_SEVERITY.get(entry.status, "info")
    if entry.status not in ("failed", "waf-blocked"):
        return []

    title = "{vc} — {ep}{param}".format(
        vc=VULN_CLASS_LABELS.get(entry.vuln_class, entry.vuln_class).upper(),
        ep=entry.endpoint,
        param=f" ({entry.param})" if entry.param else "",
    )
    return [{
        "title": title,
        "severity": severity,
        "vuln_class": entry.vuln_class,
        "endpoint": entry.endpoint,
        "method": entry.method,
        "path": entry.path,
        "param": entry.param,
        "status": entry.status,
        "tool": "coverage-matrix",
        "detail": entry.notes or f"Coverage status: {entry.status} (tested {entry.count}x).",
        "first_seen": entry.first_seen,
        "last_seen": entry.last_seen,
        "session_id": entry.session_id,
    }]


def coverage_context_for_prompt(session_id: Optional[str] = None, limit: int = 12) -> str:
    """Build a compact text block for ``/api/suggest`` and Op Admiral.

    Returns an ASCII-only block (no emojis) that lists the top next steps
    + the running pass/failed ratio. Empty when the matrix is empty so
    the LLM keeps working without noise.
    """
    summary = coverage_summary(session_id=session_id)
    if not summary["total"]:
        return ""
    steps = next_steps(session_id=session_id, limit=limit)
    if not steps:
        return ""
    lines = [
        "## Coverage Matrix Context",
        f"Pass ratio: {summary['passed']}/{summary['passed'] + summary['failed'] or 0} "
        f"({summary['pass_ratio']*100:.1f}%) across {summary['total']} tests.",
        "Top recommended next tests:",
    ]
    for i, s in enumerate(steps, 1):
        param = f" param={s.get('param')}" if s.get("param") else ""
        lines.append(
            f"{i}. [{s.get('reason','suggested')}] {s.get('method')} {s.get('endpoint')}"
            f"{param} -> {s.get('vuln_class_label', s.get('vuln_class'))}"
        )
    return "\n".join(lines)


def reset_store_for_tests() -> None:
    """Helper used by the test-suite (and only by tests) to start clean."""
    with _lock:
        _entries.clear()
        _sessions.clear()


__all__ = [
    "ALLOWED_METHODS",
    "ALLOWED_STATUSES",
    "ALLOWED_VULN_CLASSES",
    "STATUS_LABELS",
    "STATUS_SEVERITY",
    "VULN_CLASS_LABELS",
    "CoverageEntry",
    "mark_coverage",
    "list_coverage",
    "coverage_summary",
    "untested_endpoints",
    "next_steps",
    "clear_coverage",
    "save_session",
    "list_sessions",
    "export_coverage",
    "report_to_mirv_findings",
    "coverage_context_for_prompt",
    "reset_store_for_tests",
]