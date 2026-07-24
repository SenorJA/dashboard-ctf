"""
M.I.R.V. — Self-Improvement Mission Store
========================================

Persistence layer for completed pentest "missions". Each mission captures
*what was learned* about a target so the AI suggestion loop can recall
similar past engagements and reuse techniques that worked.

Purpose
-------
This module implements the "self-improvement loop" described in
PLAN_SELFIMPROVEMENT.md:

    Mission 1: target A (Apache 2.4.49, :80) → searchsploit → CVE-2021-41773
    Mission 2: target B (Apache 2.4.49, :80)
        ↓ IA remembers Mission 1 and recommends searchsploit 'apache 2.4.49'

It is deliberately thin: it relies on ``backend.database`` for the
Supabase client and table helpers, and only adds the *mission-specific*
selection logic (similarity search) plus a prompt-context builder.

Design
------
- **Offline-first:** when Supabase is not configured, every function
  degrades gracefully — ``save_mission`` returns ``None``, list/find
  helpers return ``[]``, and ``get_suggestion_context`` returns ``""``.
  This means the AI suggest endpoint keeps working on a laptop with no
  DB, just without the memory boost.
- **No direct Supabase calls:** everything goes through
  ``database._table('mission_history')`` so the connection lifecycle
  stays centralised.
- **JSONB-aware similarity:** the table stores ``tools_used`` and
  ``findings_summary`` as JSONB. PostgREST/``supabase-py`` does not
  expose a clean JSONB-array-overlap operator, so similarity is done in
  two stages: (1) a cheap server-side filter on ``os_detected`` (ilike)
  when available, then (2) an in-process overlap check on the tools
  list. This keeps the REST payload small while still being expressive.
- **No new dependencies:** stdlib only.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from backend import database as db
from backend.redact import redact_dict as _redact_dict

logger = logging.getLogger("vulnforge.missions")

_TABLE = "mission_history"

# Severity → weight used when mining past missions for what "worked".
_SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}

# ── Compaction caps ─────────────────────────────────────────────
_MAX_OBJECTIVES = 24
_MAX_FINDINGS = 12
_MAX_CREDENTIALS = 12
_MAX_TODOS = 12
_MAX_FILES = 12
_MAX_COMMANDS = 12
_MAX_TECHNOLOGIES = 16

# Findings severities kept in the compact view.
_HIGH_SEVERITIES = {"critical", "high", "high-risk", "critical-risk"}

# Tool / keyword → human-readable technology label. Used by
# :func:`compact_session` to derive the ``technologies`` section by
# scanning the mission's commands and findings text.
_TECH_RULES: list[tuple[str, str]] = [
    ("nmap",        "Nmap scanner"),
    ("masscan",     "Masscan port scanner"),
    ("gobuster",    "Web directory bruteforce"),
    ("dirb",        "Web directory bruteforce"),
    ("ffuf",        "Web directory bruteforce"),
    ("feroxbuster", "Web directory bruteforce"),
    ("nikto",       "Nikto web scanner"),
    ("whatweb",     "Web fingerprinting"),
    ("wpscan",      "WordPress CMS"),
    ("wordpress",  "WordPress CMS"),
    ("wp-content",  "WordPress CMS"),
    ("wp-admin",    "WordPress CMS"),
    ("nginx",       "nginx web server"),
    ("apache",      "Apache web server"),
    ("httpd",       "Apache web server"),
    ("iis",         "Microsoft IIS"),
    ("express",     "Node.js / Express"),
    ("node",        "Node.js"),
    ("npm",         "Node.js"),
    ("next.js",     "Next.js framework"),
    ("react",       "React frontend"),
    ("django",      "Django framework"),
    ("flask",       "Flask framework"),
    ("postgresql",  "PostgreSQL"),
    ("psql",        "PostgreSQL"),
    ("mysql",       "MySQL"),
    ("mariadb",     "MariaDB"),
    ("mongodb",     "MongoDB"),
    ("mongo ",      "MongoDB"),
    ("redis",       "Redis"),
    ("graphql",     "GraphQL"),
    ("gql",         "GraphQL"),
    ("joomla",      "Joomla CMS"),
    ("drupal",      "Drupal CMS"),
    ("tomcat",      "Apache Tomcat"),
    ("jenkins",     "Jenkins CI"),
    ("gitlab",      "GitLab"),
    ("aws",         "AWS"),
    ("s3",          "AWS S3"),
    ("ec2",         "AWS EC2"),
    ("gcp",         "Google Cloud"),
    ("azure",       "Microsoft Azure"),
    ("docker",      "Docker"),
    ("kubernetes",  "Kubernetes"),
    ("kubectl",     "Kubernetes"),
    ("openssh",     "OpenSSH"),
    ("ssh",         "SSH service"),
    ("ftp",         "FTP service"),
    ("smb",         "SMB service"),
    ("rdp",         "RDP service"),
    ("snmp",        "SNMP service"),
]


# ══════════════════════════════════════════════════════════════════
#  SessionMemory dataclass
# ══════════════════════════════════════════════════════════════════

@dataclass
class SessionMemory:
    """Bounded summary of a mission session for AI context.

    The dataclass is intentionally narrow — it captures only the
    pieces of past missions that a downstream LLM prompt needs to
    ground its next-step recommendation, with hard caps on every list
    field so a single verbose engagement can never blow the model's
    context window. The original mission row is left untouched: the
    compact view lives alongside it in the ``session_memory`` JSONB
    column.
    """
    mission_id: str
    objectives: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    last_summary: Optional[str] = None
    compacted_at: Optional[str] = None
    compaction_count: int = 0


def _now_iso() -> str:
    """Stable ISO-8601 UTC timestamp — key for the ``compacted_at`` field."""
    return datetime.now(timezone.utc).isoformat()


def _compact_threshold() -> int:
    """Read the auto-compaction char threshold from the environment.

    ``MIRV_COMPACT_THRESHOLD=0`` explicitly disables auto-compaction
    (manual ``POST /api/missions/{id}/compact`` still works). The default
    of 16000 chars roughly maps to ~4k LLM tokens, leaving headroom for
    the rest of the suggest prompt.
    """
    raw = os.getenv("MIRV_COMPACT_THRESHOLD", "16000")
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return 16000
    return max(0, v)


def _as_json(value):
    """Best-effort decode of a JSON column that may arrive as a str or dict."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def _get_mission_details(mission_id: str) -> Optional[dict]:
    """Fetch a single mission row by UUID (internal helper).

    Returns ``None`` when the DB is unavailable, the row is missing, or
    the query fails — every caller must tolerate ``None``.
    """
    tbl = db._table(_TABLE)
    if tbl is None:
        return None
    try:
        resp = tbl.select("*").eq("id", mission_id).maybe_single().execute()
        return dict(resp.data) if resp.data else None
    except Exception as e:
        logger.error("get_mission_details: %s", e)
        return None


# Backwards-compatible alias used by the spec/prompt.
get_mission_details = _get_mission_details


def _store_session_memory(mission_id: str, memory_dict: dict) -> bool:
    """Persist the SessionMemory dict into the ``session_memory`` JSONB column.

    Returns ``True`` on success, ``False`` on any failure (missing column,
    unreachable DB, ...). ``False`` must be non-fatal — compaction just
    stays in-memory for the current request.
    """
    tbl = db._table(_TABLE)
    if tbl is None:
        return False
    try:
        tbl.update({"session_memory": memory_dict}).eq("id", mission_id).execute()
        return True
    except Exception as e:
        logger.warning("store_session_memory: %s", e)
        return False


def _extract_objectives(mission: dict) -> list[str]:
    """Pull objectives from the mission payload, or synthesise a minimal set.

    Many missions arrive without an explicit objectives list — we fall
    back to a single objective derived from the audited target so the
    "Objectives" section of the rendered memory is never empty.
    """
    raw = mission.get("objectives") or mission.get("plan") or []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = [raw]
    objs: list[str] = []
    if isinstance(raw, list):
        for o in raw:
            if isinstance(o, str) and o.strip():
                objs.append(o.strip())
            elif isinstance(o, dict):
                label = (o.get("title") or o.get("objective")
                        or o.get("description") or o.get("goal") or "")
                if label:
                    objs.append(str(label).strip())
    # Fallback: derive one objective from target / os.
    if not objs:
        target = mission.get("target") or "the target"
        os_det = mission.get("os_detected") or ""
        objs.append(f"Pentest {target}" + (f" ({os_det})" if os_det else ""))
    return objs[:_MAX_OBJECTIVES]


def _extract_findings(mission: dict) -> list[dict]:
    """Pick high/critical findings, capped at :data:`_MAX_FINDINGS`.

    Accepts both the persisted ``findings_summary`` JSONB shape
    (``{severity, title, ...}``) and the operator-supplied ``findings``
    shape from :func:`save_mission` (``{what, severity, target}``).
    Only ``what``/``severity``/``target`` survive — no evidence payloads.
    """
    findings = _as_json(mission.get("findings_summary")) \
        or _as_json(mission.get("findings")) \
        or []
    if not isinstance(findings, list):
        return []
    out: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "").strip().lower()
        if not sev:
            # Findings without severity default to "info" — skip.
            continue
        if sev not in _HIGH_SEVERITIES:
            continue
        what = (f.get("what") or f.get("title") or
                f.get("name") or f.get("detail") or "").strip()
        if not what:
            continue
        out.append({
            "what": what,
            "severity": sev,
            "target": str(f.get("target") or f.get("path") or
                          f.get("url") or f.get("host") or mission.get("target") or ""),
        })
        if len(out) >= _MAX_FINDINGS:
            break
    return out


def _extract_credentials(mission: dict) -> list[dict]:
    """Pull non-secret credential metadata (user/service/target only).

    SECURITY: this function MUST NEVER include password, secret, token,
    key, or any other authenticator value. The dict shape returned
    is ``{user, service, target}`` only. The whole SessionMemory is
    additionally passed through :func:`redact.redact_dict` before
    persistence as belt-and-suspenders protection.
    """
    creds = _as_json(mission.get("credentials"))
    if not isinstance(creds, list):
        creds = []
    out: list[dict] = []
    for c in creds:
        if not isinstance(c, dict):
            continue
        user = (c.get("user") or c.get("username") or c.get("login") or "")
        service = (c.get("service") or c.get("protocol") or c.get("type") or "")
        target = (c.get("target") or c.get("host") or mission.get("target") or "")
        if not user and not service:
            continue
        out.append({
            "user": str(user),
            "service": str(service),
            "target": str(target),
        })
        if len(out) >= _MAX_CREDENTIALS:
            break
    return out


def _extract_todos(mission: dict) -> list[str]:
    """Derive open TODOs from incomplete coverage / next-steps hints."""
    todos_raw = mission.get("todos") or mission.get("next_steps")
    if isinstance(todos_raw, str):
        try:
            todos_raw = json.loads(todos_raw)
        except Exception:
            todos_raw = [todos_raw] if todos_raw.strip() else []
    todos: list[str] = []
    if isinstance(todos_raw, list):
        for t in todos_raw:
            if isinstance(t, str) and t.strip():
                todos.append(t.strip())
            elif isinstance(t, dict):
                txt = (t.get("description") or t.get("title") or
                       t.get("task") or t.get("step") or "")
                if txt:
                    todos.append(str(txt).strip())
            if len(todos) >= _MAX_TODOS:
                break
    return todos


_FILE_REDIRECT_RE = __import__("re").compile(
    r'(?:>>|>)\s*([^\s|;&]+)',
)
_FILE_TEE_RE = __import__("re").compile(
    r'\btee\s+(?:-a\s+)?([^\s|;&]+)',
    __import__("re").IGNORECASE,
)
_FILE_CP_MV_RE = __import__("re").compile(
    r'\b(?:cp|mv|install)\s+(?:-\S+\s+)*\S+\s+([^\s|;&]+)',
    __import__("re").IGNORECASE,
)


def _extract_files(mission: dict) -> list[str]:
    """Pull file paths touched by commands that wrote to disk.

    Heuristic — over approximate rather than miss an artifact. We look
    for ``tee``/``>``/``>>``/``cp``/``mv``/``install`` style fragments
    and keep the destination path token (redacted later).
    """
    commands = _collect_commands(mission)
    files: list[str] = []
    for cmd in commands:
        if not isinstance(cmd, str):
            continue
        paths: list[str] = []
        for rx in (_FILE_REDIRECT_RE, _FILE_TEE_RE, _FILE_CP_MV_RE):
            for m in rx.finditer(cmd):
                path = m.group(1).strip("\"'")
                if path and path not in paths:
                    paths.append(path)
        for path in paths:
            if path not in files:
                files.append(path)
            if len(files) >= _MAX_FILES:
                return files
    return files


def _collect_commands(mission: dict) -> list[str]:
    """Normalise the many command-storage shapes into a flat list[str]."""
    cmds: list[str] = []

    # 1) Explicit commands_executed list (operator-supplied).
    raw_cmds = mission.get("commands_executed")
    if isinstance(raw_cmds, str):
        try:
            raw_cmds = json.loads(raw_cmds)
        except Exception:
            raw_cmds = [raw_cmds]
    if isinstance(raw_cmds, list):
        for c in raw_cmds:
            if isinstance(c, str):
                cmds.append(c)
            elif isinstance(c, dict):
                txt = (c.get("command") or c.get("cmd") or
                       c.get("text") or "")
                if txt:
                    cmds.append(str(txt))
    # 2) tools_used `[{tool, command, useful}]`
    tools_used = _as_json(mission.get("tools_used")) or []
    if isinstance(tools_used, list):
        for t in tools_used:
            if isinstance(t, dict):
                cmd = (t.get("command") or "").strip()
                if cmd and cmd not in cmds:
                    cmds.append(cmd)
            elif isinstance(t, str) and t.strip():
                cmds.append(t.strip())
    return cmds


def _extract_commands(mission: dict) -> list[str]:
    """Dedup, cap at :data:`_MAX_COMMANDS`, last-wins."""
    cmds = _collect_commands(mission)
    seen: set[str] = set()
    deduped: list[str] = []
    for c in reversed(cmds):
        key = c.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(key)
        if len(deduped) >= _MAX_COMMANDS:
            break
    return list(reversed(deduped))


def _extract_technologies(mission: dict) -> list[str]:
    """Scan commands + findings + os_detected for known tech keywords."""
    haystack_parts: list[str] = []
    cmds = _collect_commands(mission)
    haystack_parts.extend(cmds)
    findings = _as_json(mission.get("findings_summary")) \
        or _as_json(mission.get("findings")) \
        or []
    if isinstance(findings, list):
        for f in findings:
            if isinstance(f, dict):
                for k in ("what", "title", "detail", "name", "target", "url"):
                    v = f.get(k)
                    if v:
                        haystack_parts.append(str(v))
    if mission.get("os_detected"):
        haystack_parts.append(str(mission.get("os_detected")))
    haystack = " ".join(haystack_parts).lower()
    detected: list[str] = []
    for keyword, label in _TECH_RULES:
        if keyword in haystack and label not in detected:
            detected.append(label)
        if len(detected) >= _MAX_TECHNOLOGIES:
            break
    return detected


def get_session_memory(mission_id: str) -> Optional[dict]:
    """Return stored SessionMemory dict for ``mission_id`` or ``None``.

    Mirrors the ``session_memory`` JSONB column. Tolerant of either a
    dict (PostgREST decodes JSONB) or a JSON-encoded string. When the
    DB is unavailable, returns ``None`` — callers must handle that.
    """
    mission = _get_mission_details(mission_id)
    if not mission:
        return None
    raw = _as_json(mission.get("session_memory"))
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    return None


def compact_session(mission_id: str) -> dict:
    """Build a bounded SessionMemory and persist it for the mission.

    Returns ``{"ok": True, "memory": <SessionMemory dict>}`` on success
    or ``{"ok": False, "error": "..."}`` when the mission cannot be
    found or the DB is unreachable. The compact view is also stored in
    the ``session_memory`` JSONB column so future "render for prompt"
    calls are zero-cost. Compaction is idempotent — running it twice on
    the same mission simply refreshes ``compacted_at`` and increments
    ``compaction_count``.
    """
    mission = _get_mission_details(mission_id)
    if not mission:
        return {"ok": False, "error": "Mission not found"}

    # Read prior compaction count so repeated compactions increment it.
    prior = _as_json(mission.get("session_memory")) or {}
    prior_count = 0
    if isinstance(prior, dict):
        try:
            prior_count = int(prior.get("compaction_count") or 0)
        except (TypeError, ValueError):
            prior_count = 0

    memory = SessionMemory(
        mission_id=str(mission_id),
        objectives=_extract_objectives(mission),
        findings=_extract_findings(mission),
        credentials=_extract_credentials(mission),
        todos=_extract_todos(mission),
        files=_extract_files(mission),
        commands=_extract_commands(mission),
        technologies=_extract_technologies(mission),
        last_summary=None,  # no LLM-generated prose yet; reserved for future use
        compacted_at=_now_iso(),
        compaction_count=prior_count + 1,
    )

    # Serialize to plain dict BEFORE redaction (redact_dict returns a
    # new dict). Belt-and-suspenders: the per-field extractors already
    # avoid secret values, but redact_dict also masks anything that may
    # have slipped in via e.g. file paths that look like tokens.
    mem_dict = asdict(memory)
    try:
        mem_dict = _redact_dict(mem_dict)
    except Exception as e:
        logger.debug("compact_session redact skipped: %s", e)

    # Persist (best-effort — failure keeps the in-memory view usable).
    _store_session_memory(mission_id, mem_dict)

    return {"ok": True, "memory": mem_dict}


def auto_compact_if_needed(mission_id: str,
                           threshold_chars: Optional[int] = None) -> Optional[dict]:
    """Compact a mission when its serialized size exceeds ``threshold_chars``.

    Used by :func:`save_mission` and the batch endpoint to keep long
    sessions bounded. The threshold defaults to :func:`_compact_threshold`
    (env ``MIRV_COMPACT_THRESHOLD``). A threshold of ``0`` disables
    compaction entirely (returns ``None``). Although the persisted row
    for a *just-saved* mission usually has no ``session_memory`` yet,
    we still exclude the column from the size check so re-compactions
    stay stable.
    """
    if threshold_chars is None:
        threshold_chars = _compact_threshold()
    try:
        threshold_chars = int(threshold_chars)
    except (TypeError, ValueError):
        threshold_chars = _compact_threshold()
    if threshold_chars <= 0:
        return None

    mission = _get_mission_details(mission_id)
    if not mission:
        return None

    payload = {k: v for k, v in mission.items() if k != "session_memory"}
    try:
        size = len(json.dumps(payload, default=str, ensure_ascii=False))
    except Exception:
        size = 0

    if size <= threshold_chars:
        return None

    return compact_session(mission_id)


def render_session_memory_for_prompt(mission_id: str) -> str:
    """Return a markdown block ready to splice into an LLM system prompt.

    When the mission has never been compacted, this triggers a one-off
    compaction so the first ``/api/suggest`` call after a long session
    always carries fresh context (idempotent — cheap when buffers fit).
    The output is intentionally short — every section is bounded by the
    caps in :data:`_MAX_*`.
    """
    memory = get_session_memory(mission_id)
    if memory is None:
        # Lazy compaction: build the memory on first render request.
        res = compact_session(mission_id)
        if not res.get("ok"):
            return ""
        memory = res.get("memory") or {}
    if not isinstance(memory, dict) or not memory:
        return ""

    lines: list[str] = ["## Session Memory"]
    compacted_at = memory.get("compacted_at")
    if compacted_at:
        lines[0] = f"## Session Memory (last compacted: {compacted_at})"
    lines.append("")

    objectives = memory.get("objectives") or []
    if objectives:
        lines.append("### Objectives")
        for o in objectives:
            lines.append(f"- {o}")
        lines.append("")

    findings = memory.get("findings") or []
    if findings:
        lines.append("### High-severity findings")
        for f in findings:
            sev = (f.get("severity") or "").upper()
            what = f.get("what") or ""
            target = f.get("target") or ""
            lines.append(f"- [{sev}] {what} — target: {target}".rstrip())
        lines.append("")

    creds = memory.get("credentials") or []
    if creds:
        lines.append("### Discovered credentials")
        for c in creds:
            user = c.get("user") or ""
            service = c.get("service") or ""
            target = c.get("target") or ""
            lines.append(f"- {user}@{service} on {target}".rstrip())
        lines.append("")

    todos = memory.get("todos") or []
    if todos:
        lines.append("### Open TODOs")
        for t in todos:
            lines.append(f"- {t}")
        lines.append("")

    files = memory.get("files") or []
    if files:
        lines.append("### Files touched")
        for path in files:
            lines.append(f"- {path}")
        lines.append("")

    commands = memory.get("commands") or []
    if commands:
        lines.append("### Recent commands")
        for c in commands:
            lines.append(f"- {c}")
        lines.append("")

    techs = memory.get("technologies") or []
    if techs:
        lines.append("### Technologies")
        lines.append("- " + ", ".join(techs))
        lines.append("")

    return "\n".join(lines).strip()


def count_compact_sessions() -> int:
    """Count how many missions carry a non-null ``session_memory`` blob."""
    tbl = db._table(_TABLE)
    if tbl is None:
        return 0
    try:
        resp = tbl.select("id", count="exact").not_.is_("session_memory", "null").execute()
        # supabase-py exposes the total via `resp.count` (preferred) or
        # falls back to the body length.
        count = getattr(resp, "count", None)
        if count is None:
            count = len(resp.data or [])
        return int(count)
    except Exception as e:
        logger.debug("count_compact_sessions: %s", e)
        # Fallback: pull the column and count non-null rows in-process.
        try:
            resp = tbl.select("session_memory").execute()
            return sum(1 for r in (resp.data or []) if r and r.get("session_memory") is not None)
        except Exception:
            return 0


def save_mission(data: dict) -> dict | None:
    """Persist a completed mission to ``mission_history``.

    Purpose
    -------
    Records the outcome of one engagement (target, detected OS, tools
    used, top findings, success score) so future engagements on similar
    targets can reuse the playbook via :func:`find_similar`.

    Parameters
    ----------
    data : dict
        Expected keys (all optional except ``target``):
          - ``target`` (str)            — the host that was audited
          - ``os_detected`` (str)       — OS or banner fingerprint
          - ``tools_used`` (list[dict]) — ``[{"tool","command","useful"}]``
          - ``findings_count`` (int)    — number of findings produced
          - ``findings_summary`` (list) — top N findings (severity/tool/title)
          - ``plan_steps`` (int)        — size of the Op Admiral plan
          - ``success_score`` (int)     — 0..100 heuristic score

    Returns
    -------
    dict | None
        The inserted row, or ``None`` if Supabase is unavailable or the
        insert failed. Missing keys are defaulted; the only hard
        requirement is a non-empty ``target``.
    """
    target = (data.get("target") or "").strip()
    if not target:
        logger.warning("save_mission: refusing row with empty target")
        return None

    # Redact any secrets that may have slipped into findings/tool
    # output BEFORE persisting (this content is later fed to the AI
    # suggest loop, so we must not leak credentials/tokens to the LLM).
    safe_data = _redact_dict(data)

    # ── Preserve rich mission payloads the compactor needs ─────────
    # ``findings`` (operator-supplied) and ``findings_summary`` (legacy
    # column) are both JSONB; when the caller supplies ``findings`` we
    # promote it into ``findings_summary`` so :func:`compact_session`
    # can still reach it after a Supabase round trip.
    findings_summary = safe_data.get("findings_summary")
    findings = safe_data.get("findings")
    if not findings_summary and findings:
        findings_summary = findings
    # Likewise, ``commands_executed`` lands into the ``tools_used``
    # JSONB column so the compactor's command/files extractors find them
    # without an extra column.
    tools_used = safe_data.get("tools_used")
    cmds_exec = safe_data.get("commands_executed")
    if not tools_used and cmds_exec:
        tools_used = [
            {"tool": "", "command": c, "useful": True}
            for c in cmds_exec
            if isinstance(c, str) and c.strip()
        ]
    if findings is None and findings_summary is None:
        findings_summary = []
    if tools_used is None:
        tools_used = []
    if findings_summary is None:
        findings_summary = []

    # Derive findings_count when the caller didn't supply it.
    findings_count = safe_data.get("findings_count")
    if findings_count in (None, 0) and isinstance(findings_summary, list):
        findings_count = len(findings_summary)

    row = {
        "target": safe_data.get("target", target),
        "os_detected": safe_data.get("os_detected", ""),
        "tools_used": json.dumps(tools_used, default=str),
        "findings_count": int(findings_count or 0),
        "findings_summary": json.dumps(findings_summary, default=str),
        "plan_steps": int(safe_data.get("plan_steps", 0) or 0),
        "success_score": int(safe_data.get("success_score", 0) or 0),
    }

    tbl = db._table(_TABLE)
    if tbl is None:
        logger.info("save_mission: Supabase not configured — skipping")
        return None
    try:
        resp = tbl.insert(row).execute()
        result = dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("save_mission: %s", e)
        return None

    # ── Trigger auto-compaction if the mission grew above threshold ──
    # We only run if the env threshold is positive (a 0 value disables
    # auto-compaction entirely — the operator can still call
    # ``POST /api/missions/{id}/compact`` manually). Failures here are
    # non-fatal: the just-inserted row is returned untouched.
    if result and result.get("id"):
        try:
            threshold = _compact_threshold()
            if threshold > 0:
                auto_compact_if_needed(result["id"], threshold)
        except Exception as e:
            logger.debug("save_mission auto-compact skipped: %s", e)
    return result


def list_missions(limit: int = 50, target: Optional[str] = None) -> list:
    """List missions, newest first, optionally filtered by target.

    Purpose
    -------
    Backs the ``GET /api/missions`` endpoint and the "Mission History"
    panel in Op Admiral. Returns ``[]`` (not ``None``) when the DB is
    unavailable so the frontend can render an empty list instead of
    erroring.
    """
    tbl = db._table(_TABLE)
    if tbl is None:
        return []
    try:
        q = tbl.select("*").order("created_at", desc=True)
        if target:
            q = q.eq("target", target)
        resp = q.limit(int(limit or 50)).execute()
        return [dict(r) for r in resp.data] if resp.data else []
    except Exception as e:
        logger.error("list_missions: %s", e)
        return []


def find_similar(
    target_os: Optional[str] = None,
    tools: Optional[list] = None,
    limit: int = 5,
) -> list:
    """Find past missions similar to the current engagement.

    Purpose
    -------
    Powers the "_IA remembers_" step of the self-improvement loop. Given
    the OS / tech stack just detected (e.g. ``"Apache 2.4.49"``) and the
    set of tools already used (e.g. ``["nmap","nikto"]``), return up to
    ``limit`` past missions that share the OS or whose ``tools_used``
    list overlaps with the supplied tools, ranked by ``success_score``
    descending so the most fruitful past playbook surfaces first.

    Parameters
    ----------
    target_os : str | None
        OS / technology banner to match (case-insensitive substring).
    tools : list[str] | None
        Tools already run this mission. Used to find historical
        engagements that touched the same tools.
    limit : int
        Maximum missions to return (default 5).

    Returns
    -------
    list[dict]
        Missions sorted by ``success_score`` desc. ``[]`` on failure or
        when Supabase is not configured.
    """
    tools = [t.strip().lower() for t in (tools or []) if t and t.strip()]
    limit = max(1, int(limit or 5))

    tbl = db._table(_TABLE)
    if tbl is None:
        return []

    try:
        q = tbl.select("*")
        if target_os:
            q = q.ilike("os_detected", f"%{target_os}%")
        resp = q.limit(100).execute()
        rows = [dict(r) for r in resp.data] if resp.data else []
    except Exception as e:
        logger.error("find_similar: %s", e)
        return []

    if not rows:
        return []

    def _tool_names(row: dict) -> set[str]:
        raw = row.get("tools_used") or []
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = []
        names = set()
        for t in raw:
            if isinstance(t, dict):
                n = (t.get("tool") or "").strip().lower()
            else:
                n = str(t).strip().lower()
            if n:
                names.add(n)
        return names

    # Rank: missions that actually used similar tools rank higher than
    # those that only share the OS.
    def _overlap(row: dict) -> int:
        return len(_tool_names(row) & set(tools))

    rows.sort(
        key=lambda r: (r.get("success_score", 0) or 0) + 50 * _overlap(r),
        reverse=True,
    )

    # Keep only rows that have at least *some* signal: either a tool
    # overlap or (when no tools were supplied) any matching OS row.
    if tools:
        rows = [r for r in rows if _overlap(r) > 0] or rows

    return rows[:limit]


def get_suggestion_context(current_findings) -> str:
    """Build a "Mission History" preamble for the AI suggest prompt.

    Purpose
    -------
    Called from ``POST /api/suggest``. Inspects the findings the
    operator has so far, derives a target OS hint, asks
    :func:`find_similar` for the closest historical missions, and
    synthesises a short markdown section that the LLM can ground on.

    Parameters
    ----------
    current_findings : list | str
        The findings payload (list of dicts) **or** the raw text the
        frontend sends in ``SuggestRequest.findings`` (string). Both are
        accepted so :

    Returns
    -------
    str
        Either a non-empty markdown block under the heading
        ``## Mission History Context`` listing similar missions and what
        worked for them, or ``""`` when no context is available (DB off,
        no similar missions, unparseable findings). Returning ``""``
        means :func:`backend.main.suggest_next_step` flows through the
        unmodified prompt — the suggest endpoint must never crash on
        this.
    """
    target_os: Optional[str] = None
    tools: list[str] = []

    try:
        findings_list: list = []
        if isinstance(current_findings, str):
            # Best-effort heuristic: scan the text for known banners.
            text_l = current_findings.lower()
            for banner in ("apache", "nginx", "iis", "openssh", "linux", "windows"):
                if banner in text_l:
                    target_os = banner
                    break
        elif isinstance(current_findings, list):
            findings_list = current_findings
            for f in findings_list:
                if not isinstance(f, dict):
                    continue
                t = (f.get("type") or "").lower()
                title = (f.get("title") or "").lower()
                sev = (f.get("severity") or "").lower()
                if t == "os" or "os" in t:
                    val = f.get("version") or f.get("detail") or f.get("title")
                    if val:
                        target_os = val
                        break
                if not target_os and ("apache" in title or "nginx" in title or "openssh" in title):
                    target_os = f.get("title")
                    break
                _sev = _SEVERITY_WEIGHT.get(sev, 0)
                tool = (f.get("tool") or "").lower()
                if tool and _sev >= _SEVERITY_WEIGHT["medium"]:
                    tools.append(tool)

    except Exception as e:
        logger.debug("get_suggestion_context parse error: %s", e)
        return ""

    if not target_os and not tools:
        return ""

    similar = find_similar(
        target_os=target_os or None,
        tools=tools or None,
        limit=5,
    )
    if not similar:
        return ""

    lines = ["## Mission History Context",
             f"The following {len(similar)} past mission(s) appear similar "
             f"to the current target (OS hint: `{target_os or 'unknown'}`)."]
    lines.append("Use these historical outcomes as prior knowledge when "
                 "recommending next steps, but DO NOT assume the same "
                 "vulnerabilities exist — validate first.")
    lines.append("")

    for i, m in enumerate(similar, 1):
        # Normalise tools_used (may be a JSON string)
        tools_used = m.get("tools_used") or []
        if isinstance(tools_used, str):
            try:
                tools_used = json.loads(tools_used)
            except Exception:
                tools_used = []
        useful_tools = []
        for t in tools_used:
            if isinstance(t, dict) and t.get("useful"):
                cmd = (t.get("command") or "").strip()
                tn  = (t.get("tool") or "").strip()
                # Prefer the concrete command, fall back to tool name.
                label = cmd or tn
                if label:
                    useful_tools.append(label)
        summary = m.get("findings_summary") or []
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except Exception:
                summary = []

        lines.append(
            f"### Mission #{i} — target `{m.get('target','?')}` "
            f"(score {m.get('success_score',0)}, "
            f"{m.get('findings_count',0)} findings)"
        )
        if useful_tools:
            lines.append("Effective commands from this engagement:")
            for c in useful_tools[:5]:
                lines.append(f"  - `{c[:200]}`")
        if summary:
            lines.append("Top findings:")
            for s in summary[:3]:
                if not isinstance(s, dict):
                    continue
                lines.append(
                    f"  - [{(s.get('severity') or 'info').upper()}] "
                    f"{(s.get('title') or s.get('tool',''))[:160]}"
                )
        lines.append("")

    return "\n".join(lines).strip()