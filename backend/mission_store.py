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

    row = {
        "target": safe_data.get("target", target),
        "os_detected": safe_data.get("os_detected", ""),
        "tools_used": json.dumps(safe_data.get("tools_used", [])),
        "findings_count": int(safe_data.get("findings_count", 0) or 0),
        "findings_summary": json.dumps(safe_data.get("findings_summary", [])),
        "plan_steps": int(safe_data.get("plan_steps", 0) or 0),
        "success_score": int(safe_data.get("success_score", 0) or 0),
    }

    tbl = db._table(_TABLE)
    if tbl is None:
        logger.info("save_mission: Supabase not configured — skipping")
        return None
    try:
        resp = tbl.insert(row).execute()
        return dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("save_mission: %s", e)
        return None


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