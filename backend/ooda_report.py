# -*- coding: utf-8 -*-
"""
M.I.R.V. — OODA Report (F3)
===========================
Markdown report from OODA run JSONL. Only evidence-based.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from backend import ooda_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def render_markdown(run_id: str) -> str:
    run = ooda_store.get_run(run_id)
    if not run:
        return f"# OODA Report\n\nRun not found: {run_id}\n"
    lines = []
    lines.append(f"# OODA Report — {run.run_id}")
    lines.append("")
    lines.append(f"- **Target:** {run.target or '-'}")
    lines.append(f"- **Goal:** {run.goal or '-'}")
    lines.append(f"- **Mode:** {run.mode}")
    lines.append(f"- **Status:** {run.status}")
    lines.append(f"- **Created:** {run.created_at}")
    lines.append(f"- **Assessment:** {run.assessment_id or '-'}")
    lines.append("")
    lines.append("## Timeline")
    lines.append("")
    for s in run.steps:
        lines.append(f"### [{s.phase.upper()}] {s.ts} — {s.step_id}")
        if s.reasoning:
            lines.append(f"**Reasoning:** {s.reasoning}")
            lines.append("")
        if s.technique_id or s.confidence:
            lines.append(f"- technique_id: {s.technique_id or '-'} | confidence: {s.confidence}")
            lines.append("")
        if s.actions:
            lines.append("**Actions:**")
            for a in s.actions:
                cmd = a.get('command') or a.get('cmd') or a.get('name') or str(a)
                risk = a.get('_risk') or ''
                perm = ' [needs-permission]' if a.get('_needs_permission') else ''
                lines.append(f"- `{cmd}`{perm} {('(' + risk + ')') if risk else ''}")
            lines.append("")
        if s.evidence:
            lines.append("**Evidence:**")
            for e in s.evidence:
                lines.append(f"- {e}")
            lines.append("")
        if s.findings:
            lines.append("**Findings:**")
            for f in s.findings:
                title = f.get('title') or f.get('name') or 'finding'
                sev = f.get('severity') or '-'
                tid = f.get('technique_id') or s.technique_id or '-'
                ost = f.get('ooda_status') or s.ooda_status or '-'
                conf = f.get('confidence') if f.get('confidence') is not None else s.confidence
                lines.append(f"- [{sev}] {title} | technique_id={tid} | ooda_status={ost} | confidence={conf}")
                if f.get('details'):
                    lines.append(f"  - {f.get('details')}")
            lines.append("")
    lines.append("---")
    lines.append(f"_Generated { _now_iso() } by M.I.R.V. OODA_")
    return "\n".join(lines)
