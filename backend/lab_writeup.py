"""
lab_writeup.py -- MIRV Module

Dark-mode, self-contained renderers for Lab Sessions write-ups.

Ported/adapted from afsh4ck/exploitpath ``client/src/lib/exportWriteup.ts``:

  * ``build_writeup_html`` — a single self-contained HTML document with the
    ``#090d14`` / ``#9FEF00`` palette, no remote dependencies, and every
    dynamic value escaped before insertion.
  * ``build_writeup_pdf`` — a ReportLab PDF with the same dark visual system
    (terminal cards + interleaved narrative).

Both accept an optional AI ``narrative`` (per-step title/description) and place
each description *before* its corresponding command, mirroring ExploitPath.
"""

from __future__ import annotations

import html
import io
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

_BG = "#090d14"
_PANEL = "#0f1620"
_BORDER = "#1e2a38"
_FG = "#d7e0ea"
_MUTED = "#7c8b9c"
_GREEN = "#9FEF00"

_LABELS = {
    "es": {
        "writeup": "Write-up",
        "machine": "Máquina",
        "session": "Sesión",
        "os": "Sistema",
        "difficulty": "Dificultad",
        "phase": "Fase",
        "flags": "Flags",
        "user": "Usuario",
        "root": "Root",
        "captured": "capturada",
        "not_captured": "pendiente",
        "timeline": "Cronología de evidencias",
        "command": "Comando",
        "output": "Salida",
        "notes": "Notas",
        "evidence": "Evidencia",
        "no_steps": "Sin evidencias registradas.",
        "generated": "Generado",
    },
    "en": {
        "writeup": "Write-up",
        "machine": "Machine",
        "session": "Session",
        "os": "OS",
        "difficulty": "Difficulty",
        "phase": "Phase",
        "flags": "Flags",
        "user": "User",
        "root": "Root",
        "captured": "captured",
        "not_captured": "pending",
        "timeline": "Evidence timeline",
        "command": "Command",
        "output": "Output",
        "notes": "Notes",
        "evidence": "Evidence",
        "no_steps": "No evidence recorded.",
        "generated": "Generated",
    },
}


def _t(language: str, key: str) -> str:
    return _LABELS.get(language, _LABELS["es"]).get(key, key)


def _narrative_map(narrative: Optional[List[Dict[str, Any]]]) -> Dict[Any, Dict[str, str]]:
    out: Dict[Any, Dict[str, str]] = {}
    for entry in narrative or []:
        if not isinstance(entry, dict):
            continue
        step_id = entry.get("step_id", entry.get("stepId"))
        out[step_id] = {
            "title": str(entry.get("title") or ""),
            "description": str(entry.get("description") or ""),
        }
    return out


def _flag_summary(session: Dict[str, Any]) -> str:
    user = session.get("user_flag_captured")
    root = session.get("root_flag_captured")
    return f"user={'OK' if user else 'x'} / root={'OK' if root else 'x'}"


# ── HTML ───────────────────────────────────────────────────────────────────

def build_writeup_html(
    workspace: Dict[str, Any],
    narrative: Optional[List[Dict[str, Any]]] = None,
    language: str = "es",
) -> str:
    """Render a self-contained dark-mode HTML write-up. All values escaped."""
    session = workspace.get("session", {}) or {}
    steps: List[Dict[str, Any]] = workspace.get("steps", []) or []
    narr = _narrative_map(narrative)
    esc = html.escape

    def step_block(index: int, step: Dict[str, Any]) -> str:
        sid = step.get("id")
        entry = narr.get(sid, {})
        title = esc(entry.get("title") or f"{_t(language, 'evidence')} {index + 1}")
        description = esc(entry.get("description") or "").replace("\n", "<br>")
        command = esc(step.get("command") or "")
        output = esc(step.get("output") or "")
        notes = esc(step.get("notes") or "")
        flag = step.get("detected_flag_type")
        badge = ""
        if flag in ("user", "root"):
            badge = f'<span class="flag {flag}">{esc(flag)} flag</span>'
        desc_html = f'<p class="desc">{description}</p>' if description else ""
        notes_html = (
            f'<div class="notes"><span class="lbl">{_t(language, "notes")}</span>'
            f"<pre>{notes}</pre></div>"
            if notes else ""
        )
        return f"""
        <section class="step">
          <h3>{title} {badge}</h3>
          {desc_html}
          <div class="term">
            <div class="term-h"><span class="lbl">{_t(language, "command")}</span></div>
            <pre class="cmd">{command}</pre>
            <div class="term-h"><span class="lbl">{_t(language, "output")}</span></div>
            <pre class="out">{output}</pre>
          </div>
          {notes_html}
        </section>"""

    blocks = "".join(step_block(i, s) for i, s in enumerate(steps))
    if not blocks:
        blocks = f'<p class="muted">{_t(language, "no_steps")}</p>'

    machine = esc(str(session.get("machine_name") or ""))
    ip = esc(str(session.get("machine_ip") or ""))
    title = esc(str(session.get("title") or _t(language, "writeup")))
    os_name = esc(str(session.get("operating_system") or ""))
    difficulty = esc(str(session.get("difficulty") or ""))
    phase = esc(str(session.get("phase") or ""))

    return f"""<!doctype html>
<html lang="{esc(language)}" style="color-scheme:dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · {machine}</title>
<style>
:root{{--bg:{_BG};--panel:{_PANEL};--border:{_BORDER};--fg:{_FG};--muted:{_MUTED};--green:{_GREEN};}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font-family:"Space Grotesk","Segoe UI",system-ui,sans-serif;line-height:1.55}}
.wrap{{max-width:920px;margin:0 auto;padding:40px 24px 80px}}
header{{border-bottom:1px solid var(--border);padding-bottom:18px;margin-bottom:28px}}
h1{{margin:0 0 6px;font-size:1.9rem;letter-spacing:-.01em}}
h1 .accent{{color:var(--green)}}
.meta{{display:flex;flex-wrap:wrap;gap:10px 22px;color:var(--muted);font-size:.86rem}}
.meta b{{color:var(--fg);font-weight:600}}
.flags{{color:var(--green);font-weight:600}}
h2{{margin:34px 0 16px;font-size:1.2rem;color:var(--green);text-transform:uppercase;letter-spacing:.06em}}
.step{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:18px}}
.step h3{{margin:0 0 10px;font-size:1.02rem;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.desc{{margin:0 0 14px;color:#c6d2df}}
.flag{{font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;border:1px solid var(--green);color:var(--green);border-radius:999px;padding:2px 9px}}
.flag.root{{border-color:#ff5f6d;color:#ff8a94}}
.term{{background:#060a10;border:1px solid var(--border);border-radius:9px;overflow:hidden}}
.term-h{{padding:6px 12px;background:#0b121b;border-bottom:1px solid var(--border)}}
.lbl{{font-size:.68rem;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}}
pre{{margin:0;padding:12px 14px;white-space:pre-wrap;word-break:break-word;font-family:"JetBrains Mono","Cascadia Code",Consolas,monospace;font-size:.82rem}}
pre.cmd{{color:var(--green)}}
pre.out{{color:var(--fg)}}
.notes{{margin-top:10px}}
.notes pre{{color:var(--muted)}}
.muted{{color:var(--muted)}}
footer{{margin-top:40px;color:var(--muted);font-size:.78rem;border-top:1px solid var(--border);padding-top:14px}}
@media print{{body{{background:#fff;color:#111}}}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>{machine} <span class="accent">/</span> {title}</h1>
    <div class="meta">
      <span><b>{_t(language, "machine")}:</b> {machine} {ip}</span>
      <span><b>{_t(language, "os")}:</b> {os_name}</span>
      <span><b>{_t(language, "difficulty")}:</b> {difficulty}</span>
      <span><b>{_t(language, "phase")}:</b> {phase}</span>
      <span class="flags"><b>{_t(language, "flags")}:</b> {_flag_summary(session)}</span>
    </div>
  </header>
  <h2>{_t(language, "timeline")}</h2>
  {blocks}
  <footer>MIRV · {_t(language, "writeup")} · {_t(language, "generated")}</footer>
</div>
</body>
</html>"""


# ── PDF ────────────────────────────────────────────────────────────────────

def build_writeup_pdf(
    workspace: Dict[str, Any],
    narrative: Optional[List[Dict[str, Any]]] = None,
    language: str = "es",
) -> bytes:
    """Render a dark-mode PDF write-up (ReportLab). Returns raw bytes."""
    session = workspace.get("session", {}) or {}
    steps: List[Dict[str, Any]] = workspace.get("steps", []) or []
    narr = _narrative_map(narrative)

    bg = colors.HexColor(_BG)
    panel = colors.HexColor(_PANEL)
    border = colors.HexColor(_BORDER)
    green = colors.HexColor(_GREEN)
    fg = colors.HexColor(_FG)
    muted = colors.HexColor(_MUTED)

    title_style = ParagraphStyle("wt", fontName="Helvetica-Bold", fontSize=20, textColor=fg, leading=24)
    meta_style = ParagraphStyle("wm", fontName="Helvetica", fontSize=9, textColor=muted, leading=13)
    h2_style = ParagraphStyle("wh2", fontName="Helvetica-Bold", fontSize=12, textColor=green, spaceAfter=8, leading=15)
    step_style = ParagraphStyle("ws", fontName="Helvetica-Bold", fontSize=11, textColor=fg, leading=14)
    desc_style = ParagraphStyle("wd", fontName="Helvetica", fontSize=9.5, textColor=colors.HexColor("#c6d2df"), leading=13, alignment=TA_LEFT)
    lbl_style = ParagraphStyle("wl", fontName="Helvetica-Bold", fontSize=7, textColor=muted, leading=10)
    code_style = ParagraphStyle("wc", fontName="Courier", fontSize=8, textColor=green, leading=10.5)
    out_style = ParagraphStyle("wo", fontName="Courier", fontSize=8, textColor=fg, leading=10.5)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"{session.get('machine_name', '')} {session.get('title', '')}".strip(),
    )

    def _dark_canvas(canvas, _doc):
        canvas.saveState()
        canvas.setFillColor(bg)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    story: List[Any] = []
    machine = str(session.get("machine_name") or "")
    story.append(Paragraph(f"{html.escape(machine)} / {html.escape(str(session.get('title') or ''))}", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"{_t(language, 'os')}: {html.escape(str(session.get('operating_system') or ''))} · "
        f"{_t(language, 'difficulty')}: {html.escape(str(session.get('difficulty') or ''))} · "
        f"{_t(language, 'phase')}: {html.escape(str(session.get('phase') or ''))} · "
        f"{_t(language, 'flags')}: {_flag_summary(session)}",
        meta_style,
    ))
    story.append(Spacer(1, 14))
    story.append(Paragraph(_t(language, "timeline"), h2_style))

    if not steps:
        story.append(Paragraph(_t(language, "no_steps"), meta_style))

    for index, step in enumerate(steps):
        sid = step.get("id")
        entry = narr.get(sid, {})
        stitle = entry.get("title") or f"{_t(language, 'evidence')} {index + 1}"
        sdesc = entry.get("description") or ""
        block: List[Any] = [Paragraph(html.escape(stitle), step_style)]
        if sdesc:
            block.append(Spacer(1, 3))
            block.append(Paragraph(html.escape(sdesc).replace("\n", "<br/>"), desc_style))
        block.append(Spacer(1, 5))

        cmd_tbl = Table(
            [[Paragraph(_t(language, "command").upper(), lbl_style)],
             [Preformatted(step.get("command") or "", code_style)]],
            colWidths=[doc.width - 4],
        )
        out_tbl = Table(
            [[Paragraph(_t(language, "output").upper(), lbl_style)],
             [Preformatted(step.get("output") or "", out_style)]],
            colWidths=[doc.width - 4],
        )
        for tbl in (cmd_tbl, out_tbl):
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#060a10")),
                ("BOX", (0, 0), (-1, -1), 0.5, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
        block.extend([cmd_tbl, Spacer(1, 4), out_tbl])
        notes = step.get("notes")
        if notes:
            block.append(Spacer(1, 4))
            block.append(Paragraph(_t(language, "notes").upper(), lbl_style))
            block.append(Paragraph(html.escape(str(notes)).replace("\n", "<br/>"), desc_style))
        block.append(Spacer(1, 14))
        story.append(KeepTogether(block))

    doc.build(story, onFirstPage=_dark_canvas, onLaterPages=_dark_canvas)
    return buf.getvalue()
