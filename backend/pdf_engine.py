"""
M.I.R.V. Professional PDF Engine
================================
ReportLab-based PDF generation with:
- Cover page with MIRV branding
- Table of contents
- Page numbers + footer
- Severity color coding for findings
- Code blocks with background
- Findings summary table
- Executive summary section
- Professional typography
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import HRFlowable

logger = logging.getLogger("vulnforge.pdf")

__all__ = ["PdfEngine", "PdfReport", "PdfSection", "PdfFinding"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAGE_WIDTH, PAGE_HEIGHT = A4  # 595.27, 841.89 points

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class PdfFinding:
    """Single finding for PDF rendering."""

    title: str
    severity: str  # critical, high, medium, low, info
    detail: str = ""
    target: str = ""
    tool: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class PdfSection:
    """A section in the PDF."""

    heading: str
    content: str = ""  # markdown-like text
    findings: List[PdfFinding] = field(default_factory=list)
    subsections: List[PdfSection] = field(default_factory=list)


@dataclass
class PdfReport:
    """Complete PDF report specification."""

    title: str = "Security Assessment Report"
    subtitle: str = ""
    author: str = "M.I.R.V."
    date: str = field(
        default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d")
    )
    target: str = ""
    executive_summary: str = ""
    sections: List[PdfSection] = field(default_factory=list)
    findings: List[PdfFinding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PdfEngine:
    """Professional PDF generation engine."""

    # Color palette
    COLORS = {
        "primary": "#1a2744",      # Dark navy
        "accent": "#3b8f8a",       # Teal accent
        "gold": "#d4a843",         # Gold title
        "critical": "#dc2626",     # Red
        "high": "#ea580c",         # Orange
        "medium": "#ca8a04",       # Yellow
        "low": "#2563eb",          # Blue
        "info": "#6b7280",         # Gray
        "bg_code": "#f3f4f6",      # Light gray for code blocks
        "bg_table": "#f9fafb",     # Table background
        "white": "#ffffff",
        "black": "#000000",
        "text": "#1f2937",         # Dark gray text
        "muted": "#9ca3af",        # Muted text
    }

    SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]

    # Frame dimensions for BaseDocTemplate (A4 minus margins)
    _MARGIN_LEFT = 20 * mm
    _MARGIN_RIGHT = 20 * mm
    _MARGIN_TOP = 25 * mm
    _MARGIN_BOTTOM = 25 * mm

    # -----------------------------------------------------------------------
    # Init
    # -----------------------------------------------------------------------

    def __init__(self) -> None:
        """Initialize styles and fonts."""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    # -----------------------------------------------------------------------
    # Custom paragraph styles
    # -----------------------------------------------------------------------

    def _setup_custom_styles(self) -> None:
        """Create all custom paragraph styles."""
        c = self.COLORS

        # ── Cover styles ──────────────────────────────────────────────────
        self._cover_title_style = ParagraphStyle(
            "CoverTitle",
            parent=self.styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=colors.HexColor(c["gold"]),
            alignment=TA_CENTER,
            spaceAfter=8 * mm,
        )
        self._cover_subtitle_style = ParagraphStyle(
            "CoverSubtitle",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor(c["white"]),
            alignment=TA_CENTER,
            spaceAfter=4 * mm,
        )
        self._cover_meta_style = ParagraphStyle(
            "CoverMeta",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor(c["white"]),
            alignment=TA_CENTER,
            spaceAfter=2 * mm,
        )

        # ── Section heading styles ────────────────────────────────────────
        self._h1_style = ParagraphStyle(
            "MIRV_H1",
            parent=self.styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor(c["primary"]),
            spaceBefore=6 * mm,
            spaceAfter=3 * mm,
        )
        self._h2_style = ParagraphStyle(
            "MIRV_H2",
            parent=self.styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor(c["accent"]),
            spaceBefore=5 * mm,
            spaceAfter=2 * mm,
        )
        self._h3_style = ParagraphStyle(
            "MIRV_H3",
            parent=self.styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor(c["primary"]),
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        )

        # ── Body / text ───────────────────────────────────────────────────
        self._body_style = ParagraphStyle(
            "MIRV_Body",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor(c["text"]),
            spaceAfter=2 * mm,
        )

        # ── Code ──────────────────────────────────────────────────────────
        self._code_style = ParagraphStyle(
            "MIRV_Code",
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor(c["text"]),
            leftIndent=4,
            rightIndent=4,
            spaceAfter=1,
            spaceBefore=1,
        )

        # ── Bullet ────────────────────────────────────────────────────────
        self._bullet_style = ParagraphStyle(
            "MIRV_Bullet",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor(c["text"]),
            leftIndent=16,
            bulletIndent=6,
            spaceAfter=1 * mm,
        )

        # ── TOC styles ────────────────────────────────────────────────────
        self._toc_title_style = ParagraphStyle(
            "TOC_Title",
            parent=self.styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor(c["primary"]),
            alignment=TA_LEFT,
            spaceAfter=8 * mm,
        )
        self._toc_h1_style = ParagraphStyle(
            "TOC_H1",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=16,
            textColor=colors.HexColor(c["primary"]),
            leftIndent=0,
            spaceAfter=1 * mm,
        )
        self._toc_h2_style = ParagraphStyle(
            "TOC_H2",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=14,
            textColor=colors.HexColor(c["text"]),
            leftIndent=12,
            spaceAfter=0.5 * mm,
        )

        # ── Table header / cell ───────────────────────────────────────────
        self._table_header_style = ParagraphStyle(
            "MIRV_TableHeader",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor(c["white"]),
            alignment=TA_LEFT,
        )
        self._table_cell_style = ParagraphStyle(
            "MIRV_TableCell",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor(c["text"]),
            alignment=TA_LEFT,
        )
        self._table_cell_bold_style = ParagraphStyle(
            "MIRV_TableCellBold",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor(c["text"]),
            alignment=TA_LEFT,
        )

        # ── Finding block styles ──────────────────────────────────────────
        self._finding_title_style = ParagraphStyle(
            "MIRV_FindingTitle",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor(c["primary"]),
            spaceAfter=1 * mm,
        )
        self._finding_detail_style = ParagraphStyle(
            "MIRV_FindingDetail",
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor(c["text"]),
            leftIndent=4,
            spaceAfter=1 * mm,
        )
        self._finding_label_style = ParagraphStyle(
            "MIRV_FindingLabel",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor(c["accent"]),
            leftIndent=4,
            spaceAfter=1 * mm,
        )

        # ── Footer / header (used in callbacks via canvas) ────────────────
        self._footer_style = ParagraphStyle(
            "MIRV_Footer",
            fontName="Helvetica",
            fontSize=7,
            leading=9,
            textColor=colors.HexColor(c["muted"]),
        )

        # ── Executive summary ─────────────────────────────────────────────
        self._exec_style = ParagraphStyle(
            "MIRV_ExecSummary",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=colors.HexColor(c["text"]),
            spaceAfter=3 * mm,
        )

    # ===================================================================
    # Public API
    # ===================================================================

    def generate(self, report: PdfReport) -> bytes:
        """Generate complete PDF report. Returns raw PDF bytes."""
        buffer = io.BytesIO()
        doc = self._build_document(buffer, report)
        story = self._build_story(report)

        try:
            doc.build(
                story,
                onFirstPage=self._cover_page_callback,
                onLaterPages=self._header_footer_callback,
            )
        except Exception:
            logger.exception("PDF build failed")
            raise

        pdf_bytes = buffer.getvalue()
        buffer.close()
        logger.info("PDF generated: %d bytes", len(pdf_bytes))
        return pdf_bytes

    # ===================================================================
    # Document builder
    # ===================================================================

    def _build_document(self, buffer: io.BytesIO, report: PdfReport) -> SimpleDocTemplate:
        """Create SimpleDocTemplate with proper margins."""
        return SimpleDocTemplate(
            buffer,
            pagesize=A4,
            topMargin=self._MARGIN_TOP,
            bottomMargin=self._MARGIN_BOTTOM,
            leftMargin=self._MARGIN_LEFT,
            rightMargin=self._MARGIN_RIGHT,
            title=report.title,
            author=report.author,
            subject=f"Security Assessment — {report.target}" if report.target else report.title,
        )

    # ===================================================================
    # Story builder
    # ===================================================================

    def _build_story(self, report: PdfReport) -> list:
        """Build the full story (list of flowables)."""
        story: list = []

        # 1. Cover page
        story.extend(self._cover_page(report))
        story.append(PageBreak())

        # 2. Table of contents
        story.extend(self._toc_page(report))
        story.append(PageBreak())

        # 3. Executive summary
        if report.executive_summary:
            story.extend(self._executive_summary(report))
            story.append(PageBreak())

        # 4. Findings summary table (if findings exist)
        if report.findings:
            story.extend(self._findings_summary_table(report))
            story.append(PageBreak())

        # 5. Content sections
        for section in report.sections:
            story.extend(self._render_section(section, level=0))

        return story

    # ===================================================================
    # Cover page
    # ===================================================================

    def _cover_page(self, report: PdfReport) -> list:
        """Professional cover page with MIRV branding."""
        flowables: list = []

        # Top spacer to push content towards the visual center
        flowables.append(Spacer(1, 60 * mm))

        # M.I.R.V. brand line
        brand_style = ParagraphStyle(
            "CoverBrand",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=14,
            textColor=colors.HexColor(self.COLORS["accent"]),
            alignment=TA_CENTER,
            spaceAfter=6 * mm,
        )
        flowables.append(Paragraph("M.I.R.V.", brand_style))

        # Teal accent line above the title
        flowables.append(
            HRFlowable(
                width="60%",
                thickness=2,
                color=colors.HexColor(self.COLORS["accent"]),
                spaceAfter=8 * mm,
                hAlign="CENTER",
            )
        )

        # Title
        flowables.append(Paragraph(self._escape(report.title), self._cover_title_style))

        # Subtitle (if provided)
        if report.subtitle:
            flowables.append(
                Paragraph(self._escape(report.subtitle), self._cover_subtitle_style)
            )

        # Teal accent line below the title
        flowables.append(
            HRFlowable(
                width="40%",
                thickness=1,
                color=colors.HexColor(self.COLORS["accent"]),
                spaceBefore=4 * mm,
                spaceAfter=10 * mm,
                hAlign="CENTER",
            )
        )

        # Meta block
        if report.target:
            flowables.append(
                Paragraph(
                    f"Target: {self._escape(report.target)}",
                    self._cover_meta_style,
                )
            )
        flowables.append(
            Paragraph(
                f"Author: {self._escape(report.author)}",
                self._cover_meta_style,
            )
        )
        flowables.append(
            Paragraph(
                f"Date: {report.date}",
                self._cover_meta_style,
            )
        )

        # Optional metadata rows
        for key, value in report.metadata.items():
            if key in ("title", "author", "date", "target", "subtitle"):
                continue
            flowables.append(
                Paragraph(
                    f"{self._escape(str(key))}: {self._escape(str(value))}",
                    self._cover_meta_style,
                )
            )

        return flowables

    # ===================================================================
    # Table of contents
    # ===================================================================

    def _toc_page(self, report: PdfReport) -> list:
        """Table of contents from sections."""
        flowables: list = []

        flowables.append(Paragraph("Table of Contents", self._toc_title_style))
        flowables.append(
            HRFlowable(
                width="100%",
                thickness=1,
                color=colors.HexColor(self.COLORS["accent"]),
                spaceAfter=6 * mm,
            )
        )

        # Static entries (always present)
        toc_entries: list[str] = []

        if report.executive_summary:
            toc_entries.append("Executive Summary")
        if report.findings:
            toc_entries.append("Findings Summary")

        # Walk sections
        for idx, section in enumerate(report.sections, start=1):
            toc_entries.append(f"{idx}. {section.heading}")
            for sub in section.subsections:
                toc_entries.append(f"    {idx}. {sub.heading}")

        for entry in toc_entries:
            is_sub = entry.startswith("    ")
            style = self._toc_h2_style if is_sub else self._toc_h1_style
            flowables.append(Paragraph(self._escape(entry.strip()), style))

        if not toc_entries:
            flowables.append(
                Paragraph(
                    "<i>No sections defined.</i>",
                    ParagraphStyle(
                        "TOC_Empty",
                        parent=self._body_style,
                        textColor=colors.HexColor(self.COLORS["muted"]),
                    ),
                )
            )

        return flowables

    # ===================================================================
    # Executive summary
    # ===================================================================

    def _executive_summary(self, report: PdfReport) -> list:
        """Executive summary section."""
        flowables: list = []

        flowables.append(Paragraph("Executive Summary", self._h1_style))
        flowables.append(
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=colors.HexColor(self.COLORS["accent"]),
                spaceAfter=4 * mm,
            )
        )

        # Render the summary as parsed markdown
        flowables.extend(self._render_markdown_text(report.executive_summary))

        # If there are findings, add a quick count table
        if report.findings:
            flowables.append(Spacer(1, 4 * mm))
            counts = self._count_by_severity(report.findings)
            summary_data = [
                [Paragraph("Severity", self._table_header_style),
                 Paragraph("Count", self._table_header_style)],
            ]
            for sev in self.SEVERITY_ORDER:
                cnt = counts.get(sev, 0)
                if cnt == 0:
                    continue
                sev_color = colors.HexColor(self.severity_color(sev))
                sev_para = Paragraph(
                    f'<font color="{self.severity_color(sev)}">'
                    f"<b>{sev.upper()}</b></font>",
                    self._table_cell_style,
                )
                summary_data.append([
                    sev_para,
                    Paragraph(str(cnt), self._table_cell_style),
                ])
            summary_data.append([
                Paragraph("<b>TOTAL</b>", self._table_cell_bold_style),
                Paragraph(f"<b>{len(report.findings)}</b>", self._table_cell_bold_style),
            ])

            t = Table(summary_data, colWidths=[80, 50])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(self.COLORS["primary"])),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(self.COLORS["white"])),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(self.COLORS["muted"])),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [
                    colors.HexColor(self.COLORS["bg_table"]),
                    colors.white,
                ]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor(self.COLORS["bg_table"])),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            flowables.append(t)

        return flowables

    # ===================================================================
    # Findings summary table
    # ===================================================================

    def _findings_summary_table(self, report: PdfReport) -> list:
        """Severity-colored findings summary table."""
        flowables: list = []

        flowables.append(Paragraph("Findings Summary", self._h1_style))
        flowables.append(
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=colors.HexColor(self.COLORS["accent"]),
                spaceAfter=4 * mm,
            )
        )

        # Sort by severity
        sorted_findings = sorted(
            report.findings,
            key=lambda f: self.SEVERITY_ORDER.index(f.severity.lower())
            if f.severity.lower() in self.SEVERITY_ORDER
            else len(self.SEVERITY_ORDER),
        )

        # Column widths: #, Title, Severity, Tool, Target
        usable_width = PAGE_WIDTH - self._MARGIN_LEFT - self._MARGIN_RIGHT
        col_widths = [
            usable_width * 0.06,   # #
            usable_width * 0.38,   # Title
            usable_width * 0.14,   # Severity
            usable_width * 0.18,   # Tool
            usable_width * 0.24,   # Target
        ]

        # Header row
        headers = ["#", "Title", "Severity", "Tool", "Target"]
        header_row = [
            Paragraph(f"<b>{h}</b>", self._table_header_style) for h in headers
        ]

        data = [header_row]

        for idx, finding in enumerate(sorted_findings, start=1):
            sev = finding.severity.lower()
            sev_label = sev.upper()
            sev_color_hex = self.severity_color(sev)

            sev_cell = Paragraph(
                f'<font color="{self.COLORS["white"]}"><b>{sev_label}</b></font>',
                ParagraphStyle(
                    f"SevCell_{sev}",
                    parent=self._table_cell_style,
                    alignment=TA_CENTER,
                ),
            )

            row = [
                Paragraph(str(idx), self._table_cell_style),
                Paragraph(self._escape(finding.title), self._table_cell_style),
                sev_cell,
                Paragraph(self._escape(finding.tool or "—"), self._table_cell_style),
                Paragraph(self._escape(finding.target or "—"), self._table_cell_style),
            ]
            data.append(row)

        t = Table(data, colWidths=col_widths, repeatRows=1)

        # Build table style commands
        style_cmds = [
            # Header
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(self.COLORS["primary"])),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(self.COLORS["white"])),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(self.COLORS["muted"])),
            # Padding
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]

        # Severity cell backgrounds + alternating row backgrounds
        for row_idx in range(1, len(data)):
            sev = sorted_findings[row_idx - 1].severity.lower()
            sev_bg = self.severity_color(sev)
            # Severity column background
            style_cmds.append(
                ("BACKGROUND", (2, row_idx), (2, row_idx), colors.HexColor(sev_bg))
            )
            # Alternating row background (for non-severity columns)
            if row_idx % 2 == 0:
                bg_color = colors.HexColor(self.COLORS["bg_table"])
                style_cmds.append(
                    ("BACKGROUND", (0, row_idx), (1, row_idx), bg_color)
                )
                style_cmds.append(
                    ("BACKGROUND", (3, row_idx), (-1, row_idx), bg_color)
                )

        t.setStyle(TableStyle(style_cmds))
        flowables.append(t)

        return flowables

    # ===================================================================
    # Section renderer
    # ===================================================================

    def _render_section(self, section: PdfSection, level: int = 0) -> list:
        """Recursively render a section with its content and findings."""
        flowables: list = []

        # Heading
        heading_map = {0: self._h1_style, 1: self._h2_style, 2: self._h3_style}
        style = heading_map.get(level, self._h3_style)
        flowables.append(Paragraph(self._escape(section.heading), style))
        flowables.append(
            HRFlowable(
                width="100%",
                thickness=0.5,
                color=colors.HexColor(self.COLORS["accent"]),
                spaceAfter=3 * mm,
            )
        )

        # Content (markdown-like)
        if section.content:
            flowables.extend(self._render_markdown_text(section.content))
            flowables.append(Spacer(1, 2 * mm))

        # Findings
        for finding in section.findings:
            flowables.extend(self._render_finding(finding))

        # Subsections (recursive)
        for sub in section.subsections:
            flowables.extend(self._render_section(sub, level=level + 1))

        return flowables

    # ===================================================================
    # Finding renderer
    # ===================================================================

    def _render_finding(self, finding: PdfFinding) -> list:
        """Render a single finding block with severity badge."""
        flowables: list = []
        sev = finding.severity.lower()
        sev_color_hex = self.severity_color(sev)
        badge = self.severity_badge(sev)

        # Title with severity badge
        title_text = (
            f'<font color="{sev_color_hex}"><b>[{badge} {sev.upper()}]</b></font>'
            f"  <b>{self._escape(finding.title)}</b>"
        )
        flowables.append(Paragraph(title_text, self._finding_title_style))

        # Colored left border via a 1-cell table trick
        border_color = colors.HexColor(sev_color_hex)

        # Detail
        if finding.detail:
            flowables.append(
                Paragraph(self._escape(finding.detail), self._finding_detail_style)
            )

        # Target & Tool line
        meta_parts = []
        if finding.target:
            meta_parts.append(f"Target: {self._escape(finding.target)}")
        if finding.tool:
            meta_parts.append(f"Tool: {self._escape(finding.tool)}")
        if meta_parts:
            flowables.append(
                Paragraph(
                    " | ".join(meta_parts),
                    ParagraphStyle(
                        "FindingMeta",
                        parent=self._finding_detail_style,
                        fontName="Helvetica-Oblique",
                        fontSize=8,
                        textColor=colors.HexColor(self.COLORS["muted"]),
                    ),
                )
            )

        # Recommendation
        if finding.recommendation:
            flowables.append(
                Paragraph(
                    f"<b>Recommendation:</b> {self._escape(finding.recommendation)}",
                    self._finding_detail_style,
                )
            )

        # References
        if finding.references:
            refs_text = "<b>References:</b> " + ", ".join(
                self._escape(ref) for ref in finding.references
            )
            flowables.append(
                Paragraph(refs_text, self._finding_detail_style)
            )

        # Wrap the whole finding in a border table
        inner_table = Table(
            [[flowables[-len(flowables):]]],
            colWidths=[
                PAGE_WIDTH - self._MARGIN_LEFT - self._MARGIN_RIGHT - 8 * mm
            ],
        )
        inner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(self.COLORS["bg_table"])),
            ("BOX", (0, 0), (-1, -1), 0.6, border_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBEFOREDECOR", (0, 0), (0, -1), 3, border_color),
        ]))

        # Replace the individual flowables we just added with the wrapper table.
        # We pop what we pushed and use the table instead.
        # Simpler approach: rebuild the finding block cleanly.
        wrapped: list = []

        # Build content cells for the inner table
        inner_flowables: list = []

        inner_flowables.append(Paragraph(title_text, self._finding_title_style))

        if finding.detail:
            inner_flowables.append(
                Paragraph(self._escape(finding.detail), self._finding_detail_style)
            )

        if meta_parts:
            inner_flowables.append(
                Paragraph(
                    " | ".join(meta_parts),
                    ParagraphStyle(
                        "FindingMeta2",
                        parent=self._finding_detail_style,
                        fontName="Helvetica-Oblique",
                        fontSize=8,
                        textColor=colors.HexColor(self.COLORS["muted"]),
                    ),
                )
            )

        if finding.recommendation:
            inner_flowables.append(
                Paragraph(
                    f"<b>Recommendation:</b> {self._escape(finding.recommendation)}",
                    self._finding_detail_style,
                )
            )

        if finding.references:
            refs_text = "<b>References:</b> " + ", ".join(
                self._escape(ref) for ref in finding.references
            )
            inner_flowables.append(Paragraph(refs_text, self._finding_detail_style))

        # Use a single-cell table to create the bordered box
        wrapper = Table(
            [[inner_flowables]],
            colWidths=[
                PAGE_WIDTH - self._MARGIN_LEFT - self._MARGIN_RIGHT - 6 * mm
            ],
        )
        wrapper.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(self.COLORS["bg_table"])),
            ("BOX", (0, 0), (-1, -1), 0.5, border_color),
            ("LINEBEFORE", (0, 0), (0, -1), 3, border_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        wrapped.append(Spacer(1, 3 * mm))
        wrapped.append(wrapper)
        wrapped.append(Spacer(1, 3 * mm))

        return wrapped

    # ===================================================================
    # Markdown parser
    # ===================================================================

    def _render_markdown_text(self, text: str) -> list:
        """Parse simple markdown to ReportLab flowables.

        Handles: ##, ###, - / * bullets, ``` code blocks ```,
        `inline`, **bold**, ---, | table |.
        """
        flowables: list = []
        if not text:
            return flowables

        lines = text.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.rstrip()

            # Empty line
            if not stripped:
                flowables.append(Spacer(1, 2 * mm))
                i += 1
                continue

            # Code block (fenced)
            if stripped.startswith("```"):
                code_lines: list[str] = []
                i += 1
                while i < len(lines) and not lines[i].rstrip().startswith("```"):
                    code_lines.append(lines[i])
                    i += 1
                i += 1  # skip closing ```
                flowables.extend(self._render_code_block(code_lines))
                continue

            # Horizontal rule
            if re.match(r"^---+$", stripped) or re.match(r"^___+$", stripped):
                flowables.append(
                    HRFlowable(
                        width="100%",
                        thickness=0.5,
                        color=colors.HexColor(self.COLORS["muted"]),
                        spaceBefore=2 * mm,
                        spaceAfter=2 * mm,
                    )
                )
                i += 1
                continue

            # Headers
            if stripped.startswith("### "):
                flowables.append(
                    Paragraph(self._inline_format(stripped[4:]), self._h3_style)
                )
                i += 1
                continue
            if stripped.startswith("## "):
                flowables.append(
                    Paragraph(self._inline_format(stripped[3:]), self._h2_style)
                )
                i += 1
                continue
            if stripped.startswith("# "):
                flowables.append(
                    Paragraph(self._inline_format(stripped[2:]), self._h1_style)
                )
                i += 1
                continue

            # Table (| ... | ... |)
            if stripped.startswith("|") and stripped.endswith("|"):
                table_rows: list[str] = []
                while i < len(lines):
                    row_stripped = lines[i].rstrip()
                    if not (
                        row_stripped.startswith("|")
                        and row_stripped.endswith("|")
                    ):
                        break
                    # Skip separator rows (| --- | --- |)
                    if re.match(r"^\|[\s\-:|]+\|$", row_stripped):
                        i += 1
                        continue
                    table_rows.append(row_stripped)
                    i += 1
                flowables.extend(self._render_table(table_rows))
                continue

            # Bullet list
            if re.match(r"^[-*]\s+", stripped):
                bullet_text = re.sub(r"^[-*]\s+", "", stripped)
                flowables.append(
                    Paragraph(
                        f"&bull;  {self._inline_format(bullet_text)}",
                        self._bullet_style,
                    )
                )
                i += 1
                continue

            # Numbered list
            m_num = re.match(r"^(\d+)\.\s+(.+)", stripped)
            if m_num:
                num = m_num.group(1)
                content = m_num.group(2)
                flowables.append(
                    Paragraph(
                        f"{num}.  {self._inline_format(content)}",
                        self._bullet_style,
                    )
                )
                i += 1
                continue

            # Inline code (full-line backtick)
            if stripped.startswith("`") and stripped.endswith("`") and len(stripped) > 1:
                flowables.extend(self._render_code_block([stripped[1:-1]]))
                i += 1
                continue

            # Normal paragraph
            flowables.append(
                Paragraph(self._inline_format(stripped), self._body_style)
            )
            i += 1

        return flowables

    # ===================================================================
    # Inline formatting helper
    # ===================================================================

    @staticmethod
    def _inline_format(text: str) -> str:
        """Apply inline markdown formatting to text for ReportLab XML.

        Handles: **bold**, `code`, ~~strike~~.
        """
        # Escape HTML entities first (but not our tags)
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")

        # **bold**
        text = re.sub(
            r"\*\*(.+?)\*\*",
            r"<b>\1</b>",
            text,
        )

        # `inline code`
        text = re.sub(
            r"`([^`]+?)`",
            r'<font face="Courier" size="8" color="#374151">\1</font>',
            text,
        )

        # ~~strikethrough~~
        text = re.sub(
            r"~~(.+?)~~",
            r"<strike>\1</strike>",
            text,
        )

        return text

    # ===================================================================
    # Code block renderer
    # ===================================================================

    def _render_code_block(self, lines: list[str]) -> list:
        """Render code block with gray background."""
        if not lines:
            return []

        # Remove trailing empty lines
        while lines and not lines[-1].strip():
            lines.pop()

        code_text = "\n".join(lines)
        # Escape XML entities
        code_text = (
            code_text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        # Create a Preformatted inside a Table for background color
        preformatted = Preformatted(code_text, self._code_style)

        usable_width = PAGE_WIDTH - self._MARGIN_LEFT - self._MARGIN_RIGHT
        t = Table([[preformatted]], colWidths=[usable_width - 4 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(self.COLORS["bg_code"])),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(self.COLORS["muted"])),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        return [Spacer(1, 2 * mm), t, Spacer(1, 2 * mm)]

    # ===================================================================
    # Table renderer
    # ===================================================================

    def _render_table(self, rows: list[str]) -> list:
        """Render a markdown table as ReportLab Table."""
        if not rows:
            return []

        usable_width = PAGE_WIDTH - self._MARGIN_LEFT - self._MARGIN_RIGHT
        parsed_rows: list[list[str]] = []
        for row in rows:
            # Split by | and strip
            cells = [c.strip() for c in row.split("|")]
            # Remove empty leading/trailing from split
            if cells and cells[0] == "":
                cells = cells[1:]
            if cells and cells[-1] == "":
                cells = cells[:-1]
            parsed_rows.append(cells)

        if not parsed_rows:
            return []

        num_cols = max(len(r) for r in parsed_rows)
        col_width = usable_width / num_cols
        col_widths = [col_width] * num_cols

        # Build table data with Paragraphs for word wrapping
        table_data: list[list] = []
        for row_idx, row_cells in enumerate(parsed_rows):
            styled_row: list = []
            for cell_text in row_cells:
                if row_idx == 0:
                    styled_row.append(
                        Paragraph(f"<b>{self._inline_format(cell_text)}</b>", self._table_header_style)
                    )
                else:
                    styled_row.append(
                        Paragraph(self._inline_format(cell_text), self._table_cell_style)
                    )
            # Pad short rows
            while len(styled_row) < num_cols:
                styled_row.append(Paragraph("", self._table_cell_style))
            table_data.append(styled_row)

        t = Table(table_data, colWidths=col_widths)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(self.COLORS["primary"])),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(self.COLORS["white"])),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor(self.COLORS["muted"])),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]
        # Alternating row backgrounds
        for row_idx in range(1, len(table_data)):
            if row_idx % 2 == 0:
                style_cmds.append(
                    ("BACKGROUND", (0, row_idx), (-1, row_idx),
                     colors.HexColor(self.COLORS["bg_table"]))
                )
        t.setStyle(TableStyle(style_cmds))

        return [Spacer(1, 2 * mm), t, Spacer(1, 2 * mm)]

    # ===================================================================
    # Page callbacks (canvas-level drawing)
    # ===================================================================

    def _cover_page_callback(self, canvas, doc) -> None:
        """Draw cover page background elements."""
        canvas.saveState()

        w, h = A4

        # Dark navy background for top portion
        canvas.setFillColor(colors.HexColor(self.COLORS["primary"]))
        canvas.rect(0, h * 0.55, w, h * 0.45, fill=1, stroke=0)

        # Teal accent strip at the bottom of the navy area
        canvas.setFillColor(colors.HexColor(self.COLORS["accent"]))
        canvas.rect(0, h * 0.55 - 3, w, 6, fill=1, stroke=0)

        # M.I.R.V. watermark in the navy area
        canvas.setFillColor(colors.HexColor(self.COLORS["accent"]))
        canvas.setFont("Helvetica-Bold", 60)
        canvas.setFillAlpha(0.08)
        canvas.drawCentredString(w / 2, h * 0.72, "M.I.R.V.")
        canvas.setFillAlpha(1.0)

        canvas.restoreState()

    def _header_footer_callback(self, canvas, doc) -> None:
        """Draw header and footer on content pages."""
        canvas.saveState()

        w, h = A4

        # ── Header: thin teal line ────────────────────────────────────────
        canvas.setStrokeColor(colors.HexColor(self.COLORS["accent"]))
        canvas.setLineWidth(1.5)
        canvas.line(
            self._MARGIN_LEFT,
            h - self._MARGIN_TOP + 6 * mm,
            w - self._MARGIN_RIGHT,
            h - self._MARGIN_TOP + 6 * mm,
        )

        # ── Footer ────────────────────────────────────────────────────────
        footer_y = self._MARGIN_BOTTOM - 12 * mm

        # Thin separator line above footer
        canvas.setStrokeColor(colors.HexColor(self.COLORS["muted"]))
        canvas.setLineWidth(0.4)
        canvas.line(self._MARGIN_LEFT, footer_y + 8, w - self._MARGIN_RIGHT, footer_y + 8)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor(self.COLORS["muted"]))

        # Left: M.I.R.V. branding
        canvas.drawString(self._MARGIN_LEFT, footer_y, "M.I.R.V. \u2014 Security Assessment")

        # Center: page number
        page_num = canvas.getPageNumber()
        canvas.drawCentredString(w / 2, footer_y, f"Page {page_num}")

        # Right: date
        canvas.drawRightString(
            w - self._MARGIN_RIGHT,
            footer_y,
            datetime.utcnow().strftime("%Y-%m-%d"),
        )

        canvas.restoreState()

    # ===================================================================
    # Utility methods
    # ===================================================================

    @staticmethod
    def severity_color(severity: str) -> str:
        """Get hex color for severity level."""
        mapping = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "info": "#6b7280",
        }
        return mapping.get(severity.lower(), "#6b7280")

    @staticmethod
    def severity_badge(severity: str) -> str:
        """Get text badge for severity (safe for all fonts/encodings)."""
        mapping = {
            "critical": "CRIT",
            "high": "HIGH",
            "medium": "MED",
            "low": "LOW",
            "info": "INFO",
        }
        return mapping.get(severity.lower(), "INFO")

    @staticmethod
    def _count_by_severity(findings: list) -> dict:
        """Count findings by severity level."""
        counts: dict = {}
        for f in findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _escape(text: str) -> str:
        """Escape XML/HTML special characters for ReportLab Paragraphs."""
        if not text:
            return ""
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        return text
