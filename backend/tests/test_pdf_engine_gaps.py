"""
Coverage-gap tests for backend/pdf_engine.py — edge branches.

Covers:
  - _cover_page(): extra metadata rows (skip reserved keys)
  - _render_section(): findings loop → _render_finding full block
  - _render_markdown_text(): empty text, broken table, numbered list
  - _render_code_block(): empty lines, trailing blank lines
  - _render_table(): empty rows, short row padding
  - _escape(): None input
  - Finding detail blocks (status/cve/cvss/evidence) via _findings_detail
  - Auto executive summary (severity/tool/target metrics)
  - KeepTogether wrapping for finding blocks
  - _estimate_block_height() height estimation
"""

import re
import zlib
import base64

import pytest

from backend.pdf_engine import PdfEngine, PdfFinding, PdfReport, PdfSection


def _pdf_text(pdf_bytes: bytes) -> bytes:
    """Extract decompressed text streams from a ReportLab-generated PDF.

    ReportLab 5.x writes page content streams as
    ``/ASCII85Decode /FlateDecode``; this helper decodes them so tests can
    assert on the actual rendered text.
    """
    texts = []
    for m in re.finditer(rb"stream\r?\n(.*?)~>endstream", pdf_bytes, re.S):
        raw = m.group(1)
        try:
            texts.append(zlib.decompress(base64.a85decode(raw, adobe=False)))
        except Exception:
            pass
    return b"\n".join(texts)


@pytest.fixture
def engine():
    return PdfEngine()


class TestCoverPageGaps:
    def test_metadata_rows(self, engine):
        report = PdfReport(
            title="T",
            subtitle="S",
            target="tgt",
            metadata={
                "title": "reserved",
                "author": "reserved",
                "date": "reserved",
                "target": "reserved",
                "subtitle": "reserved",
                "engagement_id": "ENG-001",
                "client": "Acme",
            },
        )
        flowables = engine._cover_page(report)
        rendered = "\n".join(getattr(f, "text", "") for f in flowables)
        # Reserved keys skipped — custom keys rendered
        assert "reserved" not in rendered
        assert "ENG-001" in rendered
        assert "Acme" in rendered


class TestRenderSectionGaps:
    def test_section_with_findings(self, engine):
        section = PdfSection(
            heading="Findings",
            content="## Overview",
            findings=[
                PdfFinding(
                    title="SQL Injection",
                    severity="high",
                    detail="Parameter id is vulnerable",
                    target="example.com",
                    tool="sqlmap",
                    recommendation="Use parameterized queries",
                    references=["https://owasp.org/sql-injection"],
                ),
                PdfFinding(
                    title="Info leak",
                    severity="info",
                    detail="",
                    target="",
                    tool="",
                    recommendation="",
                    references=[],
                ),
            ],
            subsections=[
                PdfSection(heading="Sub", content="text")
            ],
        )
        flowables = engine._render_section(section)
        assert len(flowables) > 0

    def test_finding_wrapper_is_table(self, engine):
        section = PdfSection(
            heading="H",
            findings=[PdfFinding(title="XSS", severity="critical", detail="d")],
        )
        flowables = engine._render_section(section)
        from reportlab.platypus import Table

        assert any(isinstance(f, Table) for f in flowables)


class TestRenderMarkdownTextGaps:
    def test_empty_text(self, engine):
        assert engine._render_markdown_text("") == []

    def test_broken_table(self, engine):
        flowables = engine._render_markdown_text("| a | b |\nplain text")
        assert len(flowables) > 0

    def test_numbered_list(self, engine):
        flowables = engine._render_markdown_text("1. First item\n2. Second item")
        rendered = "\n".join(getattr(f, "text", "") for f in flowables)
        assert "1." in rendered
        assert "First item" in rendered

    def test_strikethrough_inline(self, engine):
        flowables = engine._render_markdown_text("~~old~~ text")
        rendered = "\n".join(getattr(f, "text", "") for f in flowables)
        assert "<strike>" in rendered


class TestRenderCodeBlockGaps:
    def test_empty_lines(self, engine):
        assert engine._render_code_block([]) == []

    def test_trailing_blank_lines_removed(self, engine):
        flowables = engine._render_code_block(["code", ""])
        assert len(flowables) == 3  # Spacer, Table, Spacer


class TestRenderTableGaps:
    def test_empty_rows(self, engine):
        assert engine._render_table([]) == []

    def test_short_row_padded(self, engine):
        flowables = engine._render_table([
            "| header1 | header2 |",
            "| short |",
        ])
        assert len(flowables) == 3

    def test_separator_row_skipped(self, engine):
        flowables = engine._render_markdown_text("| a | b |\n| --- | --- |\n| 1 | 2 |")
        assert len(flowables) > 0


class TestEscapeGaps:
    def test_none_returns_empty(self):
        assert PdfEngine._escape(None) == ""

    def test_escape_special(self):
        assert PdfEngine._escape("a<b&c>d") == "a&lt;b&amp;c&gt;d"


# ── New PdfFinding fields + per-finding detail rendering ──


class TestFindingDetailRendering:
    """New PdfFinding fields (status/cve/cvss/evidence) in the detail blocks."""

    def test_defaults_unaffected(self):
        """Existing constructors without the new fields keep working."""
        f = PdfFinding(title="T", severity="info")
        assert f.status == ""
        assert f.cve == ""
        assert f.cvss is None
        assert f.evidence == ""

    def test_new_fields_rendered_in_pdf(self, engine):
        """Detail section renders status/cve/cvss/evidence text."""
        report = PdfReport(
            title="Detail",
            findings=[
                PdfFinding(
                    title="RCE via deserialization",
                    severity="critical",
                    detail="Java gadget chain",
                    target="app.example.com",
                    tool="ysoserial",
                    recommendation="Upgrade the library",
                    references=["https://example.com/advisory"],
                    status="open",
                    cve="CVE-2024-1234",
                    cvss=9.8,
                    evidence="POST /rpc -> serialized payload",
                ),
            ],
        )
        pdf = engine.generate(report)
        text = _pdf_text(pdf)
        assert b"Findings Detail" in text
        assert b"CVE-2024-1234" in text
        assert b"CVSS" in text
        assert b"9.8" in text
        assert b"Status: open" in text
        assert b"Evidence:" in text
        assert b"serialized payload" in text
        assert b"Upgrade the library" in text

    def test_evidence_multiline_preserved(self, engine):
        """Newlines inside evidence become line breaks, not lost text."""
        report = PdfReport(
            title="ML",
            findings=[
                PdfFinding(title="XSS", severity="high", evidence="line one\nline two"),
            ],
        )
        pdf = engine.generate(report)
        text = _pdf_text(pdf)
        assert b"line one" in text
        assert b"line two" in text


# ── Auto executive summary ──


class TestAutoExecutiveSummary:
    """generate() synthesizes an executive summary when none is provided."""

    def test_generated_when_empty(self, engine):
        """Multi-severity report gets counts, tools and targets tables."""
        report = PdfReport(
            title="Auto",
            findings=[
                PdfFinding(title="A", severity="critical", tool="nmap", target="t1"),
                PdfFinding(title="B", severity="high", tool="nmap", target="t1"),
                PdfFinding(title="C", severity="info", tool="curl", target="t2"),
            ],
        )
        pdf = engine.generate(report)
        text = _pdf_text(pdf)
        assert b"The analysis identified 3 findings" in text
        assert b"1 critical" in text
        assert b"1 high" in text
        assert b"1 informational" in text
        assert b"Top Tools" in text
        assert b"Top Targets" in text
        assert b"nmap" in text
        assert b"curl" in text
        assert b"t1" in text
        assert b"t2" in text

    def test_single_severity_sentence(self, engine):
        """A single-severity report uses the singular sentence form."""
        report = PdfReport(
            title="Single",
            findings=[PdfFinding(title="X", severity="low", tool="nmap")],
        )
        pdf = engine.generate(report)
        text = _pdf_text(pdf)
        assert b"The analysis identified 1 finding: 1 low." in text

    def test_unknown_severity_fallback(self, engine):
        """Unknown severities fall back to the plain count sentence."""
        report = PdfReport(
            title="Unknown",
            findings=[PdfFinding(title="X", severity="weird")],
        )
        pdf = engine.generate(report)
        text = _pdf_text(pdf)
        assert b"The analysis identified 1 finding." in text

    def test_existing_summary_not_replaced(self, engine):
        """An explicit executive_summary is preserved verbatim."""
        report = PdfReport(
            title="Custom",
            executive_summary="Custom executive summary text that must stay.",
            findings=[PdfFinding(title="X", severity="low")],
        )
        pdf = engine.generate(report)
        text = _pdf_text(pdf)
        assert b"Custom executive summary text that must stay." in text
        assert b"The analysis identified" not in text

    def test_report_not_mutated(self, engine):
        """generate() must not mutate the caller's report object."""
        report = PdfReport(
            title="Mut",
            findings=[PdfFinding(title="X", severity="high")],
        )
        engine.generate(report)
        assert report.executive_summary == ""


# ── KeepTogether wrapping ──


class TestKeepTogetherFindings:
    """Finding detail blocks are wrapped in KeepTogether."""

    def test_short_finding_wrapped(self, engine):
        """Short blocks are wrapped in a KeepTogether flowable."""
        from reportlab.platypus import KeepTogether

        block = engine._render_finding(PdfFinding(title="Short", severity="medium", detail="d"))
        wrapped = engine._wrap_keep_together(block)
        assert len(wrapped) == 1
        assert isinstance(wrapped[0], KeepTogether)

    def test_long_finding_does_not_crash(self, engine):
        """A finding taller than one page still generates a valid PDF."""
        report = PdfReport(
            title="Long",
            findings=[
                PdfFinding(
                    title="Very long finding",
                    severity="high",
                    detail="word " * 3000,
                    evidence="e " * 1000,
                    recommendation="rec " * 500,
                ),
            ],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b"%PDF-"
        assert len(pdf) > 1000

    def test_height_estimate_mixed_flowables(self, engine):
        """Height estimation handles Spacer/Paragraph/Table/other flowables."""
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            Spacer,
            Table as RLTable,
        )

        block = [
            Spacer(1, 10),
            Paragraph("hello world", engine._body_style),
            RLTable([["a", "b"]], colWidths=[50, 50]),
            HRFlowable(width="50%"),
        ]
        height = engine._estimate_block_height(block)
        assert height > 0


# ── Pre-existing markdown gaps ──


class TestMarkdownExtraGaps:
    def test_full_line_inline_code(self, engine):
        """A full line wrapped in backticks renders as a code block."""
        flowables = engine._render_markdown_text("`pip install x`")
        assert len(flowables) > 0
