"""
Coverage-gap tests for backend/pdf_engine.py — edge branches.

Covers:
  - _cover_page(): extra metadata rows (skip reserved keys)
  - _render_section(): findings loop → _render_finding full block
  - _render_markdown_text(): empty text, broken table, numbered list
  - _render_code_block(): empty lines, trailing blank lines
  - _render_table(): empty rows, short row padding
  - _escape(): None input
"""

import pytest

from backend.pdf_engine import PdfEngine, PdfFinding, PdfReport, PdfSection


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
