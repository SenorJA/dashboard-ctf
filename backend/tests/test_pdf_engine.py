"""
Tests for backend.pdf_engine — Professional PDF generation engine.
"""

import pytest
from backend.pdf_engine import PdfEngine, PdfReport, PdfSection, PdfFinding


# ── Data Structure Tests ──


class TestPdfFinding:
    """PdfFinding dataclass defaults."""

    def test_defaults(self):
        f = PdfFinding(title="Test", severity="info")
        assert f.title == "Test"
        assert f.severity == "info"
        assert f.detail == ""
        assert f.target == ""
        assert f.tool == ""
        assert f.recommendation == ""
        assert f.references == []

    def test_full_fields(self):
        f = PdfFinding(
            title="SQL Injection",
            severity="critical",
            detail="Parameter id is vulnerable",
            target="example.com",
            tool="sqlmap",
            recommendation="Use parameterized queries",
            references=["https://owasp.org/sql-injection"],
        )
        assert f.severity == "critical"
        assert len(f.references) == 1


class TestPdfSection:
    """PdfSection dataclass defaults."""

    def test_defaults(self):
        s = PdfSection(heading="Test")
        assert s.heading == "Test"
        assert s.content == ""
        assert s.findings == []
        assert s.subsections == []

    def test_with_content(self):
        s = PdfSection(heading="Recon", content="## DNS\n\nFound 5 records")
        assert "DNS" in s.content


class TestPdfReport:
    """PdfReport dataclass defaults."""

    def test_defaults(self):
        r = PdfReport()
        assert r.title == "Security Assessment Report"
        assert r.author == "M.I.R.V."
        assert r.date  # auto-populated
        assert r.sections == []
        assert r.findings == []

    def test_custom_fields(self):
        r = PdfReport(
            title="Pentest Report",
            subtitle="Q3 2026",
            target="acme.com",
            executive_summary="Found 3 critical vulns.",
        )
        assert r.subtitle == "Q3 2026"
        assert r.target == "acme.com"


# ── Engine Tests ──


class TestPdfEngineInit:
    """PdfEngine initialization and styles."""

    def test_init(self):
        engine = PdfEngine()
        assert engine.styles is not None

    def test_has_custom_styles(self):
        engine = PdfEngine()
        # Custom styles stored as individual attributes
        assert hasattr(engine, '_h1_style')
        assert hasattr(engine, '_body_style')
        assert hasattr(engine, '_table_header_style')


class TestPdfEngineGenerate:
    """PdfEngine.generate() core functionality."""

    def test_empty_report(self):
        engine = PdfEngine()
        report = PdfReport(title="Empty Report")
        pdf = engine.generate(report)
        assert isinstance(pdf, bytes)
        assert len(pdf) > 0
        assert pdf[:5] == b'%PDF-'

    def test_report_with_sections(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Test Report",
            sections=[
                PdfSection(heading="Introduction", content="This is the intro."),
                PdfSection(heading="Findings", content="## Critical\n\nFound SQL injection."),
            ],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'
        assert len(pdf) > 1000

    def test_report_with_findings(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Vuln Report",
            findings=[
                PdfFinding(title="SQL Injection", severity="critical", detail="param id"),
                PdfFinding(title="XSS", severity="high", detail="reflected"),
                PdfFinding(title="Info Leak", severity="info", detail="server version"),
            ],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'
        assert len(pdf) > 2000

    def test_report_with_executive_summary(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Assessment",
            executive_summary="We found 5 critical vulnerabilities that need immediate attention.",
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_report_with_all_features(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Full Report",
            subtitle="Comprehensive Assessment",
            author="M.I.R.V.",
            target="example.com",
            executive_summary="Summary of findings.",
            sections=[
                PdfSection(heading="Recon", content="- DNS records found\n- Ports open: 80, 443"),
                PdfSection(heading="Web Analysis", content="## Headers\n\nMissing CSP header."),
            ],
            findings=[
                PdfFinding(title="Missing CSP", severity="high", tool="curl", target="example.com"),
                PdfFinding(title="Open Port", severity="info", tool="nmap", target="example.com"),
            ],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'
        assert len(pdf) > 3000

    def test_many_findings(self):
        engine = PdfEngine()
        findings = [
            PdfFinding(title=f"Vuln {i}", severity=["critical", "high", "medium", "low", "info"][i % 5])
            for i in range(50)
        ]
        report = PdfReport(title="50 Vulns", findings=findings)
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'


class TestSeverityColors:
    """Severity color mapping."""

    def test_all_severities(self):
        assert PdfEngine.severity_color("critical") == "#dc2626"
        assert PdfEngine.severity_color("high") == "#ea580c"
        assert PdfEngine.severity_color("medium") == "#ca8a04"
        assert PdfEngine.severity_color("low") == "#2563eb"
        assert PdfEngine.severity_color("info") == "#6b7280"

    def test_unknown_severity(self):
        color = PdfEngine.severity_color("unknown")
        assert color.startswith("#")


class TestSeverityBadges:
    """Severity badge text."""

    def test_all_badges(self):
        assert PdfEngine.severity_badge("critical") is not None
        assert PdfEngine.severity_badge("high") is not None
        assert PdfEngine.severity_badge("medium") is not None
        assert PdfEngine.severity_badge("low") is not None
        assert PdfEngine.severity_badge("info") is not None


class TestMarkdownRendering:
    """Markdown parsing in content."""

    def test_headers(self):
        engine = PdfEngine()
        report = PdfReport(
            title="MD Test",
            sections=[PdfSection(heading="Test", content="# H1\n## H2\n### H3\nBody text")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_bullet_lists(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Bullets",
            sections=[PdfSection(heading="List", content="- Item 1\n- Item 2\n- Item 3")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_code_blocks(self):
        engine = PdfEngine()
        content = "```python\nprint('hello')\nx = 1\n```"
        report = PdfReport(
            title="Code",
            sections=[PdfSection(heading="Code Block", content=content)],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_bold_text(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Bold",
            sections=[PdfSection(heading="Bold", content="This is **bold** text")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_inline_code(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Inline",
            sections=[PdfSection(heading="Code", content="Use `pip install` to install")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_horizontal_rule(self):
        engine = PdfEngine()
        report = PdfReport(
            title="HR",
            sections=[PdfSection(heading="Section", content="Before\n---\nAfter")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_tables(self):
        engine = PdfEngine()
        content = "| Name | Severity |\n|------|----------|\n| SQLi | critical |\n| XSS | high |"
        report = PdfReport(
            title="Table",
            sections=[PdfSection(heading="Table", content=content)],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_empty_content(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Empty",
            sections=[PdfSection(heading="Empty Section", content="")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_special_characters(self):
        engine = PdfEngine()
        report = PdfReport(
            title="Special",
            sections=[PdfSection(heading="XSS", content="<script>alert('xss')</script> & \"quotes\"")],
        )
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'


class TestSubsections:
    """Recursive section rendering."""

    def test_nested_subsections(self):
        engine = PdfEngine()
        sub = PdfSection(heading="Nested", content="Deep content")
        section = PdfSection(heading="Parent", content="Parent content", subsections=[sub])
        report = PdfReport(title="Nested", sections=[section])
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'

    def test_deep_nesting(self):
        engine = PdfEngine()
        deep = PdfSection(heading="Level 3", content="Deep")
        mid = PdfSection(heading="Level 2", subsections=[deep])
        top = PdfSection(heading="Level 1", subsections=[mid])
        report = PdfReport(title="Deep", sections=[top])
        pdf = engine.generate(report)
        assert pdf[:5] == b'%PDF-'
