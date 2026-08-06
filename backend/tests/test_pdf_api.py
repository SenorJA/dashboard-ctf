"""
Tests for PDF generation API endpoints.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


class TestGeneratePdfLegacy:
    """POST /api/generate-pdf — legacy markdown endpoint."""

    def test_basic(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "# Hello\n\nBody text here.",
            "title": "Test PDF",
        })
        assert resp.status_code == 200
        assert resp.headers.get("content-type", "").startswith("application/pdf")
        assert resp.content[:5] == b"%PDF-"

    def test_empty_content(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "",
            "title": "Empty",
        })
        assert resp.status_code == 200
        assert resp.content[:5] == b"%PDF-"

    def test_markdown_sections(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "## Section 1\n\nContent here\n\n## Section 2\n\nMore content",
            "title": "Sections",
        })
        assert resp.status_code == 200
        assert resp.content[:5] == b"%PDF-"

    def test_bullets_and_code(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "- Bullet 1\n- Bullet 2\n\n```\ncode here\n```",
            "title": "Lists",
        })
        assert resp.status_code == 200

    def test_custom_author(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "Hello",
            "title": "Custom",
            "author": "Security Auditor",
        })
        assert resp.status_code == 200

    def test_missing_body(self):
        resp = client.post("/api/generate-pdf")
        assert resp.status_code == 422

    def test_filename_in_headers(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "Test",
            "title": "My Report Name",
        })
        assert resp.status_code == 200
        cd = resp.headers.get("content-disposition", "")
        assert "My_Report_Name" in cd or "My Report" in cd

    def test_content_length(self):
        resp = client.post("/api/generate-pdf", json={
            "content": "Hello world",
            "title": "Size Check",
        })
        assert resp.status_code == 200
        cl = resp.headers.get("content-length")
        assert cl is not None
        assert int(cl) == len(resp.content)


class TestGeneratePdfProfessional:
    """POST /api/generate-pdf-professional — new professional endpoint."""

    def test_basic(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Pro Report",
            "executive_summary": "Found critical vulnerabilities.",
        })
        assert resp.status_code == 200
        assert resp.headers.get("content-type", "").startswith("application/pdf")
        assert resp.content[:5] == b"%PDF-"

    def test_with_sections(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "With Sections",
            "sections": [
                {"heading": "Recon", "content": "DNS records found."},
                {"heading": "Analysis", "content": "Ports 80, 443 open."},
            ],
        })
        assert resp.status_code == 200
        assert resp.content[:5] == b'%PDF-'

    def test_with_findings(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Vuln Report",
            "target": "example.com",
            "findings": [
                {"title": "SQL Injection", "severity": "critical", "detail": "param id", "tool": "sqlmap"},
                {"title": "XSS", "severity": "high", "detail": "reflected", "tool": "nikto"},
                {"title": "Info Leak", "severity": "info", "detail": "server header"},
            ],
        })
        assert resp.status_code == 200
        assert resp.content[:5] == b'%PDF-'
        assert len(resp.content) > 3000

    def test_with_all_fields(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Full Report",
            "subtitle": "Q3 2026 Assessment",
            "author": "M.I.R.V.",
            "target": "acme.com",
            "executive_summary": "We found 5 critical issues.",
            "sections": [
                {"heading": "Executive Summary", "content": "Overview of findings."},
                {"heading": "Methodology", "content": "- Passive recon\n- Active scanning\n- Manual testing"},
            ],
            "findings": [
                {"title": "RCE", "severity": "critical", "tool": "sqlmap", "target": "acme.com"},
                {"title": "Open Redirect", "severity": "medium", "tool": "nikto"},
            ],
        })
        assert resp.status_code == 200
        assert resp.content[:5] == b'%PDF-'

    def test_empty_findings(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "No Vulns",
            "executive_summary": "No vulnerabilities found.",
            "findings": [],
        })
        assert resp.status_code == 200

    def test_markdown_fallback(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Markdown Fallback",
            "content": "# Section 1\n\nContent here\n\n## Sub\n\nMore content",
        })
        assert resp.status_code == 200
        assert resp.content[:5] == b'%PDF-'

    def test_many_findings(self):
        findings = [
            {"title": f"Vuln {i}", "severity": ["critical", "high", "medium", "low", "info"][i % 5]}
            for i in range(30)
        ]
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "30 Vulns",
            "findings": findings,
        })
        assert resp.status_code == 200
        assert len(resp.content) > 5000

    def test_filename_header(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "My Assessment Report",
        })
        cd = resp.headers.get("content-disposition", "")
        assert "My_Assessment_Report" in cd or "My Assessment" in cd

    def test_subsections(self):
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Nested",
            "sections": [
                {
                    "heading": "Parent",
                    "content": "Parent content",
                    "subsections": [
                        {"heading": "Child", "content": "Child content"},
                    ],
                },
            ],
        })
        assert resp.status_code == 200

    def test_import_error_handling(self):
        """ImportError returns 500 with helpful message."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "backend.pdf_engine":
                raise ImportError("No module named 'backend.pdf_engine'")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, '__import__', side_effect=mock_import):
            resp = client.post("/api/generate-pdf-professional", json={
                "title": "Fail",
            })
            assert resp.status_code == 500
            data = resp.json()
            assert data.get("ok") is False


class TestPdfEngineModule:
    """Direct PdfEngine unit tests via API."""

    def test_engine_generates_valid_pdf(self):
        from backend.pdf_engine import PdfEngine, PdfReport, PdfSection, PdfFinding

        engine = PdfEngine()
        report = PdfReport(
            title="Engine Test",
            subtitle="Direct test",
            target="test.local",
            executive_summary="Testing the engine directly.",
            sections=[
                PdfSection(heading="Findings", content="- Critical SQL injection\n- Medium XSS"),
            ],
            findings=[
                PdfFinding(title="SQLi", severity="critical", tool="sqlmap"),
                PdfFinding(title="XSS", severity="medium", tool="nikto"),
            ],
        )
        pdf = engine.generate(report)
        assert isinstance(pdf, bytes)
        assert pdf[:5] == b'%PDF-'
        assert len(pdf) > 2000
