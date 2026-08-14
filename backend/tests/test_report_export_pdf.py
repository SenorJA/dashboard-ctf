"""
Tests for POST /api/report/export-pdf — unified professional PDF export.

Covers:
  - findings provided in the request body → 200 application/pdf
  - no findings in body + mocked database layer → 200
  - no findings in body + database unavailable (None) → 400
  - reportlab ImportError → 500 JSON
"""

import builtins
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


class TestReportExportPdf:
    """POST /api/report/export-pdf behaviors."""

    def test_with_findings_in_body(self):
        """Body findings produce a downloadable PDF with proper headers."""
        resp = client.post("/api/report/export-pdf", json={
            "title": "Export Report",
            "subtitle": "Q3 2026",
            "author": "M.I.R.V.",
            "target": "example.com",
            "executive_summary": "Custom executive summary.",
            "findings": [
                {
                    "title": "SQL Injection",
                    "severity": "critical",
                    "detail": "Parameter id is vulnerable",
                    "target": "example.com",
                    "tool": "sqlmap",
                    "recommendation": "Use parameterized queries",
                    "references": ["https://owasp.org/sql-injection"],
                    "status": "open",
                    "cve": "CVE-2024-1234",
                    "cvss": 9.8,
                    "evidence": "POST /items?id=1'",
                },
            ],
        })
        assert resp.status_code == 200
        assert resp.headers.get("content-type", "").startswith("application/pdf")
        assert resp.content[:5] == b"%PDF-"
        cd = resp.headers.get("content-disposition", "")
        assert "mirv-report-" in cd
        assert ".pdf" in cd
        cl = resp.headers.get("content-length")
        assert cl is not None
        assert int(cl) == len(resp.content)

    def test_empty_findings_list_in_body_with_db_mocked(self):
        """An explicit empty findings list falls back to the database."""
        rows = [
            {"title": "Open Port", "severity": "high", "detail": "Port 22 open",
             "target": "db.example.com", "tool": "nmap", "status": 1},
            {"title": "XSS", "severity": "medium", "detail": "reflected",
             "target": "db.example.com", "tool": "nikto", "status": 0},
        ]
        with patch("backend.database.list_findings", return_value=rows) as mock_lf:
            resp = client.post("/api/report/export-pdf", json={
                "title": "From DB",
                "findings": [],
            })
        mock_lf.assert_called_once()
        assert resp.status_code == 200
        assert resp.headers.get("content-type", "").startswith("application/pdf")
        assert resp.content[:5] == b"%PDF-"

    def test_no_findings_key_with_db_mocked(self):
        """Missing findings key falls back to the database layer."""
        rows = [
            {"title": "SQLi", "severity": "critical", "detail": "param id",
             "target": "x.com", "tool": "sqlmap", "status": 0},
        ]
        with patch("backend.database.list_findings", return_value=rows) as mock_lf:
            resp = client.post("/api/report/export-pdf", json={"title": "From DB 2"})
        mock_lf.assert_called_once()
        assert resp.status_code == 200
        assert resp.content[:5] == b"%PDF-"

    def test_no_findings_db_unavailable(self):
        """Database returning None yields a 400 JSON error."""
        with patch("backend.database.list_findings", return_value=None):
            resp = client.post("/api/report/export-pdf", json={"title": "No DB"})
        assert resp.status_code == 400
        data = resp.json()
        assert data.get("ok") is False
        assert "No findings provided and database unavailable" in data.get("error", "")

    def test_db_rows_rendered_into_pdf(self):
        """DB rows are mapped onto the PDF (titles/tools appear in output)."""
        rows = [
            {"title": "DB_EXPORT_MARKER_ONE", "severity": "high",
             "detail": "found via db", "target": "db.example.com",
             "tool": "nmap", "status": 1},
        ]
        with patch("backend.database.list_findings", return_value=rows):
            resp = client.post("/api/report/export-pdf", json={"title": "Marker"})
        assert resp.status_code == 200
        assert resp.content[:5] == b"%PDF-"

    def test_import_error_returns_500(self):
        """Missing reportlab yields a 500 JSON error."""
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "backend.pdf_engine":
                raise ImportError("No module named 'backend.pdf_engine'")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=mock_import):
            resp = client.post("/api/report/export-pdf", json={
                "title": "Fail",
                "findings": [{"title": "X", "severity": "high"}],
            })
            assert resp.status_code == 500
            data = resp.json()
            assert data.get("ok") is False

    def test_invalid_findings_type_422(self):
        """A non-list findings field fails request validation with 422."""
        resp = client.post("/api/report/export-pdf", json={
            "title": "Bad",
            "findings": "not-a-list",
        })
        assert resp.status_code == 422

    def test_invalid_finding_entry_422(self):
        """A malformed finding entry (non-object) fails validation with 422."""
        resp = client.post("/api/report/export-pdf", json={
            "title": "Bad entry",
            "findings": ["not-an-object"],
        })
        assert resp.status_code == 422

    def test_missing_body_422(self):
        """A request without a body is rejected with 422."""
        resp = client.post("/api/report/export-pdf")
        assert resp.status_code == 422
