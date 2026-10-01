"""
Tests for backend.lab_writeup (Pack 11 — dark-mode HTML/PDF write-up renderers).
"""

from backend.lab_writeup import build_writeup_html, build_writeup_pdf

WORKSPACE = {
    "session": {
        "id": "s1",
        "title": "Enumeración",
        "machine_name": "Lab <Uno>",
        "machine_ip": "10.10.11.47",
        "operating_system": "linux",
        "difficulty": "easy",
        "phase": "foothold",
        "user_flag_captured": True,
        "root_flag_captured": False,
    },
    "steps": [
        {
            "id": 1,
            "command": "nmap -sCV 10.10.11.47",
            "output": "22/tcp open ssh",
            "notes": "",
            "detected_flag_type": "none",
        },
        {
            "id": 2,
            "command": "cat <script>alert(1)</script>",
            "output": "resultado & evidencia",
            "notes": "Validación final",
            "detected_flag_type": "user",
        },
    ],
}

NARRATIVE = [
    {"step_id": 1, "title": "Enumeración inicial", "description": "El escaneo identifica la superficie expuesta."},
    {"step_id": 2, "title": "Validación", "description": "El segundo paso confirma el hallazgo anterior."},
]


class TestBuildWriteupHtml:
    def test_self_contained_dark_mode(self):
        doc = build_writeup_html(WORKSPACE, NARRATIVE, "es")
        assert doc.startswith("<!doctype html>")
        assert "--bg:#090d14" in doc
        assert "--green:#9FEF00" in doc
        assert "color-scheme:dark" in doc
        assert "http://" not in doc and "https://" not in doc

    def test_narrative_before_command(self):
        doc = build_writeup_html(WORKSPACE, NARRATIVE, "es")
        assert doc.index("El escaneo identifica") < doc.index("nmap -sCV")
        assert doc.index("El segundo paso confirma") < doc.index("cat &lt;script&gt;")

    def test_escapes_injection(self):
        doc = build_writeup_html(WORKSPACE, NARRATIVE, "es")
        assert "Lab &lt;Uno&gt;" in doc
        assert "cat &lt;script&gt;alert(1)&lt;/script&gt;" in doc
        assert "resultado &amp; evidencia" in doc
        assert "<script>alert(1)</script>" not in doc

    def test_no_steps_message(self):
        ws = {"session": {"title": "Empty"}, "steps": []}
        doc = build_writeup_html(ws, None, "en")
        assert "No evidence recorded." in doc

    def test_language_switch(self):
        ws = {"session": {}, "steps": []}
        assert "Cronología" in build_writeup_html(ws, None, "es")
        assert "Evidence timeline" in build_writeup_html(ws, None, "en")

    def test_works_without_narrative(self):
        doc = build_writeup_html(WORKSPACE, None, "es")
        assert "nmap -sCV" in doc


class TestBuildWriteupPdf:
    def test_returns_pdf_bytes(self):
        pdf = build_writeup_pdf(WORKSPACE, NARRATIVE, "es")
        assert isinstance(pdf, bytes)
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 800

    def test_handles_empty_and_unicode(self):
        ws = {"session": {"title": "Ø"}, "steps": []}
        pdf = build_writeup_pdf(ws, None, "en")
        assert pdf.startswith(b"%PDF")
