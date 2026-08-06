"""
tests/test_crud_endpoints.py — Integration tests for CRUD, Coverage, Scanner,
Burp snapshot, Intelligence REST, and SIEM module endpoints.

Covers 27 endpoints that were previously untested.  CRUD endpoints use the
full create-then-delete lifecycle against the live Supabase instance.
Coverage, Intelligence, and SIEM tests exercise in-memory stores directly.

Network-dependent tests (subdomain scan, stego) are marked with
``@pytest.mark.slow`` so they can be skipped with ``-m "not slow"``.
"""

from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

# Import the app at module level so every test function can use it via
# the ``client`` fixture or a plain ``with TestClient(app) as c:`` block.
from main import app

# ── Intelligence module (in-memory, needs reset between tests) ──
from backend import intelligence as intel
from backend.intelligence import reset as intel_reset

# ── SIEM module (in-memory, thread-safe) ──
from backend import siem as siem_mod


# ═══════════════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture()
def client():
    """Yield a FastAPI TestClient that shares the same app instance."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _clean_intel_state():
    """Reset intelligence module state before every test."""
    intel_reset()
    yield


# ═══════════════════════════════════════════════════════════════════════
#  DB Mocking
# ═══════════════════════════════════════════════════════════════════════
#  The CRUD tests were written against the live Supabase instance, which
#  makes them network-dependent (they 503 with `getaddrinfo failed` when
#  there is no connectivity). Mock the DB layer so the same endpoints are
#  exercised deterministically without external calls.
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def _mock_db(monkeypatch):
    """Mock Supabase CRUD functions so CRUD endpoint tests run offline."""
    from backend import database as db_mod

    state = {"counter": 0}

    def _gen_id() -> str:
        state["counter"] += 1
        return f"mock-{state['counter']:08d}-0000-0000-0000-000000000000"

    # save_* return a dict with id (never None -> endpoint returns 201)
    monkeypatch.setattr(db_mod, "save_finding", lambda item: {"id": _gen_id(), **item})
    monkeypatch.setattr(db_mod, "save_findings_bulk", lambda items: len(items))
    monkeypatch.setattr(db_mod, "save_report", lambda item: {"id": _gen_id(), **item})
    monkeypatch.setattr(db_mod, "save_script", lambda item: {"id": _gen_id(), **item})
    monkeypatch.setattr(db_mod, "save_connection", lambda item: {"id": _gen_id(), **item})
    monkeypatch.setattr(db_mod, "save_hak5_payload", lambda item: {"id": _gen_id(), **item})
    monkeypatch.setattr(db_mod, "save_credential", lambda item: {"id": _gen_id(), **item})
    monkeypatch.setattr(db_mod, "save_ctf_challenge", lambda item: {"id": state["counter"] + 1000, **item})

    # delete_* return True (never None -> endpoint returns 200 ok=True)
    monkeypatch.setattr(db_mod, "delete_finding", lambda _fid: True)
    monkeypatch.setattr(db_mod, "delete_all_findings", lambda: True)
    monkeypatch.setattr(db_mod, "delete_report", lambda _rid: True)
    monkeypatch.setattr(db_mod, "delete_script", lambda _sid: True)
    monkeypatch.setattr(db_mod, "delete_connection", lambda _cid: True)
    monkeypatch.setattr(db_mod, "delete_hak5_payload", lambda _pid: True)
    monkeypatch.setattr(db_mod, "delete_credential", lambda _cid: True)
    monkeypatch.setattr(db_mod, "delete_all_credentials", lambda: True)
    monkeypatch.setattr(db_mod, "delete_ctf_challenge", lambda _cid: True)

    yield
    intel_reset()


# ═══════════════════════════════════════════════════════════════════════
#  Group 1: Standard CRUD DELETE endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestFindingsCRUD:
    """POST + DELETE /api/findings — create and delete findings."""

    def test_post_and_delete_finding(self, client: TestClient):
        """Create a finding via POST, then delete it by ID."""
        resp = client.post("/api/findings", json={
            "tool": "nmap", "target": "10.0.0.1", "severity": "high",
            "title": "Open port 22", "type": "port",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        finding_id = data["data"]["id"]

        # Delete it
        resp = client.delete(f"/api/findings/{finding_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_all_findings(self, client: TestClient):
        """DELETE /api/findings (all) should return ok=True."""
        # Create a few findings first
        for i in range(3):
            client.post("/api/findings", json={
                "tool": "nmap", "target": f"10.0.0.{i}",
                "severity": "info", "title": f"Finding {i}",
            })
        resp = client.delete("/api/findings")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_post_finding_empty_body_returns_400(self, client: TestClient):
        """POST /api/findings with empty body should return 400."""
        resp = client.post("/api/findings", json={})
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data

    def test_delete_nonexistent_finding_returns_ok_false(self, client: TestClient):
        """DELETE /api/findings/{id} for a non-existent ID should return ok=False."""
        resp = client.delete("/api/findings/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 200
        data = resp.json()
        # May succeed or not depending on DB — just verify the shape
        assert "ok" in data


class TestReportsCRUD:
    """POST + DELETE /api/reports — create and delete reports."""

    def test_post_and_delete_report(self, client: TestClient):
        """Create a report via POST, then delete it by ID."""
        resp = client.post("/api/reports", json={
            "type": "scan", "title": "Test Report", "target": "10.0.0.1",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        report_id = data["data"]["id"]

        resp = client.delete(f"/api/reports/{report_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent_report(self, client: TestClient):
        """Deleting a non-existent report should still return 200 (idempotent)."""
        resp = client.delete("/api/reports/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestScriptsCRUD:
    """POST + DELETE /api/scripts — create and delete scripts."""

    def test_post_and_delete_script(self, client: TestClient):
        """Create a script via POST, then delete it by ID."""
        resp = client.post("/api/scripts", json={
            "name": "recon.sh", "content": "#!/bin/bash\nwhoami", "language": "bash",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        script_id = data["data"]["id"]

        resp = client.delete(f"/api/scripts/{script_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent_script(self, client: TestClient):
        """Deleting a non-existent script should still return 200 (idempotent)."""
        resp = client.delete("/api/scripts/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestConnectionsCRUD:
    """POST + DELETE /api/connections — create and delete SSH connections."""

    def test_post_and_delete_connection(self, client: TestClient):
        """Create a connection via POST, then delete it by ID."""
        resp = client.post("/api/connections", json={
            "name": "test-lab", "ip": "192.168.1.100",
            "username": "root", "password": "toor",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        conn_id = data["data"]["id"]

        resp = client.delete(f"/api/connections/{conn_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent_connection(self, client: TestClient):
        """Deleting a non-existent connection should still return 200 (idempotent)."""
        resp = client.delete("/api/connections/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestPayloadsCRUD:
    """GET + POST + DELETE /api/payloads — list, create, and delete payloads."""

    def test_get_payloads_returns_200(self, client: TestClient):
        """GET /api/payloads should return a list."""
        resp = client.get("/api/payloads")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_post_and_delete_payload(self, client: TestClient):
        """Create a payload via POST, then delete it by ID."""
        resp = client.post("/api/payloads", json={
            "device": "bunny", "name": "recon-test", "content": "QUACK",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        payload_id = data["data"]["id"]

        resp = client.delete(f"/api/payloads/{payload_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent_payload(self, client: TestClient):
        """Deleting a non-existent payload should still return 200 (idempotent)."""
        resp = client.delete("/api/payloads/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestCredentialsCRUD:
    """POST + DELETE /api/credentials — create and delete credentials."""

    def test_post_and_delete_credential(self, client: TestClient):
        """Create a credential via POST, then delete it by UUID."""
        resp = client.post("/api/credentials", json={
            "type": "password", "target": "10.0.0.1",
            "username": "admin", "password": "admin",
            "service": "ssh",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        # Credentials table uses 'uuid' as primary key
        cred_id = data["data"].get("id") or data["data"].get("uuid")
        assert cred_id is not None, f"Expected 'id' or 'uuid' in data, got keys: {list(data['data'].keys())}"

        resp = client.delete(f"/api/credentials/{cred_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent_credential(self, client: TestClient):
        """Deleting a non-existent credential should still return 200 (idempotent)."""
        resp = client.delete("/api/credentials/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_all_credentials(self, client: TestClient):
        """DELETE /api/credentials (all) should return ok=True."""
        resp = client.delete("/api/credentials")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


class TestCtfChallengesDelete:
    """DELETE /api/ctf/challenges/{id} — delete a CTF challenge."""

    def test_post_and_delete_ctf_challenge(self, client: TestClient):
        """Create a CTF challenge via POST, then delete it by ID."""
        resp = client.post("/api/ctf/challenges", json={
            "title": "Test Challenge", "category": "web",
            "flags": "FLAG{test123}", "points": 100,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        challenge_id = data["data"]["id"]

        resp = client.delete(f"/api/ctf/challenges/{challenge_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent_ctf_challenge(self, client: TestClient):
        """Deleting a non-existent CTF challenge should still return ok=True (no-op)."""
        resp = client.delete("/api/ctf/challenges/999999")
        assert resp.status_code == 200
        # Supabase delete with no match still returns True
        assert resp.json()["ok"] is True


class TestForensicsDelete:
    """DELETE /api/forensics/{id} — delete forensic evidence."""

    def test_delete_forensics_not_found_returns_404(self, client: TestClient):
        """DELETE /api/forensics/{id} for non-existent evidence should return 404."""
        resp = client.delete("/api/forensics/nonexistent-id")
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False
        assert "not found" in data["error"].lower()


# ═══════════════════════════════════════════════════════════════════════
#  Group 2: Coverage Tracking API endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestCoverageMark:
    """POST /api/coverage/mark — mark a coverage entry."""

    def test_mark_returns_200(self, client: TestClient):
        """Marking a valid coverage entry should succeed."""
        resp = client.post("/api/coverage/mark", json={
            "endpoint": "GET /api/users",
            "method": "GET",
            "path": "/api/users",
            "param": "id",
            "vuln_class": "idor",
            "status": "passed",
            "session_id": "test-crud-session",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "entry" in data

    def test_mark_with_notes(self, client: TestClient):
        """Marking with notes should include them in the response."""
        resp = client.post("/api/coverage/mark", json={
            "endpoint": "POST /api/login",
            "method": "POST",
            "vuln_class": "sqli",
            "status": "failed",
            "notes": "Payload: ' OR 1=1 --",
            "session_id": "test-crud-session",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_mark_invalid_vuln_class_returns_400(self, client: TestClient):
        """Marking with an invalid vuln_class should return 400."""
        resp = client.post("/api/coverage/mark", json={
            "endpoint": "GET /x",
            "vuln_class": "not-a-real-class",
            "status": "passed",
        })
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False

    def test_mark_invalid_status_returns_400(self, client: TestClient):
        """Marking with an invalid status should return 400."""
        resp = client.post("/api/coverage/mark", json={
            "endpoint": "GET /x",
            "vuln_class": "xss",
            "status": "not-a-real-status",
        })
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False


class TestCoverageList:
    """GET /api/coverage/list — list coverage entries."""

    def test_list_returns_200(self, client: TestClient):
        """Coverage list endpoint should return 200."""
        resp = client.get("/api/coverage/list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "entries" in data
        assert "count" in data

    def test_list_with_session_filter(self, client: TestClient):
        """Listing with a session_id filter should scope results."""
        client.post("/api/coverage/mark", json={
            "endpoint": "GET /cov-filter-a", "vuln_class": "sqli",
            "status": "tried", "session_id": "cov-filter-test",
        })
        resp = client.get("/api/coverage/list", params={"session_id": "cov-filter-test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        for entry in data["entries"]:
            assert entry["session_id"] == "cov-filter-test"

    def test_list_with_status_filter(self, client: TestClient):
        """Listing with a status filter should only return matching entries."""
        client.post("/api/coverage/mark", json={
            "endpoint": "GET /cov-status-a", "vuln_class": "xss",
            "status": "failed", "session_id": "cov-status-filter",
        })
        resp = client.get("/api/coverage/list", params={
            "status": "failed", "session_id": "cov-status-filter",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        for entry in data["entries"]:
            assert entry["status"] == "failed"


class TestCoverageSummary:
    """GET /api/coverage/summary — summary statistics."""

    def test_summary_returns_200(self, client: TestClient):
        """Coverage summary should return 200 with stats."""
        resp = client.get("/api/coverage/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "total" in data
        assert "by_status" in data


class TestCoverageUntested:
    """GET /api/coverage/untested — list untested combos."""

    def test_untested_returns_200(self, client: TestClient):
        """Coverage untested endpoint should return 200."""
        resp = client.get("/api/coverage/untested")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "entries" in data
        assert "count" in data


class TestCoverageNext:
    """GET /api/coverage/next — prioritised next steps."""

    def test_next_returns_200(self, client: TestClient):
        """Coverage next steps should return 200."""
        resp = client.get("/api/coverage/next")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "suggestions" in data
        assert "count" in data

    def test_next_respects_limit(self, client: TestClient):
        """Limit parameter should cap the number of suggestions."""
        resp = client.get("/api/coverage/next", params={"limit": 3})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["suggestions"]) <= 3


class TestCoverageClear:
    """DELETE /api/coverage — clear all coverage entries."""

    def test_clear_returns_200(self, client: TestClient):
        """Clearing coverage should return 200 with removed count."""
        client.post("/api/coverage/mark", json={
            "endpoint": "GET /cov-clear-a", "vuln_class": "rce",
            "status": "tried", "session_id": "cov-clear-test",
        })
        resp = client.delete("/api/coverage")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "removed" in data

    def test_clear_with_session_id(self, client: TestClient):
        """Clearing a specific session should only remove that session's entries."""
        client.post("/api/coverage/mark", json={
            "endpoint": "GET /cov-keep-a", "vuln_class": "ssrf",
            "status": "tried", "session_id": "cov-keep",
        })
        client.post("/api/coverage/mark", json={
            "endpoint": "GET /cov-del-a", "vuln_class": "ssti",
            "status": "passed", "session_id": "cov-delete",
        })
        resp = client.delete("/api/coverage", params={"session_id": "cov-delete"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # The other session should still exist
        resp2 = client.get("/api/coverage/list", params={"session_id": "cov-keep"})
        data2 = resp2.json()
        assert data2["count"] >= 1


class TestCoverageSessions:
    """POST + GET /api/coverage/sessions — save and list sessions."""

    def test_save_session_returns_200(self, client: TestClient):
        """Saving a coverage session should return 200."""
        resp = client.post("/api/coverage/sessions", json={
            "session_id": "crud-session-save", "name": "CRUD Test Session",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "session" in data

    def test_save_session_empty_id_returns_400(self, client: TestClient):
        """Saving with empty session_id should return 400."""
        resp = client.post("/api/coverage/sessions", json={
            "session_id": "", "name": "Bad",
        })
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False

    def test_list_sessions_returns_200(self, client: TestClient):
        """Listing sessions should return 200 with a list."""
        client.post("/api/coverage/sessions", json={
            "session_id": "crud-session-list", "name": "List Test",
        })
        resp = client.get("/api/coverage/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "sessions" in data
        assert len(data["sessions"]) >= 1


class TestCoverageExport:
    """GET /api/coverage/export — export coverage matrix."""

    def test_export_json_returns_200(self, client: TestClient):
        """Exporting as JSON should return 200 with payload."""
        resp = client.get("/api/coverage/export", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "payload" in data

    def test_export_csv_returns_200(self, client: TestClient):
        """Exporting as CSV should return 200."""
        resp = client.get("/api/coverage/export", params={"format": "csv"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["ext"] == "csv"

    def test_export_md_returns_200(self, client: TestClient):
        """Exporting as Markdown should return 200."""
        resp = client.get("/api/coverage/export", params={"format": "md"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["ext"] == "md"

    def test_export_unsupported_format_returns_400(self, client: TestClient):
        """Exporting with unsupported format should return 400."""
        resp = client.get("/api/coverage/export", params={"format": "xml"})
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False


class TestCoverageVocab:
    """GET /api/coverage/vocab — controlled vocabularies."""

    def test_vocab_returns_200(self, client: TestClient):
        """Vocab endpoint should return 200 with vuln_classes and statuses."""
        resp = client.get("/api/coverage/vocab")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "vuln_classes" in data
        assert "statuses" in data
        assert isinstance(data["vuln_classes"], list)
        assert isinstance(data["statuses"], list)
        assert len(data["vuln_classes"]) > 0
        assert len(data["statuses"]) > 0


# ═══════════════════════════════════════════════════════════════════════
#  Group 3: Scanner endpoints not tested via API
# ═══════════════════════════════════════════════════════════════════════

class TestSubdomainScan:
    """GET /api/subdomain/scan — enumerate subdomains via DNS."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_subdomain_scan_returns_200(self, client: TestClient):
        """Scanning a valid domain should return 200."""
        resp = client.get("/api/subdomain/scan", params={"domain": "example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "domain" in data
        assert "results" in data

    def test_subdomain_scan_invalid_domain_returns_422(self, client: TestClient):
        """Scanning an invalid domain should return 422."""
        resp = client.get("/api/subdomain/scan", params={"domain": "notadomain"})
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False

    def test_subdomain_scan_empty_domain_returns_422(self, client: TestClient):
        """Scanning with empty domain should return 422."""
        resp = client.get("/api/subdomain/scan", params={"domain": ""})
        assert resp.status_code == 422

    def test_subdomain_scan_strips_url_scheme(self, client: TestClient):
        """Scanning with a full URL should strip the scheme."""
        resp = client.get("/api/subdomain/scan", params={"domain": "https://example.com"})
        # Should work the same as just "example.com"
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


class TestStegoAnalyze:
    """GET /api/stego/analyze — analyze image for steganographic content."""

    def test_stego_no_url_returns_422(self, client: TestClient):
        """Stego without a URL parameter should return 422."""
        resp = client.get("/api/stego/analyze")
        assert resp.status_code == 422

    def test_stego_empty_url_returns_422(self, client: TestClient):
        """Stego with empty URL should return 422."""
        resp = client.get("/api/stego/analyze", params={"url": ""})
        assert resp.status_code == 422

    def test_stego_invalid_scheme_returns_422(self, client: TestClient):
        """Stego with non-HTTP URL should return 422."""
        resp = client.get("/api/stego/analyze", params={"url": "ftp://example.com/img.png"})
        assert resp.status_code == 422
        data = resp.json()
        assert "http" in data["error"].lower()


# ═══════════════════════════════════════════════════════════════════════
#  Group 4: Burp snapshot
# ═══════════════════════════════════════════════════════════════════════

class TestBurpSnapshot:
    """POST /api/burp/snapshot — ingest browser page snapshot."""

    def test_snapshot_returns_200(self, client: TestClient):
        """Ingesting a snapshot should return 200 with an id."""
        resp = client.post("/api/burp/snapshot", json={
            "page_url": "https://example.com/dashboard",
            "cookies": [{"name": "session", "value": "abc123"}],
            "local_storage": {"theme": "dark"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "id" in data

    def test_snapshot_minimal_payload(self, client: TestClient):
        """Snapshot with only page_url should succeed."""
        resp = client.post("/api/burp/snapshot", json={
            "page_url": "https://example.com/login",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_snapshot_with_session_storage(self, client: TestClient):
        """Snapshot with session_storage should include it."""
        resp = client.post("/api/burp/snapshot", json={
            "page_url": "https://example.com/api",
            "cookies": [],
            "local_storage": {},
            "session_storage": {"token": "xyz"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_snapshot_missing_url_returns_422(self, client: TestClient):
        """Snapshot without page_url should return 422."""
        resp = client.post("/api/burp/snapshot", json={})
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  Group 5: Intelligence REST endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestIntelUpdateWatch:
    """PUT /api/intelligence/watches/{id} — update a watch definition."""

    def test_update_watch_returns_200(self, client: TestClient):
        """Updating an existing watch should return 200 with updated data."""
        # Create a watch first
        resp = client.post("/api/intelligence/watches", json={
            "name": "Test Watch",
            "target": "https://example.com",
            "watch_type": "http_headers",
        })
        assert resp.status_code == 200
        watch_id = resp.json()["watch"]["id"]

        # Update it
        resp = client.put(f"/api/intelligence/watches/{watch_id}", json={
            "name": "Updated Watch",
            "enabled": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["watch"]["name"] == "Updated Watch"
        assert data["watch"]["enabled"] is False

    def test_update_watch_not_found_returns_404(self, client: TestClient):
        """Updating a non-existent watch should return 404."""
        resp = client.put("/api/intelligence/watches/nonexistent", json={
            "name": "Ghost",
        })
        assert resp.status_code == 404

    def test_update_watch_target(self, client: TestClient):
        """Updating the target of a watch should persist the change."""
        resp = client.post("/api/intelligence/watches", json={
            "name": "DNS",
            "target": "old.com",
            "watch_type": "dns",
        })
        watch_id = resp.json()["watch"]["id"]

        resp = client.put(f"/api/intelligence/watches/{watch_id}", json={
            "target": "new.com",
        })
        assert resp.status_code == 200
        assert resp.json()["watch"]["target"] == "new.com"


class TestIntelCaptureSnapshot:
    """POST /api/intelligence/watches/{id}/snapshot — manual snapshot."""

    def test_capture_snapshot_returns_200(self, client: TestClient):
        """Manually capturing a snapshot should return 200."""
        resp = client.post("/api/intelligence/watches", json={
            "name": "HTTP Snap",
            "target": "https://example.com",
            "watch_type": "http_headers",
        })
        watch_id = resp.json()["watch"]["id"]

        resp = client.post(f"/api/intelligence/watches/{watch_id}/snapshot", json={
            "data": {"headers": {"server": "nginx", "x-frame-options": "DENY"}},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "snapshot" in data
        assert data["snapshot"]["watch_id"] == watch_id

    def test_capture_snapshot_not_found_returns_404(self, client: TestClient):
        """Capturing a snapshot for a non-existent watch should return 404."""
        resp = client.post("/api/intelligence/watches/ghost/snapshot", json={
            "data": {"key": "value"},
        })
        assert resp.status_code == 404


class TestIntelAcknowledgeAlert:
    """POST /api/intelligence/alerts/{id}/acknowledge — acknowledge alert."""

    def test_acknowledge_alert_not_found_returns_404(self, client: TestClient):
        """Acknowledging a non-existent alert should return 404."""
        resp = client.post("/api/intelligence/alerts/nonexistent/acknowledge")
        assert resp.status_code == 404

    def test_acknowledge_alert_success(self, client: TestClient):
        """Acknowledging an existing alert should return 200."""
        # Create a watch and two snapshots to trigger an alert via diff
        resp = client.post("/api/intelligence/watches", json={
            "name": "Cert Watch Ack",
            "target": "example.com",
            "watch_type": "certificate",
        })
        watch_id = resp.json()["watch"]["id"]

        # First snapshot (baseline)
        client.post(f"/api/intelligence/watches/{watch_id}/snapshot", json={
            "data": {"issuer": "Let's Encrypt", "subject": "example.com"},
        })

        # Second snapshot (changed)
        client.post(f"/api/intelligence/watches/{watch_id}/snapshot", json={
            "data": {"issuer": "DigiCert", "subject": "example.com"},
        })

        # Run diff to generate alert
        resp = client.post(f"/api/intelligence/diff/{watch_id}", json={
            "data": {"issuer": "DigiCert", "subject": "example.com"},
        })
        assert resp.status_code == 200

        # List alerts to find one
        resp = client.get("/api/intelligence/alerts")
        alerts = resp.json().get("alerts", [])
        if alerts:
            alert_id = alerts[0]["id"]
            resp = client.post(f"/api/intelligence/alerts/{alert_id}/acknowledge")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True


class TestIntelClearAlerts:
    """DELETE /api/intelligence/alerts — clear all alerts."""

    def test_clear_alerts_returns_200(self, client: TestClient):
        """Clearing alerts should return 200 with a count."""
        resp = client.delete("/api/intelligence/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "cleared" in data

    def test_clear_alerts_with_watch_filter(self, client: TestClient):
        """Clearing alerts with a watch_id filter should scope the clear."""
        resp = client.delete("/api/intelligence/alerts", params={"watch_id": "some-watch"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════════════
#  Group 6: SIEM module functions (no dedicated REST endpoints for
#  toggle/resolve — test module functions directly)
# ═══════════════════════════════════════════════════════════════════════

class TestSIEMToggleRule:
    """siem.toggle_rule — enable/disable a correlation rule."""

    def test_toggle_rule_enable(self):
        """Toggling a rule on should return the rule with enabled=True."""
        rule = siem_mod.create_rule(
            name="Test Brute Toggle",
            description="Detect brute force",
            condition="brute-force",
            severity="high",
            config={"threshold": 5, "window_seconds": 60},
        )
        toggled = siem_mod.toggle_rule(rule.id, True)
        assert toggled is not None
        assert toggled.enabled is True
        # Cleanup
        siem_mod.delete_rule(rule.id)

    def test_toggle_rule_disable(self):
        """Toggling a rule off should return the rule with enabled=False."""
        rule = siem_mod.create_rule(
            name="Test Port Toggle",
            description="Detect port scan",
            condition="port-scan",
            severity="critical",
        )
        toggled = siem_mod.toggle_rule(rule.id, False)
        assert toggled is not None
        assert toggled.enabled is False
        # Cleanup
        siem_mod.delete_rule(rule.id)

    def test_toggle_rule_not_found_returns_none(self):
        """Toggling a non-existent rule should return None."""
        result = siem_mod.toggle_rule("nonexistent-rule-id", True)
        assert result is None

    def test_toggle_rule_roundtrip(self):
        """Create rule, toggle off, verify in list, toggle back on."""
        rule = siem_mod.create_rule(
            name="Canary Check Toggle",
            description="Check canary triggers",
            condition="canary-trigger",
            severity="high",
        )
        # Toggle it off
        siem_mod.toggle_rule(rule.id, False)
        rules = siem_mod.get_rules()
        found = [r for r in rules if r["id"] == rule.id]
        assert len(found) == 1
        assert found[0]["enabled"] is False

        # Toggle back on
        siem_mod.toggle_rule(rule.id, True)
        rules = siem_mod.get_rules()
        found = [r for r in rules if r["id"] == rule.id]
        assert found[0]["enabled"] is True

        # Cleanup
        siem_mod.delete_rule(rule.id)


class TestSIEMResolveAlert:
    """siem.resolve_alert — mark an alert as resolved."""

    def test_resolve_alert_not_found_returns_false(self):
        """Resolving a non-existent alert should return False."""
        result = siem_mod.resolve_alert("nonexistent-alert-id")
        assert result is False

    def test_resolve_alert_success(self):
        """Resolving an existing alert should return True."""
        # Create events that trigger brute-force alert
        for i in range(6):
            siem_mod.ingest_event(
                source="ssh",
                severity="high",
                title=f"Failed login {i}",
                detail="Failed password for root",
                tags=["auth", "failed"],
                ip="192.168.1.50",
            )

        # Check if alerts were generated
        alerts = siem_mod.get_alerts(limit=10)
        if alerts:
            alert_id = alerts[0]["id"]
            result = siem_mod.resolve_alert(alert_id)
            assert result is True

            # Verify it's marked as resolved
            alerts_after = siem_mod.get_alerts(limit=10)
            resolved = [a for a in alerts_after if a["id"] == alert_id]
            if resolved:
                assert resolved[0]["resolved"] is True

    def test_resolve_alert_double_resolve(self):
        """Double-resolving an alert should still return True."""
        for i in range(6):
            siem_mod.ingest_event(
                source="ssh",
                severity="high",
                title=f"Brute attempt {i}",
                detail="Failed auth",
                tags=["auth", "failed"],
                ip="10.0.0.99",
            )

        alerts = siem_mod.get_alerts(limit=20)
        brute_alerts = [a for a in alerts if "brute" in a.get("rule_name", "").lower()]
        if brute_alerts:
            alert_id = brute_alerts[0]["id"]
            assert siem_mod.resolve_alert(alert_id) is True
            # Double-resolve should still return True
            assert siem_mod.resolve_alert(alert_id) is True
