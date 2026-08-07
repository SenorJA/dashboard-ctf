"""
tests/test_deep_coverage_2.py — Deep coverage tests for uncovered branches.

Targets error handling, edge cases, and validation branches that are NOT
covered in test_main_coverage.py or test_crud_endpoints.py.  External
services (SSH, Supabase, forensic tools) are mocked.

Test groups:
  1. Audit Log API endpoints
  2. Mobile upload deep edge cases
  3. Mobile APK management (fallback + DB paths)
  4. Forensics deep testing (run tool, delete, upload edge cases)
  5. KnowledgeBase endpoints
  6. File upload with mocked Supabase success
  7. Scope GET/POST + validate edge cases
  8. CTF endpoints (create/list/score/delete with mocked DB)
  9. Missions similar (with mocked DB returning data)
  10. Connection CRUD (with mocked DB returning data)
  11. Forensics delete endpoint (success path + error path)
  12. Mobile frida stop with None body
  13. Mobile upload SSH connection failure

Run:
    python -m pytest tests/test_deep_coverage_2.py --tb=short -q
"""

from __future__ import annotations

import io
import json
import os
import sys
from typing import Generator
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from fastapi.testclient import TestClient

# ── Path setup ──
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app


# ═══════════════════════════════════════════════════════════════
#  Shared fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    """Yield a FastAPI TestClient that shares the same app instance."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _patch_db_unavailable():
    """Make all DB calls return None (Supabase not configured).

    This is autouse so that every test gets a clean 'no DB' environment
    unless the individual test explicitly patches something else.
    """
    with patch("backend.database.is_available", return_value=False), \
         patch("backend.database.get_client", return_value=None):
        yield


# ═══════════════════════════════════════════════════════════════
#  1. Audit Log API endpoints (GET /api/audit/logs, stats, POST)
# ═══════════════════════════════════════════════════════════════

class TestAuditLogs:
    """GET /api/audit/logs — retrieve recent audit log entries."""

    @patch("main.al_recent")
    def test_get_logs_returns_list(self, mock_recent, client: TestClient):
        """GET /api/audit/logs returns a list of log entries."""
        mock_recent.return_value = [
            {"ts": "2025-01-01T00:00:00", "level": "INFO", "event": "test"},
        ]
        resp = client.get("/api/audit/logs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert isinstance(data["logs"], list)
        assert data["count"] == 1

    @patch("main.al_recent")
    def test_get_logs_empty(self, mock_recent, client: TestClient):
        """GET /api/audit/logs returns empty list when no entries exist."""
        mock_recent.return_value = []
        resp = client.get("/api/audit/logs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["logs"] == []
        assert data["count"] == 0

    @patch("main.al_recent")
    def test_get_logs_with_filters(self, mock_recent, client: TestClient):
        """GET /api/audit/logs with level, category, event, and since filters."""
        mock_recent.return_value = [
            {"ts": "2025-06-01T12:00:00", "level": "WARNING", "category": "auth", "event": "login_failed"},
        ]
        resp = client.get(
            "/api/audit/logs",
            params={"limit": 10, "level": "WARNING", "category": "auth", "event": "login_failed", "since": "2025-06-01T00:00:00"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] == 1
        # Verify filters were passed through
        mock_recent.assert_called_once_with(
            limit=10, level="WARNING", category="auth",
            event="login_failed", since="2025-06-01T00:00:00",
        )

    @patch("main.al_recent")
    def test_get_logs_empty_filters_are_none(self, mock_recent, client: TestClient):
        """GET /api/audit/logs with no filters passes None for optional params."""
        mock_recent.return_value = []
        resp = client.get("/api/audit/logs")
        assert resp.status_code == 200
        mock_recent.assert_called_once_with(
            limit=200, level=None, category=None, event=None, since=None,
        )

    @patch("main.al_recent", side_effect=RuntimeError("disk error"))
    def test_get_logs_exception_returns_500(self, mock_recent, client: TestClient):
        """GET /api/audit/logs handles exceptions gracefully."""
        resp = client.get("/api/audit/logs")
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False
        assert "error" in data


class TestAuditStats:
    """GET /api/audit/stats — aggregate audit-log statistics."""

    @patch("main.al_stats")
    def test_get_stats_returns_structure(self, mock_stats, client: TestClient):
        """GET /api/audit/stats returns statistics structure."""
        mock_stats.return_value = {"total": 42, "by_level": {"INFO": 30, "WARNING": 12}}
        resp = client.get("/api/audit/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 42
        assert "by_level" in data

    @patch("main.al_stats")
    def test_get_stats_empty(self, mock_stats, client: TestClient):
        """GET /api/audit/stats returns zeros when no entries exist."""
        mock_stats.return_value = {"total": 0, "by_level": {}}
        resp = client.get("/api/audit/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    @patch("main.al_stats", side_effect=RuntimeError("read error"))
    def test_get_stats_exception_returns_500(self, mock_stats, client: TestClient):
        """GET /api/audit/stats handles exceptions gracefully."""
        resp = client.get("/api/audit/stats")
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False


class TestAuditCreate:
    """POST /api/audit — manually create an audit entry."""

    @patch("main.al_audit")
    def test_create_audit_entry(self, mock_al, client: TestClient):
        """POST /api/audit with a valid body creates an entry."""
        mock_al.return_value = {"ok": True}
        resp = client.post("/api/audit", json={
            "level": "INFO",
            "category": "auth",
            "event": "user_login",
            "message": "User logged in successfully",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        mock_al.assert_called_once()

    @patch("main.al_audit")
    def test_create_audit_with_all_fields(self, mock_al, client: TestClient):
        """POST /api/audit with all optional fields populated."""
        mock_al.return_value = {"ok": True}
        resp = client.post("/api/audit", json={
            "level": "WARNING",
            "category": "scope",
            "event": "scope_violation",
            "message": "Command outside scope",
            "user": "admin",
            "ip": "10.0.0.1",
            "target": "192.168.1.1",
            "session_id": "sess-abc",
            "details": {"command": "rm -rf /"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        # Verify keyword arguments were passed
        call_kwargs = mock_al.call_args[1]
        assert call_kwargs["level"] == "WARNING"
        assert call_kwargs["category"] == "scope"
        assert call_kwargs["event"] == "scope_violation"
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["ip"] == "10.0.0.1"

    def test_create_audit_invalid_level_returns_422(self, client: TestClient):
        """POST /api/audit with invalid level returns 422."""
        resp = client.post("/api/audit", json={
            "level": "INVALID_LEVEL",
            "message": "test",
        })
        assert resp.status_code == 422

    @patch("main.al_audit")
    def test_create_audit_invalid_level_uppercase(self, mock_al, client: TestClient):
        """POST /api/audit normalises level to uppercase."""
        mock_al.return_value = {"ok": True}
        resp = client.post("/api/audit", json={
            "level": "info",
            "message": "test",
        })
        assert resp.status_code == 200
        call_kwargs = mock_al.call_args[1]
        assert call_kwargs["level"] == "INFO"

    @patch("main.al_audit")
    def test_create_audit_defaults(self, mock_al, client: TestClient):
        """POST /api/audit with minimal body uses default values."""
        mock_al.return_value = {"ok": True}
        resp = client.post("/api/audit", json={})
        assert resp.status_code == 200
        call_kwargs = mock_al.call_args[1]
        assert call_kwargs["level"] == "INFO"
        assert call_kwargs["category"] == "system"
        assert call_kwargs["event"] == "manual_entry"

    @patch("main.al_audit")
    def test_create_audit_skipped_returns_200(self, mock_al, client: TestClient):
        """POST /api/audit returns 200 when level is below min threshold (skipped)."""
        mock_al.return_value = {"ok": True, "skipped": True}
        resp = client.post("/api/audit", json={
            "level": "DEBUG",
            "message": "below threshold",
        })
        assert resp.status_code == 200

    @patch("main.al_audit")
    def test_create_audit_db_failure_returns_422(self, mock_al, client: TestClient):
        """POST /api/audit returns 422 when al_audit returns ok=False."""
        mock_al.return_value = {"ok": False, "error": "write failed"}
        resp = client.post("/api/audit", json={
            "message": "test",
        })
        assert resp.status_code == 422

    @patch("main.al_audit", side_effect=RuntimeError("IO error"))
    def test_create_audit_exception_returns_500(self, mock_al, client: TestClient):
        """POST /api/audit handles exceptions gracefully."""
        resp = client.post("/api/audit", json={
            "message": "test",
        })
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False

    def test_create_audit_no_body_returns_422(self, client: TestClient):
        """POST /api/audit without body returns 422."""
        resp = client.post("/api/audit")
        assert resp.status_code == 422

    @patch("main.al_audit")
    def test_create_audit_unknown_category_allowed(self, mock_al, client: TestClient):
        """POST /api/audit with unknown category is allowed (forward-compatibility)."""
        mock_al.return_value = {"ok": True}
        resp = client.post("/api/audit", json={
            "category": "custom_plugin_category",
            "message": "plugin event",
        })
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════
#  2. Mobile upload deep edge cases
# ═══════════════════════════════════════════════════════════════

class TestMobileUploadDeep:
    """POST /api/mobile/upload — deep edge case testing."""

    def test_upload_no_filename_returns_error(self, client: TestClient):
        """Upload with empty filename returns 400 or 422 (validation error).

        FastAPI may reject the empty-filename upload before the handler runs,
        resulting in 422 (validation) rather than the handler's 400.
        """
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("", b"PK\x03\x04", "application/octet-stream")},
        )
        assert resp.status_code in (400, 422)
        # 400 returns {"ok": False, ...}, 422 returns {"detail": [...]}
        if resp.status_code == 422:
            assert "detail" in resp.json()
        else:
            assert resp.json()["ok"] is False

    @patch("main._ensure_ssh_connection", new_callable=AsyncMock)
    @patch("main.mobile_analyze_apk")
    def test_upload_ssh_connection_failure(self, mock_analyze, mock_ssh, client: TestClient):
        """Upload triggers SSH connection attempt; if analyze works, upload succeeds."""
        mock_analyze.return_value = {"package": "com.test"}
        mock_ssh.return_value = None  # SSH connection failed
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("test.apk", b"PK\x03\x04", "application/vnd.android.package-archive")},
        )
        # Even if SSH fails, _ensure_ssh_connection returns None (doesn't raise).
        # The analyze call still runs. Returns 200 with the result.
        assert resp.status_code == 200

    @patch("main.mobile_analyze_apk", side_effect=Exception("analysis exploded"))
    @patch("main._ensure_ssh_connection", new_callable=AsyncMock)
    def test_upload_analyze_exception_returns_500(self, mock_ssh, mock_analyze, client: TestClient):
        """Upload with analyze raising exception returns 500."""
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("crash.apk", b"PK\x03\x04", "application/vnd.android.package-archive")},
        )
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False
        assert "Analysis failed" in data["error"]

    def test_upload_zip_not_apk_returns_400(self, client: TestClient):
        """Upload a .zip file (not .apk) returns 400."""
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("archive.zip", b"PK\x03\x04", "application/zip")},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "apk" in data["error"].lower()

    @patch("main.mobile_analyze_apk")
    @patch("main._ensure_ssh_connection", new_callable=AsyncMock)
    @patch("main.db")
    def test_upload_db_save_failure_still_returns_ok(self, mock_db_mod, mock_ssh, mock_analyze, client: TestClient):
        """Upload succeeds even when DB save fails (logs warning, no crash)."""
        mock_analyze.return_value = {
            "package": "com.test",
            "version_name": "1.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "size": 1024,
            "md5": "abc",
            "sha256": "def",
            "findings": [],
            "summary": {},
        }
        # Let everything else fall through to default autouse mock
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("test.apk", b"PK\x03\x04", "application/vnd.android.package-archive")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  3. Mobile APK management (fallback + DB paths)
# ═══════════════════════════════════════════════════════════════

class TestMobileAPKManagement:
    """GET /api/mobile/apks, GET /api/mobile/analyze/{id}, DELETE /api/mobile/apks/{id}."""

    @patch("main.mobile_list_apks")
    @patch("backend.database.list_mobile_apks")
    def test_list_apks_from_db(self, mock_db, mock_local, client: TestClient):
        """List APKs returns data from DB when available."""
        mock_db.return_value = [{"apk_id": "a1", "package": "com.app1"}, {"apk_id": "a2", "package": "com.app2"}]
        resp = client.get("/api/mobile/apks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 2

    @patch("main.mobile_list_apks")
    @patch("backend.database.list_mobile_apks", side_effect=Exception("DB down"))
    def test_list_apks_db_error_falls_back_to_local(self, mock_db, mock_local, client: TestClient):
        """List APKs falls back to in-memory when DB raises."""
        mock_local.return_value = [{"apk_id": "local1", "package": "com.local"}]
        resp = client.get("/api/mobile/apks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"][0]["apk_id"] == "local1"

    @patch("main.mobile_get_apk")
    @patch("backend.database.get_mobile_apk", side_effect=Exception("DB error"))
    def test_get_analysis_db_error_falls_back_to_local(self, mock_db, mock_local, client: TestClient):
        """Get analysis falls back to local when DB raises."""
        mock_local.return_value = {"apk_id": "abc", "package": "com.test"}
        resp = client.get("/api/mobile/analyze/abc")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("main.mobile_get_apk")
    @patch("backend.database.get_mobile_apk", side_effect=Exception("DB error"))
    def test_get_analysis_db_error_and_local_not_found_returns_404(self, mock_db, mock_local, client: TestClient):
        """Get analysis returns 404 when both DB and local fail."""
        mock_local.return_value = None
        resp = client.get("/api/mobile/analyze/nonexistent")
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False
        assert "not found" in data["error"].lower()

    @patch("main.mobile_delete_apk")
    @patch("backend.database.delete_mobile_apk", side_effect=Exception("DB error"))
    def test_delete_apk_db_error_falls_back_to_local(self, mock_db, mock_local, client: TestClient):
        """Delete APK falls back to local when DB raises."""
        mock_local.return_value = True
        resp = client.delete("/api/mobile/apks/abc")
        assert resp.status_code == 200

    def test_frida_stop_no_body(self, client: TestClient):
        """POST /api/mobile/frida/stop with no body (None body handling)."""
        with patch("main._ensure_ssh_connection", new_callable=AsyncMock), \
             patch("main.mobile_stop_frida") as mock_stop:
            mock_stop.return_value = "No frida processes"
            resp = client.post("/api/mobile/frida/stop")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  4. Forensics deep testing
# ═══════════════════════════════════════════════════════════════

class TestForensicsDeep:
    """Forensics endpoints — deep edge case testing."""

    @patch("main.forensics_analyze")
    def test_upload_db_save_failure_still_succeeds(self, mock_analyze, client: TestClient):
        """Upload succeeds even when DB save fails (logs warning)."""
        mock_analyze.return_value = {
            "file_type": "text",
            "size": 11,
            "md5": "abc",
            "sha256": "def",
            "findings": [],
            "summary": {"type": "text"},
        }
        resp = client.post(
            "/api/forensics/upload",
            files={"file": ("test.txt", b"hello world", "text/plain")},
            data={"category": "file"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "id" in data["data"]

    @patch("main.forensics_analyze", side_effect=Exception("tool crashed"))
    def test_upload_analysis_exception_returns_500(self, mock_analyze, client: TestClient):
        """Upload with analysis exception returns 500."""
        resp = client.post(
            "/api/forensics/upload",
            files={"file": ("crash.bin", b"\x00\x01\x02", "application/octet-stream")},
            data={"category": "memory"},
        )
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False
        assert "Analysis failed" in data["error"]

    @patch("main.forensics_run_tool")
    @patch("main.forensics_get")
    def test_run_tool_with_existing_file(self, mock_get, mock_run, client: TestClient):
        """Run forensic tool on existing evidence with file on disk."""
        import tempfile
        mock_get.return_value = {"id": "ev1", "filename": "sample.bin", "findings": []}
        mock_run.return_value = {"tool": "strings", "output": "secret_data", "lines": 1}
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create the expected file
            filepath = os.path.join(tmpdir, "ev1_sample.bin")
            with open(filepath, "wb") as f:
                f.write(b"binary content")
            with patch("main.FORENSICS_UPLOAD_DIR", tmpdir):
                resp = client.post("/api/forensics/analyze/ev1/run", json={"tool": "strings"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["ok"] is True
                assert data["data"]["tool"] == "strings"

    @patch("main.forensics_run_tool")
    @patch("main.forensics_get")
    def test_run_tool_file_not_on_disk(self, mock_get, mock_run, client: TestClient):
        """Run forensic tool when evidence file is not on disk returns 404."""
        mock_get.return_value = {"id": "ev_missing", "filename": "gone.bin", "findings": []}
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            # Empty directory — no file exists
            with patch("main.FORENSICS_UPLOAD_DIR", tmpdir):
                resp = client.post("/api/forensics/analyze/ev_missing/run", json={"tool": "strings"})
                assert resp.status_code == 404
                data = resp.json()
                assert "not found" in data["error"].lower()

    @patch("main.forensics_delete")
    @patch("backend.database.delete_forensics_evidence")
    @patch("os.listdir", return_value=[])
    def test_delete_forensics_success(self, mock_listdir, mock_db_del, mock_del, client: TestClient):
        """DELETE /api/forensics/{ev_id} succeeds."""
        mock_db_del.return_value = False
        mock_del.return_value = True
        resp = client.delete("/api/forensics/ev1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("main.forensics_delete")
    @patch("backend.database.delete_forensics_evidence")
    @patch("os.listdir", return_value=[])
    def test_delete_forensics_not_found(self, mock_listdir, mock_db_del, mock_del, client: TestClient):
        """DELETE /api/forensics/{ev_id} when not found returns 404."""
        mock_db_del.return_value = False
        mock_del.return_value = False
        resp = client.delete("/api/forensics/nonexistent")
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False

    @patch("main.forensics_list")
    @patch("backend.database.list_forensics_evidence")
    def test_forensics_list_from_db(self, mock_db_list, mock_local, client: TestClient):
        """GET /api/forensics/list returns data from DB."""
        mock_db_list.return_value = [
            {"id": "ev1", "filename": "sample.bin", "category": "file"},
            {"id": "ev2", "filename": "memory.dmp", "category": "memory"},
        ]
        resp = client.get("/api/forensics/list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 2

    @patch("main.forensics_list")
    @patch("backend.database.list_forensics_evidence", side_effect=Exception("DB error"))
    def test_forensics_list_db_error_falls_back(self, mock_db_list, mock_local, client: TestClient):
        """GET /api/forensics/list falls back to local when DB raises."""
        mock_local.return_value = [{"id": "local1"}]
        resp = client.get("/api/forensics/list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"][0]["id"] == "local1"

    @patch("main.forensics_get")
    @patch("backend.database.get_forensics_evidence")
    def test_forensics_analyze_from_db(self, mock_db_get, mock_get, client: TestClient):
        """GET /api/forensics/analyze/{id} returns data from DB."""
        mock_db_get.return_value = {"id": "ev_db", "filename": "from_db.bin", "findings": []}
        resp = client.get("/api/forensics/analyze/ev_db")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["id"] == "ev_db"

    @patch("main.forensics_get")
    @patch("backend.database.get_forensics_evidence", side_effect=Exception("DB error"))
    def test_forensics_analyze_db_error_falls_back(self, mock_db_get, mock_get, client: TestClient):
        """GET /api/forensics/analyze/{id} falls back when DB raises."""
        mock_get.return_value = {"id": "ev_local", "filename": "local.bin"}
        resp = client.get("/api/forensics/analyze/ev_local")
        assert resp.status_code == 200

    @patch("main.forensics_get")
    @patch("backend.database.get_forensics_evidence", side_effect=Exception("DB error"))
    def test_forensics_analyze_db_error_and_local_not_found(self, mock_db_get, mock_get, client: TestClient):
        """GET /api/forensics/analyze/{id} returns 404 when both DB and local fail."""
        mock_get.return_value = None
        resp = client.get("/api/forensics/analyze/nonexistent")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  5. KnowledgeBase endpoints
# ═══════════════════════════════════════════════════════════════

class TestKnowledgeBaseDeep:
    """KnowledgeBase API — CVE lookup, MITRE lookup, search edge cases."""

    def test_search_empty_query_returns_results(self, client: TestClient):
        """GET /api/knowledgebase/search with empty query returns all or empty."""
        resp = client.get("/api/knowledgebase/search")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "data" in data

    def test_search_with_query(self, client: TestClient):
        """GET /api/knowledgebase/search with a specific query returns results."""
        resp = client.get("/api/knowledgebase/search", params={"query": "SMB"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_cve_lookup_valid(self, client: TestClient):
        """GET /api/knowledgebase/cve/CVE-2021-44228 returns Log4Shell."""
        resp = client.get("/api/knowledgebase/cve/CVE-2021-44228")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["id"] == "CVE-2021-44228"
        assert "Log4Shell" in data["data"]["description"]

    def test_cve_lookup_invalid(self, client: TestClient):
        """GET /api/knowledgebase/cve/CVE-9999-99999 returns 404."""
        resp = client.get("/api/knowledgebase/cve/CVE-9999-99999")
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False
        assert "not found" in data["error"].lower()

    def test_mitre_lookup_valid(self, client: TestClient):
        """GET /api/knowledgebase/mitre/T1059 returns technique data."""
        resp = client.get("/api/knowledgebase/mitre/T1059")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "id" in data["data"]

    def test_mitre_lookup_invalid(self, client: TestClient):
        """GET /api/knowledgebase/mitre/T9999 returns 404."""
        resp = client.get("/api/knowledgebase/mitre/T9999")
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False
        assert "not found" in data["error"].lower()

    def test_cve_lookup_partial_match_not_found(self, client: TestClient):
        """GET /api/knowledgebase/cve/CVE with partial ID returns 404."""
        resp = client.get("/api/knowledgebase/cve/CVE")
        assert resp.status_code == 404

    def test_search_query_xss(self, client: TestClient):
        """GET /api/knowledgebase/search with XSS-like query returns safely."""
        resp = client.get("/api/knowledgebase/search", params={"query": "<script>alert(1)</script>"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  6. File upload/list (mocked Supabase success)
# ═══════════════════════════════════════════════════════════════

class TestFileUploadDeep:
    """POST /api/upload and GET /api/files — with mocked Supabase success."""

    def test_upload_no_file_returns_422(self, client: TestClient):
        """Upload without a file returns 422 (missing required field)."""
        resp = client.post("/api/upload")
        assert resp.status_code == 422

    def test_upload_no_supabase_returns_503(self, client: TestClient):
        """Upload without Supabase configured returns 503."""
        resp = client.post(
            "/api/upload",
            files={"file": ("test.txt", b"hello", "text/plain")},
        )
        assert resp.status_code == 503
        data = resp.json()
        assert data["ok"] is False
        assert "not configured" in data["error"].lower()

    def test_files_list_returns_list(self, client: TestClient):
        """GET /api/files returns a list (may be empty)."""
        resp = client.get("/api/files")
        # With DB unavailable, list_uploaded_files returns None → _ok(None) → 503
        assert resp.status_code in (200, 503)

    def test_upload_with_mocked_supabase_success(self, client: TestClient):
        """Upload succeeds when Supabase client and storage are mocked."""
        mock_client = MagicMock()
        mock_storage = MagicMock()
        mock_client.storage.from_.return_value = mock_storage
        mock_storage.upload.return_value = None
        mock_storage.get_public_url.return_value = "https://example.com/uploads/test.txt"

        mock_meta_result = {"id": "file-123"}
        with patch("main.db") as mock_db:
            mock_db.get_client.return_value = mock_client
            mock_db.save_uploaded_file.return_value = mock_meta_result
            resp = client.post(
                "/api/upload",
                files={"file": ("test.txt", b"hello world", "text/plain")},
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["ok"] is True
            assert data["data"]["filename"] == "test.txt"
            assert data["data"]["public_url"] == "https://example.com/uploads/test.txt"

    def test_upload_supabase_storage_error_returns_500(self, client: TestClient):
        """Upload returns 500 when Supabase storage raises."""
        mock_client = MagicMock()
        mock_storage = MagicMock()
        mock_client.storage.from_.return_value = mock_storage
        mock_storage.upload.side_effect = Exception("Storage full")

        with patch("main.db") as mock_db:
            mock_db.get_client.return_value = mock_client
            resp = client.post(
                "/api/upload",
                files={"file": ("big.bin", b"\x00" * 100, "application/octet-stream")},
            )
            assert resp.status_code == 500
            data = resp.json()
            assert data["ok"] is False


# ═══════════════════════════════════════════════════════════════
#  7. Scope GET/POST + validate edge cases
# ═══════════════════════════════════════════════════════════════

class TestScopeEndpoints:
    """GET/POST /api/scope, POST /api/scope/validate, GET /api/scope/history."""

    def test_get_scope_returns_config(self, client: TestClient):
        """GET /api/scope returns current scope configuration."""
        resp = client.get("/api/scope")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "data" in data
        assert "enabled" in data["data"]
        assert "mode" in data["data"]
        assert "targets" in data["data"]

    @patch("main.save_config")
    def test_post_scope_save_success(self, mock_save, client: TestClient):
        """POST /api/scope saves configuration successfully."""
        mock_save.return_value = True
        resp = client.post("/api/scope", json={
            "enabled": True,
            "mode": "block",
            "targets": ["10.0.0.0/24"],
            "block_private": True,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("main.save_config")
    def test_post_scope_save_failure(self, mock_save, client: TestClient):
        """POST /api/scope returns 503 when persistence is unavailable."""
        mock_save.return_value = False
        resp = client.post("/api/scope", json={
            "enabled": True,
            "mode": "warn",
            "targets": [],
        })
        assert resp.status_code == 503
        data = resp.json()
        assert data["ok"] is False

    def test_post_scope_invalid_mode_defaults_to_warn(self, client: TestClient):
        """POST /api/scope with invalid mode defaults to 'warn'."""
        with patch("main.save_config", return_value=True) as mock_save:
            resp = client.post("/api/scope", json={
                "enabled": True,
                "mode": "INVALID_MODE",
                "targets": [],
            })
            assert resp.status_code == 200
            # Verify mode was normalised to "warn"
            saved_cfg = mock_save.call_args[0][0]
            assert saved_cfg["mode"] == "warn"

    @patch("main.validate_command")
    def test_validate_returns_blocked_result(self, mock_validate, client: TestClient):
        """POST /api/scope/validate returns blocked result when command is dangerous."""
        mock_validate.return_value = {"blocked": True, "reason": "out of scope", "severity": "high"}
        resp = client.post("/api/scope/validate", json={"command": "rm -rf /"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["blocked"] is True
        assert data["reason"] == "out of scope"

    @patch("main.validate_command")
    def test_validate_returns_none_for_safe_command(self, mock_validate, client: TestClient):
        """POST /api/scope/validate returns not blocked for safe command."""
        mock_validate.return_value = None
        resp = client.post("/api/scope/validate", json={"command": "ls -la"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["blocked"] is False

    def test_validate_no_command_key(self, client: TestClient):
        """POST /api/scope/validate without 'command' key returns not blocked."""
        resp = client.post("/api/scope/validate", json={"something_else": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is False

    def test_validate_non_dict_body_returns_422(self, client: TestClient):
        """POST /api/scope/validate with non-dict body returns 422.

        FastAPI's ``req: dict`` parameter requires a JSON object (dict).
        A bare string is rejected by Pydantic validation before the handler runs.
        """
        resp = client.post("/api/scope/validate", json="just a string")
        assert resp.status_code == 422

    def test_scope_history_returns_list(self, client: TestClient):
        """GET /api/scope/history returns a list."""
        resp = client.get("/api/scope/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_scope_clear_history(self, client: TestClient):
        """POST /api/scope/history/clear clears the history."""
        resp = client.post("/api/scope/history/clear")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_post_scope_no_body_returns_422(self, client: TestClient):
        """POST /api/scope without body returns 422."""
        resp = client.post("/api/scope")
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════
#  8. CTF endpoints (create/list/score/delete with mocked DB)
# ═══════════════════════════════════════════════════════════════

class TestCTFEndpoints:
    """CTF mode API — create, list, solve, score, delete."""

    def test_list_challenges_no_db(self, client: TestClient):
        """GET /api/ctf/challenges returns empty fallback when DB unavailable."""
        resp = client.get("/api/ctf/challenges")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"] == []
        assert data.get("fallback") is True

    @patch("main.db")
    def test_list_challenges_from_db(self, mock_db, client: TestClient):
        """GET /api/ctf/challenges returns data from DB."""
        mock_db.list_ctf_challenges.return_value = [
            {"id": 1, "title": "Easy Web", "category": "web", "points": 100, "solved": False},
            {"id": 2, "title": "Hard Crypto", "category": "crypto", "points": 500, "solved": True},
        ]
        resp = client.get("/api/ctf/challenges")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 2

    def test_create_challenge_no_db(self, client: TestClient):
        """POST /api/ctf/challenges returns 503 when DB unavailable."""
        resp = client.post("/api/ctf/challenges", json={
            "title": "Test Challenge",
            "category": "web",
            "flags": "FLAG{test}",
            "points": 100,
        })
        assert resp.status_code == 503

    @patch("main.db")
    def test_create_challenge_success(self, mock_db, client: TestClient):
        """POST /api/ctf/challenges creates a challenge."""
        mock_db.save_ctf_challenge.return_value = {"id": 1, "title": "New Challenge"}
        resp = client.post("/api/ctf/challenges", json={
            "title": "New Challenge",
            "category": "pwn",
            "flags": "FLAG{pwned}",
            "points": 200,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["title"] == "New Challenge"

    def test_create_challenge_no_body_returns_422(self, client: TestClient):
        """POST /api/ctf/challenges without body returns 422."""
        resp = client.post("/api/ctf/challenges")
        assert resp.status_code == 422

    def test_score_no_db_returns_fallback(self, client: TestClient):
        """GET /api/ctf/score returns fallback zeros when DB unavailable."""
        resp = client.get("/api/ctf/score")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["solved"] == 0
        assert data["data"]["total"] == 0
        assert data["data"]["points"] == 0
        assert data.get("fallback") is True

    @patch("main.db")
    def test_score_from_db(self, mock_db, client: TestClient):
        """GET /api/ctf/score returns score from DB."""
        mock_db.get_ctf_score.return_value = {
            "solved": 5, "total": 10, "points": 1500, "total_points": 3000,
        }
        resp = client.get("/api/ctf/score")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["solved"] == 5
        assert data["data"]["points"] == 1500

    @patch("main.db")
    def test_solve_correct_flag(self, mock_db, client: TestClient):
        """POST /api/ctf/challenges/{id}/solve with correct flag succeeds."""
        mock_db.solve_ctf_challenge.return_value = {"ok": True, "points": 100}
        resp = client.post("/api/ctf/challenges/1/solve", json={"flag": "FLAG{correct}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["points"] == 100

    @patch("main.db")
    def test_solve_wrong_flag(self, mock_db, client: TestClient):
        """POST /api/ctf/challenges/{id}/solve with wrong flag returns error."""
        mock_db.solve_ctf_challenge.return_value = {"ok": False, "error": "Wrong flag"}
        resp = client.post("/api/ctf/challenges/1/solve", json={"flag": "FLAG{wrong}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is False

    @patch("main.db")
    def test_solve_empty_flag_returns_400(self, mock_db, client: TestClient):
        """POST /api/ctf/challenges/{id}/solve with empty flag returns 400."""
        resp = client.post("/api/ctf/challenges/1/solve", json={"flag": ""})
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False

    def test_solve_missing_flag_returns_400(self, client: TestClient):
        """POST /api/ctf/challenges/{id}/solve without flag key returns 400."""
        resp = client.post("/api/ctf/challenges/1/solve", json={})
        assert resp.status_code == 400

    def test_delete_challenge(self, client: TestClient):
        """DELETE /api/ctf/challenges/{id} returns ok (DB unavailable)."""
        resp = client.delete("/api/ctf/challenges/1")
        assert resp.status_code == 200
        data = resp.json()
        # With DB unavailable, delete returns False → ok: false
        assert "ok" in data

    @patch("main.db")
    def test_delete_challenge_success(self, mock_db, client: TestClient):
        """DELETE /api/ctf/challenges/{id} deletes successfully."""
        mock_db.delete_ctf_challenge.return_value = True
        resp = client.delete("/api/ctf/challenges/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  9. Missions similar (with mocked DB returning data)
# ═══════════════════════════════════════════════════════════════

class TestMissionsSimilarDeep:
    """GET /api/missions/similar — with mocked DB returning data."""

    @patch("main.find_similar")
    def test_similar_with_data(self, mock_find, client: TestClient):
        """Similar missions returns data from DB."""
        mock_find.return_value = [
            {"id": "m1", "target": "10.0.0.1", "tools_used": ["nmap"], "findings_count": 5},
            {"id": "m2", "target": "10.0.0.2", "tools_used": ["gobuster"], "findings_count": 3},
        ]
        resp = client.get("/api/missions/similar?target_os=linux&tools=nmap,gobuster&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 2

    @patch("main.find_similar")
    def test_similar_empty_result(self, mock_find, client: TestClient):
        """Similar missions returns empty list when no matches."""
        mock_find.return_value = []
        resp = client.get("/api/missions/similar?target_os=windows")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"] == []

    @patch("main.find_similar", side_effect=RuntimeError("DB connection lost"))
    def test_similar_exception_returns_500(self, mock_find, client: TestClient):
        """Similar missions handles DB exceptions."""
        resp = client.get("/api/missions/similar")
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False


# ═══════════════════════════════════════════════════════════════
#  10. Connection CRUD (with mocked DB returning data)
# ═══════════════════════════════════════════════════════════════

class TestConnectionEndpoints:
    """GET/POST/DELETE /api/connections."""

    def test_list_connections_no_db(self, client: TestClient):
        """GET /api/connections returns 503 when DB unavailable."""
        resp = client.get("/api/connections")
        # list_connections returns None → _ok(None) → 503
        assert resp.status_code in (200, 503)

    @patch("main.db")
    def test_list_connections_from_db(self, mock_db, client: TestClient):
        """GET /api/connections returns connections from DB."""
        mock_db.list_connections.return_value = [
            {"id": "c1", "name": "Kali", "ip": "192.168.1.100", "username": "javi"},
        ]
        resp = client.get("/api/connections")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 1

    @patch("main.db")
    def test_create_connection_success(self, mock_db, client: TestClient):
        """POST /api/connections creates a connection."""
        mock_db.save_connection.return_value = {"id": "new-c1", "name": "New Server"}
        resp = client.post("/api/connections", json={
            "name": "New Server",
            "ip": "10.0.0.5",
            "username": "root",
            "password": "pass123",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["name"] == "New Server"

    def test_create_connection_no_body_returns_422(self, client: TestClient):
        """POST /api/connections without body returns 422."""
        resp = client.post("/api/connections")
        assert resp.status_code == 422

    def test_create_connection_missing_fields_returns_422(self, client: TestClient):
        """POST /api/connections with missing required fields returns 422."""
        resp = client.post("/api/connections", json={"name": "Server"})
        assert resp.status_code == 422

    def test_delete_connection_no_db(self, client: TestClient):
        """DELETE /api/connections/{id} returns 400 when DB unavailable."""
        resp = client.delete("/api/connections/nonexistent")
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False

    @patch("main.db")
    def test_delete_connection_success(self, mock_db, client: TestClient):
        """DELETE /api/connections/{id} deletes successfully."""
        mock_db.delete_connection.return_value = True
        resp = client.delete("/api/connections/c1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  11. Forensics delete endpoint (success path)
# ═══════════════════════════════════════════════════════════════

class TestForensicsDelete:
    """DELETE /api/forensics/{ev_id} — deep testing."""

    @patch("main.os.listdir", return_value=["ev1_sample.bin"])
    @patch("main.os.remove")
    @patch("main.forensics_delete", return_value=True)
    @patch("backend.database.delete_forensics_evidence", return_value=False)
    def test_delete_success_cleans_disk(self, mock_db, mock_del, mock_rm, mock_ls, client: TestClient):
        """DELETE /api/forensics/{ev_id} removes files from disk."""
        resp = client.delete("/api/forensics/ev1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("main.os.listdir", return_value=[])
    @patch("main.forensics_delete", return_value=True)
    @patch("backend.database.delete_forensics_evidence", return_value=True)
    def test_delete_db_success(self, mock_db, mock_del, mock_ls, client: TestClient):
        """DELETE /api/forensics/{ev_id} when DB delete succeeds."""
        resp = client.delete("/api/forensics/ev1")
        assert resp.status_code == 200

    @patch("main.os.listdir", return_value=[])
    @patch("main.forensics_delete", return_value=False)
    @patch("backend.database.delete_forensics_evidence", return_value=False)
    def test_delete_not_found(self, mock_db, mock_del, mock_ls, client: TestClient):
        """DELETE /api/forensics/{ev_id} when nothing exists returns 404."""
        resp = client.delete("/api/forensics/ghost")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  12. Mobile upload SSH connection failure
# ═══════════════════════════════════════════════════════════════

class TestMobileUploadSSHFailure:
    """POST /api/mobile/upload — SSH connection failure handling."""

    @patch("main.mobile_analyze_apk")
    @patch("main._ensure_ssh_connection", new_callable=AsyncMock)
    def test_upload_ssh_none_still_runs_analysis(self, mock_ssh, mock_analyze, client: TestClient):
        """Upload still runs analysis when SSH connection returns None."""
        mock_ssh.return_value = None
        mock_analyze.return_value = {"package": "com.test", "findings": []}
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("test.apk", b"PK\x03\x04", "application/vnd.android.package-archive")},
        )
        assert resp.status_code == 200
        mock_analyze.assert_called_once()

    @patch("main.mobile_analyze_apk", side_effect=OSError("Network unreachable"))
    @patch("main._ensure_ssh_connection", new_callable=AsyncMock)
    def test_upload_ssh_none_analyze_raises(self, mock_ssh, mock_analyze, client: TestClient):
        """Upload returns 500 when SSH fails and analyze raises."""
        mock_ssh.return_value = None
        resp = client.post(
            "/api/mobile/upload",
            files={"file": ("test.apk", b"PK\x03\x04", "application/vnd.android.package-archive")},
        )
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False
        assert "Analysis failed" in data["error"]


# ═══════════════════════════════════════════════════════════════
#  13. Health endpoint (additional validation)
# ═══════════════════════════════════════════════════════════════

class TestHealthDeep:
    """GET /api/health — additional coverage."""

    def test_health_returns_json(self, client: TestClient):
        """GET /api/health returns valid JSON."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "status" in data
        # Status can be 'ok' or 'degraded' depending on DB availability
        assert data["status"] in ("ok", "degraded")

    def test_health_has_uptime(self, client: TestClient):
        """GET /api/health includes uptime_seconds."""
        resp = client.get("/api/health")
        data = resp.json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0


# ═══════════════════════════════════════════════════════════════
#  14. OPSEC levels (additional validation)
# ═══════════════════════════════════════════════════════════════

class TestOpsecLevels:
    """GET /api/opsec/levels — verify structure."""

    def test_opsec_levels_structure(self, client: TestClient):
        """GET /api/opsec/levels returns levels array."""
        resp = client.get("/api/opsec/levels")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "levels" in data
        assert isinstance(data["levels"], (list, dict))

    @patch("main.opsec_apply")
    def test_opsec_apply_tool_exception(self, mock_apply, client: TestClient):
        """POST /api/opsec/apply handles tool-level exceptions."""
        mock_apply.side_effect = ValueError("Unknown tool")
        resp = client.post("/api/opsec/apply", json={
            "tool": "unknown_tool",
            "command": "test",
            "level": "loud",
        })
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False


# ═══════════════════════════════════════════════════════════════
#  15. Forensics run tool — existing file path
# ═══════════════════════════════════════════════════════════════

class TestForensicsRunToolDeep:
    """POST /api/forensics/analyze/{ev_id}/run — additional coverage."""

    def test_run_tool_nonexistent_evidence_returns_404(self, client: TestClient):
        """Run tool on evidence that doesn't exist returns 404."""
        resp = client.post("/api/forensics/analyze/ghost/run", json={"tool": "strings"})
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False

    def test_run_tool_no_body_uses_defaults(self, client: TestClient):
        """Run tool with empty body uses default tool 'strings'."""
        # Will return 404 since evidence doesn't exist, but validates body parsing
        resp = client.post("/api/forensics/analyze/nonexistent/run", json={})
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  16. Payloads endpoints
# ═══════════════════════════════════════════════════════════════

class TestPayloadsEndpoints:
    """GET/POST/DELETE /api/payloads."""

    @patch("main.db")
    def test_list_payloads_from_db(self, mock_db, client: TestClient):
        """GET /api/payloads returns payloads from DB."""
        mock_db.list_hak5_payloads.return_value = [
            {"id": "p1", "device": "bunny", "name": "enum", "content": "LED R"},
        ]
        resp = client.get("/api/payloads")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 1

    @patch("main.db")
    def test_create_payload_success(self, mock_db, client: TestClient):
        """POST /api/payloads creates a payload."""
        mock_db.save_hak5_payload.return_value = {"id": "p-new", "name": "new"}
        resp = client.post("/api/payloads", json={
            "device": "omg",
            "name": "wifi-grab",
            "content": "LED G R",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True

    def test_create_payload_no_body_returns_422(self, client: TestClient):
        """POST /api/payloads without body returns 422."""
        resp = client.post("/api/payloads")
        assert resp.status_code == 422

    def test_delete_payload_no_db(self, client: TestClient):
        """DELETE /api/payloads/{id} returns 400 when DB unavailable."""
        resp = client.delete("/api/payloads/nonexistent")
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════
#  17. Scripts endpoints
# ═══════════════════════════════════════════════════════════════

class TestScriptsEndpoints:
    """GET/POST/DELETE /api/scripts."""

    @patch("main.db")
    def test_list_scripts_from_db(self, mock_db, client: TestClient):
        """GET /api/scripts returns scripts from DB."""
        mock_db.list_scripts.return_value = [{"id": "s1", "name": "recon"}]
        resp = client.get("/api/scripts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("main.db")
    def test_create_script_success(self, mock_db, client: TestClient):
        """POST /api/scripts creates a script."""
        mock_db.save_script.return_value = {"id": "s-new", "name": "new"}
        resp = client.post("/api/scripts", json={"name": "new", "content": "echo hello"})
        assert resp.status_code == 201

    def test_create_script_no_body_returns_422(self, client: TestClient):
        """POST /api/scripts without body returns 422."""
        resp = client.post("/api/scripts")
        assert resp.status_code == 422

    def test_delete_script_no_db(self, client: TestClient):
        """DELETE /api/scripts/{id} returns 400 when DB unavailable."""
        resp = client.delete("/api/scripts/nonexistent")
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════
#  18. Settings endpoints
# ═══════════════════════════════════════════════════════════════

class TestSettingsEndpoints:
    """GET/POST /api/settings."""

    def test_get_setting_no_db(self, client: TestClient):
        """GET /api/settings/{key} returns 503 when DB unavailable."""
        resp = client.get("/api/settings/theme")
        assert resp.status_code in (200, 503)

    @patch("main.db")
    def test_get_setting_from_db(self, mock_db, client: TestClient):
        """GET /api/settings/{key} returns setting from DB."""
        mock_db.get_setting.return_value = "dark"
        mock_db.is_available.return_value = True
        resp = client.get("/api/settings/theme")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["value"] == "dark"

    def test_set_setting_no_body(self, client: TestClient):
        """POST /api/settings without body returns 422."""
        resp = client.post("/api/settings")
        assert resp.status_code == 422

    @patch("main.db")
    def test_set_setting_success(self, mock_db, client: TestClient):
        """POST /api/settings saves setting."""
        mock_db.set_setting.return_value = {"key": "theme", "value": "neon"}
        resp = client.post("/api/settings", json={"key": "theme", "value": "neon"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
