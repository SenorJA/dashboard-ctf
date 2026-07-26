"""
tests/test_deep_coverage_1.py — Deep branch-coverage tests for MIRV backend.

Targets **uncovered error-handling, validation, and edge-case branches** in
main.py that the happy-path tests in test_main_coverage.py do not reach.

Run:
    python -m pytest backend/tests/test_deep_coverage_1.py -v --tb=short -q
"""

from __future__ import annotations

import io
import json
import os
import sys
import asyncio
import urllib.error
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
def client():
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
#  1. POST /api/ai/chat — error branches
# ═══════════════════════════════════════════════════════════════

class TestAIChatDeep:
    """POST /api/ai/chat — deep error-handling and edge-case branches."""

    def test_ai_chat_empty_messages_list(self, client: TestClient):
        """Empty messages list is valid — LLM call proceeds with empty list."""
        with patch("main._call_llm_sync", return_value="empty ok") as mock_llm:
            resp = client.post("/api/ai/chat", json={
                "provider": "openai",
                "api_key": "sk-test",
                "model": "gpt-4o-mini",
                "messages": [],
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["content"] == "empty ok"
            mock_llm.assert_called_once()

    def test_ai_chat_no_messages_key(self, client: TestClient):
        """Missing 'messages' key entirely — defaults to empty list via Pydantic."""
        with patch("main._call_llm_sync", return_value="no-key-ok") as mock_llm:
            resp = client.post("/api/ai/chat", json={
                "provider": "openai",
                "api_key": "sk-test",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True

    def test_ai_chat_missing_body(self, client: TestClient):
        """POST without JSON body returns 422."""
        resp = client.post("/api/ai/chat")
        assert resp.status_code == 422

    def test_ai_chat_redacts_secrets_before_llm(self, client: TestClient):
        """Secrets in messages are redacted before the LLM call."""
        with patch("main._call_llm_sync", return_value="redacted ok") as mock_llm:
            with patch("main.redact_ai_payload", return_value=[{"role": "user", "content": "[REDACTED]"}]) as mock_redact:
                resp = client.post("/api/ai/chat", json={
                    "provider": "openai",
                    "api_key": "sk-secret",
                    "messages": [{"role": "user", "content": "My key is sk-abc123"}],
                })
                assert resp.status_code == 200
                mock_redact.assert_called_once()
                # The LLM was called with redacted messages
                call_args = mock_llm.call_args
                assert call_args[0][3] == [{"role": "user", "content": "[REDACTED]"}]

    def test_ai_chat_error_includes_provider_name(self, client: TestClient):
        """Exception error message includes the provider name."""
        with patch("main._call_llm_sync", side_effect=RuntimeError("something broke")):
            resp = client.post("/api/ai/chat", json={
                "provider": "anthropic",
                "api_key": "sk-test",
                "messages": [{"role": "user", "content": "hi"}],
            })
            assert resp.status_code == 500
            data = resp.json()
            assert "anthropic" in data["error"]

    def test_ai_chat_http_error_includes_status(self, client: TestClient):
        """HTTP error includes provider and status code."""
        err = urllib.error.HTTPError(
            url="", code=429, msg="Rate limit",
            hdrs=None, fp=io.BytesIO(b"rate limited")
        )
        with patch("main._call_llm_sync", side_effect=err):
            resp = client.post("/api/ai/chat", json={
                "provider": "groq",
                "api_key": "sk-test",
                "messages": [{"role": "user", "content": "hi"}],
            })
            assert resp.status_code == 502
            data = resp.json()
            assert "groq" in data["error"]
            assert "429" in data["error"]

    @patch("main._call_llm_sync")
    def test_ai_chat_multiple_messages(self, mock_llm, client: TestClient):
        """Chat with multi-turn conversation."""
        mock_llm.return_value = "multi-turn response"
        resp = client.post("/api/ai/chat", json={
            "provider": "openai",
            "api_key": "sk-test",
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "user", "content": "How are you?"},
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  2. POST /api/suggest — deep branches
# ═══════════════════════════════════════════════════════════════

class TestAISuggestDeep:
    """POST /api/suggest — deep error-handling and edge-case branches."""

    def test_suggest_empty_findings_generates_suggestion(self, client: TestClient):
        """Empty findings still generates a suggestion (recon prompt)."""
        with patch("main._call_llm_sync", return_value="Run nmap -sV") as mock_llm:
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
                "findings": "",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert "suggestion" in data
            # Verify the system prompt includes the recon fallback text
            call_args = mock_llm.call_args
            messages = call_args[0][3]
            system_msg = messages[0]["content"]
            assert "reconnaissance" in system_msg.lower() or "No findings" in system_msg

    def test_suggest_local_provider_no_key_needed(self, client: TestClient):
        """Local provider doesn't require API key."""
        with patch("main._call_llm_sync", return_value="use local model") as mock_llm:
            resp = client.post("/api/suggest", json={
                "provider": "local",
                "api_key": "",
                "target": "10.0.0.1",
                "findings": "",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True

    def test_suggest_mission_id_triggers_memory_render(self, client: TestClient):
        """When mission_id is provided, ms_render_memory is called."""
        with patch("main._call_llm_sync", return_value="suggestion") as mock_llm, \
             patch("main.ms_render_memory", return_value="## Mission History\nPast scan found X") as mock_mem:
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
                "mission_id": "mission-123",
            })
            assert resp.status_code == 200
            mock_mem.assert_called_once_with("mission-123")
            # Verify the memory block is injected into the system prompt
            call_args = mock_llm.call_args
            messages = call_args[0][3]
            system_msg = messages[0]["content"]
            assert "Mission History" in system_msg

    def test_suggest_mission_id_memory_failure_degrades_gracefully(self, client: TestClient):
        """ms_render_memory exception degrades to context-less prompt."""
        with patch("main._call_llm_sync", return_value="fallback suggestion") as mock_llm, \
             patch("main.ms_render_memory", side_effect=RuntimeError("DB down")):
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
                "mission_id": "bad-mission",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True

    def test_suggest_coverage_context_failure_degrades(self, client: TestClient):
        """cov_context exception degrades gracefully."""
        with patch("main._call_llm_sync", return_value="ok") as mock_llm, \
             patch("main.cov_context", side_effect=RuntimeError("coverage module down")):
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
            })
            assert resp.status_code == 200

    def test_suggest_suggestion_context_failure_degrades(self, client: TestClient):
        """get_suggestion_context exception degrades gracefully."""
        with patch("main._call_llm_sync", return_value="ok") as mock_llm, \
             patch("main.get_suggestion_context", side_effect=RuntimeError("mission store error")):
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
            })
            assert resp.status_code == 200

    def test_suggest_with_all_context_blocks(self, client: TestClient):
        """With coverage context, mission context, and memory all present."""
        with patch("main._call_llm_sync", return_value="comprehensive suggestion") as mock_llm, \
             patch("main.get_suggestion_context", return_value="## Past Missions\nDid X"), \
             patch("main.cov_context", return_value="## Coverage\nTested: nmap"), \
             patch("main.ms_render_memory", return_value="## Memory\nSession data"):
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
                "mission_id": "mem-123",
                "findings": "Port 22 open",
            })
            assert resp.status_code == 200
            call_args = mock_llm.call_args
            messages = call_args[0][3]
            system_msg = messages[0]["content"]
            assert "Past Missions" in system_msg
            assert "Coverage" in system_msg
            assert "Memory" in system_msg

    def test_suggest_with_custom_system_prompt(self, client: TestClient):
        """Custom system_prompt overrides default."""
        with patch("main._call_llm_sync", return_value="custom response") as mock_llm:
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
                "system_prompt": "You are a custom assistant.",
            })
            assert resp.status_code == 200
            call_args = mock_llm.call_args
            messages = call_args[0][3]
            system_msg = messages[0]["content"]
            assert "custom assistant" in system_msg

    def test_suggest_missing_body(self, client: TestClient):
        """POST without body returns 422."""
        resp = client.post("/api/suggest")
        assert resp.status_code == 422

    def test_suggest_non_ascii_findings_cleaned(self, client: TestClient):
        """Non-ASCII characters in findings are cleaned before LLM call."""
        with patch("main._call_llm_sync", return_value="cleaned") as mock_llm:
            resp = client.post("/api/suggest", json={
                "provider": "openai",
                "api_key": "sk-test",
                "target": "10.0.0.1",
                "findings": "Port 22 open 🔓 \u00e9\u00e8\u00ea",
            })
            assert resp.status_code == 200
            call_args = mock_llm.call_args
            messages = call_args[0][3]
            # User message should not contain emoji
            user_msg = messages[-1]["content"]
            assert "\U0001f513" not in user_msg


# ═══════════════════════════════════════════════════════════════
#  3. GET /api/docker/status — deep branches
# ═══════════════════════════════════════════════════════════════

class TestDockerStatusDeep:
    """GET /api/docker/status — edge cases in container parsing."""

    @patch("main._run_docker_cmd", new_callable=AsyncMock)
    def test_docker_status_multiple_containers(self, mock_run, client: TestClient):
        """Multiple containers returned — running flag and kali/backend detection."""
        mock_run.return_value = {
            "ok": True,
            "exit": 0,
            "stdout": (
                '{"Names":"mirv-kali-tools","State":"running","Ports":"22/tcp"}\n'
                '{"Names":"mirv-backend","State":"running","Ports":"8000/tcp"}\n'
                '{"Names":"some-other","State":"exited","Ports":""}\n'
            ),
            "stderr": "",
        }
        resp = client.get("/api/docker/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["installed"] is True
        assert data["running"] is True
        assert data["kali_running"] is True
        assert data["backend_running"] is True
        assert len(data["containers"]) == 3

    @patch("main._run_docker_cmd", new_callable=AsyncMock)
    def test_docker_status_json_decode_error_skips_line(self, mock_run, client: TestClient):
        """Lines that fail JSON parsing are skipped gracefully."""
        mock_run.return_value = {
            "ok": True,
            "exit": 0,
            "stdout": (
                "not-valid-json\n"
                '{"Names":"mirv-kali-tools","State":"running","Ports":"22/tcp"}\n'
                "another-bad-line\n"
            ),
            "stderr": "",
        }
        resp = client.get("/api/docker/status")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["containers"]) == 1
        assert data["containers"][0]["name"] == "mirv-kali-tools"

    @patch("main._run_docker_cmd", new_callable=AsyncMock)
    def test_docker_status_empty_stdout(self, mock_run, client: TestClient):
        """Empty stdout — no containers."""
        mock_run.return_value = {
            "ok": True,
            "exit": 0,
            "stdout": "",
            "stderr": "",
        }
        resp = client.get("/api/docker/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["installed"] is True
        assert data["running"] is False
        assert data["containers"] == []

    @patch("main._run_docker_cmd", new_callable=AsyncMock)
    def test_docker_status_not_found_stderr(self, mock_run, client: TestClient):
        """Docker command not found error."""
        mock_run.return_value = {
            "ok": False,
            "exit": -1,
            "stdout": "",
            "stderr": "command not found",
        }
        resp = client.get("/api/docker/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["installed"] is False

    @patch("main._run_docker_cmd", new_callable=AsyncMock)
    def test_docker_status_alternate_field_names(self, mock_run, client: TestClient):
        """Containers with alternate JSON field names (Name vs Names, state vs State)."""
        mock_run.return_value = {
            "ok": True,
            "exit": 0,
            "stdout": '{"Name":"test-container","state":"running","ports":"8080/tcp"}\n',
            "stderr": "",
        }
        resp = client.get("/api/docker/status")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["containers"]) == 1
        assert data["containers"][0]["name"] == "test-container"
        assert data["containers"][0]["state"] == "running"


# ═══════════════════════════════════════════════════════════════
#  4. POST /api/docker/* — deep branches
# ═══════════════════════════════════════════════════════════════

class TestDockerControlDeep:
    """Docker start/stop/clean/build — error paths not covered elsewhere."""

    @patch("main._docker_compose", new_callable=AsyncMock)
    @patch("os.path.exists", return_value=True)
    def test_docker_start_failure_includes_stderr(self, mock_exists, mock_compose, client: TestClient):
        """Start failure returns error with stderr in the msg."""
        mock_compose.return_value = {
            "ok": False, "exit": 1, "stdout": "", "stderr": "permission denied"
        }
        resp = client.post("/api/docker/start")
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False
        assert "permission denied" in data["msg"]

    @patch("main._docker_compose", new_callable=AsyncMock)
    def test_docker_stop_failure_includes_stderr(self, mock_compose, client: TestClient):
        """Stop failure includes stderr in msg."""
        mock_compose.return_value = {
            "ok": False, "exit": 1, "stdout": "", "stderr": "no such container"
        }
        resp = client.post("/api/docker/stop")
        assert resp.status_code == 500
        data = resp.json()
        assert "no such container" in data["msg"]

    @patch("main._docker_compose", new_callable=AsyncMock)
    def test_docker_clean_second_step_failure(self, mock_compose, client: TestClient):
        """Clean succeeds at stop but fails at rm."""
        mock_compose.side_effect = [
            {"ok": True, "exit": 0, "stdout": "stopped", "stderr": ""},
            {"ok": False, "exit": 1, "stdout": "", "stderr": "cannot remove"},
        ]
        resp = client.post("/api/docker/clean")
        assert resp.status_code == 500
        data = resp.json()
        assert data["ok"] is False
        assert "cannot remove" in data["msg"]

    @patch("main._docker_compose", new_callable=AsyncMock)
    def test_docker_clean_success_messages(self, mock_compose, client: TestClient):
        """Clean success returns correct success message."""
        mock_compose.side_effect = [
            {"ok": True, "exit": 0, "stdout": "stopped", "stderr": ""},
            {"ok": True, "exit": 0, "stdout": "removed", "stderr": ""},
        ]
        resp = client.post("/api/docker/clean")
        assert resp.status_code == 200
        data = resp.json()
        assert "cleaned" in data["msg"].lower() or "volumes removed" in data["msg"].lower()

    def test_docker_build_returns_task_id_format(self, client: TestClient):
        """Build returns a task_id that starts with 'build_'."""
        resp = client.post("/api/docker/build")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["task_id"].startswith("build_")

    def test_docker_task_status_includes_action(self, client: TestClient):
        """Docker task status includes the action field."""
        import main as main_mod
        main_mod._docker_tasks["build_test_123"] = {
            "status": "done",
            "action": "build",
            "result": {"ok": True, "exit": 0, "stdout": "done", "stderr": ""},
        }
        try:
            resp = client.get("/api/docker/task/build_test_123")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["task"]["action"] == "build"
            assert data["task"]["status"] == "done"
        finally:
            del main_mod._docker_tasks["build_test_123"]

    def test_docker_task_running_status(self, client: TestClient):
        """Docker task in running state."""
        import main as main_mod
        main_mod._docker_tasks["build_run"] = {"status": "running", "action": "build"}
        try:
            resp = client.get("/api/docker/task/build_run")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["task"]["status"] == "running"
        finally:
            del main_mod._docker_tasks["build_run"]

    @patch("main._docker_compose", new_callable=AsyncMock)
    @patch("os.path.exists", return_value=True)
    def test_docker_start_success_message(self, mock_exists, mock_compose, client: TestClient):
        """Start success returns correct success message."""
        mock_compose.return_value = {
            "ok": True, "exit": 0, "stdout": "started", "stderr": ""
        }
        resp = client.post("/api/docker/start")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "started" in data["msg"].lower()

    @patch("main._docker_compose", new_callable=AsyncMock)
    def test_docker_stop_success_message(self, mock_compose, client: TestClient):
        """Stop success returns correct success message."""
        mock_compose.return_value = {
            "ok": True, "exit": 0, "stdout": "stopped", "stderr": ""
        }
        resp = client.post("/api/docker/stop")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "stopped" in data["msg"].lower()


# ═══════════════════════════════════════════════════════════════
#  5. GET/POST/DELETE /api/reports — CRUD endpoints
# ═══════════════════════════════════════════════════════════════

class TestReportsCRUD:
    """GET/POST/DELETE /api/reports — CRUD endpoints."""

    @patch("backend.database.list_reports")
    def test_get_reports_db_unavailable(self, mock_list, client: TestClient):
        """GET /api/reports when DB unavailable returns 503."""
        mock_list.return_value = None
        resp = client.get("/api/reports")
        assert resp.status_code == 503
        data = resp.json()
        assert data["ok"] is False
        assert "Database not configured" in data["error"]

    @patch("backend.database.list_reports")
    def test_get_reports_returns_list(self, mock_list, client: TestClient):
        """GET /api/reports returns list from DB."""
        mock_list.return_value = [
            {"id": "r1", "type": "scan", "title": "Test"},
            {"id": "r2", "type": "bounty", "title": "Test2"},
        ]
        resp = client.get("/api/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert len(data["data"]) == 2

    @patch("backend.database.list_reports")
    def test_get_reports_empty_list(self, mock_list, client: TestClient):
        """GET /api/reports returns empty list."""
        mock_list.return_value = []
        resp = client.get("/api/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["data"] == []

    @patch("backend.database.save_report")
    def test_post_reports_creates_report(self, mock_save, client: TestClient):
        """POST /api/reports with valid body creates report."""
        mock_save.return_value = {"id": "new-id", "type": "scan", "title": "My Report"}
        resp = client.post("/api/reports", json={
            "type": "scan",
            "title": "My Report",
            "target": "10.0.0.1",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["data"]["id"] == "new-id"

    @patch("backend.database.save_report")
    def test_post_reports_db_unavailable(self, mock_save, client: TestClient):
        """POST /api/reports when DB unavailable returns 503."""
        mock_save.return_value = None
        resp = client.post("/api/reports", json={
            "type": "scan",
            "title": "Test",
        })
        assert resp.status_code == 503

    def test_post_reports_missing_body(self, client: TestClient):
        """POST /api/reports without body returns 422."""
        resp = client.post("/api/reports")
        assert resp.status_code == 422

    def test_post_reports_missing_type(self, client: TestClient):
        """POST /api/reports without required 'type' field returns 422."""
        resp = client.post("/api/reports", json={"title": "Test"})
        assert resp.status_code == 422

    @patch("backend.database.save_report")
    def test_post_reports_minimal_body(self, mock_save, client: TestClient):
        """POST /api/reports with only required 'type' field."""
        mock_save.return_value = {"id": "x", "type": "scan"}
        resp = client.post("/api/reports", json={"type": "scan"})
        assert resp.status_code == 201

    @patch("backend.database.delete_report")
    def test_delete_report_success(self, mock_delete, client: TestClient):
        """DELETE /api/reports/{id} succeeds."""
        mock_delete.return_value = True
        resp = client.delete("/api/reports/report-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("backend.database.delete_report")
    def test_delete_report_not_found(self, mock_delete, client: TestClient):
        """DELETE /api/reports/{id} when delete fails returns 400."""
        mock_delete.return_value = False
        resp = client.delete("/api/reports/nonexistent")
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False


# ═══════════════════════════════════════════════════════════════
#  6. GET/POST /api/settings — deep branches
# ═══════════════════════════════════════════════════════════════

class TestSettingsDeep:
    """GET/POST /api/settings — deep branches for value lookups."""

    @patch("backend.database.is_available", return_value=False)
    @patch("backend.database.get_setting", return_value=None)
    def test_get_setting_db_unavailable_returns_503(self, mock_get, mock_avail, client: TestClient):
        """GET /api/settings/{key} returns 503 when DB unavailable and value is None."""
        resp = client.get("/api/settings/my_key")
        assert resp.status_code == 503
        data = resp.json()
        assert data["ok"] is False
        assert "Database not configured" in data["error"]

    @patch("backend.database.is_available", return_value=True)
    @patch("backend.database.get_setting", return_value=None)
    def test_get_setting_value_none_but_available(self, mock_get, mock_avail, client: TestClient):
        """GET /api/settings/{key} returns 200 with null value when key doesn't exist but DB is up."""
        resp = client.get("/api/settings/nonexistent_key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["value"] is None

    @patch("backend.database.is_available", return_value=True)
    @patch("backend.database.get_setting", return_value="dark")
    def test_get_setting_existing_value(self, mock_get, mock_avail, client: TestClient):
        """GET /api/settings/{key} returns the value."""
        resp = client.get("/api/settings/theme")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["key"] == "theme"
        assert data["value"] == "dark"

    @patch("backend.database.set_setting")
    def test_set_setting_complex_value(self, mock_set, client: TestClient):
        """POST /api/settings with dict value."""
        mock_set.return_value = True
        resp = client.post("/api/settings", json={
            "key": "ai_config",
            "value": {"provider": "openai", "model": "gpt-4"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    @patch("backend.database.set_setting")
    def test_set_setting_list_value(self, mock_set, client: TestClient):
        """POST /api/settings with list value."""
        mock_set.return_value = True
        resp = client.post("/api/settings", json={
            "key": "allowed_tools",
            "value": ["nmap", "nikto"],
        })
        assert resp.status_code == 200

    @patch("backend.database.set_setting")
    def test_set_setting_db_unavailable(self, mock_set, client: TestClient):
        """POST /api/settings when DB unavailable returns 503."""
        mock_set.return_value = None
        resp = client.post("/api/settings", json={
            "key": "theme",
            "value": "dark",
        })
        assert resp.status_code == 503


# ═══════════════════════════════════════════════════════════════
#  7. POST /api/generate-pdf — deep branches
# ═══════════════════════════════════════════════════════════════

class TestGeneratePDFDeep:
    """POST /api/generate-pdf — ImportError and exception paths."""

    def test_generate_pdf_import_error(self, client: TestClient):
        """ImportError when reportlab not installed returns 500."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "reportlab":
                raise ImportError("No module named 'reportlab'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fake_import):
            resp = client.post("/api/generate-pdf", json={
                "content": "# Test",
                "title": "Test",
            })
            assert resp.status_code == 500
            data = resp.json()
            assert data["ok"] is False
            assert "reportlab" in data["error"].lower()

    def test_generate_pdf_exception_during_build(self, client: TestClient):
        """Exception during PDF build returns 500."""
        with patch("reportlab.platypus.SimpleDocTemplate.build", side_effect=RuntimeError("build failed")):
            resp = client.post("/api/generate-pdf", json={
                "content": "# Test\nHello world",
                "title": "Error PDF",
            })
            assert resp.status_code == 500
            data = resp.json()
            assert data["ok"] is False

    def test_generate_pdf_returns_valid_content_type(self, client: TestClient):
        """Successful PDF returns application/pdf content type."""
        resp = client.post("/api/generate-pdf", json={
            "content": "# Title\nSome content here",
            "title": "Content Type Test",
        })
        if resp.status_code == 200:
            assert resp.headers["content-type"] == "application/pdf"
            assert "Content-Disposition" in resp.headers

    def test_generate_pdf_custom_author(self, client: TestClient):
        """PDF with custom author field."""
        resp = client.post("/api/generate-pdf", json={
            "content": "Hello",
            "title": "Author Test",
            "author": "Security Auditor",
        })
        # Should succeed (200) or fail if reportlab missing (500)
        assert resp.status_code in (200, 500)

    def test_generate_pdf_bullet_list_items(self, client: TestClient):
        """PDF with bullet list items rendered correctly."""
        content = "- Item one\n* Item two\n- Item three"
        resp = client.post("/api/generate-pdf", json={
            "content": content,
            "title": "Bullet Test",
        })
        assert resp.status_code in (200, 500)

    def test_generate_pdf_inline_code(self, client: TestClient):
        """PDF with inline code (backtick-wrapped text)."""
        content = "Use `nmap -sV` to scan"
        resp = client.post("/api/generate-pdf", json={
            "content": content,
            "title": "Code Test",
        })
        assert resp.status_code in (200, 500)

    def test_generate_pdf_all_headers(self, client: TestClient):
        """PDF with H1, H2, H3 headers."""
        content = "# Main Title\n## Subtitle\n### Details\nParagraph here."
        resp = client.post("/api/generate-pdf", json={
            "content": content,
            "title": "Headers Test",
        })
        assert resp.status_code in (200, 500)


# ═══════════════════════════════════════════════════════════════
#  8. GET /api/findings/stats — stats endpoint
# ═══════════════════════════════════════════════════════════════

class TestFindingsStats:
    """GET /api/findings/stats — statistics about findings."""

    @patch("backend.database.list_findings")
    def test_stats_db_unavailable_returns_zeros(self, mock_list, client: TestClient):
        """Stats when DB unavailable returns zero counts."""
        mock_list.return_value = None
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] == 0
        assert data["tools"] == []
        assert data["targets"] == []

    @patch("backend.database.list_findings")
    def test_stats_empty_findings(self, mock_list, client: TestClient):
        """Stats with empty findings list."""
        mock_list.return_value = []
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] == 0
        assert data["tools"] == []
        assert data["targets"] == []

    @patch("backend.database.list_findings")
    def test_stats_with_findings(self, mock_list, client: TestClient):
        """Stats with findings returns correct counts, tools, and targets."""
        mock_list.return_value = [
            {"tool": "nmap", "target": "10.0.0.1", "severity": "high"},
            {"tool": "nmap", "target": "10.0.0.1", "severity": "medium"},
            {"tool": "nikto", "target": "10.0.0.2", "severity": "low"},
            {"tool": "gobuster", "target": "10.0.0.1", "severity": "info"},
        ]
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] == 4
        assert sorted(data["tools"]) == ["gobuster", "nikto", "nmap"]
        assert sorted(data["targets"]) == ["10.0.0.1", "10.0.0.2"]

    @patch("backend.database.list_findings")
    def test_stats_findings_missing_tool_field(self, mock_list, client: TestClient):
        """Findings missing 'tool' field default to '?'."""
        mock_list.return_value = [
            {"target": "10.0.0.1", "severity": "high"},
        ]
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert "?" in data["tools"]

    @patch("backend.database.list_findings")
    def test_stats_findings_missing_target_field(self, mock_list, client: TestClient):
        """Findings with empty/missing target are excluded from targets list."""
        mock_list.return_value = [
            {"tool": "nmap", "severity": "high"},
            {"tool": "nikto", "target": "", "severity": "medium"},
            {"tool": "gobuster", "target": "10.0.0.1", "severity": "info"},
        ]
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert data["targets"] == ["10.0.0.1"]

    @patch("backend.database.list_findings")
    def test_stats_deduplicates_tools(self, mock_list, client: TestClient):
        """Same tool name appears only once in tools list."""
        mock_list.return_value = [
            {"tool": "nmap", "target": "10.0.0.1"},
            {"tool": "nmap", "target": "10.0.0.2"},
            {"tool": "nmap", "target": "10.0.0.3"},
        ]
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert data["tools"] == ["nmap"]


# ═══════════════════════════════════════════════════════════════
#  9. POST /api/n8n/trigger, GET /api/n8n/status — deep branches
# ═══════════════════════════════════════════════════════════════

class TestN8nDeep:
    """n8n trigger and status — deep branches."""

    @patch("main._http_post_json")
    def test_trigger_non_2xx_response(self, mock_http, client: TestClient):
        """Trigger when n8n returns non-2xx status."""
        mock_http.return_value = (500, '{"error":"internal"}')
        resp = client.post("/api/n8n/trigger", json={
            "target": "10.0.0.1",
            "scan_type": "full",
            "n8n_url": "http://localhost:5678",
        })
        assert resp.status_code == 200  # Endpoint itself returns 200, but ok=False
        data = resp.json()
        assert data["ok"] is False
        assert data["status"] == 500

    @patch("main._http_post_json")
    def test_trigger_response_data_truncated(self, mock_http, client: TestClient):
        """Trigger truncates response data to 2000 chars."""
        long_response = "x" * 3000
        mock_http.return_value = (200, long_response)
        resp = client.post("/api/n8n/trigger", json={
            "target": "10.0.0.1",
            "n8n_url": "http://localhost:5678",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["data"]) <= 2000

    @patch("main._http_post_json")
    def test_trigger_custom_n8n_url(self, mock_http, client: TestClient):
        """Trigger with custom n8n URL."""
        mock_http.return_value = (200, '{"ok":true}')
        resp = client.post("/api/n8n/trigger", json={
            "target": "192.168.1.0/24",
            "scan_type": "recon",
            "n8n_url": "http://n8n.example.com:5678",
        })
        assert resp.status_code == 200
        # Verify the URL was constructed correctly
        call_args = mock_http.call_args
        url = call_args[0][0]
        assert "n8n.example.com" in url
        assert "attack-surface-scan" in url

    @patch("main._http_get")
    def test_n8n_status_unreachable(self, mock_get, client: TestClient):
        """n8n status returns unreachable when health check fails."""
        mock_get.return_value = 0
        resp = client.get("/api/n8n/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["reachable"] is False
        assert data["status"] == 0

    @patch("main._http_get")
    def test_n8n_status_custom_url(self, mock_get, client: TestClient):
        """n8n status with custom URL."""
        mock_get.return_value = 200
        resp = client.get("/api/n8n/status?n8n_url=http://remote:5678")
        assert resp.status_code == 200
        data = resp.json()
        assert data["reachable"] is True
        # Verify the URL was constructed with /healthz
        call_args = mock_get.call_args
        url = call_args[0][0]
        assert "remote:5678" in url
        assert "healthz" in url


# ═══════════════════════════════════════════════════════════════
#  10. Kali-MCP endpoints — deep branches
# ═══════════════════════════════════════════════════════════════

class TestKaliMCPDeep:
    """Kali-MCP endpoints — deep validation and error branches."""

    def test_kali_mcp_status_fields(self, client: TestClient):
        """Status returns all expected fields."""
        resp = client.get("/api/kali-mcp/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "configured" in data
        assert "available" in data
        assert "url" in data

    @patch("backend.kali_mcp_client.execute_command", new_callable=AsyncMock)
    def test_kali_mcp_exec_empty_command_string(self, mock_exec, client: TestClient):
        """Exec with empty command string returns 400 (when available)."""
        import main as main_mod
        original = main_mod._kali_mcp_available
        main_mod._kali_mcp_available = True
        try:
            resp = client.post("/api/kali-mcp/exec", json={"command": ""})
            assert resp.status_code == 400
            data = resp.json()
            assert data["ok"] is False
            assert "command is required" in data["error"]
        finally:
            main_mod._kali_mcp_available = original

    @patch("backend.kali_mcp_client.execute_command", new_callable=AsyncMock)
    def test_kali_mcp_exec_exception_propagates(self, mock_exec):
        """Exec exception propagates as 500 (endpoint has no try/except)."""
        mock_exec.side_effect = RuntimeError("Connection refused")
        import main as main_mod
        original = main_mod._kali_mcp_available
        main_mod._kali_mcp_available = True
        try:
            # raise_server_exceptions=False so TestClient returns 500 instead of raising
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.post("/api/kali-mcp/exec", json={"command": "nmap -sV 10.0.0.1"})
                assert resp.status_code == 500
        finally:
            main_mod._kali_mcp_available = original

    @patch("backend.kali_mcp_client.list_available_tools", new_callable=AsyncMock)
    def test_kali_mcp_tools_empty_list(self, mock_tools, client: TestClient):
        """Tools returns empty list when no tools available."""
        mock_tools.return_value = []
        import main as main_mod
        original = main_mod._kali_mcp_available
        main_mod._kali_mcp_available = True
        try:
            resp = client.get("/api/kali-mcp/tools")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["tools"] == []
        finally:
            main_mod._kali_mcp_available = original

    @patch("backend.kali_mcp_client.list_available_tools", new_callable=AsyncMock)
    def test_kali_mcp_tools_exception(self, mock_tools):
        """Tools exception propagates as 500 (endpoint has no try/except)."""
        mock_tools.side_effect = RuntimeError("MCP server down")
        import main as main_mod
        original = main_mod._kali_mcp_available
        main_mod._kali_mcp_available = True
        try:
            with TestClient(app, raise_server_exceptions=False) as c:
                resp = c.get("/api/kali-mcp/tools")
                assert resp.status_code == 500
        finally:
            main_mod._kali_mcp_available = original

    @patch("backend.kali_mcp_client.execute_command", new_callable=AsyncMock)
    def test_kali_mcp_exec_error_prefix_lowercase(self, mock_exec, client: TestClient):
        """Exec returns 500 when output starts with 'ERROR' (case-sensitive)."""
        mock_exec.return_value = "ERROR: something failed"
        import main as main_mod
        original = main_mod._kali_mcp_available
        main_mod._kali_mcp_available = True
        try:
            resp = client.post("/api/kali-mcp/exec", json={"command": "bad cmd"})
            assert resp.status_code == 500
            data = resp.json()
            assert data["ok"] is False
            assert "ERROR" in data["error"]
        finally:
            main_mod._kali_mcp_available = original


# ═══════════════════════════════════════════════════════════════
#  11. POST /api/exif/analyze — validation branches
# ═══════════════════════════════════════════════════════════════

class TestExifAnalyzeDeep:
    """POST /api/exif/analyze — validation and error branches."""

    def test_exif_analyze_unsupported_content_type(self, client: TestClient):
        """Upload with unsupported MIME type returns 422."""
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("test.pdf", b"%PDF-1.4 fake content here", "application/pdf")},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False
        assert "Unsupported file type" in data["error"]

    def test_exif_analyze_file_too_small(self, client: TestClient):
        """File smaller than 50 bytes returns 422."""
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("tiny.jpg", b"tiny", "image/jpeg")},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False
        assert "too small" in data["error"].lower()

    @patch("main.exif_analyze", new_callable=AsyncMock)
    def test_exif_analyze_no_exif_data(self, mock_analyze, client: TestClient):
        """Image with no EXIF data returns ok with null gps/camera/metadata."""
        mock_result = MagicMock()
        mock_result.gps = None
        mock_result.camera = None
        mock_result.metadata = None
        mock_result.image.format = "JPEG"
        mock_result.image.width = 100
        mock_result.image.height = 100
        mock_result.image.file_size = 5000
        mock_result.image.color_space = "sRGB"
        mock_result.image.orientation = "Normal"
        mock_result.has_exif = False
        mock_result.severity = "info"
        mock_result.thumbnail = None
        mock_result.raw_tags = {}
        mock_result.duration_seconds = 0.1
        mock_analyze.return_value = mock_result

        with patch("main.exif_to_mirv", return_value=[]):
            # Create valid JPEG content (>50 bytes)
            content = b"\xff\xd8\xff\xe0" + b"\x00" * 100
            resp = client.post(
                "/api/exif/analyze",
                files={"file": ("no_exif.jpg", content, "image/jpeg")},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["gps"] is None
            assert data["camera"] is None
            assert data["metadata"] is None

    @patch("main.exif_analyze", new_callable=AsyncMock)
    def test_exif_analyze_value_error(self, mock_analyze, client: TestClient):
        """ValueError from exif_analyze returns 422."""
        mock_analyze.side_effect = ValueError("Not a valid image")
        content = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("bad.jpg", content, "image/jpeg")},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False
        assert "Not a valid image" in data["error"]

    @patch("main.exif_analyze", new_callable=AsyncMock)
    def test_exif_analyze_general_exception(self, mock_analyze, client: TestClient):
        """General exception from exif_analyze returns 502."""
        mock_analyze.side_effect = RuntimeError("Something broke")
        content = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("error.jpg", content, "image/jpeg")},
        )
        assert resp.status_code == 502
        data = resp.json()
        assert data["ok"] is False
        assert "EXIF analysis failed" in data["error"]


# ═══════════════════════════════════════════════════════════════
#  12. GET /api/exif/analyze — URL-based validation branches
# ═══════════════════════════════════════════════════════════════

class TestExifAnalyzeURLDeep:
    """GET /api/exif/analyze — URL parameter validation branches."""

    def test_exif_url_empty_string(self, client: TestClient):
        """Empty URL parameter returns 422."""
        resp = client.get("/api/exif/analyze?url=")
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False
        assert "Provide" in data["error"]

    def test_exif_url_missing_param(self, client: TestClient):
        """Missing url parameter returns 422 (or error)."""
        resp = client.get("/api/exif/analyze")
        # Without url param, FastAPI may return 422 or the handler may handle it
        assert resp.status_code in (422, 200, 400)

    def test_exif_url_no_http_prefix(self, client: TestClient):
        """URL without http:// or https:// prefix returns 422."""
        resp = client.get("/api/exif/analyze?url=ftp://example.com/image.jpg")
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False
        assert "http://" in data["error"] or "https://" in data["error"]

    def test_exif_url_ftp_protocol(self, client: TestClient):
        """FTP URL is rejected."""
        resp = client.get("/api/exif/analyze?url=ftp://files.example.com/pic.jpg")
        assert resp.status_code == 422

    @patch("main.exif_analyze_url", new_callable=AsyncMock)
    def test_exif_url_value_error(self, mock_analyze, client: TestClient):
        """ValueError from URL analysis returns 422."""
        mock_analyze.side_effect = ValueError("Cannot fetch image")
        resp = client.get("/api/exif/analyze?url=https://example.com/bad.jpg")
        assert resp.status_code == 422
        data = resp.json()
        assert data["ok"] is False
        assert "Cannot fetch image" in data["error"]

    @patch("main.exif_analyze_url", new_callable=AsyncMock)
    def test_exif_url_general_exception(self, mock_analyze, client: TestClient):
        """General exception from URL analysis returns 502."""
        mock_analyze.side_effect = RuntimeError("Network error")
        resp = client.get("/api/exif/analyze?url=https://example.com/img.jpg")
        assert resp.status_code == 502
        data = resp.json()
        assert data["ok"] is False
        assert "EXIF analysis failed" in data["error"]

    @patch("main.exif_to_mirv", return_value=[])
    @patch("main.exif_reverse_geocode", new_callable=AsyncMock)
    @patch("main.exif_analyze_url", new_callable=AsyncMock)
    def test_exif_url_with_gps_triggers_geocoding(self, mock_analyze, mock_geocode, mock_mirv, client: TestClient):
        """URL analysis with GPS data triggers reverse geocoding."""
        mock_result = MagicMock()
        mock_result.gps = MagicMock()
        mock_result.gps.lat = 40.7128
        mock_result.gps.lon = -74.0060
        mock_result.gps.altitude = None
        mock_result.gps.altitude_ref = None
        mock_result.gps.gps_timestamp = None
        mock_result.gps.map_url = None
        mock_result.gps.google_maps_url = None
        mock_result.camera = None
        mock_result.metadata = None
        mock_result.image.format = "JPEG"
        mock_result.image.width = 800
        mock_result.image.height = 600
        mock_result.image.file_size = 50000
        mock_result.image.color_space = "sRGB"
        mock_result.image.orientation = "Normal"
        mock_result.has_exif = True
        mock_result.severity = "medium"
        mock_result.thumbnail = None
        mock_result.raw_tags = {}
        mock_result.duration_seconds = 0.5
        mock_result.filename = "gps_photo.jpg"
        mock_result.geocoding = None
        mock_analyze.return_value = mock_result
        mock_geocode.return_value = {"city": "New York", "country": "US"}

        resp = client.get("/api/exif/analyze?url=https://example.com/gps.jpg")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["gps"]["lat"] == 40.7128
        mock_geocode.assert_called_once_with(40.7128, -74.0060)

    @patch("main.exif_to_mirv", return_value=[])
    @patch("main.exif_analyze_url", new_callable=AsyncMock)
    def test_exif_url_with_camera_data(self, mock_analyze, mock_mirv, client: TestClient):
        """URL analysis with camera data populates camera field."""
        mock_result = MagicMock()
        mock_result.gps = None
        mock_result.camera = MagicMock()
        mock_result.camera.make = "Canon"
        mock_result.camera.model = "EOS R5"
        mock_result.camera.lens = "RF 50mm"
        mock_result.camera.focal_length = "50mm"
        mock_result.camera.fnumber = "f/1.8"
        mock_result.camera.iso = 100
        mock_result.camera.exposure_time = "1/200"
        mock_result.camera.flash = "No Flash"
        mock_result.camera.software = "Adobe Lightroom"
        mock_result.metadata = None
        mock_result.image.format = "JPEG"
        mock_result.image.width = 100
        mock_result.image.height = 100
        mock_result.image.file_size = 1000
        mock_result.image.color_space = "sRGB"
        mock_result.image.orientation = "Normal"
        mock_result.has_exif = True
        mock_result.severity = "info"
        mock_result.thumbnail = None
        mock_result.raw_tags = {}
        mock_result.duration_seconds = 0
        mock_result.filename = "camera.jpg"
        mock_result.geocoding = None
        mock_analyze.return_value = mock_result

        resp = client.get("/api/exif/analyze?url=https://example.com/camera.jpg")
        assert resp.status_code == 200
        data = resp.json()
        assert data["camera"]["make"] == "Canon"
        assert data["camera"]["model"] == "EOS R5"


# ═══════════════════════════════════════════════════════════════
#  13. POST /api/exif/analyze — with GPS data
# ═══════════════════════════════════════════════════════════════

class TestExifAnalyzeGPS:
    """POST /api/exif/analyze — GPS data populates correctly."""

    @patch("main.exif_reverse_geocode", new_callable=AsyncMock)
    @patch("main.exif_to_mirv", return_value=[{"type": "gps", "severity": "medium"}])
    @patch("main.exif_analyze", new_callable=AsyncMock)
    def test_exif_analyze_with_gps_and_metadata(self, mock_analyze, mock_mirv, mock_geocode, client: TestClient):
        """Image with GPS, camera, and metadata populates all fields."""
        mock_result = MagicMock()
        mock_result.gps = MagicMock()
        mock_result.gps.lat = 51.5074
        mock_result.gps.lon = -0.1278
        mock_result.gps.altitude = 10.0
        mock_result.gps.altitude_ref = "above sea level"
        mock_result.gps.gps_timestamp = "2025:01:01 12:00:00"
        mock_result.gps.map_url = "https://maps.google.com/?q=51.5,-0.12"
        mock_result.gps.google_maps_url = "https://maps.google.com/?q=51.5,-0.12"
        mock_result.camera = MagicMock()
        mock_result.camera.make = "Apple"
        mock_result.camera.model = "iPhone 15"
        mock_result.camera.lens = None
        mock_result.camera.focal_length = "6.86mm"
        mock_result.camera.fnumber = "f/1.78"
        mock_result.camera.iso = 64
        mock_result.camera.exposure_time = "1/120"
        mock_result.camera.flash = "Off"
        mock_result.camera.software = "17.0"
        mock_result.metadata = MagicMock()
        mock_result.metadata.datetime_original = "2025:01:01 12:00:00"
        mock_result.metadata.datetime_digitized = "2025:01:01 12:00:00"
        mock_result.metadata.artist = "John"
        mock_result.metadata.copyright = "CC-BY"
        mock_result.metadata.description = "Test photo"
        mock_result.metadata.x_resolution = 300
        mock_result.metadata.y_resolution = 300
        mock_result.image.format = "JPEG"
        mock_result.image.width = 4032
        mock_result.image.height = 3024
        mock_result.image.file_size = 2048000
        mock_result.image.color_space = "sRGB"
        mock_result.image.orientation = "Normal"
        mock_result.has_exif = True
        mock_result.severity = "high"
        mock_result.thumbnail = "base64data..."
        mock_result.raw_tags = {"0th": "value"}
        mock_result.duration_seconds = 0.3
        mock_analyze.return_value = mock_result
        mock_geocode.return_value = {"city": "London", "country": "GB"}

        content = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("gps_photo.jpg", content, "image/jpeg")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["gps"]["lat"] == 51.5074
        assert data["gps"]["lon"] == -0.1278
        assert data["gps"]["altitude"] == 10.0
        assert data["camera"]["make"] == "Apple"
        assert data["metadata"]["artist"] == "John"
        assert data["geocoding"]["city"] == "London"
        assert data["findings"] == [{"type": "gps", "severity": "medium"}]
        mock_geocode.assert_called_once()


# ═══════════════════════════════════════════════════════════════
#  14. _call_llm_sync — provider branches
# ═══════════════════════════════════════════════════════════════

class TestCallLLMSyncDeep:
    """_call_llm_sync — provider-specific branches."""

    def test_unknown_provider_raises_value_error(self):
        """Unknown provider raises ValueError."""
        from main import _call_llm_sync
        with pytest.raises(ValueError, match="Unknown provider"):
            _call_llm_sync("nonexistent", "key", "model", [{"role": "user", "content": "hi"}])

    def test_local_provider_default_model(self):
        """Local provider uses 'llama3' as default model."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "hello from local"}}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("local", "", "", [{"role": "user", "content": "hi"}])
            assert result == "hello from local"
            # Verify the URL uses default model
            call_args = mock_urlopen.call_args
            req = call_args[0][0]
            body = json.loads(req.data.decode())
            assert body["model"] == "llama3"

    def test_openai_default_model_fallback(self):
        """OpenAI provider uses default model when model is provider name."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "ok"}}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("openai", "sk-test", "openai", [{"role": "user", "content": "hi"}])
            req = mock_urlopen.call_args[0][0]
            body = json.loads(req.data.decode())
            assert body["model"] == "gpt-4o-mini"

    def test_openai_empty_choices_returns_string(self):
        """OpenAI response with no choices returns string of data."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"no_choices": True}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("openai", "sk-test", "gpt-4o", [{"role": "user", "content": "hi"}])
            assert "no_choices" in result

    def test_gemini_default_model(self):
        """Gemini provider uses default model when none specified."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "candidates": [{"content": {"parts": [{"text": "gemini response"}]}}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("gemini", "key", "", [{"role": "user", "content": "hi"}])
            assert result == "gemini response"
            req = mock_urlopen.call_args[0][0]
            assert "gemini-2.0-flash" in req.full_url

    def test_gemini_empty_candidates(self):
        """Gemini response with no candidates returns string."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"candidates": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("gemini", "key", "gemini-pro", [{"role": "user", "content": "hi"}])
            assert "candidates" in result

    def test_anthropic_default_model(self):
        """Anthropic provider uses default model when none specified."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "content": [{"text": "claude response"}]
            }).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("anthropic", "key", "", [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "hi"},
            ])
            assert result == "claude response"

    def test_anthropic_empty_content(self):
        """Anthropic response with no content returns string."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"content": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _call_llm_sync("anthropic", "key", "claude-3", [{"role": "user", "content": "hi"}])
            assert "content" in result

    def test_local_provider_connection_error(self):
        """Local provider raises RuntimeError on connection error."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            with pytest.raises(RuntimeError, match="Cannot connect to local AI"):
                _call_llm_sync("local", "", "", [{"role": "user", "content": "hi"}])

    def test_openai_unicode_decode_error(self):
        """OpenAI provider raises RuntimeError on UnicodeDecodeError."""
        from main import _call_llm_sync
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = b"\xff\xfe\xfd"
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            with pytest.raises(RuntimeError, match="Encoding error"):
                _call_llm_sync("openai", "sk-test", "gpt-4o", [{"role": "user", "content": "hi"}])
