"""
tests/test_orchestrator.py — Multi-Agent Orchestrator tests.

Covers:
  * route() — keyword matching, default fallback, multi-keyword tie-break.
  * execute() — auto-routing, explicit specialist, OK / error responses,
    missing skill playbook (generic prompt), secret redaction before LLM.
  * REST endpoints — POST /api/orchestrator/route (200/422/500),
    GET /api/orchestrator/specialists (200),
    GET /api/orchestrator/specialists/{name} (200/404).

Mocks the LLM call (``orchestrator._call_llm``) and skill rendering so
no network or filesystem I/O is required.
"""

from __future__ import annotations

import io
import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# ── Path setup ──
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.orchestrator as orch
from backend.orchestrator import (
    route,
    execute,
    list_specialists,
    get_specialist,
    _build_system_prompt,
    _SPECIALISTS,
)
from main import app


# ═══════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture()
def client():
    """Yield a FastAPI TestClient sharing the global app instance."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _patch_db_unavailable():
    """Make all DB calls return None (Supabase not configured)."""
    with patch("backend.database.is_available", return_value=False), \
         patch("backend.database.get_client", return_value=None):
        yield


@pytest.fixture(autouse=True)
def _reset_scope():
    """Ensure scope_guard returns no authorized scope between tests."""
    with patch("backend.scope_guard.get_config", return_value={}):
        yield


@pytest.fixture(autouse=True)
def _isolate_episodic_memory():
    """Keep the existing execute() tests hermetic — never touch the real
    SQLite store. Tests that need to assert on episodic-memory behaviour
    apply their own ``patch`` on top of this default no-op layer.
    """
    with patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}), \
         patch("backend.episodic_memory.get_episodic_context", return_value=""):
        yield


# ═══════════════════════════════════════════════════════════════
#  1. route() — keyword matching
# ═══════════════════════════════════════════════════════════════

class TestRoute:
    def test_webvuln_sql_injection(self):
        assert route("scan this web app for SQL injection") == "webvuln"

    def test_recon_subdomains(self):
        assert route("enumerate subdomains for example.com") == "recon"

    def test_osint_email_breaches(self):
        assert route("check email for breaches") == "osint"

    def test_forensics_memory_dump(self):
        assert route("analyze memory dump for malware") == "forensics"

    def test_password_audit_ntlm(self):
        assert route("crack this NTLM hash") == "password-audit"

    def test_default_when_no_keywords(self):
        assert route("do something") == "recon"

    def test_empty_string_defaults_to_recon(self):
        assert route("") == "recon"

    def test_non_string_defaults_to_recon(self):
        assert route(None) == "recon"  # type: ignore[arg-type]

    def test_case_insensitive(self):
        assert route("SCAN THIS WEB APP FOR SQL INJECTION") == "webvuln"

    def test_multiple_keywords_picks_highest(self):
        # "nmap" + "subdomain" + "port scan" → 3 recon keywords,
        # "web" → 1 webvuln keyword. recon should win.
        task = "use nmap to port scan and find subdomain, not really web"
        assert route(task) == "recon"

    def test_nmap_routes_to_recon(self):
        assert route("run nmap against 10.0.0.1") == "recon"

    def test_hashcat_routes_to_password_audit(self):
        assert route("use hashcat to crack the hash") == "password-audit"

    def test_volatility_routes_to_forensics(self):
        assert route("run volatility on the memory image") == "forensics"

    def test_xss_routes_to_webvuln(self):
        assert route("test for XSS vulnerabilities") == "webvuln"

    def test_tie_break_is_stable(self):
        # Equal hit counts across two specialists → first in dict order wins.
        # "recon" (1: web) vs "webvuln" (1: web) — only webvuln matches here.
        assert route("investigate the web") == "webvuln"


# ═══════════════════════════════════════════════════════════════
#  2. _build_system_prompt() — grounding + fallback
# ═══════════════════════════════════════════════════════════════

class TestBuildSystemPrompt:
    def test_uses_skill_playbook_when_available(self):
        with patch("backend.orchestrator._render_skill", return_value="# Recon Methodology\n1. nmap"):
            prompt = _build_system_prompt("recon", "10.0.0.1", "open ports")
            assert "MIRV recon specialist" in prompt
            assert "# Recon Methodology" in prompt
            assert "10.0.0.1" in prompt
            assert "open ports" in prompt
            assert "structured JSON array" in prompt

    def test_falls_back_to_generic_when_skill_missing(self):
        with patch("backend.orchestrator._render_skill", return_value=""):
            prompt = _build_system_prompt("recon", "", "")
            assert "MIRV recon specialist" in prompt
            assert "structured JSON array" in prompt
            # No skill body section
            assert "Recon Methodology" not in prompt

    def test_includes_context_block_always(self):
        with patch("backend.orchestrator._render_skill", return_value=""):
            prompt = _build_system_prompt("osint", "", "")
            assert "Context:" in prompt
            assert "Target: unspecified" in prompt
            assert "Current findings: none" in prompt

    def test_unknown_specialist_uses_generic(self):
        with patch("backend.orchestrator._render_skill", return_value=""):
            prompt = _build_system_prompt("bogus", "x", "y")
            assert "MIRV bogus specialist" in prompt
            assert "Target: x" in prompt


# ═══════════════════════════════════════════════════════════════
#  3. execute() — happy path, routing, errors, redaction
# ═══════════════════════════════════════════════════════════════

class TestExecute:
    def test_auto_route_uses_route(self):
        with patch("backend.orchestrator._call_llm", return_value="LLM OK") as mock_llm, \
             patch("backend.orchestrator._render_skill", return_value=""):
            result = execute(task="scan web app for SQL injection")
            assert result["ok"] is True
            assert result["specialist"] == "webvuln"
            assert result["response"] == "LLM OK"
            assert result["task"] == "scan web app for SQL injection"
            mock_llm.assert_called_once()

    def test_explicit_specialist_overrides_routing(self):
        with patch("backend.orchestrator._call_llm", return_value="LLM OK") as mock_llm, \
             patch("backend.orchestrator._render_skill", return_value=""):
            # Task looks like webvuln, but caller forces recon
            result = execute(task="SQL injection", specialist="recon")
            assert result["ok"] is True
            assert result["specialist"] == "recon"
            # System prompt should be for recon specialist
            call_args = mock_llm.call_args
            messages = call_args.kwargs.get("messages") or call_args[0][3]
            assert "MIRV recon specialist" in messages[0]["content"]

    def test_unknown_specialist_returns_error(self):
        result = execute(task="x", specialist="bogus")
        assert result["ok"] is False
        assert "Unknown specialist" in result["error"]

    def test_llm_error_returns_error_dict(self):
        with patch("backend.orchestrator._call_llm", side_effect=RuntimeError("LLM down")), \
             patch("backend.orchestrator._render_skill", return_value=""):
            result = execute(task="recon target")
            assert result["ok"] is False
            assert "LLM down" in result["error"]

    def test_missing_skill_playbook_uses_generic_prompt(self):
        """When sp_render returns "" the specialist still operates."""
        with patch("backend.orchestrator._call_llm", return_value="generic ok") as mock_llm, \
             patch("backend.orchestrator._render_skill", return_value=""):
            result = execute(task="enumerate subdomains", specialist="recon")
            assert result["ok"] is True
            call_args = mock_llm.call_args
            messages = call_args.kwargs.get("messages") or call_args[0][3]
            system = messages[0]["content"]
            assert "MIRV recon specialist" in system
            # Generic fallback prompt is used (no methodology body)
            assert "step-by-step guidance" in system

    def test_skill_playbook_render_exception_falls_back_gracefully(self):
        """If sp_render raises, the orchestrator degrades to generic prompt."""
        with patch("backend.orchestrator._render_skill", side_effect=RuntimeError("boom")), \
             patch("backend.orchestrator._call_llm", return_value="ok") as mock_llm:
            result = execute(task="recon", specialist="recon")
            assert result["ok"] is True
            call_args = mock_llm.call_args
            messages = call_args.kwargs.get("messages") or call_args[0][3]
            assert "MIRV recon specialist" in messages[0]["content"]

    def test_redacts_task_before_llm_call(self):
        """Secrets in the task must be redacted before reaching the LLM."""
        secret_task = "my AWS key is AKIAIOSFODNN7EXAMPLE and github token ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        captured_messages = {}

        def _capture(messages, **kwargs):
            captured_messages["msgs"] = messages
            return "redacted response"

        with patch("backend.orchestrator._call_llm", side_effect=_capture), \
             patch("backend.orchestrator._render_skill", return_value=""):
            result = execute(task=secret_task, specialist="recon")
            assert result["ok"] is True
            user_msg = captured_messages["msgs"][1]["content"]
            # The raw secrets must NOT appear verbatim in the LLM payload
            assert "AKIAIOSFODNN7EXAMPLE" not in user_msg
            assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in user_msg
            assert "[AWS_KEY]" in user_msg
            assert "[GITHUB_TOKEN]" in user_msg

    def test_redacts_context_before_llm_call(self):
        secret_context = "found token ghp_1234567890abcdefghijklmnopqrstuvwxyz in logs"
        captured = {}

        def _capture(messages, **kwargs):
            captured["msgs"] = messages
            return "ok"

        with patch("backend.orchestrator._call_llm", side_effect=_capture), \
             patch("backend.orchestrator._render_skill", return_value=""):
            execute(task="recon", context=secret_context, specialist="recon")
            system = captured["msgs"][0]["content"]
            assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in system
            assert "[GITHUB_TOKEN]" in system

    def test_messages_structure_system_first(self):
        """System prompt must be first message (prompt-cache friendly)."""
        with patch("backend.orchestrator._call_llm", return_value="ok") as mock_llm, \
             patch("backend.orchestrator._render_skill", return_value="body"):
            execute(task="hi", specialist="recon")
            call_args = mock_llm.call_args
            messages = call_args.kwargs.get("messages") or call_args[0][3]
            assert messages[0]["role"] == "system"
            assert messages[1]["role"] == "user"

    def test_provider_kwargs_forwarded(self):
        with patch("backend.orchestrator._call_llm", return_value="ok") as mock_llm, \
             patch("backend.orchestrator._render_skill", return_value=""):
            execute(
                task="recon",
                specialist="recon",
                provider="openai",
                api_key="sk-test",
                model="gpt-4o-mini",
                timeout=30.0,
            )
            call_args = mock_llm.call_args
            assert call_args.kwargs.get("provider") == "openai" or "openai" in str(call_args)
            assert call_args.kwargs.get("api_key") == "sk-test" or "sk-test" in str(call_args)

    def test_scope_required_blocks_when_unauthorized(self):
        """A specialist whose skill requires scope is blocked without one."""
        with patch("backend.orchestrator._specialist_requires_scope", return_value=True), \
             patch("backend.orchestrator._scope_authorized", return_value=False):
            result = execute(task="exploit", specialist="webvuln")
            assert result["ok"] is False
            assert "authorized scope" in result["error"]

    def test_scope_required_passes_when_authorized(self):
        with patch("backend.orchestrator._specialist_requires_scope", return_value=True), \
             patch("backend.orchestrator._scope_authorized", return_value=True), \
             patch("backend.orchestrator._call_llm", return_value="ok"), \
             patch("backend.orchestrator._render_skill", return_value=""):
            result = execute(task="exploit", specialist="webvuln")
            assert result["ok"] is True


# ═══════════════════════════════════════════════════════════════
#  3b. execute() — episodic memory integration
# ═══════════════════════════════════════════════════════════════

class TestExecuteEpisodicMemory:
    """Episodic-memory wiring: save after each call, recall on session reuse."""

    def test_execute_calls_save_episodic_memory(self):
        """A successful execute() must persist an episodic-memory entry."""
        with patch("backend.orchestrator._call_llm", return_value="LLM OK"), \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}) as mock_save:
            result = execute(task="recon target", specialist="recon")
            assert result["ok"] is True
            mock_save.assert_called_once()
            call = mock_save.call_args
            assert call.kwargs.get("specialist") == "recon"
            assert call.kwargs.get("task") == "recon target"
            assert call.kwargs.get("response") == "LLM OK"
            # session_id should be minted (a uuid) and echoed back.
            assert "session_id" in result
            assert call.kwargs.get("session_id") == result["session_id"]

    def test_execute_response_includes_session_id(self):
        with patch("backend.orchestrator._call_llm", return_value="ok"), \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}):
            result = execute(task="recon", specialist="recon")
            assert result["ok"] is True
            assert "session_id" in result
            assert isinstance(result["session_id"], str) and result["session_id"]

    def test_execute_reuses_provided_session_id(self):
        """When the caller passes a session_id, it is reused verbatim."""
        with patch("backend.orchestrator._call_llm", return_value="ok"), \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}) as mock_save:
            result = execute(task="recon", specialist="recon", session_id="sess-123")
            assert result["session_id"] == "sess-123"
            assert mock_save.call_args.kwargs.get("session_id") == "sess-123"

    def test_execute_injects_episodic_context_into_system_prompt(self):
        """When a session_id is provided, past decisions ground the prompt."""
        captured = {}

        def _capture(messages, **kwargs):
            captured["msgs"] = messages
            return "ok"

        with patch("backend.orchestrator._call_llm", side_effect=_capture), \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.get_episodic_context",
                   return_value="<past_decisions>\n- [recon] prior: do X\n</past_decisions>") as mock_ctx, \
             patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}):
            result = execute(task="recon again", specialist="recon", session_id="sess-xyz")
            assert result["ok"] is True
            mock_ctx.assert_called_once_with("sess-xyz")
            system_prompt = captured["msgs"][0]["content"]
            assert "<past_decisions>" in system_prompt
            assert "do X" in system_prompt

    def test_execute_no_context_injected_when_session_has_no_memory(self):
        captured = {}

        def _capture(messages, **kwargs):
            captured["msgs"] = messages
            return "ok"

        with patch("backend.orchestrator._call_llm", side_effect=_capture), \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.get_episodic_context", return_value=""), \
             patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}):
            execute(task="recon", specialist="recon", session_id="empty-sess")
            assert "<past_decisions>" not in captured["msgs"][0]["content"]

    def test_execute_survives_episodic_save_failure(self):
        """If save_episodic_memory raises, execute() still returns the LLM result."""
        with patch("backend.orchestrator._call_llm", return_value="LLM OK"), \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.save_episodic_memory",
                   side_effect=RuntimeError("db locked")):
            result = execute(task="recon", specialist="recon")
            assert result["ok"] is True
            assert result["response"] == "LLM OK"

    def test_execute_survives_episodic_recall_failure(self):
        with patch("backend.orchestrator._call_llm", return_value="ok") as mock_llm, \
             patch("backend.orchestrator._render_skill", return_value=""), \
             patch("backend.episodic_memory.get_episodic_context",
                   side_effect=RuntimeError("recall boom")), \
             patch("backend.episodic_memory.save_episodic_memory", return_value={"ok": True}):
            result = execute(task="recon", specialist="recon", session_id="s1")
            assert result["ok"] is True
            mock_llm.assert_called_once()


# ═══════════════════════════════════════════════════════════════
#  4. list_specialists() & get_specialist()
# ═══════════════════════════════════════════════════════════════

class TestIntrospection:
    def test_list_specialists_returns_all(self):
        specs = list_specialists()
        assert len(specs) == len(_SPECIALISTS)
        names = {s["name"] for s in specs}
        assert names == set(_SPECIALISTS.keys())
        for s in specs:
            assert "skill" in s
            assert "description" in s

    def test_get_specialist_known(self):
        info = get_specialist("recon")
        assert info is not None
        assert info["name"] == "recon"
        assert info["skill"] == "recon"

    def test_get_specialist_unknown_returns_none(self):
        assert get_specialist("bogus") is None

    def test_specialists_have_unique_skills(self):
        """Each specialist maps to a distinct skill playbook."""
        specs = list_specialists()
        skills = [s["skill"] for s in specs]
        assert len(skills) == len(set(skills))


# ═══════════════════════════════════════════════════════════════
#  5. REST endpoints
# ═══════════════════════════════════════════════════════════════

class TestOrchestratorEndpoints:
    def test_post_route_200(self, client: TestClient):
        with patch("backend.orchestrator._call_llm", return_value="LLM OK"), \
             patch("backend.orchestrator._render_skill", return_value=""):
            resp = client.post("/api/orchestrator/route", json={
                "task": "scan web app for SQL injection",
                "context": "",
                "target": "example.com",
                "provider": "openai",
                "api_key": "sk-test",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["ok"] is True
            assert data["specialist"] == "webvuln"
            assert data["response"] == "LLM OK"

    def test_post_route_explicit_specialist(self, client: TestClient):
        with patch("backend.orchestrator._call_llm", return_value="ok"), \
             patch("backend.orchestrator._render_skill", return_value=""):
            resp = client.post("/api/orchestrator/route", json={
                "task": "anything",
                "specialist": "forensics",
            })
            assert resp.status_code == 200
            assert resp.json()["specialist"] == "forensics"

    def test_post_route_missing_body_returns_422(self, client: TestClient):
        resp = client.post("/api/orchestrator/route")
        assert resp.status_code == 422

    def test_post_route_empty_task_returns_400(self, client: TestClient):
        resp = client.post("/api/orchestrator/route", json={"task": "   "})
        assert resp.status_code == 400
        assert resp.json()["ok"] is False

    def test_post_route_task_too_long_returns_422(self, client: TestClient):
        resp = client.post("/api/orchestrator/route", json={"task": "x" * 2001})
        assert resp.status_code == 422

    def test_post_route_llm_error_returns_400(self, client: TestClient):
        with patch("backend.orchestrator._call_llm", side_effect=RuntimeError("LLM down")), \
             patch("backend.orchestrator._render_skill", return_value=""):
            resp = client.post("/api/orchestrator/route", json={
                "task": "recon",
                "provider": "openai",
                "api_key": "sk-test",
            })
            # execute() returns {"ok": False} → 400
            assert resp.status_code == 400
            data = resp.json()
            assert data["ok"] is False
            assert "LLM down" in data["error"]

    def test_post_route_internal_exception_returns_500(self, client: TestClient):
        with patch("main.orchestrator_execute", side_effect=RuntimeError("unexpected")):
            resp = client.post("/api/orchestrator/route", json={"task": "recon"})
            assert resp.status_code == 500
            assert resp.json()["error"] == "Internal error"

    def test_get_specialists_200(self, client: TestClient):
        resp = client.get("/api/orchestrator/specialists")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert isinstance(data["specialists"], list)
        assert len(data["specialists"]) >= 5

    def test_get_specialist_known_200(self, client: TestClient):
        resp = client.get("/api/orchestrator/specialists/recon")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["specialist"]["name"] == "recon"

    def test_get_specialist_unknown_404(self, client: TestClient):
        resp = client.get("/api/orchestrator/specialists/nonexistent")
        assert resp.status_code == 404
        data = resp.json()
        assert data["ok"] is False

    def test_get_specialists_internal_error_returns_500(self, client: TestClient):
        with patch("main.orchestrator_list_specialists", side_effect=RuntimeError("boom")):
            resp = client.get("/api/orchestrator/specialists")
            assert resp.status_code == 500
            assert resp.json()["error"] == "Internal error"

    def test_get_specialist_internal_error_returns_500(self, client: TestClient):
        with patch("main.orchestrator_get_specialist", side_effect=RuntimeError("boom")):
            resp = client.get("/api/orchestrator/specialists/recon")
            assert resp.status_code == 500
            assert resp.json()["error"] == "Internal error"


# ═══════════════════════════════════════════════════════════════
#  6. _resolve_provider_config() & _call_llm() env fallbacks
# ═══════════════════════════════════════════════════════════════

class TestProviderConfig:
    def test_explicit_args_win_over_env(self, monkeypatch):
        monkeypatch.setenv("MIRV_AI_PROVIDER", "local")
        monkeypatch.setenv("MIRV_AI_KEY", "env-key")
        monkeypatch.setenv("MIRV_AI_MODEL", "env-model")
        p, k, m = orch._resolve_provider_config("openai", "explicit-key", "explicit-model")
        assert p == "openai"
        assert k == "explicit-key"
        assert m == "explicit-model"

    def test_env_fallback_when_empty(self, monkeypatch):
        monkeypatch.setenv("MIRV_AI_PROVIDER", "groq")
        monkeypatch.setenv("MIRV_AI_KEY", "env-key")
        monkeypatch.setenv("MIRV_AI_MODEL", "env-model")
        p, k, m = orch._resolve_provider_config("", "", "")
        assert p == "groq"
        assert k == "env-key"
        assert m == "env-model"

    def test_defaults_to_local_when_nothing_set(self, monkeypatch):
        monkeypatch.delenv("MIRV_AI_PROVIDER", raising=False)
        monkeypatch.delenv("MIRV_AI_KEY", raising=False)
        monkeypatch.delenv("MIRV_AI_MODEL", raising=False)
        p, k, m = orch._resolve_provider_config("", "", "")
        assert p == "local"
        assert k == ""
        assert m == ""

    def test_call_llm_unknown_provider_raises(self):
        with pytest.raises(ValueError):
            orch._call_llm("bogus", "k", "m", [{"role": "user", "content": "hi"}])


# ═══════════════════════════════════════════════════════════════
#  7. _call_llm() — urllib paths (mocked urlopen, no network)
# ═══════════════════════════════════════════════════════════════

class TestCallLlm:
    def _fake_urlopen(self, payload: bytes):
        """Build a context-manager mock for urllib.request.urlopen."""
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=payload)))
        cm.__exit__ = MagicMock(return_value=False)
        return cm

    def test_local_provider_returns_choices_content(self):
        payload = b'{"choices":[{"message":{"content":"hello from ollama"}}]}'
        with patch("backend.orchestrator.urllib.request.urlopen",
                   return_value=self._fake_urlopen(payload)) as mock_open:
            result = orch._call_llm("local", "", "", [{"role": "user", "content": "hi"}])
            assert result == "hello from ollama"
            mock_open.assert_called_once()
            # URL should hit the local Ollama endpoint
            req = mock_open.call_args[0][0]
            assert "localhost:11434" in req.full_url

    def test_local_provider_custom_ollama_url(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_URL", "http://my-ollama:1234")
        payload = b'{"choices":[{"message":{"content":"ok"}}]}'
        with patch("backend.orchestrator.urllib.request.urlopen",
                   return_value=self._fake_urlopen(payload)) as mock_open:
            orch._call_llm("local", "", "", [{"role": "user", "content": "hi"}])
            req = mock_open.call_args[0][0]
            assert "my-ollama:1234" in req.full_url

    def test_openai_provider_adds_auth_header(self):
        payload = b'{"choices":[{"message":{"content":"cloud ok"}}]}'
        with patch("backend.orchestrator.urllib.request.urlopen",
                   return_value=self._fake_urlopen(payload)) as mock_open:
            result = orch._call_llm("openai", "sk-secret", "", [{"role": "user", "content": "hi"}])
            assert result == "cloud ok"
            req = mock_open.call_args[0][0]
            assert req.get_header("Authorization") == "Bearer sk-secret"
            assert "api.openai.com" in req.full_url

    def test_openai_provider_default_model_when_empty(self):
        payload = b'{"choices":[{"message":{"content":"ok"}}]}'
        with patch("backend.orchestrator.urllib.request.urlopen",
                   return_value=self._fake_urlopen(payload)) as mock_open:
            orch._call_llm("openai", "sk-secret", "", [{"role": "user", "content": "hi"}])
            req = mock_open.call_args[0][0]
            body = json.loads(req.data.decode("utf-8"))
            assert body["model"] == "gpt-4o-mini"

    def test_no_choices_returns_str_data(self):
        payload = b'{"choices":[]}'
        with patch("backend.orchestrator.urllib.request.urlopen",
                   return_value=self._fake_urlopen(payload)):
            result = orch._call_llm("openai", "sk", "m", [{"role": "user", "content": "hi"}])
            assert "choices" in result  # str(data)

    def test_http_error_raises_runtime_error(self):
        import urllib.error as ue
        err = ue.HTTPError(
            url="http://x", code=429, msg="rate",
            hdrs=None, fp=__import__("io").BytesIO(b"rate limited"),
        )
        with patch("backend.orchestrator.urllib.request.urlopen", side_effect=err):
            with pytest.raises(RuntimeError) as exc:
                orch._call_llm("openai", "sk", "m", [{"role": "user", "content": "hi"}])
            assert "429" in str(exc.value)
            assert "rate limited" in str(exc.value)

    def test_unicode_decode_error_raises_runtime_error(self):
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=b"\xff\xfe\x00")))
        cm.__exit__ = MagicMock(return_value=False)
        with patch("backend.orchestrator.urllib.request.urlopen", return_value=cm):
            with pytest.raises(RuntimeError) as exc:
                orch._call_llm("local", "", "", [{"role": "user", "content": "hi"}])
            assert "Encoding error" in str(exc.value)

    def test_timeout_forwarded(self):
        payload = b'{"choices":[{"message":{"content":"ok"}}]}'
        with patch("backend.orchestrator.urllib.request.urlopen",
                   return_value=self._fake_urlopen(payload)) as mock_open:
            orch._call_llm("local", "", "", [{"role": "user", "content": "hi"}], timeout=12.5)
            assert mock_open.call_args.kwargs.get("timeout") == 12.5 or \
                   mock_open.call_args[1].get("timeout") == 12.5


# ═══════════════════════════════════════════════════════════════
#  8. _render_skill / scope-gate direct calls
# ═══════════════════════════════════════════════════════════════

class TestRenderSkillAndScope:
    def test_render_skill_returns_string_for_unknown_skill(self):
        # Built-in skills are disabled by default → render returns ""
        result = orch._render_skill("nonexistent-skill-xyz")
        assert isinstance(result, str)

    def test_render_skill_handles_import_failure(self):
        with patch("backend.skill_playbooks.render_skill_for_prompt",
                   side_effect=RuntimeError("boom")):
            result = orch._render_skill("recon")
            assert result == ""

    def test_specialist_requires_scope_returns_false_for_builtins(self):
        # Built-in specialists are not red-team flagged.
        for name in _SPECIALISTS:
            assert orch._specialist_requires_scope(name) is False

    def test_specialist_requires_scope_unknown_specialist(self):
        assert orch._specialist_requires_scope("bogus") is False

    def test_specialist_requires_scope_with_flagged_skill(self):
        with patch("backend.skill_playbooks.get_skill_info",
                   return_value={"requires_scope": True}):
            assert orch._specialist_requires_scope("recon") is True

    def test_specialist_requires_scope_skill_info_none(self):
        with patch("backend.skill_playbooks.get_skill_info", return_value=None):
            assert orch._specialist_requires_scope("recon") is False

    def test_scope_authorized_false_when_empty(self):
        with patch("backend.scope_guard.get_config", return_value={}):
            assert orch._scope_authorized() is False

    def test_scope_authorized_true_when_targets_set(self):
        with patch("backend.scope_guard.get_config", return_value={"targets": ["10.0.0.0/24"]}):
            assert orch._scope_authorized() is True

    def test_scope_authorized_false_when_config_none(self):
        with patch("backend.scope_guard.get_config", return_value=None):
            assert orch._scope_authorized() is False
