"""
Endpoint tests for the AI persona registry (Pack 17) — ``/api/personas/*``.
"""
from unittest.mock import patch

import pytest

from backend import agency_agents as aa


@pytest.fixture
def writable(tmp_path, monkeypatch):
    """Redirect persona writes to a temp dir so bundled files stay intact."""
    monkeypatch.setenv("MIRV_AGENTS_WRITE_DIR", str(tmp_path / "agents"))
    aa.discover(force=True)
    yield
    aa.discover(force=True)


# ════════════════════════════════════════════════════════════════
#  Read
# ════════════════════════════════════════════════════════════════

def test_personas_list(client):
    r = client.get("/api/personas")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["count"] >= 39
    assert any(a["slug"] == "security-penetration-tester" for a in data["agents"])


def test_personas_list_filtered_by_division(client):
    r = client.get("/api/personas", params={"division": "testing"})
    assert r.status_code == 200
    assert {a["division"] for a in r.json()["agents"]} == {"testing"}


def test_personas_list_filtered_by_query(client):
    r = client.get("/api/personas", params={"q": "forensics"})
    assert r.status_code == 200
    assert r.json()["count"] >= 1


def test_personas_divisions(client):
    r = client.get("/api/personas/divisions")
    assert r.status_code == 200
    ids = {d["id"] for d in r.json()["divisions"]}
    assert {"security", "testing", "engineering", "specialized"} <= ids


def test_personas_summary(client):
    r = client.get("/api/personas/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 39
    assert isinstance(body["dirs"], list)


def test_personas_get_with_body(client):
    r = client.get("/api/personas/security-penetration-tester")
    assert r.status_code == 200
    agent = r.json()["agent"]
    assert agent["slug"] == "security-penetration-tester"
    assert agent["editable"] is False
    assert len(agent["body"]) > 500


def test_personas_get_unknown_404(client):
    assert client.get("/api/personas/ghost").status_code == 404


def test_personas_prompt_endpoint(client):
    r = client.post("/api/personas/security-appsec-engineer/prompt",
                    json={"task": "audita el login", "body_limit": 700})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["slug"] == "security-appsec-engineer"
    assert "audita el login" in body["prompt"]
    assert body["chars"] == len(body["prompt"])


def test_personas_prompt_unknown_404(client):
    assert client.post("/api/personas/ghost/prompt", json={}).status_code == 404


# ════════════════════════════════════════════════════════════════
#  Export / import
# ════════════════════════════════════════════════════════════════

def test_personas_export_and_import_roundtrip(client, writable):
    client.post("/api/personas", json={
        "slug": "roundtrip-agent", "division": "custom",
        "name": "Roundtrip", "body": "# Roundtrip\n\nbody",
    })
    exported = client.get("/api/personas/export").json()
    assert exported["exported"] == len(exported["agents"])
    assert any(a["slug"] == "roundtrip-agent" for a in exported["agents"])

    assert client.delete("/api/personas/roundtrip-agent").status_code == 200
    r = client.post("/api/personas/import", json=exported)
    assert r.status_code == 200
    assert r.json()["imported"] == 1
    assert client.get("/api/personas/roundtrip-agent").status_code == 200


def test_personas_import_invalid_payload(client):
    r = client.post("/api/personas/import", json={"agents": "nope"})
    assert r.status_code == 400
    assert r.json()["errors"]


# ════════════════════════════════════════════════════════════════
#  Write
# ════════════════════════════════════════════════════════════════

def test_persona_create_and_delete(client, writable):
    payload = {
        "slug": "endpoint-agent", "division": "custom", "name": "Endpoint Agent",
        "description": "created via API", "emoji": "E", "color": "teal",
        "vibe": "direct", "body": "# Endpoint Agent\n\nRules.",
    }
    r = client.post("/api/personas", json=payload)
    assert r.status_code == 200
    agent = r.json()["agent"]
    assert agent["slug"] == "endpoint-agent"
    assert agent["color"] == "#14b8a6"
    assert agent["editable"] is True

    r = client.delete("/api/personas/endpoint-agent")
    assert r.status_code == 200
    assert r.json()["deleted"] == "endpoint-agent"


def test_persona_create_duplicate_400(client, writable):
    body = {"slug": "dupe-endpoint", "division": "custom", "body": "b"}
    assert client.post("/api/personas", json=body).status_code == 200
    r = client.post("/api/personas", json=body)
    assert r.status_code == 400
    assert "already exists" in r.json()["error"]


def test_persona_create_validation_400(client, writable):
    r = client.post("/api/personas", json={"slug": "Bad Slug", "division": "custom", "body": "b"})
    assert r.status_code == 400
    assert r.json()["error"]


def test_persona_delete_bundled_is_rejected(client):
    r = client.delete("/api/personas/security-penetration-tester")
    assert r.status_code == 400
    assert "bundled" in r.json()["error"]
    assert client.get("/api/personas/security-penetration-tester").status_code == 200


def test_persona_delete_unknown_400(client):
    assert client.delete("/api/personas/ghost").status_code == 400


# ════════════════════════════════════════════════════════════════
#  AI chat integration
# ════════════════════════════════════════════════════════════════

def test_ai_chat_injects_persona_system_message(client):
    captured = {}

    def fake_call(provider, api_key, model, messages, timeout):
        captured["messages"] = messages
        return "respuesta"

    with patch("main._call_llm_sync", side_effect=fake_call):
        r = client.post("/api/ai/chat", json={
            "provider": "openai", "api_key": "k", "model": "gpt-x",
            "messages": [{"role": "user", "content": "hola"}],
            "agent": "security-penetration-tester",
            "agent_task": "enumera subdominios",
        })
    assert r.status_code == 200
    messages = captured["messages"]
    assert messages[0]["role"] == "system"
    assert "Penetration Tester" in messages[0]["content"]
    assert "enumera subdominios" in messages[0]["content"]
    assert messages[-1]["content"] == "hola"


def test_ai_chat_unknown_persona_is_ignored(client):
    captured = {}

    def fake_call(provider, api_key, model, messages, timeout):
        captured["messages"] = messages
        return "ok"

    with patch("main._call_llm_sync", side_effect=fake_call):
        r = client.post("/api/ai/chat", json={
            "provider": "openai", "api_key": "k", "model": "gpt-x",
            "messages": [{"role": "user", "content": "hola"}],
            "agent": "ghost-persona",
        })
    assert r.status_code == 200
    assert all(m["role"] != "system" for m in captured["messages"])


def test_ai_chat_redacts_secrets_with_persona_active(client):
    captured = {}

    def fake_call(provider, api_key, model, messages, timeout):
        captured["messages"] = messages
        return "ok"

    secret = "ghp_" + "a" * 36
    with patch("main._call_llm_sync", side_effect=fake_call):
        client.post("/api/ai/chat", json={
            "provider": "openai", "api_key": "k", "model": "gpt-x",
            "messages": [{"role": "user", "content": "usa " + secret}],
            "agent": "security-penetration-tester",
        })
    body = " ".join(m["content"] for m in captured["messages"])
    assert secret not in body


def test_ai_chat_persona_body_limit_is_honoured(client):
    captured = {}

    def fake_call(provider, api_key, model, messages, timeout):
        captured["messages"] = messages
        return "ok"

    with patch("main._call_llm_sync", side_effect=fake_call):
        client.post("/api/ai/chat", json={
            "provider": "openai", "api_key": "k", "model": "gpt-x",
            "messages": [{"role": "user", "content": "hola"}],
            "agent": "security-penetration-tester",
            "agent_body_limit": 400,
        })
    system = captured["messages"][0]["content"]
    assert "Penetration Tester" in system
    assert len(system) < 3000
