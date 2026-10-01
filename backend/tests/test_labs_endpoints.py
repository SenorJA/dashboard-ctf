"""
Endpoint tests for Pack 11 — /api/labs/* (Lab Sessions workspace).
"""

import json

import pytest

from backend import lab_sessions as ls
from backend import workspace_store

USER_FLAG = "0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    ls.reset_lab_sessions()
    workspace_store.clear_cache("lab_sessions")
    monkeypatch.setattr("backend.workspace_store.is_enabled", lambda: False)
    yield
    ls.reset_lab_sessions()
    workspace_store.clear_cache("lab_sessions")


def _make_session(client):
    m = client.post("/api/labs/machines", json={
        "name": "Lab", "ip": "10.10.11.1", "operating_system": "linux", "difficulty": "easy",
    }).json()
    s = client.post("/api/labs/sessions", json={
        "machine_id": m["id"], "title": "Recon",
    }).json()
    return m, s


class TestMachines:
    def test_list_empty(self, client):
        assert client.get("/api/labs/machines").json() == {"machines": []}

    def test_crud_flow(self, client):
        m = client.post("/api/labs/machines", json={"name": "Box", "ip": "1.2.3.4"}).json()
        assert m["name"] == "Box"
        assert client.get(f"/api/labs/machines/{m['id']}").json()["id"] == m["id"]
        upd = client.put(f"/api/labs/machines/{m['id']}", json={"name": "Box2", "difficulty": "hard"}).json()
        assert upd["name"] == "Box2" and upd["difficulty"] == "hard"
        assert client.delete(f"/api/labs/machines/{m['id']}").json() == {"ok": True}
        assert client.get(f"/api/labs/machines/{m['id']}").status_code == 404

    def test_create_requires_name(self, client):
        assert client.post("/api/labs/machines", json={"name": ""}).status_code == 400

    def test_update_missing_404(self, client):
        assert client.put("/api/labs/machines/nope", json={"name": "x"}).status_code == 404

    def test_machine_sessions_404(self, client):
        assert client.get("/api/labs/machines/nope/sessions").status_code == 404


class TestSessionsAndSteps:
    def test_create_session_requires_machine(self, client):
        assert client.post("/api/labs/sessions", json={"machine_id": "x", "title": "t"}).status_code == 400

    def test_workspace_flow_detects_flag(self, client):
        m, s = _make_session(client)
        resp = client.post(f"/api/labs/sessions/{s['id']}/steps", json={
            "command": "cat /home/x/user.txt", "output": USER_FLAG,
        })
        body = resp.json()
        assert body["step"]["detected_flag_type"] == "user"
        assert body["session"]["user_flag_captured"] is True
        ws = client.get(f"/api/labs/sessions/{s['id']}/workspace").json()
        assert ws["session"]["machine_name"] == "Lab"
        assert len(ws["steps"]) == 1

    def test_add_step_requires_command(self, client):
        _, s = _make_session(client)
        assert client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": ""}).status_code == 400

    def test_update_and_delete_step(self, client):
        _, s = _make_session(client)
        step = client.post(f"/api/labs/sessions/{s['id']}/steps", json={
            "command": "cat user.txt", "output": USER_FLAG,
        }).json()["step"]
        upd = client.put(f"/api/labs/steps/{step['id']}", json={"command": "ls"}).json()
        assert upd["step"]["command"] == "ls"
        assert upd["session"]["user_flag_captured"] is False
        assert client.delete(f"/api/labs/steps/{step['id']}").json() == {"ok": True}
        assert client.delete(f"/api/labs/steps/{step['id']}").status_code == 404

    def test_update_session_and_delete(self, client):
        _, s = _make_session(client)
        assert client.put(f"/api/labs/sessions/{s['id']}", json={"title": "New"}).json()["title"] == "New"
        assert client.delete(f"/api/labs/sessions/{s['id']}").json() == {"ok": True}
        assert client.get(f"/api/labs/sessions/{s['id']}").status_code == 404

    def test_step_missing_session_404(self, client):
        assert client.post("/api/labs/sessions/nope/steps", json={"command": "ls"}).status_code == 404


class TestAi:
    def test_analyze(self, client, monkeypatch):
        _, s = _make_session(client)
        client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "nmap -sV target"})
        payload = json.dumps({
            "currentPhase": "foothold", "summary": "enum ok", "evidence": ["22/tcp"],
            "nextObjective": "check sudo", "safeCommands": ["sudo -l"],
            "rationale": "least privilege", "cautions": ["lab only"],
        })
        monkeypatch.setattr("main._call_llm_sync", lambda *a, **k: payload)
        resp = client.post(f"/api/labs/sessions/{s['id']}/analyze", json={"provider": "openai", "api_key": "k"})
        body = resp.json()
        assert body["analysis"]["current_phase"] == "foothold"
        assert body["analysis"]["safe_commands"] == ["sudo -l"]

    def test_analyze_requires_steps(self, client):
        _, s = _make_session(client)
        assert client.post(f"/api/labs/sessions/{s['id']}/analyze", json={}).status_code == 400

    def test_analyze_ai_error_502(self, client, monkeypatch):
        _, s = _make_session(client)
        client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "ls"})
        monkeypatch.setattr("main._call_llm_sync", lambda *a, **k: "not json at all")
        assert client.post(f"/api/labs/sessions/{s['id']}/analyze", json={}).status_code == 502

    def test_writeup(self, client, monkeypatch):
        _, s = _make_session(client)
        step = client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "nmap target"}).json()["step"]
        payload = json.dumps({"steps": [{"stepId": step["id"], "title": "Scan", "description": "Recon done."}]})
        monkeypatch.setattr("main._call_llm_sync", lambda *a, **k: payload)
        body = client.post(f"/api/labs/sessions/{s['id']}/writeup", json={"language": "en"}).json()
        assert body["steps"][0]["title"] == "Scan"


class TestExport:
    def test_export_html(self, client):
        _, s = _make_session(client)
        client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "cat x", "output": "<b>hi</b>"})
        resp = client.post(f"/api/labs/sessions/{s['id']}/export", json={"format": "html"})
        assert resp.status_code == 200
        assert "color-scheme:dark" in resp.text
        assert "&lt;b&gt;hi&lt;/b&gt;" in resp.text
        assert "<b>hi</b>" not in resp.text

    def test_export_pdf(self, client):
        _, s = _make_session(client)
        client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "ls"})
        resp = client.post(f"/api/labs/sessions/{s['id']}/export", json={"format": "pdf"})
        assert resp.status_code == 200
        assert resp.content.startswith(b"%PDF")

    def test_export_bad_format(self, client):
        _, s = _make_session(client)
        assert client.post(f"/api/labs/sessions/{s['id']}/export", json={"format": "docx"}).status_code == 400

    def test_export_missing_session_404(self, client):
        assert client.post("/api/labs/sessions/nope/export", json={}).status_code == 404


class TestState:
    def test_summary(self, client):
        _, s = _make_session(client)
        client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "cat user.txt", "output": USER_FLAG})
        summ = client.get("/api/labs/summary").json()
        assert summ["machines"] == 1 and summ["user_flags"] == 1

    def test_export_import_roundtrip(self, client):
        m, s = _make_session(client)
        client.post(f"/api/labs/sessions/{s['id']}/steps", json={"command": "cat user.txt", "output": USER_FLAG})
        state = client.get("/api/labs/export").json()
        assert state["machines"][0]["sessions"][0]["steps"][0]["detected_flag_value"] == USER_FLAG
        ls.reset_lab_sessions()
        result = client.post("/api/labs/import", json={"machines": state["machines"], "replace": True}).json()
        assert result["imported"] == 1
        assert client.get(f"/api/labs/machines/{m['id']}").json()["name"] == "Lab"

    def test_import_bad_payload(self, client):
        assert client.post("/api/labs/import", json={"nope": []}).status_code == 400
