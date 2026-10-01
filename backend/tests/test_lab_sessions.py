"""
Tests for backend.lab_sessions (Pack 11 — Lab Sessions workspace).

Ported from afsh4ck/exploitpath's machine/session/step/analysis model and
adapted to MIRV registries. Hermetic: the in-memory registry is reset between
tests and Supabase persistence is disabled.
"""

import pytest

from backend import lab_sessions as ls
from backend import workspace_store

USER_FLAG = "0123456789abcdef0123456789abcdef"
ROOT_FLAG = "fedcba9876543210fedcba9876543210"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    ls.reset_lab_sessions()
    workspace_store.clear_cache("lab_sessions")
    monkeypatch.setattr("backend.workspace_store.is_enabled", lambda: False)
    yield
    ls.reset_lab_sessions()
    workspace_store.clear_cache("lab_sessions")


def _machine(name="Lab", **kw):
    return ls.create_machine(name=name, **kw)


class TestMachines:
    def test_create_and_list(self):
        m = _machine("Academy", ip="10.10.11.5", operating_system="linux", difficulty="easy")
        assert m.name == "Academy"
        items = ls.list_machines()
        assert len(items) == 1
        assert items[0]["id"] == m.id
        assert items[0]["session_count"] == 0

    def test_create_requires_name(self):
        with pytest.raises(ValueError):
            ls.create_machine("")

    def test_create_rejects_bad_os(self):
        with pytest.raises(ValueError):
            ls.create_machine("x", operating_system="bsd")

    def test_create_rejects_bad_difficulty(self):
        with pytest.raises(ValueError):
            ls.create_machine("x", difficulty="lol")

    def test_update_and_get(self):
        m = _machine("A")
        updated = ls.update_machine(m.id, name="B", difficulty="hard", status="pwned")
        assert updated["name"] == "B"
        assert updated["difficulty"] == "hard"
        assert updated["status"] == "pwned"
        assert ls.get_machine(m.id)["name"] == "B"

    def test_update_missing_returns_none(self):
        assert ls.update_machine("nope", name="x") is None

    def test_update_invalid_returns_none(self):
        m = _machine("A")
        assert ls.update_machine(m.id, difficulty="lol") is None

    def test_delete_machine(self):
        m = _machine("A")
        assert ls.delete_machine(m.id) is True
        assert ls.get_machine(m.id) is None
        assert ls.delete_machine(m.id) is False


class TestSessions:
    def test_create_session_requires_machine(self):
        with pytest.raises(ValueError):
            ls.create_session("missing", "s1")

    def test_create_and_list_sessions(self):
        m = _machine("A")
        s = ls.create_session(m.id, "Recon")
        assert s.machine_id == m.id
        items = ls.list_sessions(m.id)
        assert len(items) == 1
        assert items[0]["step_count"] == 0

    def test_create_session_requires_title(self):
        m = _machine("A")
        with pytest.raises(ValueError):
            ls.create_session(m.id, "   ")

    def test_update_session(self):
        m = _machine("A")
        s = ls.create_session(m.id, "Old")
        assert ls.update_session(s.id, "New")["title"] == "New"
        assert ls.update_session(s.id, "") is None
        assert ls.update_session("nope", "x") is None

    def test_delete_session_cascades(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "cat user.txt", USER_FLAG)
        assert ls.delete_session(s.id) is True
        assert ls.get_session(s.id) is None
        assert ls.list_steps(s.id) == []


class TestStepsAndFlags:
    def test_add_step_detects_user_flag(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        step = ls.add_step(s.id, "cat /home/x/user.txt", USER_FLAG)
        assert step["detected_flag_type"] == "user"
        assert step["detected_flag_value"] == USER_FLAG
        sess = ls.get_session(s.id)
        assert sess["user_flag_captured"] is True
        assert sess["phase"] == "foothold"

    def test_root_flag_completes_session(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "cat user.txt", USER_FLAG)
        ls.add_step(s.id, "cat /root/root.txt", f"uid=0(root) {ROOT_FLAG}")
        sess = ls.get_session(s.id)
        assert sess["root_flag_captured"] is True
        assert sess["root_flag_value"] == ROOT_FLAG
        assert sess["phase"] == "complete"

    def test_add_step_requires_command(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        assert ls.add_step(s.id, "   ") is None

    def test_add_step_missing_session(self):
        assert ls.add_step("nope", "ls") is None

    def test_steps_are_ordered(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "one")
        ls.add_step(s.id, "two")
        ls.add_step(s.id, "three")
        cmds = [st["command"] for st in ls.list_steps(s.id)]
        assert cmds == ["one", "two", "three"]

    def test_edit_evidence_recomputes_flags(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        step = ls.add_step(s.id, "cat user.txt", USER_FLAG)
        assert ls.get_session(s.id)["user_flag_captured"] is True
        ls.update_step(step["id"], command="ls", output="nothing here")
        sess = ls.get_session(s.id)
        assert sess["user_flag_captured"] is False
        assert sess["phase"] == "recon"

    def test_delete_evidence_clears_flags(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        step = ls.add_step(s.id, "cat user.txt", USER_FLAG)
        assert ls.delete_step(step["id"]) is True
        assert ls.get_session(s.id)["user_flag_captured"] is False
        assert ls.delete_step(step["id"]) is False

    def test_update_missing_step(self):
        assert ls.update_step("nope", command="ls") is None

    def test_update_step_rejects_empty_command(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        step = ls.add_step(s.id, "ls")
        assert ls.update_step(step["id"], command="") is None


class TestAnalyses:
    def test_save_and_fetch_analysis(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "nmap -sCV target")
        saved = ls.save_analysis(s.id, {
            "model": "gpt-x",
            "current_phase": "privesc",
            "summary": "enum ok",
            "evidence": ["22/tcp open"],
            "next_objective": "check sudo",
            "safe_commands": ["sudo -l"],
            "rationale": "least privilege",
            "cautions": ["lab only"],
        })
        assert saved["current_phase"] == "privesc"
        assert ls.latest_analysis(s.id)["summary"] == "enum ok"
        assert ls.get_session(s.id)["phase"] == "privesc"

    def test_save_analysis_missing_session(self):
        assert ls.save_analysis("nope", {}) is None

    def test_invalid_phase_defaults_to_recon(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        saved = ls.save_analysis(s.id, {"current_phase": "banana"})
        assert saved["current_phase"] == "recon"

    def test_new_evidence_invalidates_analysis(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "ls")
        ls.save_analysis(s.id, {"current_phase": "foothold"})
        assert ls.latest_analysis(s.id) is not None
        ls.add_step(s.id, "whoami")
        assert ls.latest_analysis(s.id) is None

    def test_edit_step_invalidates_analysis(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        step = ls.add_step(s.id, "ls")
        ls.save_analysis(s.id, {"current_phase": "foothold"})
        ls.update_step(step["id"], output="more")
        assert ls.latest_analysis(s.id) is None

    def test_complete_phase_not_overwritten_by_analysis(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "cat user.txt", USER_FLAG)
        ls.add_step(s.id, "cat /root/root.txt", f"uid=0(root) {ROOT_FLAG}")
        ls.save_analysis(s.id, {"current_phase": "privesc"})
        assert ls.get_session(s.id)["phase"] == "complete"


class TestWorkspaceAndSummary:
    def test_get_workspace(self):
        m = _machine("Academy", ip="10.0.0.1", operating_system="windows", difficulty="hard")
        s = ls.create_session(m.id, "Path")
        ls.add_step(s.id, "type C:\\Users\\x\\Desktop\\user.txt", USER_FLAG)
        ws = ls.get_workspace(s.id)
        assert ws["session"]["machine_name"] == "Academy"
        assert ws["session"]["operating_system"] == "windows"
        assert len(ws["steps"]) == 1
        assert ws["analysis"] is None

    def test_get_workspace_missing(self):
        assert ls.get_workspace("nope") is None

    def test_summary(self):
        m = _machine("A")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "cat user.txt", USER_FLAG)
        summ = ls.summary()
        assert summ["machines"] == 1
        assert summ["sessions"] == 1
        assert summ["steps"] == 1
        assert summ["user_flags"] == 1
        assert summ["by_os"]["linux"] == 1


class TestExportImport:
    def test_export_import_roundtrip(self):
        m = _machine("A", ip="1.2.3.4", operating_system="windows", difficulty="insane")
        s = ls.create_session(m.id, "S")
        ls.add_step(s.id, "cat user.txt", USER_FLAG)
        ls.save_analysis(s.id, {"current_phase": "foothold", "summary": "x"})
        state = ls.export_state()
        assert state[0]["sessions"][0]["steps"][0]["detected_flag_value"] == USER_FLAG

        ls.reset_lab_sessions()
        result = ls.import_state(state, replace=True)
        assert result["imported"] == 1
        assert result["sessions"] == 1
        assert result["steps"] == 1
        assert ls.summary()["machines"] == 1
        assert ls.get_session(s.id)["user_flag_captured"] is True

    def test_import_skips_invalid(self):
        result = ls.import_state(["nope", {"name": ""}, {"name": "ok"}], replace=True)
        assert result["imported"] == 1
        assert result["skipped"] == 2

    def test_import_rejects_non_list(self):
        with pytest.raises(ValueError):
            ls.import_state({"not": "a list"})

    def test_import_without_replace_keeps_existing(self):
        m = _machine("A")
        ls.import_state([{"id": m.id, "name": "B"}], replace=False)
        assert ls.get_machine(m.id)["name"] == "A"


class TestPersistence:
    def test_persist_noop_when_disabled(self):
        m = _machine("A")
        assert ls._persist() is None
        assert len(ls.list_machines()) == 1

    def test_persist_called_when_enabled(self, monkeypatch):
        calls = []
        monkeypatch.setattr("backend.workspace_store.is_enabled", lambda: True)
        monkeypatch.setattr("backend.workspace_store.upsert", lambda k, d: calls.append((k, d)) or True)
        ls.create_machine("A")
        assert calls and calls[0][0] == "lab_sessions"

    def test_load_from_store_hydrates(self, monkeypatch):
        monkeypatch.setattr("backend.workspace_store.load", lambda k: [{
            "id": "m1", "name": "Hydrated", "sessions": [{
                "id": "s1", "title": "S", "steps": [{
                    "id": "st1", "command": "cat user.txt", "output": USER_FLAG,
                }],
            }],
        }])
        ls.load_from_store()
        assert ls.get_machine("m1")["name"] == "Hydrated"
        assert ls.get_session("s1")["user_flag_captured"] is True
