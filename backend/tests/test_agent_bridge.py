"""
Tests for backend.agent_bridge (Pack 12 — multi-provider Code Agent).

Hermetic: the real CLIs are never executed; subprocess/shutil are mocked.
"""

from types import SimpleNamespace

import pytest

from backend import agent_bridge as ab


@pytest.fixture(autouse=True)
def _clean_caches():
    ab._CLAUDE_VERSION_CACHE.clear()
    yield
    ab._CLAUDE_VERSION_CACHE.clear()


def _fake_proc(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestStatus:
    def test_status_all_shape(self):
        data = ab.status_all()
        assert data["ok"] is True
        assert data["default"] == "opencode"
        assert set(data["providers"]) == {"opencode", "claude", "codex"}

    def test_opencode_delegates(self, monkeypatch):
        monkeypatch.setattr(ab._oc, "status", lambda: {"ok": True, "installed": True, "version": "1.2.3"})
        st = ab.status("opencode")
        assert st["provider"] == "opencode" and st["installed"] is True

    def test_claude_not_installed(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: None)
        st = ab.status("claude")
        assert st["installed"] is False
        assert st["safe_mode"] is True
        assert st["label"] == "Claude Code"

    def test_claude_installed_and_version(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")
        monkeypatch.setattr(ab.subprocess, "run", lambda *a, **k: _fake_proc(0, "1.0.50"))
        st = ab.status("claude")
        assert st["installed"] is True and st["version"] == "1.0.50"

    def test_codex_reserved_not_implemented(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: None)
        st = ab.status("codex")
        assert st["implemented"] is False

    def test_unknown_provider(self):
        assert ab.status("bogus")["ok"] is False


class TestClaudeRun:
    def test_run_parses_json_result(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")
        monkeypatch.setattr(ab.subprocess, "run", lambda *a, **k: _fake_proc(0, '{"type":"result","result":"hola"}'))
        out = ab.run("claude", "hi")
        assert out["ok"] is True
        assert out["stdout"] == "hola"
        assert out["provider"] == "claude"

    def test_run_extracts_structured_output(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")
        monkeypatch.setattr(ab.subprocess, "run", lambda *a, **k: _fake_proc(0, '{"structured_output":{"a":1}}'))
        out = ab.run("claude", "hi")
        assert '"a": 1' in out["stdout"]

    def test_run_non_json_passthrough(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")
        monkeypatch.setattr(ab.subprocess, "run", lambda *a, **k: _fake_proc(0, "plain text"))
        out = ab.run("claude", "hi")
        assert out["stdout"] == "plain text"

    def test_run_flags_are_safe(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            return _fake_proc(0, '{"result":"ok"}')

        monkeypatch.setattr(ab.subprocess, "run", fake_run)
        ab.run("claude", "hi", agent="plan")
        argv = captured["argv"]
        assert argv[0] == "/usr/bin/claude"
        assert "--tools" in argv and argv[argv.index("--tools") + 1] == ""
        assert "--max-turns" in argv and argv[argv.index("--max-turns") + 1] == "1"
        assert "--strict-mcp-config" in argv
        assert not any(a in ("--dangerously-skip-permissions", "--auto") for a in argv)

    def test_run_not_available(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: None)
        out = ab.run("claude", "hi")
        assert out["ok"] is False and "not available" in out["error"]

    def test_run_timeout(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")

        def boom(*a, **k):
            raise ab.subprocess.TimeoutExpired(cmd="claude", timeout=1)

        monkeypatch.setattr(ab.subprocess, "run", boom)
        out = ab.run("claude", "hi", timeout=1)
        assert out["ok"] is False and "timed out" in out["error"]

    def test_run_oserror(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")

        def boom(*a, **k):
            raise OSError("nope")

        monkeypatch.setattr(ab.subprocess, "run", boom)
        out = ab.run("claude", "hi")
        assert out["ok"] is False and "failed" in out["error"]

    def test_cwd_escape_rejected(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: "/usr/bin/claude")
        out = ab.run("claude", "hi", cwd="C:/Windows/System32" if ab.os.name == "nt" else "/etc")
        assert out["ok"] is False and "escapes" in out["error"]


class TestRunDispatch:
    def test_opencode_delegates(self, monkeypatch):
        monkeypatch.setattr(ab._oc, "run", lambda *a, **k: {"ok": True, "stdout": "oc"})
        out = ab.run("opencode", "hi", agent="build")
        assert out["provider"] == "opencode" and out["ok"] is True

    def test_codex_not_implemented(self, monkeypatch):
        monkeypatch.setattr(ab.shutil, "which", lambda _: None)
        out = ab.run("codex", "hi")
        assert out["ok"] is False and "not implemented" in out["error"]

    def test_unknown_provider(self):
        out = ab.run("bogus", "hi")
        assert out["ok"] is False and "unknown provider" in out["error"]

    def test_default_provider(self, monkeypatch):
        monkeypatch.setattr(ab._oc, "run", lambda *a, **k: {"ok": True})
        out = ab.run("", "hi")
        assert out["provider"] == "opencode"


class TestExtract:
    def test_error_envelope(self):
        assert ab._extract_claude_text('{"is_error":true,"result":"boom"}') == "boom"

    def test_empty(self):
        assert ab._extract_claude_text("") == ""


class TestEndpoints:
    def test_agents_status(self, client):
        r = client.get("/api/agents/status")
        assert r.status_code == 200
        body = r.json()
        assert body["default"] == "opencode"
        assert "opencode" in body["providers"] and "claude" in body["providers"]

    def test_agents_run_requires_prompt(self, client):
        assert client.post("/api/agents/run", json={"provider": "claude", "prompt": ""}).status_code == 400

    def test_agents_run_ok(self, client, monkeypatch):
        monkeypatch.setattr("backend.agent_bridge.run", lambda *a, **k: {"ok": True, "available": True, "stdout": "hi", "provider": "claude"})
        r = client.post("/api/agents/run", json={"provider": "claude", "prompt": "hello"})
        assert r.status_code == 200 and r.json()["stdout"] == "hi"

    def test_agents_run_503_when_unavailable(self, client, monkeypatch):
        monkeypatch.setattr("backend.agent_bridge.run", lambda *a, **k: {"ok": False, "available": False, "error": "claude not available", "provider": "claude"})
        r = client.post("/api/agents/run", json={"provider": "claude", "prompt": "hello"})
        assert r.status_code == 503
