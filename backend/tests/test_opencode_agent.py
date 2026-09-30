"""
Tests for backend.opencode_agent (Pack 10 — Code Agent bridge).

Hermetic: the binary and subprocess are mocked; actual ``opencode`` presence
is irrelevant here (the live E2E lives in tests/manual_e2e_opencode.py).
"""
import pytest

from backend import opencode_agent as oa

PWD = r"C:\fake\opencode"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MIRV_OPENCODE_BIN", raising=False)
    monkeypatch.delenv("MIRV_OPENCODE_ROOT", raising=False)
    oa._VERSION_CACHE.clear()
    with oa._LOCK:
        pass
    yield
    oa._VERSION_CACHE.clear()
    while oa._LOCK.locked():
        oa._LOCK.release()


def test_status_when_not_installed(monkeypatch):
    monkeypatch.setattr("backend.opencode_agent.shutil.which", lambda _: None)
    st = oa.status()
    assert st["ok"] is True
    assert st["installed"] is False
    assert st["agents"] == ["build", "plan", "general"]
    assert st["root"]


def test_is_installed_via_env_override(monkeypatch):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    assert oa.is_installed() is True
    assert oa.status()["path"] == PWD


def test_version_cached_and_parsed(monkeypatch):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)

    class _Proc:
        returncode = 0
        stdout = "1.18.33\n"
        stderr = ""

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", lambda *a, **k: _Proc())
    assert oa.version() == "1.18.33"
    assert oa.version() == "1.18.33"  # cached
    assert oa.status()["version"] == "1.18.33"


def test_version_none_when_binary_missing(monkeypatch):
    monkeypatch.setattr("backend.opencode_agent.shutil.which", lambda _: None)
    assert oa.version() is None


def test_run_rejects_when_not_installed(monkeypatch):
    monkeypatch.setattr("backend.opencode_agent.shutil.which", lambda _: None)
    res = oa.run("hola")
    assert res["ok"] is False
    assert res["error"] == "opencode not available"
    assert res["available"] is False


def test_run_rejects_unknown_agent(monkeypatch):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    res = oa.run("hola", agent="rogue")
    assert res["ok"] is False
    assert "agent must be one of" in res["error"]


def test_run_rejects_cwd_escaping_root(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    outside = str(tmp_path / "outside")
    (tmp_path / "outside").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)
    res = oa.run("hola", cwd=outside)
    assert res["ok"] is False
    assert "cwd escapes" in res["error"]


def test_run_success_builds_argv(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)

    captured = {}

    class _Proc:
        returncode = 0
        stdout = "Plan listo"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _Proc()

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", fake_run)
    res = oa.run("revisa el código", agent="build")
    assert res["ok"] is True
    assert res["exit_code"] == 0
    assert res["stdout"] == "Plan listo"
    assert res["agent"] == "build"
    assert res["cwd"] == root
    assert captured["argv"][:5] == [PWD, "run", "--agent", "build", "--dir"]
    assert captured["argv"][5] == root
    assert captured["argv"][6] == "revisa el código"
    assert "shell" not in captured.get("argv", [])


def test_run_model_and_pure_flags(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)
    captured = {}

    class _Proc:
        returncode = 0
        stdout = "x"
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _Proc()

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", fake_run)
    oa.run("p", agent="plan", model="provider/m", pure=True)
    assert "--model" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--model") + 1] == "provider/m"
    assert "--pure" in captured["argv"]
    assert "--auto" not in captured["argv"]


def test_run_timeout(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)

    import subprocess as _sp

    def boom(argv, **kwargs):
        raise _sp.TimeoutExpired(argv[-1], kwargs.get("timeout", 1))

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", boom)
    res = oa.run("p", timeout=2)
    assert res["ok"] is False
    assert "timed out" in res["error"]


def test_run_busy_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)

    class _Proc:
        returncode = 0
        stdout = "x"
        stderr = ""

    def fake_run(argv, **kwargs):
        return _Proc()

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", fake_run)
    oa._LOCK.acquire()
    try:
        res = oa.run("p")
        assert res["ok"] is False
        assert "another agent run is in progress" in res["error"]
        assert res["busy"] is True
    finally:
        oa._LOCK.release()
    res = oa.run("p")
    assert res["ok"] is True


def test_run_redacts_output(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)

    class _Proc:
        returncode = 0
        stdout = "creds AKIA1111111111111111 found"
        stderr = ""

    def fake_run(argv, **kwargs):
        return _Proc()

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", fake_run)
    res = oa.run("p")
    assert "AKIA1111111111111111" not in res["stdout"]


def test_run_stderr_included_on_nonzero(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)

    class _Proc:
        returncode = 2
        stdout = ""
        stderr = "boom: boom"

    def fake_run(argv, **kwargs):
        return _Proc()

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", fake_run)
    res = oa.run("p")
    assert res["ok"] is False
    assert res["exit_code"] == 2
    assert "boom" in res["stderr"]


def test_run_truncates_long_output(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    root = str(tmp_path / "root")
    (tmp_path / "root").mkdir()
    monkeypatch.setenv("MIRV_OPENCODE_ROOT", root)

    class _Proc:
        returncode = 0
        stdout = "A" * (oa.MAX_OUTPUT + 5000)
        stderr = ""

    def fake_run(argv, **kwargs):
        return _Proc()

    monkeypatch.setattr("backend.opencode_agent.subprocess.run", fake_run)
    res = oa.run("p")
    assert len(res["stdout"]) <= oa.MAX_OUTPUT + 100
    assert "truncated" in res["stdout"]


def test_status_busy_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRV_OPENCODE_BIN", PWD)
    oa._LOCK.acquire()
    try:
        assert oa.status()["busy"] is True
    finally:
        oa._LOCK.release()
    assert oa.status()["busy"] is False


# ═─────────────── API endpoint integration ────────────────

def test_api_opencode_status(client, monkeypatch):
    monkeypatch.setattr("backend.opencode_agent.status",
                        lambda: {"installed": True, "version": "1.18.33",
                                 "agents": ["build", "plan", "general"], "busy": False})
    r = client.get("/api/opencode/status")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["installed"] is True
    assert body["allowed_agents"] == ["build", "plan", "general"]


def test_api_opencode_run_rejects_empty_prompt(client):
    r = client.post("/api/opencode/run", json={"prompt": ""})
    assert r.status_code == 400
    assert "prompt is required" in r.json()["error"]


def test_api_opencode_run_rejects_unknown_agent(client):
    r = client.post("/api/opencode/run", json={"prompt": "x", "agent": "rogue"})
    assert r.status_code == 400
    assert "agent must be one of" in r.json()["error"]


def test_api_opencode_run_not_available(client, monkeypatch):
    monkeypatch.setattr("backend.opencode_agent.run",
                        lambda *a, **k: {"ok": False, "available": False, "error": "opencode not available"})
    r = client.post("/api/opencode/run", json={"prompt": "hola", "agent": "plan"})
    assert r.status_code == 503
    assert r.json()["available"] is False


def test_api_opencode_run_success(client, monkeypatch):
    captured = {}
    def fake_run(prompt, agent="plan", cwd=None, model=None, pure=False, timeout=600):
        captured["args"] = (prompt, agent, cwd, model, pure, timeout)
        return {"ok": True, "available": True, "stdout": "made a plan",
                "exit_code": 0, "agent": agent, "cwd": cwd}
    monkeypatch.setattr("backend.opencode_agent.run", fake_run)
    r = client.post("/api/opencode/run",
                    json={"prompt": "revisa x", "agent": "build", "model": "m/1", "pure": True})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["stdout"] == "made a plan"
    assert captured["args"][0] == "revisa x"
    assert captured["args"][1] == "build"
    assert captured["args"][3] == "m/1"
    assert captured["args"][4] is True