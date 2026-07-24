"""
Tests for Session Compaction — `backend/mission_store.py` compact_session
plus the REST surface in `backend/main.py`.

Covers:
    - SessionMemory dataclass defaults & caps
    - compact_session valid + non-existent
    - findings filtered to high/critical only, capped at 12
    - credentials: NO secret values ever exposed (redacted)
    - todos capped at 12, files capped at 12, commands deduped+capped
    - technologies extraction via _TECH_RULES keyword scan
    - auto_compact_if_needed below/above threshold, threshold 0 disabled
    - render_session_memory_for_prompt contains ## Session Memory + sections
    - get_session_memory for non-compacted mission → None
    - count_compact_sessions query
    - compaction idempotent (re-compact increments count)
    - MIRV_COMPACT_THRESHOLD env var honored
    - REST smoke tests (4 endpoints + count)
    - /api/suggest includes memory in prompt when mission_id provided
"""

import json
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mission_store
from mission_store import (
    SessionMemory,
    compact_session,
    get_session_memory,
    render_session_memory_for_prompt,
    auto_compact_if_needed,
    count_compact_sessions,
    save_mission,
)

from main import app
from fastapi.testclient import TestClient


# ════════════════════════════════════════════════════════════════
#  Helpers / fixtures
# ════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
def mock_db():
    """Mock mission_store.db so no live Supabase connection is required."""
    with patch.object(mission_store, "db") as mock:
        yield mock


@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Reset MIRV_COMPACT_THRESHOLD for deterministic behavior."""
    monkeypatch.delenv("MIRV_COMPACT_THRESHOLD", raising=False)


def _mock_mission_row(mid="m-1", **overrides):
    """Build a mission row that read_back from DB would return."""
    row = {
        "id": mid,
        "target": "example.com",
        "os_detected": "Linux nginx 1.18",
        "tools_used": json.dumps(
            [{"tool": "nmap", "command": "nmap -sV example.com", "useful": True},
             {"tool": "gobuster", "command": "gobuster dir -u http://example.com -w wordlist", "useful": True}]
        ),
        "findings_summary": json.dumps([
            {"what": "SQLi", "severity": "high", "target": "/search?q="},
            {"what": "RCE", "severity": "critical", "target": "/admin"},
            {"what": "Info banner", "severity": "info", "target": "/"},
            {"what": "XSS", "severity": "medium", "target": "/x"},
        ]),
        "findings_count": 4,
        "plan_steps": 0,
        "success_score": 80,
        "session_memory": None,
    }
    row.update(overrides)
    return row


def _mock_get_details(row):
    """Mock the mission-row lookup so compact_session sees `row`."""
    mock_tbl = MagicMock()
    mission_store.db._table.return_value = mock_tbl
    chain = mock_tbl.select.return_value.eq.return_value
    chain.maybe_single.return_value.execute.return_value = MagicMock(data=row)
    return mock_tbl


# ════════════════════════════════════════════════════════════════
#  SessionMemory dataclass
# ════════════════════════════════════════════════════════════════

class TestSessionMemoryDataclass:
    def test_default_factory(self):
        m = SessionMemory(mission_id="m-1")
        assert m.mission_id == "m-1"
        assert m.objectives == []
        assert m.findings == []
        assert m.credentials == []
        assert m.todos == []
        assert m.files == []
        assert m.commands == []
        assert m.technologies == []
        assert m.last_summary is None
        assert m.compacted_at is None
        assert m.compaction_count == 0

    def test_caps_constants(self):
        assert mission_store._MAX_OBJECTIVES == 24
        assert mission_store._MAX_FINDINGS == 12
        assert mission_store._MAX_CREDENTIALS == 12
        assert mission_store._MAX_TODOS == 12
        assert mission_store._MAX_FILES == 12
        assert mission_store._MAX_COMMANDS == 12
        assert mission_store._MAX_TECHNOLOGIES == 16


# ════════════════════════════════════════════════════════════════
#  compact_session
# ════════════════════════════════════════════════════════════════

class TestCompactSession:
    def test_returns_memory_dict(self):
        _mock_get_details(_mock_mission_row())
        res = compact_session("m-1")
        assert res["ok"] is True
        mem = res["memory"]
        assert mem["mission_id"] == "m-1"
        for key in ("objectives", "findings", "credentials", "todos",
                    "files", "commands", "technologies",
                    "last_summary", "compacted_at", "compaction_count"):
            assert key in mem

    def test_compacted_at_set_iso(self):
        _mock_get_details(_mock_mission_row())
        mem = compact_session("m-1")["memory"]
        assert mem["compacted_at"]
        # ISO-8601 contains the 'T' separator
        assert "T" in mem["compacted_at"]

    def test_max_findings_cap(self):
        row = _mock_mission_row()
        row["findings_summary"] = json.dumps(
            [{"what": f"vuln {i}", "severity": "high", "target": "/p"}
             for i in range(50)]
        )
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert len(mem["findings"]) == 12

    def test_high_severity_filter(self):
        _mock_get_details(_mock_mission_row())
        mem = compact_session("m-1")["memory"]
        # only high + critical kept from the 4 findings (info & medium dropped)
        assert len(mem["findings"]) == 2
        for f in mem["findings"]:
            assert f["severity"] in ("high", "critical")

    def test_findings_shape_what_severity_target(self):
        _mock_get_details(_mock_mission_row())
        f = compact_session("m-1")["memory"]["findings"][0]
        assert set(f.keys()) == {"what", "severity", "target"}

    def test_credential_secret_redacted(self):
        row = _mock_mission_row()
        row["credentials"] = [
            {"user": "admin", "password": "SuperSecret123!=", "service": "ssh", "target": "10.0.0.1"},
            {"user": "root", "token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaa", "service": "git", "target": "host"},
        ]
        row["findings_summary"] = json.dumps([{"what": "ssh", "severity": "high", "target": "10.0.0.1"}])
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        for c in mem["credentials"]:
            # Only user/service/target keys are allowed
            assert set(c.keys()) <= {"user", "service", "target"}
            blob = json.dumps(c)
            assert "SuperSecret123" not in blob
            assert "ghp_aaaaaaa" not in blob
            assert "password" not in blob
            assert "token" not in blob

    def test_credential_capped_12(self):
        row = _mock_mission_row()
        row["credentials"] = [{"user": f"u{i}", "service": "ssh", "target": "h"} for i in range(30)]
        row["findings_summary"] = json.dumps([{"what": "x", "severity": "high", "target": "/"}])
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert len(mem["credentials"]) == 12

    def test_objectives_max_24(self):
        row = _mock_mission_row()
        row["objectives"] = [f"obj {i}" for i in range(50)]
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert len(mem["objectives"]) == 24

    def test_objectives_fallback_when_missing(self):
        _mock_get_details(_mock_mission_row(target="acme.io", os_detected="Linux"))
        mem = compact_session("m-1")["memory"]
        assert len(mem["objectives"]) >= 1
        assert "acme.io" in mem["objectives"][0] or "Linux" in mem["objectives"][0]

    def test_todos_max_12(self):
        row = _mock_mission_row()
        row["todos"] = [f"todo {i}" for i in range(30)]
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert len(mem["todos"]) == 12

    def test_commands_dedupe_and_cap(self):
        row = _mock_mission_row()
        row["commands_executed"] = [
            "nmap -sV example.com",
            "echo test > /tmp/out.txt",
            "nmap -sV example.com",      # dup
            "tee /tmp/loot.txt",
            "echo A > /tmp/a.txt",
            "echo B > /tmp/b.txt",
            "echo C > /tmp/c.txt",
            "echo D > /tmp/d.txt",
            "echo E > /tmp/e.txt",
            "echo F > /tmp/f.txt",
            "echo G > /tmp/g.txt",
        ]
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert len(mem["commands"]) <= 12
        # dedup: only one of ("nmap -sV example.com") plus tool-supplied entry stays
        assert mem["commands"].count("nmap -sV example.com") == 1
        # no duplicate commands in the output
        assert len(mem["commands"]) == len(set(mem["commands"]))

    def test_technologies_extraction(self):
        row = _mock_mission_row()
        row["tools_used"] = json.dumps([
            {"tool": "nmap", "command": "nmap -sV example.com", "useful": True},
            {"tool": "gobuster", "command": "gobuster dir -u http://example.com -w w", "useful": True},
            {"tool": "wpscan", "command": "wpscan --url http://example.com", "useful": True},
        ])
        row["os_detected"] = "nginx/1.18 on PostgreSQL backend"
        row["findings_summary"] = json.dumps([{"what": "nginx admin", "severity": "high", "target": "/"}])
        _mock_get_details(row)
        techs = compact_session("m-1")["memory"]["technologies"]
        assert "Nmap scanner" in techs
        assert "Web directory bruteforce" in techs
        assert "WordPress CMS" in techs
        assert "nginx web server" in techs
        assert "PostgreSQL" in techs

    def test_technologies_max_16(self):
        row = _mock_mission_row()
        row["os_detected"] = " ".join(k for k, _ in mission_store._TECH_RULES[:30])
        _mock_get_details(row)
        techs = compact_session("m-1")["memory"]["technologies"]
        assert len(techs) <= 16

    def test_files_extracted_from_write_commands(self):
        row = _mock_mission_row()
        row["commands_executed"] = [
            "echo data > /tmp/loot.txt",
            "nmap -sV host | tee /tmp/scan.txt",
            "cp /etc/passwd /tmp/passwd.bak",
        ]
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert "/tmp/loot.txt" in mem["files"]
        assert "/tmp/scan.txt" in mem["files"]
        assert "/tmp/passwd.bak" in mem["files"]

    def test_files_max_12(self):
        row = _mock_mission_row()
        row["commands_executed"] = [f"echo x{i} > /tmp/f{i}.txt" for i in range(40)]
        _mock_get_details(row)
        mem = compact_session("m-1")["memory"]
        assert len(mem["files"]) == 12

    def test_nonexistent_mission(self):
        mission_store.db._table.return_value = MagicMock()
        chain = mission_store.db._table.return_value.select.return_value.eq.return_value
        chain.maybe_single.return_value.execute.return_value = MagicMock(data=None)
        res = compact_session("no-pe")
        assert res["ok"] is False
        assert res["error"] == "Mission not found"

    def test_no_db_returns_error(self):
        mission_store.db._table.return_value = None
        res = compact_session("m-1")
        assert res["ok"] is False

    def test_idempotent_increments_count(self):
        # First compaction sees no prior memory → count becomes 1
        _mock_get_details(_mock_mission_row())
        first = compact_session("m-1")["memory"]
        assert first["compaction_count"] == 1

        # Second compaction sees the first memory stored on the row
        row2 = _mock_mission_row(session_memory=first)
        _mock_get_details(row2)
        second = compact_session("m-1")["memory"]
        assert second["compaction_count"] == 2

    def test_store_session_memory_called(self):
        mock_tbl = _mock_get_details(_mock_mission_row())
        compact_session("m-1")
        mock_tbl.update.assert_called_once()
        # The first positional arg must be a dict with the session_memory key
        args, _ = mock_tbl.update.call_args
        assert "session_memory" in args[0]


# ════════════════════════════════════════════════════════════════
#  get_session_memory
# ════════════════════════════════════════════════════════════════

class TestGetSessionMemory:
    def test_returns_stored_memory(self):
        mem = {"mission_id": "m-2", "objectives": ["x"], "compaction_count": 1}
        row = _mock_mission_row(mid="m-2", session_memory=mem)
        _mock_get_details(row)
        assert get_session_memory("m-2") == mem

    def test_no_session_memory_returns_none(self):
        _mock_get_details(_mock_mission_row())
        assert get_session_memory("m-1") is None

    def test_mission_not_found_returns_none(self):
        mission_store.db._table.return_value = MagicMock()
        chain = mission_store.db._table.return_value.select.return_value.eq.return_value
        chain.maybe_single.return_value.execute.return_value = MagicMock(data=None)
        assert get_session_memory("zzz") is None

    def test_no_db_returns_none(self):
        mission_store.db._table.return_value = None
        assert get_session_memory("m-1") is None

    def test_json_string_session_memory_decoded(self):
        mem_str = json.dumps({"mission_id": "m-3", "objectives": ["y"]})
        row = _mock_mission_row(mid="m-3", session_memory=mem_str)
        _mock_get_details(row)
        out = get_session_memory("m-3")
        assert out == {"mission_id": "m-3", "objectives": ["y"]}


# ════════════════════════════════════════════════════════════════
#  auto_compact_if_needed
# ════════════════════════════════════════════════════════════════

class TestAutoCompactIfNeeded:
    def test_below_threshold_returns_none(self):
        _mock_get_details(_mock_mission_row())
        assert auto_compact_if_needed("m-1", threshold_chars=100000) is None

    def test_above_threshold_compacts(self):
        row = _mock_mission_row()
        row["findings_summary"] = json.dumps(
            [{"what": "v" * 5000, "severity": "high", "target": "/"}]
        )
        _mock_get_details(row)
        res = auto_compact_if_needed("m-1", threshold_chars=100)
        assert res is not None
        assert res["ok"] is True
        assert res["memory"]["compaction_count"] >= 1

    def test_threshold_zero_disabled(self):
        _mock_get_details(_mock_mission_row())
        # threshold 0 → disabled → None
        assert auto_compact_if_needed("m-1", threshold_chars=0) is None

    def test_default_uses_env_threshold(self, monkeypatch):
        # When threshold is None we read env var
        monkeypatch.setenv("MIRV_COMPACT_THRESHOLD", "10")
        row = _mock_mission_row()
        row["findings_summary"] = json.dumps(
            [{"what": "x" * 200, "severity": "high", "target": "/"}]
        )
        _mock_get_details(row)
        res = auto_compact_if_needed("m-1", threshold_chars=None)
        assert res is not None
        assert res["ok"] is True

    def test_env_threshold_zero_disables(self, monkeypatch):
        # When threshold is None and env is 0 → skip
        monkeypatch.setenv("MIRV_COMPACT_THRESHOLD", "0")
        _mock_get_details(_mock_mission_row())
        assert auto_compact_if_needed("m-1", threshold_chars=None) is None

    def test_missing_mission_returns_none(self):
        mission_store.db._table.return_value = MagicMock()
        chain = mission_store.db._table.return_value.select.return_value.eq.return_value
        chain.maybe_single.return_value.execute.return_value = MagicMock(data=None)
        assert auto_compact_if_needed("?", threshold_chars=10) is None


# ════════════════════════════════════════════════════════════════
#  render_session_memory_for_prompt
# ════════════════════════════════════════════════════════════════

class TestRenderSessionMemory:
    def test_contains_header(self):
        _mock_get_details(_mock_mission_row())
        out = render_session_memory_for_prompt("m-1")
        assert out.startswith("## Session Memory")

    def test_compacted_at_in_header(self):
        _mock_get_details(_mock_mission_row())
        out = render_session_memory_for_prompt("m-1")
        assert "last compacted:" in out

    def test_objectives_section_listed(self):
        row = _mock_mission_row()
        row["objectives"] = ["Find RCE", "Dump users"]
        _mock_get_details(row)
        out = render_session_memory_for_prompt("m-1")
        assert "### Objectives" in out
        assert "Find RCE" in out
        assert "Dump users" in out

    def test_findings_section_listed(self):
        row = _mock_mission_row()
        row["findings_summary"] = json.dumps(
            [{"what": "SQLi", "severity": "high", "target": "/search?q="}]
        )
        _mock_get_details(row)
        out = render_session_memory_for_prompt("m-1")
        assert "### High-severity findings" in out
        assert "SQLi" in out
        assert "HIGH" in out

    def test_credentials_section_listed(self):
        row = _mock_mission_row()
        row["credentials"] = [{"user": "admin", "service": "ssh", "target": "h"}]
        _mock_get_details(row)
        out = render_session_memory_for_prompt("m-1")
        assert "### Discovered credentials" in out
        assert "admin@ssh" in out

    def test_empty_returns_empty_string(self):
        mission_store.db._table.return_value = MagicMock()
        chain = mission_store.db._table.return_value.select.return_value.eq.return_value
        chain.maybe_single.return_value.execute.return_value = MagicMock(data=None)
        assert render_session_memory_for_prompt("none") == ""

    def test_recent_commands_section(self):
        row = _mock_mission_row()
        row["commands_executed"] = ["nmap -sV host", "nuclei -u host"]
        _mock_get_details(row)
        out = render_session_memory_for_prompt("m-1")
        assert "### Recent commands" in out
        assert "nmap -sV host" in out

    def test_technologies_section(self):
        row = _mock_mission_row()
        row["os_detected"] = "nginx + node.js"
        row["tools_used"] = json.dumps([
            {"tool": "nmap", "command": "nmap -sV host", "useful": True}
        ])
        _mock_get_details(row)
        out = render_session_memory_for_prompt("m-1")
        assert "### Technologies" in out

    def test_uses_stored_memory_when_present(self):
        # Pre-stored memory should be rendered without re-compacting
        mem = {
            "mission_id": "m-stored",
            "objectives": ["prestored obj"],
            "findings": [{"what": "prestored finding", "severity": "high", "target": "/x"}],
            "credentials": [], "todos": [], "files": [], "commands": [],
            "technologies": [], "last_summary": None,
            "compacted_at": "2026-01-01T00:00:00+00:00",
            "compaction_count": 5,
        }
        row = _mock_mission_row(mid="m-stored", session_memory=mem)
        _mock_get_details(row)
        out = render_session_memory_for_prompt("m-stored")
        assert "prestored obj" in out
        assert "prestored finding" in out
        assert "2026-01-01" in out


# ════════════════════════════════════════════════════════════════
#  count_compact_sessions
# ════════════════════════════════════════════════════════════════

class TestCountCompactSessions:
    def test_no_db_returns_zero(self):
        mission_store.db._table.return_value = None
        assert count_compact_sessions() == 0

    def test_counts_viacount_attribute(self):
        mock_tbl = MagicMock()
        mission_store.db._table.return_value = mock_tbl
        # Build the chain: select().not_.is_().execute()
        mock_tbl.select.return_value.not_.is_.return_value.execute.return_value = MagicMock(
            data=[], count=7
        )
        assert count_compact_sessions() == 7

    def test_fallback_to_row_count(self):
        mock_tbl = MagicMock()
        mission_store.db._table.return_value = mock_tbl
        # First call (uses count=) raises → fallback path
        mock_tbl.select.return_value.not_.is_.return_value.execute.side_effect = RuntimeError("boom")
        mock_tbl.select.return_value.execute.return_value = MagicMock(
            data=[
                {"id": "a", "session_memory": {"mission_id": "a"}},
                {"id": "b", "session_memory": None},
                {"id": "c", "session_memory": {"mission_id": "c"}},
            ]
        )
        assert count_compact_sessions() == 2


# ════════════════════════════════════════════════════════════════
#  Env threshold helper
# ════════════════════════════════════════════════════════════════

class TestCompactThresholdEnv:
    def test_default_16000(self, monkeypatch):
        monkeypatch.delenv("MIRV_COMPACT_THRESHOLD", raising=False)
        assert mission_store._compact_threshold() == 16000

    def test_override(self, monkeypatch):
        monkeypatch.setenv("MIRV_COMPACT_THRESHOLD", "5000")
        assert mission_store._compact_threshold() == 5000

    def test_zero_disables(self, monkeypatch):
        monkeypatch.setenv("MIRV_COMPACT_THRESHOLD", "0")
        assert mission_store._compact_threshold() == 0

    def test_invalid_falls_back(self, monkeypatch):
        monkeypatch.setenv("MIRV_COMPACT_THRESHOLD", "not-a-number")
        assert mission_store._compact_threshold() == 16000


# ════════════════════════════════════════════════════════════════
#  REST endpoints
# ════════════════════════════════════════════════════════════════
#
# NOTE: ``main.py`` imports the compaction helpers as
# ``ms_compact / ms_memory / ms_render_memory / ms_autocompact /
# ms_count_compact`` — these live in ``backend.mission_store`` (a
# *different* module object than the top-level ``mission_store`` this
# file imports for unit tests). Patching ``mission_store.db`` does NOT
# affect the functions ``main.py`` bound at import time, so we patch
# the ``main.*`` aliases directly for the endpoint smoke tests.

import main as main_module  # noqa: E402

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _memory_dict(mid="m-1", **over):
    base = {
        "mission_id": mid,
        "objectives": ["Pentest example.com"],
        "findings": [{"what": "SQLi", "severity": "high", "target": "/q"}],
        "credentials": [{"user": "admin", "service": "ssh", "target": "h"}],
        "todos": ["verify RCE"],
        "files": ["/tmp/loot.txt"],
        "commands": ["nmap -sV example.com"],
        "technologies": ["nginx web server"],
        "last_summary": None,
        "compacted_at": "2026-07-24T00:00:00+00:00",
        "compaction_count": 1,
    }
    base.update(over)
    return base


class TestCompactEndpoints:
    def test_post_compact_ok(self, client):
        with patch.object(main_module, "ms_compact", return_value={"ok": True, "memory": _memory_dict()}):
            resp = client.post("/api/missions/m-1/compact")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["memory"]["mission_id"] == "m-1"

    def test_post_compact_not_found(self, client):
        with patch.object(main_module, "ms_compact", return_value={"ok": False, "error": "Mission not found"}):
            resp = client.post("/api/missions/none/compact")
        assert resp.status_code == 404
        assert resp.json()["ok"] is False

    def test_get_memory_ok(self, client):
        mem = _memory_dict(mid="m-mem")
        with patch.object(main_module, "ms_memory", return_value=mem):
            resp = client.get("/api/missions/m-mem/memory")
        assert resp.status_code == 200
        assert resp.json()["memory"] == mem

    def test_get_memory_not_stored(self, client):
        with patch.object(main_module, "ms_memory", return_value=None):
            resp = client.get("/api/missions/m-1/memory")
        assert resp.status_code == 404

    def test_get_memory_render_ok(self, client):
        rendered = "## Session Memory (last compacted: 2026-07-24)\n\n### Objectives\n- Pentest example.com\n"
        with patch.object(main_module, "ms_render_memory", return_value=rendered):
            resp = client.get("/api/missions/m-1/memory/render")
        assert resp.status_code == 200
        assert "## Session Memory" in resp.json()["markdown"]

    def test_get_memory_render_empty(self, client):
        with patch.object(main_module, "ms_render_memory", return_value=""):
            resp = client.get("/api/missions/none/memory/render")
        assert resp.status_code == 404

    def test_post_compact_all(self, client):
        # list_missions is also imported into main; patch it to return two rows
        with patch.object(main_module, "list_missions", return_value=[{"id": "a"}, {"id": "b"}]):
            with patch.object(main_module, "ms_autocompact", return_value=None):
                resp = client.post("/api/missions/compact-all")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["count"] == 0  # nothing compacted (mock returned None)
        assert isinstance(body["compacted"], list)

    def test_post_compact_all_with_compaction(self, client):
        with patch.object(main_module, "list_missions", return_value=[{"id": "a"}, {"id": "b"}]):
            with patch.object(main_module, "ms_autocompact",
                              return_value={"ok": True, "memory": _memory_dict(mid="a")}):
                resp = client.post("/api/missions/compact-all")
        body = resp.json()
        assert body["ok"] is True
        assert body["count"] == 2

    def test_get_compact_count(self, client):
        with patch.object(main_module, "ms_count_compact", return_value=3):
            resp = client.get("/api/missions/compact/count")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True, "count": 3}


# ════════════════════════════════════════════════════════════════
#  /api/suggest + session memory integration
# ════════════════════════════════════════════════════════════════

class TestSuggestWithMemory:
    def test_suggest_includes_memory_when_mission_id(self, client):
        captured = {}

        def _fake_call(provider, api_key, model, messages, timeout):
            captured["messages"] = messages
            return "OK suggestion"

        mem_block = "## Session Memory (last compacted: 2026-07-24)\n\n### Objectives\n- Pentest example.com\n"
        with patch.object(main_module, "_call_llm_sync", side_effect=_fake_call):
            with patch.object(main_module, "cov_context", return_value=""):
                with patch.object(main_module, "get_suggestion_context", return_value=""):
                    with patch.object(main_module, "ms_render_memory", return_value=mem_block):
                        resp = client.post("/api/suggest", json={
                            "provider": "local",
                            "target": "example.com",
                            "findings": "found SQLi",
                            "mission_id": "m-sug",
                        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        system_msg = next(m for m in captured["messages"] if m["role"] == "system")
        assert "## Session Memory" in system_msg["content"]
        assert "Pentest example.com" in system_msg["content"]

    def test_suggest_injects_memory_block_into_prompt(self, client):
        captured = {}

        def _fake_call(provider, api_key, model, messages, timeout):
            captured["messages"] = messages
            return "stub"

        mem_block = "## Session Memory\n\n### High-severity findings\n- [HIGH] SQLi — target: /q\n"
        with patch.object(main_module, "_call_llm_sync", side_effect=_fake_call):
            with patch.object(main_module, "cov_context", return_value=""):
                with patch.object(main_module, "get_suggestion_context", return_value=""):
                    with patch.object(main_module, "ms_render_memory", return_value=mem_block):
                        resp = client.post("/api/suggest", json={
                            "provider": "local",
                            "target": "example.com",
                            "findings": "none",
                            "mission_id": "m-sug2",
                        })
        assert resp.status_code == 200
        system_msg = next(m for m in captured["messages"] if m["role"] == "system")
        assert "## Session Memory" in system_msg["content"]
        assert "SQLi" in system_msg["content"]

    def test_suggest_no_memory_without_mission_id(self, client):
        captured = {}

        def _fake_call(provider, api_key, model, messages, timeout):
            captured["messages"] = messages
            return "stub"

        with patch.object(main_module, "_call_llm_sync", side_effect=_fake_call):
            with patch.object(main_module, "cov_context", return_value=""):
                with patch.object(main_module, "get_suggestion_context", return_value=""):
                    with patch.object(main_module, "ms_render_memory", return_value="SHOULD_NOT_APPEAR"):
                        resp = client.post("/api/suggest", json={
                            "provider": "local",
                            "target": "example.com",
                            "findings": "none",
                        })
        assert resp.status_code == 200
        system_msg = next(m for m in captured["messages"] if m["role"] == "system")
        assert "## Session Memory" not in system_msg["content"]
        assert "SHOULD_NOT_APPEAR" not in system_msg["content"]

    def test_suggest_render_failure_degrades_gracefully(self, client):
        captured = {}

        def _fake_call(provider, api_key, model, messages, timeout):
            captured["messages"] = messages
            return "stub"

        with patch.object(main_module, "_call_llm_sync", side_effect=_fake_call):
            with patch.object(main_module, "cov_context", return_value=""):
                with patch.object(main_module, "get_suggestion_context", return_value=""):
                    with patch.object(main_module, "ms_render_memory", side_effect=RuntimeError("boom")):
                        resp = client.post("/api/suggest", json={
                            "provider": "local",
                            "target": "example.com",
                            "findings": "none",
                            "mission_id": "m-err",
                        })
        # Render failure must NOT crash the suggest endpoint
        assert resp.status_code == 200
        system_msg = next(m for m in captured["messages"] if m["role"] == "system")
        assert "## Session Memory" not in system_msg["content"]


# ════════════════════════════════════════════════════════════════
#  save_mission integration with auto-compact
# ════════════════════════════════════════════════════════════════

class TestSaveMissionAutoCompact:
    def test_save_promotes_findings_into_summary(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": "abc", "target": "example.com"}]
        )
        # Pre-empt the auto-compact call from corrupting the test
        with patch.object(mission_store, "auto_compact_if_needed", return_value=None) as ac:
            save_mission({
                "target": "example.com",
                "findings": [{"what": "SQLi", "severity": "high", "target": "/q"}],
                "commands_executed": ["nmap -sV example.com"],
            })
        row = mock_tbl.insert.call_args[0][0]
        assert json.loads(row["findings_summary"]) == [{"what": "SQLi", "severity": "high", "target": "/q"}]
        assert json.loads(row["tools_used"]) == [{"tool": "", "command": "nmap -sV example.com", "useful": True}]
        assert row["findings_count"] == 1
        # auto-compact was triggered (env default positive)
        ac.assert_called_once()

    def test_save_skips_autocompact_when_env_zero(self, mock_db, monkeypatch):
        monkeypatch.setenv("MIRV_COMPACT_THRESHOLD", "0")
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": "abc", "target": "example.com"}]
        )
        with patch.object(mission_store, "auto_compact_if_needed") as ac:
            save_mission({"target": "example.com"})
        ac.assert_not_called()