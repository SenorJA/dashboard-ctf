"""
Coverage-gap tests for backend/mission_store.py — edge branches.

Covers:
  - _as_json: invalid JSON string
  - _get_mission_details: DB exception
  - _store_session_memory: no table, DB exception
  - _extract_objectives: invalid JSON string, dict objectives
  - _extract_findings: non-list, non-dict item, missing severity/what
  - _extract_credentials: non-dict item, missing user+service
  - _extract_todos: invalid JSON string, dict todos
  - _extract_files: non-str command
  - _collect_commands: invalid JSON string, dict commands, str tools
  - get_session_memory: non-dict parsed memory
  - compact_session: bad prior compaction_count, redact exception
  - auto_compact_if_needed: bad threshold, dumps exception
  - render_session_memory_for_prompt: empty memory, todos/files sections
  - count_compact_sessions: count None, fallback exception
  - save_mission: empty findings promote, auto-compact exception
  - find_similar: invalid tools JSON, non-dict tools
  - get_suggestion_context: non-dict finding, parse exception,
    invalid tools JSON, invalid summary JSON, non-dict summary item
"""

import json
import os
import sys

from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.mission_store as mission_store
from backend.mission_store import (
    _as_json,
    _collect_commands,
    _extract_credentials,
    _extract_files,
    _extract_findings,
    _extract_objectives,
    _extract_todos,
    _get_mission_details,
    _store_session_memory,
    auto_compact_if_needed,
    compact_session,
    count_compact_sessions,
    find_similar,
    get_session_memory,
    get_suggestion_context,
    render_session_memory_for_prompt,
    save_mission,
)


@pytest.fixture(autouse=True)
def mock_db():
    with patch.object(mission_store, "db") as mock:
        yield mock


class TestAsJsonGaps:
    def test_invalid_json_string_returns_none(self):
        assert _as_json("not json") is None

    def test_other_types_passthrough(self):
        assert _as_json(42) == 42


class TestGetMissionDetailsGaps:
    def test_db_exception_returns_none(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.side_effect = RuntimeError("db down")
        assert _get_mission_details("id") is None

    def test_empty_data_returns_none(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = MagicMock(data=None)
        assert _get_mission_details("id") is None


class TestStoreSessionMemoryGaps:
    def test_no_table_returns_false(self, mock_db):
        mock_db._table.return_value = None
        assert _store_session_memory("id", {}) is False

    def test_db_exception_returns_false(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.update.return_value.eq.return_value.execute.side_effect = RuntimeError("db down")
        assert _store_session_memory("id", {}) is False


class TestExtractObjectivesGaps:
    def test_invalid_json_string_wraps(self):
        out = _extract_objectives({"objectives": "not json"})
        assert out == ["not json"]

    def test_dict_objectives_labels(self):
        out = _extract_objectives({
            "objectives": [
                {"title": "Recon"},
                {"description": "Scan"},
                {"goal": "Exploit"},
                {"nope": "ignored"},
            ]
        })
        assert out == ["Recon", "Scan", "Exploit"]


class TestExtractFindingsGaps:
    def test_non_list_returns_empty(self):
        assert _extract_findings({"findings": "oops"}) == []

    def test_dict_findings_returns_empty(self):
        # _as_json passes dicts through → non-list branch (282)
        assert _extract_findings({"findings_summary": {"not": "a list"}}) == []

    def test_non_dict_item_skipped(self):
        out = _extract_findings({"findings": ["nope", {"what": "x", "severity": "high"}]})
        assert len(out) == 1

    def test_missing_severity_skipped(self):
        out = _extract_findings({"findings": [{"what": "x", "severity": ""}]})
        assert out == []

    def test_missing_what_skipped(self):
        out = _extract_findings({"findings": [{"severity": "high", "what": ""}]})
        assert out == []

    def test_low_severity_skipped(self):
        out = _extract_findings({"findings": [{"severity": "low", "what": "x"}]})
        assert out == []


class TestExtractCredentialsGaps:
    def test_non_dict_item_skipped(self):
        out = _extract_credentials({"credentials": [42, {"user": "u", "service": "ssh"}]})
        assert len(out) == 1

    def test_missing_user_and_service_skipped(self):
        out = _extract_credentials({"credentials": [{"target": "h"}]})
        assert out == []


class TestExtractTodosGaps:
    def test_invalid_json_string_wraps(self):
        out = _extract_todos({"todos": "not json"})
        assert out == ["not json"]

    def test_dict_todos(self):
        out = _extract_todos({"todos": [{"description": "Do A"}, {"title": "Do B"}, 42]})
        assert out == ["Do A", "Do B"]


class TestExtractFilesGaps:
    def test_non_str_command_skipped(self):
        out = _extract_files({"commands_executed": [42, "echo hi > /tmp/x.txt"]})
        assert "/tmp/x.txt" in out

    def test_collect_returns_non_str_skipped(self):
        with patch("mission_store._collect_commands", return_value=[42, "echo done > /tmp/y.txt"]):
            out = _extract_files({"commands_executed": []})
        assert "/tmp/y.txt" in out

    def test_redirect_and_tee_detected(self):
        out = _extract_files({"commands_executed": [
            "echo done > report.txt",
            "curl url | tee -a out.log",
            "cp src dst.txt",
            "mv a b.txt",
        ]})
        assert "report.txt" in out
        assert "out.log" in out
        assert "dst.txt" in out


class TestCollectCommandsGaps:
    def test_invalid_json_string_wraps(self):
        assert _collect_commands({"commands_executed": "not json"}) == ["not json"]

    def test_dict_commands(self):
        out = _collect_commands({"commands_executed": [
            {"command": "whoami"},
            {"cmd": "id"},
            {"text": "uname -a"},
            {"nope": 1},
        ]})
        assert out == ["whoami", "id", "uname -a"]

    def test_str_tools_used(self):
        out = _collect_commands({"tools_used": ["nmap -sV", 42, ""]})
        assert out == ["nmap -sV"]


class TestGetSessionMemoryGaps:
    def test_non_dict_memory_returns_none(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = MagicMock(
            data={"session_memory": "123"}
        )
        assert get_session_memory("id") is None

    def test_dict_memory_returns_raw(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = MagicMock(
            data={"session_memory": {"compacted_at": "now"}}
        )
        out = get_session_memory("id")
        assert out == {"compacted_at": "now"}


def _mock_mission(mock_db, row):
    mock_tbl = MagicMock()
    mock_db._table.return_value = mock_tbl
    mock_tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = MagicMock(
        data=row
    )
    return mock_tbl


class TestCompactSessionGaps:
    def test_bad_prior_count_resets_to_zero(self, mock_db):
        _mock_mission(mock_db, {
            "id": "m1",
            "target": "10.0.0.1",
            "session_memory": json.dumps({"compaction_count": "abc"}),
        })
        res = compact_session("m1")
        assert res["ok"] is True
        assert res["memory"]["compaction_count"] == 1

    def test_redact_exception_skipped(self, mock_db):
        _mock_mission(mock_db, {"id": "m1", "target": "10.0.0.1"})
        with patch("mission_store._redact_dict", side_effect=RuntimeError("boom")):
            res = compact_session("m1")
        assert res["ok"] is True

    def test_mission_not_found(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = MagicMock(data=None)
        assert compact_session("x") == {"ok": False, "error": "Mission not found"}


class TestAutoCompactGaps:
    def test_invalid_threshold_uses_default(self, mock_db):
        _mock_mission(mock_db, None)
        # int("abc") fails → falls back to _compact_threshold() then mission is None
        assert auto_compact_if_needed("m1", threshold_chars="abc") is None

    def test_zero_threshold_disables(self, mock_db):
        assert auto_compact_if_needed("m1", threshold_chars=0) is None

    def test_dumps_exception_size_zero(self, mock_db):
        _mock_mission(mock_db, {"id": "m1", "target": "10.0.0.1"})
        with patch("mission_store.json.dumps", side_effect=TypeError("nope")):
            assert auto_compact_if_needed("m1", threshold_chars=100) is None


class TestRenderSessionMemoryGaps:
    def test_empty_memory_returns_empty(self, mock_db):
        with patch("mission_store.get_session_memory", return_value={}):
            assert render_session_memory_for_prompt("m1") == ""

    def test_non_dict_memory_returns_empty(self, mock_db):
        with patch("mission_store.get_session_memory", return_value=42):
            assert render_session_memory_for_prompt("m1") == ""

    def test_lazy_compaction_failure_returns_empty(self, mock_db):
        with patch("mission_store.get_session_memory", return_value=None):
            with patch("mission_store.compact_session", return_value={"ok": False}):
                assert render_session_memory_for_prompt("m1") == ""

    def test_todos_and_files_sections(self, mock_db):
        with patch("mission_store.get_session_memory", return_value={
            "compacted_at": "2026-01-01T00:00:00+00:00",
            "objectives": ["Recon"],
            "findings": [{"severity": "high", "what": "SQLi", "target": "t"}],
            "credentials": [{"user": "u", "service": "ssh", "target": "t"}],
            "todos": ["Run nmap"],
            "files": ["/tmp/out.txt"],
            "commands": ["nmap -sV t"],
            "technologies": ["nginx"],
        }):
            out = render_session_memory_for_prompt("m1")
        assert "Open TODOs" in out
        assert "Run nmap" in out
        assert "Files touched" in out
        assert "/tmp/out.txt" in out


class TestCountCompactSessionsGaps:
    def test_count_none_falls_back_to_data(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.not_.is_.return_value.execute.return_value = MagicMock(
            count=None, data=[{"id": "1"}, {"id": "2"}]
        )
        assert count_compact_sessions() == 2

    def test_fallback_exception_returns_zero(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.not_.is_.return_value.execute.side_effect = RuntimeError("boom")
        mock_tbl.select.return_value.execute.side_effect = RuntimeError("boom2")
        assert count_compact_sessions() == 0


class TestSaveMissionGaps:
    def test_empty_findings_promoted(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(data=[{"id": "abc"}])
        save_mission({"target": "10.0.0.1", "findings": []})
        call_args = mock_tbl.insert.call_args[0][0]
        assert call_args["findings_summary"] == "[]"

    def test_auto_compact_exception_skipped(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(data=[{"id": "abc"}])
        with patch("mission_store._compact_threshold", return_value=100):
            with patch("mission_store.auto_compact_if_needed", side_effect=RuntimeError("boom")):
                res = save_mission({"target": "10.0.0.1"})
        assert res["id"] == "abc"

    def test_db_exception_returns_none(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.side_effect = RuntimeError("boom")
        assert save_mission({"target": "10.0.0.1"}) is None


class TestFindSimilarGaps:
    def _setup(self, mock_db, rows):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.ilike.return_value.limit.return_value.execute.return_value = MagicMock(data=rows)
        return mock_tbl

    def test_invalid_tools_json(self, mock_db):
        self._setup(mock_db, [{"tools_used": "not json", "success_score": 10}])
        out = find_similar(target_os="apache", tools=["nmap"])
        # Invalid tools JSON → empty names → no overlap → [] (fallback to rows only when tools truthy)
        assert isinstance(out, list)

    def test_str_tools_items(self, mock_db):
        self._setup(mock_db, [{"tools_used": ["nmap", "nikto"], "success_score": 10}])
        out = find_similar(target_os="apache", tools=["nmap"])
        assert out and out[0]["success_score"] == 10

    def test_no_rows_returns_empty(self, mock_db):
        self._setup(mock_db, None)
        assert find_similar(target_os="apache") == []


class _BadStr(str):
    def lower(self):
        raise RuntimeError("boom")


class TestGetSuggestionContextGaps:
    def test_non_dict_finding_skipped(self, mock_db):
        with patch("mission_store.find_similar", return_value=[]):
            assert get_suggestion_context([42]) == ""

    def test_parse_exception_returns_empty(self, mock_db):
        assert get_suggestion_context(_BadStr("apache")) == ""

    def test_invalid_tools_and_summary_json(self, mock_db):
        with patch("mission_store.find_similar", return_value=[{
            "target": "t", "success_score": 50, "findings_count": 2,
            "tools_used": "not json", "findings_summary": "not json",
        }]):
            out = get_suggestion_context("apache")
        assert "Mission History Context" in out

    def test_summary_non_dict_item_skipped(self, mock_db):
        with patch("mission_store.find_similar", return_value=[{
            "target": "t", "success_score": 50, "findings_count": 2,
            "tools_used": [], "findings_summary": json.dumps(["notadict"]),
        }]):
            out = get_suggestion_context("apache")
        assert "Top findings" in out
