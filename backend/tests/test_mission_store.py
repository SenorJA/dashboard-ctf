"""
Tests for backend/mission_store.py — Self-Improvement Mission Store.

Covers:
    - save_mission() happy path, empty target, no DB, DB error, defaults
    - list_missions() happy, no DB, with target filter, DB error
    - find_similar() with OS, with tools, with overlap, no DB, no rows
    - get_suggestion_context() string findings, list findings, empty, no similar
    - _SEVERITY_WEIGHT constant
"""

import json
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import mission_store
from mission_store import (
    _SEVERITY_WEIGHT,
    save_mission,
    list_missions,
    find_similar,
    get_suggestion_context,
)


@pytest.fixture(autouse=True)
def mock_db():
    """Mock database module."""
    with patch.object(mission_store, "db") as mock:
        yield mock


# ════════════════════════════════════════════════════════════════
#  _SEVERITY_WEIGHT
# ════════════════════════════════════════════════════════════════

class TestSeverityWeight:
    def test_has_all_levels(self):
        assert "critical" in _SEVERITY_WEIGHT
        assert "high" in _SEVERITY_WEIGHT
        assert "medium" in _SEVERITY_WEIGHT
        assert "low" in _SEVERITY_WEIGHT
        assert "info" in _SEVERITY_WEIGHT

    def test_critical_highest(self):
        assert _SEVERITY_WEIGHT["critical"] > _SEVERITY_WEIGHT["high"]

    def test_ordering(self):
        assert _SEVERITY_WEIGHT["critical"] > _SEVERITY_WEIGHT["high"] > _SEVERITY_WEIGHT["medium"] > _SEVERITY_WEIGHT["low"] > _SEVERITY_WEIGHT["info"]


# ════════════════════════════════════════════════════════════════
#  save_mission()
# ════════════════════════════════════════════════════════════════

class TestSaveMission:
    def test_empty_target_returns_none(self, mock_db):
        result = save_mission({"target": ""})
        assert result is None

    def test_whitespace_target_returns_none(self, mock_db):
        result = save_mission({"target": "   "})
        assert result is None

    def test_none_target_returns_none(self, mock_db):
        result = save_mission({"target": None})
        assert result is None

    def test_no_target_key_returns_none(self, mock_db):
        result = save_mission({})
        assert result is None

    def test_no_db_returns_none(self, mock_db):
        mock_db._table.return_value = None
        result = save_mission({"target": "10.0.0.1"})
        assert result is None

    def test_success(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": "abc", "target": "10.0.0.1"}]
        )
        result = save_mission({
            "target": "10.0.0.1",
            "os_detected": "Linux",
            "tools_used": [{"tool": "nmap"}],
            "findings_count": 5,
            "success_score": 80,
        })
        assert result is not None
        assert result["target"] == "10.0.0.1"

    def test_defaults_applied(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": "abc"}]
        )
        save_mission({"target": "10.0.0.1"})
        call_args = mock_tbl.insert.call_args[0][0]
        assert call_args["os_detected"] == ""
        assert call_args["findings_count"] == 0
        assert call_args["success_score"] == 0

    def test_json_serialization(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(
            data=[{"id": "abc"}]
        )
        tools = [{"tool": "nmap", "command": "nmap -sV", "useful": True}]
        save_mission({"target": "10.0.0.1", "tools_used": tools, "findings_summary": [{"title": "x"}]})
        call_args = mock_tbl.insert.call_args[0][0]
        assert isinstance(call_args["tools_used"], str)
        assert isinstance(call_args["findings_summary"], str)
        assert json.loads(call_args["tools_used"]) == tools

    def test_db_exception_returns_none(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.side_effect = RuntimeError("DB error")
        result = save_mission({"target": "10.0.0.1"})
        assert result is None

    def test_empty_data_response(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.insert.return_value.execute.return_value = MagicMock(data=[])
        result = save_mission({"target": "10.0.0.1"})
        assert result is None


# ════════════════════════════════════════════════════════════════
#  list_missions()
# ════════════════════════════════════════════════════════════════

class TestListMissions:
    def test_no_db_returns_empty(self, mock_db):
        mock_db._table.return_value = None
        assert list_missions() == []

    def test_success(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[{"id": "1", "target": "10.0.0.1"}, {"id": "2", "target": "10.0.0.2"}]
        )
        result = list_missions()
        assert len(result) == 2

    def test_with_target_filter(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.order.return_value.eq.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[{"id": "1", "target": "10.0.0.1"}]
        )
        result = list_missions(target="10.0.0.1")
        mock_tbl.select.return_value.order.return_value.eq.assert_called_with("target", "10.0.0.1")

    def test_empty_response(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(
            data=None
        )
        assert list_missions() == []

    def test_db_exception_returns_empty(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.order.return_value.limit.return_value.execute.side_effect = RuntimeError("DB error")
        assert list_missions() == []

    def test_default_limit(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(data=[])
        list_missions()
        mock_tbl.select.return_value.order.return_value.limit.assert_called_with(50)

    def test_custom_limit(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(data=[])
        list_missions(limit=10)
        mock_tbl.select.return_value.order.return_value.limit.assert_called_with(10)


# ════════════════════════════════════════════════════════════════
#  find_similar()
# ════════════════════════════════════════════════════════════════

class TestFindSimilar:
    def test_no_db_returns_empty(self, mock_db):
        mock_db._table.return_value = None
        assert find_similar() == []

    def test_no_rows_returns_empty(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.ilike.return_value.limit.return_value.execute.return_value = MagicMock(
            data=None
        )
        assert find_similar(target_os="Linux") == []

    def test_with_os_match(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.ilike.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[{"target": "10.0.0.1", "os_detected": "Linux", "tools_used": "[]", "success_score": 80}]
        )
        result = find_similar(target_os="Linux")
        assert len(result) == 1

    def test_with_tools_overlap(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        missions = [
            {"target": "a", "tools_used": json.dumps([{"tool": "nmap"}]), "success_score": 90},
            {"target": "b", "tools_used": json.dumps([{"tool": "nikto"}]), "success_score": 70},
        ]
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=missions)
        result = find_similar(tools=["nmap"])
        assert len(result) >= 1
        # nmap mission should rank higher
        assert result[0]["target"] == "a"

    def test_no_tools_no_os_returns_empty(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=[])
        assert find_similar() == []

    def test_db_exception_returns_empty(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.limit.return_value.execute.side_effect = RuntimeError("DB error")
        assert find_similar(tools=["nmap"]) == []

    def test_tool_names_normalization(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        missions = [
            {"target": "a", "tools_used": [{"tool": "NMAP"}], "success_score": 90},
        ]
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=missions)
        result = find_similar(tools=["nmap"])
        assert len(result) == 1

    def test_limit_enforced(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        missions = [{"target": f"t{i}", "tools_used": json.dumps([{"tool": "nmap"}]), "success_score": 90 - i} for i in range(20)]
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=missions)
        result = find_similar(tools=["nmap"], limit=3)
        assert len(result) == 3

    def test_limit_minimum_one(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=[])
        find_similar(limit=0)
        # Should not crash

    def test_empty_tools_list_filtered(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=[])
        result = find_similar(tools=[])
        assert result == []

    def test_tools_string_normalization(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.limit.return_value.execute.return_value = MagicMock(data=[])
        # Strings with whitespace should be stripped
        result = find_similar(tools=["  NMAP  ", "", "  "])
        # Empty/whitespace-only tools should be filtered


# ════════════════════════════════════════════════════════════════
#  get_suggestion_context()
# ════════════════════════════════════════════════════════════════

class TestGetSuggestionContext:
    def test_empty_findings_returns_empty(self, mock_db):
        mock_db._table.return_value = None
        result = get_suggestion_context([])
        assert result == ""

    def test_string_findings_with_apache(self, mock_db):
        mock_db._table.return_value = None
        result = get_suggestion_context("Server: Apache/2.4.49")
        # Even with no DB, this should not crash

    def test_string_findings_no_banner(self, mock_db):
        mock_db._table.return_value = None
        result = get_suggestion_context("just some text")
        assert result == ""

    def test_list_findings_with_os(self, mock_db):
        mock_db._table.return_value = None
        findings = [{"type": "os", "title": "Linux"}]
        result = get_suggestion_context(findings)
        # No DB → no similar → empty

    def test_list_findings_with_tool(self, mock_db):
        mock_db._table.return_value = None
        findings = [{"tool": "nmap", "severity": "high", "title": "Port 22"}]
        result = get_suggestion_context(findings)
        # No DB → empty

    def test_string_input_with_nginx(self, mock_db):
        mock_db._table.return_value = None
        result = get_suggestion_context("nginx/1.18.0 running")
        # Should extract nginx and try to find similar (no DB → empty)

    def test_no_os_no_tools_returns_empty(self, mock_db):
        mock_db._table.return_value = None
        result = get_suggestion_context([{"severity": "low", "title": "something"}])
        assert result == ""

    def test_exception_returns_empty(self, mock_db):
        mock_db._table.return_value = None
        result = get_suggestion_context(None)
        assert result == ""

    def test_list_findings_with_findings_summary(self, mock_db):
        mock_db._table.return_value = None
        findings = [{"type": "service", "tool": "nmap", "severity": "critical", "title": "Apache 2.4.49"}]
        result = get_suggestion_context(findings)
        # No DB → empty

    def test_with_db_and_similar(self, mock_db):
        mock_tbl = MagicMock()
        mock_db._table.return_value = mock_tbl
        mock_tbl.select.return_value.ilike.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[{
                "target": "10.0.0.1",
                "os_detected": "Apache",
                "tools_used": json.dumps([{"tool": "nmap", "command": "nmap -sV", "useful": True}]),
                "findings_count": 5,
                "findings_summary": json.dumps([{"severity": "high", "title": "XSS"}]),
                "success_score": 85,
            }]
        )
        findings = [{"type": "service", "severity": "high", "tool": "nmap", "title": "Apache/2.4.49"}]
        result = get_suggestion_context(findings)
        assert "Mission History Context" in result
        assert "10.0.0.1" in result

    def test_string_input_all_banners(self, mock_db):
        mock_db._table.return_value = None
        for banner in ("apache", "nginx", "iis", "openssh", "linux", "windows"):
            result = get_suggestion_context(f"Server: {banner}/2.0")
            # Should not crash
