"""Tests for backend/mcp_server.py — browser capture MCP tools.

Covers the 7 `vulnforge_browser_*` tools that wrap the in-memory
browser_capture HAR store.  Uses the real browser_capture module
(no mocks) and resets its store between tests.
"""
import asyncio
import json
from unittest.mock import patch

import pytest

import backend.mcp_server as mcp
from backend import browser_capture


def _minimal_har() -> dict:
    """A valid HAR 1.2 dict: 1 HTML entry over plain HTTP.

    The HTML-over-HTTP entry triggers missing-CSP (high), missing
    X-Frame-Options (medium) and missing X-Content-Type-Options (low)
    so analysis always produces at least one finding.
    """
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "pytest", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 10,
                    "request": {
                        "method": "GET",
                        "url": "http://example.com/",
                        "headers": [{"name": "Host", "value": "example.com"}],
                        "cookies": [],
                        "queryString": [],
                        "postData": None,
                        "httpVersion": "HTTP/1.1",
                        "clientIPAddress": "192.168.1.10",
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "content": {
                            "mimeType": "text/html",
                            "text": "<html><body>hello</body></html>",
                        },
                    },
                },
            ],
        }
    }


def _har_json() -> str:
    return json.dumps(_minimal_har())


def _zero_issue_har() -> dict:
    """An HTTPS JSON API entry with auth header — triggers no checks.

    No cookies, no query params, non-HTML content type, small body,
    no CORS headers, no sensitive headers → zero security issues.
    """
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "pytest", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 5,
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/health",
                        "headers": [{"name": "Authorization", "value": "Bearer xyz"}],
                        "cookies": [],
                        "queryString": [],
                        "postData": None,
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": "{}"},
                    },
                },
            ],
        }
    }


def _har_with_websocket() -> dict:
    """A HAR containing a ws:// entry (triggers the websocket category)."""
    har = _minimal_har()
    har["log"]["entries"].append({
        "startedDateTime": "2026-01-01T00:00:01Z",
        "time": 2,
        "request": {
            "method": "GET",
            "url": "ws://example.com/socket",
            "headers": [],
            "cookies": [],
            "queryString": [],
            "postData": None,
        },
        "response": {
            "status": 101,
            "headers": [],
            "content": {"mimeType": "", "text": ""},
        },
    })
    return har


def _import_session_id(content: str = None) -> str:
    """Import a HAR through the MCP tool and return the new session id."""
    text = asyncio.run(mcp._tool_browser_import(
        {"har_content": content or _har_json()}
    ))
    return text.split("session_id:")[1].strip().splitlines()[0].strip()


@pytest.fixture(autouse=True)
def _clean_browser_state():
    """Reset the findings store and the browser_capture store between tests."""
    mcp._session_findings = []
    browser_capture.reset()
    yield
    mcp._session_findings = []
    browser_capture.reset()


# ════════════════════════════════════════════════════════════════
#  TOOL DEFINITIONS
# ════════════════════════════════════════════════════════════════

def test_tools_list_contains_browser_tools():
    names = [t["name"] for t in mcp.TOOLS]
    for name in (
        "vulnforge_browser_import",
        "vulnforge_browser_list_sessions",
        "vulnforge_browser_get_session",
        "vulnforge_browser_analyze",
        "vulnforge_browser_get_analysis",
        "vulnforge_browser_create_findings",
        "vulnforge_browser_stats",
    ):
        assert name in names


def test_browser_tool_schemas_are_valid():
    browser_tools = [t for t in mcp.TOOLS if t["name"].startswith("vulnforge_browser_")]
    assert len(browser_tools) == 7
    for tool in browser_tools:
        assert tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert isinstance(schema["properties"], dict)


def test_browser_import_schema_requires_har_content():
    tool = next(t for t in mcp.TOOLS if t["name"] == "vulnforge_browser_import")
    assert "har_content" in tool["inputSchema"]["required"]
    assert tool["inputSchema"]["properties"]["filename"]["default"] == "har_capture.har"


# ════════════════════════════════════════════════════════════════
#  _tool_browser_import
# ════════════════════════════════════════════════════════════════

def test_tool_browser_import_valid_har():
    text = asyncio.run(mcp._tool_browser_import({"har_content": _har_json()}))
    assert "session_id:" in text
    assert "target:" in text and "example.com" in text
    assert "requests:" in text and "1" in text
    assert "har_version:" in text and "1.2" in text
    assert browser_capture.status()["sessions"] == 1


def test_tool_browser_import_custom_filename():
    text = asyncio.run(mcp._tool_browser_import(
        {"har_content": _har_json(), "filename": "mycapture.har"}
    ))
    assert "session_id:" in text
    session_id = text.split("session_id:")[1].strip().splitlines()[0].strip()
    session = browser_capture.get_session(session_id)
    assert session["name"] == "mycapture"


def test_tool_browser_import_invalid_json_returns_error():
    text = asyncio.run(mcp._tool_browser_import({"har_content": "not json!!!"}))
    assert "Invalid" in text or "error" in text.lower()
    assert browser_capture.status()["sessions"] == 0


def test_tool_browser_import_unsupported_version():
    har = _minimal_har()
    har["log"]["version"] = "2.0"
    text = asyncio.run(mcp._tool_browser_import({"har_content": json.dumps(har)}))
    assert "version" in text.lower()
    assert browser_capture.status()["sessions"] == 0


def test_tool_browser_import_handles_exception():
    with patch("backend.browser_capture.import_har", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_import({"har_content": _har_json()}))
    assert "boom" in text


# ════════════════════════════════════════════════════════════════
#  _tool_browser_list_sessions
# ════════════════════════════════════════════════════════════════

def test_tool_browser_list_sessions_after_import():
    _import_session_id()
    text = asyncio.run(mcp._tool_browser_list_sessions({"limit": 50, "offset": 0}))
    assert "Browser sessions" in text
    assert "example.com" in text
    assert "not analyzed" in text


def test_tool_browser_list_sessions_empty():
    text = asyncio.run(mcp._tool_browser_list_sessions({}))
    assert text == "(no sessions)"


def test_tool_browser_list_sessions_handles_exception():
    with patch("backend.browser_capture.list_sessions", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_list_sessions({}))
    assert "boom" in text


# ════════════════════════════════════════════════════════════════
#  _tool_browser_get_session
# ════════════════════════════════════════════════════════════════

def test_tool_browser_get_session_found():
    session_id = _import_session_id()
    text = asyncio.run(mcp._tool_browser_get_session({"session_id": session_id}))
    assert "target:" in text and "example.com" in text
    assert "request_count:" in text and "1" in text
    assert "not analyzed" in text


def test_tool_browser_get_session_not_found():
    text = asyncio.run(mcp._tool_browser_get_session({"session_id": "nope"}))
    assert "not found" in text


def test_tool_browser_get_session_handles_exception():
    with patch("backend.browser_capture.get_session", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_get_session({"session_id": "x"}))
    assert "boom" in text


# ════════════════════════════════════════════════════════════════
#  _tool_browser_analyze
# ════════════════════════════════════════════════════════════════

def test_tool_browser_analyze_populates_findings():
    session_id = _import_session_id()
    text = asyncio.run(mcp._tool_browser_analyze({"session_id": session_id}))
    assert "risk_score" in text
    assert "issues:" in text
    assert len(mcp._session_findings) >= 1
    assert all(f["tool"] == "browser-capture" for f in mcp._session_findings)


def test_tool_browser_analyze_not_found():
    text = asyncio.run(mcp._tool_browser_analyze({"session_id": "nope"}))
    assert "not found" in text
    assert mcp._session_findings == []


def test_tool_browser_analyze_handles_exception():
    with patch("backend.browser_capture.analyze_session", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_analyze({"session_id": "x"}))
    assert "boom" in text


# ════════════════════════════════════════════════════════════════
#  _tool_browser_get_analysis
# ════════════════════════════════════════════════════════════════

def test_tool_browser_get_analysis_full():
    session_id = _import_session_id()
    asyncio.run(mcp._tool_browser_analyze({"session_id": session_id}))
    text = asyncio.run(mcp._tool_browser_get_analysis({"session_id": session_id}))
    assert "risk_score" in text
    assert "Security issues" in text or "issues" in text.lower()
    assert "check_id:" in text
    assert "recommendation" in text or "fix:" in text


def test_tool_browser_get_analysis_includes_categories():
    session_id = _import_session_id(json.dumps(_har_with_websocket()))
    asyncio.run(mcp._tool_browser_analyze({"session_id": session_id}))
    text = asyncio.run(mcp._tool_browser_get_analysis({"session_id": session_id}))
    assert "categories:" in text
    assert "websocket=1" in text
    assert "websocket-insecure" in text


def test_tool_browser_get_analysis_no_issues():
    session_id = _import_session_id(json.dumps(_zero_issue_har()))
    asyncio.run(mcp._tool_browser_analyze({"session_id": session_id}))
    text = asyncio.run(mcp._tool_browser_get_analysis({"session_id": session_id}))
    assert "No security issues detected." in text
    assert "risk_score" in text


def test_tool_browser_get_analysis_without_analysis_suggests_analyze():
    session_id = _import_session_id()
    text = asyncio.run(mcp._tool_browser_get_analysis({"session_id": session_id}))
    assert "analyze" in text.lower()


def test_tool_browser_get_analysis_session_not_found():
    text = asyncio.run(mcp._tool_browser_get_analysis({"session_id": "nope"}))
    assert "not found" in text


def test_tool_browser_get_analysis_handles_exception():
    with patch("backend.browser_capture.get_session", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_get_analysis({"session_id": "x"}))
    assert "boom" in text


# ════════════════════════════════════════════════════════════════
#  _tool_browser_create_findings
# ════════════════════════════════════════════════════════════════

def test_tool_browser_create_findings_populates_store():
    session_id = _import_session_id()
    asyncio.run(mcp._tool_browser_analyze({"session_id": session_id}))
    mcp._session_findings = []  # only count findings created by this tool

    text = asyncio.run(mcp._tool_browser_create_findings({"session_id": session_id}))
    assert "Findings created" in text
    assert len(mcp._session_findings) >= 1
    assert all(f["tool"] == "browser-capture" for f in mcp._session_findings)


def test_tool_browser_create_findings_without_analysis():
    session_id = _import_session_id()
    text = asyncio.run(mcp._tool_browser_create_findings({"session_id": session_id}))
    assert "analyze" in text.lower()
    assert mcp._session_findings == []


def test_tool_browser_create_findings_session_not_found():
    text = asyncio.run(mcp._tool_browser_create_findings({"session_id": "nope"}))
    assert "not found" in text


def test_tool_browser_create_findings_handles_exception():
    with patch("backend.browser_capture.get_session", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_create_findings({"session_id": "x"}))
    assert "boom" in text


def test_tool_browser_create_findings_analysis_vanished():
    # Session exists with a stored analysis, but analyze_session drops it
    # (returns None) → "Session not found" message.
    session_id = _import_session_id()
    asyncio.run(mcp._tool_browser_analyze({"session_id": session_id}))
    mcp._session_findings = []  # ignore findings from the analyze step
    with patch("backend.browser_capture.analyze_session", return_value=None):
        text = asyncio.run(mcp._tool_browser_create_findings({"session_id": session_id}))
    assert "not found" in text
    assert mcp._session_findings == []


# ════════════════════════════════════════════════════════════════
#  _tool_browser_stats
# ════════════════════════════════════════════════════════════════

def test_tool_browser_stats():
    _import_session_id()
    text = asyncio.run(mcp._tool_browser_stats({}))
    assert "sessions" in text
    assert "total_requests" in text
    assert "analyses" in text
    assert "max_sessions" in text  # verbose by default


def test_tool_browser_stats_non_verbose():
    text = asyncio.run(mcp._tool_browser_stats({"verbose": False}))
    assert "sessions" in text
    assert "max_sessions" not in text


def test_tool_browser_stats_handles_exception():
    with patch("backend.browser_capture.status", side_effect=RuntimeError("boom")):
        text = asyncio.run(mcp._tool_browser_stats({}))
    assert "boom" in text


# ════════════════════════════════════════════════════════════════
#  handle_tool_call routing
# ════════════════════════════════════════════════════════════════

def test_handle_tool_call_routes_browser_import_and_stats():
    text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_import", {"har_content": _har_json()}
    ))
    assert "session_id:" in text

    text = asyncio.run(mcp.handle_tool_call("vulnforge_browser_stats", {}))
    assert "sessions" in text


def test_handle_tool_call_routes_full_browser_flow():
    import_text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_import", {"har_content": _har_json()}
    ))
    session_id = import_text.split("session_id:")[1].strip().splitlines()[0].strip()

    text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_list_sessions", {}
    ))
    assert "example.com" in text

    text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_get_session", {"session_id": session_id}
    ))
    assert "example.com" in text

    text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_analyze", {"session_id": session_id}
    ))
    assert "risk_score" in text

    text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_get_analysis", {"session_id": session_id}
    ))
    assert "risk_score" in text

    mcp._session_findings = []
    text = asyncio.run(mcp.handle_tool_call(
        "vulnforge_browser_create_findings", {"session_id": session_id}
    ))
    assert "Findings created" in text
    assert any(f["tool"] == "browser-capture" for f in mcp._session_findings)


def test_handle_tool_call_unknown_tool():
    assert asyncio.run(mcp.handle_tool_call("bogus_browser_tool", {})) == \
        "Unknown tool: bogus_browser_tool"
