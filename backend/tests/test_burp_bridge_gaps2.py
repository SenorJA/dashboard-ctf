"""
Coverage-gap tests for backend/burp_bridge.py.

Covers edge branches in header/body param normalization, negative limit
handling, finding conversion and the best-effort curl parser.
"""

from unittest.mock import patch

import pytest

import backend.burp_bridge as bb
from backend.burp_bridge import (
    clear_all,
    ingest_request,
    list_requests,
    list_endpoints,
    list_tasks,
    list_issues,
    finding_to_burp_issue,
    _curl_to_raw,
    _extract_body_params,
    _normalize_headers,
)


@pytest.fixture(autouse=True)
def clean():
    clear_all()
    yield
    clear_all()


class TestNormalizeHeaders:
    def test_list_line_without_colon_skipped(self):
        out = _normalize_headers(["Host: example.com", "no-colon-here"])
        assert out == {"Host": "example.com"}


class TestExtractBodyParams:
    def test_parse_failure_returns_empty(self):
        with patch("backend.burp_bridge.parse_qsl", side_effect=ValueError("bad")):
            assert _extract_body_params("a=1&b=2", "application/x-www-form-urlencoded") == []


class TestListLimits:
    def test_list_requests_negative_offset_and_limit(self):
        ingest_request("GET", "http://x/a")
        rows = list_requests(offset=-5, limit=-5)
        assert rows == []

    def test_list_endpoints_negative_limit(self):
        ingest_request("GET", "http://x/a")
        assert list_endpoints(limit=-1) == []

    def test_list_tasks_negative_limit(self):
        ingest_request("GET", "http://x/a")
        bb.queue_task(list_requests()[0]["id"])
        assert list_tasks(limit=-1) == []

    def test_list_issues_negative_limit(self):
        bb.add_issue("t", "high", "http://x", "GET", "raw")
        assert list_issues(limit=-1) == []


class TestFindingToBurpIssue:
    def test_request_raw_branch(self):
        res = finding_to_burp_issue({
            "what": "XSS", "severity": "high", "target": "http://x",
            "method": "GET", "id": "f1",
            "data": {"request_raw": "GET / HTTP/1.1"},
        })
        assert res["ok"] is True
        assert res["issue"]["request_raw"] == "GET / HTTP/1.1"
        assert res["issue"]["finding_id"] == "f1"

    def test_request_branch(self):
        res = finding_to_burp_issue({
            "title": "X", "target": "http://x", "method": "GET",
            "data": {"request": "GET /y HTTP/1.1"},
        })
        assert res["issue"]["request_raw"] == "GET /y HTTP/1.1"


class TestCurlToRaw:
    def test_not_curl_command(self):
        assert _curl_to_raw("wget http://x") == ""

    def test_data_promotes_post(self):
        raw = _curl_to_raw('curl -X GET -d a=1 http://example.com')
        assert raw.startswith("POST /")

    def test_no_url_returns_empty(self):
        assert _curl_to_raw("curl -X POST") == ""

    def test_query_string_preserved(self):
        raw = _curl_to_raw("curl http://example.com/p?a=1")
        assert "GET /p?a=1 HTTP/1.1" in raw
        assert "Host: example.com" in raw

    def test_no_body_terminator(self):
        raw = _curl_to_raw("curl http://example.com")
        assert raw.endswith("\r\n\r\n")

    def test_shlex_failure_returns_empty(self):
        assert _curl_to_raw("curl 'unterminated") == ""
