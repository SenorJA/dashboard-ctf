"""
Coverage-gap tests for backend/finding_poc.py — edge branches.

Covers:
  - sanitize_payload(): None, non-str
  - validate_url(): urlsplit exception
  - _truncate(): non-str input
  - _build_curl_command(): verify_tls=False → -k
  - _build_raw_request(): oversized request truncation
  - finding_to_poc(): non-dict data
  - replay_poc(): bad shlex command, unparseable status line,
    unexpected exception
  - parse_curl_to_poc(): malformed quoting fallback, empty tokens,
    bare "curl", -A/--user-agent, unknown flag with value
  - finding_to_markdown_report(): data fallback notes
  - validate_poc(): None, non-dict headers, bad header entry,
    non-str body
  - poc_from_burp_request(): non-dict/list headers, non-str body,
    invalid response_status
"""

from unittest.mock import MagicMock, patch

import pytest

from backend.finding_poc import (
    MAX_RAW_REQUEST_SIZE,
    FindingPoC,
    _build_curl_command,
    _build_raw_request,
    _truncate,
    build_poc,
    finding_to_markdown_report,
    finding_to_poc,
    parse_curl_to_poc,
    poc_from_burp_request,
    replay_poc,
    sanitize_payload,
    validate_poc,
    validate_url,
)


class TestSanitizePayloadGaps:
    def test_none_returns_empty(self):
        assert sanitize_payload(None) == ""

    def test_non_str_coerced(self):
        assert sanitize_payload(123) == "123"


class TestValidateUrlGaps:
    def test_urlsplit_exception(self):
        with patch("backend.finding_poc.urlsplit", side_effect=ValueError("bad")):
            assert validate_url("http://x") is False

    def test_empty_returns_false(self):
        assert validate_url("") is False
        assert validate_url(None) is False


class TestTruncateGaps:
    def test_non_str_coerced(self):
        assert _truncate(12345, 100) == "12345"

    def test_none_returns_none(self):
        assert _truncate(None, 100) is None


class TestBuildCurlCommandGaps:
    def test_verify_tls_false_adds_k(self):
        cmd = _build_curl_command("GET", "https://example.com/", {}, None, verify_tls=False)
        assert "-k" in cmd


class TestBuildRawRequestGaps:
    def test_oversized_body_truncated(self):
        body = "x" * (MAX_RAW_REQUEST_SIZE + 1000)
        request = _build_raw_request("POST", "https://example.com/upload", {}, body)
        assert len(request) == MAX_RAW_REQUEST_SIZE

    def test_host_and_content_length_added(self):
        request = _build_raw_request("POST", "https://example.com/api", {}, '{"a":1}')
        assert "Host: example.com" in request
        assert "Content-Length: 7" in request


class TestFindingToPocGaps:
    def test_non_dict_data_returns_none(self):
        assert finding_to_poc({"data": "not a dict"}) is None

    def test_non_dict_finding_returns_none(self):
        assert finding_to_poc("nope") is None


class TestReplayPocGaps:
    def test_bad_shlex_command(self):
        poc = build_poc("GET", "https://example.com/")
        poc.curl_command = "'unclosed"
        res = replay_poc(poc, timeout=5)
        assert res["ok"] is False
        assert "bad curl_command" in res["error"]

    def test_unparseable_status_line(self):
        poc = build_poc("GET", "https://example.com/")
        fake = MagicMock(returncode=0, stdout="HTTP/1.1  200 OK\r\n\r\nbody\n", stderr="")
        with patch("backend.finding_poc.subprocess.run", return_value=fake):
            res = replay_poc(poc, timeout=5)
        assert res["ok"] is True
        assert res["status_code"] is None

    def test_unexpected_exception(self):
        poc = build_poc("GET", "https://example.com/")
        with patch("backend.finding_poc.subprocess.run", side_effect=RuntimeError("boom")):
            res = replay_poc(poc, timeout=5)
        assert res["ok"] is False
        assert "unexpected" in res["error"]


class TestParseCurlGaps:
    def test_malformed_quoting_fallback(self):
        poc = parse_curl_to_poc("curl -H 'unclosed http://example.com/")
        assert poc.url == "http://example.com/"

    def test_bare_curl_word(self):
        poc = parse_curl_to_poc("curl http://example.com/")
        assert poc.url == "http://example.com/"

    def test_empty_tokens(self):
        poc = parse_curl_to_poc("   ")
        assert poc.method == "GET"

    def test_user_agent_flag(self):
        poc = parse_curl_to_poc("curl -A 'MyAgent/1.0' http://example.com/")
        assert poc.headers.get("User-Agent") == "MyAgent/1.0"

    def test_unknown_flag_with_value(self):
        poc = parse_curl_to_poc("curl --weird value http://example.com/")
        # "--weird" skipped, "value" consumed as URL, then real URL wins
        assert poc.url == "http://example.com/"


class TestFindingToMarkdownGaps:
    def test_data_notes_section(self):
        out = finding_to_markdown_report({"what": "x", "data": {"key": "val"}})
        assert "### Notes" in out
        assert "key" in out

    def test_data_notes_non_serializable(self):
        class _BadStr:
            def __str__(self):
                raise RuntimeError("boom")

        out = finding_to_markdown_report({"what": "x", "data": {"k": _BadStr()}})
        assert "### Notes" in out

    def test_no_data_fallback_text(self):
        out = finding_to_markdown_report({"what": "x", "data": "plain"})
        assert "No reproducible PoC context" in out

    def test_invalid_finding(self):
        out = finding_to_markdown_report("nope")
        assert "invalid finding" in out


class TestValidatePocGaps:
    def test_none(self):
        assert validate_poc(None) == ["poc is None"]

    def test_headers_not_dict(self):
        poc = build_poc("GET", "https://example.com/")
        poc.headers = "bad"
        errors = validate_poc(poc)
        assert any("headers must be a dict" in e for e in errors)

    def test_bad_header_entry(self):
        poc = build_poc("GET", "https://example.com/")
        poc.headers = {"a": {"b": 1}}
        errors = validate_poc(poc)
        assert any("bad header entry" in e for e in errors)

    def test_body_not_str(self):
        poc = build_poc("GET", "https://example.com/")
        poc.body = 123
        errors = validate_poc(poc)
        assert any("body must be str or None" in e for e in errors)


class TestPocFromBurpGaps:
    def test_non_dict_headers_cleared(self):
        poc = poc_from_burp_request({"url": "https://example.com/", "headers": 42})
        assert poc.url == "https://example.com/"
        assert poc.headers == {}

    def test_headers_list_form(self):
        poc = poc_from_burp_request({
            "url": "https://example.com/",
            "headers": ["X-Test: 1", "bad-no-colon"],
        })
        assert poc.headers == {"X-Test": "1"}

    def test_non_str_body_coerced(self):
        poc = poc_from_burp_request({"url": "https://example.com/", "body": 123})
        assert poc.body == "123"

    def test_invalid_response_status(self):
        poc = poc_from_burp_request({"url": "https://example.com/", "response_status": "abc"})
        assert poc.response_status is None

    def test_missing_url_returns_none(self):
        assert poc_from_burp_request({}) is None
