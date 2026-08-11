"""
Coverage-gap tests for browser_capture.py.

Covers _extract_domain failure, sensitive-value default False, HAR timing
variants, decode fallbacks, cookie-flag skip, insecure-redirect guards,
large-response header parse errors, and the analyze_session category
buckets + cookie stats.

NOTE: imports the module as plain `browser_capture` (same name as the
existing test suite) to avoid a second module instance.
"""

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.browser_capture as bc
from backend.browser_capture import (
    CapturedRequest,
    analyze_request,
    analyze_session,
    import_har,
    parse_har,
    reset,
    _check_cookie_flags,
    _check_insecure_redirects,
    _check_large_responses,
    _detect_sensitive_param_value,
    _extract_domain,
    _requests,
    _sessions,
)


@pytest.fixture(autouse=True)
def _clean_store():
    reset()
    yield
    reset()


def _req(**overrides):
    base = dict(
        id="r1",
        session_id="s1",
        method="GET",
        url="https://example.com/x",
        headers={},
        body=None,
        response_status=200,
        response_headers=None,
        response_body=None,
        timing=None,
        cookies=[],
        query_params=[],
        ip=None,
        protocol=None,
        mime_type=None,
        redirect_url=None,
        captured_at="2025-01-01T00:00:00Z",
    )
    base.update(overrides)
    return CapturedRequest(**base)


class TestExtractDomain:
    def test_invalid_url_returns_empty(self):
        # Malformed IPv6 bracket raises ValueError in urlparse -> caught -> "".
        assert _extract_domain("http://[::1") == ""

    def test_valid(self):
        assert _extract_domain("https://example.com/x") == "example.com"


class TestDetectSensitiveValue:
    def test_plain_value_false(self):
        assert _detect_sensitive_param_value("hello-world!") is False

    def test_short_value_false(self):
        assert _detect_sensitive_param_value("abc") is False


class TestParseHarTiming:
    def test_time_and_timings(self):
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "time": 123,
                        "timings": {"blocked": 1, "dns": 2},
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/",
                            "headers": [],
                            "queryString": [],
                            "cookies": [],
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [],
                            "content": {"text": ""},
                            "mimeType": "text/html",
                        },
                    }
                ],
            }
        }
        reqs = parse_har(har, session_id="s1")
        assert len(reqs) == 1
        # detailed timings dict wins
        assert reqs[0].timing == {"blocked": 1, "dns": 2}

    def test_time_only(self):
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "time": 55,
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/",
                            "headers": [],
                            "queryString": [],
                            "cookies": [],
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": ""},
                        },
                    }
                ],
            }
        }
        reqs = parse_har(har, session_id="s1")
        assert reqs[0].timing == {"total": 55}


class TestImportHarDecode:
    def test_latin1_fallback(self):
        # 'é' is invalid UTF-8 when encoded latin-1, but decodes cleanly
        # to a valid JSON document via latin-1.
        doc = '{"log": {"version": "1.2", "entries": []}, "creator": {"name": "caf\u00e9"}}'
        payload = doc.encode("latin-1")
        out = import_har(payload, "sample.har")
        assert out["ok"] is True

    def test_both_decodes_fail(self):
        class FlakyBytes:
            def __init__(self):
                self.n = 0

            def decode(self, encoding="utf-8", errors="strict"):
                self.n += 1
                if self.n <= 2:
                    raise UnicodeDecodeError(encoding, b"", 0, 1, "boom")
                return "{}"

        out = import_har(FlakyBytes(), "sample.har")
        assert out["ok"] is False
        assert "Failed to decode" in out["error"]


class TestCookieFlags:
    def test_cookie_without_name_skipped(self):
        req = _req(cookies=[{"value": "x"}], url="http://example.com/")
        assert _check_cookie_flags(req) == []

    def test_session_cookie_http(self):
        req = _req(cookies=[{"name": "sessionid", "value": "x"}], url="http://example.com/")
        issues = _check_cookie_flags(req)
        cats = {i["category"] for i in issues}
        assert "cookie_flags" in cats


class TestInsecureRedirects:
    def test_no_response_status(self):
        req = _req(response_status=None, redirect_url="http://insecure.example")
        assert _check_insecure_redirects(req) == []

    def test_no_redirect_url(self):
        req = _req(response_status=302, redirect_url=None)
        assert _check_insecure_redirects(req) == []

    def test_http_redirect(self):
        req = _req(response_status=302, redirect_url="http://insecure.example")
        issues = _check_insecure_redirects(req)
        assert any(i["check_id"] == "insecure-redirect-http" for i in issues)


class TestLargeResponses:
    def test_non_numeric_content_length(self):
        req = _req(response_headers={"Content-Length": "chunky"}, response_body="x")
        # No exception, and no large-response issue for a tiny body.
        assert _check_large_responses(req) == []


class TestAnalyzeSessionBuckets:
    def test_all_categories_and_cookie_stats(self):
        session_id = "sess-buckets"
        reqs = [
            _req(
                id=f"r{i}",
                url=url,
                cookies=cookies,
                response_headers={"Content-Type": "text/html"},
            )
            for i, (url, cookies) in enumerate(
                [
                    ("http://example.com/", [{"name": "sessionid"}, {"name": "other"}]),
                    ("https://example.com/", []),
                    ("https://example.com/", []),
                    ("https://example.com/", []),
                    ("https://example.com/", []),
                    ("https://example.com/", []),
                    ("https://example.com/", []),
                    ("https://example.com/", []),
                ]
            )
        ]
        bc._sessions[session_id] = bc.BrowserSession(
            id=session_id, name="t", target="example.com",
            created_at="x", request_count=8, har_version="1.2",
            har_creator=None, analysis=None, tags=[],
        )
        bc._requests[session_id] = reqs

        categories = [
            "mixed_content", "sensitive_urls", "insecure_redirects",
            "missing_auth", "cors", "info_leakage", "large_responses", "websocket",
        ]

        def fake_analyze(req):
            # One issue per category, cycling across requests.
            cat = categories[reqs.index(req) % len(categories)]
            return [{
                "check_id": f"check-{cat}",
                "severity": "low",
                "category": cat,
                "title": cat,
                "detail": cat,
                "url": req.url,
                "recommendation": "fix",
            }]

        with patch.object(bc, "analyze_request", side_effect=fake_analyze):
            analysis = analyze_session(session_id)

        assert analysis is not None
        assert len(analysis.mixed_content) + len(analysis.sensitive_in_urls) + \
            len(analysis.insecure_redirects) + len(analysis.missing_auth) + \
            len(analysis.cors_issues) + len(analysis.info_leakage) + \
            len(analysis.large_responses) + len(analysis.websocket_issues) == 8
        assert len(analysis.insecure_redirects) == 1
        assert len(analysis.cors_issues) == 1
        assert len(analysis.info_leakage) == 1
        assert len(analysis.large_responses) == 1
        assert len(analysis.websocket_issues) == 1
        assert analysis.cookies_analysis["total_cookies"] == 2
        assert analysis.cookies_analysis["session_cookies"] == 1
        assert analysis.cookies_analysis["http_cookies"] == 2
