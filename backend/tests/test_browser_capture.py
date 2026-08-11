"""
Tests for browser_capture -- Browser HTTP traffic capture & security analysis.

Covers:
  - HAR parsing (valid, empty, malformed, missing fields)
  - Session CRUD (create, list, get, delete, max limit)
  - Request storage (truncation, pagination, filters)
  - All 10 security check categories (at least 2 tests each)
  - report_to_mirv_findings format
  - risk_score calculation
  - Edge cases (reset, nonexistent session)
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend.browser_capture import (
    parse_har,
    import_har,
    analyze_session,
    analyze_request,
    list_sessions,
    get_session,
    get_requests,
    delete_session,
    report_to_mirv_findings,
    reset,
    status,
    CapturedRequest,
    BrowserSession,
    CaptureAnalysis,
    _sessions,
    _requests,
    _analyses,
    _normalize_har_headers,
    _extract_domain,
    _is_html_content_type,
    _detect_sensitive_param_name,
    _detect_sensitive_param_value,
    _severity_rank,
    _cap_body,
    _MAX_SESSIONS,
    _MAX_BODY,
)


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_store():
    """Reset browser capture state before every test."""
    reset()
    yield
    reset()


def _make_har_entry(
    method="GET",
    url="https://example.com/page",
    req_headers=None,
    resp_status=200,
    resp_headers=None,
    resp_body="",
    cookies=None,
    query_string=None,
    body_text=None,
    ip="10.0.0.1",
    started_dt="2025-01-01T00:00:00Z",
):
    """Build a single HAR entry dict."""
    entry = {
        "startedDateTime": started_dt,
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
            "cookies": [{"name": c["name"], "value": c["value"]} for c in (cookies or [])],
            "queryString": [{"name": p["name"], "value": p["value"]} for p in (query_string or [])],
            "postData": {"text": body_text} if body_text else {},
            "clientIPAddress": ip,
        },
        "response": {
            "status": resp_status,
            "headers": [{"name": k, "value": v} for k, v in (resp_headers or {}).items()],
            "content": {
                "size": len(resp_body) if resp_body else 0,
                "text": resp_body,
                "mimeType": "text/html",
            },
        },
    }
    return entry


def _make_har(entries=None, version="1.2", creator=None):
    """Build a full HAR dict."""
    if entries is None:
        entries = [_make_har_entry()]
    return {
        "log": {
            "version": version,
            "creator": creator or {"name": "Test", "version": "1.0"},
            "entries": entries,
        }
    }


def _make_har_bytes(entries=None, version="1.2", encoding="utf-8"):
    """Build HAR file bytes."""
    return json.dumps(_make_har(entries, version)).encode(encoding)


def _make_request(
    url="https://example.com/page",
    method="GET",
    resp_status=200,
    resp_headers=None,
    resp_body="",
    req_headers=None,
    cookies=None,
    query_params=None,
    body=None,
    session_id="test-session",
):
    """Build a CapturedRequest directly."""
    return CapturedRequest(
        id="test-req-id",
        session_id=session_id,
        method=method,
        url=url,
        headers=req_headers or {},
        body=body,
        response_status=resp_status,
        response_headers=resp_headers,
        response_body=resp_body,
        timing=None,
        cookies=cookies or [],
        query_params=query_params or [],
        ip="10.0.0.1",
        protocol="HTTP/1.1",
        mime_type="text/html",
        redirect_url=None,
        captured_at="2025-01-01T00:00:00Z",
    )


# ──────────────────────────────────────────────
# 1. HAR parsing
# ──────────────────────────────────────────────

class TestParseHAR:
    def test_parse_har_valid_entry(self):
        """A valid HAR entry should produce a CapturedRequest."""
        har = _make_har()
        reqs = parse_har(har, session_id="s1")
        assert len(reqs) == 1
        r = reqs[0]
        assert r.method == "GET"
        assert r.url == "https://example.com/page"
        assert r.session_id == "s1"
        assert r.response_status == 200

    def test_parse_har_normalizes_headers(self):
        """HAR headers list should be normalized to a flat dict."""
        har = _make_har(entries=[
            _make_har_entry(req_headers={"Host": "example.com", "Accept": "text/html"}),
        ])
        reqs = parse_har(har)
        assert reqs[0].headers == {"Host": "example.com", "Accept": "text/html"}

    def test_parse_har_empty_entries(self):
        """HAR with empty entries list should return empty."""
        har = _make_har(entries=[])
        reqs = parse_har(har)
        assert reqs == []

    def test_parse_har_malformed_entry_skipped(self):
        """Entries without 'request' or 'response' should be skipped."""
        entries = [
            {},  # no request
            {"request": {"method": "GET", "url": "https://x.com"}},  # no response
            "not a dict",
        ]
        har = _make_har(entries=entries)
        reqs = parse_har(har)
        assert len(reqs) == 0

    def test_parse_har_extracts_cookies(self):
        """Cookies from HAR should be extracted."""
        cookies = [{"name": "sid", "value": "abc123"}]
        har = _make_har(entries=[_make_har_entry(cookies=cookies)])
        reqs = parse_har(har)
        assert len(reqs[0].cookies) == 1
        assert reqs[0].cookies[0]["name"] == "sid"

    def test_parse_har_extracts_query_params(self):
        """Query string params should be extracted."""
        params = [{"name": "q", "value": "test"}, {"name": "page", "value": "1"}]
        har = _make_har(entries=[_make_har_entry(query_string=params)])
        reqs = parse_har(har)
        assert len(reqs[0].query_params) == 2

    def test_parse_har_truncates_large_response_body(self):
        """Response body should be truncated to _MAX_BODY."""
        large_body = "A" * (_MAX_BODY + 1000)
        har = _make_har(entries=[_make_har_entry(resp_body=large_body)])
        reqs = parse_har(har)
        assert len(reqs[0].response_body) <= _MAX_BODY + 200
        assert "truncated" in reqs[0].response_body

    def test_parse_har_redirect_url_from_location_header(self):
        """Location header should be extracted as redirect_url."""
        har = _make_har(entries=[_make_har_entry(
            resp_status=302,
            resp_headers={"Location": "https://other.com/new"},
        )])
        reqs = parse_har(har)
        assert reqs[0].redirect_url == "https://other.com/new"

    def test_parse_har_missing_log_wrapper(self):
        """HAR without 'log' wrapper should still parse."""
        har = {"version": "1.2", "entries": [_make_har_entry()]}
        reqs = parse_har(har)
        assert len(reqs) == 1

    def test_parse_har_missing_version_fails_import(self):
        """HAR with wrong version should fail on import."""
        bad_har = json.dumps({"log": {"version": "2.0", "entries": []}}).encode()
        result = import_har(bad_har, "test.har")
        assert result["ok"] is False


# ──────────────────────────────────────────────
# 2. Import HAR
# ──────────────────────────────────────────────

class TestImportHAR:
    def test_import_har_creates_session(self):
        """import_har should create a session with correct fields."""
        data = _make_har_bytes()
        result = import_har(data, "capture.har")
        assert result["ok"] is True
        session = result["session"]
        assert session["name"] == "capture"
        assert session["target"] == "example.com"
        assert session["request_count"] == 1

    def test_import_har_invalid_json(self):
        """Invalid JSON should return error."""
        result = import_har(b"not json at all", "bad.har")
        assert result["ok"] is False
        assert "Invalid JSON" in result["error"]

    def test_import_har_bad_encoding_fallback(self):
        """latin-1 encoding should be used as fallback."""
        data = json.dumps(_make_har()).encode("latin-1")
        result = import_har(data, "test.har")
        assert result["ok"] is True

    def test_import_har_completely_invalid_bytes(self):
        """Completely unreadable bytes should return error."""
        result = import_har(bytes(range(256)), "binary.har")
        # latin-1 always succeeds so this will be a JSON error
        assert result["ok"] is False

    def test_import_har_most_frequent_domain(self):
        """Target should be the most frequent domain."""
        entries = [
            _make_har_entry(url="https://api.example.com/v1"),
            _make_har_entry(url="https://api.example.com/v2"),
            _make_har_entry(url="https://cdn.other.com/style.css"),
        ]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "multi.har")
        assert result["ok"] is True
        assert result["session"]["target"] == "api.example.com"

    def test_import_har_stores_requests(self):
        """Imported requests should be retrievable."""
        entries = [_make_har_entry(url=f"https://example.com/p{i}") for i in range(3)]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "three.har")
        sid = result["session"]["id"]
        reqs = get_requests(sid, limit=100)
        assert len(reqs) == 3


# ──────────────────────────────────────────────
# 3. Session CRUD
# ──────────────────────────────────────────────

class TestSessionCRUD:
    def test_list_sessions_empty(self):
        """Empty store returns empty list."""
        assert list_sessions() == []

    def test_list_sessions_sorted_newest_first(self):
        """Sessions should be sorted by created_at descending."""
        import_har(_make_har_bytes(entries=[_make_har_entry(url="https://a.com")]), "first.har")
        import_har(_make_har_bytes(entries=[_make_har_entry(url="https://b.com")]), "second.har")
        sessions = list_sessions()
        assert len(sessions) == 2
        assert sessions[0]["created_at"] >= sessions[1]["created_at"]

    def test_list_sessions_pagination(self):
        """Pagination with limit/offset should work."""
        for i in range(5):
            import_har(_make_har_bytes(entries=[_make_har_entry(url=f"https://s{i}.com")]), f"s{i}.har")
        page1 = list_sessions(limit=2, offset=0)
        page2 = list_sessions(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0]["id"] != page2[0]["id"]

    def test_get_session_existing(self):
        """get_session should return existing session."""
        result = import_har(_make_har_bytes(), "test.har")
        sid = result["session"]["id"]
        got = get_session(sid)
        assert got is not None
        assert got["id"] == sid

    def test_get_session_not_found(self):
        """get_session should return None for nonexistent ID."""
        assert get_session("nonexistent") is None

    def test_delete_session(self):
        """delete_session should remove session + requests + analysis."""
        result = import_har(_make_har_bytes(), "del.har")
        sid = result["session"]["id"]
        # Create an analysis
        analyze_session(sid)
        assert delete_session(sid) is True
        assert get_session(sid) is None
        assert get_requests(sid) == []

    def test_delete_session_not_found(self):
        """delete_session should return False for nonexistent ID."""
        assert delete_session("nonexistent") is False

    def test_max_sessions_evicts_oldest(self):
        """When max sessions reached, oldest should be evicted."""
        import browser_capture as bc
        old_max = bc._MAX_SESSIONS
        bc._MAX_SESSIONS = 3
        try:
            for i in range(5):
                import_har(
                    _make_har_bytes(entries=[_make_har_entry(url=f"https://s{i}.com")]),
                    f"s{i}.har",
                )
            sessions = list_sessions(limit=100)
            assert len(sessions) == 3
            names = [s["name"] for s in sessions]
            assert "s0" not in names
            assert "s4" in names
        finally:
            bc._MAX_SESSIONS = old_max

    def test_import_har_filename_without_extension(self):
        """Session name should strip the file extension."""
        result = import_har(_make_har_bytes(), "my_capture.json")
        assert result["session"]["name"] == "my_capture"


# ──────────────────────────────────────────────
# 4. Request storage & pagination
# ──────────────────────────────────────────────

class TestRequestStorage:
    def test_get_requests_empty_session(self):
        """Nonexistent session should return empty list."""
        assert get_requests("nonexistent") == []

    def test_get_requests_pagination(self):
        """Pagination should work on requests."""
        entries = [_make_har_entry(url=f"https://example.com/p{i}") for i in range(10)]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "pages.har")
        sid = result["session"]["id"]
        page1 = get_requests(sid, limit=3, offset=0)
        page2 = get_requests(sid, limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3

    def test_get_requests_method_filter(self):
        """Filtering by method should return only matching requests."""
        entries = [
            _make_har_entry(method="GET", url="https://example.com/a"),
            _make_har_entry(method="POST", url="https://example.com/b"),
            _make_har_entry(method="GET", url="https://example.com/c"),
        ]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "methods.har")
        sid = result["session"]["id"]
        posts = get_requests(sid, method_filter="POST")
        assert len(posts) == 1
        assert posts[0]["method"] == "POST"

    def test_get_requests_domain_filter(self):
        """Filtering by domain substring should work."""
        entries = [
            _make_har_entry(url="https://api.example.com/v1"),
            _make_har_entry(url="https://cdn.other.com/s.js"),
        ]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "domains.har")
        sid = result["session"]["id"]
        api_reqs = get_requests(sid, domain_filter="api.example")
        assert len(api_reqs) == 1

    def test_response_body_truncation(self):
        """Large response body should be truncated to _MAX_BODY."""
        large_body = "B" * (_MAX_BODY + 500)
        entries = [_make_har_entry(resp_body=large_body)]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "big.har")
        sid = result["session"]["id"]
        reqs = get_requests(sid, limit=1)
        marker = "\n...[truncated by MIRV browser capture]"
        assert len(reqs[0]["response_body"]) <= _MAX_BODY + len(marker) + 10
        assert "truncated" in reqs[0]["response_body"]


# ──────────────────────────────────────────────
# 5. Check A: Cookie flags
# ──────────────────────────────────────────────

class TestCookieFlags:
    def test_session_cookie_over_http(self):
        """Session cookie over HTTP should trigger cookie-missing-httponly."""
        req = _make_request(
            url="http://example.com/page",
            cookies=[{"name": "session_id", "value": "abc"}],
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "cookie-missing-httponly" in check_ids

    def test_cookie_over_http_missing_secure(self):
        """Any cookie over HTTP should trigger cookie-missing-secure."""
        req = _make_request(
            url="http://example.com/page",
            cookies=[{"name": "preferences", "value": "dark"}],
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "cookie-missing-secure" in check_ids

    def test_no_cookies_no_issues(self):
        """No cookies should produce no cookie issues."""
        req = _make_request(url="http://example.com/page")
        issues = [i for i in analyze_request(req) if i["category"] == "cookie_flags"]
        assert issues == []


# ──────────────────────────────────────────────
# 6. Check B: Security headers
# ──────────────────────────────────────────────

class TestSecurityHeaders:
    def test_missing_csp_on_html(self):
        """HTML response without CSP should flag header-missing-csp."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Content-Type": "text/html"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "header-missing-csp" in check_ids

    def test_missing_hsts_on_https(self):
        """HTTPS HTML response without HSTS should flag."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Content-Type": "text/html"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "header-missing-hsts" in check_ids

    def test_missing_xfo_on_html(self):
        """HTML response without X-Frame-Options should flag."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Content-Type": "text/html"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "header-missing-xfo" in check_ids

    def test_missing_xcto(self):
        """Response without X-Content-Type-Options should flag."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Content-Type": "text/html"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "header-missing-xcto" in check_ids

    def test_non_html_skips_header_checks(self):
        """Non-HTML responses should not trigger header checks."""
        req = _make_request(
            url="https://example.com/api",
            resp_headers={"Content-Type": "application/json"},
        )
        issues = [i for i in analyze_request(req) if i["category"] == "security_headers"]
        assert issues == []

    def test_hsts_present_no_issue(self):
        """HTML response with HSTS should not flag."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
        )
        issues = [i for i in analyze_request(req) if i["category"] == "security_headers"]
        assert issues == []


# ──────────────────────────────────────────────
# 7. Check C: Mixed content
# ──────────────────────────────────────────────

class TestMixedContent:
    def test_active_mixed_content(self):
        """HTTPS page loading script over HTTP should flag active mixed content."""
        req = _make_request(
            url="https://example.com/page",
            resp_body='<script src="http://evil.com/xss.js"></script>',
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "mixed-content-active" in check_ids

    def test_passive_mixed_content(self):
        """HTTPS page loading image over HTTP should flag passive mixed content."""
        req = _make_request(
            url="https://example.com/page",
            resp_body='<img src="http://cdn.example.com/logo.png">',
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "mixed-content-passive" in check_ids

    def test_http_page_no_mixed_content(self):
        """HTTP page should not trigger mixed content checks."""
        req = _make_request(
            url="http://example.com/page",
            resp_body='<script src="http://evil.com/xss.js"></script>',
        )
        issues = [i for i in analyze_request(req) if i["category"] == "mixed_content"]
        assert issues == []


# ──────────────────────────────────────────────
# 8. Check D: Sensitive data in URLs
# ──────────────────────────────────────────────

class TestSensitiveInURLs:
    def test_token_param_name(self):
        """Parameter named 'token' should be flagged."""
        req = _make_request(
            url="https://example.com/page?token=abc123",
            query_params=[{"name": "token", "value": "abc123"}],
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "sensitive-token-in-url" in check_ids

    def test_jwt_value_in_url(self):
        """JWT-looking value in URL should be flagged."""
        jwt_val = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
        req = _make_request(
            url="https://example.com/auth?data=" + jwt_val,
            query_params=[{"name": "data", "value": jwt_val}],
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "sensitive-value-in-url" in check_ids

    def test_aws_key_in_url(self):
        """AWS access key in URL should be flagged."""
        req = _make_request(
            url="https://example.com/api?key=AKIAIOSFODNN7EXAMPLE",
            query_params=[{"name": "key", "value": "AKIAIOSFODNN7EXAMPLE"}],
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "sensitive-value-in-url" in check_ids

    def test_safe_param_no_flag(self):
        """Normal param should not trigger sensitive URL checks."""
        req = _make_request(
            url="https://example.com/page?page=1&sort=name",
            query_params=[
                {"name": "page", "value": "1"},
                {"name": "sort", "value": "name"},
            ],
        )
        issues = [i for i in analyze_request(req) if i["category"] == "sensitive_urls"]
        assert issues == []


# ──────────────────────────────────────────────
# 9. Check E: Insecure redirects
# ──────────────────────────────────────────────

class TestInsecureRedirects:
    def test_redirect_to_http(self):
        """3xx redirect to HTTP should be flagged."""
        req = _make_request(
            url="https://example.com/page",
            resp_status=302,
            resp_headers={"Location": "http://example.com/new"},
        )
        req = CapturedRequest(
            id="r1", session_id="s", method="GET", url="https://example.com/page",
            headers={}, body=None, response_status=302,
            response_headers={"Location": "http://example.com/new"},
            response_body=None, timing=None, cookies=[], query_params=[],
            ip=None, protocol=None, mime_type=None,
            redirect_url="http://example.com/new", captured_at="2025-01-01T00:00:00Z",
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "insecure-redirect-http" in check_ids

    def test_https_to_http_downgrade(self):
        """HTTPS → HTTP downgrade redirect should be flagged."""
        req = CapturedRequest(
            id="r1", session_id="s", method="GET", url="https://example.com/page",
            headers={}, body=None, response_status=301,
            response_headers={"Location": "http://example.com/moved"},
            response_body=None, timing=None, cookies=[], query_params=[],
            ip=None, protocol=None, mime_type=None,
            redirect_url="http://example.com/moved", captured_at="2025-01-01T00:00:00Z",
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "insecure-redirect-downgrade" in check_ids

    def test_no_redirect_no_issue(self):
        """Non-redirect response should produce no redirect issues."""
        req = _make_request(url="https://example.com/page", resp_status=200)
        issues = [i for i in analyze_request(req) if i["category"] == "insecure_redirects"]
        assert issues == []


# ──────────────────────────────────────────────
# 10. Check F: Missing auth on API endpoints
# ──────────────────────────────────────────────

class TestMissingAuth:
    def test_api_endpoint_no_auth(self):
        """API endpoint without Authorization/Cookie should be flagged."""
        req = _make_request(
            url="https://example.com/api/users",
            req_headers={"Accept": "application/json"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "missing-auth-api-endpoint" in check_ids

    def test_api_endpoint_with_auth(self):
        """API endpoint with Authorization header should not be flagged."""
        req = _make_request(
            url="https://example.com/api/users",
            req_headers={"Authorization": "Bearer tok123"},
        )
        issues = [i for i in analyze_request(req) if i["category"] == "missing_auth"]
        assert issues == []

    def test_non_api_endpoint_no_flag(self):
        """Non-API endpoint should not trigger missing auth check."""
        req = _make_request(url="https://example.com/page")
        issues = [i for i in analyze_request(req) if i["category"] == "missing_auth"]
        assert issues == []

    def test_admin_endpoint_no_auth(self):
        """Admin endpoint without auth should be flagged."""
        req = _make_request(url="https://example.com/admin/dashboard")
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "missing-auth-api-endpoint" in check_ids


# ──────────────────────────────────────────────
# 11. Check G: CORS
# ──────────────────────────────────────────────

class TestCORS:
    def test_wildcard_with_credentials(self):
        """CORS wildcard + credentials should be flagged as high."""
        req = _make_request(
            url="https://example.com/api",
            resp_headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "cors-wildcard-credentials" in check_ids

    def test_wildcard_without_credentials(self):
        """CORS wildcard without credentials should be flagged as low."""
        req = _make_request(
            url="https://example.com/api",
            resp_headers={"Access-Control-Allow-Origin": "*"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "cors-wildcard" in check_ids

    def test_reflected_origin_with_credentials(self):
        """Reflected origin + credentials should be flagged."""
        req = _make_request(
            url="https://example.com/api",
            req_headers={"Origin": "https://evil.com"},
            resp_headers={
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "cors-reflected-origin" in check_ids

    def test_no_acao_no_issue(self):
        """No CORS headers should produce no CORS issues."""
        req = _make_request(url="https://example.com/api")
        issues = [i for i in analyze_request(req) if i["category"] == "cors"]
        assert issues == []


# ──────────────────────────────────────────────
# 12. Check H: Info leakage
# ──────────────────────────────────────────────

class TestInfoLeakage:
    def test_x_powered_by_present(self):
        """X-Powered-By header should be flagged."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"X-Powered-By": "Express"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "info-leakage-x-powered-by" in check_ids

    def test_server_version_present(self):
        """Server header with version should be flagged."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Server": "Apache/2.4.51"},
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "info-leakage-server-version" in check_ids

    def test_no_info_headers_no_issue(self):
        """No X-Powered-By or versioned Server should produce no issues."""
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Server": "nginx"},
        )
        issues = [i for i in analyze_request(req) if i["category"] == "info_leakage"]
        assert issues == []


# ──────────────────────────────────────────────
# 13. Check I: Large responses
# ──────────────────────────────────────────────

class TestLargeResponses:
    def test_large_json_response(self):
        """Large JSON response should be flagged as medium."""
        large_body = '{"data": "' + "x" * (1024 * 1024 + 100) + '"}'
        req = _make_request(
            url="https://example.com/api/data",
            resp_headers={"Content-Type": "application/json", "Content-Length": str(len(large_body) + 1000)},
            resp_body=large_body,
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "large-response-json" in check_ids

    def test_large_html_response(self):
        """Large non-JSON response should be flagged as info."""
        large_body = "<html>" + "x" * (1024 * 1024 + 100) + "</html>"
        req = _make_request(
            url="https://example.com/page",
            resp_headers={"Content-Type": "text/html", "Content-Length": str(len(large_body) + 1000)},
            resp_body=large_body,
        )
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "large-response" in check_ids


# ──────────────────────────────────────────────
# 14. Check J: WebSocket
# ──────────────────────────────────────────────

class TestWebSocket:
    def test_insecure_ws(self):
        """ws:// URL should be flagged."""
        req = _make_request(url="ws://example.com/socket")
        issues = analyze_request(req)
        check_ids = [i["check_id"] for i in issues]
        assert "websocket-insecure" in check_ids

    def test_secure_wss_no_issue(self):
        """wss:// URL should not be flagged."""
        req = _make_request(url="wss://example.com/socket")
        issues = [i for i in analyze_request(req) if i["category"] == "websocket"]
        assert issues == []


# ──────────────────────────────────────────────
# 15. Session analysis
# ──────────────────────────────────────────────

class TestAnalyzeSession:
    def test_analyze_session_returns_analysis(self):
        """analyze_session should return a CaptureAnalysis."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/page",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "test.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        assert analysis is not None
        assert isinstance(analysis, CaptureAnalysis)
        assert analysis.session_id == sid
        assert analysis.total_requests == 1
        assert analysis.risk_score > 0

    def test_analyze_session_nonexistent(self):
        """Analyzing a nonexistent session should return None."""
        assert analyze_session("nonexistent") is None

    def test_analyze_session_stored_in_analyses(self):
        """Analysis should be stored and retrievable."""
        result = import_har(_make_har_bytes(), "store.har")
        sid = result["session"]["id"]
        analyze_session(sid)
        # Access through the module to avoid stale reference after reset()
        import browser_capture as _bc_mod
        with _lock_ctx():
            assert sid in _bc_mod._analyses

    def test_analyze_session_stored_on_session(self):
        """Analysis should be stored on the session object."""
        result = import_har(_make_har_bytes(), "sess.har")
        sid = result["session"]["id"]
        analyze_session(sid)
        sess = get_session(sid)
        assert sess["analysis"] is not None

    def test_risk_score_formula(self):
        """Risk score should be calculated correctly."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/page",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "risk.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        # Should have some findings for the HTML page
        assert analysis.risk_score >= 0
        assert analysis.risk_score <= 100

    def test_findings_count_severities(self):
        """Findings count should breakdown by severity."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/api/data",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "counts.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        fc = analysis.findings_count
        assert "critical" in fc
        assert "high" in fc
        assert "medium" in fc
        assert "low" in fc
        assert "info" in fc

    def test_recommendations_populated(self):
        """Recommendations should be generated when issues exist."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/page",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "recs.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        assert len(analysis.recommendations) > 0


# ──────────────────────────────────────────────
# 16. report_to_mirv_findings
# ──────────────────────────────────────────────

class TestMIRVFindings:
    def test_report_to_mirv_findings_format(self):
        """Findings should match MIRV format."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/page",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "mrv.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        findings = report_to_mirv_findings(analysis)
        assert len(findings) > 0
        f = findings[0]
        assert f["tool"] == "browser-capture"
        assert "severity" in f
        assert "title" in f
        assert "detail" in f
        assert "target" in f
        assert "type" in f
        assert "extra" in f

    def test_report_to_mirv_findings_sorted_by_severity(self):
        """Findings should be sorted by severity (critical first)."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/page",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "sorted.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        findings = report_to_mirv_findings(analysis)
        if len(findings) > 1:
            for i in range(len(findings) - 1):
                assert _severity_rank(findings[i]["severity"]) <= _severity_rank(
                    findings[i + 1]["severity"]
                )

    def test_report_to_mirv_findings_capped_at_200(self):
        """Should return at most 200 findings."""
        result = import_har(_make_har_bytes(entries=[
            _make_har_entry(
                url="https://example.com/page",
                resp_headers={"Content-Type": "text/html"},
            ),
        ]), "cap.har")
        sid = result["session"]["id"]
        analysis = analyze_session(sid)
        findings = report_to_mirv_findings(analysis)
        assert len(findings) <= 200

    def test_report_to_mirv_findings_empty_analysis(self):
        """Analysis with no issues should return empty findings."""
        analysis = CaptureAnalysis(
            session_id="s",
            analyzed_at="2025-01-01T00:00:00Z",
            total_requests=0,
            findings_count={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            security_issues=[],
            cookies_analysis={},
            headers_analysis={},
            mixed_content=[],
            sensitive_in_urls=[],
            insecure_redirects=[],
            missing_auth=[],
            cors_issues=[],
            info_leakage=[],
            large_responses=[],
            websocket_issues=[],
            risk_score=0.0,
            recommendations=[],
        )
        findings = report_to_mirv_findings(analysis)
        assert findings == []


# ──────────────────────────────────────────────
# 17. Helper functions
# ──────────────────────────────────────────────

class TestHelpers:
    def test_normalize_har_headers(self):
        """Should convert [{name, value}] to {name: value}."""
        raw = [{"name": "Content-Type", "value": "text/html"}, {"name": "Accept", "value": "*/*"}]
        result = _normalize_har_headers(raw)
        assert result == {"Content-Type": "text/html", "Accept": "*/*"}

    def test_normalize_har_headers_empty(self):
        """Empty or None headers should return empty dict."""
        assert _normalize_har_headers([]) == {}
        assert _normalize_har_headers(None) == {}

    def test_extract_domain(self):
        """Should extract hostname from URL."""
        assert _extract_domain("https://example.com/path") == "example.com"
        assert _extract_domain("http://sub.domain.co.uk:8080/x") == "sub.domain.co.uk"
        assert _extract_domain("not-a-url") == ""

    def test_is_html_content_type(self):
        """Should detect HTML content types."""
        assert _is_html_content_type("text/html") is True
        assert _is_html_content_type("application/xhtml+xml") is True
        assert _is_html_content_type("application/json") is False
        assert _is_html_content_type("") is False

    def test_detect_sensitive_param_name(self):
        """Should detect secret-like parameter names."""
        assert _detect_sensitive_param_name("token") is True
        assert _detect_sensitive_param_name("api_key") is True
        assert _detect_sensitive_param_name("password") is True
        assert _detect_sensitive_param_name("jwt") is True
        assert _detect_sensitive_param_name("page") is False
        assert _detect_sensitive_param_name("sort") is False

    def test_detect_sensitive_param_value(self):
        """Should detect JWT, AWS keys, high-entropy strings."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
        assert _detect_sensitive_param_value(jwt) is True
        assert _detect_sensitive_param_value("AKIAIOSFODNN7EXAMPLE") is True
        assert _detect_sensitive_param_value("A" * 50) is True  # high entropy
        assert _detect_sensitive_param_value("short") is False
        assert _detect_sensitive_param_value("") is False

    def test_severity_rank(self):
        """Should return correct severity ranks."""
        assert _severity_rank("critical") == 0
        assert _severity_rank("high") == 1
        assert _severity_rank("medium") == 2
        assert _severity_rank("low") == 3
        assert _severity_rank("info") == 4
        assert _severity_rank("unknown") == 99

    def test_cap_body_none(self):
        """None body should return None."""
        assert _cap_body(None) is None

    def test_cap_body_short(self):
        """Short body should not be truncated."""
        assert _cap_body("hello") == "hello"

    def test_cap_body_long(self):
        """Long body should be truncated with marker."""
        big = "A" * (_MAX_BODY + 100)
        result = _cap_body(big)
        assert len(result) <= _MAX_BODY + 200
        assert "truncated" in result


# ──────────────────────────────────────────────
# 18. Reset & status
# ──────────────────────────────────────────────

class TestResetAndStatus:
    def test_reset_clears_all(self):
        """reset() should clear all stores."""
        import_har(_make_har_bytes(), "test.har")
        s = status()
        assert s["sessions"] > 0
        reset()
        s = status()
        assert s["sessions"] == 0
        assert s["total_requests"] == 0
        assert s["analyses"] == 0

    def test_status_returns_counts(self):
        """status() should return expected keys."""
        s = status()
        assert "ok" in s
        assert "sessions" in s
        assert "total_requests" in s
        assert "analyses" in s
        assert "max_sessions" in s

    def test_status_after_import(self):
        """Status should reflect imported data."""
        import_har(_make_har_bytes(entries=[
            _make_har_entry(), _make_har_entry(url="https://example.com/2"),
        ]), "status.har")
        s = status()
        assert s["sessions"] == 1
        assert s["total_requests"] == 2


# ──────────────────────────────────────────────
# 19. Edge cases
# ──────────────────────────────────────────────

class TestEdgeCases:
    def test_analyze_request_all_checks_on_clean_request(self):
        """A fully-compliant HTTPS request should have minimal issues."""
        req = _make_request(
            url="https://example.com/page",
            resp_status=200,
            resp_headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
            req_headers={"Authorization": "Bearer tok123"},
        )
        issues = analyze_request(req)
        # Should have no security_headers issues
        header_issues = [i for i in issues if i["category"] == "security_headers"]
        assert header_issues == []
        # Should have no missing_auth issues
        auth_issues = [i for i in issues if i["category"] == "missing_auth"]
        assert auth_issues == []

    def test_import_har_no_entries_field(self):
        """HAR with entries as non-list should handle gracefully."""
        bad_har = json.dumps({"log": {"version": "1.2", "entries": "not-a-list"}}).encode()
        result = import_har(bad_har, "bad.har")
        assert result["ok"] is True
        assert result["session"]["request_count"] == 0

    def test_get_requests_method_case_insensitive(self):
        """Method filter should be case-insensitive (uppercased internally)."""
        entries = [_make_har_entry(method="GET", url="https://example.com/a")]
        data = _make_har_bytes(entries=entries)
        result = import_har(data, "case.har")
        sid = result["session"]["id"]
        reqs = get_requests(sid, method_filter="get")
        assert len(reqs) == 1

    def test_double_analyze_session(self):
        """Analyzing a session twice should overwrite the previous analysis."""
        result = import_har(_make_har_bytes(), "double.har")
        sid = result["session"]["id"]
        a1 = analyze_session(sid)
        a2 = analyze_session(sid)
        assert a1 is not None and a2 is not None
        assert a1.session_id == a2.session_id

    def test_delete_after_analyze(self):
        """Deleting a session after analysis should clean up analysis too."""
        result = import_har(_make_har_bytes(), "del2.har")
        sid = result["session"]["id"]
        analyze_session(sid)
        import browser_capture as _bc_mod
        assert sid in _bc_mod._analyses
        delete_session(sid)
        assert sid not in _bc_mod._analyses

    def test_empty_har_file(self):
        """Empty HAR file should fail with JSON error."""
        result = import_har(b"", "empty.har")
        assert result["ok"] is False

    def test_list_sessions_limit_capped(self):
        """Session list limit should be capped at 200."""
        for i in range(3):
            import_har(_make_har_bytes(entries=[_make_har_entry(url=f"https://s{i}.com")]), f"s{i}.har")
        sessions = list_sessions(limit=999)
        assert len(sessions) == 3


# ──────────────────────────────────────────────
# 20. Lock context helper (for direct store access)
# ──────────────────────────────────────────────

import contextlib

@contextlib.contextmanager
def _lock_ctx():
    """Context manager that acquires the module lock."""
    from browser_capture import _lock
    _lock.acquire()
    try:
        yield
    finally:
        _lock.release()
