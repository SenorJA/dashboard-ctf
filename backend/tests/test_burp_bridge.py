"""
tests/test_burp_bridge.py — Burp Bridge module + REST endpoints.

Covers:
  * ingest_request (with/without response, URL normalization, body cap,
    LRU eviction, param extraction from query + form body)
  * list_requests filters + pagination
  * get_request single
  * list_endpoints (dedup, hit_count, param collection)
  * queue_task + update_task + list_tasks
  * add_issue + list_issues
  * finding_to_burp_issue conversion (curl/http/fallback)
  * request_to_raw_http output shape
  * export_findings_as_burp batch
  * ingest_snapshot
  * clear_all + status counts + report_to_mirv_findings
  * auth token validation (verify_token)
  * Endpoint smoke tests for all 14 REST endpoints under /api/burp/
"""

from __future__ import annotations

import os
import sys
import threading

import pytest
from fastapi.testclient import TestClient

# Make backend/ importable (matches conftest pattern) so `from main import app`
# resolves.  `main.py` itself inserts the project root into sys.path on import,
# so once it is imported, `backend.burp_bridge` resolves too — and crucially
# resolves to the SAME module instance the FastAPI app's endpoints bind to.
# We must therefore import `backend.burp_bridge` (not the bare `burp_bridge`
# that backend/ on sys.path would expose) so test state and endpoint state
# share the same in-memory dict.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402  (must run first to install project root)
import backend.burp_bridge as bb  # noqa: E402
from backend.burp_bridge import (  # noqa: E402
    CapturedRequest,
    ingest_request,
    ingest_snapshot,
    list_requests,
    get_request,
    list_endpoints,
    queue_task,
    list_tasks,
    update_task,
    add_issue,
    list_issues,
    finding_to_burp_issue,
    request_to_raw_http,
    export_findings_as_burp,
    clear_all,
    status,
    report_to_mirv_findings,
    verify_token,
)


# ────────────────────────────────────────────────────────────────────
#  Fixtures
# ────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_store():
    """Reset every in-memory bridge store before each test."""
    clear_all()
    yield
    clear_all()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


# ────────────────────────────────────────────────────────────────────
#  1. ingest_request
# ────────────────────────────────────────────────────────────────────

class TestIngest:
    def test_ingest_basic_stores_request(self):
        r = ingest_request("GET", "https://example.com/api/v1/users?id=42")
        assert r["ok"] is True
        assert "request" in r
        assert r["request"]["method"] == "GET"
        assert r["request"]["url"] == "https://example.com/api/v1/users?id=42"
        assert r["request"]["path"] == "/api/v1/users"
        assert r["request"]["source"] == "burp"
        assert r["request"]["id"]

    def test_ingest_with_response(self):
        r = ingest_request(
            "POST", "https://example.com/login",
            headers={"Content-Type": "application/json"},
            body='{"user":"admin"}',
            response_status=200,
            response_headers={"Set-Cookie": "sid=abc"},
            response_body='{"ok":true}',
        )
        req = r["request"]
        assert req["response_status"] == 200
        assert req["response_headers"]["Set-Cookie"] == "sid=abc"
        assert req["response_body"] == '{"ok":true}'
        assert req["body"] == '{"user":"admin"}'

    def test_ingest_returns_error_on_missing_url(self):
        r = ingest_request("GET", "")
        assert r["ok"] is False
        assert "url" in r["error"]

    def test_url_normalization_splits_path_and_query(self):
        r = ingest_request("GET", "https://h.test/a/b?q=1&z=2#frag")
        assert r["request"]["path"] == "/a/b"
        assert r["request"]["url"].startswith("https://h.test/a/b?q=1")

    def test_param_extraction_from_query_string(self):
        ingest_request("GET", "https://h.test/x?id=42&name=bob")
        eps = list_endpoints()
        assert eps[0]["params"] == ["id", "name"] or set(eps[0]["params"]) == {"id", "name"}

    def test_param_extraction_from_form_body(self):
        ingest_request(
            "POST", "https://h.test/form",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="user=bob&pass=s3cret",
        )
        eps = list_endpoints()
        assert set(eps[0]["params"]) == {"user", "pass"}

    def test_json_body_params_are_not_extracted(self):
        """JSON body param extraction is explicitly skipped (documented)."""
        ingest_request(
            "POST", "https://h.test/json",
            headers={"Content-Type": "application/json"},
            body='{"username":"bob","password":"x"}',
        )
        eps = list_endpoints()
        assert eps[0]["params"] == []

    def test_body_cap_truncates_over_64kb(self):
        big = "A" * (64 * 1024 + 100)
        r = ingest_request("POST", "https://h.test/big", body=big)
        body = r["request"]["body"]
        assert len(body) <= 64 * 1024 + 200
        assert "truncated" in body

    def test_ingest_accepts_list_headers(self):
        """Burp plugin sends headers as a list of raw header strings."""
        r = ingest_request(
            "GET", "https://h.test/x",
            headers=["Host: h.test", "User-Agent: burp"],
        )
        assert r["request"]["headers"]["Host"] == "h.test"
        assert r["request"]["headers"]["User-Agent"] == "burp"

    def test_ingest_source_custom(self):
        r = ingest_request("GET", "https://h.test/x", source="browser")
        assert r["request"]["source"] == "browser"


# ────────────────────────────────────────────────────────────────────
#  2. LRU eviction at _MAX_ENTRIES
# ────────────────────────────────────────────────────────────────────

class TestLRU:
    def test_lru_eviction_at_max_entries(self, monkeypatch):
        monkeypatch.setattr(bb, "_MAX_ENTRIES", 3)
        for i in range(5):
            ingest_request("GET", "https://h.test/p%d" % i)
        assert status()["requests"] == 3
        # oldest (p0, p1) should be evicted, p2,p3,p4 retained
        paths = {r["path"] for r in list_requests(limit=10)}
        assert "/p0" not in paths
        assert "/p1" not in paths
        assert "/p4" in paths

    def test_max_body_constant_is_64kb(self):
        assert bb._MAX_BODY == 64 * 1024


# ────────────────────────────────────────────────────────────────────
#  3. list_requests filters + pagination
# ────────────────────────────────────────────────────────────────────

class TestListRequests:
    def _seed(self):
        ingest_request("GET", "https://h.test/a")
        ingest_request("POST", "https://h.test/b")
        ingest_request("GET", "https://h.test/c", response_status=200)
        ingest_request("GET", "https://h.test/api/users")

    def test_list_all_returns_newest_first(self):
        self._seed()
        items = list_requests(limit=10)
        assert len(items) == 4
        # newest first → /api/users should be the first
        assert items[0]["path"] == "/api/users"

    def test_filter_by_method(self):
        self._seed()
        posts = list_requests(method="post")
        assert len(posts) == 1
        assert posts[0]["method"] == "POST"

    def test_filter_by_path_substring(self):
        self._seed()
        api_items = list_requests(path_filter="api")
        assert all("api" in r["path"] for r in api_items)
        assert len(api_items) == 1

    def test_filter_by_status(self):
        self._seed()
        r200 = list_requests(status=200)
        assert len(r200) == 1
        assert r200[0]["response_status"] == 200

    def test_pagination_offset_limit(self):
        self._seed()
        page1 = list_requests(limit=2, offset=0)
        page2 = list_requests(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0]["id"] != page2[0]["id"]

    def test_empty_store_returns_empty_list(self):
        assert list_requests() == []


# ────────────────────────────────────────────────────────────────────
#  4. get_request
# ────────────────────────────────────────────────────────────────────

class TestGetRequest:
    def test_get_existing(self):
        r = ingest_request("GET", "https://h.test/x")["request"]
        got = get_request(r["id"])
        assert got is not None
        assert got["id"] == r["id"]

    def test_get_missing_returns_none(self):
        assert get_request("doesnotexist") is None


# ────────────────────────────────────────────────────────────────────
#  5. list_endpoints
# ────────────────────────────────────────────────────────────────────

class TestEndpoints:
    def test_endpoint_dedup_and_hit_count(self):
        for _ in range(3):
            ingest_request("GET", "https://h.test/users?id=1")
        eps = list_endpoints()
        assert len(eps) == 1
        assert eps[0]["hit_count"] == 3
        assert eps[0]["method"] == "GET"
        assert eps[0]["path"] == "/users"

    def test_endpoint_param_collection_merges(self):
        ingest_request("GET", "https://h.test/x?a=1&b=2")
        ingest_request("GET", "https://h.test/x?c=3")
        eps = list_endpoints()
        assert set(eps[0]["params"]) == {"a", "b", "c"}

    def test_endpoint_sorted_by_hit_count_desc(self):
        for _ in range(2):
            ingest_request("GET", "https://h.test/popular")
        ingest_request("GET", "https://h.test/rare")
        eps = list_endpoints()
        assert eps[0]["path"] == "/popular"
        assert eps[0]["hit_count"] >= eps[1]["hit_count"]

    def test_endpoints_empty_returns_empty(self):
        assert list_endpoints() == []


# ────────────────────────────────────────────────────────────────────
#  6. tasks
# ────────────────────────────────────────────────────────────────────

class TestTasks:
    def test_queue_task_for_existing_request(self):
        rid = ingest_request("GET", "https://h.test/x")["request"]["id"]
        t = queue_task(rid)
        assert t["ok"] is True
        assert t["task"]["status"] == "pending"
        assert t["task"]["request_id"] == rid

    def test_queue_task_unknown_request_fails(self):
        t = queue_task("nope")
        assert t["ok"] is False

    def test_update_task_status(self):
        rid = ingest_request("GET", "https://h.test/x")["request"]["id"]
        tid = queue_task(rid)["task"]["id"]
        upd = update_task(tid, "scanning")
        assert upd["ok"] is True
        assert upd["task"]["status"] == "scanning"

    def test_update_task_invalid_status(self):
        rid = ingest_request("GET", "https://h.test/x")["request"]["id"]
        tid = queue_task(rid)["task"]["id"]
        assert update_task(tid, "bogus")["ok"] is False

    def test_update_task_unknown_id(self):
        assert update_task("nope", "done")["ok"] is False

    def test_list_tasks_returns_in_order(self):
        for i in range(3):
            rid = ingest_request("GET", "https://h.test/p%d" % i)["request"]["id"]
            queue_task(rid)
        assert len(list_tasks()) == 3


# ────────────────────────────────────────────────────────────────────
#  7. issues
# ────────────────────────────────────────────────────────────────────

class TestIssues:
    def test_add_issue_basic(self):
        i = add_issue("SQLi", "critical", "https://h.test/x", "GET", "GET /x HTTP/1.1\r\n\r\n")
        assert i["ok"] is True
        assert i["issue"]["severity"] == "critical"
        assert i["issue"]["request_raw"].startswith("GET /x")

    def test_add_issue_invalid_severity_rejected(self):
        i = add_issue("title", "BOGUS", "https://h.test/x", "GET", "")
        assert i["ok"] is False

    def test_list_issues(self):
        add_issue("a", "high", "https://h.test/x", "GET", "")
        add_issue("b", "low", "https://h.test/y", "GET", "")
        assert len(list_issues()) == 2

    def test_list_issues_empty(self):
        assert list_issues() == []


# ────────────────────────────────────────────────────────────────────
#  8. finding_to_burp_issue + request_to_raw_http + export
# ────────────────────────────────────────────────────────────────────

class TestConversions:
    def test_request_to_raw_http_includes_request_line_and_host(self):
        r = ingest_request("GET", "https://h.test/api/x?q=1",
                           headers=["User-Agent: mirv"])["request"]
        cap = CapturedRequest(
            id=r["id"], method=r["method"], url=r["url"], path=r["path"],
            headers=r["headers"], body=r["body"],
            response_status=r["response_status"],
            response_headers=r["response_headers"],
            response_body=r["response_body"],
            source=r["source"], received_at=r["received_at"],
        )
        raw = request_to_raw_http(cap)
        assert raw.startswith("GET /api/x?q=1 HTTP/1.1\r\n")
        assert "Host: h.test" in raw
        assert "User-Agent: mirv" in raw
        assert raw.endswith("\r\n\r\n")

    def test_request_to_raw_http_includes_body(self):
        r = ingest_request("POST", "https://h.test/api",
                           headers=["Host: h.test"], body='{"k":1}')["request"]
        cap = CapturedRequest(
            id=r["id"], method=r["method"], url=r["url"], path=r["path"],
            headers=r["headers"], body=r["body"],
            response_status=r["response_status"],
            response_headers=r["response_headers"],
            response_body=r["response_body"],
            source=r["source"], received_at=r["received_at"],
        )
        raw = request_to_raw_http(cap)
        assert raw.endswith('{"k":1}')

    def test_finding_to_burp_issue_fallback_raw(self):
        finding = {
            "id": "f1",
            "what": "Captured SQLi",
            "severity": "high",
            "target": "https://h.test/users?id=1",
            "method": "GET",
            "data": {},
        }
        res = finding_to_burp_issue(finding)
        assert res["ok"] is True
        issue = res["issue"]
        assert issue["title"] == "Captured SQLi"
        assert issue["severity"] == "high"
        assert issue["url"] == "https://h.test/users?id=1"
        # fallback raw built from target
        assert issue["request_raw"].startswith("GET /users?id=1 HTTP/1.1")
        assert issue["finding_id"] == "f1"

    def test_finding_to_burp_issue_uses_http_data(self):
        finding = {
            "what": "xss",
            "severity": "medium",
            "target": "https://h.test/x",
            "method": "POST",
            "data": {"http": "POST /x HTTP/1.1\r\nHost: h.test\r\n\r\n<body>"},
        }
        res = finding_to_burp_issue(finding)
        assert res["issue"]["request_raw"] == "POST /x HTTP/1.1\r\nHost: h.test\r\n\r\n<body>"

    def test_finding_to_burp_issue_parses_curl(self):
        finding = {
            "what": "ssrf",
            "severity": "critical",
            "target": "https://h.test/x",
            "method": "GET",
            "data": {"curl": "curl -X POST -H 'Content-Type: application/json' -d '{\"a\":1}' https://h.test/x"},
        }
        res = finding_to_burp_issue(finding)
        raw = res["issue"]["request_raw"]
        assert raw.startswith("POST /x HTTP/1.1")
        assert "Host: h.test" in raw
        assert "Content-Type: application/json" in raw
        assert '{"a":1}' in raw

    def test_finding_to_burp_issue_normalizes_severity_aliases(self):
        for input_sev, expected in [("Informational", "info"), ("WARNING", "medium"), ("bogus", "info")]:
            clear_all()
            res = finding_to_burp_issue({"what": "x", "severity": input_sev, "target": "https://h.test/x"})
            assert res["issue"]["severity"] == expected

    def test_finding_to_burp_issue_invalid_input(self):
        assert finding_to_burp_issue("not a dict")["ok"] is False

    def test_export_findings_as_burp_batch(self):
        findings = [
            {"what": "f-a", "severity": "high", "target": "https://h.test/a", "method": "GET"},
            {"what": "f-b", "severity": "low", "target": "https://h.test/b", "method": "GET"},
        ]
        res = export_findings_as_burp(findings)
        assert res["ok"] is True
        assert len(res["issues"]) == 2

    def test_export_findings_non_list_rejected(self):
        assert export_findings_as_burp("nope")["ok"] is False

    def test_export_findings_with_invalid_entry_skips(self):
        res = export_findings_as_burp([{"what": "x", "target": "https://h.test/x"}, "broken"])
        assert res["ok"] is True
        assert len(res["issues"]) == 1


# ────────────────────────────────────────────────────────────────────
#  9. ingest_snapshot + report_to_mirv_findings + clear + status
# ────────────────────────────────────────────────────────────────────

class TestMisc:
    def test_ingest_snapshot_stores(self):
        r = ingest_snapshot("https://h.test/x",
                            cookies=[{"name": "sid", "value": "v"}],
                            local_storage={"token": "abc"},
                            session_storage={"x": "y"})
        assert r["ok"] is True
        assert r["id"]

    def test_ingest_snapshot_caps_at_100(self, monkeypatch):
        monkeypatch.setattr(bb, "_MAX_SNAPSHOTS", 2)
        ingest_snapshot("u1")
        ingest_snapshot("u2")
        ingest_snapshot("u3")
        assert status()["snapshots"] == 2

    def test_report_to_mirv_findings_format(self):
        rid = ingest_request("GET", "https://h.test/x")["request"]["id"]
        cap = bb._requests[rid]
        findings = report_to_mirv_findings(cap)
        assert isinstance(findings, list)
        assert findings[0]["what"] == "captured-request"
        assert findings[0]["severity"] == "info"
        assert findings[0]["target"] == "https://h.test/x"

    def test_clear_all_empties_stores(self):
        ingest_request("GET", "https://h.test/x")
        queue_task("x")  # invalid → no task added
        add_issue("t", "info", "https://h.test", "GET", "")
        r = clear_all()
        assert r["ok"] is True
        s = status()
        assert s["requests"] == 0
        assert s["endpoints"] == 0
        assert s["tasks"] == 0
        assert s["issues"] == 0

    def test_status_counts_after_seed(self):
        ingest_request("GET", "https://h.test/a")
        ingest_request("GET", "https://h.test/b")
        s = status()
        assert s["requests"] == 2
        assert s["endpoints"] == 2
        assert s["max_entries"] == 5000
        assert s["ok"] is True


# ────────────────────────────────────────────────────────────────────
#  10. auth token
# ────────────────────────────────────────────────────────────────────

class TestAuthToken:
    def test_open_bridge_when_no_token(self, monkeypatch):
        monkeypatch.setenv("MIRV_BURP_TOKEN", "")
        # reload token cache — _load_token reads env at call time
        assert verify_token(None) is True
        assert verify_token("anything") is True

    def test_token_required_when_set(self, monkeypatch):
        monkeypatch.setenv("MIRV_BURP_TOKEN", "secret123")
        assert verify_token("secret123") is True
        assert verify_token("wrong") is False
        assert verify_token(None) is False
        assert verify_token("") is False

    def test_token_status_reports_required_flag(self, monkeypatch):
        monkeypatch.setenv("MIRV_BURP_TOKEN", "abc")
        assert status()["token_required"] is True
        monkeypatch.setenv("MIRV_BURP_TOKEN", "")
        assert status()["token_required"] is False


# ────────────────────────────────────────────────────────────────────
#  11. REST endpoint smoke tests (all 14 endpoints)
# ────────────────────────────────────────────────────────────────────

class TestRestEndpoints:
    def test_post_ingest(self, client):
        r = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_get_requests(self, client):
        client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/a"})
        r = client.get("/api/burp/requests")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert len(data["requests"]) == 1

    def test_get_requests_with_filters(self, client):
        client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/a"})
        client.post("/api/burp/ingest", json={"method": "POST", "url": "https://h.test/b"})
        r = client.get("/api/burp/requests?method=POST")
        assert len(r.json()["requests"]) == 1

    def test_get_single_request(self, client):
        rid = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"}).json()["request"]["id"]
        r = client.get("/api/burp/requests/%s" % rid)
        assert r.status_code == 200
        assert r.json()["request"]["id"] == rid

    def test_get_single_request_404(self, client):
        r = client.get("/api/burp/requests/nope")
        assert r.status_code == 404

    def test_get_endpoints(self, client):
        client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/a"})
        client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/a"})
        r = client.get("/api/burp/endpoints")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["endpoints"][0]["hit_count"] == 2

    def test_post_task(self, client):
        rid = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"}).json()["request"]["id"]
        r = client.post("/api/burp/tasks", json={"request_id": rid})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_post_task_unknown(self, client):
        r = client.post("/api/burp/tasks", json={"request_id": "x"})
        assert r.status_code == 404
        assert r.json()["ok"] is False

    def test_get_tasks(self, client):
        rid = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"}).json()["request"]["id"]
        client.post("/api/burp/tasks", json={"request_id": rid})
        r = client.get("/api/burp/tasks")
        assert r.status_code == 200
        assert len(r.json()["tasks"]) == 1

    def test_patch_task(self, client):
        rid = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"}).json()["request"]["id"]
        tid = client.post("/api/burp/tasks", json={"request_id": rid}).json()["task"]["id"]
        r = client.patch("/api/burp/tasks/%s" % tid, json={"status": "done"})
        assert r.status_code == 200
        assert r.json()["task"]["status"] == "done"

    def test_post_issue(self, client):
        r = client.post("/api/burp/issues", json={
            "title": "SQLi", "severity": "critical",
            "url": "https://h.test/x", "method": "GET",
            "request_raw": "GET /x HTTP/1.1\r\n\r\n",
        })
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_get_issues(self, client):
        client.post("/api/burp/issues", json={
            "title": "x", "severity": "info", "url": "https://h.test/x",
            "method": "GET", "request_raw": "",
        })
        r = client.get("/api/burp/issues")
        assert r.status_code == 200
        assert len(r.json()["issues"]) == 1

    def test_post_finding_to_issue(self, client):
        r = client.post("/api/burp/finding-to-issue", json={
            "what": "SQLi", "severity": "high",
            "target": "https://h.test/x", "method": "GET",
        })
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["issue"]["severity"] == "high"

    def test_post_raw(self, client):
        rid = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"}).json()["request"]["id"]
        r = client.post("/api/burp/raw", json={"request_id": rid})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert "HTTP/1.1" in r.json()["raw"]

    def test_post_raw_404(self, client):
        r = client.post("/api/burp/raw", json={"request_id": "nope"})
        assert r.status_code == 404

    def test_post_export_findings(self, client):
        r = client.post("/api/burp/export-findings", json=[
            {"what": "a", "severity": "high", "target": "https://h.test/a", "method": "GET"},
            {"what": "b", "severity": "low", "target": "https://h.test/b", "method": "GET"},
        ])
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert len(data["issues"]) == 2

    def test_delete_clear(self, client):
        client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"})
        r = client.delete("/api/burp/clear")
        assert r.status_code == 200
        assert client.get("/api/burp/status").json()["requests"] == 0

    def test_get_status(self, client):
        r = client.get("/api/burp/status")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "requests" in data and "endpoints" in data


# ────────────────────────────────────────────────────────────────────
#  12. Auth token integration through the REST layer
# ────────────────────────────────────────────────────────────────────

class TestRestToken:
    def test_ingest_rejected_without_token_when_set(self, client, monkeypatch):
        monkeypatch.setenv("MIRV_BURP_TOKEN", "tkn")
        r = client.post("/api/burp/ingest", json={"method": "GET", "url": "https://h.test/x"})
        assert r.status_code == 401

    def test_ingest_accepted_with_correct_token(self, client, monkeypatch):
        monkeypatch.setenv("MIRV_BURP_TOKEN", "tkn")
        r = client.post(
            "/api/burp/ingest",
            json={"method": "GET", "url": "https://h.test/x"},
            headers={"X-MIRV-Token": "tkn"},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True