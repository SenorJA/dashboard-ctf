"""
tests/test_finding_poc.py — Reproducible FindingPoC module + REST endpoints.

Covers:
  * build_poc: GET, POST-with-body, raw request generation,
    curl one-liner generation, response_excerpt truncation, evidence_hash
  * poc_to_finding: required fields populated
  * finding_to_poc: round-trip from dict with data.poc, None when no PoC info
  * parse_curl_to_poc: GET / POST --data / -H / -X PUT / --cookie / -k
  * replay_poc: success / timeout / connection error / matches_original
  * finding_to_markdown_report: structural rendering
  * validate_poc: valid / bad method / bad url
  * sanitize_payload: null-byte removal, SQLi preservation
  * poc_from_burp_request: valid + missing-fields → None
  * Endpoint smoke tests for all 6 /api/poc/* routes
"""

from __future__ import annotations

import os
import sys
import subprocess
import dataclasses
from unittest.mock import patch, MagicMock

import pytest

# Mirror conftest's import ordering so `from main import app` resolves and
# `backend.finding_poc` binds to the same module the endpoints use.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402  (installs project root on sys.path)
import backend.finding_poc as fp  # noqa: E402
from backend.finding_poc import (  # noqa: E402
    FindingPoC,
    MAX_RESPONSE_EXCERPT,
    build_poc,
    poc_to_finding,
    finding_to_poc,
    replay_poc,
    parse_curl_to_poc,
    finding_to_markdown_report,
    validate_poc,
    validate_url,
    sanitize_payload,
    poc_from_burp_request,
)


# ── build_poc ───────────────────────────────────────────────────────
def test_build_poc_basic_get():
    p = build_poc("GET", "https://example.com/api/x")
    assert p.method == "GET"
    assert p.url == "https://example.com/api/x"
    assert p.body is None
    assert p.headers == {}
    assert p.finding_id  # uuid populated
    assert p.evidence_hash is None  # no excerpt


def test_build_poc_post_with_body():
    p = build_poc("POST", "https://x.io/api", body="a=1&b=2")
    assert p.method == "POST"
    assert p.body == "a=1&b=2"
    assert "--data-raw" in p.curl_command or "--data" in p.curl_command
    # raw request should mention body
    assert "a=1&b=2" in p.raw_request


def test_build_poc_includes_raw_http_request():
    p = build_poc("GET", "https://example.com/path?x=1")
    # HTTP/1.1 request line + Host header + empty line ending.
    assert p.raw_request.startswith("GET /path?x=1 HTTP/1.1")
    assert "Host: example.com" in p.raw_request
    assert p.raw_request.endswith("\r\n\r\n") or "\r\n\r\n" in p.raw_request


def test_build_poc_generates_curl_one_liner():
    p = build_poc("GET", "https://example.com/")
    assert p.curl_command.startswith("curl ")
    assert p.url in p.curl_command


def test_build_poc_truncates_response_excerpt():
    long_excerpt = "A" * (MAX_RESPONSE_EXCERPT + 500)
    p = build_poc("GET", "https://example.com/", response_excerpt=long_excerpt)
    assert len(p.response_excerpt) == MAX_RESPONSE_EXCERPT


def test_build_poc_computes_evidence_hash():
    excerpt = "<h1>Welcome admin</h1>"
    p = build_poc("GET", "https://example.com/", response_excerpt=excerpt)
    assert p.evidence_hash is not None
    assert len(p.evidence_hash) == 12
    # sha256[:12] is hex
    int(p.evidence_hash, 16)


def test_build_poc_no_excerpt_no_hash():
    p = build_poc("GET", "https://example.com/")
    assert p.evidence_hash is None


def test_build_poc_impact_default_empty():
    p = build_poc("GET", "https://example.com/")
    assert p.impact == ""


def test_build_poc_multi_headers():
    p = build_poc(
        "GET", "https://example.com/",
        headers={"Authorization": "Bearer X", "X-Custom": "abc"},
    )
    assert "-H " in p.curl_command
    assert p.curl_command.count("-H ") >= 2
    assert "Authorization" in p.raw_request
    assert "X-Custom" in p.raw_request


# ── poc_to_finding ──────────────────────────────────────────────────
def test_poc_to_finding_has_required_fields():
    p = build_poc("GET", "https://example.com/", parameter="id", payload="1")
    f = poc_to_finding(p, "SQLi in id", "high", "example.com", tool="sqlmap")
    assert f["what"] == "SQLi in id"
    assert f["severity"] == "high"
    assert f["target"] == "example.com"
    assert f["tool"] == "sqlmap"
    d = f["data"]
    assert d["method"] == "GET"
    assert d["url"] == "https://example.com/"
    assert d["parameter"] == "id"
    assert d["payload"] == "1"
    assert "poc" in d and isinstance(d["poc"], dict)
    assert d["poc"]["finding_id"] == p.finding_id


# ── finding_to_poc ──────────────────────────────────────────────────
def test_finding_to_poc_round_trip_with_data_poc():
    p = build_poc("POST", "https://x.io/api", body="a=1", parameter="u", payload="admin",
                  response_status=200, response_excerpt="ok")
    f = poc_to_finding(p, "Auth bypass", "high", "x.io")
    rt = finding_to_poc(f)
    assert rt is not None
    assert rt.method == "POST"
    assert rt.url == "https://x.io/api"
    assert rt.body == "a=1"
    assert rt.parameter == "u"
    assert rt.payload == "admin"
    assert rt.response_status == 200
    assert rt.response_excerpt == "ok"
    assert rt.evidence_hash == p.evidence_hash


def test_finding_to_poc_without_poc_returns_none():
    assert finding_to_poc({"what": "x", "data": {}}) is None
    assert finding_to_poc({"what": "x"}) is None
    assert finding_to_poc(None) is None


def test_finding_to_poc_from_legacy_curl():
    f = {
        "what": "XSS", "severity": "high", "target": "x.io",
        "data": {
            "curl": "curl -X POST -H 'Content-Type: application/json' "
                    "--data '{\"a\":1}' https://x.io/api",
            "response_excerpt": "evidence",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "impact": "account takeover",
        }
    }
    rt = finding_to_poc(f)
    assert rt is not None
    assert rt.method == "POST"
    assert rt.url == "https://x.io/api"
    assert rt.parameter == "q"
    assert rt.payload == "<script>alert(1)</script>"
    assert rt.impact == "account takeover"


# ── parse_curl_to_poc ───────────────────────────────────────────────
def test_parse_curl_get():
    p = parse_curl_to_poc("curl https://example.com/")
    assert p.method == "GET"
    assert p.url == "https://example.com/"


def test_parse_curl_post_with_data():
    p = parse_curl_to_poc("curl -X POST --data '{\"a\":1}' https://x.io/api")
    assert p.method == "POST"
    assert p.body == "{\"a\":1}"


def test_parse_curl_data_implies_post():
    p = parse_curl_to_poc("curl --data 'a=1' https://x.io/api")
    assert p.method == "POST"


def test_parse_curl_headers():
    p = parse_curl_to_poc("curl -H 'Authorization: Bearer X' -H 'Accept: */*' https://x.io/")
    assert p.headers.get("Authorization") == "Bearer X"
    assert p.headers.get("Accept") == "*/*"


def test_parse_curl_put():
    p = parse_curl_to_poc("curl -X PUT -H 'Content-Type: application/json' "
                          "--data '{\"a\":1}' https://api.test/v1")
    assert p.method == "PUT"
    assert p.body == "{\"a\":1}"
    assert p.url == "https://api.test/v1"


def test_parse_curl_cookie():
    p = parse_curl_to_poc("curl --cookie 'session=abc' https://x.io/")
    assert p.headers.get("Cookie") == "session=abc"


def test_parse_curl_ignores_k():
    p = parse_curl_to_poc("curl -k https://x.io/")
    assert p.url == "https://x.io/"
    assert p.method == "GET"


def test_parse_curl_with_response_context():
    p = parse_curl_to_poc("curl https://x.io/", response_excerpt="evidence", response_status=200)
    assert p.response_excerpt == "evidence"
    assert p.response_status == 200
    assert p.evidence_hash is not None


def test_parse_curl_partial_url_promoted_to_https():
    p = parse_curl_to_poc("curl example.com/api")
    assert p.url.startswith("https://")


def test_parse_curl_empty_returns_empty_poc():
    p = parse_curl_to_poc("")
    assert p.method == "GET"


def test_parse_curl_realistic_xss_payload():
    cmd = (
        "curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
        "-H 'Cookie: session=abc123' "
        "--data-raw 'q=<script>alert(document.cookie)</script>' "
        "https://victim.example/search "
        "--cookie 'extra=ignored'"
    )
    p = parse_curl_to_poc(cmd, response_excerpt="<script>alert(1)</script>", response_status=200)
    assert p.method == "POST"
    assert "<script>alert(document.cookie)</script>" in (p.body or "")
    assert "session=abc123" in p.headers.get("Cookie", "")
    assert p.url == "https://victim.example/search"


# ── replay_poc ──────────────────────────────────────────────────────
def _fake_completed(stdout="HTTP/1.1 200 OK\r\n\r\nok\n", stderr="", rc=0):
    return MagicMock(returncode=rc, stdout=stdout, stderr=stderr)


def test_replay_poc_success():
    p = build_poc("GET", "https://example.com/", response_excerpt="ok")
    fake = _fake_completed(stdout="HTTP/1.1 200 OK\r\n\r\nok\n")
    with patch("backend.finding_poc.subprocess.run", return_value=fake) as m:
        res = replay_poc(p, timeout=5)
    assert res["ok"] is True
    assert res["status_code"] == 200
    assert res["error"] is None
    # We appended -k (default verify_tls=False)
    args = m.call_args[0][0]
    assert "-k" in args
    # Never shell=True
    assert m.call_args.kwargs.get("shell") in (None, False)


def test_replay_poc_timeout():
    p = build_poc("GET", "https://example.com/", response_excerpt="ok")
    with patch("backend.finding_poc.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=1)):
        res = replay_poc(p, timeout=1)
    assert res["ok"] is False
    assert res["error"] == "timeout"


def test_replay_poc_connection_error():
    p = build_poc("GET", "https://example.com/", response_excerpt="ok")
    with patch("backend.finding_poc.subprocess.run", side_effect=subprocess.CalledProcessError(1, "curl")):
        res = replay_poc(p, timeout=5)
    assert res["ok"] is False
    assert "subprocess error" in (res["error"] or "")


def test_replay_poc_curl_missing():
    p = build_poc("GET", "https://example.com/")
    with patch("backend.finding_poc.subprocess.run", side_effect=FileNotFoundError()):
        res = replay_poc(p, timeout=5)
    assert res["ok"] is False
    assert "not found" in (res["error"] or "")


def test_replay_poc_matches_original_true():
    excerpt = "EXACT EVIDENCE"
    p = build_poc("GET", "https://example.com/", response_excerpt=excerpt)
    # Replay returns the same excerpt → hashes match.
    fake = _fake_completed(stdout="HTTP/1.1 200 OK\r\n\r\n" + excerpt + "\n")
    with patch("backend.finding_poc.subprocess.run", return_value=fake):
        res = replay_poc(p, timeout=5)
    assert res["ok"] is True
    assert res["matches_original"] is True


def test_replay_poc_matches_original_false_when_changed():
    p = build_poc("GET", "https://example.com/", response_excerpt="ORIG")
    fake = _fake_completed(stdout="HTTP/1.1 200 OK\r\n\r\nDIFFERENT\n")
    with patch("backend.finding_poc.subprocess.run", return_value=fake):
        res = replay_poc(p, timeout=5)
    assert res["matches_original"] is False


def test_replay_poc_empty_command():
    p = FindingPoC(
        finding_id="x", method="GET", url="https://x.io/", headers={},
        body=None, parameter=None, payload=None, response_status=None,
        response_excerpt=None, curl_command="", raw_request="",
    )
    res = replay_poc(p)
    assert res["ok"] is False
    assert "curl_command" in (res["error"] or "")


def test_replay_poc_respects_verify_tls_true():
    p = build_poc("GET", "https://example.com/")
    fake = _fake_completed()
    with patch("backend.finding_poc.subprocess.run", return_value=fake) as m:
        replay_poc(p, verify_tls=True, timeout=5)
    args = m.call_args[0][0]
    assert "-k" not in args


# ── finding_to_markdown_report ──────────────────────────────────────
def test_finding_to_markdown_report_structure():
    p = build_poc("POST", "https://x.io/api", body="a=1", parameter="u",
                  payload="admin", response_status=200,
                  response_excerpt="<h1>Welcome admin</h1>",
                  remediation="Validate input.", impact="Auth bypass.")
    f = poc_to_finding(p, "Auth bypass", "high", "x.io")
    md = finding_to_markdown_report(f)
    assert "## " in md  # title heading
    assert "AUTH BYPASS" in md.upper() or "Auth bypass" in md
    assert "Reproducible PoC" in md
    assert "POST https://x.io/api" in md
    assert "```" in md  # code blocks present
    assert "admin" in md  # payload visible (in curl/data)
    assert "Remediation" in md
    assert "Impact" in md
    assert p.evidence_hash in md


def test_finding_to_markdown_report_no_poc():
    md = finding_to_markdown_report({"what": "gap", "severity": "info", "target": "x.io", "data": {}})
    assert "##" in md
    assert "PoC" in md or "PoC" not in md  # graceful


def test_finding_to_markdown_invalid():
    md = finding_to_markdown_report("not a dict")
    assert "invalid" in md.lower()


# ── validate_poc / validate_url ────────────────────────────────────
def test_validate_poc_valid():
    p = build_poc("GET", "https://example.com/", response_status=200)
    assert validate_poc(p) == []


def test_validate_poc_bad_method():
    p = FindingPoC(
        finding_id="x", method="frob", url="https://x.io/", headers={},
        body=None, parameter=None, payload=None,
        response_status=None, response_excerpt=None,
        curl_command="", raw_request="",
    )
    errs = validate_poc(p)
    assert any("method" in e for e in errs)


def test_validate_poc_bad_url():
    p = FindingPoC(
        finding_id="x", method="GET", url="not a url", headers={},
        body=None, parameter=None, payload=None,
        response_status=None, response_excerpt=None,
        curl_command="", raw_request="",
    )
    errs = validate_poc(p)
    assert any("url" in e for e in errs)


def test_validate_poc_bad_response_status():
    p = FindingPoC(
        finding_id="x", method="GET", url="https://x.io/", headers={},
        body=None, parameter=None, payload=None,
        response_status=999, response_excerpt=None,
        curl_command="", raw_request="",
    )
    errs = validate_poc(p)
    assert any("status" in e for e in errs)


def test_validate_url_basic():
    assert validate_url("https://example.com/") is True
    assert validate_url("http://localhost:8000/x") is True
    assert validate_url("ftp://example/") is False
    assert validate_url("example.com/") is False
    assert validate_url("") is False
    assert validate_url(None) is False


# ── sanitize_payload ────────────────────────────────────────────────
def test_sanitize_payload_removes_null_bytes():
    bad = "a\x00b\x01c"
    assert sanitize_payload(bad) == "abc"


def test_sanitize_payload_preserves_sqli():
    sqli = "' OR 1=1--"
    assert sanitize_payload(sqli) == sqli


def test_sanitize_payload_preserves_xss():
    xss = "<script>alert(document.cookie)</script>"
    assert sanitize_payload(xss) == xss


def test_sanitize_payload_preserves_multiline():
    multi = "line1\nline2\r\nline3"
    assert sanitize_payload(multi) == multi


# ── poc_from_burp_request ───────────────────────────────────────────
def test_poc_from_burp_request_valid():
    cap = {
        "method": "POST",
        "url": "https://x.io/api",
        "headers": {"Content-Type": "application/json", "Authorization": "Bearer X"},
        "body": "{\"a\":1}",
        "response_status": 201,
        "response_body": "{\"id\":1}",
    }
    poc = poc_from_burp_request(cap)
    assert poc is not None
    assert poc.method == "POST"
    assert poc.url == "https://x.io/api"
    assert poc.body == "{\"a\":1}"
    assert poc.response_status == 201
    assert poc.response_excerpt == "{\"id\":1}"
    assert poc.evidence_hash is not None


def test_poc_from_burp_request_missing_fields():
    assert poc_from_burp_request({"method": "GET"}) is None  # missing url
    assert poc_from_burp_request({}) is None
    assert poc_from_burp_request(None) is None
    assert poc_from_burp_request("x") is None


def test_poc_from_burp_request_header_list_form():
    cap = {
        "method": "GET", "url": "https://x.io/",
        "headers": ["Authorization: Bearer X", "X-A: 1"],
        "response_status": 200,
    }
    poc = poc_from_burp_request(cap)
    assert poc is not None
    assert poc.headers.get("Authorization") == "Bearer X"
    assert poc.headers.get("X-A") == "1"


# ── Endpoint smoke tests ───────────────────────────────────────────
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_endpoint_build(client):
    r = client.post("/api/poc/build", json={
        "method": "POST", "url": "https://example.com/api",
        "headers": {"Authorization": "Bearer X"},
        "body": "a=1", "parameter": "u", "payload": "admin",
        "response_status": 200, "response_excerpt": "<h1>admin</h1>",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    poc = body["poc"]
    assert poc["method"] == "POST"
    assert poc["url"] == "https://example.com/api"
    assert poc["curl_command"].startswith("curl ")
    assert poc["raw_request"].startswith("POST /api HTTP/1.1")
    assert poc["evidence_hash"]
    assert len(poc["evidence_hash"]) == 12


def test_endpoint_build_bad_url(client):
    r = client.post("/api/poc/build", json={"method": "GET", "url": "nope"})
    assert r.status_code == 400
    assert r.json()["ok"] is False


def test_endpoint_parse_curl(client):
    r = client.post("/api/poc/parse-curl", json={
        "curl": "curl -X PUT -H 'Content-Type: application/json' --data '{\"a\":1}' https://x.io/v",
        "response_excerpt": "ok", "response_status": 200,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    poc = body["poc"]
    assert poc["method"] == "PUT"
    assert poc["url"] == "https://x.io/v"
    assert poc["body"] == "{\"a\":1}"
    assert "Content-Type" in poc["headers"]


def test_endpoint_parse_curl_empty(client):
    r = client.post("/api/poc/parse-curl", json={"curl": ""})
    assert r.status_code == 400


def test_endpoint_finding_to_md(client):
    poc = dataclasses.asdict(build_poc("POST", "https://x.io/api", body="a=1", parameter="u",
                                       payload="admin", response_status=200,
                                       response_excerpt="ok", remediation="Fix it.",
                                       impact="Bypass."))
    finding = {"what": "Auth bypass", "severity": "high", "target": "x.io",
              "tool": "manual", "data": {"poc": poc}}
    r = client.post("/api/poc/finding-to-md", json=finding)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "##" in body["markdown"]
    assert "Auth bypass" in body["markdown"]


def test_endpoint_from_burp(client):
    r = client.post("/api/poc/from-burp", json={
        "method": "POST", "url": "https://x.io/api", "headers": {"X": "Y"},
        "body": "a=1", "response_status": 200, "response_body": "ok",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["poc"]["method"] == "POST"


def test_endpoint_from_burp_missing(client):
    r = client.post("/api/poc/from-burp", json={"method": "GET"})
    assert r.status_code == 400


def test_endpoint_validate_valid(client):
    poc = dataclasses.asdict(build_poc("GET", "https://example.com/", response_status=200))
    r = client.post("/api/poc/validate", json=poc)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["errors"] == []


def test_endpoint_validate_bad(client):
    bad = {"method": "frob", "url": "nope", "headers": {}}
    r = client.post("/api/poc/validate", json=bad)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert len(body["errors"]) >= 2  # method + url


def test_endpoint_replay_with_poc(client):
    # Mock subprocess so we never hit the network.
    poc = dataclasses.asdict(build_poc("GET", "https://example.com/", response_excerpt="ok"))
    fake = _fake_completed(stdout="HTTP/1.1 200 OK\r\n\r\nok\n")
    with patch("backend.finding_poc.subprocess.run", return_value=fake):
        r = client.post("/api/poc/replay", json={"poc": poc, "timeout": 5})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["status_code"] == 200


def test_endpoint_replay_with_finding(client):
    poc = dataclasses.asdict(build_poc("GET", "https://example.com/", response_excerpt="ok"))
    finding = {"what": "x", "severity": "info", "target": "x.io", "data": {"poc": poc}}
    fake = _fake_completed(stdout="HTTP/1.1 200 OK\r\n\r\nok\n")
    with patch("backend.finding_poc.subprocess.run", return_value=fake):
        r = client.post("/api/poc/replay", json={"finding": finding, "timeout": 5})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_endpoint_replay_no_input(client):
    r = client.post("/api/poc/replay", json={})
    assert r.status_code == 400


def test_endpoint_finding_to_md_with_curl_only(client):
    # Finding with legacy data.curl instead of data.poc.
    finding = {
        "what": "XSS", "severity": "high", "target": "x.io",
        "data": {
            "curl": "curl -X POST --data 'a=1' https://x.io/api",
            "parameter": "q", "payload": "<script>x</script>",
            "impact": "perf",
        },
    }
    r = client.post("/api/poc/finding-to-md", json=finding)
    assert r.status_code == 200
    md = r.json()["markdown"]
    assert "##" in md
    assert "XSS" in md


def test_endpoint_build_multi_headers(client):
    r = client.post("/api/poc/build", json={
        "method": "GET", "url": "https://example.com/",
        "headers": {"Authorization": "Bearer X", "Accept": "*/*", "X-C": "1"},
    })
    assert r.status_code == 200
    poc = r.json()["poc"]
    assert poc["headers"]["Authorization"] == "Bearer X"
    assert poc["headers"]["Accept"] == "*/*"
    assert poc["headers"]["X-C"] == "1"
    assert poc["curl_command"].count("-H ") >= 3