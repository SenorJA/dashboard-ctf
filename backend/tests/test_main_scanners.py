"""
tests/test_main_scanners.py — Scanner endpoint success/error branches in main.py.

Covers the happy-path response serialization of the 10 scanner endpoints
(secrets, port, subdomain, dns lookup/reverse, hash crack, stego, news,
api scan, headers scan) by mocking the underlying scanner modules, plus
their validation and 502 error branches.

Run:
    python -m pytest backend/tests/test_main_scanners.py -q
"""

from __future__ import annotations

import sys
import os
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app
from backend.secrets_scanner import ScanReport as SecretsReport, SecretFinding, SecretPattern
from backend.port_scanner import ScanReport as PortReport, PortResult
from backend.subdomain_scanner import SubdomainReport, SubdomainResult
from backend.dns_lookup import DNSReport, DNSRecord
from backend.hash_cracker import CrackReport, HashResult
from backend.stego_tool import StegoResult, ImageInfo
from backend.news_scraper import NewsReport, NewsArticle
from backend.api_scanner import ApiScanReport
from backend.headers_scanner import ScanReport as HeadersReport


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _patch_db_unavailable():
    with patch("backend.database.is_available", return_value=False), \
         patch("backend.database.get_client", return_value=None):
        yield


# ──────────────────────────────────────────────
# /api/secrets/scan
# ──────────────────────────────────────────────

def test_secrets_scan_url_success(client):
    pattern = SecretPattern(
        name="API Key", severity="high", description="Hardcoded API key",
        recommendation="Rotate and move to env", regex=r"(?i)api_key", group="",
    )
    report = SecretsReport(
        source="url", content_length=100, lines_scanned=10,
        findings=[SecretFinding(pattern=pattern, line=1,
                                match='api_key = "abc"', context="", note="")],
    )
    with patch("main.secrets_scan_url", AsyncMock(return_value=report)):
        resp = client.get("/api/secrets/scan", params={"url": "https://example.com/page"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["source"] == "url"
    assert data["content_length"] == 100
    assert data["lines_scanned"] == 10
    assert data["findings"][0]["severity"] == "high"


def test_secrets_scan_invalid_url(client):
    resp = client.get("/api/secrets/scan", params={"url": "example.com"})
    assert resp.status_code == 422
    assert resp.json()["ok"] is False


def test_secrets_scan_raw_success(client):
    report = SecretsReport(
        source="raw_input", content_length=10, lines_scanned=1, findings=[],
    )
    with patch("main.secrets_scan_text", return_value=report):
        resp = client.get("/api/secrets/scan", params={"raw": "hello world"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["secrets_found"] == 0


def test_secrets_scan_no_input(client):
    resp = client.get("/api/secrets/scan")
    assert resp.status_code == 422
    assert "Provide either" in resp.json()["error"]


def test_secrets_scan_exception(client):
    with patch("main.secrets_scan_url", AsyncMock(side_effect=RuntimeError("boom"))):
        resp = client.get("/api/secrets/scan", params={"url": "https://example.com"})
    assert resp.status_code == 502
    assert resp.json()["ok"] is False


# ──────────────────────────────────────────────
# /api/port/scan
# ──────────────────────────────────────────────

def test_port_scan_success(client):
    report = PortReport(
        target="example.com", resolved_ip="1.2.3.4", ports_scanned=2,
        open_ports=[80, 443],
        results=[PortResult(80, "http", "open", None),
                 PortResult(443, "https", "open", "nginx")],
        duration_seconds=0.5,
    )
    with patch("main.port_scan", AsyncMock(return_value=report)):
        resp = client.get("/api/port/scan", params={"target": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["target"] == "example.com"
    assert data["open_ports"] == [80, 443]
    assert data["results"][0]["port"] == 80
    assert data["results"][1]["banner"] == "nginx"


def test_port_scan_invalid_ports(client):
    resp = client.get("/api/port/scan", params={"target": "example.com", "ports": "22,abc"})
    assert resp.status_code == 422
    assert "Invalid port list" in resp.json()["error"]


def test_port_scan_exception(client):
    with patch("main.port_scan", AsyncMock(side_effect=RuntimeError("net down"))):
        resp = client.get("/api/port/scan", params={"target": "example.com"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/subdomain/scan
# ──────────────────────────────────────────────

def test_subdomain_scan_success(client):
    report = SubdomainReport(
        domain="example.com", total_checked=2, found=1,
        results=[SubdomainResult("www", "example.com", "www.example.com",
                                 ["1.2.3.4"], "A", None)],
        duration_seconds=0.2,
    )
    with patch("main.subdomain_scan", AsyncMock(return_value=report)):
        resp = client.get("/api/subdomain/scan", params={"domain": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["total_checked"] == 2
    assert data["results"][0]["subdomain"] == "www"


def test_subdomain_scan_url_input_strips_scheme(client):
    with patch("main.subdomain_scan", AsyncMock()) as m:
        client.get("/api/subdomain/scan", params={"domain": "https://example.com/path"})
    assert m.await_args.args[0] == "example.com"


def test_subdomain_scan_invalid_domain(client):
    resp = client.get("/api/subdomain/scan", params={"domain": "nodot"})
    assert resp.status_code == 422


def test_subdomain_scan_exception(client):
    with patch("main.subdomain_scan", AsyncMock(side_effect=RuntimeError("dns fail"))):
        resp = client.get("/api/subdomain/scan", params={"domain": "example.com"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/dns/lookup
# ──────────────────────────────────────────────

def test_dns_lookup_success(client):
    report = DNSReport(
        domain="example.com",
        records={"A": [DNSRecord("example.com", "A", 300, "1.2.3.4")]},
        reverse_dns=["1.2.3.4"],
        duration_seconds=0.1,
    )
    with patch("main.dns_lookup", AsyncMock(return_value=report)):
        resp = client.get("/api/dns/lookup", params={"domain": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["records"]["A"][0]["value"] == "1.2.3.4"


def test_dns_lookup_with_types(client):
    with patch("main.dns_lookup", AsyncMock()) as m:
        client.get("/api/dns/lookup", params={"domain": "example.com", "types": "A,MX"})
    assert m.await_args.kwargs["record_types"] == ["A", "MX"]


def test_dns_lookup_url_strips_scheme(client):
    with patch("main.dns_lookup", AsyncMock()) as m:
        client.get("/api/dns/lookup", params={"domain": "http://example.com"})
    assert m.await_args.args[0] == "example.com"


def test_dns_lookup_invalid_domain(client):
    resp = client.get("/api/dns/lookup", params={"domain": "nodot"})
    assert resp.status_code == 422


def test_dns_lookup_exception(client):
    with patch("main.dns_lookup", AsyncMock(side_effect=RuntimeError("doh down"))):
        resp = client.get("/api/dns/lookup", params={"domain": "example.com"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/dns/reverse
# ──────────────────────────────────────────────

def test_dns_reverse_success(client):
    report = DNSReport(domain="8.8.8.8", records={}, reverse_dns=["dns.google"],
                       duration_seconds=0.1)
    with patch("main.dns_reverse", AsyncMock(return_value=report)):
        resp = client.get("/api/dns/reverse", params={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    assert resp.json()["hostname"] == ["dns.google"]


def test_dns_reverse_exception(client):
    with patch("main.dns_reverse", AsyncMock(side_effect=RuntimeError("doh down"))):
        resp = client.get("/api/dns/reverse", params={"ip": "8.8.8.8"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/hash/crack
# ──────────────────────────────────────────────

def test_hash_crack_success(client):
    report = CrackReport(
        hashes=[HashResult("5d41402abc4b2a76b9719d911017c592", ["MD5"], True,
                           "hello", "rainbow")],
        total=1, cracked=1, duration_seconds=0.1,
    )
    with patch("main.hash_crack", AsyncMock(return_value=report)):
        resp = client.get("/api/hash/crack",
                          params={"hash": "5d41402abc4b2a76b9719d911017c592"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["total"] == 1
    assert data["cracked"] == 1
    assert data["results"][0]["plaintext"] == "hello"


def test_hash_crack_list_param(client):
    with patch("main.hash_crack", AsyncMock()) as m:
        client.get("/api/hash/crack", params={"hashes": "abc,def"})
    assert m.await_args.args[0] == "abc,def"


def test_hash_crack_missing(client):
    resp = client.get("/api/hash/crack")
    assert resp.status_code == 422
    assert "Provide 'hash' or 'hashes'" in resp.json()["error"]


def test_hash_crack_exception(client):
    with patch("main.hash_crack", AsyncMock(side_effect=RuntimeError("no table"))):
        resp = client.get("/api/hash/crack", params={"hash": "abc123"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/stego/analyze
# ──────────────────────────────────────────────

def _stego_report():
    return StegoResult(
        image_info=ImageInfo(width=100, height=50, bit_depth=24, color_type="RGB",
                             format="PNG", file_size=1000, compression="deflate",
                             has_alpha=False, estimated_capacity_bytes=100),
        lsb_suspicious=True, trailing_data_found=True, lsb_message="hi",
        lsb_bytes=b"hi", lsb_extracted_length=2, trailing_data_size=10,
        trailing_data_preview="...", anomalies=["trailing data"],
        duration_seconds=0.1,
    )


def test_stego_analyze_success(client):
    with patch("main.stego_analyze", AsyncMock(return_value=_stego_report())):
        resp = client.get("/api/stego/analyze",
                          params={"url": "https://example.com/img.png"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["format"] == "PNG"
    assert data["width"] == 100
    assert data["lsb_suspicious"] is True
    assert data["trailing_data_found"] is True


def test_stego_analyze_no_url(client):
    resp = client.get("/api/stego/analyze")
    assert resp.status_code == 422


def test_stego_analyze_bad_scheme(client):
    resp = client.get("/api/stego/analyze", params={"url": "ftp://example.com/x"})
    assert resp.status_code == 422


def test_stego_analyze_exception(client):
    with patch("main.stego_analyze", AsyncMock(side_effect=RuntimeError("bad image"))):
        resp = client.get("/api/stego/analyze",
                          params={"url": "https://example.com/img.png"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/news
# ──────────────────────────────────────────────

def test_news_success(client):
    report = NewsReport(
        articles=[NewsArticle("Title", "https://example.com/a", "2026-01-01",
                              "src1", "Source One", "summary text", "news",
                              "author")],
        sources_ok=["Source One"], sources_failed=0, total_articles=1,
        duration_seconds=0.2, source_details={},
    )
    with patch("main.fetch_news", AsyncMock(return_value=report)):
        resp = client.get("/api/news", params={"max_per_source": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["total_articles"] == 1
    assert data["articles"][0]["title"] == "Title"
    assert data["articles"][0]["summary"] == "summary text"


def test_news_with_sources(client):
    with patch("main.fetch_news", AsyncMock()) as m:
        client.get("/api/news", params={"sources": "src1,src2"})
    assert m.await_args.kwargs["sources"] == ["src1", "src2"]


def test_news_exception(client):
    with patch("main.fetch_news", AsyncMock(side_effect=RuntimeError("rss down"))):
        resp = client.get("/api/news")
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/apiscan
# ──────────────────────────────────────────────

def test_api_scan_success(client):
    report = ApiScanReport(
        base_url="https://example.com/api", endpoints_scanned=1,
        issues=[SimpleNamespace(severity="high", title="Missing Auth",
                                detail="d", endpoint="/users", category="auth")],
        open_endpoints=[SimpleNamespace(path="/users", method="GET", status_code=200,
                                        content_length=10, response_time=0.1)],
        duration_seconds=0.3, cors_enabled=False, auth_required=True,
        missing_headers=["x-frame-options"], info_disclosures=["server"],
    )
    with patch("main.api_scan", AsyncMock(return_value=report)):
        resp = client.get("/api/apiscan", params={"url": "https://example.com/api"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["endpoints_scanned"] == 1
    assert data["open_endpoints"][0]["path"] == "/users"
    assert data["issues"][0]["title"] == "Missing Auth"


def test_api_scan_missing_url(client):
    resp = client.get("/api/apiscan")
    assert resp.status_code == 422


def test_api_scan_exception(client):
    with patch("main.api_scan", AsyncMock(side_effect=RuntimeError("conn refused"))):
        resp = client.get("/api/apiscan", params={"url": "https://example.com/api"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/headers/scan
# ──────────────────────────────────────────────

def test_headers_scan_success(client):
    report = HeadersReport(url="https://example.com", final_url="https://example.com",
                           status_code=200, findings=[])
    with patch("main.headers_scan", AsyncMock(return_value=report)):
        resp = client.get("/api/headers/scan", params={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["status_code"] == 200
    assert data["score"] == 0
    assert data["grade"] == "F"


def test_headers_scan_bad_scheme(client):
    resp = client.get("/api/headers/scan", params={"url": "example.com"})
    assert resp.status_code == 422


def test_headers_scan_exception(client):
    with patch("main.headers_scan", AsyncMock(side_effect=RuntimeError("tls fail"))):
        resp = client.get("/api/headers/scan", params={"url": "https://example.com"})
    assert resp.status_code == 502
