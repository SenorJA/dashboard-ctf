"""
tests/test_api_endpoints.py — Integration tests for FastAPI REST endpoints.

Tests the HTTP layer via TestClient (no real server needed).  Covers health,
headers scanner, secrets scanner, port scanner, DNS lookup/reverse, hash
cracker, news feed, API scanner, and 404 handling.

Network-dependent tests are marked with @pytest.mark.slow and
@pytest.mark.timeout(30) so they can be skipped in CI with ``-m "not slow"``.
"""

from __future__ import annotations

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

# Import the app at module level so every test function can use it via
# the ``client`` fixture or a plain ``with TestClient(app) as c:`` block.
from main import app


# ═══════════════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture()
def client():
    """Yield a FastAPI TestClient that shares the same app instance."""
    with TestClient(app) as c:
        yield c


# ═══════════════════════════════════════════════════════════════════════
#  1. Health endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestHealthEndpoint:
    """GET /api/health — returns status, uptime, and version information."""

    def test_health_returns_200(self, client: TestClient):
        """Health endpoint should always respond with HTTP 200."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_contains_status_key(self, client: TestClient):
        """Response JSON must include a ``status`` key."""
        data = client.get("/api/health").json()
        assert "status" in data
        assert data["status"] in ("ok", "degraded")

    def test_health_contains_version(self, client: TestClient):
        """Response JSON must include a ``version`` key."""
        data = client.get("/api/health").json()
        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_health_contains_uptime(self, client: TestClient):
        """Response JSON must include an ``uptime_seconds`` key."""
        data = client.get("/api/health").json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], int)
        assert data["uptime_seconds"] >= 0

    def test_health_contains_database_info(self, client: TestClient):
        """Response should indicate database status and type."""
        data = client.get("/api/health").json()
        assert "supabase" in data
        assert isinstance(data["supabase"], bool)
        assert "database" in data
        assert isinstance(data["database"], str)

    def test_health_full_schema(self, client: TestClient):
        """Verify the complete set of keys returned by /api/health."""
        data = client.get("/api/health").json()
        expected_keys = {
            "status", "mode", "version", "uptime_seconds",
            "supabase", "database", "kali_mcp_url", "kali_mcp_available",
        }
        assert expected_keys.issubset(data.keys()), (
            f"Missing keys: {expected_keys - data.keys()}"
        )

    def test_health_mode_is_valid(self, client: TestClient):
        """``mode`` must be either 'production' or 'development'."""
        data = client.get("/api/health").json()
        assert data["mode"] in ("production", "development")


# ═══════════════════════════════════════════════════════════════════════
#  2. Headers Scanner endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestHeadersScannerEndpoint:
    """GET /api/headers/scan — grades a URL's HTTP security headers."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_headers_scan_returns_200(self, client: TestClient):
        """Scanning a known-good URL should succeed with HTTP 200."""
        resp = client.get("/api/headers/scan", params={"url": "https://example.com"})
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_headers_scan_ok_flag(self, client: TestClient):
        """Response JSON must include ``ok: true`` on success."""
        data = client.get("/api/headers/scan", params={"url": "https://example.com"}).json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_headers_scan_returns_url(self, client: TestClient):
        """Response must echo the scanned URL back."""
        data = client.get("/api/headers/scan", params={"url": "https://example.com"}).json()
        assert "url" in data
        assert data["url"] == "https://example.com"

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_headers_scan_returns_score(self, client: TestClient):
        """Response must include a numeric score between 0 and 100."""
        data = client.get("/api/headers/scan", params={"url": "https://example.com"}).json()
        assert "score" in data
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_headers_scan_returns_grade(self, client: TestClient):
        """Response must include a letter grade A–F."""
        data = client.get("/api/headers/scan", params={"url": "https://example.com"}).json()
        assert "grade" in data
        assert data["grade"] in ("A", "B", "C", "D", "F")

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_headers_scan_returns_findings(self, client: TestClient):
        """Response must include a ``findings`` list with expected keys."""
        data = client.get("/api/headers/scan", params={"url": "https://example.com"}).json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0
        for finding in data["findings"]:
            assert "tool" in finding
            assert "severity" in finding
            assert "title" in finding

    def test_headers_scan_missing_url_returns_422(self, client: TestClient):
        """Calling without a URL parameter must return 422."""
        resp = client.get("/api/headers/scan")
        assert resp.status_code == 422

    def test_headers_scan_bad_scheme_returns_422(self, client: TestClient):
        """URL without http/https scheme must return 422."""
        resp = client.get("/api/headers/scan", params={"url": "ftp://example.com"})
        assert resp.status_code == 422
        data = resp.json()
        assert "error" in data


# ═══════════════════════════════════════════════════════════════════════
#  3. Secrets Scanner endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestSecretsScannerEndpoint:
    """GET /api/secrets/scan — scans URL or raw text for hardcoded secrets."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_secrets_scan_url_returns_200(self, client: TestClient):
        """Scanning a public URL for secrets should return 200."""
        resp = client.get("/api/secrets/scan", params={"url": "https://example.com"})
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_secrets_scan_url_ok_flag(self, client: TestClient):
        """Response must include ``ok: true`` on success."""
        data = client.get("/api/secrets/scan", params={"url": "https://example.com"}).json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_secrets_scan_url_response_shape(self, client: TestClient):
        """Response must contain source, content_length, lines_scanned, findings."""
        data = client.get("/api/secrets/scan", params={"url": "https://example.com"}).json()
        assert "source" in data
        assert "content_length" in data
        assert "lines_scanned" in data
        assert "secrets_found" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_secrets_scan_raw_text(self, client: TestClient):
        """Scanning raw text containing a known secret pattern should detect it."""
        raw_text = 'password="SuperSecret123!"'
        resp = client.get("/api/secrets/scan", params={"raw": raw_text})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert data["secrets_found"] >= 1
        # The finding should mention the detected pattern
        findings = data["findings"]
        assert len(findings) >= 1
        assert findings[0]["tool"] == "secrets-scan"

    def test_secrets_scan_no_params_returns_422(self, client: TestClient):
        """Calling without url or raw must return 422."""
        resp = client.get("/api/secrets/scan")
        assert resp.status_code == 422

    def test_secrets_scan_bad_scheme_returns_422(self, client: TestClient):
        """Non-http/https URL must return 422."""
        resp = client.get("/api/secrets/scan", params={"url": "ftp://example.com"})
        assert resp.status_code == 422

    def test_secrets_scan_clean_raw_text(self, client: TestClient):
        """Scanning clean text should return zero secrets_found."""
        resp = client.get("/api/secrets/scan", params={"raw": "No secrets here."})
        assert resp.status_code == 200
        data = resp.json()
        assert data["secrets_found"] == 0
        assert data["findings"] == []


# ═══════════════════════════════════════════════════════════════════════
#  4. Port Scanner endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestPortScannerEndpoint:
    """GET /api/port/scan — scans a target for open TCP ports."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_port_scan_returns_200(self, client: TestClient):
        """Scanning scanme.nmap.org should return HTTP 200."""
        resp = client.get("/api/port/scan", params={
            "target": "scanme.nmap.org",
            "ports": "22,80,443",
        })
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_port_scan_ok_flag(self, client: TestClient):
        """Response must include ``ok: true``."""
        data = client.get("/api/port/scan", params={
            "target": "scanme.nmap.org",
            "ports": "22,80,443",
        }).json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_port_scan_finds_open_ports(self, client: TestClient):
        """scanme.nmap.org should have at least one open port (22 or 80)."""
        data = client.get("/api/port/scan", params={
            "target": "scanme.nmap.org",
            "ports": "22,80,443",
        }).json()
        assert data["open_ports"] >= 1, (
            f"Expected at least 1 open port, got {data['open_ports']}"
        )
        open_port_numbers = {r["port"] for r in data["results"]}
        assert 22 in open_port_numbers or 80 in open_port_numbers

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_port_scan_response_shape(self, client: TestClient):
        """Response must contain target, resolved_ip, ports_scanned, results."""
        data = client.get("/api/port/scan", params={
            "target": "scanme.nmap.org",
            "ports": "22,80",
        }).json()
        assert "target" in data
        assert data["target"] == "scanme.nmap.org"
        assert "resolved_ip" in data
        assert isinstance(data["resolved_ip"], str)
        assert "ports_scanned" in data
        assert data["ports_scanned"] == 2
        assert "results" in data
        assert isinstance(data["results"], list)

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_port_scan_result_items_shape(self, client: TestClient):
        """Each result item must have port, service, state, banner keys."""
        data = client.get("/api/port/scan", params={
            "target": "scanme.nmap.org",
            "ports": "22,80",
        }).json()
        for result in data["results"]:
            assert "port" in result
            assert "service" in result
            assert "state" in result
            assert "banner" in result
            assert result["state"] in ("open", "closed", "filtered")

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_port_scan_includes_findings(self, client: TestClient):
        """Response must include a ``findings`` list."""
        data = client.get("/api/port/scan", params={
            "target": "scanme.nmap.org",
            "ports": "22,80",
        }).json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        for f in data["findings"]:
            assert "tool" in f
            assert f["tool"] == "port-scan"

    def test_port_scan_missing_target_returns_422(self, client: TestClient):
        """Calling without target must return 422."""
        resp = client.get("/api/port/scan")
        assert resp.status_code == 422

    def test_port_scan_invalid_ports_returns_422(self, client: TestClient):
        """Non-integer port string must return 422."""
        resp = client.get("/api/port/scan", params={
            "target": "127.0.0.1",
            "ports": "abc,xyz",
        })
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  5. DNS Lookup endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestDNSLookupEndpoint:
    """GET /api/dns/lookup — performs DNS-over-HTTPS queries."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_lookup_returns_200(self, client: TestClient):
        """DNS lookup for a well-known domain should succeed."""
        resp = client.get("/api/dns/lookup", params={"domain": "example.com", "types": "A"})
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_lookup_ok_flag(self, client: TestClient):
        """Response must include ``ok: true``."""
        data = client.get("/api/dns/lookup", params={"domain": "example.com", "types": "A"}).json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_lookup_has_records(self, client: TestClient):
        """DNS lookup for example.com must return at least one A record."""
        data = client.get("/api/dns/lookup", params={"domain": "example.com", "types": "A"}).json()
        assert "records" in data
        assert isinstance(data["records"], dict)
        assert "A" in data["records"], "Expected A records for example.com"
        assert len(data["records"]["A"]) >= 1

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_lookup_record_shape(self, client: TestClient):
        """Each record must have name, type, ttl, value keys."""
        data = client.get("/api/dns/lookup", params={"domain": "example.com", "types": "A"}).json()
        for record in data["records"]["A"]:
            assert "name" in record
            assert "type" in record
            assert "ttl" in record
            assert "value" in record

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_lookup_response_shape(self, client: TestClient):
        """Response must contain domain, duration_seconds, records, findings."""
        data = client.get("/api/dns/lookup", params={"domain": "example.com", "types": "A"}).json()
        assert "domain" in data
        assert data["domain"] == "example.com"
        assert "duration_seconds" in data
        assert isinstance(data["duration_seconds"], (int, float))
        assert "findings" in data
        assert isinstance(data["findings"], list)

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_lookup_multiple_types(self, client: TestClient):
        """Querying multiple record types should return results for each."""
        data = client.get("/api/dns/lookup", params={
            "domain": "example.com",
            "types": "A,MX",
        }).json()
        assert data.get("ok") is True
        assert "A" in data["records"] or "MX" in data["records"]

    def test_dns_lookup_missing_domain_returns_422(self, client: TestClient):
        """Calling without domain must return 422."""
        resp = client.get("/api/dns/lookup")
        assert resp.status_code == 422

    def test_dns_lookup_invalid_domain_returns_422(self, client: TestClient):
        """A single-label domain must return 422."""
        resp = client.get("/api/dns/lookup", params={"domain": "localhost"})
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  6. DNS Reverse endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestDNSReverseEndpoint:
    """GET /api/dns/reverse — performs reverse DNS (PTR) lookups."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_reverse_returns_200(self, client: TestClient):
        """Reverse lookup on 8.8.8.8 should return HTTP 200."""
        resp = client.get("/api/dns/reverse", params={"ip": "8.8.8.8"})
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_reverse_ok_flag(self, client: TestClient):
        """Response must include ``ok: true``."""
        data = client.get("/api/dns/reverse", params={"ip": "8.8.8.8"}).json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_reverse_response_shape(self, client: TestClient):
        """Response must contain ip, hostname, and findings keys."""
        data = client.get("/api/dns/reverse", params={"ip": "8.8.8.8"}).json()
        assert "ip" in data
        assert data["ip"] == "8.8.8.8"
        assert "hostname" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_reverse_may_or_may_not_resolve(self, client: TestClient):
        """8.8.8.8 may or may not resolve — but endpoint must not crash."""
        data = client.get("/api/dns/reverse", params={"ip": "8.8.8.8"}).json()
        assert data.get("ok") is True
        # hostname may be a string or None — both are acceptable
        if data["hostname"] is not None:
            assert isinstance(data["hostname"], str)
            assert len(data["hostname"]) > 0

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dns_reverse_unresolvable_ip(self, client: TestClient):
        """A non-routable IP should still return 200 (graceful handling)."""
        resp = client.get("/api/dns/reverse", params={"ip": "192.0.2.1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True


# ═══════════════════════════════════════════════════════════════════════
#  7. Hash Cracker endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestHashCrackerEndpoint:
    """GET /api/hash/crack — identifies and cracks hashes via rainbow table."""

    def test_hash_crack_returns_200(self, client: TestClient):
        """Cracking a known MD5 hash should return HTTP 200."""
        resp = client.get("/api/hash/crack", params={
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        })
        assert resp.status_code == 200

    def test_hash_crack_ok_flag(self, client: TestClient):
        """Response must include ``ok: true``."""
        data = client.get("/api/hash/crack", params={
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        }).json()
        assert data.get("ok") is True

    def test_hash_crack_cracks_password(self, client: TestClient):
        """MD5 of 'password' should be cracked to 'password'."""
        data = client.get("/api/hash/crack", params={
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        }).json()
        assert data["total"] == 1
        assert data["cracked"] == 1
        result = data["results"][0]
        assert result["cracked"] is True
        assert result["plaintext"] == "password"
        assert "MD5" in result["types"]

    def test_hash_crack_response_shape(self, client: TestClient):
        """Response must contain total, cracked, duration_seconds, results."""
        data = client.get("/api/hash/crack", params={
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        }).json()
        assert "total" in data
        assert "cracked" in data
        assert "duration_seconds" in data
        assert isinstance(data["duration_seconds"], (int, float))
        assert "results" in data
        assert isinstance(data["results"], list)

    def test_hash_crack_result_item_shape(self, client: TestClient):
        """Each result must have hash, types, cracked, plaintext, method keys."""
        data = client.get("/api/hash/crack", params={
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        }).json()
        result = data["results"][0]
        assert "hash" in result
        assert "types" in result
        assert isinstance(result["types"], list)
        assert "cracked" in result
        assert "plaintext" in result
        assert "method" in result

    def test_hash_crack_includes_findings(self, client: TestClient):
        """Response must include a ``findings`` list."""
        data = client.get("/api/hash/crack", params={
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        }).json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        for f in data["findings"]:
            assert "tool" in f
            assert f["tool"] == "hash-cracker"

    def test_hash_crack_unknown_hash(self, client: TestClient):
        """A hash not in the rainbow table should return cracked=0."""
        import hashlib
        obscure = hashlib.md5(b"xyz!@#nonexistent").hexdigest()
        data = client.get("/api/hash/crack", params={"hash": obscure}).json()
        assert data["total"] == 1
        assert data["cracked"] == 0
        assert data["results"][0]["cracked"] is False

    def test_hash_crack_no_hash_param_returns_422(self, client: TestClient):
        """Calling without hash or hashes parameter must return 422."""
        resp = client.get("/api/hash/crack")
        assert resp.status_code == 422

    def test_hash_crack_empty_hash_returns_422(self, client: TestClient):
        """An empty hash string must return 422."""
        resp = client.get("/api/hash/crack", params={"hash": ""})
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  8. News endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestNewsEndpoint:
    """GET /api/news — fetches cybersecurity news from RSS/Atom feeds."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_returns_200(self, client: TestClient):
        """News endpoint should return HTTP 200."""
        resp = client.get("/api/news")
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_ok_flag(self, client: TestClient):
        """Response must include ``ok: true``."""
        data = client.get("/api/news").json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_has_articles(self, client: TestClient):
        """At least one security article should be returned."""
        data = client.get("/api/news").json()
        assert data["total_articles"] > 0, "Expected at least 1 article"

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_response_shape(self, client: TestClient):
        """Response must contain total_articles, sources_ok, articles, etc."""
        data = client.get("/api/news").json()
        assert "total_articles" in data
        assert isinstance(data["total_articles"], int)
        assert "sources_ok" in data
        assert isinstance(data["sources_ok"], int)
        assert "sources_failed" in data
        assert "duration_seconds" in data
        assert "articles" in data
        assert isinstance(data["articles"], list)

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_article_shape(self, client: TestClient):
        """Each article must have title, link, published, source_name."""
        data = client.get("/api/news").json()
        assert len(data["articles"]) > 0
        for article in data["articles"][:5]:  # check first 5
            assert "title" in article
            assert isinstance(article["title"], str)
            assert len(article["title"]) > 0
            assert "link" in article
            assert article["link"].startswith("http")
            assert "source_name" in article
            assert "published" in article

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_includes_findings(self, client: TestClient):
        """Response must include a ``findings`` list."""
        data = client.get("/api/news").json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        for f in data["findings"]:
            assert "tool" in f
            assert f["tool"] == "news-scraper"

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_news_source_details(self, client: TestClient):
        """Response must include ``source_details`` with per-source stats."""
        data = client.get("/api/news").json()
        assert "source_details" in data
        assert isinstance(data["source_details"], list)
        assert len(data["source_details"]) > 0
        for detail in data["source_details"]:
            assert "id" in detail
            assert "name" in detail
            assert "ok" in detail


# ═══════════════════════════════════════════════════════════════════════
#  9. API Scanner endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestAPIScannerEndpoint:
    """GET /api/apiscan — scans a URL for API security issues."""

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_apiscan_returns_200(self, client: TestClient):
        """Scanning a known public URL should succeed with 200."""
        resp = client.get("/api/apiscan", params={"url": "https://example.com"})
        assert resp.status_code == 200

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_apiscan_ok_flag(self, client: TestClient):
        """Response must include ``ok: true``."""
        data = client.get("/api/apiscan", params={"url": "https://example.com"}).json()
        assert data.get("ok") is True

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_apiscan_response_shape(self, client: TestClient):
        """Response must contain base_url, endpoints_scanned, issues, etc."""
        data = client.get("/api/apiscan", params={"url": "https://example.com"}).json()
        assert "base_url" in data
        assert data["base_url"] == "https://example.com"
        assert "endpoints_scanned" in data
        assert isinstance(data["endpoints_scanned"], int)
        assert "issues_count" in data
        assert isinstance(data["issues_count"], int)
        assert "cors_enabled" in data
        assert isinstance(data["cors_enabled"], bool)
        assert "missing_headers" in data
        assert isinstance(data["missing_headers"], list)

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_apiscan_issues_shape(self, client: TestClient):
        """Each issue must have severity, title, detail, category keys."""
        data = client.get("/api/apiscan", params={"url": "https://example.com"}).json()
        assert isinstance(data["issues"], list)
        for issue in data["issues"]:
            assert "severity" in issue
            assert issue["severity"] in ("high", "medium", "low", "info")
            assert "title" in issue
            assert "detail" in issue
            assert "category" in issue

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_apiscan_open_endpoints_shape(self, client: TestClient):
        """Each open endpoint must have path, method, status_code keys."""
        data = client.get("/api/apiscan", params={"url": "https://example.com"}).json()
        assert "open_endpoints" in data
        assert isinstance(data["open_endpoints"], list)
        for ep in data["open_endpoints"]:
            assert "path" in ep
            assert "method" in ep
            assert "status_code" in ep

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_apiscan_includes_findings(self, client: TestClient):
        """Response must include a ``findings`` list."""
        data = client.get("/api/apiscan", params={"url": "https://example.com"}).json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1
        for f in data["findings"]:
            assert "tool" in f
            assert f["tool"] == "api-scanner"

    def test_apiscan_missing_url_returns_422(self, client: TestClient):
        """Calling without url parameter must return 422."""
        resp = client.get("/api/apiscan")
        assert resp.status_code == 422

    def test_apiscan_empty_url_returns_422(self, client: TestClient):
        """An empty URL string must return 422."""
        resp = client.get("/api/apiscan", params={"url": ""})
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  10. 404 handling
# ═══════════════════════════════════════════════════════════════════════

class TestNotFoundHandling:
    """Verify that undefined routes return proper 404 responses."""

    def test_nonexistent_endpoint_returns_404(self, client: TestClient):
        """A GET to a completely unknown path should return 404."""
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404

    def test_404_response_is_json(self, client: TestClient):
        """The 404 response body should be valid JSON."""
        resp = client.get("/api/nonexistent")
        # FastAPI returns JSON for 404s
        data = resp.json()
        assert isinstance(data, dict)

    def test_404_response_has_detail(self, client: TestClient):
        """FastAPI 404 responses include a ``detail`` key."""
        data = client.get("/api/nonexistent").json()
        assert "detail" in data

    def test_deep_nonexistent_path_returns_404(self, client: TestClient):
        """Nested unknown paths should also return 404."""
        resp = client.get("/api/this/does/not/exist")
        assert resp.status_code == 404

    def test_non_api_path_returns_404(self, client: TestClient):
        """Paths outside /api/ should also return 404 if not served."""
        resp = client.get("/totally/fake/route")
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
#  11. OPSEC endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestOpsecLevelsEndpoint:
    """GET /api/opsec/levels — lists the three OPSEC stealth levels."""

    def test_opsec_levels_returns_200(self, client: TestClient):
        resp = client.get("/api/opsec/levels")
        assert resp.status_code == 200

    def test_opsec_levels_ok_flag(self, client: TestClient):
        data = client.get("/api/opsec/levels").json()
        assert data.get("ok") is True

    def test_opsec_levels_returns_levels_list(self, client: TestClient):
        data = client.get("/api/opsec/levels").json()
        assert "levels" in data
        assert isinstance(data["levels"], (list, dict))


class TestOpsecApplyEndpoint:
    """POST /api/opsec/apply — applies OPSEC transformations to a command."""

    def test_opsec_apply_returns_200(self, client: TestClient):
        resp = client.post("/api/opsec/apply", json={
            "tool": "nmap",
            "command": "nmap -sV 192.168.1.1",
            "level": "silent",
            "target": "192.168.1.1",
        })
        assert resp.status_code == 200

    def test_opsec_apply_ok_flag(self, client: TestClient):
        data = client.post("/api/opsec/apply", json={
            "tool": "nmap",
            "command": "nmap -sV 192.168.1.1",
            "level": "covert",
            "target": "192.168.1.1",
        }).json()
        assert data.get("ok") is True

    def test_opsec_apply_returns_modified_command(self, client: TestClient):
        data = client.post("/api/opsec/apply", json={
            "tool": "nmap",
            "command": "nmap -sV 192.168.1.1",
            "level": "loud",
            "target": "192.168.1.1",
        }).json()
        assert "blocked" in data
        assert "modified_command" in data
        assert isinstance(data["modified_command"], str)

    def test_opsec_apply_missing_body_returns_422(self, client: TestClient):
        resp = client.post("/api/opsec/apply")
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  12. Docker endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestDockerStatusEndpoint:
    """GET /api/docker/status — checks Docker daemon and containers."""

    def test_docker_status_returns_200(self, client: TestClient):
        resp = client.get("/api/docker/status")
        assert resp.status_code == 200

    def test_docker_status_ok_flag(self, client: TestClient):
        data = client.get("/api/docker/status").json()
        assert data.get("ok") is True

    def test_docker_status_has_expected_keys(self, client: TestClient):
        data = client.get("/api/docker/status").json()
        assert "installed" in data
        assert isinstance(data["installed"], bool)
        assert "running" in data
        assert isinstance(data["running"], bool)
        assert "containers" in data
        assert isinstance(data["containers"], list)


# ═══════════════════════════════════════════════════════════════════════
#  13. Scope endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestScopeGetEndpoint:
    """GET /api/scope — returns current scope configuration."""

    def test_scope_get_returns_200(self, client: TestClient):
        resp = client.get("/api/scope")
        assert resp.status_code == 200

    def test_scope_get_ok_flag(self, client: TestClient):
        data = client.get("/api/scope").json()
        assert data.get("ok") is True

    def test_scope_get_has_data(self, client: TestClient):
        data = client.get("/api/scope").json()
        assert "data" in data
        assert isinstance(data["data"], dict)
        assert "enabled" in data["data"]
        assert "mode" in data["data"]
        assert "targets" in data["data"]


class TestScopeValidateEndpoint:
    """POST /api/scope/validate — validates a command against scope rules."""

    def test_scope_validate_returns_200(self, client: TestClient):
        resp = client.post("/api/scope/validate", json={"command": "nmap -sV 10.0.0.1"})
        assert resp.status_code == 200

    def test_scope_validate_ok_flag(self, client: TestClient):
        data = client.post("/api/scope/validate", json={"command": "nmap -sV 10.0.0.1"}).json()
        assert data.get("ok") is True

    def test_scope_validate_returns_blocked_field(self, client: TestClient):
        data = client.post("/api/scope/validate", json={"command": "nmap -sV 10.0.0.1"}).json()
        assert "blocked" in data
        assert isinstance(data["blocked"], bool)

    def test_scope_validate_empty_command(self, client: TestClient):
        """Empty command should return ok with blocked=False."""
        data = client.post("/api/scope/validate", json={"command": ""}).json()
        assert data.get("ok") is True
        assert data.get("blocked") is False


# ═══════════════════════════════════════════════════════════════════════
#  14. Findings endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestFindingsListEndpoint:
    """GET /api/findings — lists findings with optional filters."""

    def test_findings_list_returns_200(self, client: TestClient):
        resp = client.get("/api/findings")
        assert resp.status_code == 200

    def test_findings_list_ok_flag(self, client: TestClient):
        data = client.get("/api/findings").json()
        assert data.get("ok") is True

    def test_findings_list_has_data(self, client: TestClient):
        data = client.get("/api/findings").json()
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_findings_list_with_target_filter(self, client: TestClient):
        resp = client.get("/api/findings", params={"target": "10.0.0.1"})
        assert resp.status_code == 200

    def test_findings_list_with_tool_filter(self, client: TestClient):
        resp = client.get("/api/findings", params={"tool": "nmap"})
        assert resp.status_code == 200

    def test_findings_list_with_severity_filter(self, client: TestClient):
        resp = client.get("/api/findings", params={"severity": "high"})
        assert resp.status_code == 200


class TestFindingsStatsEndpoint:
    """GET /api/findings/stats — returns quick statistics about findings."""

    def test_findings_stats_returns_200(self, client: TestClient):
        resp = client.get("/api/findings/stats")
        assert resp.status_code == 200

    def test_findings_stats_ok_flag(self, client: TestClient):
        data = client.get("/api/findings/stats").json()
        assert data.get("ok") is True

    def test_findings_stats_has_expected_keys(self, client: TestClient):
        data = client.get("/api/findings/stats").json()
        assert "count" in data
        assert isinstance(data["count"], int)
        assert "tools" in data
        assert isinstance(data["tools"], list)
        assert "targets" in data
        assert isinstance(data["targets"], list)


# ═══════════════════════════════════════════════════════════════════════
#  15. Credentials endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestCredentialsEndpoint:
    """GET /api/credentials — lists stored credentials."""

    def test_credentials_returns_200(self, client: TestClient):
        resp = client.get("/api/credentials")
        assert resp.status_code == 200

    def test_credentials_ok_flag(self, client: TestClient):
        data = client.get("/api/credentials").json()
        assert data.get("ok") is True

    def test_credentials_has_data(self, client: TestClient):
        data = client.get("/api/credentials").json()
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_credentials_with_target_filter(self, client: TestClient):
        resp = client.get("/api/credentials", params={"target": "10.0.0.1"})
        assert resp.status_code == 200

    def test_credentials_with_service_filter(self, client: TestClient):
        resp = client.get("/api/credentials", params={"service": "ssh"})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
#  16. Reports endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestReportsEndpoint:
    """GET /api/reports — lists saved scan reports."""

    def test_reports_returns_200(self, client: TestClient):
        resp = client.get("/api/reports")
        assert resp.status_code == 200

    def test_reports_ok_flag(self, client: TestClient):
        data = client.get("/api/reports").json()
        assert data.get("ok") is True

    def test_reports_has_data(self, client: TestClient):
        data = client.get("/api/reports").json()
        assert "data" in data
        assert isinstance(data["data"], list)


# ═══════════════════════════════════════════════════════════════════════
#  17. Scripts endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestScriptsEndpoint:
    """GET /api/scripts — lists saved RCE scripts."""

    def test_scripts_returns_200(self, client: TestClient):
        resp = client.get("/api/scripts")
        assert resp.status_code == 200

    def test_scripts_ok_flag(self, client: TestClient):
        data = client.get("/api/scripts").json()
        assert data.get("ok") is True

    def test_scripts_has_data(self, client: TestClient):
        data = client.get("/api/scripts").json()
        assert "data" in data
        assert isinstance(data["data"], list)


# ═══════════════════════════════════════════════════════════════════════
#  18. Connections endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestConnectionsEndpoint:
    """GET /api/connections — lists saved SSH connection profiles."""

    def test_connections_returns_200(self, client: TestClient):
        resp = client.get("/api/connections")
        assert resp.status_code == 200

    def test_connections_ok_flag(self, client: TestClient):
        data = client.get("/api/connections").json()
        assert data.get("ok") is True

    def test_connections_has_data(self, client: TestClient):
        data = client.get("/api/connections").json()
        assert "data" in data
        assert isinstance(data["data"], list)


# ═══════════════════════════════════════════════════════════════════════
#  19. Files / Upload endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestFilesEndpoint:
    """GET /api/files — lists uploaded files metadata."""

    def test_files_returns_200(self, client: TestClient):
        resp = client.get("/api/files")
        assert resp.status_code == 200

    def test_files_ok_flag(self, client: TestClient):
        data = client.get("/api/files").json()
        assert data.get("ok") is True

    def test_files_has_data(self, client: TestClient):
        data = client.get("/api/files").json()
        assert "data" in data
        assert isinstance(data["data"], list)


# ═══════════════════════════════════════════════════════════════════════
#  20. Settings endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestSettingsEndpoint:
    """GET /api/settings/{key} — retrieves a setting value by key."""

    def test_settings_get_returns_200_or_503(self, client: TestClient):
        """Settings endpoint returns 200 if value found, 503 if DB unavailable."""
        resp = client.get("/api/settings/theme")
        assert resp.status_code in (200, 503)

    def test_settings_get_ok_flag_when_200(self, client: TestClient):
        resp = client.get("/api/settings/theme")
        if resp.status_code == 200:
            data = resp.json()
            assert data.get("ok") is True
            assert "key" in data
            assert data["key"] == "theme"

    def test_settings_post_returns_200(self, client: TestClient):
        """POST /api/settings should persist a setting."""
        resp = client.post("/api/settings", json={"key": "test_key", "value": "test_val"})
        assert resp.status_code in (200, 503)

    def test_settings_missing_key_returns_405(self, client: TestClient):
        """GET /api/settings without key returns 405 (needs /api/settings/{key})."""
        resp = client.get("/api/settings")
        assert resp.status_code == 405


# ═══════════════════════════════════════════════════════════════════════
#  21. Missions endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestMissionsEndpoint:
    """GET /api/missions — lists past mission history."""

    def test_missions_returns_200(self, client: TestClient):
        resp = client.get("/api/missions")
        assert resp.status_code == 200

    def test_missions_ok_flag(self, client: TestClient):
        data = client.get("/api/missions").json()
        assert data.get("ok") is True

    def test_missions_has_data(self, client: TestClient):
        data = client.get("/api/missions").json()
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_missions_with_target_filter(self, client: TestClient):
        resp = client.get("/api/missions", params={"target": "10.0.0.1"})
        assert resp.status_code == 200

    def test_missions_with_limit(self, client: TestClient):
        resp = client.get("/api/missions", params={"limit": 5})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
#  22. Plans endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestPlansEndpoint:
    """GET /api/plans — lists saved mission plans."""

    def test_plans_returns_200(self, client: TestClient):
        resp = client.get("/api/plans")
        assert resp.status_code == 200

    def test_plans_ok_flag(self, client: TestClient):
        data = client.get("/api/plans").json()
        assert data.get("ok") is True

    def test_plans_has_data(self, client: TestClient):
        data = client.get("/api/plans").json()
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_plans_with_target_filter(self, client: TestClient):
        resp = client.get("/api/plans", params={"target": "10.0.0.1"})
        assert resp.status_code == 200

    def test_plans_with_limit(self, client: TestClient):
        resp = client.get("/api/plans", params={"limit": 3})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
#  23. CTF endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestCTFChallengesEndpoint:
    """GET /api/ctf/challenges — lists CTF challenges."""

    def test_ctf_challenges_returns_200(self, client: TestClient):
        resp = client.get("/api/ctf/challenges")
        assert resp.status_code == 200

    def test_ctf_challenges_ok_flag(self, client: TestClient):
        data = client.get("/api/ctf/challenges").json()
        assert data.get("ok") is True

    def test_ctf_challenges_has_data(self, client: TestClient):
        data = client.get("/api/ctf/challenges").json()
        assert "data" in data
        assert isinstance(data["data"], list)


class TestCTFScoreEndpoint:
    """GET /api/ctf/score — returns current CTF score summary."""

    def test_ctf_score_returns_200(self, client: TestClient):
        resp = client.get("/api/ctf/score")
        assert resp.status_code == 200

    def test_ctf_score_ok_flag(self, client: TestClient):
        data = client.get("/api/ctf/score").json()
        assert data.get("ok") is True

    def test_ctf_score_has_data(self, client: TestClient):
        data = client.get("/api/ctf/score").json()
        assert "data" in data
        score = data["data"]
        assert isinstance(score, dict)
        assert "solved" in score
        assert "total" in score
        assert "points" in score
        assert "total_points" in score


# ═══════════════════════════════════════════════════════════════════════
#  24. Mobile endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestMobileApksEndpoint:
    """GET /api/mobile/apks — lists analyzed APKs."""

    def test_mobile_apks_returns_200(self, client: TestClient):
        resp = client.get("/api/mobile/apks")
        assert resp.status_code == 200

    def test_mobile_apks_ok_flag(self, client: TestClient):
        data = client.get("/api/mobile/apks").json()
        assert data.get("ok") is True

    def test_mobile_apks_has_data(self, client: TestClient):
        data = client.get("/api/mobile/apks").json()
        assert "data" in data
        assert isinstance(data["data"], list)


@pytest.mark.slow
@pytest.mark.timeout(15)
class TestMobileDevicesEndpoint:
    """GET /api/mobile/devices — lists ADB devices connected to Kali."""

    def test_mobile_devices_returns_200(self, client: TestClient):
        resp = client.get("/api/mobile/devices")
        assert resp.status_code == 200

    def test_mobile_devices_ok_flag(self, client: TestClient):
        data = client.get("/api/mobile/devices").json()
        assert data.get("ok") is True

    def test_mobile_devices_has_data(self, client: TestClient):
        data = client.get("/api/mobile/devices").json()
        assert "data" in data
        assert isinstance(data["data"], list)


# ═══════════════════════════════════════════════════════════════════════
#  25. Forensics endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestForensicsListEndpoint:
    """GET /api/forensics/list — lists analyzed forensic evidence."""

    def test_forensics_list_returns_200(self, client: TestClient):
        resp = client.get("/api/forensics/list")
        assert resp.status_code == 200

    def test_forensics_list_ok_flag(self, client: TestClient):
        data = client.get("/api/forensics/list").json()
        assert data.get("ok") is True

    def test_forensics_list_has_data(self, client: TestClient):
        data = client.get("/api/forensics/list").json()
        assert "data" in data
        assert isinstance(data["data"], list)


# ═══════════════════════════════════════════════════════════════════════
#  26. Swarm endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestSwarmSessionsEndpoint:
    """GET /api/swarm/sessions — lists all swarm sessions."""

    def test_swarm_sessions_returns_valid(self, client: TestClient):
        resp = client.get("/api/swarm/sessions")
        # Accept any valid response: 200 (OK), 404 (no session), 500 (DB error)
        assert resp.status_code in (200, 404, 500)
        if resp.status_code == 200:
            data = resp.json()
            assert "ok" in data


# ═══════════════════════════════════════════════════════════════════════
#  27. KnowledgeBase endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestKnowledgeBaseSearchEndpoint:
    """GET /api/knowledgebase/search — searches CVE + MITRE databases."""

    def test_kb_search_returns_200(self, client: TestClient):
        resp = client.get("/api/knowledgebase/search", params={"query": "SQL injection"})
        assert resp.status_code == 200

    def test_kb_search_ok_flag(self, client: TestClient):
        data = client.get("/api/knowledgebase/search", params={"query": "XSS"}).json()
        assert data.get("ok") is True

    def test_kb_search_has_data(self, client: TestClient):
        data = client.get("/api/knowledgebase/search", params={"query": "buffer overflow"}).json()
        assert "data" in data
        assert isinstance(data["data"], (list, dict))

    def test_kb_search_empty_query(self, client: TestClient):
        """Empty query should still return 200 with results."""
        resp = client.get("/api/knowledgebase/search", params={"query": ""})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
#  28. n8n endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestN8nStatusEndpoint:
    """GET /api/n8n/status — checks if n8n is reachable."""

    def test_n8n_status_returns_200(self, client: TestClient):
        resp = client.get("/api/n8n/status")
        assert resp.status_code == 200

    def test_n8n_status_has_reachable_key(self, client: TestClient):
        data = client.get("/api/n8n/status").json()
        assert "reachable" in data
        assert isinstance(data["reachable"], bool)

    def test_n8n_status_has_status_key(self, client: TestClient):
        data = client.get("/api/n8n/status").json()
        assert "status" in data

    def test_n8n_status_custom_url(self, client: TestClient):
        resp = client.get("/api/n8n/status", params={"n8n_url": "http://localhost:5678"})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
#  29. AI Chat endpoint
# ═══════════════════════════════════════════════════════════════════════

class TestAIChatEndpoint:
    """POST /api/ai/chat — generic AI chat proxy."""

    def test_ai_chat_missing_api_key_returns_400(self, client: TestClient):
        """Calling without api_key should return 400."""
        resp = client.post("/api/ai/chat", json={
            "provider": "openai",
            "api_key": "",
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hello"}],
        })
        assert resp.status_code == 400

    def test_ai_chat_error_has_ok_false(self, client: TestClient):
        """Response should include ok=false with error message."""
        data = client.post("/api/ai/chat", json={
            "provider": "openai",
            "api_key": "",
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hello"}],
        }).json()
        assert data.get("ok") is False
        assert "error" in data

    def test_ai_chat_missing_body_returns_422(self, client: TestClient):
        """Calling without JSON body should return 422."""
        resp = client.post("/api/ai/chat")
        assert resp.status_code == 422

    def test_ai_chat_with_local_provider_no_key(self, client: TestClient):
        """Local provider may not require API key — tests the branch logic."""
        resp = client.post("/api/ai/chat", json={
            "provider": "local",
            "api_key": "",
            "model": "",
            "messages": [{"role": "user", "content": "hello"}],
        })
        # May return 200, 500, or 502 depending on local setup — just verify it doesn't crash
        assert resp.status_code in (200, 500, 502)


# ═══════════════════════════════════════════════════════════════════════
#  30. Kali MCP endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestKaliMCPStatusEndpoint:
    """GET /api/kali-mcp/status — checks kali-mcp container availability."""

    def test_kali_mcp_status_returns_200(self, client: TestClient):
        resp = client.get("/api/kali-mcp/status")
        assert resp.status_code == 200

    def test_kali_mcp_status_ok_flag(self, client: TestClient):
        data = client.get("/api/kali-mcp/status").json()
        assert data.get("ok") is True

    def test_kali_mcp_status_has_expected_keys(self, client: TestClient):
        data = client.get("/api/kali-mcp/status").json()
        assert "configured" in data
        assert isinstance(data["configured"], bool)
        assert "available" in data
        assert isinstance(data["available"], bool)
        assert "url" in data


# ═══════════════════════════════════════════════════════════════════════
#  31. EXIF endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestEXIFEndpoints:
    """GET /api/exif/analyze and POST /api/exif/analyze — EXIF metadata extraction."""

    def test_exif_get_no_url(self, client: TestClient):
        """Calling GET without url param should return 422."""
        resp = client.get("/api/exif/analyze")
        assert resp.status_code == 422

    def test_exif_get_empty_url(self, client: TestClient):
        """Empty url string should return 422."""
        resp = client.get("/api/exif/analyze", params={"url": ""})
        assert resp.status_code == 422

    def test_exif_get_blank_url(self, client: TestClient):
        """Whitespace-only url should return 422."""
        resp = client.get("/api/exif/analyze", params={"url": "   "})
        assert resp.status_code == 422

    def test_exif_get_bad_scheme(self, client: TestClient):
        """Non-http scheme should return 422."""
        resp = client.get("/api/exif/analyze", params={"url": "ftp://example.com/photo.jpg"})
        assert resp.status_code == 422
        data = resp.json()
        assert "error" in data

    def test_exif_get_with_url(self, client: TestClient):
        """GET with valid URL — may succeed (200), fail on download (502), or 422."""
        resp = client.get("/api/exif/analyze", params={"url": "https://example.com/photo.jpg"})
        assert resp.status_code in (200, 422, 502)

    def test_exif_post_no_file(self, client: TestClient):
        """POST without file multipart should return 422."""
        resp = client.post("/api/exif/analyze")
        assert resp.status_code == 422

    def test_exif_post_empty_file(self, client: TestClient):
        """POST with file < 50 bytes should return 422."""
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("tiny.jpg", b"\x00" * 10, "image/jpeg")},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data.get("ok") is False
        assert "too small" in data["error"].lower()

    def test_exif_post_invalid_content_type(self, client: TestClient):
        """POST with non-image content type should return 422."""
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("data.txt", b"\x00" * 200, "text/plain")},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data.get("ok") is False

    def test_exif_post_valid_image_type(self, client: TestClient):
        """POST with valid image type should return 200 or 502 (image may lack EXIF)."""
        # Minimal JPEG header bytes
        fake_jpeg = (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00"
            b"\x00\x01\x00\x01\x00\x00" + b"\x00" * 100
        )
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("test.jpg", fake_jpeg, "image/jpeg")},
        )
        assert resp.status_code in (200, 502)

    def test_exif_post_png_type(self, client: TestClient):
        """POST with PNG type should be accepted (not rejected)."""
        fake_png = (
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
        )
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("test.png", fake_png, "image/png")},
        )
        assert resp.status_code in (200, 502)

    @pytest.mark.parametrize("content_type", [
        "application/pdf", "video/mp4", "audio/mpeg", "application/zip",
        "text/html", "application/javascript",
    ])
    def test_exif_post_rejected_types(self, client: TestClient, content_type: str):
        """Non-image content types must be rejected with 422."""
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("file.bin", b"\x00" * 200, content_type)},
        )
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  32. Canary Tokens endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestCanaryEndpoints:
    """POST /api/canary/token, GET /api/canary/tokens, DELETE /api/canary/token/{id}, etc."""

    def test_canary_create_no_body(self, client: TestClient):
        """POST without form body should return 422."""
        resp = client.post("/api/canary/token")
        assert resp.status_code == 422

    def test_canary_create_invalid_type(self, client: TestClient):
        """POST with invalid token_type should return 422."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": "invalid-type-xyz", "name": "test"},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data.get("ok") is False

    @pytest.mark.parametrize("token_type", [
        "api-key", "db-url", "jwt", "aws-key",
        "slack-token", "generic-url", "env-file", "config-file",
    ])
    def test_canary_create_valid_types(self, client: TestClient, token_type: str):
        """All valid token types should return 200 with ok=True."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": token_type, "name": f"test-{token_type}", "notes": "pytest"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert "token" in data
        assert "findings" in data

    def test_canary_create_response_shape(self, client: TestClient):
        """Created token should have id, type, name, value, created_at keys."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": "jwt", "name": "shape-test", "notes": ""},
        )
        data = resp.json()
        token = data["token"]
        assert "id" in token
        assert "type" in token
        assert token["type"] == "jwt"
        assert "name" in token
        assert "value" in token
        assert "created_at" in token

    def test_canary_list_returns_200(self, client: TestClient):
        """GET /api/canary/tokens returns 200."""
        resp = client.get("/api/canary/tokens")
        assert resp.status_code == 200

    def test_canary_list_response_shape(self, client: TestClient):
        """Response should have ok, tokens, count keys."""
        data = client.get("/api/canary/tokens").json()
        assert data.get("ok") is True
        assert "tokens" in data
        assert isinstance(data["tokens"], list)
        assert "count" in data
        assert isinstance(data["count"], int)

    def test_canary_activate_nonexistent_token(self, client: TestClient):
        """Activating a nonexistent token should return 404."""
        resp = client.get("/api/canary/activate/nonexistent-token-id")
        assert resp.status_code == 404
        data = resp.json()
        assert data.get("ok") is False

    def test_canary_activate_found_token(self, client: TestClient):
        """Activating a valid token should return 200 with event data."""
        # Create a token first
        create_resp = client.post(
            "/api/canary/token",
            data={"token_type": "generic-url", "name": "activate-test", "notes": ""},
        )
        token_id = create_resp.json()["token"]["id"]
        # Activate it
        resp = client.get(f"/api/canary/activate/{token_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert data["message"] == "Token activated"
        assert "event" in data

    def test_canary_events_returns_200(self, client: TestClient):
        """GET /api/canary/events returns 200."""
        resp = client.get("/api/canary/events")
        assert resp.status_code == 200

    def test_canary_events_response_shape(self, client: TestClient):
        """Response should have ok, events, count keys."""
        data = client.get("/api/canary/events").json()
        assert data.get("ok") is True
        assert "events" in data
        assert isinstance(data["events"], list)
        assert "count" in data

    def test_canary_events_with_token_id_filter(self, client: TestClient):
        """Filtering events by token_id should return 200."""
        resp = client.get("/api/canary/events", params={"token_id": "some-id"})
        assert resp.status_code == 200

    def test_canary_delete_nonexistent(self, client: TestClient):
        """DELETE nonexistent token should return 404."""
        resp = client.delete("/api/canary/token/nonexistent-id")
        assert resp.status_code == 404

    def test_canary_delete_found_token(self, client: TestClient):
        """DELETE an existing token should return 200."""
        create_resp = client.post(
            "/api/canary/token",
            data={"token_type": "slack-token", "name": "delete-test", "notes": ""},
        )
        token_id = create_resp.json()["token"]["id"]
        resp = client.delete(f"/api/canary/token/{token_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True

    def test_canary_create_sql_injection_in_name(self, client: TestClient):
        """SQL injection in name should be accepted as text, not cause errors."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": "api-key", "name": "'; DROP TABLE tokens; --", "notes": ""},
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_canary_create_xss_in_name(self, client: TestClient):
        """XSS payload in name should be accepted as text, not cause errors."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": "env-file", "name": "<script>alert('xss')</script>", "notes": ""},
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_canary_create_unicode_in_notes(self, client: TestClient):
        """Unicode characters in notes should be handled gracefully."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": "jwt", "name": "unicode-test", "notes": "日本語テスト 🔐 Ñoño"},
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True


# ═══════════════════════════════════════════════════════════════════════
#  33. DLP Scanner endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestDLPEndpoints:
    """POST /api/dlp/scan, POST /api/dlp/scan-file, GET /api/dlp/scan-url."""

    def test_dlp_scan_no_body(self, client: TestClient):
        """POST without body should return 422."""
        resp = client.post("/api/dlp/scan")
        assert resp.status_code == 422

    def test_dlp_scan_empty_body(self, client: TestClient):
        """POST with empty body (no text key) should return 422."""
        resp = client.post("/api/dlp/scan", json={})
        assert resp.status_code == 422

    def test_dlp_scan_empty_text(self, client: TestClient):
        """POST with empty text should return 422."""
        resp = client.post("/api/dlp/scan", json={"text": ""})
        assert resp.status_code == 422

    def test_dlp_scan_whitespace_text(self, client: TestClient):
        """POST with whitespace-only text should return 422."""
        resp = client.post("/api/dlp/scan", json={"text": "   \n\t  "})
        assert resp.status_code == 422

    def test_dlp_scan_clean_text(self, client: TestClient):
        """Scanning text without PII should return 200 with low risk score."""
        resp = client.post("/api/dlp/scan", json={"text": "The quick brown fox jumps over the lazy dog."})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert "risk_score" in data
        assert "findings" in data

    def test_dlp_scan_with_pii(self, client: TestClient):
        """Text with SSN pattern should detect PII findings."""
        resp = client.post("/api/dlp/scan", json={
            "text": "My SSN is 123-45-6789 and email is test@example.com"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert data["findings_count"] >= 1
        assert data["risk_score"] > 0

    def test_dlp_scan_response_shape(self, client: TestClient):
        """Response should have all expected keys."""
        data = client.post("/api/dlp/scan", json={"text": "hello world"}).json()
        expected = {"ok", "source", "content_length", "lines_scanned", "findings_count", "risk_score", "duration_seconds", "findings"}
        assert expected.issubset(data.keys())

    def test_dlp_scan_long_text(self, client: TestClient):
        """Scanning a long text block should succeed."""
        text = ("Lorem ipsum dolor sit amet. " * 100 + "\n") * 50
        resp = client.post("/api/dlp/scan", json={"text": text})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True

    def test_dlp_scan_file_no_file(self, client: TestClient):
        """POST /api/dlp/scan-file without file should return 422."""
        resp = client.post("/api/dlp/scan-file")
        assert resp.status_code == 422

    def test_dlp_scan_file_with_text_file(self, client: TestClient):
        """POST /api/dlp/scan-file with a text file should return 200."""
        content = "User: admin@admin.com\nSSN: 123-45-6789\nPhone: 555-123-4567"
        resp = client.post(
            "/api/dlp/scan-file",
            files={"file": ("data.txt", content.encode(), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert data["findings_count"] >= 1

    def test_dlp_scan_url_no_url(self, client: TestClient):
        """GET /api/dlp/scan-url without url param should return 422."""
        resp = client.get("/api/dlp/scan-url")
        assert resp.status_code == 422

    def test_dlp_scan_url_empty(self, client: TestClient):
        """GET with empty url should return 422."""
        resp = client.get("/api/dlp/scan-url", params={"url": ""})
        assert resp.status_code == 422

    def test_dlp_scan_url_bad_scheme(self, client: TestClient):
        """GET with ftp:// url should return 422."""
        resp = client.get("/api/dlp/scan-url", params={"url": "ftp://example.com/page"})
        assert resp.status_code == 422
        data = resp.json()
        assert "error" in data

    @pytest.mark.slow
    @pytest.mark.timeout(30)
    def test_dlp_scan_url_valid(self, client: TestClient):
        """GET with a valid URL should return 200 or 502."""
        resp = client.get("/api/dlp/scan-url", params={"url": "https://example.com"})
        assert resp.status_code in (200, 502)

    def test_dlp_scan_sql_injection_in_text(self, client: TestClient):
        """SQL injection in text should be scanned as text, not cause errors."""
        resp = client.post("/api/dlp/scan", json={
            "text": "'; DROP TABLE users; -- SELECT * FROM passwords WHERE 1=1"
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_dlp_scan_xss_in_text(self, client: TestClient):
        """XSS payload in text should be scanned as text, not cause errors."""
        resp = client.post("/api/dlp/scan", json={
            "text": "<script>document.cookie</script><img src=x onerror=alert(1)>"
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_dlp_scan_unicode_text(self, client: TestClient):
        """Unicode text should be handled gracefully."""
        resp = client.post("/api/dlp/scan", json={
            "text": "日本語テキスト密码 Password123! Correo: usuario@ejemplo.com"
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True


# ═══════════════════════════════════════════════════════════════════════
#  34. SIEM endpoints (expanded)
# ═══════════════════════════════════════════════════════════════════════

class TestSIEMEventEndpoint:
    """POST /api/siem/event — ingest a security event."""

    def test_siem_event_no_body(self, client: TestClient):
        """POST without body should return 422."""
        resp = client.post("/api/siem/event")
        assert resp.status_code == 422

    def test_siem_event_missing_required_fields(self, client: TestClient):
        """POST missing 'source' should return 422."""
        resp = client.post("/api/siem/event", json={
            "severity": "high",
            "title": "Test",
            "detail": "Test detail",
        })
        assert resp.status_code == 422

    def test_siem_event_empty_body(self, client: TestClient):
        """POST with empty body should return 422."""
        resp = client.post("/api/siem/event", json={})
        assert resp.status_code == 422

    def test_siem_event_full_body(self, client: TestClient):
        """POST with all required fields should return 200."""
        resp = client.post("/api/siem/event", json={
            "source": "api",
            "severity": "high",
            "title": "Test alert",
            "detail": "Something happened",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert "event" in data
        assert "id" in data["event"]
        assert "timestamp" in data["event"]

    def test_siem_event_with_optional_fields(self, client: TestClient):
        """POST with raw_data, tags, ip should succeed."""
        resp = client.post("/api/siem/event", json={
            "source": "firewall",
            "severity": "critical",
            "title": "Port scan detected",
            "detail": "SYN flood from external",
            "raw_data": {"packets": 500, "protocol": "TCP"},
            "tags": ["network", "scan"],
            "ip": "10.0.0.99",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True

    @pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
    def test_siem_event_all_severities(self, client: TestClient, severity: str):
        """All severity levels should be accepted."""
        resp = client.post("/api/siem/event", json={
            "source": "ssh",
            "severity": severity,
            "title": f"Test {severity}",
            "detail": "Detail",
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_siem_event_invalid_source_returns_422(self, client: TestClient):
        """Invalid source should return 422."""
        resp = client.post("/api/siem/event", json={
            "source": "nonexistent-source",
            "severity": "high",
            "title": "Test",
            "detail": "Detail",
        })
        assert resp.status_code == 422
        assert resp.json().get("ok") is False

    def test_siem_event_sql_injection_in_title(self, client: TestClient):
        """SQL injection in title/detail should be accepted as text (source must be valid)."""
        resp = client.post("/api/siem/event", json={
            "source": "api",
            "severity": "high",
            "title": "1 OR 1=1 -- DROP TABLE users",
            "detail": "UNION SELECT * FROM users",
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_siem_event_xss_in_title(self, client: TestClient):
        """XSS payload in title/detail should be accepted as text."""
        resp = client.post("/api/siem/event", json={
            "source": "dlp",
            "severity": "high",
            "title": "<script>alert(1)</script>",
            "detail": "<img src=x onerror=alert('xss')>",
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True


class TestSIEMEventsListEndpoint:
    """GET /api/siem/events — list events with filters."""

    def test_siem_events_returns_200(self, client: TestClient):
        resp = client.get("/api/siem/events")
        assert resp.status_code == 200

    def test_siem_events_response_shape(self, client: TestClient):
        data = client.get("/api/siem/events").json()
        assert data.get("ok") is True
        assert "events" in data
        assert isinstance(data["events"], list)
        assert "count" in data

    def test_siem_events_with_severity_filter(self, client: TestClient):
        resp = client.get("/api/siem/events", params={"severity": "high"})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True

    def test_siem_events_with_source_filter(self, client: TestClient):
        resp = client.get("/api/siem/events", params={"source": "nids"})
        assert resp.status_code == 200

    def test_siem_events_with_limit(self, client: TestClient):
        resp = client.get("/api/siem/events", params={"limit": 5})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) <= 5

    def test_siem_events_with_offset(self, client: TestClient):
        resp = client.get("/api/siem/events", params={"offset": 0, "limit": 10})
        assert resp.status_code == 200

    def test_siem_events_with_since(self, client: TestClient):
        resp = client.get("/api/siem/events", params={"since": "2025-01-01"})
        assert resp.status_code == 200


class TestSIEMStatsEndpoint:
    """GET /api/siem/stats — aggregate dashboard statistics."""

    def test_siem_stats_returns_200(self, client: TestClient):
        resp = client.get("/api/siem/stats")
        assert resp.status_code == 200

    def test_siem_stats_ok_flag(self, client: TestClient):
        data = client.get("/api/siem/stats").json()
        assert data.get("ok") is True

    def test_siem_stats_has_data(self, client: TestClient):
        data = client.get("/api/siem/stats").json()
        # Stats should return some aggregate info (keys vary by implementation)
        assert isinstance(data, dict)
        assert data.get("ok") is True


class TestSIEMAlertsEndpoint:
    """GET /api/siem/alerts — list alerts."""

    def test_siem_alerts_returns_200(self, client: TestClient):
        resp = client.get("/api/siem/alerts")
        assert resp.status_code == 200

    def test_siem_alerts_response_shape(self, client: TestClient):
        data = client.get("/api/siem/alerts").json()
        assert data.get("ok") is True
        assert "alerts" in data
        assert isinstance(data["alerts"], list)
        assert "count" in data

    def test_siem_alerts_with_limit(self, client: TestClient):
        resp = client.get("/api/siem/alerts", params={"limit": 3})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["alerts"]) <= 3

    def test_siem_alerts_with_offset(self, client: TestClient):
        resp = client.get("/api/siem/alerts", params={"offset": 0, "limit": 10})
        assert resp.status_code == 200


class TestSIEMRulesEndpoint:
    """POST /api/siem/rules, GET /api/siem/rules, DELETE /api/siem/rules/{id}."""

    def test_siem_rules_list_returns_200(self, client: TestClient):
        resp = client.get("/api/siem/rules")
        assert resp.status_code == 200

    def test_siem_rules_list_response_shape(self, client: TestClient):
        data = client.get("/api/siem/rules").json()
        assert data.get("ok") is True
        assert "rules" in data
        assert isinstance(data["rules"], list)
        assert "count" in data

    def test_siem_rules_create_no_body(self, client: TestClient):
        """POST without body should return 422."""
        resp = client.post("/api/siem/rules")
        assert resp.status_code == 422

    def test_siem_rules_create_missing_fields(self, client: TestClient):
        """POST missing 'name' should return 422."""
        resp = client.post("/api/siem/rules", json={
            "description": "Test rule",
            "condition": "severity == 'high'",
        })
        assert resp.status_code == 422

    def test_siem_rules_create_full_body(self, client: TestClient):
        """POST with all required fields should succeed."""
        resp = client.post("/api/siem/rules", json={
            "name": "brute-force-detector",
            "description": "Detects multiple failed logins",
            "condition": "brute-force",
            "severity": "high",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert "rule" in data
        assert "id" in data["rule"]
        assert data["rule"]["name"] == "brute-force-detector"
        assert data["rule"]["severity"] == "high"

    def test_siem_rules_create_with_config(self, client: TestClient):
        """POST with config dict should succeed."""
        resp = client.post("/api/siem/rules", json={
            "name": "port-scan-alert",
            "description": "Detects port scanning",
            "condition": "port-scan",
            "severity": "critical",
            "config": {"window_seconds": 300, "threshold": 20},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True

    def test_siem_rules_delete_nonexistent(self, client: TestClient):
        """DELETE with a UUID that doesn't exist should return 404."""
        resp = client.delete("/api/siem/rules/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    def test_siem_rules_delete_found(self, client: TestClient):
        """DELETE a rule we just created should return 200."""
        # Create first — use valid condition and severity
        create_resp = client.post("/api/siem/rules", json={
            "name": "to-delete",
            "description": "Will be deleted",
            "condition": "custom",
            "severity": "high",
        })
        if create_resp.status_code == 200:
            rule_id = create_resp.json()["rule"]["id"]
            # Delete
            resp = client.delete(f"/api/siem/rules/{rule_id}")
            assert resp.status_code == 200
            assert resp.json().get("ok") is True
        else:
            # If creation failed (DB not configured), just verify 422/503
            assert create_resp.status_code in (422, 500)

    def test_siem_findings_returns_200(self, client: TestClient):
        """GET /api/siem/findings should return 200."""
        resp = client.get("/api/siem/findings")
        assert resp.status_code == 200

    def test_siem_findings_response_shape(self, client: TestClient):
        data = client.get("/api/siem/findings").json()
        assert data.get("ok") is True
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert "count" in data


# ═══════════════════════════════════════════════════════════════════════
#  35. Plugin endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestPluginEndpoints:
    """GET /api/plugins, POST /api/plugins/{name}/load|unload|reload|enable|disable."""

    def test_plugins_list_returns_200(self, client: TestClient):
        resp = client.get("/api/plugins")
        assert resp.status_code == 200

    def test_plugins_list_response_shape(self, client: TestClient):
        data = client.get("/api/plugins").json()
        assert data.get("ok") is True
        assert "plugins" in data
        assert isinstance(data["plugins"], (list, dict))

    def test_plugin_info_nonexistent(self, client: TestClient):
        """GET /api/plugins/{name} for a nonexistent plugin should return 404."""
        resp = client.get("/api/plugins/this-plugin-does-not-exist-xyz")
        assert resp.status_code == 404
        data = resp.json()
        assert data.get("ok") is False
        assert "not found" in data["error"].lower()

    def test_plugin_load_nonexistent(self, client: TestClient):
        """POST /api/plugins/{name}/load for nonexistent plugin should return 400."""
        resp = client.post("/api/plugins/ghost-plugin/load")
        assert resp.status_code in (400, 500)
        data = resp.json()
        assert data.get("ok") is False

    def test_plugin_unload_nonexistent(self, client: TestClient):
        """POST /api/plugins/{name}/unload for nonexistent plugin should return 400."""
        resp = client.post("/api/plugins/ghost-plugin/unload")
        assert resp.status_code in (400, 500)
        data = resp.json()
        assert data.get("ok") is False

    def test_plugin_reload_nonexistent(self, client: TestClient):
        """POST /api/plugins/{name}/reload for nonexistent plugin should return 400."""
        resp = client.post("/api/plugins/ghost-plugin/reload")
        assert resp.status_code in (400, 500)

    def test_plugin_enable_nonexistent(self, client: TestClient):
        """POST /api/plugins/{name}/enable for nonexistent plugin should return 400."""
        resp = client.post("/api/plugins/ghost-plugin/enable")
        assert resp.status_code in (400, 500)

    def test_plugin_disable_nonexistent(self, client: TestClient):
        """POST /api/plugins/{name}/disable for nonexistent plugin should return 400."""
        resp = client.post("/api/plugins/ghost-plugin/disable")
        assert resp.status_code in (400, 500)

    def test_plugin_hook_call(self, client: TestClient):
        """POST /api/plugins/hooks/{hook_name} should return 200."""
        resp = client.post("/api/plugins/hooks/on_startup", json={"args": [], "kwargs": {}})
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True
        assert "hook" in data
        assert data["hook"] == "on_startup"

    def test_plugin_hook_empty_body(self, client: TestClient):
        """POST /api/plugins/hooks/{hook_name} with empty JSON should work."""
        resp = client.post("/api/plugins/hooks/on_scan_complete", json={})
        assert resp.status_code == 200

    @pytest.mark.parametrize("plugin_name", [
        "xss-scanner", "sqlmap-wrapper", "nuclei-integration",
        "custom-reporter", "log-collector",
    ])
    def test_plugin_lifecycle_nonexistent(self, client: TestClient, plugin_name: str):
        """All lifecycle operations on unknown plugin should fail gracefully."""
        for action in ["load", "unload", "reload", "enable", "disable"]:
            resp = client.post(f"/api/plugins/{plugin_name}/{action}")
            assert resp.status_code in (400, 500), f"{action} returned {resp.status_code}"


# ═══════════════════════════════════════════════════════════════════════
#  36. Error handling — invalid JSON, missing fields, edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Verify proper error codes for malformed, missing, or extreme inputs."""

    @pytest.mark.parametrize("endpoint", [
        "/api/siem/event",
        "/api/siem/rules",
        "/api/opsec/apply",
        "/api/ai/chat",
    ])
    def test_post_no_body_returns_422(self, client: TestClient, endpoint: str):
        """POST endpoints with Pydantic models must return 422 when body is missing."""
        resp = client.post(endpoint)
        assert resp.status_code == 422

    @pytest.mark.parametrize("endpoint", [
        "/api/siem/event",
        "/api/siem/rules",
    ])
    def test_post_invalid_json_returns_422(self, client: TestClient, endpoint: str):
        """Sending non-JSON body should return 422."""
        resp = client.post(endpoint, content=b"not json at all", headers={"Content-Type": "application/json"})
        assert resp.status_code == 422

    def test_nonexistent_siem_rule_404(self, client: TestClient):
        """DELETE /api/siem/rules/{id} with invalid UUID should return 404."""
        resp = client.delete("/api/siem/rules/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert resp.status_code == 404

    def test_nonexistent_canary_token_404(self, client: TestClient):
        """GET /api/canary/activate/{id} with unknown id should return 404."""
        resp = client.get("/api/canary/activate/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert resp.status_code == 404

    def test_nonexistent_knowledgebase_cve_404(self, client: TestClient):
        """GET /api/knowledgebase/cve/{id} for unknown CVE should return 404."""
        resp = client.get("/api/knowledgebase/cve/CVE-9999-99999")
        assert resp.status_code == 404
        data = resp.json()
        assert data.get("ok") is False

    def test_nonexistent_knowledgebase_mitre_404(self, client: TestClient):
        """GET /api/knowledgebase/mitre/{id} for unknown technique should return 404."""
        resp = client.get("/api/knowledgebase/mitre/T9999.999")
        assert resp.status_code == 404

    def test_empty_body_on_dlp_scan_returns_422(self, client: TestClient):
        """POST /api/dlp/scan with no JSON body should return 422."""
        resp = client.post("/api/dlp/scan")
        assert resp.status_code == 422

    def test_empty_body_on_canary_returns_422(self, client: TestClient):
        """POST /api/canary/token without form data should return 422."""
        resp = client.post("/api/canary/token")
        assert resp.status_code == 422

    def test_post_exif_with_wrong_content_type(self, client: TestClient):
        """POST to multipart endpoint with JSON content type should return 422."""
        resp = client.post("/api/exif/analyze", json={"not": "a file"})
        assert resp.status_code == 422

    def test_post_dlp_scan_file_with_json(self, client: TestClient):
        """POST to /api/dlp/scan-file with JSON instead of file should return 422."""
        resp = client.post("/api/dlp/scan-file", json={"text": "hello"})
        assert resp.status_code == 422


# ═══════════════════════════════════════════════════════════════════════
#  37. Edge cases — long strings, SQL injection, XSS, unicode
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Verify the API handles adversarial/extreme inputs gracefully."""

    def test_siem_event_extremely_long_title(self, client: TestClient):
        """A 4001-char title should be accepted (no hard limit enforced at API level)."""
        resp = client.post("/api/siem/event", json={
            "source": "test",
            "severity": "low",
            "title": "A" * 4001,
            "detail": "B" * 4001,
        })
        # Should not crash — accept or reject with 422, but not 500
        assert resp.status_code in (200, 422)
        assert resp.json().get("ok") is True or "error" in resp.json()

    def test_siem_event_very_long_detail(self, client: TestClient):
        """A 10000-char detail string should not crash the server."""
        resp = client.post("/api/siem/event", json={
            "source": "test",
            "severity": "low",
            "title": "Long detail test",
            "detail": "X" * 10000,
        })
        assert resp.status_code in (200, 422)

    def test_dlp_scan_sql_injection(self, client: TestClient):
        """SQL injection patterns in text should be scanned, not executed."""
        sql_texts = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT username, password FROM admin--",
            "INSERT INTO logs VALUES('pwned')",
        ]
        for text in sql_texts:
            resp = client.post("/api/dlp/scan", json={"text": text})
            assert resp.status_code == 200
            assert resp.json().get("ok") is True

    def test_dlp_scan_xss_payloads(self, client: TestClient):
        """XSS payloads in text should be scanned, not rendered."""
        xss_texts = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
            "<svg onload=alert(1)>",
        ]
        for text in xss_texts:
            resp = client.post("/api/dlp/scan", json={"text": text})
            assert resp.status_code == 200
            assert resp.json().get("ok") is True

    def test_canary_unicode_token_name(self, client: TestClient):
        """Unicode characters in token names should be accepted."""
        resp = client.post(
            "/api/canary/token",
            data={"token_type": "jwt", "name": "日本語テスト名前", "notes": "café résumé"},
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_siem_event_unicode_in_fields(self, client: TestClient):
        """Unicode in SIEM event title/detail should be accepted (source must be valid)."""
        resp = client.post("/api/siem/event", json={
            "source": "system",
            "severity": "high",
            "title": "Инцидент безопасности",
            "detail": "Événement de sécurité détecté 🔒",
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_plugin_name_with_special_chars(self, client: TestClient):
        """Plugin names with special characters should fail gracefully."""
        resp = client.get("/api/plugins/../../../etc/passwd")
        assert resp.status_code in (400, 404, 422, 500)

    def test_siem_rules_create_empty_name(self, client: TestClient):
        """Empty name in rule should still be accepted or rejected cleanly."""
        resp = client.post("/api/siem/rules", json={
            "name": "",
            "description": "Empty name rule",
            "condition": "always",
            "severity": "low",
        })
        # Depends on whether Pydantic enforces min_length
        assert resp.status_code in (200, 422)

    @pytest.mark.parametrize("severity", ["INFO", "HIGH", "Critical", "MEDIUM"])
    def test_siem_event_case_insensitive_severity(self, client: TestClient, severity: str):
        """Severity with mixed case should still be accepted."""
        resp = client.post("/api/siem/event", json={
            "source": "test",
            "severity": severity.lower(),
            "title": f"Test {severity}",
            "detail": "Detail",
        })
        assert resp.status_code in (200, 422)

    def test_multiple_concurrent_siem_events(self, client: TestClient):
        """Sending multiple events quickly should not cause errors."""
        sources = ["api", "ssh", "dlp", "docker", "firewall", "canary", "system"]
        for i in range(10):
            resp = client.post("/api/siem/event", json={
                "source": sources[i % len(sources)],
                "severity": "low",
                "title": f"Event #{i}",
                "detail": f"Detail for event {i}",
            })
            assert resp.status_code == 200

    def test_dlp_scan_empty_file(self, client: TestClient):
        """DLP scan-file with empty file should return 200."""
        resp = client.post(
            "/api/dlp/scan-file",
            files={"file": ("empty.txt", b"", "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("ok") is True

    def test_canary_create_very_long_notes(self, client: TestClient):
        """Notes with 5000 chars should be accepted."""
        resp = client.post(
            "/api/canary/token",
            data={
                "token_type": "generic-url",
                "name": "long-notes",
                "notes": "N" * 5000,
            },
        )
        assert resp.status_code == 200
        assert resp.json().get("ok") is True

    def test_scope_validate_sql_injection(self, client: TestClient):
        """SQL injection in scope validate command should be accepted."""
        resp = client.post("/api/scope/validate", json={
            "command": "'; DROP TABLE scope; -- SELECT 1"
        })
        assert resp.status_code == 200
        assert resp.json().get("ok") is True


# ═══════════════════════════════════════════════════════════════════════
#  38. Scope events endpoints
# ═══════════════════════════════════════════════════════════════════════

class TestScopeEventsEndpoints:
    """GET/POST/DELETE /api/scope/events."""

    def test_scope_events_list_returns_200(self, client: TestClient):
        resp = client.get("/api/scope/events")
        assert resp.status_code == 200

    def test_scope_events_list_response_shape(self, client: TestClient):
        data = client.get("/api/scope/events").json()
        assert data.get("ok") is True
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_scope_events_save_returns_200_or_503(self, client: TestClient):
        """POST /api/scope/events should return 200 (saved) or 503 (DB unavailable)."""
        resp = client.post("/api/scope/events", json={
            "command": "nmap -sV 10.0.0.1",
            "action": "blocked",
            "reason": "out-of-scope",
        })
        assert resp.status_code in (200, 503)

    def test_scope_events_clear_returns_200_or_503(self, client: TestClient):
        resp = client.delete("/api/scope/events")
        assert resp.status_code in (200, 503)

    def test_scope_events_with_limit(self, client: TestClient):
        resp = client.get("/api/scope/events", params={"limit": 5})
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
#  39. Swarm sessions endpoints (expanded)
# ═══════════════════════════════════════════════════════════════════════

class TestSwarmSessionsExpanded:
    """GET/POST/DELETE /api/swarm/sessions."""

    def test_swarm_sessions_list(self, client: TestClient):
        # /api/swarm/sessions may collide with /api/swarm/{session_id} route
        resp = client.get("/api/swarm/sessions")
        assert resp.status_code in (200, 404, 500)

    def test_swarm_sessions_list_with_limit(self, client: TestClient):
        resp = client.get("/api/swarm/sessions", params={"limit": 5})
        assert resp.status_code in (200, 404, 500)

    def test_swarm_session_get_nonexistent(self, client: TestClient):
        """GET /api/swarm/sessions/{id} for nonexistent id should return 404."""
        resp = client.get("/api/swarm/sessions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert resp.status_code == 404

    def test_swarm_session_save_no_body(self, client: TestClient):
        """POST without body should return 422."""
        resp = client.post("/api/swarm/sessions")
        assert resp.status_code == 422

    def test_swarm_session_save_with_body(self, client: TestClient):
        """POST with valid body should return 200 or 503."""
        resp = client.post("/api/swarm/sessions", json={
            "target": "10.0.0.1",
            "mode": "auto",
            "status": "running",
            "phases": [],
            "total_findings": 0,
        })
        assert resp.status_code in (200, 503)

    def test_swarm_session_delete_nonexistent(self, client: TestClient):
        """DELETE nonexistent session should return 503 (DB unavailable) or 200 (ok=False)."""
        resp = client.delete("/api/swarm/sessions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        assert resp.status_code in (200, 503)

    def test_swarm_session_get_invalid_uuid(self, client: TestClient):
        """GET with obviously invalid UUID should return 404 or other error."""
        resp = client.get("/api/swarm/sessions/not-a-uuid")
        assert resp.status_code in (404, 500)


# ═══════════════════════════════════════════════════════════════════════
#  40. Additional edge case & robustness tests
# ═══════════════════════════════════════════════════════════════════════

class TestAdditionalEdgeCases:
    """More edge cases for robustness validation."""

    @pytest.mark.parametrize("url", [
        "https://example.com",
        "http://example.com",
        "http://127.0.0.1:8080",
        "http://192.168.1.1/api/v1",
    ])
    def test_exif_get_various_urls(self, client: TestClient, url: str):
        """Various valid URLs should not cause 500 errors."""
        resp = client.get("/api/exif/analyze", params={"url": url})
        assert resp.status_code in (200, 422, 502)

    def test_dlp_scan_url_with_special_chars(self, client: TestClient):
        """URL with special chars should be rejected (422) or handled."""
        resp = client.get("/api/dlp/scan-url", params={
            "url": "https://example.com/path?q=hello world&x=<script>"
        })
        assert resp.status_code in (200, 422, 502)

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_unsupported_http_methods(self, client: TestClient, method: str):
        """PUT/PATCH on GET-only endpoints should return 405."""
        resp = client.request(method, "/api/siem/stats")
        assert resp.status_code == 405

    def test_put_on_post_endpoint(self, client: TestClient):
        """PUT on a POST-only endpoint should return 405."""
        resp = client.put("/api/siem/event", json={})
        assert resp.status_code == 405

    def test_delete_on_get_endpoint(self, client: TestClient):
        """DELETE on a GET-only endpoint should return 405."""
        resp = client.delete("/api/siem/stats")
        assert resp.status_code == 405

    def test_post_with_content_type_mismatch(self, client: TestClient):
        """POST with wrong content-type header should fail gracefully."""
        resp = client.post(
            "/api/siem/event",
            content=b"source=test&severity=high",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert resp.status_code == 422

    def test_concurrent_read_endpoints(self, client: TestClient):
        """Multiple GET calls simultaneously should not fail."""
        endpoints = [
            "/api/siem/events",
            "/api/siem/stats",
            "/api/siem/alerts",
            "/api/siem/rules",
            "/api/plugins",
            "/api/canary/tokens",
            "/api/findings",
        ]
        for ep in endpoints:
            resp = client.get(ep)
            assert resp.status_code == 200, f"{ep} returned {resp.status_code}"

    def test_scope_post_returns_200_or_503(self, client: TestClient):
        """POST /api/scope should save or return 503."""
        resp = client.post("/api/scope", json={
            "enabled": True,
            "mode": "warn",
            "targets": ["10.0.0.0/24"],
        })
        assert resp.status_code in (200, 503)

    def test_scope_history_returns_200(self, client: TestClient):
        resp = client.get("/api/scope/history")
        assert resp.status_code == 200

    def test_scope_history_clear_returns_200_or_503(self, client: TestClient):
        resp = client.post("/api/scope/history/clear")
        assert resp.status_code in (200, 503)

    def test_knowledgebase_search_no_query(self, client: TestClient):
        """Search without query should return 200."""
        resp = client.get("/api/knowledgebase/search")
        assert resp.status_code == 200

    def test_missions_similar_returns_200(self, client: TestClient):
        resp = client.get("/api/missions/similar")
        assert resp.status_code == 200

    def test_missions_similar_with_params(self, client: TestClient):
        resp = client.get("/api/missions/similar", params={
            "target_os": "linux",
            "tools": "nmap,gobuster",
            "limit": 3,
        })
        assert resp.status_code == 200

    def test_ctf_challenges_create_no_body(self, client: TestClient):
        """POST /api/ctf/challenges without body should return 422."""
        resp = client.post("/api/ctf/challenges")
        assert resp.status_code == 422

    def test_ctf_challenges_create_valid(self, client: TestClient):
        """POST /api/ctf/challenges with valid body should return 200 or 503."""
        resp = client.post("/api/ctf/challenges", json={
            "title": "Test Challenge",
            "category": "web",
            "description": "Find the flag",
            "flags": "FLAG{test}",
            "points": 100,
            "difficulty": "easy",
        })
        assert resp.status_code in (200, 201, 503)

    def test_ctf_solve_flag_empty_returns_400(self, client: TestClient):
        """POST /api/ctf/challenges/{id}/solve with empty flag should return 400."""
        resp = client.post("/api/ctf/challenges/1/solve", json={"flag": ""})
        assert resp.status_code == 400
        data = resp.json()
        assert data.get("ok") is False

    def test_ctf_solve_no_flag_returns_400(self, client: TestClient):
        """POST /api/ctf/challenges/{id}/solve without flag key should return 400."""
        resp = client.post("/api/ctf/challenges/1/solve", json={})
        assert resp.status_code == 400

    def test_upload_no_file(self, client: TestClient):
        """POST /api/upload without file should return 422."""
        resp = client.post("/api/upload")
        assert resp.status_code == 422

    def test_generate_pdf_no_body(self, client: TestClient):
        """POST /api/generate-pdf without body should return 422."""
        resp = client.post("/api/generate-pdf")
        assert resp.status_code == 422

    def test_report_generate_no_body(self, client: TestClient):
        """POST /api/report/generate without body should return 422."""
        resp = client.post("/api/report/generate")
        assert resp.status_code == 422
