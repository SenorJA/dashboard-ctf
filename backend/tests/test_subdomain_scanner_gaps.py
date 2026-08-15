"""
tests/test_subdomain_scanner_gaps.py — Tests for passive subdomain enumeration.

Covers the passive / combined APIs added to subdomain_scanner.py:

    1. scan_passive() — both sources OK, cross-source dedup
    2. scan_passive() — crt.sh fails (HTTPError) → wayback still used + error note
    3. scan_passive() — both sources fail → empty report + errors, never raises
    4. scan_passive() — normalization (*., scheme, path, case, apex, decoys)
    5. scan_passive() — DNS resolution cap (max_resolve)
    6. scan_passive() — malformed JSON / non-list payload degrade gracefully
    7. scan_combined() — merges brute + passive without duplicates
    8. scan_combined() — resolved result wins over unresolved duplicate
    9. scan_combined() — sources/errors propagate from the passive pass
    10. scan_combined() — never raises when both passive sources fail
    11. SubdomainReport — new fields (sources/errors) keep default compat
    12. report_to_mirv_findings() — still works on a passive report

All HTTP + DNS are mocked — no real network traffic.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import AsyncMock, patch

import pytest

from backend.subdomain_scanner import (
    SubdomainReport,
    SubdomainResult,
    report_to_mirv_findings,
    scan_combined,
    scan_passive,
)

DOMAIN = "example.com"

# ── shared fakes ─────────────────────────────────────────────────────────────


class _FakeResp:
    """Minimal urllib.response mock: context-manager + read()."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._payload


def _make_urlopen(crtsh_payload, wayback_payload, crtsh_error=None, wayback_error=None):
    """Build a urlopen side_effect that dispatches on the request URL."""
    urls: list[str] = []

    def _fake(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        urls.append(url)
        if "crt.sh" in url:
            if crtsh_error is not None:
                raise crtsh_error
            return _FakeResp(crtsh_payload)
        if "web.archive.org" in url:
            if wayback_error is not None:
                raise wayback_error
            return _FakeResp(wayback_payload)
        raise AssertionError(f"Unexpected URL requested: {url}")

    _fake.urls = urls  # type: ignore[attr-defined]
    return _fake


def _make_resolver(ip_map: dict[str, list[str]], counter: dict | None = None):
    """Build an async _resolve_subdomain stand-in backed by a static map."""

    async def _resolve(full_domain: str, timeout: float = 3.0):
        if counter is not None:
            counter["n"] += 1
        ips = ip_map.get(full_domain)
        if not ips:
            return None
        return SubdomainResult(
            subdomain=full_domain.split(".", 1)[0],
            domain=DOMAIN,
            full_domain=full_domain,
            resolved_ips=ips,
            record_type="A",
        )

    return _resolve


def _default_crtsh_payload() -> bytes:
    return json.dumps([
        {"name_value": "*.www.example.com\napi.example.com"},
        {"common_name": "STAGING.Example.COM"},
    ]).encode()


def _default_wayback_payload() -> bytes:
    return json.dumps([
        ["original"],
        ["http://www.example.com/path?x=1"],   # dup w/ crt.sh + scheme/path
        ["https://deep.example.com"],
        ["http://fakeexample.com"],            # look-alike decoy → filtered
    ]).encode()


# ── 1. scan_passive — both sources OK + cross-source dedup ──────────────────


async def test_scan_passive_both_sources_ok_and_dedup():
    """crt.sh + wayback both return data; dedup merges overlapping hosts."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=_default_crtsh_payload(),
        wayback_payload=_default_wayback_payload(),
    )
    ip_map = {
        "www.example.com": ["1.2.3.4"],
        "api.example.com": ["5.6.7.8"],
        "staging.example.com": ["9.9.9.9"],
        "deep.example.com": [],
    }
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver(ip_map)):
        report = await scan_passive(DOMAIN)

    assert report.domain == DOMAIN
    assert report.total_checked == 4
    assert report.found == 4
    assert report.sources == ["crt.sh", "wayback"]
    assert report.errors == []

    full_names = {r.full_domain for r in report.results}
    assert full_names == {
        "www.example.com",
        "api.example.com",
        "staging.example.com",
        "deep.example.com",
    }

    by_name = {r.full_domain: r for r in report.results}
    # Resolved host carries its IPs; unresolved passive host stays empty.
    assert by_name["www.example.com"].resolved_ips == ["1.2.3.4"]
    assert by_name["deep.example.com"].resolved_ips == []
    assert by_name["deep.example.com"].record_type is None

    # Source endpoints were hit with the expected query shapes.
    called = " ".join(fake_urlopen.urls)
    assert "crt.sh/?" in called and "output=json" in called
    # crt.sh expects the `%.{domain}` wildcard query double-encoded
    # (quote("%25.example.com") → "%2525.example.com"), matching ShadowEnum.
    assert "%2525.example.com" in called
    assert "web.archive.org/cdx/search/cdx" in called
    assert "collapse=urlkey" in called and "limit=500" in called


# ── 2. scan_passive — crt.sh fails, wayback still contributes ────────────────


async def test_scan_passive_crtsh_fails_uses_wayback():
    """A crt.sh HTTPError must not sink the scan; error is recorded."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=b"",
        wayback_payload=_default_wayback_payload(),
        crtsh_error=urllib.error.HTTPError(
            "https://crt.sh/?q=%25.example.com&output=json", 403,
            "Forbidden", {}, None,
        ),
    )
    ip_map = {"www.example.com": ["1.2.3.4"], "deep.example.com": []}
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver(ip_map)):
        report = await scan_passive(DOMAIN)

    assert report.sources == ["wayback"]
    assert len(report.errors) == 1
    assert "crt.sh" in report.errors[0]

    # wayback-only discovery: www (resolved) + deep (passive, unresolved)
    assert report.found == 2
    by_name = {r.full_domain: r for r in report.results}
    assert set(by_name) == {"www.example.com", "deep.example.com"}
    assert by_name["www.example.com"].resolved_ips == ["1.2.3.4"]
    assert by_name["deep.example.com"].resolved_ips == []


# ── 3. scan_passive — both sources fail → empty, never raises ────────────────


async def test_scan_passive_both_sources_fail():
    """Both sources down → zero found, both errors recorded, no exception."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=b"",
        wayback_payload=b"",
        crtsh_error=urllib.error.URLError("Connection refused"),
        wayback_error=urllib.error.URLError("Timeout"),
    )
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver({})):
        report = await scan_passive(DOMAIN)

    assert report.found == 0
    assert report.results == []
    assert report.total_checked == 0
    assert report.sources == []
    assert len(report.errors) == 2
    joined = " ".join(report.errors)
    assert "crt.sh" in joined and "wayback" in joined
    assert report.duration_seconds >= 0


# ── 4. scan_passive — normalization ──────────────────────────────────────────


async def test_scan_passive_normalization():
    """Wildcards, schemes, paths, uppercase, apex and decoys are handled."""
    crtsh_payload = json.dumps([
        {"name_value": "*.sub.example.com"},            # wildcard prefix
        {"name_value": "https://deep.example.com/x?y=1"},  # scheme + path
        {"name_value": "MAIL.Example.COM"},             # case-insensitive
        {"name_value": "example.com"},                  # apex is kept
        {"name_value": "fakeexample.com"},              # look-alike → dropped
    ]).encode()
    fake_urlopen = _make_urlopen(
        crtsh_payload=crtsh_payload,
        wayback_payload=json.dumps([["original"]]).encode(),
    )
    ip_map = {
        "sub.example.com": ["1.1.1.1"],
        "deep.example.com": ["2.2.2.2"],
        "mail.example.com": ["3.3.3.3"],
    }
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver(ip_map)):
        report = await scan_passive(DOMAIN)

    full_names = {r.full_domain for r in report.results}
    assert full_names == {
        "sub.example.com",
        "deep.example.com",
        "mail.example.com",
        "example.com",
    }
    assert "fakeexample.com" not in full_names

    by_name = {r.full_domain: r for r in report.results}
    assert by_name["sub.example.com"].resolved_ips == ["1.1.1.1"]
    assert by_name["example.com"].resolved_ips == []  # apex: passive only


# ── 5. scan_passive — DNS resolution cap ─────────────────────────────────────


async def test_scan_passive_resolution_limit():
    """Only max_resolve hosts are DNS-validated; the rest stay passive."""
    crtsh_payload = json.dumps([
        {"name_value": "\n".join(
            f"a{i}.example.com" for i in range(5)
        )},
    ]).encode()
    fake_urlopen = _make_urlopen(
        crtsh_payload=crtsh_payload,
        wayback_payload=json.dumps([["original"]]).encode(),
    )
    counter = {"n": 0}
    ip_map = {f"a{i}.example.com": [f"10.0.0.{i}"] for i in range(5)}
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver(ip_map, counter)):
        report = await scan_passive(DOMAIN, max_resolve=2)

    assert report.found == 5
    assert counter["n"] == 2, "Only 2 hosts should be DNS-validated"
    assert sum(1 for r in report.results if r.resolved_ips) == 2
    unresolved = [r for r in report.results if not r.resolved_ips]
    assert len(unresolved) == 3
    assert all(r.record_type is None for r in unresolved)


# ── 6. scan_passive — malformed / unexpected payloads ────────────────────────


async def test_scan_passive_malformed_crtsh_json_records_error():
    """Invalid JSON from a source is recorded as that source's error."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=b"<html>rate limited</html>",  # not JSON
        wayback_payload=_default_wayback_payload(),
    )
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver({"www.example.com": ["1.2.3.4"]})):
        report = await scan_passive(DOMAIN)

    assert report.sources == ["wayback"]
    assert len(report.errors) == 1
    assert "crt.sh" in report.errors[0]
    assert report.found == 2  # www + deep from wayback


async def test_scan_passive_non_list_crtsh_is_no_data_not_error():
    """A JSON object (e.g. error envelope) is treated as empty, not a failure."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=json.dumps({"error": "rate limited"}).encode(),
        wayback_payload=_default_wayback_payload(),
    )
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver({"www.example.com": ["1.2.3.4"]})):
        report = await scan_passive(DOMAIN)

    assert report.sources == ["crt.sh", "wayback"]
    assert report.errors == []
    assert report.found == 2  # www + deep from wayback


# ── 7. scan_combined — merge without duplicates ──────────────────────────────


async def test_scan_combined_merges_without_duplicates():
    """Passive hosts not hit by brute-force are appended; no dups."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=_default_crtsh_payload(),
        wayback_payload=_default_wayback_payload(),
    )
    ip_map = {
        "www.example.com": ["1.2.3.4"],
        "api.example.com": ["5.6.7.8"],
        "staging.example.com": ["9.9.9.9"],
        "deep.example.com": [],
    }
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver(ip_map)):
        # Brute wordlist: www + api resolve; ghost does not.
        report = await scan_combined(
            DOMAIN,
            subdomains=["www", "api", "ghost"],
        )

    # Brute found www+api; passive adds staging + deep → 4 unique.
    assert report.found == 4
    full_names = [r.full_domain for r in report.results]
    assert len(full_names) == len(set(full_names)), "duplicates in merged results"
    assert set(full_names) == {
        "www.example.com",
        "api.example.com",
        "staging.example.com",
        "deep.example.com",
    }
    # total_checked = 3 brute + 2 passive-only
    assert report.total_checked == 5
    assert report.sources == ["crt.sh", "wayback"]
    assert report.errors == []


# ── 8. scan_combined — resolved result wins over unresolved duplicate ────────


async def test_scan_combined_prefers_resolved_ips():
    """When brute has an unresolved passive duplicate, the IPs win."""
    brute_report = SubdomainReport(
        domain=DOMAIN,
        total_checked=1,
        found=1,
        results=[SubdomainResult(
            subdomain="www", domain=DOMAIN, full_domain="www.example.com",
            resolved_ips=[], record_type=None,
        )],
        duration_seconds=0.1,
    )
    passive_report = SubdomainReport(
        domain=DOMAIN,
        total_checked=2,
        found=2,
        results=[
            SubdomainResult(
                subdomain="www", domain=DOMAIN, full_domain="www.example.com",
                resolved_ips=["9.9.9.9"], record_type="A",
            ),
            SubdomainResult(
                subdomain="staging", domain=DOMAIN,
                full_domain="staging.example.com", resolved_ips=[],
                record_type=None,
            ),
        ],
        duration_seconds=0.1,
        sources=["crt.sh"],
        errors=[],
    )
    with patch("backend.subdomain_scanner.scan",
               AsyncMock(return_value=brute_report)), \
         patch("backend.subdomain_scanner.scan_passive",
               AsyncMock(return_value=passive_report)):
        report = await scan_combined(DOMAIN, subdomains=["www"])

    assert report.found == 2
    assert report.total_checked == 2  # 1 brute + 1 passive-only (staging)
    by_name = {r.full_domain: r for r in report.results}
    # passive IPs won over the unresolved brute duplicate
    assert by_name["www.example.com"].resolved_ips == ["9.9.9.9"]
    assert by_name["staging.example.com"].resolved_ips == []


# ── 9. scan_combined — sources/errors propagate ──────────────────────────────


async def test_scan_combined_propagates_passive_metadata():
    """Combined report inherits sources/errors from the passive pass."""
    empty = SubdomainReport(
        domain=DOMAIN, total_checked=0, found=0, results=[], duration_seconds=0.0,
    )
    passive = SubdomainReport(
        domain=DOMAIN, total_checked=1, found=1,
        results=[SubdomainResult(
            subdomain="www", domain=DOMAIN, full_domain="www.example.com",
            resolved_ips=[], record_type=None,
        )],
        duration_seconds=0.1,
        sources=["wayback"],
        errors=["crt.sh: HTTP Error 403: Forbidden"],
    )
    with patch("backend.subdomain_scanner.scan",
               AsyncMock(return_value=empty)), \
         patch("backend.subdomain_scanner.scan_passive",
               AsyncMock(return_value=passive)):
        report = await scan_combined(DOMAIN, subdomains=["www"])

    assert report.sources == ["wayback"]
    assert report.errors == ["crt.sh: HTTP Error 403: Forbidden"]


# ── 10. scan_combined — never raises when passive sources are down ───────────


async def test_scan_combined_survives_passive_outage():
    """Both passive sources down → brute still runs; combined never raises."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=b"",
        wayback_payload=b"",
        crtsh_error=urllib.error.URLError("down"),
        wayback_error=urllib.error.URLError("down"),
    )
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver({})):
        report = await scan_combined(DOMAIN, subdomains=["www", "api"])

    assert isinstance(report, SubdomainReport)
    assert report.found == 0
    assert report.total_checked == 2  # brute checks still counted
    assert len(report.errors) == 2
    assert "crt.sh" in " ".join(report.errors)
    assert "wayback" in " ".join(report.errors)


# ── 11. SubdomainReport — new field defaults ─────────────────────────────────


def test_subdomain_report_new_fields_default():
    """sources/errors default to empty lists (backwards compatible)."""
    report = SubdomainReport(
        domain=DOMAIN,
        total_checked=0,
        found=0,
        results=[],
        duration_seconds=0.0,
    )
    assert report.sources == []
    assert report.errors == []
    # Still frozen
    with pytest.raises(AttributeError):
        report.sources = ["crt.sh"]


# ── 12. report_to_mirv_findings still works on a passive report ─────────────


async def test_report_to_mirv_findings_on_passive_report():
    """Passive reports convert to MIRV findings without changes."""
    fake_urlopen = _make_urlopen(
        crtsh_payload=_default_crtsh_payload(),
        wayback_payload=json.dumps([["original"]]).encode(),
    )
    ip_map = {"www.example.com": ["1.2.3.4"], "api.example.com": []}
    with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
         patch("backend.subdomain_scanner._resolve_subdomain",
               new=_make_resolver(ip_map)):
        report = await scan_passive(DOMAIN)

    findings = report_to_mirv_findings(report)
    required_keys = {"tool", "severity", "title", "detail", "target", "type"}
    assert len(findings) == report.found + 1  # per-host + summary
    for f in findings:
        assert required_keys.issubset(f.keys())
        assert f["tool"] == "subdomain-scan"
