"""
Coverage-gap tests for backend/intelligence.py.

Covers:
  - _max_severity with empty change list
  - create_watch watch-limit reached
  - update_watch invalid watch_type / empty target / tags
  - capture_snapshot history trimming
  - compute_diff with unknown watch_type
  - _diff_http_headers non-security header added (low severity)
  - create_alert eviction (acknowledged and unacknowledged)
  - collect_dns AAAA (AF_INET6) records
  - collect_tech_stack extra header/body detections + failure path
"""

import socket
from unittest.mock import patch

import backend.intelligence as intel
from backend.intelligence import (
    MAX_ALERTS,
    MAX_SNAPSHOTS_PER_WATCH,
    MAX_WATCHES,
    Snapshot,
    _max_severity,
    acknowledge_alert,
    capture_snapshot,
    collect_dns,
    collect_tech_stack,
    compute_diff,
    create_alert,
    create_watch,
    reset,
    update_watch,
)


def _mk_watch(name="w", target="t.com", watch_type="dns"):
    return intel.WatchDefinition(
        id="w1", name=name, target=target, watch_type=watch_type,
        interval_seconds=60, enabled=True, created_at="2026-01-01T00:00:00Z",
        tags=[],
    )


class TestMaxSeverityEmpty:
    def test_empty_changes_info(self):
        assert _max_severity([]) == "info"


class TestCreateWatchLimit:
    def test_watch_limit_reached(self):
        reset()
        with patch.object(intel, "MAX_WATCHES", 0):
            try:
                create_watch("x", "t.com", "dns")
                assert False, "expected ValueError"
            except ValueError as exc:
                assert "Watch limit reached" in str(exc)


class TestUpdateWatchErrors:
    def test_invalid_watch_type(self):
        reset()
        w = create_watch("w", "t.com", "dns")
        try:
            update_watch(w.id, watch_type="bogus")
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "Invalid watch_type" in str(exc)

    def test_empty_target(self):
        reset()
        w = create_watch("w", "t.com", "dns")
        try:
            update_watch(w.id, target="   ")
            assert False, "expected ValueError"
        except ValueError as exc:
            assert "target must be a non-empty string" in str(exc)

    def test_tags_applied(self):
        reset()
        w = create_watch("w", "t.com", "dns")
        updated = update_watch(w.id, tags=["a", "b"])
        assert updated.tags == ["a", "b"]
        updated2 = update_watch(w.id, tags=[])
        assert updated2.tags == []

    def test_valid_watch_type_applied(self):
        reset()
        w = create_watch("w", "t.com", "dns")
        updated = update_watch(w.id, watch_type="http_headers")
        assert updated.watch_type == "http_headers"


class TestCaptureSnapshotTrim:
    def test_history_trimmed(self):
        reset()
        w = _mk_watch()
        intel._watches[w.id] = w
        with patch.object(intel, "MAX_SNAPSHOTS_PER_WATCH", 2):
            for i in range(5):
                capture_snapshot(w, {"i": i})
        history = intel.get_snapshot_history(w.id, limit=100)
        assert len(history) == 2
        assert history[-1].data == {"i": 4}


class TestComputeDiffUnknownType:
    def test_unknown_watch_type_no_changes(self):
        old = Snapshot("o", "w1", "t.com", "bogus", "2026-01-01T00:00:00Z", {"a": 1})
        new = Snapshot("n", "w1", "t.com", "bogus", "2026-01-02T00:00:00Z", {"a": 2})
        diff = compute_diff(old, new)
        assert diff.changed is False
        assert diff.changes == []


class TestDiffHttpHeadersAddedNonSecurity:
    def test_added_non_security_header_is_low(self):
        old = {"headers": {}}
        new = {"headers": {"x-ratelimit-limit": "100"}}
        changes = intel._diff_http_headers(old, new)
        assert len(changes) == 1
        assert changes[0]["field"] == "header:x-ratelimit-limit"
        assert changes[0]["severity"] == "low"


class TestCreateAlertEviction:
    def test_evicts_acknowledged_first(self):
        reset()
        with patch.object(intel, "MAX_ALERTS", 1):
            a1 = create_alert("w1", "t.com", "dns", "low", "one")
            assert acknowledge_alert(a1.id) is True
            a2 = create_alert("w1", "t.com", "dns", "low", "two")
        alerts = intel.list_alerts(limit=100)
        assert len(alerts) == 1
        assert alerts[0].id == a2.id

    def test_evicts_oldest_when_none_acknowledged(self):
        reset()
        with patch.object(intel, "MAX_ALERTS", 1):
            a1 = create_alert("w1", "t.com", "dns", "low", "one")
            a2 = create_alert("w1", "t.com", "dns", "low", "two")
        alerts = intel.list_alerts(limit=100)
        assert len(alerts) == 1
        assert alerts[0].id == a2.id


class TestCollectDnsAAAA:
    def test_aaaa_records(self, monkeypatch):
        def fake_getaddrinfo(host, port):
            return [
                (socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)),
                (socket.AF_INET6, 0, 0, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
            ]
        monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
        result = collect_dns("example.com")
        assert "A" in result["records"]
        assert "AAAA" in result["records"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in result["records"]["AAAA"]


class TestCollectTechStackExtra:
    class _FakeResp:
        status = 200
        headers = {
            "x-drupal-cache": "HIT",
            "x-generator": "Drupal 9",
            "cf-ray": "abc123",
            "x-amz-cf-id": "xyz",
            "x-varnish": "12345",
            "x-akamai-transformed": "x",
        }

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def read(self, n=0):
            return b"joomla drupal shopify react vue angular"

    def test_all_detections(self, monkeypatch):
        def fake_urlopen(req, timeout=None):
            return self._FakeResp()
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        result = collect_tech_stack("https://example.com")
        techs = set(result["technologies"])
        assert "Drupal" in techs
        assert "Generator:Drupal 9" in techs
        assert "Cloudflare" in techs
        assert "AWS CloudFront" in techs
        assert "Varnish" in techs
        assert "Akamai" in techs
        assert "Joomla" in techs
        assert "Shopify" in techs
        assert "React" in techs
        assert "Vue.js" in techs
        assert "Angular" in techs

    def test_failure_returns_synthetic(self, monkeypatch):
        def fake_urlopen(req, timeout=None):
            raise ConnectionError("refused")
        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        result = collect_tech_stack("https://down.example.com")
        assert result["technologies"] == []
        assert result["status_code"] == 0
        assert "error" in result
