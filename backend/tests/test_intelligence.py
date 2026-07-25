"""
Tests for intelligence -- Continuous Intelligence module.

Covers:
  - Watch CRUD (create, get, list, update, delete)
  - Snapshot management (capture, latest, history, chain)
  - Diff engine (no changes, headers, certificate, DNS, tech, ports, baseline)
  - Alert management (create, list filtered, acknowledge, clear, max severity)
  - Collectors (http_headers, certificate, dns, tech_stack) with mocked I/O
  - REST endpoints (create, list, get, delete watch, snapshots, alerts)
  - Edge cases (invalid watch_type, empty target, thread safety)
"""

import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend.intelligence import (
    # Data classes
    WatchDefinition,
    Snapshot,
    DiffResult,
    IntelAlert,
    # Watch CRUD
    create_watch,
    get_watch,
    list_watches,
    update_watch,
    delete_watch,
    # Snapshots
    capture_snapshot,
    get_latest_snapshot,
    get_snapshot_history,
    # Diff
    compute_diff,
    _diff_http_headers,
    _diff_certificate,
    _diff_dns,
    _diff_tech_stack,
    _diff_page_content,
    _diff_port_scan,
    # Alerts
    create_alert,
    list_alerts,
    acknowledge_alert,
    clear_alerts,
    # Collectors
    collect_http_headers,
    collect_certificate,
    collect_dns,
    collect_tech_stack,
    # Internal stores
    _watches,
    _snapshots,
    _alerts,
    _lock,
    # Reset
    reset,
    # Constants
    VALID_WATCH_TYPES,
)
from fastapi.testclient import TestClient
from main import app


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_state():
    """Reset intelligence module state before every test."""
    reset()
    yield
    reset()


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient fixture."""
    with TestClient(app) as c:
        yield c


# ══════════════════════════════════════════════
# 1. Watch CRUD (5 tests)
# ══════════════════════════════════════════════

def test_create_watch():
    """Creating a watch returns a WatchDefinition with generated id."""
    w = create_watch("My Site", "https://example.com", "http_headers")
    assert isinstance(w, WatchDefinition)
    assert len(w.id) > 0
    assert w.name == "My Site"
    assert w.target == "https://example.com"
    assert w.watch_type == "http_headers"
    assert w.enabled is True
    assert w.interval_seconds == 3600


def test_get_watch():
    """get_watch returns the correct watch by ID."""
    w = create_watch("DNS Watch", "example.com", "dns")
    found = get_watch(w.id)
    assert found is not None
    assert found.id == w.id
    assert found.watch_type == "dns"


def test_get_watch_not_found():
    """get_watch returns None for non-existent ID."""
    assert get_watch("nonexistent-id") is None


def test_list_watches():
    """list_watches returns all created watches."""
    create_watch("A", "a.com", "http_headers")
    create_watch("B", "b.com", "dns")
    watches = list_watches()
    assert len(watches) >= 2
    names = [w.name for w in watches]
    assert "A" in names
    assert "B" in names


def test_list_watches_enabled_only():
    """list_watches(enabled_only=True) filters disabled watches."""
    w = create_watch("Disabled", "x.com", "http_headers")
    update_watch(w.id, enabled=False)
    result = list_watches(enabled_only=True)
    ids = [r.id for r in result]
    assert w.id not in ids


def test_update_watch():
    """update_watch modifies fields and returns updated watch."""
    w = create_watch("Original", "old.com", "dns")
    updated = update_watch(w.id, name="Renamed", target="new.com", interval_seconds=600)
    assert updated is not None
    assert updated.name == "Renamed"
    assert updated.target == "new.com"
    assert updated.interval_seconds == 600


def test_update_watch_not_found():
    """update_watch returns None for non-existent ID."""
    assert update_watch("ghost", name="X") is None


def test_delete_watch():
    """delete_watch removes the watch and its snapshots."""
    w = create_watch("ToDelete", "del.com", "certificate")
    # Add a snapshot so there's cleanup
    capture_snapshot(w, {"issuer": "test"})
    assert delete_watch(w.id) is True
    assert get_watch(w.id) is None
    assert get_latest_snapshot(w.id) is None


def test_delete_watch_not_found():
    """delete_watch returns False for non-existent ID."""
    assert delete_watch("ghost-id") is False


# ══════════════════════════════════════════════
# 2. Snapshot management (4 tests)
# ══════════════════════════════════════════════

def test_capture_snapshot():
    """capture_snapshot stores data and returns a Snapshot."""
    w = create_watch("Snap Test", "snap.com", "http_headers")
    snap = capture_snapshot(w, {"headers": {"server": "nginx"}})
    assert isinstance(snap, Snapshot)
    assert snap.watch_id == w.id
    assert snap.data == {"headers": {"server": "nginx"}}
    assert snap.previous_snapshot_id is None


def test_get_latest_snapshot():
    """get_latest_snapshot returns the most recent snapshot."""
    w = create_watch("Latest", "lat.com", "dns")
    s1 = capture_snapshot(w, {"records": {"A": ["1.1.1.1"]}})
    s2 = capture_snapshot(w, {"records": {"A": ["1.1.1.1", "2.2.2.2"]}})
    latest = get_latest_snapshot(w.id)
    assert latest is not None
    assert latest.id == s2.id


def test_get_snapshot_history():
    """get_snapshot_history returns up to limit snapshots."""
    w = create_watch("History", "hist.com", "port_scan")
    for i in range(5):
        capture_snapshot(w, {"open_ports": [22 + i]})
    history = get_snapshot_history(w.id, limit=3)
    assert len(history) == 3
    # Should be the last 3
    assert history[0].data["open_ports"] == [24]
    assert history[-1].data["open_ports"] == [26]


def test_snapshot_chain():
    """Each snapshot links to the previous snapshot's ID."""
    w = create_watch("Chain", "chain.com", "page_content")
    s1 = capture_snapshot(w, {"content_hash": "aaa"})
    s2 = capture_snapshot(w, {"content_hash": "bbb"})
    s3 = capture_snapshot(w, {"content_hash": "ccc"})
    assert s1.previous_snapshot_id is None
    assert s2.previous_snapshot_id == s1.id
    assert s3.previous_snapshot_id == s2.id


# ══════════════════════════════════════════════
# 3. Diff engine (8 tests)
# ══════════════════════════════════════════════

def test_diff_no_changes():
    """Identical snapshots should produce changed=False."""
    old = Snapshot("o1", "w1", "t.com", "http_headers", "2025-01-01T00:00:00Z", {"headers": {"server": "nginx"}})
    new = Snapshot("n1", "w1", "t.com", "http_headers", "2025-01-02T00:00:00Z", {"headers": {"server": "nginx"}})
    diff = compute_diff(old, new)
    assert diff.changed is False
    assert len(diff.changes) == 0


def test_diff_header_added_removed():
    """Added/removed HTTP headers should be detected."""
    old = Snapshot("o1", "w1", "t.com", "http_headers", "2025-01-01T00:00:00Z", {
        "headers": {"server": "nginx", "x-custom": "val"},
    })
    new = Snapshot("n1", "w1", "t.com", "http_headers", "2025-01-02T00:00:00Z", {
        "headers": {"server": "apache"},
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    fields = [c["field"] for c in diff.changes]
    assert "header:x-custom" in fields  # removed
    assert "header:server" in fields    # changed


def test_diff_header_security_removed():
    """Removing a security header should have severity 'high'."""
    old = Snapshot("o1", "w1", "t.com", "http_headers", "2025-01-01T00:00:00Z", {
        "headers": {"content-security-policy": "default-src 'self'"},
    })
    new = Snapshot("n1", "w1", "t.com", "http_headers", "2025-01-02T00:00:00Z", {
        "headers": {},
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    csp_change = [c for c in diff.changes if "content-security-policy" in c["field"]]
    assert len(csp_change) == 1
    assert csp_change[0]["severity"] == "high"


def test_diff_certificate_issuer_change():
    """Certificate issuer change should be detected with severity 'high'."""
    old = Snapshot("o1", "w1", "t.com", "certificate", "2025-01-01T00:00:00Z", {
        "issuer": "Let's Encrypt",
        "serial_number": "ABC123",
        "not_after": "2026-01-01T00:00:00Z",
        "san": ["t.com"],
    })
    new = Snapshot("n1", "w1", "t.com", "certificate", "2025-06-01T00:00:00Z", {
        "issuer": "DigiCert",
        "serial_number": "DEF456",
        "not_after": "2027-01-01T00:00:00Z",
        "san": ["t.com", "www.t.com"],
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    issuer_changes = [c for c in diff.changes if c["field"] == "cert:issuer"]
    assert len(issuer_changes) == 1
    assert issuer_changes[0]["severity"] == "high"


def test_diff_dns_record_change():
    """DNS record additions/removals should be detected."""
    old = Snapshot("o1", "w1", "t.com", "dns", "2025-01-01T00:00:00Z", {
        "records": {"A": ["1.1.1.1"], "MX": ["mail.t.com"]},
    })
    new = Snapshot("n1", "w1", "t.com", "dns", "2025-06-01T00:00:00Z", {
        "records": {"A": ["1.1.1.1", "2.2.2.2"], "TXT": ["v=spf1 ..."]},
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    fields = [c["field"] for c in diff.changes]
    assert "dns:A" in fields
    assert "dns:MX" in fields
    assert "dns:TXT" in fields


def test_diff_tech_stack_change():
    """Technology stack additions/removals should be detected."""
    old = Snapshot("o1", "w1", "t.com", "tech_stack", "2025-01-01T00:00:00Z", {
        "technologies": ["Server:nginx", "WordPress"],
    })
    new = Snapshot("n1", "w1", "t.com", "tech_stack", "2025-06-01T00:00:00Z", {
        "technologies": ["Server:apache", "WordPress", "React"],
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    assert len(diff.changes) == 1
    detail = diff.changes[0]["detail"]
    assert "React" in detail["added"]
    assert "Server:nginx" in detail["removed"]


def test_diff_port_scan():
    """New and closed ports should be detected with correct severities."""
    old = Snapshot("o1", "w1", "t.com", "port_scan", "2025-01-01T00:00:00Z", {
        "open_ports": [22, 80, 443],
    })
    new = Snapshot("n1", "w1", "t.com", "port_scan", "2025-06-01T00:00:00Z", {
        "open_ports": [22, 80, 8080],
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    # 443 removed (low), 8080 added (medium)
    severities = {c["field"]: c["severity"] for c in diff.changes}
    assert severities.get("port:443") == "low"
    assert severities.get("port:8080") == "medium"


def test_diff_empty_old_snapshot():
    """When old_snapshot is None, it should be a baseline (no changes)."""
    new = Snapshot("n1", "w1", "t.com", "dns", "2025-01-01T00:00:00Z", {
        "records": {"A": ["1.1.1.1"]},
    })
    diff = compute_diff(None, new)
    assert diff.changed is False
    assert diff.old_snapshot_id is None
    assert "Baseline" in diff.summary


def test_diff_page_content():
    """Page content hash and body length changes should be detected."""
    old = Snapshot("o1", "w1", "t.com", "page_content", "2025-01-01T00:00:00Z", {
        "content_hash": "abc123",
        "body_length": 1000,
    })
    new = Snapshot("n1", "w1", "t.com", "page_content", "2025-06-01T00:00:00Z", {
        "content_hash": "def456",
        "body_length": 1500,
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    fields = [c["field"] for c in diff.changes]
    assert "content_hash" in fields
    assert "body_length" in fields


# ══════════════════════════════════════════════
# 4. Alert management (5 tests)
# ══════════════════════════════════════════════

def test_create_alert():
    """Creating an alert returns an IntelAlert with generated id."""
    a = create_alert("w1", "t.com", "change_detected", "medium", "DNS changed")
    assert isinstance(a, IntelAlert)
    assert len(a.id) > 0
    assert a.watch_id == "w1"
    assert a.severity == "medium"
    assert a.acknowledged is False


def test_list_alerts_filtered():
    """list_alerts filters by watch_id and severity."""
    create_alert("w1", "a.com", "change_detected", "high", "msg1")
    create_alert("w2", "b.com", "target_down", "critical", "msg2")
    create_alert("w1", "a.com", "cert_expiring", "info", "msg3")

    by_w1 = list_alerts(watch_id="w1")
    assert len(by_w1) == 2

    by_crit = list_alerts(severity="critical")
    assert len(by_crit) == 1
    assert by_crit[0].watch_id == "w2"


def test_acknowledge_alert():
    """acknowledge_alert marks an alert as acknowledged."""
    a = create_alert("w1", "t.com", "new_tech", "info", "React detected")
    assert acknowledge_alert(a.id) is True
    alerts = list_alerts()
    acked = [al for al in alerts if al.id == a.id]
    assert len(acked) == 1
    assert acked[0].acknowledged is True


def test_acknowledge_alert_not_found():
    """acknowledge_alert returns False for non-existent ID."""
    assert acknowledge_alert("ghost") is False


def test_clear_alerts():
    """clear_alerts removes all or filtered alerts."""
    create_alert("w1", "a.com", "change_detected", "low", "msg1")
    create_alert("w2", "b.com", "target_down", "high", "msg2")
    count = clear_alerts(watch_id="w1")
    assert count == 1
    remaining = list_alerts()
    assert len(remaining) == 1
    assert remaining[0].watch_id == "w2"


def test_clear_all_alerts():
    """clear_alerts() with no watch_id removes everything."""
    create_alert("w1", "a.com", "change_detected", "low", "msg1")
    create_alert("w2", "b.com", "target_down", "high", "msg2")
    count = clear_alerts()
    assert count == 2
    assert len(list_alerts()) == 0


def test_max_severity_from_diff_changes():
    """compute_diff should reflect the max severity across all changes."""
    old = Snapshot("o1", "w1", "t.com", "certificate", "2025-01-01T00:00:00Z", {
        "issuer": "Let's Encrypt",
        "serial_number": "AAA",
        "not_after": "2026-01-01T00:00:00Z",
    })
    new = Snapshot("n1", "w1", "t.com", "certificate", "2025-06-01T00:00:00Z", {
        "issuer": "DigiCert",
        "serial_number": "BBB",
        "not_after": "2027-01-01T00:00:00Z",
    })
    diff = compute_diff(old, new)
    assert diff.changed is True
    # Overall summary should mention severity
    assert "high" in diff.summary


# ══════════════════════════════════════════════
# 5. Collectors (4 tests, mocked)
# ══════════════════════════════════════════════

def test_collect_http_headers_success(monkeypatch):
    """collect_http_headers returns parsed headers on success."""
    class FakeResp:
        status = 200
        headers = {"Server": "nginx", "X-Custom": "hello"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    def fake_urlopen(req, timeout=None):
        return FakeResp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = collect_http_headers("https://example.com")
    assert result["status_code"] == 200
    assert "server" in result["headers"]
    assert result["headers"]["server"] == "nginx"


def test_collect_http_headers_failure(monkeypatch):
    """collect_http_headers returns error info on failure."""
    def fake_urlopen(req, timeout=None):
        raise ConnectionError("refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = collect_http_headers("https://down.example.com")
    assert result["status_code"] == 0
    assert "error" in result


def test_collect_dns_success(monkeypatch):
    """collect_dns returns resolved records on success."""
    def fake_getaddrinfo(host, port):
        return [
            (socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)),
            (socket.AF_INET, 0, 0, "", ("93.184.216.35", 0)),
        ]

    import socket
    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
    result = collect_dns("example.com")
    assert "A" in result["records"]
    assert "93.184.216.34" in result["records"]["A"]


def test_collect_dns_failure(monkeypatch):
    """collect_dns returns empty records on failure."""
    def fake_getaddrinfo(host, port):
        raise socket.gaierror("no such host")

    import socket
    monkeypatch.setattr("socket.getaddrinfo", fake_getaddrinfo)
    result = collect_dns("nonexistent.invalid")
    assert result["records"] == {}
    assert "error" in result


def test_collect_tech_stack_success(monkeypatch):
    """collect_tech_stack detects technologies from headers/body."""
    class FakeResp:
        status = 200
        headers = {"Server": "Apache", "X-Powered-By": "PHP/8.2"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def read(self, n=0):
            return b"<html><body>wp-content/themes/test</body></html>"

    def fake_urlopen(req, timeout=None):
        return FakeResp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = collect_tech_stack("https://example.com")
    assert "Server:Apache" in result["technologies"]
    assert "X-Powered-By:PHP/8.2" in result["technologies"]
    assert "WordPress" in result["technologies"]


# ══════════════════════════════════════════════
# 6. REST Endpoints (6 tests)
# ══════════════════════════════════════════════

def test_api_create_watch(client):
    """POST /api/intelligence/watches creates a watch."""
    resp = client.post("/api/intelligence/watches", json={
        "name": "API Watch",
        "target": "https://api.example.com",
        "watch_type": "http_headers",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "watch" in data
    assert data["watch"]["name"] == "API Watch"


def test_api_list_watches(client):
    """GET /api/intelligence/watches lists watches."""
    client.post("/api/intelligence/watches", json={
        "name": "List1", "target": "a.com", "watch_type": "dns",
    })
    client.post("/api/intelligence/watches", json={
        "name": "List2", "target": "b.com", "watch_type": "dns",
    })
    resp = client.get("/api/intelligence/watches")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert len(data["watches"]) >= 2


def test_api_get_watch(client):
    """GET /api/intelligence/watches/{id} returns a specific watch."""
    create_resp = client.post("/api/intelligence/watches", json={
        "name": "Get Me", "target": "get.com", "watch_type": "certificate",
    })
    watch_id = create_resp.json()["watch"]["id"]
    resp = client.get(f"/api/intelligence/watches/{watch_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["watch"]["id"] == watch_id


def test_api_delete_watch(client):
    """DELETE /api/intelligence/watches/{id} deletes a watch."""
    create_resp = client.post("/api/intelligence/watches", json={
        "name": "Delete Me", "target": "del.com", "watch_type": "http_headers",
    })
    watch_id = create_resp.json()["watch"]["id"]
    resp = client.delete(f"/api/intelligence/watches/{watch_id}")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    # Verify deleted
    get_resp = client.get(f"/api/intelligence/watches/{watch_id}")
    assert get_resp.json()["ok"] is False


def test_api_get_snapshots(client):
    """GET /api/intelligence/watches/{id}/snapshots returns snapshot list."""
    create_resp = client.post("/api/intelligence/watches", json={
        "name": "Snap API", "target": "snap.com", "watch_type": "dns",
    })
    watch_id = create_resp.json()["watch"]["id"]
    # Capture a snapshot via diff endpoint (triggers capture internally)
    client.post(f"/api/intelligence/diff/{watch_id}", json={
        "data": {"records": {"A": ["1.1.1.1"]}},
    })
    resp = client.get(f"/api/intelligence/watches/{watch_id}/snapshots")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True


def test_api_list_alerts(client):
    """GET /api/intelligence/alerts lists alerts."""
    resp = client.get("/api/intelligence/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "alerts" in data


# ══════════════════════════════════════════════
# 7. Edge cases (3 tests)
# ══════════════════════════════════════════════

def test_invalid_watch_type():
    """Creating a watch with invalid watch_type raises ValueError."""
    with pytest.raises(ValueError, match="Invalid watch_type"):
        create_watch("Bad", "bad.com", "not_a_real_type")


def test_empty_target():
    """Creating a watch with an empty target raises ValueError."""
    with pytest.raises(ValueError, match="non-empty"):
        create_watch("Empty", "", "dns")


def test_thread_safety():
    """Concurrent watch creation should not corrupt data."""
    errors: list[Exception] = []

    def create_many(n: int):
        try:
            for i in range(n):
                create_watch(f"Thread-{threading.get_ident()}-{i}", f"t{i}.com", "dns")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=create_many, args=(20,)) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    watches = list_watches()
    assert len(watches) == 100  # 5 threads * 20 watches
