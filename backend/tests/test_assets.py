"""Tests for the Asset inventory module (backend/assets.py) + REST endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend import assets as assetslib
from backend import assessments as assess
from backend.main import app


@pytest.fixture()
def clean():
    assetslib.reset_assets()
    assess.reset_assessments()
    yield
    assetslib.reset_assets()
    assess.reset_assessments()


@pytest.fixture()
def client(clean):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample_assessment(clean):
    a = assess.create_assessment("Client A", targets=["10.0.0.1", "www.example.com"])
    return {"id": a.id, "name": a.name}


# ── Registry unit tests ───────────────────────────────────────────────────

def test_create_asset_requires_assessment(clean):
    with pytest.raises(ValueError, match="not found"):
        assetslib.create_asset("missing", "host", "10.0.0.1")


def test_create_asset_invalid_kind_status(clean):
    a = assess.create_assessment("X", targets=[])
    aid = a.id
    with pytest.raises(ValueError, match="invalid kind"):
        assetslib.create_asset(aid, "planet", "10.0.0.1")
    with pytest.raises(ValueError, match="invalid status"):
        assetslib.create_asset(aid, "host", "10.0.0.1", status="busy")


def test_create_and_dedup_merge(clean):
    a = assess.create_assessment("X")
    aid = a.id
    first = assetslib.create_asset(aid, "host", "10.0.0.5", tags=["web"], source="tool")
    second = assetslib.create_asset(aid, "host", "10.0.0.5", label="db", source="tool")
    assert first.id == second.id
    assert second.label == "db"
    assert second.tags == ["web"]
    assert len(assetslib.list_assets(assessment_id=aid)) == 1


def test_create_same_address_different_kind(clean):
    a = assess.create_assessment("X")
    h = assetslib.create_asset(a.id, "host", "10.0.0.9")
    _e = assetslib.create_asset(a.id, "endpoint", "10.0.0.9/login")
    assert h.id != _e.id
    assert len(assetslib.list_assets(assessment_id=a.id)) == 2


def test_list_filters(clean):
    a = assess.create_assessment("X")
    assetslib.create_asset(a.id, "host", "10.0.0.1", status="active")
    assetslib.create_asset(a.id, "host", "10.0.0.2", status="compromised")
    assetslib.create_asset(a.id, "domain", "api.example.com")
    assert len(assetslib.list_assets(assessment_id=a.id, kind="host")) == 2
    assert len(assetslib.list_assets(assessment_id=a.id, status="compromised")) == 1
    assert len(assetslib.list_assets(assessment_id="other")) == 0


def test_update_and_kind_change(clean):
    a = assess.create_assessment("X")
    asset = assetslib.create_asset(a.id, "domain", "OLD.example.com")
    upd = assetslib.update_asset(asset.id, label="renamed", status="out-of-scope", tags=["t"])
    assert upd["label"] == "renamed"
    assert upd["status"] == "out-of-scope"
    assert upd["tags"] == ["t"]
    moved = assetslib.update_asset(asset.id, kind="service")
    assert moved["kind"] == "service"
    # old dedup key no longer matches a host lookup
    assert assetslib.get_asset(asset.id)["kind"] == "service"
    assert assetslib.update_asset(asset.id, status="bogus", kind="planet") is None


def test_delete_asset(clean):
    a = assess.create_assessment("X")
    asset = assetslib.create_asset(a.id, "host", "10.0.0.1")
    assert assetslib.delete_asset(asset.id) is True
    assert assetslib.delete_asset(asset.id) is False
    assert not assetslib.list_assets(assessment_id=a.id)


def test_summary_counts(clean):
    a = assess.create_assessment("X")
    assetslib.create_asset(a.id, "host", "10.0.0.1")
    assetslib.create_asset(a.id, "host", "10.0.0.2")
    assetslib.create_asset(a.id, "endpoint", "10.0.0.1/admin")
    s = assetslib.summary(assessment_id=a.id)
    assert s["total"] == 3
    assert s["by_kind"] == {"host": 2, "endpoint": 1}
    sglobal = assetslib.summary()
    assert sglobal["total"] == 3


# ── ingest_findings ───────────────────────────────────────────────────────

def test_ingest_classifies_ip_and_domain(clean):
    a = assess.create_assessment("X")
    res = assetslib.ingest_findings(a.id, [
        {"tool": "nmap", "target": "10.0.0.1", "type": "open-port", "port": 22, "service": "ssh", "version": "8.2p1"},
        {"tool": "whatweb", "target": "www.example.com", "type": "tech", "service": "nginx", "version": "1.18.0"},
    ])
    assert res["created"] == 2
    assert res["ports"] == 1
    assert res["services"] == 2  # one service entry per distinct asset
    items = assetslib.list_assets(assessment_id=a.id, kind="host")
    assert items[0]["address"] == "10.0.0.1"
    assert items[0]["ports"][0]["service"] == "ssh"
    doms = assetslib.list_assets(assessment_id=a.id, kind="domain")
    assert doms[0]["address"] == "www.example.com"
    assert assetslib.list_assets(assessment_id=a.id, kind="host")[0]["findings_count"] == 1


def test_ingest_requires_assessment(clean):
    with pytest.raises(ValueError, match="not found"):
        assetslib.ingest_findings("missing", [{"target": "10.0.0.1"}])


def test_ingest_skips_empty_targets(clean):
    a = assess.create_assessment("X")
    res = assetslib.ingest_findings(a.id, [
        {"tool": "nmap", "target": ""},
        {"tool": "nmap", "target": None},
        "not-a-dict",
    ])
    assert res["skipped"] == 2
    assert res["errors"] == 1
    assert not assetslib.list_assets(assessment_id=a.id)


def test_ingest_endpoint_assets(clean):
    a = assess.create_assessment("X")
    res = assetslib.ingest_findings(a.id, [
        {"tool": "gobuster", "target": "http://10.0.0.1", "type": "directory", "path": "/admin", "status": 200},
    ])
    assert res["created"] == 1
    eps = assetslib.list_assets(assessment_id=a.id, kind="host")
    assert eps[0]["address"] == "10.0.0.1"
    # '/' paths are not turned into endpoints
    res2 = assetslib.ingest_findings(a.id, [
        {"tool": "curl", "target": "http://10.0.0.1", "type": "generic", "path": "/"},
    ])
    endpoints = assetslib.list_assets(assessment_id=a.id, kind="endpoint")
    assert len(endpoints) == 1
    assert endpoints[0]["address"] == "10.0.0.1/admin"
    assert res2["skipped"] == 0


def test_ingest_merge_reuses_host(clean):
    a = assess.create_assessment("X")
    assetslib.ingest_findings(a.id, [{"tool": "nmap", "target": "10.0.0.1", "port": "443/tcp", "service": "https"}])
    assetslib.ingest_findings(a.id, [{"tool": "nmap", "target": "https://10.0.0.1", "port": 22, "service": "ssh"}])
    hosts = assetslib.list_assets(assessment_id=a.id, kind="host")
    assert len(hosts) == 1
    assert len(hosts[0]["ports"]) == 2


def test_ingest_port_dedup(clean):
    a = assess.create_assessment("X")
    assetslib.ingest_findings(a.id, [{"tool": "nmap", "target": "10.0.0.1", "port": "80/tcp", "service": "http"}])
    assetslib.ingest_findings(a.id, [{"tool": "nmap", "target": "10.0.0.1", "port": 80, "service": "http"}])
    hosts = assetslib.list_assets(assessment_id=a.id, kind="host")
    assert len(hosts[0]["ports"]) == 1


def test_export_import_roundtrip(clean):
    a = assess.create_assessment("X")
    assetslib.create_asset(a.id, "host", "10.0.0.1", notes="n")
    rows = assetslib.export_state()
    assert len(rows) == 1
    assetslib.reset_assets()
    res = assetslib.import_state(rows, replace=True)
    assert res["imported"] == 1
    assert assetslib.list_assets(assessment_id=a.id)[0]["address"] == "10.0.0.1"
    bad = assetslib.import_state([{"kind": "host", "address": ""}, "junk"], replace=False)
    assert bad["rejected"] == 1


def test_delete_assets_for_assessment(clean):
    a1 = assess.create_assessment("X")
    a2 = assess.create_assessment("Y")
    assetslib.create_asset(a1.id, "host", "10.0.0.1")
    assetslib.create_asset(a2.id, "host", "10.0.0.9")
    assert assetslib.delete_assets_for_assessment(a1.id) == 1
    assert not assetslib.list_assets(assessment_id=a1.id)
    assert len(assetslib.list_assets(assessment_id=a2.id)) == 1


# ── REST endpoints ────────────────────────────────────────────────────────

def test_api_create_list_filter(client, sample_assessment):
    aid = sample_assessment["id"]
    r = client.post("/api/assets", json={"assessment_id": aid, "kind": "host", "address": "10.0.0.1"})
    assert r.status_code == 200
    asset = r.json()["asset"]
    assert asset["kind"] == "host"
    r = client.get("/api/assets", params={"assessment_id": aid})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["assets"][0]["id"] == asset["id"]
    # unknown assessment -> 400
    r = client.post("/api/assets", json={"assessment_id": "nope", "kind": "host", "address": "10.0.0.2"})
    assert r.status_code == 400


def test_api_get_update_delete(client, sample_assessment):
    aid = sample_assessment["id"]
    asset = client.post("/api/assets", json={"assessment_id": aid, "kind": "domain", "address": "x.com"}).json()["asset"]
    g = client.get(f"/api/assets/{asset['id']}")
    assert g.status_code == 200
    assert g.json()["asset"]["address"] == "x.com"
    u = client.put(f"/api/assets/{asset['id']}", json={"status": "compromised", "notes": "owned"})
    assert u.status_code == 200
    assert u.json()["asset"]["status"] == "compromised"
    d = client.delete(f"/api/assets/{asset['id']}")
    assert d.status_code == 200
    assert client.get(f"/api/assets/{asset['id']}").status_code == 404
    assert client.delete(f"/api/assets/{asset['id']}").status_code == 404


def test_api_by_assessment_and_summary(client, sample_assessment):
    aid = sample_assessment["id"]
    client.post("/api/assets", json={"assessment_id": aid, "kind": "host", "address": "10.0.0.1"})
    r = client.get(f"/api/assets/by-assessment/{aid}")
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["summary"]["by_kind"] == {"host": 1}
    r = client.get("/api/assets/summary", params={"assessment_id": aid})
    assert r.status_code == 200
    assert r.json()["summary"]["total"] == 1


def test_api_ingest(client, sample_assessment):
    aid = sample_assessment["id"]
    r = client.post("/api/assets/ingest", json={"assessment_id": aid, "findings": [
        {"tool": "nmap", "target": "10.0.0.1", "port": 22, "service": "ssh"},
    ]})
    assert r.status_code == 200
    assert r.json()["created"] == 1
    r = client.post("/api/assets/ingest", json={"assessment_id": "missing", "findings": []})
    assert r.status_code == 400


def test_api_export_import(client, sample_assessment):
    aid = sample_assessment["id"]
    client.post("/api/assets", json={"assessment_id": aid, "kind": "host", "address": "10.0.0.1"})
    rows = client.get("/api/assets/export").json()["rows"]
    assert len(rows) == 1
    # cleanup via API list is read-only; clear by deleting assessment
    r = client.delete(f"/api/assessments/{aid}")
    assert r.status_code == 200
    assert client.get(f"/api/assets/by-assessment/{aid}").json()["count"] == 0
    r = client.post("/api/assets/import", json={"rows": rows, "replace": True})
    # assessment no longer exists but import validates rows only
    assert r.status_code == 200
    assert r.json()["imported"] == 1


def test_assessment_delete_cascades_assets(client, sample_assessment):
    aid = sample_assessment["id"]
    client.post("/api/assets", json={"assessment_id": aid, "kind": "host", "address": "10.0.0.1"})
    assert client.get(f"/api/assets/by-assessment/{aid}").json()["count"] == 1
    assert client.delete(f"/api/assessments/{aid}").status_code == 200
    assert client.get(f"/api/assets/by-assessment/{aid}").json()["count"] == 0