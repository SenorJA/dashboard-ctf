"""
Tests for backend.phishing_sim (phishing awareness simulation, training-only).

The registry is process-wide; fixtures wipe it and reset the hydration flag.
Persistence (workspace_store) is opt-out here so tests are hermetic.
"""
import pytest

from backend import phishing_sim as ps

VALID = {
    "name": "Campaña Q3",
    "template_id": "generic_portal",
    "target": "equipo.ventas@corp.example",
    "authorized_by": "dpo@corp.example",
}


@pytest.fixture(autouse=True)
def _clean_registry(monkeypatch):
    monkeypatch.delenv("MIRV_PERSIST_WORKSPACE", raising=False)
    from backend import workspace_store as ws
    monkeypatch.setattr(ws, "is_enabled", lambda: False)  # hermetic: no live Supabase
    ps._REGISTRY.clear()
    ps._HYDRATED = False
    if ps._store is not None:
        ws.clear_cache("phishing")
    yield
    ps._REGISTRY.clear()
    ps._HYDRATED = False


def test_templates_expose_three_generic():
    t = ps.templates()
    assert len(t) == 3
    assert {x["id"] for x in t} == {"generic_portal", "invoice_notice", "it_password_reset"}
    for item in t:
        assert item["name"] and item["category"] and item["description"]


def test_stats_empty_start():
    assert ps.stats() == {
        "total": 0,
        "by_status": {},
        "total_clicks": 0,
        "total_submissions": 0,
    }


def test_create_requires_fields():
    c, err = ps.create_campaign("", "generic_portal", "t", "o")
    assert c is None and "obligatorios" in err
    c, err = ps.create_campaign("n", "generic_portal", "t", "")
    assert c is None and "obligatorios" in err


def test_create_unknown_template():
    c, err = ps.create_campaign("n", "nope", "t", "o")
    assert c is None and "plantilla desconocida" in err


def test_create_lists_and_get():
    camp, err = ps.create_campaign(**VALID)
    assert err is None and camp is not None
    assert camp.id.startswith("ph-")
    assert camp.status == "planning"
    assert camp.clicks == 0 and camp.submissions == 0
    assert ps.get_campaign(camp.id).name == VALID["name"]
    lst = ps.list_campaigns()
    assert len(lst) == 1 and lst[0]["id"] == camp.id
    stats = ps.stats()
    assert stats["total"] == 1 and stats["by_status"] == {"planning": 1}


def test_landing_only_when_active():
    camp, _ = ps.create_campaign(**VALID)
    html, err = ps.render_landing(camp.id)
    assert html is None and "no activa" in err
    camp, err = ps.activate_campaign(camp.id)
    assert err is None and camp.status == "active"
    html, err = ps.render_landing(camp.id)
    assert err is None and html is not None
    assert "SIMULACIÓN DE PHISHING CONTROLADA" in html
    assert f'action="/phishing/{camp.id}/submit"' in html
    assert camp.started_at


def test_click_only_when_active():
    camp, _ = ps.create_campaign(**VALID)
    target_id = camp.id
    camp, err = ps.record_click(target_id)
    assert camp is None and "no activa" in err
    camp, err = ps.activate_campaign(target_id)
    assert err is None and camp.status == "active"
    camp, err = ps.record_click(target_id)
    assert err is None and camp.clicks == 1


def test_submission_hashes_and_never_plaintext():
    camp, _ = ps.create_campaign(**VALID)
    camp, _ = ps.activate_campaign(camp.id)
    evt, err = ps.record_submission(camp.id, "realmail@x.es", "P4ssw0rd!")
    assert err is None
    assert evt["campaign_id"] == camp.id
    assert len(evt["username_hash"]) == 16
    assert len(evt["password_hash"]) == 16
    for secret in ("realmail@x.es", "P4ssw0rd!"):
        assert secret not in ps.list_campaigns()[0].get("hashes", [])
    entry = ps.list_campaigns()[0]["hashes"][0]
    assert entry["p"] == evt["password_hash"]
    camp2 = ps.get_campaign(camp.id)
    assert camp2.submissions == 1


def test_submission_rejected_when_inactive():
    camp, _ = ps.create_campaign(**VALID)
    evt, err = ps.record_submission(camp.id, "u", "p")
    assert evt is None and "no activa" in err


def test_archive_then_no_landing():
    camp, _ = ps.create_campaign(**VALID)
    camp, _ = ps.activate_campaign(camp.id)
    camp, err = ps.archive_campaign(camp.id)
    assert err is None and camp.status == "archived" and camp.finished_at
    html, err = ps.render_landing(camp.id)
    assert html is None and "no activa" in err


def test_archive_cannot_reactivate():
    camp, _ = ps.create_campaign(**VALID)
    ps.activate_campaign(camp.id)
    ps.archive_campaign(camp.id)
    camp, err = ps.activate_campaign(camp.id)
    assert camp is None and "archivada" in err


def test_delete_removes():
    camp, _ = ps.create_campaign(**VALID)
    assert ps.delete_campaign("ph-nope") is False
    assert ps.delete_campaign(camp.id) is True
    assert ps.get_campaign(camp.id) is None
    assert ps.stats()["total"] == 0


def test_result_page():
    camp, _ = ps.create_campaign(**VALID)
    html, err = ps.render_result(camp.id)
    assert err is None and "Has picado en la simulación" in html
    assert "credenciales reales no se introducen" not in html  # la advertencia queda en la landing


def test_escapes_html_in_landing():
    values = dict(VALID)
    values["name"] = "<script>alert(1)</script>"
    camp, _ = ps.create_campaign(**values)
    camp, _ = ps.activate_campaign(camp.id)
    html, _ = ps.render_landing(camp.id)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_persistence_opt_in_upserts(monkeypatch):
    """With MIRV_PERSIST_WORKSPACE=1 + workspace_store available, mutating ops persist."""
    monkeypatch.setenv("MIRV_PERSIST_WORKSPACE", "1")
    from backend import workspace_store as ws

    calls = []
    monkeypatch.setattr(ws, "is_enabled", lambda: True)
    monkeypatch.setattr(ws, "upsert", lambda key, data: calls.append((key, data)) or True)
    monkeypatch.setattr(ws, "load", lambda key: None)
    camp, _ = ps.create_campaign(**VALID)
    ps.activate_campaign(camp.id)
    ps.record_click(camp.id)
    assert calls, "se esperaba al menos un upsert"
    assert all(key == "phishing" for key, _ in calls)


def test_hydrates_from_workspace_store(monkeypatch):
    """Campaigns are rebuilt from a stored snapshot after a restart."""
    monkeypatch.setenv("MIRV_PERSIST_WORKSPACE", "1")
    from dataclasses import asdict
    from backend import workspace_store as ws

    camp, _ = ps.create_campaign(**VALID)
    snapshot = asdict(camp)
    monkeypatch.setattr(ws, "is_enabled", lambda: True)
    monkeypatch.setattr(ws, "load", lambda key: [snapshot])
    monkeypatch.setattr(ws, "upsert", lambda k, d: True)
    ps._REGISTRY.clear()  # simulate restart
    ps._HYDRATED = False
    assert ps.get_campaign(camp.id) is not None
    assert ps.stats()["total"] == 1
    assert ps.get_campaign(camp.id).hashes == []


def test_foreign_object_never_persisted_in_registry(monkeypatch):
    """Extra/missing fields in the snapshot are tolerated (defensive hydration)."""
    ps._REGISTRY["ph-fake"] = ps.PhishingCampaign(
        id="ph-fake",
        name="legacy",
        template_id="generic_portal",
        target="t",
        authorized_by="o",
        hashes=[{"u": "a", "p": "b", "at": "2026-01-01T00:00:00+00:00"}],
    )
    assert ps.get_campaign("ph-fake").name == "legacy"
    ps._REGISTRY.clear()


# ═─────────────── API endpoint integration ═───────────────

def test_api_phishing_templates_and_stats(client):
    r = client.get("/api/phishing/templates")
    assert r.status_code == 200 and len(r.json()["templates"]) == 3
    r = client.get("/api/phishing/stats")
    assert r.status_code == 200 and r.json()["stats"]["total"] == 0


def test_api_phishing_full_flow(client, monkeypatch):
    saved = []
    monkeypatch.setattr("main.db.save_finding", lambda f: saved.append(f) or {"id": "f1"})

    r = client.post("/api/phishing/campaigns", json={
        "name": "Camp Q3", "template_id": "invoice_notice",
        "target": "finanzas@corp.example", "authorized_by": "dpo@corp.example", "notes": "n",
    })
    assert r.status_code == 201
    cid = r.json()["campaign"]["id"]

    r = client.get("/api/phishing/campaigns")
    assert r.status_code == 200 and len(r.json()["campaigns"]) == 1

    r = client.post(f"/api/phishing/campaigns/{cid}/activate")
    assert r.status_code == 200
    assert r.json()["landing_url"] == f"/phishing/{cid}"

    r = client.get(f"/phishing/{cid}")
    assert r.status_code == 200 and "SIMULACIÓN DE PHISHING CONTROLADA" in r.text
    assert client.get("/api/phishing/stats").json()["stats"]["total_clicks"] == 1

    r = client.post(f"/phishing/{cid}/submit",
                    data={"username": "vic@corp.example", "password": "S3cr3t!"})
    assert r.status_code == 200 and "Has picado en la simulación" in r.text

    stats = client.get("/api/phishing/stats").json()["stats"]
    assert stats["total_submissions"] == 1
    assert saved, "se esperaba una finding persistida"
    assert saved[0]["severity"] == "high" and saved[0]["type"] == "phishing-awareness"

    detail = client.get(f"/api/phishing/campaigns/{cid}").json()["campaign"]
    assert detail["submissions"] == 1 and len(detail["hashes"]) == 1
    assert detail["hashes"][0]["p"] != "S3cr3t!"  # never plaintext
    assert "vic@corp.example" not in str(detail["hashes"])


def test_api_phishing_ended_landing(client):
    r = client.get("/phishing/nonexistent")
    assert r.status_code == 410
    assert "Simulación terminada" in r.text


def test_api_phishing_submit_when_inactive(client, monkeypatch):
    r = client.post("/api/phishing/campaigns", json={
        "name": "C", "template_id": "generic_portal",
        "target": "t", "authorized_by": "o",
    })
    cid = r.json()["campaign"]["id"]
    r = client.post(f"/phishing/{cid}/submit", data={"username": "u", "password": "p"})
    assert r.status_code == 410


def test_api_phishing_archive_and_delete(client):
    r = client.post("/api/phishing/campaigns", json={
        "name": "C", "template_id": "generic_portal", "target": "t", "authorized_by": "o",
    })
    cid = r.json()["campaign"]["id"]
    r = client.post(f"/api/phishing/campaigns/{cid}/activate")
    assert r.status_code == 200
    r = client.post(f"/api/phishing/campaigns/{cid}/archive")
    assert r.status_code == 200
    r = client.get(f"/phishing/{cid}")
    assert r.status_code == 410
    r = client.delete(f"/api/phishing/campaigns/{cid}")
    assert r.status_code == 200 and r.json()["ok"] is True
    r = client.get(f"/api/phishing/campaigns/{cid}")
    assert r.status_code == 404