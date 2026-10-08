"""Pack 18 — REST endpoints for the LLM security scanner (/api/llm/*).

End-to-end through `TestClient(app)` with the deterministic `stub` client, and
patched integration points (database findings + SIEM + audit + notifications)
for the finding-push flows. No real LLM / network calls happen here.
"""
from __future__ import annotations

from unittest.mock import patch

import backend.llm_scanner as llms
from backend.main import app
from fastapi.testclient import TestClient

STUB_DAN = llms.StubClient(lambda p: "Sure, DAN Mode enabled. What do you want?")


def _mk_client():
    return TestClient(app)


def _clear_registry():
    llms.registry.clear()


def test_llm_probes_catalog_endpoint():
    with _mk_client() as c:
        r = c.get("/api/llm/probes")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["total"] == len(llms.PROBES) > 0
    assert set(body["families"]) == set(llms.FAMILIES)
    assert all(p["id"] in llms.PROBES for p in body["probes"])


def test_llm_probe_single_runs_against_stub():
    _clear_registry()
    with _mk_client() as c:
        r = c.post("/api/llm/probe", json={
            "target": {"mode": "stub"},
            "probe_ids": ["dan.DAN_11_0"],
        })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    report = body["report"]
    assert report["id"]
    assert report["target"] == "stub"
    assert len(report["probes"]) == 1
    assert report["probes"][0]["id"] == "dan.DAN_11_0"


def test_llm_probe_requires_at_least_one_probe():
    with _mk_client() as c:
        r = c.post("/api/llm/probe", json={"target": {"mode": "stub"}, "probe_ids": []})
    assert r.status_code == 422


def test_llm_probe_unknown_mode_is_400():
    with _mk_client() as c:
        r = c.post("/api/llm/probe", json={
            "target": {"mode": "nope"}, "probe_ids": ["dan.DAN_11_0"],
        })
    assert r.status_code == 400


def test_llm_probe_self_mode_requires_api_key():
    with _mk_client() as c:
        r = c.post("/api/llm/probe", json={
            "target": {"mode": "self", "api_key": ""},
            "probe_ids": ["dan.DAN_11_0"],
        })
    assert r.status_code == 400


def test_llm_scan_stores_and_lists_reports():
    _clear_registry()
    with _mk_client() as c:
        r = c.post("/api/llm/scan", json={
            "target": {"mode": "stub"},
            "probe_ids": ["dan.DAN_11_0"],
        })
        assert r.status_code == 200, r.text
        report = r.json()["report"]
        rid = report["id"]

        r2 = c.get("/api/llm/results")
        assert r2.status_code == 200
        assert rid in [x["id"] for x in r2.json()["reports"]]

        r3 = c.get(f"/api/llm/results/{rid}")
        assert r3.status_code == 200
        assert r3.json()["report"]["id"] == rid

        r4 = c.delete("/api/llm/results")
        assert r4.status_code == 200
        assert r4.json()["cleared"] >= 1

        r5 = c.get("/api/llm/results")
        assert r5.json()["reports"] == []


def test_llm_results_unknown_report_404():
    _clear_registry()
    with _mk_client() as c:
        assert c.get("/api/llm/results/nope").status_code == 404
        assert c.post("/api/llm/results/nope/findings").status_code == 404


def test_llm_scan_create_findings_pushes_to_db_siem_audit_and_notify():
    _clear_registry()
    with patch("backend.main._llm_client_for", return_value=STUB_DAN), \
         patch("backend.main.db.is_available", return_value=True), \
         patch("backend.main.db.save_finding", return_value={"id": "f1"}) as m_save, \
         patch("backend.main.siem_ingest") as m_siem, \
         patch("backend.main.al_audit") as m_audit, \
         patch("backend.main._notify_finding") as m_notify:
        with _mk_client() as c:
            r = c.post("/api/llm/scan", json={
                "target": {"mode": "stub"},
                "probe_ids": ["dan.DAN_11_0"],
                "create_findings": True,
            })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["findings"]["pushed"] > 0
    assert m_save.call_count == body["findings"]["pushed"]
    assert m_siem.call_count >= 1
    assert m_siem.call_args[0][0] == "llm"
    assert m_audit.call_count >= 1
    assert m_notify.call_count >= 1  # dan.DAN_11_0 es high
    saved = m_save.call_args[0][0]
    assert saved["tool"] == "llm-scanner"
    assert saved["severity"] in {"info", "low", "medium", "high", "critical"}


def test_llm_results_push_findings_endpoint():
    _clear_registry()
    with patch("backend.main._llm_client_for", return_value=STUB_DAN):
        with _mk_client() as c:
            r = c.post("/api/llm/scan", json={
                "target": {"mode": "stub"},
                "probe_ids": ["dan.DAN_11_0"],
            })
            rid = r.json()["report"]["id"]
    with patch("backend.main.db.is_available", return_value=True), \
         patch("backend.main.db.save_finding", return_value={"id": "f1"}) as m_save, \
         patch("backend.main.siem_ingest") as m_siem, \
         patch("backend.main.al_audit"):
        with _mk_client() as c:
            r2 = c.post(f"/api/llm/results/{rid}/findings")
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["ok"] is True
    assert body["pushed"] > 0
    assert m_save.called
    assert m_siem.called


def test_llm_scan_refusing_stub_is_not_vulnerable_without_findings():
    _clear_registry()
    with patch("backend.main._llm_client_for", return_value=llms.StubClient()):
        with _mk_client() as c:
            r = c.post("/api/llm/scan", json={
                "target": {"mode": "stub"},
                "families": ["dan"],
                "create_findings": True,
            })
    assert r.status_code == 200, r.text
    assert r.json()["report"]["summary"]["vulnerable_probes"] == 0
    assert r.json()["findings"] == {"pushed": 0, "skipped_db": 0, "siem_events": 0}


def test_llm_scan_accepts_families_and_buffs():
    _clear_registry()
    with _mk_client() as c:
        r = c.post("/api/llm/scan", json={
            "target": {"mode": "stub"},
            "families": ["goodside"],
            "buffs": ["base64"],
        })
    assert r.status_code == 200, r.text
    body = r.json()["report"]
    assert body["buffs"] == ["base64"]
    assert len(body["probes"]) == len(llms.PROBES) - sum(
        1 for p in llms.PROBES.values() if p["family"] != "goodside"
    )