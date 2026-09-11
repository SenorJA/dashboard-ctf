"""
Tests for scheduler -- Scheduled scans module.

Covers:
  - Job CRUD (create, get, list, update, delete)
  - Interval validation (range, types)
  - due_jobs auto-advance logic (single trigger, respects interval)
  - Toggle (enable/disable) without resetting schedule
  - Thread safety (concurrent updates)
  - REST endpoints (list, create, update, delete, due)
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend.scheduler import (
    Job,
    MIN_INTERVAL_SECONDS,
    MAX_INTERVAL_SECONDS,
    MAX_JOBS,
    create_job,
    list_jobs,
    get_job,
    update_job,
    delete_job,
    toggle_job,
    due_jobs,
    reset_jobs,
    summary,
    _now,
)
from fastapi.testclient import TestClient
from main import app


@pytest.fixture(autouse=True)
def _clean_state():
    reset_jobs()
    yield
    reset_jobs()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── Module: core CRUD ───────────────────────────────────────────────

class TestSchedulerCRUD:
    def test_create_minimal(self):
        j = create_job("Recon", "nmap", 3600)
        assert j.name == "Recon"
        assert j.tool_id == "nmap"
        assert j.interval_seconds == 3600
        assert j.enabled is True
        assert j.last_run is None

    def test_create_with_target(self):
        j = create_job("Dir scan", "gobuster", 300, target="10.0.0.1")
        assert j.target == "10.0.0.1"

    def test_create_empty_name_raises(self):
        with pytest.raises(ValueError, match="name is required"):
            create_job("", "nmap", 100)

    def test_create_empty_tool_id_raises(self):
        with pytest.raises(ValueError, match="tool_id is required"):
            create_job("X", "", 100)

    def test_create_interval_too_small(self):
        with pytest.raises(ValueError, match="interval_seconds"):
            create_job("X", "nmap", 5)

    def test_create_interval_too_large(self):
        with pytest.raises(ValueError, match="interval_seconds"):
            create_job("X", "nmap", MAX_INTERVAL_SECONDS + 1)

    def test_create_bool_interval_raises(self):
        with pytest.raises(ValueError, match="interval_seconds"):
            create_job("X", "nmap", True)  # type: ignore

    def test_list_jobs(self):
        create_job("A", "nmap", 100)
        create_job("B", "gobuster", 200)
        jobs = list_jobs()
        assert len(jobs) == 2

    def test_get_existing(self):
        j = create_job("Get", "nikto", 100)
        out = get_job(j.id)
        assert out is not None
        assert out["name"] == "Get"

    def test_get_nonexistent(self):
        assert get_job("zzzzzzzzzzzz") is None

    def test_update_fields(self):
        j = create_job("Old", "nmap", 100)
        out = update_job(j.id, name="New", interval_seconds=200, target="x")
        assert out["name"] == "New"
        assert out["interval_seconds"] == 200
        assert out["target"] == "x"

    def test_update_invalid_interval_returns_none(self):
        j = create_job("J", "nmap", 100)
        assert update_job(j.id, interval_seconds=3) is None

    def test_update_nonexistent_returns_none(self):
        assert update_job("zzzzzzzzzzzz", name="X") is None

    def test_delete_existing(self):
        j = create_job("D", "nmap", 100)
        assert delete_job(j.id) is True
        assert get_job(j.id) is None

    def test_delete_nonexistent(self):
        assert delete_job("zzzzzzzzzzzz") is False


# ── Module: due_jobs + auto-advance ──────────────────────────────────

class TestSchedulerDueJobs:
    def test_due_now(self):
        j = create_job("D", "nmap", 60)
        old_next = j.next_run
        due = due_jobs(now=old_next + 1)
        assert len(due) == 1
        assert due[0]["id"] == j.id
        assert due[0]["last_run"] is not None
        assert due[0]["next_run"] > old_next

    def test_not_due_yet(self):
        create_job("F", "nmap", 3600)
        assert due_jobs(now=_now()) == []

    def test_auto_advance_prevents_double_trigger(self):
        j = create_job("D", "nmap", 60)
        old_next = j.next_run
        first = due_jobs(now=old_next + 1)
        assert len(first) == 1
        second = due_jobs(now=old_next + 1.01)
        assert second == []  # already advanced past old_next + 1.01

    def test_disabled_job_not_due(self):
        j = create_job("D", "nmap", 10, enabled=False)
        assert due_jobs(now=j.next_run + 100) == []

    def test_respect_interval_after_advance(self):
        j = create_job("D", "nmap", 60)
        old_next = j.next_run
        first = due_jobs(now=old_next + 1)
        assert len(first) == 1
        new_next = first[0]["next_run"]  # should be ~old_next + 61
        # Not due again before the new point
        assert due_jobs(now=new_next - 1) == []
        # Due at exactly the new point (single trigger again)
        second = due_jobs(now=new_next)
        assert len(second) == 1
        # Then quiet again
        assert due_jobs(now=new_next + 0.5) == []


# ── Module: toggle + summary ──────────────────────────────────────

class TestSchedulerToggleAndSummary:
    def test_toggle_disable(self):
        j = create_job("T", "nmap", 60)
        out = toggle_job(j.id, False)
        assert out["enabled"] is False
        assert out["interval_seconds"] == 60  # not reset

    def test_summary(self):
        create_job("A", "nmap", 100)
        create_job("B", "gobuster", 200, enabled=False)
        s = summary()
        assert s["total"] == 2
        assert s["enabled"] == 1


# ── Module: max jobs ──────────────────────────────────────────────

class TestSchedulerLimits:
    def test_max_jobs_error(self):
        for i in range(MAX_JOBS):
            create_job(f"J{i}", "nmap", 100 + i)
        with pytest.raises(ValueError, match="max"):
            create_job("Overflow", "nmap", 100)


# ── Module: thread safety ────────────────────────────────────────────

class TestSchedulerThreadSafety:
    def test_concurrent_creates(self):
        ids = set()
        def worker(i):
            j = create_job(f"J{i}", "nmap", 100 + i)
            ids.add(j.id)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(ids) == 20


# ── REST Endpoints ───────────────────────────────────────────────────

class TestSchedulerEndpoint:
    def test_list_empty(self, client: TestClient):
        r = client.get("/api/scheduler/jobs")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["jobs"] == []
        assert d["summary"]["total"] == 0

    def test_create_and_list(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={
            "name": "Port scan", "tool_id": "nmap", "interval_seconds": 300, "target": "10.0.0.1"
        })
        assert r.status_code == 200
        jid = r.json()["job"]["id"]
        r2 = client.get("/api/scheduler/jobs")
        assert len(r2.json()["jobs"]) == 1

    def test_create_invalid(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={
            "name": "", "tool_id": "nmap", "interval_seconds": 100
        })
        assert r.status_code == 400

    def test_update(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={"name": "X", "tool_id": "nmap", "interval_seconds": 100})
        jid = r.json()["job"]["id"]
        r2 = client.put(f"/api/scheduler/jobs/{jid}", json={"name": "Y"})
        assert r2.json()["job"]["name"] == "Y"

    def test_delete(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={"name": "D", "tool_id": "nmap", "interval_seconds": 100})
        jid = r.json()["job"]["id"]
        r2 = client.delete(f"/api/scheduler/jobs/{jid}")
        assert r2.json()["ok"] is True
        r3 = client.get("/api/scheduler/jobs")
        assert all(j["id"] != jid for j in r3.json()["jobs"])

    def test_due(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={"name": "D", "tool_id": "nmap", "interval_seconds": 10})
        jid = r.json()["job"]["id"]
        # force next_run into the past
        from backend.scheduler import _jobs
        _jobs[jid].next_run = _now() - 5
        r2 = client.get("/api/scheduler/due")
        assert len(r2.json()["jobs"]) == 1
        assert r2.json()["jobs"][0]["id"] == jid
        # second call should return nothing
        r3 = client.get("/api/scheduler/due")
        assert r3.json()["jobs"] == []

    def test_run_now(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={"name": "R", "tool_id": "nmap", "interval_seconds": 86400})
        jid = r.json()["job"]["id"]
        r2 = client.post(f"/api/scheduler/jobs/{jid}/run")
        assert r2.status_code == 200
        assert r2.json()["ok"] is True
        # /due now fires it
        r3 = client.get("/api/scheduler/due")
        assert len(r3.json()["jobs"]) == 1
        assert r3.json()["jobs"][0]["id"] == jid

    def test_run_now_disabled(self, client: TestClient):
        r = client.post("/api/scheduler/jobs", json={"name": "R", "tool_id": "nmap", "interval_seconds": 86400, "enabled": False})
        jid = r.json()["job"]["id"]
        assert client.post(f"/api/scheduler/jobs/{jid}/run").status_code == 404

    def test_run_now_not_found(self, client: TestClient):
        assert client.post("/api/scheduler/jobs/zzzzzzzzzzzz/run").status_code == 404

    def test_delete_not_found(self, client: TestClient):
        assert client.delete("/api/scheduler/jobs/zzzzzzzzzzzz").status_code == 404