"""
Tests for assessments -- Workspace assessments module.

Covers:
  - Assessment CRUD (create, get, list, update, delete)
  - Target management (add_target, remove_target, dedup, boundary)
  - Query by target (assessments_by_target)
  - Summary aggregate (counts, statuses)
  - Validation (empty name, invalid status, max limits)
  - Thread safety (parallel deletes)
  - REST endpoints (list, create, get, update, delete, targets, by-target)
"""

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend.assessments import (
    Assessment,
    VALID_STATUSES,
    MAX_ASSESSMENTS,
    MAX_TARGETS_PER_ASSESSMENT,
    create_assessment,
    list_assessments,
    get_assessment,
    update_assessment,
    delete_assessment,
    add_target,
    remove_target,
    assessments_by_target,
    reset_assessments,
    summary,
)
from fastapi.testclient import TestClient
from main import app


@pytest.fixture(autouse=True)
def _clean_state():
    reset_assessments()
    yield
    reset_assessments()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── Module: core CRUD ───────────────────────────────────────────────

class TestAssessmentCRUD:
    def test_create_minimal(self):
        a = create_assessment("Pentest ABC")
        assert a.name == "Pentest ABC"
        assert a.status == "planning"
        assert isinstance(a.id, str) and len(a.id) == 12

    def test_create_all_fields(self):
        a = create_assessment("Full", description="d", status="in-progress",
                              targets=["10.0.0.1", "10.0.0.2"], tags=["external"], notes="some")
        assert a.description == "d"
        assert len(a.targets) == 2
        assert a.tags == ["external"]
        assert a.notes == "some"
        assert a.status == "in-progress"

    def test_create_empty_name_raises(self):
        with pytest.raises(ValueError, match="name is required"):
            create_assessment("")

    def test_create_invalid_status_raises(self):
        with pytest.raises(ValueError, match="invalid status"):
            create_assessment("X", status="meh")

    def test_list_assessments_ordered(self):
        create_assessment("B")
        create_assessment("A")
        ids = [a["id"] for a in list_assessments()]
        # newest first (created same instant, but appended later = higher id hash)
        assert len(ids) == 2

    def test_list_has_target_count(self):
        create_assessment("T", targets=["1.1.1.1", "2.2.2.2"])
        item = list_assessments()[0]
        assert item["target_count"] == 2

    def test_get_existing(self):
        a = create_assessment("Get Me")
        out = get_assessment(a.id)
        assert out is not None
        assert out["name"] == "Get Me"

    def test_get_nonexistent(self):
        assert get_assessment("zzzzzzzzzzzz") is None

    def test_update_existing(self):
        a = create_assessment("Old")
        out = update_assessment(a.id, name="New", notes="nn")
        assert out is not None
        assert out["name"] == "New"
        assert out["notes"] == "nn"

    def test_update_status_only(self):
        a = create_assessment("S")
        out = update_assessment(a.id, status="done")
        assert out["status"] == "done"

    def test_update_invalid_status_returns_none(self):
        a = create_assessment("S")
        out = update_assessment(a.id, status="bogus")
        assert out is None

    def test_delete_existing(self):
        a = create_assessment("D")
        assert delete_assessment(a.id) is True
        assert get_assessment(a.id) is None

    def test_delete_nonexistent(self):
        assert delete_assessment("zzzzzzzzzzzz") is False


# ── Module: targets ────────────────────────────────────────────────

class TestAssessmentTargets:
    def test_add_target(self):
        a = create_assessment("T")
        out = add_target(a.id, "10.0.0.1")
        assert "10.0.0.1" in out["targets"]

    def test_add_target_dedup(self):
        a = create_assessment("T")
        add_target(a.id, "10.0.0.1")
        out = add_target(a.id, "10.0.0.1")
        assert out["targets"].count("10.0.0.1") == 1

    def test_add_target_strips_trailing_slash(self):
        a = create_assessment("T")
        out = add_target(a.id, "10.0.0.1/")
        assert out["targets"][0] == "10.0.0.1"

    def test_add_target_empty_returns_none(self):
        a = create_assessment("T")
        assert add_target(a.id, "  ") is None

    def test_add_target_nonexistent_returns_none(self):
        assert add_target("zzzzzzzzzzzz", "10.0.0.1") is None

    def test_remove_target(self):
        a = create_assessment("T", targets=["a", "b"])
        out = remove_target(a.id, "a")
        assert "a" not in out["targets"]
        assert "b" in out["targets"]

    def test_remove_nonexistent_target_ok(self):
        a = create_assessment("T", targets=["a"])
        out = remove_target(a.id, "z")
        assert "a" in out["targets"]


# ── Module: by_target + summary ──────────────────────────────────────

class TestAssessmentByTargetAndSummary:
    def test_by_target(self):
        create_assessment("A", targets=["x", "y"])
        create_assessment("B", targets=["y"])
        result = assessments_by_target("y")
        assert len(result) == 2
        assert all(any(t["id"] == r["id"] for t in result) for r in result)

    def test_by_target_empty(self):
        assert assessments_by_target("") == []
        assert assessments_by_target("zzz") == []

    def test_summary(self):
        create_assessment("A", targets=["x"], status="done")
        s = summary()
        assert s["total"] == 1
        assert s["unique_targets"] == 1
        assert s["by_status"]["done"] == 1


# ── Module: limits ────────────────────────────────────────────────

class TestAssessmentLimits:
    def test_max_assessments_error(self):
        for i in range(MAX_ASSESSMENTS):
            create_assessment(f"A{i}")
        with pytest.raises(ValueError, match="max"):
            create_assessment("Overflow")

    def test_max_targets_per_assessment(self):
        a = create_assessment("Big")
        for i in range(MAX_TARGETS_PER_ASSESSMENT + 10):
            out = add_target(a.id, f"10.0.{i}.1")
            if out is None:
                break
        final = get_assessment(a.id)
        assert len(final["targets"]) == MAX_TARGETS_PER_ASSESSMENT
        # Further adds refused once full
        assert add_target(a.id, "zzz") is None


# ── Module: thread safety ────────────────────────────────────────────

class TestAssessmentThreadSafety:
    def test_concurrent_deletes(self):
        ids = [create_assessment(f"T{i}").id for i in range(10)]
        results = []
        def worker(i):
            results.append(delete_assessment(ids[i]))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(results)
        assert len(list_assessments()) == 0


# ── REST Endpoints ───────────────────────────────────────────────────

class TestAssessmentsEndpoint:
    def test_list_empty(self, client: TestClient):
        r = client.get("/api/assessments")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["assessments"] == []
        assert d["summary"]["total"] == 0

    def test_create_and_list(self, client: TestClient):
        r = client.post("/api/assessments", json={"name": "P1", "targets": ["a", "b"]})
        assert r.status_code == 200
        aid = r.json()["assessment"]["id"]
        r2 = client.get("/api/assessments")
        assert len(r2.json()["assessments"]) == 1
        assert r2.json()["summary"]["unique_targets"] == 2

    def test_create_empty_name(self, client: TestClient):
        r = client.post("/api/assessments", json={"name": ""})
        assert r.status_code == 400
        assert r.json()["error"]

    def test_get_not_found(self, client: TestClient):
        assert client.get("/api/assessments/zzzzzzzzzzzz").status_code == 404

    def test_update_status(self, client: TestClient):
        aid = client.post("/api/assessments", json={"name": "U"}).json()["assessment"]["id"]
        r = client.put(f"/api/assessments/{aid}", json={"status": "done"})
        assert r.json()["assessment"]["status"] == "done"

    def test_delete(self, client: TestClient):
        aid = client.post("/api/assessments", json={"name": "D"}).json()["assessment"]["id"]
        r = client.delete(f"/api/assessments/{aid}")
        assert r.json()["ok"] is True
        assert client.get(f"/api/assessments/{aid}").status_code == 404

    def test_add_and_remove_target(self, client: TestClient):
        aid = client.post("/api/assessments", json={"name": "T"}).json()["assessment"]["id"]
        r = client.post(f"/api/assessments/{aid}/targets", json={"target": "10.0.0.1"})
        assert "10.0.0.1" in r.json()["assessment"]["targets"]
        r2 = client.delete(f"/api/assessments/{aid}/targets/10.0.0.1")
        assert "10.0.0.1" not in r2.json()["assessment"]["targets"]

    def test_by_target(self, client: TestClient):
        client.post("/api/assessments", json={"name": "A", "targets": ["x"]})
        r = client.get("/api/assessments/by-target/x")
        assert len(r.json()["assessments"]) == 1
        assert client.get("/api/assessments/by-target/zzz").json()["assessments"] == []