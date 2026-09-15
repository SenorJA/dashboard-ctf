"""
Tests for finding lifecycle + assessment binding (Feature B).

Covers:
  - DB CRUD: save_finding/save_findings_bulk persist assessment_id + lifecycle_status
  - update_finding: partial updates, allowed-field whitelist, not-found
  - list_findings filters lifecycle_status / assessment_id
  - list_findings_by_assessment
  - REST: PATCH /api/findings/{id} (success, invalid lifecycle 400, unknown field 400,
    not found 404, empty body 400)
  - REST: GET /api/findings/assessment/{id} and GET /api/findings?lifecycle_status=
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch

from backend import database
from backend.assessments import reset_assessments
from backend.scheduler import reset_jobs


class FakeExecute:
    def __init__(self, data):
        self.data = data


class FakeTable:
    def __init__(self, rows=None):
        self._rows = rows if rows is not None else []
        self._op = None
        self._eq = None
        self._limit = None

    def insert(self, payload):
        self._op = ("insert", payload)
        return self

    def update(self, payload):
        self._op = ("update", payload)
        return self

    def delete(self):
        self._op = ("delete",)
        return self

    def select(self, *cols):
        self._op = ("select",)
        return self

    def eq(self, col, value):
        self._eq = (col, value)
        return self

    def order(self, col, desc=False):
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        op = self._op
        if op[0] == "insert":
            payload = op[1]
            if isinstance(payload, list):
                rows = []
                for item in payload:
                    row = dict(item)
                    row.setdefault("id", f"f-{len(self._rows) + len(rows) + 1}")
                    rows.append(row)
                self._rows.extend(rows)
                return FakeExecute(rows)
            row = dict(payload)
            row.setdefault("id", "f-id")
            self._rows.append(row)
            return FakeExecute([row])
        if op[0] == "update":
            payload = op[1]
            if self._eq and self._eq[1] == "missing":
                return FakeExecute([])
            row = dict(payload)
            row["id"] = self._eq[1] if self._eq else "f-id"
            self._rows.append(row)
            return FakeExecute([row])
        if op[0] == "delete":
            return FakeExecute([])
        if op[0] == "select":
            out = list(self._rows)
            if self._eq is not None:
                col, value = self._eq
                out = [r for r in out if r.get(col) == value]
            if self._limit is not None:
                out = out[: self._limit]
            return FakeExecute(out)
        raise AssertionError(f"unhandled op: {op}")


class FakeClient:
    def __init__(self):
        self._rows = {}

    def table(self, name):
        return FakeTable(self._rows.setdefault(name, []))


BARE_FINDING = {"tool": "nmap", "target": "10.0.0.5", "type": "port", "severity": "medium"}


@pytest.fixture(autouse=True)
def _db_isolate():
    reset_assessments()
    reset_jobs()
    with patch.object(database, "get_client", return_value=FakeClient()):
        yield


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from main import app
    with TestClient(app) as c:
        yield c


# ── DB layer ──────────────────────────────────────────────────────────

class TestDbSave:
    def test_save_finding_defaults_lifecycle(self):
        resp = database.save_finding(BARE_FINDING)
        assert resp is not None
        assert resp["lifecycle_status"] == "open"
        assert resp["assessment_id"] == ""

    def test_save_finding_carries_lifecycle_and_assessment(self):
        data = {**BARE_FINDING, "lifecycle_status": "confirmed", "assessment_id": "ass-7"}
        resp = database.save_finding(data)
        assert resp["lifecycle_status"] == "confirmed"
        assert resp["assessment_id"] == "ass-7"

    def test_save_bulk_carries_lifecycle_and_assessment(self):
        items = [{**BARE_FINDING, "lifecycle_status": "accepted", "assessment_id": "ass-1"},
                 {**BARE_FINDING, "target": "10.0.0.6"}]
        assert database.save_findings_bulk(items) == 2
        listing = database.list_findings()
        assert any(r.get("lifecycle_status") == "accepted" for r in listing)
        assert any(r.get("assessment_id") == "ass-1" for r in listing)
        assert any(r.get("lifecycle_status") == "open" for r in listing)


class TestDbUpdate:
    def test_update_lifecycle(self):
        database.save_finding(BARE_FINDING)
        upd = database.update_finding("f-1", {"lifecycle_status": "fixed"})
        assert upd is not None
        assert upd["lifecycle_status"] == "fixed"

    def test_update_ignores_unknown_fields(self):
        upd = database.update_finding("f-1", {"nonsense": 1})
        assert upd is None  # nothing valid to update

    def test_update_not_found(self):
        result = database.update_finding("missing", {"lifecycle_status": "fixed"})
        assert result is None


class TestDbList:
    def test_list_filters_lifecycle(self):
        database.save_finding({**BARE_FINDING, "lifecycle_status": "confirmed"})
        database.save_finding({**BARE_FINDING, "target": "10.0.0.7", "lifecycle_status": "open"})
        rows = database.list_findings(lifecycle_status="confirmed")
        assert len(rows) == 1
        assert rows[0]["lifecycle_status"] == "confirmed"

    def test_list_filters_assessment(self):
        database.save_finding({**BARE_FINDING, "assessment_id": "ass-2"})
        database.save_finding({**BARE_FINDING, "target": "10.0.0.8", "assessment_id": "ass-3"})
        rows = database.list_findings(assessment_id="ass-2")
        assert len(rows) == 1
        assert rows[0]["assessment_id"] == "ass-2"

    def test_list_by_assessment(self):
        database.save_finding({**BARE_FINDING, "assessment_id": "ass-9"})
        database.save_finding({**BARE_FINDING, "target": "10.0.0.9"})
        rows = database.list_findings_by_assessment("ass-9")
        assert len(rows) == 1
        assert rows[0]["target"] == "10.0.0.5"


# ── REST endpoints ─────────────────────────────────────────────────────

class TestFindingEndpoints:
    def test_patch_lifecycle_success(self, client):
        with patch("main.db.update_finding",
                   return_value={"id": "f-1", "lifecycle_status": "verified"}) as m:
            r = client.patch("/api/findings/f-1", json={"lifecycle_status": "verified"})
        assert r.status_code == 200
        assert r.json()["data"]["lifecycle_status"] == "verified"
        m.assert_called_once_with("f-1", {"lifecycle_status": "verified"})

    def test_patch_assessment_binding(self, client):
        with patch("main.db.update_finding",
                   return_value={"id": "f-1", "assessment_id": "ass-5"}) as m:
            r = client.patch("/api/findings/f-1", json={"assessment_id": "ass-5"})
        assert r.status_code == 200
        m.assert_called_once_with("f-1", {"assessment_id": "ass-5"})

    def test_patch_invalid_lifecycle_400(self, client):
        with patch("main.db.update_finding") as m:
            r = client.patch("/api/findings/f-1", json={"lifecycle_status": "bogus"})
        assert r.status_code == 400
        m.assert_not_called()

    def test_patch_unknown_field_400(self, client):
        with patch("main.db.update_finding") as m:
            r = client.patch("/api/findings/f-1", json={"bogus": 1})
        assert r.status_code == 400
        m.assert_not_called()

    def test_patch_empty_body_400(self, client):
        with patch("main.db.update_finding") as m:
            r = client.patch("/api/findings/f-1", json={})
        assert r.status_code == 400
        m.assert_not_called()

    def test_patch_not_found_404(self, client):
        with patch("main.db.update_finding", return_value=None):
            r = client.patch("/api/findings/f-1", json={"lifecycle_status": "fixed"})
        assert r.status_code == 404

    def test_get_findings_assessment(self, client):
        with patch("main.db.list_findings_by_assessment") as m:
            m.return_value = [{"id": "f-1", "assessment_id": "ass-9"}]
            r = client.get("/api/findings/assessment/ass-9")
        assert r.status_code == 200
        assert r.json()["data"][0]["assessment_id"] == "ass-9"
        m.assert_called_once_with("ass-9")

    def test_get_findings_lifecycle_filter_param(self, client):
        with patch("main.db.list_findings") as m:
            m.return_value = [{"id": "f-1", "lifecycle_status": "confirmed"}]
            r = client.get("/api/findings?lifecycle_status=confirmed")
        assert r.status_code == 200
        assert r.json()["data"][0]["lifecycle_status"] == "confirmed"
        m.assert_called_once_with(
            target=None, tool=None, severity=None,
            lifecycle_status="confirmed", assessment_id=None,
        )

    def test_get_findings_empty_fallback(self, client):
        with patch("main.db.list_findings", return_value=None):
            r = client.get("/api/findings?assessment_id=ass-x")
        assert r.status_code == 200
        assert r.json()["fallback"] is True