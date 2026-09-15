"""
Tests for workspace_store + persistence wiring in assessments/scheduler.

Covers:
  - Opt-in gating: env flag AND database availability required
  - upsert/load happy path against a fake Supabase client
  - Disabled mode is a safe no-op (never touches the DB layer)
  - clear_cache isolation
  - assessments/scheduler persistence round-trip via mocks (load_from_store,
    _persist) + run history (record_run)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from backend import database, workspace_store
from backend.assessments import (
    create_assessment,
    delete_assessment,
    import_state as a_import,
    list_assessments,
    load_from_store as a_load,
    reset_assessments,
)
from backend.scheduler import (
    create_job,
    import_state as s_import,
    list_jobs,
    load_from_store as s_load,
    record_run,
    reset_jobs,
)

ENV_KEY = "MIRV_PERSIST_WORKSPACE"


class FakeExecute:
    def __init__(self, data):
        self.data = data


class FakeTable:
    """Chained-builder fake that toggles between write/read on execute()."""

    def __init__(self, rows):
        self._rows = rows
        self._op = None
        self._select = None
        self._eq = None
        self._limit = None

    def upsert(self, payload, on_conflict=None):
        self._op = ("upsert", payload, on_conflict)
        return self

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
        self._select = cols
        return self

    def eq(self, col, value):
        self._eq = (col, value)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def execute(self):
        op = self._op
        if op[0] == "upsert":
            payload, conflict = op[1], op[2]
            key = payload.get("key")
            if conflict and key is not None:
                self._rows[:] = [r for r in self._rows if r.get("key") != key]
            self._rows.append(payload)
            return FakeExecute([])
        if op[0] == "insert":
            self._rows.append(op[1])
            return FakeExecute([])
        if op[0] in ("update", "delete"):
            return FakeExecute([])
        if op[0] == "select":
            out = self._rows
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


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Ensure persistence stays disabled unless a test opts in explicitly."""
    monkeypatch.delenv(ENV_KEY, raising=False)
    with monkeypatch.context() as mp:
        mp.setattr(database, "is_available", lambda: False)
        mp.setattr(database, "get_client", lambda: FakeClient())
        yield
    workspace_store.clear_cache()


class EnabledWorkspace:
    """Context manager: switch on persistence + a fake Supabase client."""

    def __init__(self, monkeypatch, client=None):
        monkeypatch.setenv(ENV_KEY, "1")
        monkeypatch.setattr(database, "is_available", lambda: True)
        monkeypatch.setattr(database, "get_client", lambda: client or FakeClient())


# ── Gating ──────────────────────────────────────────────────────────────

class TestEnabled:
    def test_disabled_by_default(self):
        assert workspace_store.is_enabled() is False

    def test_flag_without_db_stays_disabled(self, monkeypatch):
        monkeypatch.setenv(ENV_KEY, "1")
        assert workspace_store.is_enabled() is False

    def test_flag_and_db_enables(self, monkeypatch):
        monkeypatch.setenv(ENV_KEY, "1")
        monkeypatch.setattr(database, "is_available", lambda: True)
        assert workspace_store.is_enabled() is True

    def test_true_variants_accepted(self, monkeypatch):
        for v in ("1", "true", "yes", "TRUE", "Yes"):
            monkeypatch.setenv(ENV_KEY, v)
            monkeypatch.setattr(database, "is_available", lambda: True)
            assert workspace_store.is_enabled() is True
        monkeypatch.setenv(ENV_KEY, "0")
        assert workspace_store.is_enabled() is False


# ── Disabled no-ops ───────────────────────────────────────────────────

class TestDisabled:
    def test_upsert_noop(self):
        assert workspace_store.upsert("k", [{"a": 1}]) is False

    def test_load_returns_none_when_disabled(self):
        assert workspace_store.load("k") is None

    def test_assessment_mutations_do_not_persist(self, monkeypatch):
        called = []

        def fake_upsert(key, data):
            called.append(key)
            return False

        monkeypatch.setattr(workspace_store, "is_enabled", lambda: False)
        monkeypatch.setattr(workspace_store, "upsert", fake_upsert)
        a = create_assessment("NoPersist")
        delete_assessment(a.id)
        assert called == []


# ── Happy path ─────────────────────────────────────────────────────────

class TestStore:
    def test_upsert_then_load(self, monkeypatch):
        client = FakeClient()
        EnabledWorkspace(monkeypatch, client)
        assert workspace_store.upsert("assessments", [{"name": "X"}]) is True
        assert workspace_store.load("assessments") == [{"name": "X"}]

    def test_load_unknown_key_returns_none(self, monkeypatch):
        client = FakeClient()
        EnabledWorkspace(monkeypatch, client)
        assert workspace_store.load("nope") is None

    def test_clear_cache(self, monkeypatch):
        client = FakeClient()
        EnabledWorkspace(monkeypatch, client)
        assert workspace_store.upsert("k", [{"a": 1}]) is True
        assert workspace_store.load("k") == [{"a": 1}]
        workspace_store.clear_cache("k")
        client._rows["workspace_state"].clear()  # simulate data loss
        assert workspace_store.load("k") is None

    def test_failed_upsert_returns_false(self, monkeypatch):
        EnabledWorkspace(monkeypatch)

        def boom(client):
            raise RuntimeError("db down")

        monkeypatch.setattr(database, "get_client", boom)
        assert workspace_store.upsert("k", []) is False
        assert workspace_store.load("k") is None


# ── Module wiring ──────────────────────────────────────────────────────

class TestRegistryWiring:
    def test_assessment_persist_and_load_roundtrip(self, monkeypatch):
        client = FakeClient()
        EnabledWorkspace(monkeypatch, client)
        reset_assessments()
        a = create_assessment("PersistMe", targets=["10.0.0.5"])
        delete_assessment("bogus")  # no-op, must not crash persist path

        # fresh registry, hydrate from the snapshot the mutations created
        reset_assessments()
        a_load()
        found = {x["id"]: x for x in list_assessments()}
        assert a.id in found
        assert found[a.id]["name"] == "PersistMe"
        assert "10.0.0.5" in found[a.id]["targets"]

    def test_scheduler_persist_and_load_roundtrip_with_history(self, monkeypatch):
        client = FakeClient()
        EnabledWorkspace(monkeypatch, client)
        reset_jobs()
        job = create_job("Scan", "nmap", 600, target="10.0.0.1")
        record_run(job.id, result="ok", findings=2, duration=3.5)

        reset_jobs()
        s_load()
        jobs = {j["id"]: j for j in list_jobs()}
        assert job.id in jobs
        assert jobs[job.id]["run_count"] == 1
        assert jobs[job.id]["last_findings"] == 2
        assert jobs[job.id]["last_duration"] == 3.5

    def test_load_from_store_disabled_is_noop(self, monkeypatch):
        reset_assessments()
        reset_jobs()
        a_load()
        s_load()  # must not raise

    def test_import_state_rejects_non_dicts(self):
        d = a_import([{"name": "A"}, "junk", 42, None], replace=True)
        assert d["imported"] == 1 and d["rejected"] == 3 and d["total"] == 1
        d = s_import([{"name": "B", "tool_id": "nmap", "interval_seconds": 60}, "junk", 42], replace=True)
        assert d["imported"] == 1 and d["rejected"] == 2 and d["total"] == 1

    def test_import_state_raises_on_non_list(self):
        with pytest.raises(ValueError):
            a_import({"rows": 1})  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            s_import("nope")  # type: ignore[arg-type]