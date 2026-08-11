"""
Coverage-gap tests for backend/database.py.

Covers _ensure_tables outer failure, get_setting exception, CTF/mobile/
forensics not-available guards, and the generic `except Exception` paths
of mission-plans, scope-events, and swarm-sessions CRUD helpers.

NOTE: imports the module as plain `database` (same name as the existing
suite) to avoid a second module instance.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.database as db


@pytest.fixture(autouse=True)
def reset_globals():
    db._supabase = None
    db._available = False
    yield
    db._supabase = None
    db._available = False


class _Boom:
    """Any chained method call returns another _Boom; execute() raises."""

    def __getattr__(self, name):
        if name == "execute":
            def boom(*args, **kwargs):
                raise Exception("boom")
            return boom
        return _Boom()

    def __call__(self, *args, **kwargs):
        return self


@pytest.fixture
def boom_tables():
    with patch.object(db, "_table", return_value=_Boom()), \
         patch.object(db, "is_available", return_value=True):
        yield


@pytest.fixture
def unavailable():
    with patch.object(db, "is_available", return_value=False):
        yield


class TestEnsureTables:
    def test_outer_exception(self):
        # A truthy _supabase passes the guard; the "all tables verified"
        # log raises -> outer try/except is hit and swallowed.
        db._supabase = MagicMock()
        with patch.object(db.logger, "info", side_effect=Exception("boom")):
            db._ensure_tables()

    def test_missing_tables_logs(self):
        db._supabase = MagicMock()
        db._supabase.table.side_effect = Exception("no such table")
        with patch.object(db.logger, "info") as mock_info:
            db._ensure_tables()
        assert mock_info.call_count == 1
        assert "Tables missing" in mock_info.call_args[0][0]


class TestGetSetting:
    def test_exception(self, boom_tables):
        assert db.get_setting("key") is None

    def test_returns_value(self):
        tbl = MagicMock()
        resp = MagicMock()
        resp.data = {"value": "v"}
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = resp
        with patch.object(db, "_table", return_value=tbl):
            assert db.get_setting("key") == "v"

    def test_no_table(self):
        with patch.object(db, "_table", return_value=None):
            assert db.get_setting("key") is None


class TestNotAvailableGuards:
    def test_solve_ctf_challenge_unavailable(self, unavailable):
        assert db.solve_ctf_challenge(1, "flag") is None

    def test_get_forensics_evidence_unavailable(self, unavailable):
        assert db.get_forensics_evidence("ev1") is None


class TestExceptionPaths:
    def test_list_mobile_apks(self, boom_tables):
        assert db.list_mobile_apks() == []

    def test_list_forensics_evidence(self, boom_tables):
        assert db.list_forensics_evidence() == []

    def test_list_mission_plans(self, boom_tables):
        assert db.list_mission_plans() == []

    def test_save_scope_event(self, boom_tables):
        assert db.save_scope_event({"target": "x", "action": "block"}) is None

    def test_clear_scope_events(self, boom_tables):
        assert db.clear_scope_events() is False

    def test_save_swarm_session(self, boom_tables):
        assert db.save_swarm_session({"id": "s1", "phases": []}) is None

    def test_list_swarm_sessions(self, boom_tables):
        assert db.list_swarm_sessions() == []

    def test_get_swarm_session(self, boom_tables):
        assert db.get_swarm_session("s1") is None

    def test_delete_swarm_session(self, boom_tables):
        assert db.delete_swarm_session("s1") is False
