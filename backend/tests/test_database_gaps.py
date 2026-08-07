"""
Coverage-gap tests for backend/database.py — error paths and bootstrap.

Covers:
  - _ensure_tables(): no client, psycopg2 success / ImportError / failure,
    Management API success / failure
  - CRUD exception paths for the remaining untested functions:
    delete_finding, delete_all_findings, save_credential,
    delete_credential, delete_all_credentials, save_hak5_payload,
    save_uploaded_file, delete_uploaded_file, delete_ctf_challenge,
    solve_ctf_challenge, save_mobile_apk, get_mobile_apk,
    delete_mobile_apk, save_forensics_evidence,
    delete_forensics_evidence, save_mission_history,
    delete_mission_history, save_mission_plan, delete_mission_plan
"""

import os
import sys

from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database as db


@pytest.fixture(autouse=True)
def reset_globals():
    db._supabase = None
    db._available = False
    yield
    db._supabase = None
    db._available = False


def _erring_table():
    """Table mock whose every execute() raises."""
    tbl = MagicMock()
    tbl.insert.return_value.execute.side_effect = RuntimeError("boom")
    tbl.delete.return_value.eq.return_value.execute.side_effect = RuntimeError("boom")
    tbl.delete.return_value.neq.return_value.execute.side_effect = RuntimeError("boom")
    tbl.upsert.return_value.execute.side_effect = RuntimeError("boom")
    tbl.update.return_value.eq.return_value.execute.side_effect = RuntimeError("boom")
    tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.side_effect = RuntimeError("boom")
    tbl.select.return_value.eq.return_value.execute.side_effect = RuntimeError("boom")
    return tbl


# ════════════════════════════════════════════════════════════════
#  _ensure_tables() bootstrap strategies
# ════════════════════════════════════════════════════════════════

class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql):
        pass


class _FakeConn:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return _FakeCursor()

    def close(self):
        pass


class _FakePsycopg2:
    def __init__(self, connect=None):
        self._connect = connect

    def connect(self, **kwargs):
        if self._connect:
            raise self._connect
        return _FakeConn()


class TestEnsureTablesGaps:
    def test_no_supabase_returns(self):
        assert db._ensure_tables() is None

    def test_psycopg2_success(self):
        db._supabase = MagicMock()
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://xyz.supabase.co",
            "SUPABASE_DB_PASSWORD": "pw",
        }):
            with patch.dict(sys.modules, {"psycopg2": _FakePsycopg2()}):
                db._ensure_tables()

    def test_psycopg2_import_error(self):
        db._supabase = MagicMock()
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://xyz.supabase.co",
            "SUPABASE_DB_PASSWORD": "pw",
        }):
            with patch.dict(sys.modules, {"psycopg2": None}):
                db._ensure_tables()  # ImportError swallowed → falls through

    def test_psycopg2_exception(self):
        db._supabase = MagicMock()
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://xyz.supabase.co",
            "SUPABASE_DB_PASSWORD": "pw",
        }):
            with patch.dict(sys.modules, {"psycopg2": _FakePsycopg2(connect=RuntimeError("conn refused"))}):
                db._ensure_tables()

    def test_management_api_success(self):
        class _FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        db._supabase = MagicMock()
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://xyz.supabase.co",
            "SUPABASE_MGMT_TOKEN": "tok",
        }):
            with patch.dict(sys.modules, {"psycopg2": None}):
                with patch("urllib.request.urlopen", return_value=_FakeResp()) as m:
                    db._ensure_tables()
        assert m.called

    def test_management_api_exception(self):
        db._supabase = MagicMock()
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://xyz.supabase.co",
            "SUPABASE_MGMT_TOKEN": "tok",
        }):
            with patch.dict(sys.modules, {"psycopg2": None}):
                with patch("urllib.request.urlopen", side_effect=RuntimeError("timeout")):
                    db._ensure_tables()

    def test_table_check_exception(self):
        mock_sb = MagicMock()
        mock_sb.table.side_effect = RuntimeError("boom")
        db._supabase = mock_sb
        db._available = True
        with patch.dict(os.environ, {
            "SUPABASE_URL": "",
            "SUPABASE_DB_PASSWORD": "",
            "SUPABASE_MGMT_TOKEN": "",
        }):
            db._ensure_tables()


# ════════════════════════════════════════════════════════════════
#  CRUD exception paths
# ════════════════════════════════════════════════════════════════

class TestFindingsErrors:
    def test_delete_finding_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_finding("id") is False

    def test_delete_all_findings_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_all_findings() is False


class TestCredentialsErrors:
    def test_save_credential_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.save_credential({"type": "password", "target": "t"}) is None

    def test_delete_credential_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_credential("id") is False

    def test_delete_all_credentials_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_all_credentials() is False


class TestHak5Errors:
    def test_save_hak5_payload_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.save_hak5_payload({"device": "d", "name": "n", "content": "c"}) is None


class TestUploadedFilesErrors:
    def test_save_uploaded_file_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.save_uploaded_file({"filename": "f", "storage_path": "p"}) is None

    def test_delete_uploaded_file_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_uploaded_file("id") is False


class TestCtfErrors:
    def test_delete_ctf_challenge_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_ctf_challenge(1) is False

    def test_solve_ctf_challenge_error(self):
        db._available = True
        tbl = _erring_table()
        tbl.select.return_value.eq.return_value.execute.return_value = MagicMock(
            data=[{"id": 1, "flags": "flag", "points": 100, "solved": False}]
        )
        with patch("database._table", return_value=tbl):
            assert db.solve_ctf_challenge(1, "flag") is None


class TestMobileErrors:
    def test_save_mobile_apk_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.save_mobile_apk({"apk_id": "x", "filename": "f.apk"}) is None

    def test_get_mobile_apk_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.get_mobile_apk("x") is None

    def test_get_mobile_apk_not_available(self):
        # _available False and no env → is_available() returns False
        with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}):
            assert db.get_mobile_apk("x") is None

    def test_delete_mobile_apk_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_mobile_apk("x") is False


class TestForensicsErrors:
    def test_save_forensics_evidence_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.save_forensics_evidence({"filename": "e"}) is None

    def test_delete_forensics_evidence_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_forensics_evidence("id") is False

    def test_get_forensics_evidence_error(self):
        db._available = True
        with patch("database._table", return_value=_erring_table()):
            assert db.get_forensics_evidence("id") is None


class TestMissionErrors:
    def test_save_mission_history_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.save_mission_history({"target": "10.0.0.1"}) is None

    def test_delete_mission_history_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_mission_history("id") is False

    def test_save_mission_plan_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.save_mission_plan({"title": "Plan"}) is None

    def test_delete_mission_plan_error(self):
        with patch("database._table", return_value=_erring_table()):
            assert db.delete_mission_plan("id") is False
