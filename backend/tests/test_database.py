"""
Tests for backend/database.py — Supabase CRUD Layer.

Covers all 17+ tables and ~60 functions:
  - Client initialization: get_client(), is_available()
  - SSH Connections: list_connections, save_connection, delete_connection
  - Scripts: list_scripts, save_script, delete_script
  - Reports: list_reports, save_report, delete_report
  - Findings: list_findings, save_finding, save_findings_bulk, delete_finding,
              delete_all_findings, count_findings
  - Credentials: save_credential, list_credentials, delete_credential,
                 delete_all_credentials
  - Hak5 Payloads: list_hak5_payloads, save_hak5_payload, delete_hak5_payload
  - Settings: get_setting, set_setting
  - Uploaded Files: save_uploaded_file, list_uploaded_files, delete_uploaded_file
  - CTF: save_ctf_challenge, list_ctf_challenges, delete_ctf_challenge,
         solve_ctf_challenge, get_ctf_score
  - Mobile: save_mobile_apk, list_mobile_apks, get_mobile_apk, delete_mobile_apk
  - Forensics: save_forensics_evidence, list_forensics_evidence,
               get_forensics_evidence, delete_forensics_evidence
  - Mission History: save_mission_history, list_mission_history,
                     delete_mission_history
  - Mission Plans: save_mission_plan, list_mission_plans, delete_mission_plan
  - Scope Events: save_scope_event, list_scope_events, clear_scope_events
  - Swarm Sessions: save_swarm_session, list_swarm_sessions, get_swarm_session,
                    delete_swarm_session
  - App Credentials (Secrets): save_app_credential, get_app_credential,
                               delete_app_credential

All Supabase calls are mocked via unittest.mock — no network needed.
"""

import json
import pytest
import sys
import os
from unittest.mock import patch, MagicMock, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database as db


# ════════════════════════════════════════════════════════════════
#  FIXTURES
# ════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset module-level globals before each test."""
    db._supabase = None
    db._available = False
    yield
    db._supabase = None
    db._available = False


@pytest.fixture
def mock_client():
    """Return a fully-chained mock Supabase client.

    Usage in tests:
        mock_client.table("ssh_connections").select("*").execute.return_value.data = [...]
    """
    client = MagicMock()
    return client


@pytest.fixture
def mock_table():
    """Return a mock table with chained insert/select/delete/upsert."""
    tbl = MagicMock()
    resp = MagicMock()
    resp.data = [{"id": "uuid-1", "name": "test"}]
    tbl.insert.return_value.execute.return_value = resp
    tbl.select.return_value.order.return_value.execute.return_value = resp
    tbl.select.return_value.eq.return_value.order.return_value.execute.return_value = resp
    tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value = resp
    tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value = resp
    tbl.select.return_value.order.return_value.limit.return_value.execute.return_value = resp
    tbl.select.return_value.limit.return_value.execute.return_value = resp
    tbl.delete.return_value.eq.return_value.execute.return_value = MagicMock(data=[])
    tbl.delete.return_value.neq.return_value.execute.return_value = MagicMock(data=[])
    tbl.update.return_value.eq.return_value.execute.return_value = resp
    tbl.upsert.return_value.execute.return_value = resp
    return tbl


@pytest.fixture
def patch_get_client(mock_client):
    """Patch get_client to return a mock client for the duration of the test."""
    with patch("database.get_client", return_value=mock_client) as patched:
        yield mock_client


@pytest.fixture
def patch_is_available():
    """Patch is_available to return True."""
    with patch("database.is_available", return_value=True):
        yield


# ════════════════════════════════════════════════════════════════
#  1. CLIENT INITIALIZATION
# ════════════════════════════════════════════════════════════════


class TestGetClient:
    """Tests for get_client() — lazy Supabase initialization.

    Note: create_client is imported locally inside get_client() via
    ``from supabase import create_client``, so we must patch the
    supabase module directly (``supabase.create_client``).
    """

    @patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""})
    def test_returns_none_when_env_missing(self):
        """Returns None when SUPABASE_URL and SUPABASE_KEY are empty."""
        result = db.get_client()
        assert result is None

    @patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""})
    def test_returns_none_when_url_empty(self):
        """Returns None when SUPABASE_URL is empty even if key set."""
        result = db.get_client()
        assert result is None

    @patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": "key-only"})
    def test_returns_none_when_url_missing(self):
        """Returns None when SUPABASE_URL is empty (key-only not enough)."""
        result = db.get_client()
        assert result is None

    @patch.dict(os.environ, {"SUPABASE_URL": "https://test.supabase.co", "SUPABASE_KEY": "test-key"})
    @patch("supabase.create_client")
    def test_returns_client_when_env_set(self, mock_create):
        """Returns the Supabase client when env vars are set."""
        mock_create.return_value = MagicMock()
        result = db.get_client()
        assert result is not None
        mock_create.assert_called_once_with("https://test.supabase.co", "test-key")

    @patch.dict(os.environ, {"SUPABASE_URL": "https://test.supabase.co", "SUPABASE_KEY": "test-key"})
    @patch("supabase.create_client")
    def test_caches_client_on_subsequent_calls(self, mock_create):
        """Subsequent calls return the cached client without calling create_client again."""
        mock_create.return_value = MagicMock()
        db.get_client()
        db.get_client()
        db.get_client()
        assert mock_create.call_count == 1

    @patch.dict(os.environ, {"SUPABASE_URL": "https://test.supabase.co", "SUPABASE_KEY": "test-key"})
    @patch("supabase.create_client", side_effect=Exception("connection refused"))
    def test_returns_none_on_create_client_failure(self, mock_create):
        """Returns None when create_client raises an exception."""
        result = db.get_client()
        assert result is None

    @patch.dict(os.environ, {"SUPABASE_URL": "https://test.supabase.co", "SUPABASE_KEY": "test-key"})
    @patch("supabase.create_client")
    def test_sets_available_flag_on_success(self, mock_create):
        """Sets _available=True on successful connection."""
        mock_create.return_value = MagicMock()
        db.get_client()
        assert db._available is True

    @patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""})
    def test_sets_available_false_when_no_env(self):
        """Sets _available=False when env vars are missing."""
        db.get_client()
        assert db._available is False


class TestIsAvailable:
    """Tests for is_available()."""

    @patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""})
    def test_returns_false_when_not_connected(self):
        """Returns False when client has never been initialized."""
        assert db.is_available() is False

    @patch.dict(os.environ, {"SUPABASE_URL": "https://test.supabase.co", "SUPABASE_KEY": "test-key"})
    @patch("supabase.create_client")
    def test_returns_true_after_successful_connect(self, mock_create):
        """Returns True after a successful get_client() call."""
        mock_create.return_value = MagicMock()
        db.get_client()
        assert db.is_available() is True


# ════════════════════════════════════════════════════════════════
#  2. SSH CONNECTIONS
# ════════════════════════════════════════════════════════════════


class TestSSHConnections:
    """Tests for SSH connection CRUD operations."""

    def test_list_connections_returns_data(self, patch_get_client):
        """list_connections returns data from Supabase."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "1", "name": "kali", "ip": "10.0.0.1"}
        ]
        result = db.list_connections()
        assert result is not None
        assert len(result) == 1
        patch_get_client.table.assert_called_with("ssh_connections")

    def test_list_connections_returns_none_when_no_client(self):
        """Returns None when Supabase is not configured."""
        with patch("database.get_client", return_value=None):
            result = db.list_connections()
            assert result is None

    def test_list_connections_returns_empty_on_error(self, patch_get_client):
        """Returns [] when Supabase throws an exception."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("DB error")
        result = db.list_connections()
        assert result == []

    def test_save_connection_returns_row(self, patch_get_client):
        """save_connection inserts and returns the created row."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "uuid-1", "name": "kali", "ip": "10.0.0.1", "username": "root"}
        ]
        result = db.save_connection({
            "name": "kali", "ip": "10.0.0.1",
            "username": "root", "password": "pass123"
        })
        assert result is not None
        assert result["name"] == "kali"
        patch_get_client.table.assert_called_with("ssh_connections")

    def test_save_connection_returns_none_when_no_client(self):
        """Returns None when Supabase is not configured."""
        with patch("database.get_client", return_value=None):
            result = db.save_connection({
                "name": "x", "ip": "1.1.1.1", "username": "u", "password": "p"
            })
            assert result is None

    def test_save_connection_returns_none_on_error(self, patch_get_client):
        """Returns None when insert raises an exception."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.side_effect = Exception("insert failed")
        result = db.save_connection({
            "name": "x", "ip": "1.1.1.1", "username": "u", "password": "p"
        })
        assert result is None

    def test_delete_connection_returns_true(self, patch_get_client):
        """delete_connection returns True on success."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        result = db.delete_connection("uuid-1")
        assert result is True
        tbl.delete.return_value.eq.assert_called_with("id", "uuid-1")

    def test_delete_connection_returns_false_when_no_client(self):
        """Returns False when Supabase is not configured."""
        with patch("database.get_client", return_value=None):
            result = db.delete_connection("uuid-1")
            assert result is False

    def test_delete_connection_returns_false_on_error(self, patch_get_client):
        """Returns False when delete raises an exception."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.delete.return_value.eq.return_value.execute.side_effect = Exception("fail")
        result = db.delete_connection("uuid-1")
        assert result is False


# ════════════════════════════════════════════════════════════════
#  3. SCRIPTS
# ════════════════════════════════════════════════════════════════


class TestScripts:
    """Tests for Scripts CRUD."""

    def test_list_scripts_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "s1", "name": "recon.sh"}
        ]
        result = db.list_scripts()
        assert result is not None
        assert len(result) == 1
        patch_get_client.table.assert_called_with("scripts")

    def test_list_scripts_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_scripts() is None

    def test_list_scripts_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("err")
        assert db.list_scripts() == []

    def test_save_script_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "s1", "name": "nmap.sh", "content": "#!/bin/bash"}
        ]
        result = db.save_script({"name": "nmap.sh", "content": "#!/bin/bash"})
        assert result is not None
        assert result["name"] == "nmap.sh"

    def test_save_script_defaults_language_to_bash(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "s1"}]
        db.save_script({"name": "x", "content": "echo hi"})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args.get("language") == "bash"

    def test_save_script_accepts_custom_language(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "s1"}]
        db.save_script({"name": "x", "content": "print('hi')", "language": "python"})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args.get("language") == "python"

    def test_save_script_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_script({"name": "x", "content": "y"}) is None

    def test_save_script_returns_none_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.side_effect = Exception("fail")
        assert db.save_script({"name": "x", "content": "y"}) is None

    def test_delete_script_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_script("s1") is True
        tbl.delete.return_value.eq.assert_called_with("id", "s1")

    def test_delete_script_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_script("s1") is False

    def test_delete_script_returns_false_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.delete.return_value.eq.return_value.execute.side_effect = Exception("fail")
        assert db.delete_script("s1") is False


# ════════════════════════════════════════════════════════════════
#  4. REPORTS
# ════════════════════════════════════════════════════════════════


class TestReports:
    """Tests for Reports CRUD."""

    def test_list_reports_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "r1", "type": "scan", "title": "Nmap Report"}
        ]
        result = db.list_reports()
        assert result is not None
        assert len(result) == 1
        patch_get_client.table.assert_called_with("reports")

    def test_list_reports_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_reports() is None

    def test_list_reports_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("err")
        assert db.list_reports() == []

    def test_save_report_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "r1", "type": "scan", "title": "Nmap"}
        ]
        result = db.save_report({"type": "scan", "title": "Nmap", "target": "10.0.0.1"})
        assert result is not None
        assert result["type"] == "scan"

    def test_save_report_defaults(self, patch_get_client):
        """save_report uses defaults for optional fields."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "r1"}]
        db.save_report({"type": "scan"})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["title"] == ""
        assert insert_args["target"] == ""
        assert insert_args["format"] == "md"

    def test_save_report_serializes_parsed_data_as_json(self, patch_get_client):
        """save_report serializes parsed_data dict to JSON string."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "r1"}]
        db.save_report({"type": "scan", "parsed_data": {"ports": [80, 443]}})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["parsed_data"] == json.dumps({"ports": [80, 443]})

    def test_save_report_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_report({"type": "scan"}) is None

    def test_save_report_returns_none_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.side_effect = Exception("fail")
        assert db.save_report({"type": "scan"}) is None

    def test_delete_report_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_report("r1") is True

    def test_delete_report_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_report("r1") is False

    def test_delete_report_returns_false_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.delete.return_value.eq.return_value.execute.side_effect = Exception("fail")
        assert db.delete_report("r1") is False


# ════════════════════════════════════════════════════════════════
#  5. FINDINGS
# ════════════════════════════════════════════════════════════════


class TestFindings:
    """Tests for Findings CRUD + bulk + count."""

    def test_list_findings_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"id": "f1", "tool": "nmap", "severity": "high"}
        ]
        result = db.list_findings()
        assert result is not None
        assert len(result) == 1
        patch_get_client.table.assert_called_with("findings")

    def test_list_findings_filters_by_target(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.execute.return_value.data = []
        db.list_findings(target="10.0.0.1")
        chain.eq.assert_called_with("target", "10.0.0.1")

    def test_list_findings_filters_by_tool(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.execute.return_value.data = []
        db.list_findings(tool="nmap")
        chain.eq.assert_called_with("tool", "nmap")

    def test_list_findings_filters_by_severity(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.execute.return_value.data = []
        db.list_findings(severity="critical")
        chain.eq.assert_called_with("severity", "critical")

    def test_list_findings_applies_limit(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.limit.return_value.execute.return_value.data = []
        db.list_findings(limit=50)
        chain.limit.assert_called_with(50)

    def test_list_findings_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_findings() is None

    def test_list_findings_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.side_effect = Exception("err")
        assert db.list_findings() == []

    def test_save_finding_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "f1", "tool": "nmap", "type": "port"}
        ]
        result = db.save_finding({"tool": "nmap", "type": "port", "target": "10.0.0.1"})
        assert result is not None
        assert result["tool"] == "nmap"

    def test_save_finding_defaults(self, patch_get_client):
        """save_finding uses defaults for optional fields."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "f1"}]
        db.save_finding({"tool": "nmap"})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["severity"] == "info"
        assert insert_args["target"] == ""
        assert insert_args["status"] == 0

    def test_save_finding_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_finding({"tool": "nmap"}) is None

    def test_save_finding_returns_none_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.side_effect = Exception("fail")
        assert db.save_finding({"tool": "nmap"}) is None

    def test_save_findings_bulk_returns_count(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "f1"}, {"id": "f2"}, {"id": "f3"}
        ]
        items = [
            {"tool": "nmap", "type": "port"},
            {"tool": "gobuster", "type": "dir"},
            {"tool": "nikto", "type": "vuln"},
        ]
        result = db.save_findings_bulk(items)
        assert result == 3
        patch_get_client.table.assert_called_with("findings")

    def test_save_findings_bulk_returns_none_when_no_client(self):
        """save_findings_bulk returns None when Supabase is not configured (_table returns None)."""
        with patch("database.get_client", return_value=None):
            assert db.save_findings_bulk([{"tool": "nmap"}]) is None

    def test_save_findings_bulk_returns_zero_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.side_effect = Exception("fail")
        assert db.save_findings_bulk([{"tool": "nmap"}]) == 0

    def test_delete_finding_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_finding("f1") is True

    def test_delete_finding_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_finding("f1") is False

    def test_delete_all_findings_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_all_findings() is True
        tbl.delete.return_value.neq.assert_called()

    def test_delete_all_findings_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_all_findings() is False

    def test_count_findings_returns_count(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.execute.return_value = MagicMock(count=42)
        result = db.count_findings()
        assert result == 42

    def test_count_findings_returns_zero_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.count_findings() == 0

    def test_count_findings_returns_zero_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.execute.side_effect = Exception("err")
        assert db.count_findings() == 0


# ════════════════════════════════════════════════════════════════
#  6. CREDENTIALS
# ════════════════════════════════════════════════════════════════


class TestCredentials:
    """Tests for Credentials CRUD."""

    def test_save_credential_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"uuid": "c1", "type": "password", "target": "10.0.0.1"}
        ]
        result = db.save_credential({
            "type": "password", "target": "10.0.0.1",
            "username": "admin", "password": "secret"
        })
        assert result is not None
        patch_get_client.table.assert_called_with("credentials")

    def test_save_credential_defaults(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"uuid": "c1"}]
        db.save_credential({})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["type"] == "password"
        assert insert_args["username"] == ""

    def test_save_credential_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_credential({}) is None

    def test_list_credentials_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"uuid": "c1", "target": "10.0.0.1"}
        ]
        result = db.list_credentials()
        assert result is not None
        assert len(result) == 1

    def test_list_credentials_filters_by_target(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.execute.return_value.data = []
        db.list_credentials(target="10.0.0.1")
        chain.eq.assert_called_with("target", "10.0.0.1")

    def test_list_credentials_filters_by_service(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.execute.return_value.data = []
        db.list_credentials(service="ssh")
        chain.eq.assert_called_with("service", "ssh")

    def test_list_credentials_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_credentials() is None

    def test_list_credentials_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("err")
        assert db.list_credentials() == []

    def test_delete_credential_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_credential("c1") is True
        tbl.delete.return_value.eq.assert_called_with("uuid", "c1")

    def test_delete_credential_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_credential("c1") is False

    def test_delete_all_credentials_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_all_credentials() is True

    def test_delete_all_credentials_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_all_credentials() is False


# ════════════════════════════════════════════════════════════════
#  7. HAK5 PAYLOADS
# ════════════════════════════════════════════════════════════════


class TestHak5Payloads:
    """Tests for Hak5 Payloads CRUD."""

    def test_list_hak5_payloads_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "p1", "device": "bunny", "name": "wifi-steal"}
        ]
        result = db.list_hak5_payloads()
        assert result is not None
        assert len(result) == 1

    def test_list_hak5_payloads_filters_by_device(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.execute.return_value.data = []
        db.list_hak5_payloads(device="bunny")
        chain.eq.assert_called_with("device", "bunny")

    def test_list_hak5_payloads_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_hak5_payloads() is None

    def test_list_hak5_payloads_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("err")
        assert db.list_hak5_payloads() == []

    def test_save_hak5_payload_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "p1", "device": "bunny", "name": "test"}
        ]
        result = db.save_hak5_payload({
            "device": "bunny", "name": "test", "content": "LED R"
        })
        assert result is not None
        patch_get_client.table.assert_called_with("hak5_payloads")

    def test_save_hak5_payload_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_hak5_payload({"device": "x", "name": "y", "content": "z"}) is None

    def test_delete_hak5_payload_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_hak5_payload("p1") is True

    def test_delete_hak5_payload_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_hak5_payload("p1") is False

    def test_delete_hak5_payload_returns_false_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.delete.return_value.eq.return_value.execute.side_effect = Exception("fail")
        assert db.delete_hak5_payload("p1") is False


# ════════════════════════════════════════════════════════════════
#  8. SETTINGS
# ════════════════════════════════════════════════════════════════


class TestSettings:
    """Tests for Settings (get/set)."""

    def test_get_setting_returns_value(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = {
            "key": "theme",
            "value": "dark"
        }
        result = db.get_setting("theme")
        assert result == "dark"

    def test_get_setting_returns_none_when_missing(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
        result = db.get_setting("nonexistent")
        assert result is None

    def test_get_setting_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.get_setting("theme") is None

    def test_set_setting_upserts(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.upsert.return_value.execute.return_value.data = [{"key": "theme"}]
        result = db.set_setting("theme", "dark")
        assert result is not None
        tbl.upsert.assert_called_once()
        patch_get_client.table.assert_called_with("app_settings")

    def test_set_setting_serializes_dict_value(self, patch_get_client):
        """set_setting serializes dict values to JSON strings."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.upsert.return_value.execute.return_value.data = [{"key": "x"}]
        db.set_setting("config", {"a": 1, "b": 2})
        upsert_args = tbl.upsert.call_args[0][0]
        assert upsert_args["value"] == json.dumps({"a": 1, "b": 2})

    def test_set_setting_keeps_string_value_as_is(self, patch_get_client):
        """set_setting does not double-serialize a string value."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.upsert.return_value.execute.return_value.data = [{"key": "x"}]
        db.set_setting("theme", "dark")
        upsert_args = tbl.upsert.call_args[0][0]
        assert upsert_args["value"] == "dark"

    def test_set_setting_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.set_setting("theme", "dark") is None

    def test_set_setting_returns_none_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.upsert.return_value.execute.side_effect = Exception("fail")
        assert db.set_setting("theme", "dark") is None


# ════════════════════════════════════════════════════════════════
#  9. UPLOADED FILES
# ════════════════════════════════════════════════════════════════


class TestUploadedFiles:
    """Tests for Uploaded Files CRUD."""

    def test_save_uploaded_file_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "f1", "filename": "scan.nmap"}
        ]
        result = db.save_uploaded_file({
            "filename": "scan.nmap",
            "storage_path": "/tmp/scan.nmap",
            "size_bytes": 1024,
        })
        assert result is not None
        patch_get_client.table.assert_called_with("uploaded_files")

    def test_save_uploaded_file_defaults(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "f1"}]
        db.save_uploaded_file({"filename": "test.txt", "storage_path": "/tmp/test.txt"})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["original_name"] == "test.txt"
        assert insert_args["size_bytes"] == 0
        assert insert_args["mime_type"] == "application/octet-stream"

    def test_save_uploaded_file_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_uploaded_file({"filename": "x", "storage_path": "/tmp/x"}) is None

    def test_list_uploaded_files_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "f1", "filename": "report.pdf"}
        ]
        result = db.list_uploaded_files()
        assert result is not None
        assert len(result) == 1

    def test_list_uploaded_files_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_uploaded_files() is None

    def test_list_uploaded_files_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("err")
        assert db.list_uploaded_files() == []

    def test_delete_uploaded_file_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_uploaded_file("f1") is True

    def test_delete_uploaded_file_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_uploaded_file("f1") is False


# ════════════════════════════════════════════════════════════════
#  10. CTF CHALLENGES
# ════════════════════════════════════════════════════════════════


class TestCTF:
    """Tests for CTF Challenges and Scoring."""

    def test_save_ctf_challenge_returns_row(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": 1, "title": "SQLi 101", "category": "web"}
        ]
        result = db.save_ctf_challenge({
            "title": "SQLi 101", "category": "web",
            "flags": "flag{sql_injection}\nflag{alt_flag}",
            "points": 200
        })
        assert result is not None
        assert result["title"] == "SQLi 101"
        patch_get_client.table.assert_called_with("ctf_challenges")

    def test_save_ctf_challenge_returns_none_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.save_ctf_challenge({"title": "x"}) is None

    def test_save_ctf_challenge_returns_none_on_error(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.side_effect = Exception("fail")
        assert db.save_ctf_challenge({"title": "x"}) is None

    def test_list_ctf_challenges_returns_data(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": 1, "title": "SQLi 101", "solved": False}
        ]
        result = db.list_ctf_challenges()
        assert result is not None
        assert len(result) == 1

    def test_list_ctf_challenges_returns_none_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.list_ctf_challenges() is None

    def test_list_ctf_challenges_returns_none_on_error(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.side_effect = Exception("err")
        assert db.list_ctf_challenges() is None

    def test_delete_ctf_challenge_returns_true(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_ctf_challenge(1) is True

    def test_delete_ctf_challenge_returns_false_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.delete_ctf_challenge(1) is False

    def test_solve_correct_flag(self, patch_get_client, patch_is_available):
        """solve_ctf_challenge with a correct flag returns ok=True."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        # Mock challenge lookup
        tbl.select.return_value.eq.return_value.execute.return_value.data = [{
            "id": 1, "flags": "flag{correct}\nflag{alt}",
            "points": 200, "solved": False
        }]
        result = db.solve_ctf_challenge(1, "flag{correct}")
        assert result is not None
        assert result["ok"] is True
        assert "200" in result["message"]

    def test_solve_incorrect_flag(self, patch_get_client, patch_is_available):
        """solve_ctf_challenge with wrong flag returns ok=False."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.execute.return_value.data = [{
            "id": 1, "flags": "flag{correct}",
            "points": 100, "solved": False
        }]
        result = db.solve_ctf_challenge(1, "flag{wrong}")
        assert result is not None
        assert result["ok"] is False
        assert "Incorrect" in result["error"]

    def test_solve_already_solved(self, patch_get_client, patch_is_available):
        """solve_ctf_challenge for an already-solved challenge returns ok=True with message."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.execute.return_value.data = [{
            "id": 1, "flags": "flag{ok}",
            "points": 100, "solved": True
        }]
        result = db.solve_ctf_challenge(1, "flag{ok}")
        assert result is not None
        assert result["ok"] is True
        assert "already solved" in result["message"].lower()

    def test_solve_challenge_not_found(self, patch_get_client, patch_is_available):
        """solve_ctf_challenge returns error when challenge doesn't exist."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.execute.return_value.data = []
        result = db.solve_ctf_challenge(999, "flag{x}")
        assert result is not None
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_get_ctf_score_with_challenges(self, patch_get_client, patch_is_available):
        """get_ctf_score computes solved count and points correctly."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.execute.return_value.data = [
            {"solved": True, "points": 100},
            {"solved": False, "points": 200},
            {"solved": True, "points": 150},
        ]
        result = db.get_ctf_score()
        assert result["total"] == 3
        assert result["solved"] == 2
        assert result["points"] == 250
        assert result["total_points"] == 450

    def test_get_ctf_score_empty(self, patch_get_client, patch_is_available):
        """get_ctf_score returns zeros when no challenges exist."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.execute.return_value.data = []
        result = db.get_ctf_score()
        assert result["solved"] == 0
        assert result["total"] == 0

    def test_get_ctf_score_returns_none_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.get_ctf_score() is None

    def test_get_ctf_score_returns_none_on_error(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.execute.side_effect = Exception("err")
        assert db.get_ctf_score() is None


# ════════════════════════════════════════════════════════════════
#  11. MOBILE LAB
# ════════════════════════════════════════════════════════════════


class TestMobile:
    """Tests for Mobile APK CRUD."""

    def test_save_mobile_apk_upserts(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.upsert.return_value.execute.return_value.data = [
            {"apk_id": "abc123", "filename": "app.apk"}
        ]
        result = db.save_mobile_apk({
            "apk_id": "abc123", "filename": "app.apk",
            "package": "com.test.app",
            "findings": [{"severity": "high"}],
            "permissions": ["android.permission.INTERNET"],
        })
        assert result is not None
        patch_get_client.table.assert_called_with("mobile_apks")

    def test_save_mobile_apk_serializes_json_fields(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.upsert.return_value.execute.return_value.data = [{"apk_id": "abc"}]
        db.save_mobile_apk({
            "apk_id": "abc", "findings": [1, 2], "permissions": ["perm1"],
            "components": {"activity": []}
        })
        upsert_args = tbl.upsert.call_args[0][0]
        assert isinstance(upsert_args["findings"], str)
        assert isinstance(upsert_args["permissions"], str)
        assert isinstance(upsert_args["components"], str)

    def test_save_mobile_apk_returns_none_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.save_mobile_apk({"apk_id": "x"}) is None

    def test_list_mobile_apks_returns_data(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"apk_id": "abc", "filename": "app.apk"}
        ]
        result = db.list_mobile_apks()
        assert result is not None
        assert len(result) == 1

    def test_list_mobile_apks_returns_empty_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.list_mobile_apks() is None

    def test_get_mobile_apk_returns_single(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = {
            "apk_id": "abc", "filename": "app.apk"
        }
        result = db.get_mobile_apk("abc")
        assert result is not None
        assert result["apk_id"] == "abc"

    def test_get_mobile_apk_returns_none_when_not_found(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
        assert db.get_mobile_apk("nonexistent") is None

    def test_delete_mobile_apk_returns_true(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_mobile_apk("abc") is True

    def test_delete_mobile_apk_returns_false_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.delete_mobile_apk("abc") is False


# ════════════════════════════════════════════════════════════════
#  12. FORENSICS LAB
# ════════════════════════════════════════════════════════════════


class TestForensics:
    """Tests for Forensics Evidence CRUD."""

    def test_save_forensics_evidence_returns_row(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "ev1", "filename": "memory.dmp"}
        ]
        result = db.save_forensics_evidence({
            "filename": "memory.dmp", "file_type": "memory",
            "analysis": {"strings": ["password"]},
            "findings": [{"severity": "high"}],
        })
        assert result is not None
        patch_get_client.table.assert_called_with("forensics_evidence")

    def test_save_forensics_serializes_json_fields(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "ev1"}]
        db.save_forensics_evidence({
            "analysis": {"key": "val"},
            "findings": ["a"],
            "summary": {"critical": 1}
        })
        insert_args = tbl.insert.call_args[0][0]
        assert isinstance(insert_args["analysis"], str)
        assert isinstance(insert_args["findings"], str)
        assert isinstance(insert_args["summary"], str)

    def test_save_forensics_returns_none_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.save_forensics_evidence({"filename": "x"}) is None

    def test_list_forensics_evidence_returns_data(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = [
            {"id": "ev1", "filename": "disk.img"}
        ]
        result = db.list_forensics_evidence()
        assert result is not None
        assert len(result) == 1

    def test_list_forensics_returns_empty_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.list_forensics_evidence() is None

    def test_get_forensics_evidence_returns_single(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = {
            "id": "ev1"
        }
        result = db.get_forensics_evidence("ev1")
        assert result is not None

    def test_get_forensics_evidence_returns_none_when_not_found(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = None
        assert db.get_forensics_evidence("nonexistent") is None

    def test_delete_forensics_evidence_returns_true(self, patch_get_client, patch_is_available):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_forensics_evidence("ev1") is True

    def test_delete_forensics_returns_false_when_unavailable(self):
        with patch("database.is_available", return_value=False):
            assert db.delete_forensics_evidence("ev1") is False


# ════════════════════════════════════════════════════════════════
#  13. MISSION HISTORY
# ════════════════════════════════════════════════════════════════


class TestMissionHistory:
    """Tests for Mission History CRUD."""

    def test_save_mission_history_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "m1", "target": "10.0.0.1", "success_score": 85}
        ]
        result = db.save_mission_history({
            "target": "10.0.0.1", "os_detected": "Linux",
            "tools_used": ["nmap", "gobuster"], "success_score": 85
        })
        assert result is not None
        assert result["target"] == "10.0.0.1"
        patch_get_client.table.assert_called_with("mission_history")

    def test_save_mission_history_refuses_empty_target(self, patch_get_client):
        """save_mission_history returns None for empty/whitespace target."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        result = db.save_mission_history({"target": ""})
        assert result is None
        result = db.save_mission_history({"target": "   "})
        assert result is None

    def test_save_mission_history_serializes_lists(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "m1"}]
        db.save_mission_history({
            "target": "10.0.0.1",
            "tools_used": ["nmap"],
            "findings_summary": [{"title": "x"}]
        })
        insert_args = tbl.insert.call_args[0][0]
        assert isinstance(insert_args["tools_used"], str)
        assert isinstance(insert_args["findings_summary"], str)

    def test_save_mission_history_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_mission_history({"target": "10.0.0.1"}) is None

    def test_list_mission_history_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"id": "m1", "target": "10.0.0.1"}
        ]
        result = db.list_mission_history()
        assert result is not None
        assert len(result) == 1

    def test_list_mission_history_filters_by_target(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.limit.return_value.execute.return_value.data = []
        db.list_mission_history(target="10.0.0.1")
        chain.eq.assert_called_with("target", "10.0.0.1")

    def test_list_mission_history_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_mission_history() is None

    def test_list_mission_history_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.side_effect = Exception("err")
        assert db.list_mission_history() == []

    def test_delete_mission_history_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_mission_history("m1") is True

    def test_delete_mission_history_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_mission_history("m1") is False


# ════════════════════════════════════════════════════════════════
#  14. MISSION PLANS (Op Admiral)
# ════════════════════════════════════════════════════════════════


class TestMissionPlans:
    """Tests for Mission Plans CRUD."""

    def test_save_mission_plan_inserts_new(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "p1", "target": "10.0.0.1", "name": "Recon Plan"}
        ]
        result = db.save_mission_plan({
            "target": "10.0.0.1", "name": "Recon Plan",
            "steps": [{"tool": "nmap"}]
        })
        assert result is not None
        assert result["name"] == "Recon Plan"

    def test_save_mission_plan_updates_existing(self, patch_get_client):
        """When data has an 'id', save_mission_plan calls update."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.update.return_value.eq.return_value.execute.return_value.data = [
            {"id": "p1", "name": "Updated Plan"}
        ]
        result = db.save_mission_plan({
            "id": "p1", "name": "Updated Plan"
        })
        assert result is not None
        tbl.update.assert_called_once()

    def test_save_mission_plan_serializes_steps(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "p1"}]
        db.save_mission_plan({
            "target": "10.0.0.1", "steps": [{"tool": "nmap"}]
        })
        insert_args = tbl.insert.call_args[0][0]
        assert isinstance(insert_args["steps"], str)

    def test_save_mission_plan_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_mission_plan({"target": "x"}) is None

    def test_list_mission_plans_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"id": "p1", "target": "10.0.0.1"}
        ]
        result = db.list_mission_plans()
        assert result is not None
        assert len(result) == 1

    def test_list_mission_plans_filters_by_target(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        chain = tbl.select.return_value.order.return_value
        chain.eq.return_value = MagicMock()
        chain.eq.return_value.limit.return_value.execute.return_value.data = []
        db.list_mission_plans(target="10.0.0.1")
        chain.eq.assert_called_with("target", "10.0.0.1")

    def test_list_mission_plans_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_mission_plans() is None

    def test_delete_mission_plan_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_mission_plan("p1") is True

    def test_delete_mission_plan_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_mission_plan("p1") is False


# ════════════════════════════════════════════════════════════════
#  15. SCOPE EVENTS
# ════════════════════════════════════════════════════════════════


class TestScopeEvents:
    """Tests for Scope Events CRUD."""

    def test_save_scope_event_returns_row(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "se1", "target": "evil.com", "action": "block"}
        ]
        result = db.save_scope_event({
            "target": "evil.com", "action": "block",
            "tool": "nmap", "reason": "out of scope"
        })
        assert result is not None
        assert result["action"] == "block"
        patch_get_client.table.assert_called_with("scope_events")

    def test_save_scope_event_defaults(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "se1"}]
        db.save_scope_event({})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["action"] == "block"
        assert insert_args["mode"] == "warn"

    def test_save_scope_event_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_scope_event({"target": "x", "action": "block"}) is None

    def test_list_scope_events_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"id": "se1", "target": "evil.com"}
        ]
        result = db.list_scope_events()
        assert result is not None
        assert len(result) == 1

    def test_list_scope_events_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_scope_events() is None

    def test_list_scope_events_returns_empty_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.side_effect = Exception("err")
        assert db.list_scope_events() == []

    def test_clear_scope_events_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.clear_scope_events() is True
        tbl.delete.return_value.neq.assert_called()

    def test_clear_scope_events_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.clear_scope_events() is False


# ════════════════════════════════════════════════════════════════
#  16. SWARM SESSIONS
# ════════════════════════════════════════════════════════════════


class TestSwarmSessions:
    """Tests for Swarm Sessions CRUD."""

    def test_save_swarm_session_inserts_new(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [
            {"id": "sw1", "target": "10.0.0.1", "status": "running"}
        ]
        result = db.save_swarm_session({
            "target": "10.0.0.1", "mode": "auto",
            "phases": ["recon", "scan"]
        })
        assert result is not None
        assert result["status"] == "running"

    def test_save_swarm_session_updates_existing(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.update.return_value.eq.return_value.execute.return_value.data = [
            {"id": "sw1", "status": "done"}
        ]
        result = db.save_swarm_session({
            "id": "sw1", "status": "done",
            "phases": ["recon", "scan", "exploit"]
        })
        assert result is not None
        tbl.update.assert_called_once()

    def test_save_swarm_session_serializes_phases(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "sw1"}]
        db.save_swarm_session({
            "target": "10.0.0.1", "phases": ["recon"]
        })
        insert_args = tbl.insert.call_args[0][0]
        assert isinstance(insert_args["phases"], str)

    def test_save_swarm_session_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_swarm_session({"target": "x"}) is None

    def test_list_swarm_sessions_returns_data(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.limit.return_value.execute.return_value.data = [
            {"id": "sw1", "target": "10.0.0.1"}
        ]
        result = db.list_swarm_sessions()
        assert result is not None
        assert len(result) == 1

    def test_list_swarm_sessions_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.list_swarm_sessions() is None

    def test_get_swarm_session_returns_single(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [
            {"id": "sw1", "target": "10.0.0.1"}
        ]
        result = db.get_swarm_session("sw1")
        assert result is not None
        assert result["id"] == "sw1"

    def test_get_swarm_session_returns_none_when_not_found(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = []
        assert db.get_swarm_session("nonexistent") is None

    def test_get_swarm_session_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.get_swarm_session("sw1") is None

    def test_delete_swarm_session_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_swarm_session("sw1") is True

    def test_delete_swarm_session_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_swarm_session("sw1") is False


# ════════════════════════════════════════════════════════════════
#  17. APP CREDENTIALS (Secrets)
# ════════════════════════════════════════════════════════════════


class TestAppCredentials:
    """Tests for App Credentials / Secrets KV store."""

    def test_save_app_credential_inserts_new(self, patch_get_client):
        """save_app_credential inserts when key doesn't exist."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        # No existing key
        tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = []
        result = db.save_app_credential("ai_key", "sk-abc123", "OpenAI key")
        assert result is True
        tbl.insert.assert_called_once()

    def test_save_app_credential_updates_existing(self, patch_get_client):
        """save_app_credential updates when key already exists."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [
            {"key": "ai_key"}
        ]
        result = db.save_app_credential("ai_key", "sk-new-key", "Updated")
        assert result is True
        tbl.update.assert_called_once()

    def test_save_app_credential_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.save_app_credential("k", "v") is False

    def test_save_app_credential_returns_false_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.side_effect = Exception("err")
        assert db.save_app_credential("k", "v") is False

    def test_get_app_credential_returns_value(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [
            {"value": "sk-abc123"}
        ]
        result = db.get_app_credential("ai_key")
        assert result == "sk-abc123"

    def test_get_app_credential_returns_none_when_missing(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = []
        assert db.get_app_credential("nonexistent") is None

    def test_get_app_credential_returns_none_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.get_app_credential("k") is None

    def test_get_app_credential_returns_none_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.limit.return_value.execute.side_effect = Exception("err")
        assert db.get_app_credential("k") is None

    def test_delete_app_credential_returns_true(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        assert db.delete_app_credential("ai_key") is True
        tbl.delete.return_value.eq.assert_called_with("key", "ai_key")

    def test_delete_app_credential_returns_false_when_no_client(self):
        with patch("database.get_client", return_value=None):
            assert db.delete_app_credential("k") is False

    def test_delete_app_credential_returns_false_on_error(self, patch_get_client):
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.delete.return_value.eq.return_value.execute.side_effect = Exception("err")
        assert db.delete_app_credential("k") is False


# ════════════════════════════════════════════════════════════════
#  18. EDGE CASES & CROSS-CUTTING
# ════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Edge cases and cross-cutting concerns."""

    def test_table_helper_returns_none_when_no_client(self):
        """_table() returns None when get_client() returns None."""
        with patch("database.get_client", return_value=None):
            assert db._table("anything") is None

    def test_table_helper_returns_client_table(self, patch_get_client):
        """_table() returns the correct table reference."""
        result = db._table("ssh_connections")
        patch_get_client.table.assert_called_with("ssh_connections")
        assert result is not None

    def test_empty_response_data_handled(self, patch_get_client):
        """Functions handle resp.data being an empty list gracefully."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = []
        result = db.save_connection({
            "name": "x", "ip": "1.1.1.1", "username": "u", "password": "p"
        })
        assert result is None  # data is empty → returns None

    def test_empty_response_data_list_returns_empty(self, patch_get_client):
        """list_ functions return [] when resp.data is empty."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.order.return_value.execute.return_value.data = []
        result = db.list_connections()
        assert result == []

    def test_special_characters_in_data(self, patch_get_client):
        """Functions handle special characters in input data."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "1"}]
        result = db.save_connection({
            "name": "test'; DROP TABLE--",
            "ip": "10.0.0.1",
            "username": "root",
            "password": "p@$$w0rd!#%^&*()"
        })
        assert result is not None
        # Verify the data was passed through (Supabase handles escaping)
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["password"] == "p@$$w0rd!#%^&*()"

    def test_unicode_data(self, patch_get_client):
        """Functions handle unicode characters in input data."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "1"}]
        result = db.save_connection({
            "name": "测试连接",
            "ip": "10.0.0.1",
            "username": "管理员",
            "password": "密码123"
        })
        assert result is not None

    def test_large_payload_list_findings(self, patch_get_client):
        """list_findings handles large result sets."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        big_data = [{"id": f"f{i}", "tool": "nmap"} for i in range(200)]
        tbl.select.return_value.order.return_value.limit.return_value.execute.return_value.data = big_data
        result = db.list_findings(limit=200)
        assert len(result) == 200

    def test_concurrent_get_client_caching(self):
        """Multiple calls to get_client use cached client."""
        with patch.dict(os.environ, {"SUPABASE_URL": "https://x.supabase.co", "SUPABASE_KEY": "k"}):
            with patch("supabase.create_client") as mock_create:
                mock_create.return_value = MagicMock()
                db.get_client()
                db.get_client()
                db.get_client()
                assert mock_create.call_count == 1

    def test_get_client_reinitializes_after_reset(self):
        """After global reset, get_client creates a new client."""
        with patch.dict(os.environ, {"SUPABASE_URL": "https://x.supabase.co", "SUPABASE_KEY": "k"}):
            with patch("supabase.create_client") as mock_create:
                mock_create.return_value = MagicMock()
                db.get_client()
                assert mock_create.call_count == 1
                # Simulate reset
                db._supabase = None
                db.get_client()
                assert mock_create.call_count == 2

    def test_save_findings_bulk_empty_list(self, patch_get_client):
        """save_findings_bulk with empty list."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = []
        result = db.save_findings_bulk([])
        assert result == 0

    def test_count_findings_no_count_attribute(self, patch_get_client):
        """count_findings handles response without count attribute."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        resp = MagicMock(spec=[])  # no 'count' attribute
        tbl.select.return_value.execute.return_value = resp
        result = db.count_findings()
        assert result == 0

    def test_solve_ctf_challenge_multiline_flags(self, patch_get_client, patch_is_available):
        """solve_ctf_challenge handles multiline flags with whitespace."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.select.return_value.eq.return_value.execute.return_value.data = [{
            "id": 1,
            "flags": "  flag{one}  \n\nflag{two}\n\n",
            "points": 100,
            "solved": False
        }]
        result = db.solve_ctf_challenge(1, "flag{two}")
        assert result["ok"] is True

    def test_get_setting_with_complex_value(self, patch_get_client):
        """get_setting returns nested dict values."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        complex_val = {"theme": "dark", "lang": "es", "plugins": ["a", "b"]}
        tbl.select.return_value.eq.return_value.maybe_single.return_value.execute.return_value.data = {
            "key": "settings",
            "value": complex_val
        }
        result = db.get_setting("settings")
        assert result == complex_val

    def test_save_mission_history_strips_target_whitespace(self, patch_get_client):
        """save_mission_history strips whitespace from target."""
        tbl = MagicMock()
        patch_get_client.table.return_value = tbl
        tbl.insert.return_value.execute.return_value.data = [{"id": "m1"}]
        db.save_mission_history({"target": "  10.0.0.1  "})
        insert_args = tbl.insert.call_args[0][0]
        assert insert_args["target"] == "10.0.0.1"
