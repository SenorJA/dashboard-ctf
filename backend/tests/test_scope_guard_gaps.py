"""
Coverage-gap tests for backend/scope_guard.py.

Imports through the ``backend.scope_guard`` package path so coverage
measures the module consistently (existing tests import top-level).

Covers:
  - is_in_scope: CIDR match path
  - extract_targets: flag-like token skipped
  - log_block: DB persistence failure swallowed
  - _parse_iso: invalid timestamp
  - classify_command: out-of-scope warn/block layers
  - _is_expired: non-pending request
  - wait_for_decision: computed timeout, removed request, deadline expiry
"""

import time
from unittest.mock import patch

import backend.scope_guard as sg
from backend.scope_guard import (
    classify_command,
    extract_targets,
    is_in_scope,
    log_block,
    request_permission,
    wait_for_decision,
    _is_expired,
    _parse_iso,
)


def _reset():
    sg._config = None
    sg._pending.clear()
    sg._block_history.clear()


class TestIsInScopeCidr:
    def test_cidr_match(self):
        _reset()
        with patch("backend.scope_guard.db") as m:
            m.get_setting.return_value = {
                "enabled": True, "mode": "block",
                "targets": ["192.168.1.0/24"], "block_private": False,
            }
            assert is_in_scope("192.168.1.50") is True


class TestExtractTargetsFlagSkipped:
    def test_dash_token_skipped(self):
        targets = extract_targets("nmap --top-ports 100 10.0.0.1")
        # "--top-ports" is skipped; the standalone IP is still found.
        assert "--top-ports" not in targets
        assert "10.0.0.1" in targets


class TestLogBlockDbFailure:
    def test_db_exception_swallowed(self):
        _reset()
        # log_block imports save_scope_event directly from backend.database.
        with patch("backend.database.save_scope_event",
                   side_effect=RuntimeError("offline")):
            log_block({"target": "10.0.0.1", "action": "block",
                       "tool": "nmap", "reason": "test", "mode": "warn"})
        assert len(sg._block_history) == 1


class TestParseIso:
    def test_invalid_timestamp_returns_none(self):
        assert _parse_iso("not-a-date") is None
        assert _parse_iso(None) is None


class TestClassifyOutOfScope:
    def _scope_config(self, mode):
        return {
            "enabled": True, "mode": mode,
            "targets": ["10.0.0.1"], "block_private": False,
        }

    def test_warn_mode_out_of_scope(self):
        _reset()
        with patch("backend.scope_guard.db") as m:
            m.get_setting.return_value = self._scope_config("warn")
            res = classify_command("nmap", "nmap 192.168.1.1", "192.168.1.1")
        assert res["risk_level"] == "needs-confirmation"
        assert any("out-of-scope" in r for r in res["reasons"])

    def test_block_mode_out_of_scope(self):
        _reset()
        with patch("backend.scope_guard.db") as m:
            m.get_setting.return_value = self._scope_config("block")
            res = classify_command("nmap", "nmap 192.168.1.1", "192.168.1.1")
        assert res["risk_level"] == "blocked"
        assert res["max_severity"] == "critical"


class TestIsExpired:
    def test_non_pending_returns_false(self):
        _reset()
        r = request_permission("shell", "rm -rf /", "v", "s", "d",
                               ttl_seconds=10)
        r.status = "denied"
        assert _is_expired(r) is False


class FlakyPending(dict):
    """dict whose .get() returns None on the 3rd+ call (request "vanishes")."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._get_calls = 0

    def get(self, key, default=None):
        self._get_calls += 1
        if self._get_calls >= 3:
            return None
        return super().get(key, default)


class TestWaitForDecision:
    def test_computed_timeout_marks_expired(self):
        _reset()
        # Request already past its expiry; timeout=None computes from expiry.
        r = request_permission("shell", "rm -rf /", "v", "s", "d",
                               ttl_seconds=-1)
        result = wait_for_decision(r.id)
        assert result["status"] == "expired"
        assert result["decided_by"] == "timeout"

    def test_removed_request_inside_loop(self):
        _reset()
        r = request_permission("shell", "rm -rf /", "v", "s", "d",
                               ttl_seconds=30)

        def remove_on_sleep(seconds):
            sg._pending.pop(r.id, None)

        with patch("backend.scope_guard.time.sleep", side_effect=remove_on_sleep):
            result = wait_for_decision(r.id, timeout=5)
        assert result["status"] == "unknown"
        assert result["ok"] is False
        assert result["error"] == "request removed"

    def test_deadline_branch_marks_expired(self):
        _reset()
        # Long TTL so the deadline is reached before natural expiry.
        r = request_permission("shell", "rm -rf /", "v", "s", "d",
                               ttl_seconds=60)
        with patch("backend.scope_guard.time.sleep"):
            result = wait_for_decision(r.id, timeout=0.01)
        assert result["status"] == "expired"
        assert result["decided_by"] == "timeout"

    def test_deadline_branch_request_removed(self):
        _reset()
        # deadline hit AND the request vanishes from the pending dict between
        # the loop lookup and the deadline lookup -> "request removed".
        r = request_permission("shell", "rm -rf /", "v", "s", "d",
                               ttl_seconds=60)
        with patch.object(sg, "_pending", FlakyPending(sg._pending)):
            result = wait_for_decision(r.id, timeout=0.0)
        assert result["status"] == "unknown"
        assert result["error"] == "request removed"
