"""
Coverage-gap tests for backend/audit_log.py.

Covers:
  - init_audit_log: max_bytes/generations < 1 fallback; mkdir OSError
  - _ensure_initialized auto-init path
  - _log_writer: write OSError swallowed
  - rotate_if_needed: missing file, stat OSError, unlink/replace OSErrors
  - audit: details changed by redaction without a known token
  - _dict_contains_redaction_token list branch
  - _read_jsonl: blank lines, OSError
  - get_recent_logs: since filter (missing/invalid timestamps, invalid since)
  - get_log_stats: stat OSError
"""

import json
import logging

from pathlib import Path
from unittest.mock import patch

import backend.audit_log as al
from backend.audit_log import (
    _dict_contains_redaction_token,
    _ensure_initialized,
    _log_writer,
    _read_jsonl,
    _reset_state_for_tests,
    audit,
    get_log_stats,
    get_recent_logs,
    init_audit_log,
    rotate_if_needed,
)


# ──────────────────────────────────────────────
#  init_audit_log config fallbacks
# ──────────────────────────────────────────────

class TestInitConfigFallbacks:
    def test_max_bytes_lt_1_falls_back(self, tmp_path):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=0, generations=3,
                       level="INFO", siem_min_level="WARNING")
        assert al._max_bytes == 4 * 1024 * 1024

    def test_generations_lt_1_falls_back(self, tmp_path):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=8192, generations=0,
                       level="INFO", siem_min_level="WARNING")
        assert al._generations == 3

    def test_mkdir_oserror_warns(self, tmp_path):
        _reset_state_for_tests()
        log_file = tmp_path / "nested" / "audit.jsonl"
        with patch("pathlib.Path.mkdir", side_effect=OSError("denied")):
            init_audit_log(path=str(log_file))
        # Config still applied despite dir failure.
        assert al._initialized is True
        assert al._log_path == log_file


# ──────────────────────────────────────────────
#  _ensure_initialized
# ──────────────────────────────────────────────

class TestEnsureInitialized:
    def test_auto_init_when_not_initialized(self, tmp_path):
        _reset_state_for_tests()
        _ensure_initialized()
        assert al._initialized is True


# ──────────────────────────────────────────────
#  _log_writer OSError
# ──────────────────────────────────────────────

class TestLogWriterOSError:
    def test_write_failure_swallowed(self, tmp_path, caplog):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file))
        with patch("builtins.open", side_effect=OSError("disk full")):
            # Must not raise.
            _log_writer('{"a":1}')
        assert any("write failed" in r.message for r in caplog.records)


# ──────────────────────────────────────────────
#  rotate_if_needed edge cases
# ──────────────────────────────────────────────

class TestRotateEdgeCases:
    def test_missing_file_returns_false(self, tmp_path):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=10)
        assert not log_file.exists()
        assert rotate_if_needed() is False

    def test_stat_oserror_returns_false(self, tmp_path):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=10)
        log_file.write_text("x" * 100, encoding="utf-8")
        with patch("pathlib.Path.stat", side_effect=OSError("stat fail")):
            assert rotate_if_needed() is False

    def test_unlink_oserror_warns(self, tmp_path, caplog):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=5, generations=2)
        log_file.write_text("x" * 100, encoding="utf-8")
        # Create oldest generation so unlink() is attempted.
        oldest = log_file.with_suffix(log_file.suffix + ".2")
        oldest.write_text("old", encoding="utf-8")
        with patch("pathlib.Path.unlink", side_effect=OSError("locked")):
            rotate_if_needed()
        assert any("could not delete" in r.message for r in caplog.records)

    def test_replace_oserror_warns(self, tmp_path, caplog):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=5, generations=2)
        log_file.write_text("x" * 100, encoding="utf-8")
        with patch("pathlib.Path.replace", side_effect=OSError("perm")):
            assert rotate_if_needed() is True
        assert any("rotate active" in r.message for r in caplog.records)

    def test_src_replace_oserror_warns(self, tmp_path, caplog):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=5, generations=2)
        log_file.write_text("x" * 100, encoding="utf-8")
        archive1 = log_file.with_suffix(log_file.suffix + ".1")
        archive1.write_text("old", encoding="utf-8")

        real_replace = Path.replace

        def flaky_replace(target, *a, **k):
            # Fail only the generation-shift replace (.1 -> .2). The
            # mocked method receives just the destination argument.
            if str(target).endswith(".2"):
                raise OSError("shift fail")
            return real_replace(al._log_path, target, *a, **k)

        with patch("pathlib.Path.replace", side_effect=flaky_replace):
            assert rotate_if_needed() is True
        assert any("rotate " in r.message and " failed" in r.message
                   for r in caplog.records)


# ──────────────────────────────────────────────
#  audit redaction token-less change
# ──────────────────────────────────────────────

class TestAuditRedactedNoToken:
    def test_details_changed_without_known_token(self, tmp_path):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=8192, generations=3,
                       level="INFO", siem_min_level="WARNING")
        details = {"x": "aws_secret_access_key=" + "A" * 40}
        res = audit("INFO", "system", "evt", "msg", details=details)
        assert res["ok"] is True
        assert res["event"]["redacted"] is True


# ──────────────────────────────────────────────
#  _dict_contains_redaction_token list branch
# ──────────────────────────────────────────────

class TestDictContainsToken:
    def test_list_branch_true(self):
        assert _dict_contains_redaction_token(["a", "[REDACTED]"]) is True

    def test_list_branch_false(self):
        assert _dict_contains_redaction_token(["a", "b"]) is False

    def test_non_container_false(self):
        assert _dict_contains_redaction_token(42) is False


# ──────────────────────────────────────────────
#  _read_jsonl edge cases
# ──────────────────────────────────────────────

class TestReadJsonl:
    def test_blank_lines_skipped(self, tmp_path):
        p = tmp_path / "audit.jsonl"
        p.write_text('\n{"a":1}\n\n\n{"b":2}\n', encoding="utf-8")
        rows = _read_jsonl(p)
        assert len(rows) == 2

    def test_oserror_returns_partial(self, tmp_path, caplog):
        p = tmp_path / "audit.jsonl"
        p.write_text('{"a":1}\n', encoding="utf-8")
        with patch("builtins.open", side_effect=OSError("io fail")):
            rows = _read_jsonl(p)
        assert rows == []
        assert any("read failed" in r.message for r in caplog.records)


# ──────────────────────────────────────────────
#  get_recent_logs since filter edge cases
# ──────────────────────────────────────────────

class TestSinceFilter:
    def _seed_rows(self, tmp_path, rows):
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file), max_bytes=8192, generations=3,
                       level="INFO", siem_min_level="WARNING")
        with open(log_file, "a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return log_file

    def test_row_without_timestamp_skipped(self, tmp_path):
        log_file = self._seed_rows(tmp_path, [
            {"level": "INFO", "category": "x", "event": "e", "message": "no-ts"},
            {"level": "INFO", "category": "x", "event": "e", "message": "with-ts",
             "timestamp": "2026-01-01T00:00:00+00:00"},
        ])
        rows = get_recent_logs(limit=100, since="2025-01-01T00:00:00+00:00")
        assert len(rows) == 1
        assert rows[0]["message"] == "with-ts"

    def test_invalid_row_timestamp_skipped(self, tmp_path):
        log_file = self._seed_rows(tmp_path, [
            {"level": "INFO", "category": "x", "event": "e", "message": "bad-ts",
             "timestamp": "not-a-date"},
            {"level": "INFO", "category": "x", "event": "e", "message": "good",
             "timestamp": "2026-01-01T00:00:00+00:00"},
        ])
        rows = get_recent_logs(limit=100, since="2025-01-01T00:00:00+00:00")
        assert len(rows) == 1
        assert rows[0]["message"] == "good"

    def test_invalid_since_ignored(self, tmp_path):
        log_file = self._seed_rows(tmp_path, [
            {"level": "INFO", "category": "x", "event": "e", "message": "m",
             "timestamp": "2026-01-01T00:00:00+00:00"},
        ])
        rows = get_recent_logs(limit=100, since="garbage-since")
        assert len(rows) == 1


# ──────────────────────────────────────────────
#  get_log_stats stat OSError
# ──────────────────────────────────────────────

class TestStatsOSError:
    def test_stat_oserror_sets_zero(self, tmp_path):
        import os
        _reset_state_for_tests()
        log_file = tmp_path / "audit.jsonl"
        init_audit_log(path=str(log_file))
        log_file.write_text('{"level":"INFO"}\n', encoding="utf-8")

        real_stat = os.stat
        count = {"n": 0}

        def flaky_stat(path, *a, **k):
            # First two stat() calls happen inside Path.exists(); only the
            # direct _log_path.stat().st_size access should fail.
            count["n"] += 1
            if count["n"] == 3:
                raise OSError("stat fail")
            return real_stat(path, *a, **k)

        with patch("os.stat", side_effect=flaky_stat):
            stats = get_log_stats()
        assert stats["ok"] is True
        assert stats["file_size_bytes"] == 0
        assert count["n"] >= 3
