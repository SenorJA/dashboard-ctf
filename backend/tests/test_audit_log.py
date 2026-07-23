"""
Tests for backend/audit_log.py -- Structured JSON-lines Audit Logger.

Covers:
  - init_audit_log creates dir + file (idempotent)
  - audit() INFO writes one JSON line
  - audit() DEBUG filtered out (below min level)
  - audit() WARNING forwarded to SIEM (mock siem.ingest_event)
  - audit() CRITICAL forwarded to SIEM as "critical"
  - audit() INFO not forwarded to SIEM (below threshold)
  - Message is redacted (inject a fake api_key)
  - Details dict is redacted
  - Invalid level returns an error (no raise)
  - Rotation at threshold (simulate small max_bytes)
  - Rotation keeps the configured number of generations
  - get_recent_logs with no filter returns all
  - get_recent_logs filter by level / category / event / since / limit
  - get_log_stats returns counts and file size
  - get_audit_logger returns a Logger + AuditLogHandler emit conversion
  - get_recent_logs skips invalid JSON lines
  - Endpoint smoke tests (3 endpoints)
  - Thread-safe concurrent audit() calls don't mangle the file
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from audit_log import (
    AuditEvent,
    AuditLogHandler,
    audit,
    init_audit_log,
    rotate_if_needed,
    get_recent_logs,
    get_log_stats,
    get_audit_logger,
    _level_to_siem_severity,
    _reset_state_for_tests,
    CATEGORIES,
)
import audit_log as al_mod
import siem


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_audit_env(tmp_path, monkeypatch):
    """
    Give every test a fresh, isolated audit log file + reset module
    state so tests can't bleed into each other. We also reset the SIEM
    in-memory store so cross-test correlation counters don't drift.
    """
    _reset_state_for_tests()
    log_file = tmp_path / "audit.jsonl"
    # 8 KB default: big enough that single audit lines (~150-300 bytes)
    # don't accidentally trigger rotation, but small enough that
    # rotation-focused tests can still force a rotate with a few writes.
    init_audit_log(path=str(log_file), max_bytes=8192, generations=3,
                   level="INFO", siem_min_level="WARNING")
    siem.reset()
    yield log_file
    # Detach any AuditLogHandler the test added to existing loggers
    for nm in ("vulnforge", "vulnforge.test", "vulnforge.handler_test",
               "audit_test"):
        lg = logging.getLogger(nm)
        lg.handlers = [h for h in lg.handlers
                       if not isinstance(h, AuditLogHandler)]


@pytest.fixture
def client():
    """FastAPI TestClient fixture (same pattern as conftest.py)."""
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app) as c:
        yield c


# ══════════════════════════════════════════════════════════════════
#  init_audit_log
# ══════════════════════════════════════════════════════════════════

def test_init_creates_parent_dir(tmp_path):
    _reset_state_for_tests()
    nested = tmp_path / "deep" / "nested" / "audit.jsonl"
    init_audit_log(path=str(nested))
    assert nested.parent.exists()
    assert al_mod._initialized is True
    assert al_mod._log_path == nested


def test_init_is_idempotent_when_config_unchanged(isolated_audit_env):
    path_before = al_mod._log_path
    init_audit_log(path=str(path_before), max_bytes=200, generations=3,
                   level="INFO", siem_min_level="WARNING")
    # Calling again with same config must be a no-op (no error, same path)
    init_audit_log(path=str(path_before), max_bytes=200, generations=3,
                   level="INFO", siem_min_level="WARNING")
    assert al_mod._log_path == path_before


def test_init_applies_changed_config(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), max_bytes=999,
                   generations=5, level="DEBUG", siem_min_level="ERROR")
    assert al_mod._max_bytes == 999
    assert al_mod._generations == 5
    assert al_mod._min_level == "DEBUG"
    assert al_mod._siem_min_level == "ERROR"


def test_init_garbage_level_falls_back(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), level="BOGUS",
                   siem_min_level="NOPE")
    assert al_mod._min_level == "INFO"          # fell back to default
    assert al_mod._siem_min_level == "WARNING"  # fell back to default


# ══════════════════════════════════════════════════════════════════
#  audit() core behaviour
# ══════════════════════════════════════════════════════════════════

def _read_log_lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def test_audit_info_writes_one_json_line(isolated_audit_env):
    r = audit("INFO", "tool", "tool_executed", "nmap ran on target")
    assert r["ok"] is True
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == 1
    entry = lines[0]
    assert entry["level"] == "INFO"
    assert entry["category"] == "tool"
    assert entry["event"] == "tool_executed"
    assert entry["message"] == "nmap ran on target"
    # Structured fields default to omitted (None stripped)
    assert "user" not in entry
    assert "ip" not in entry
    assert entry["redacted"] is False


def test_audit_debug_filtered_below_min_level(isolated_audit_env):
    # Default min level is INFO in our fixture
    r = audit("DEBUG", "system", "debug_test", "should not be written")
    assert r["ok"] is True
    assert r.get("skipped") is True
    assert _read_log_lines(isolated_audit_env) == []


def test_audit_passes_when_min_level_lowered(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), max_bytes=200, generations=3,
                   level="DEBUG", siem_min_level="WARNING")
    r = audit("DEBUG", "system", "debug_test", "now visible")
    assert r.get("skipped") is not True
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == 1
    assert lines[0]["level"] == "DEBUG"


def test_audit_invalid_level_returns_error(isolated_audit_env):
    r = audit("NOPE", "system", "bad", "x")
    assert r["ok"] is False
    assert "error" in r
    # No file written for an invalid-level call
    assert not isolated_audit_env.exists()


def test_audit_message_redacted(isolated_audit_env):
    secret_msg = "Connecting with api_key=sk-1234567890abcdef12345 CredentialsOK"
    audit("INFO", "auth", "ssh_connect", secret_msg)
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == 1
    written = lines[0]["message"]
    assert "sk-1234567890abcdef12345" not in written
    assert "[REDACTED]" in written or "[OPENAI_KEY]" in written
    assert lines[0]["redacted"] is True


def test_audit_details_redacted(isolated_audit_env):
    details = {
        "token": "sk-1234567890abcdef1234567890abcdef",
        "host": "10.0.0.5",
        "port": 22,
    }
    audit("INFO", "auth", "login", "user logged in", details=details)
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == 1
    d = lines[0]["details"]
    assert "sk-1234567890abcdef1234567890abcdef" not in d["token"]
    assert d["port"] == 22  # non-string preserved
    assert lines[0]["redacted"] is True


def test_audit_empty_message_is_ok(isolated_audit_env):
    r = audit("INFO", "system", "empty_event")
    assert r["ok"] is True
    lines = _read_log_lines(isolated_audit_env)
    assert lines[0]["message"] == ""


def test_audit_never_raises_on_bad_details(isolated_audit_env):
    # details is not a dict -- audit() must not crash
    r = audit("INFO", "system", "weird", "msg", details="not a dict")  # type: ignore[arg-type]
    assert r["ok"] is True
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == 1


# ══════════════════════════════════════════════════════════════════
#  SIEM forwarding
# ══════════════════════════════════════════════════════════════════

def test_audit_warning_forwarded_to_siem(isolated_audit_env, monkeypatch):
    calls = []
    # NOTE: patch the SIEM module that audit_log actually references
    # (backend.siem, accessible as al_mod.siem) -- not the top-level
    # `siem` module that tests import directly.
    monkeypatch.setattr(al_mod.siem, "ingest_event",
                        lambda **kw: calls.append(kw) or None)
    audit("WARNING", "ws", "ssh_disconnect", "client dropped")
    assert len(calls) == 1
    assert calls[0]["source"] == "system"
    assert calls[0]["severity"] == "high"
    assert calls[0]["title"] == "ssh_disconnect"


def test_audit_critical_forwarded_as_critical(isolated_audit_env, monkeypatch):
    calls = []
    monkeypatch.setattr(al_mod.siem, "ingest_event",
                        lambda **kw: calls.append(kw) or None)
    audit("CRITICAL", "siem", "intrusion", "scope violation")
    assert calls[0]["severity"] == "critical"


def test_audit_error_forwarded_as_critical(isolated_audit_env, monkeypatch):
    calls = []
    monkeypatch.setattr(al_mod.siem, "ingest_event",
                        lambda **kw: calls.append(kw) or None)
    audit("ERROR", "system", "boom", "hard failure")
    assert calls[0]["severity"] == "critical"


def test_audit_info_not_forwarded_to_siem(isolated_audit_env, monkeypatch):
    calls = []
    monkeypatch.setattr(al_mod.siem, "ingest_event",
                        lambda **kw: calls.append(kw) or None)
    audit("INFO", "api", "endpoint_hit", "GET /api/health")
    assert calls == []  # below SIEM threshold


def test_siem_forward_failure_is_swallowed(isolated_audit_env, monkeypatch):
    """If SIEM raises, audit() must still return ok."""
    def boom(**kw):
        raise RuntimeError("siem down")
    monkeypatch.setattr(al_mod.siem, "ingest_event", boom)
    r = audit("WARNING", "siem", "test", "siem broken")
    assert r["ok"] is True
    # And the line was still written to the JSONL file
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == 1


def test_level_to_siem_severity_mapping():
    assert _level_to_siem_severity("CRITICAL") == "critical"
    assert _level_to_siem_severity("ERROR") == "critical"
    assert _level_to_siem_severity("WARNING") == "high"
    assert _level_to_siem_severity("INFO") == "low"
    assert _level_to_siem_severity("DEBUG") == "info"
    # case-insensitive
    assert _level_to_siem_severity("warning") == "high"


# ══════════════════════════════════════════════════════════════════
#  Rotation
# ══════════════════════════════════════════════════════════════════

def test_rotation_triggers_when_file_exceeds_max(isolated_audit_env):
    # Force a tiny rotation threshold so a handful of writes rolls over.
    init_audit_log(path=str(isolated_audit_env), max_bytes=120, generations=3,
                   level="DEBUG", siem_min_level="WARNING")
    for i in range(40):
        audit("INFO", "tool", "tool_executed", f"event number {i:03d}")
    # At least one rotated archive must now exist
    archive1 = isolated_audit_env.with_suffix(
        isolated_audit_env.suffix + ".1"
    )
    assert archive1.exists(), "expected .log.1 archive after rotation"


def test_rotation_keeps_generations(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), max_bytes=100,
                   generations=3, level="DEBUG", siem_min_level="WARNING")
    # Hammer writes to force multiple rotations
    for i in range(40):
        audit("INFO", "tool", "tool_executed",
              f"long event number {i:04d} padding padding padding")
    # The oldest generation (.3) may or may not exist, but .1 must.
    archive1 = isolated_audit_env.with_suffix(
        isolated_audit_env.suffix + ".1"
    )
    assert archive1.exists()
    # .4 must never be created (generations=3 keeps .1/.2/.3 at most)
    archive4 = isolated_audit_env.with_suffix(
        isolated_audit_env.suffix + ".4"
    )
    assert not archive4.exists()


def test_rotate_if_needed_returns_false_below_threshold(isolated_audit_env):
    audit("INFO", "system", "one", "small")
    assert rotate_if_needed() is False


def test_rotate_if_needed_returns_true_at_threshold(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), max_bytes=50, generations=3,
                   level="DEBUG", siem_min_level="WARNING")
    # Write bytes directly so audit()'s internal rotation doesn't pre-empt
    # the explicit rotate_if_needed() call we're testing.
    with open(isolated_audit_env, "w", encoding="utf-8") as fh:
        fh.write("x" * 200)
    assert rotate_if_needed() is True
    # Active file moved away to .1
    assert not isolated_audit_env.exists()
    archive1 = isolated_audit_env.with_suffix(
        isolated_audit_env.suffix + ".1"
    )
    assert archive1.exists()


# ══════════════════════════════════════════════════════════════════
#  Query API
# ══════════════════════════════════════════════════════════════════

def _seed(isolated_audit_env, entries):
    """Write raw JSONL entries directly so tests control exact content."""
    with open(isolated_audit_env, "a", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def _ts(minutes_ago: int) -> str:
    return (datetime.now(timezone.utc)
            - __import__("datetime").timedelta(minutes=minutes_ago)).isoformat()


def test_get_recent_logs_no_filter_returns_all(isolated_audit_env):
    _seed(isolated_audit_env, [
        {"timestamp": _ts(3), "level": "INFO", "category": "tool",
         "event": "a", "message": "m1", "details": {}, "redacted": False},
        {"timestamp": _ts(2), "level": "WARNING", "category": "siem",
         "event": "b", "message": "m2", "details": {}, "redacted": False},
    ])
    rows = get_recent_logs(limit=100)
    assert len(rows) == 2
    # newest first
    assert rows[0]["event"] == "b"


def test_get_recent_logs_filter_by_level(isolated_audit_env):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    _seed(isolated_audit_env, [
        {"timestamp": base.isoformat(), "level": "INFO", "category": "x",
         "event": "e", "message": "", "details": {}, "redacted": False},
        {"timestamp": base.isoformat(), "level": "WARNING", "category": "x",
         "event": "e", "message": "", "details": {}, "redacted": False},
        {"timestamp": base.isoformat(), "level": "ERROR", "category": "x",
         "event": "e", "message": "", "details": {}, "redacted": False},
    ])
    rows = get_recent_logs(limit=100, level="WARNING")
    assert len(rows) == 1
    assert rows[0]["level"] == "WARNING"
    # case-insensitive
    assert len(get_recent_logs(limit=100, level="warning")) == 1


def test_get_recent_logs_filter_by_category(isolated_audit_env):
    _seed(isolated_audit_env, [
        {"timestamp": _ts(5), "level": "INFO", "category": "tool",
         "event": "x", "message": "", "details": {}, "redacted": False},
        {"timestamp": _ts(4), "level": "INFO", "category": "auth",
         "event": "x", "message": "", "details": {}, "redacted": False},
    ])
    rows = get_recent_logs(limit=100, category="auth")
    assert len(rows) == 1
    assert rows[0]["category"] == "auth"


def test_get_recent_logs_filter_by_event(isolated_audit_env):
    _seed(isolated_audit_env, [
        {"timestamp": _ts(5), "level": "INFO", "category": "x",
         "event": "tool_executed", "message": "", "details": {},
         "redacted": False},
        {"timestamp": _ts(4), "level": "INFO", "category": "x",
         "event": "finding_saved", "message": "", "details": {},
         "redacted": False},
    ])
    rows = get_recent_logs(limit=100, event="finding_saved")
    assert len(rows) == 1
    assert rows[0]["event"] == "finding_saved"


def test_get_recent_logs_filter_by_since(isolated_audit_env):
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    new = datetime(2030, 1, 1, tzinfo=timezone.utc)
    _seed(isolated_audit_env, [
        {"timestamp": old.isoformat(), "level": "INFO", "category": "x",
         "event": "old", "message": "", "details": {}, "redacted": False},
        {"timestamp": new.isoformat(), "level": "INFO", "category": "x",
         "event": "new", "message": "", "details": {}, "redacted": False},
    ])
    rows = get_recent_logs(limit=100, since=datetime(
        2025, 1, 1, tzinfo=timezone.utc).isoformat())
    assert len(rows) == 1
    assert rows[0]["event"] == "new"


def test_get_recent_logs_limit_applied(isolated_audit_env):
    _seed(isolated_audit_env, [
        {"timestamp": _ts(i), "level": "INFO", "category": "x",
         "event": f"e{i}", "message": "", "details": {}, "redacted": False}
        for i in range(10, 0, -1)
    ])
    rows = get_recent_logs(limit=3)
    assert len(rows) == 3


def test_get_recent_logs_skips_invalid_json_lines(isolated_audit_env):
    # Manually write one bad line and two good ones
    with open(isolated_audit_env, "w", encoding="utf-8") as fh:
        fh.write('{"timestamp":"2030-01-01T00:00:00+00:00","level":"INFO",'
                 '"category":"x","event":"good1","message":"","details":{},'
                 '"redacted":false}\n')
        fh.write('THIS IS NOT VALID JSON\n')
        fh.write('{"timestamp":"2030-01-02T00:00:00+00:00","level":"INFO",'
                 '"category":"x","event":"good2","message":"","details":{},'
                 '"redacted":false}\n')
    rows = get_recent_logs(limit=100)
    # Invalid line is silently skipped
    events = {r["event"] for r in rows}
    assert events == {"good1", "good2"}


def test_get_recent_logs_spills_into_archive(isolated_audit_env):
    # Fill active file with 2 entries and archive with 3
    archive = isolated_audit_env.with_suffix(
        isolated_audit_env.suffix + ".1"
    )
    _seed(isolated_audit_env, [
        {"timestamp": _ts(1), "level": "INFO", "category": "x",
         "event": "active1", "message": "", "details": {}, "redacted": False},
        {"timestamp": _ts(2), "level": "INFO", "category": "x",
         "event": "active2", "message": "", "details": {}, "redacted": False},
    ])
    _seed(archive, [
        {"timestamp": _ts(3), "level": "INFO", "category": "x",
         "event": f"arch{i}", "message": "", "details": {}, "redacted": False}
        for i in range(3)
    ])
    rows = get_recent_logs(limit=100)
    assert len(rows) == 5
    events = {r["event"] for r in rows}
    assert "active1" in events and "arch2" in events


# ══════════════════════════════════════════════════════════════════
#  Stats
# ══════════════════════════════════════════════════════════════════

def test_get_log_stats_counts(isolated_audit_env):
    _seed(isolated_audit_env, [
        {"timestamp": _ts(1), "level": "INFO", "category": "tool",
         "event": "a", "message": "", "details": {}, "redacted": False},
        {"timestamp": _ts(2), "level": "WARNING", "category": "tool",
         "event": "b", "message": "", "details": {}, "redacted": False},
        {"timestamp": _ts(3), "level": "ERROR", "category": "api",
         "event": "c", "message": "", "details": {}, "redacted": False},
    ])
    stats = get_log_stats()
    assert stats["ok"] is True
    assert stats["total_events"] == 3
    assert stats["by_level"]["INFO"] == 1
    assert stats["by_level"]["WARNING"] == 1
    assert stats["by_level"]["ERROR"] == 1
    assert stats["by_category"]["tool"] == 2
    assert stats["by_category"]["api"] == 1
    assert stats["file_size_bytes"] > 0
    assert stats["max_bytes"] == 8192   # fixture default
    assert stats["generations_config"] == 3
    assert stats["min_level"] == "INFO"
    assert stats["siem_min_level"] == "WARNING"


def test_get_log_stats_reports_generations_present(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), max_bytes=80, generations=3,
                   level="DEBUG", siem_min_level="WARNING")
    for i in range(20):
        audit("INFO", "tool", "tool_executed",
              f"event {i:03d} padding padding")
    stats = get_log_stats()
    assert isinstance(stats["generations_present"], list)
    assert len(stats["generations_present"]) >= 1


# ══════════════════════════════════════════════════════════════════
#  AuditLogHandler + get_audit_logger
# ══════════════════════════════════════════════════════════════════

def test_get_audit_logger_returns_logger(isolated_audit_env):
    lg = get_audit_logger("vulnforge.test", category="api")
    assert isinstance(lg, logging.Logger)
    assert any(isinstance(h, AuditLogHandler) for h in lg.handlers)


def test_get_audit_logger_idempotent_handler(isolated_audit_env):
    lg = get_audit_logger("vulnforge.test")
    lg = get_audit_logger("vulnforge.test")  # call again
    handlers = [h for h in lg.handlers if isinstance(h, AuditLogHandler)]
    assert len(handlers) == 1  # only one handler attached


def test_audit_log_handler_emit_writes_audit_entry(isolated_audit_env):
    lg = get_audit_logger("vulnforge.handler_test", category="api")
    lg.warning("a test warning from %s", "somewhere")
    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) >= 1
    # The most recent line should come from our handler
    last = lines[-1]
    assert last["level"] == "WARNING"
    assert last["category"] == "api"
    assert "a test warning" in last["message"]
    assert last["details"]["module"]      # populated
    assert isinstance(last["details"]["line"], int)


def test_audit_log_handler_emit_never_raises(isolated_audit_env, monkeypatch):
    # Force audit() to raise -> handler must swallow the exception
    def boom(**kw):
        raise RuntimeError("audit broke")
    monkeypatch.setattr(al_mod, "audit", boom)
    h = AuditLogHandler(category="system")
    record = logging.LogRecord(
        name="x", level=logging.ERROR, pathname=__file__, lineno=1,
        msg="hello", args=(), exc_info=None,
    )
    # Must not raise
    h.emit(record)


# ══════════════════════════════════════════════════════════════════
#  Thread safety
# ══════════════════════════════════════════════════════════════════

def test_concurrent_audit_calls_do_not_corrupt_file(isolated_audit_env):
    init_audit_log(path=str(isolated_audit_env), max_bytes=10 * 1024 * 1024,
                   generations=3, level="DEBUG", siem_min_level="CRITICAL")
    N = 50
    THREADS = 8

    def worker(tid):
        for i in range(N):
            audit("INFO", "api", "concurrent", f"thread {tid} event {i}")

    threads = [threading.Thread(target=worker, args=(t,))
               for t in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = _read_log_lines(isolated_audit_env)
    assert len(lines) == N * THREADS
    # Every line must parse cleanly (already guaranteed by _read_log_lines,
    # but explicitly assert no partial writes / mixed lines)
    assert all("event" in ln and ln["event"] == "concurrent" for ln in lines)


# ══════════════════════════════════════════════════════════════════
#  Endpoint smoke tests
# ══════════════════════════════════════════════════════════════════

def test_endpoint_post_audit_creates_entry(client):
    payload = {
        "level": "WARNING",
        "category": "api",
        "event": "manual_test",
        "message": "frontend generated audit entry",
        "details": {"note": "smoke"},
    }
    r = client.post("/api/audit", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["event"]["level"] == "WARNING"
    assert body["event"]["category"] == "api"
    assert body["event"]["event"] == "manual_test"


def test_endpoint_post_audit_redacts_message(client):
    payload = {
        "level": "WARNING",
        "category": "auth",
        "event": "creds_seen",
        "message": "api_key=sk-1234567890abcdef12345 was used",
    }
    r = client.post("/api/audit", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert "sk-1234567890abcdef12345" not in body["event"]["message"]
    assert body["event"]["redacted"] is True


def test_endpoint_post_audit_rejects_invalid_level(client):
    r = client.post("/api/audit", json={"level": "NOPE", "event": "x"})
    assert r.status_code == 422
    assert r.json()["ok"] is False


def test_endpoint_get_logs(client):
    # Seed via POST then GET
    client.post("/api/audit", json={
        "level": "INFO", "category": "api", "event": "list_test",
        "message": "for listing",
    })
    r = client.get("/api/audit/logs", params={"limit": 10, "event": "list_test"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert any(ln["event"] == "list_test" for ln in body["logs"])


def test_endpoint_get_logs_filters(client):
    client.post("/api/audit", json={
        "level": "ERROR", "category": "docker", "event": "filter_me",
        "message": "boom",
    })
    client.post("/api/audit", json={
        "level": "INFO", "category": "api", "event": "filter_me",
        "message": "ok",
    })
    r = client.get("/api/audit/logs",
                   params={"limit": 50, "level": "ERROR", "event": "filter_me"})
    assert r.status_code == 200
    body = r.json()
    assert all(ln["level"] == "ERROR" for ln in body["logs"])
    assert len(body["logs"]) == 1


def test_endpoint_get_stats(client):
    client.post("/api/audit", json={
        "level": "INFO", "category": "system", "event": "stat_seed",
        "message": "x",
    })
    r = client.get("/api/audit/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "total_events" in body
    assert "by_level" in body
    assert "by_category" in body
    assert "file_size_bytes" in body


# ══════════════════════════════════════════════════════════════════
#  Misc
# ══════════════════════════════════════════════════════════════════

def test_audit_event_dataclass_roundtrip():
    ev = AuditEvent(
        timestamp="2030-01-01T00:00:00+00:00",
        level="INFO", category="api", event="t", message="m",
        user=None, ip=None, target=None, session_id=None,
        details={}, redacted=False,
    )
    from dataclasses import asdict
    d = asdict(ev)
    assert d["level"] == "INFO"
    assert d["category"] == "api"


def test_categories_set_contains_expected():
    for c in ("auth", "tool", "finding", "report", "plugin", "siem",
              "system", "api", "ws", "docker", "scope"):
        assert c in CATEGORIES