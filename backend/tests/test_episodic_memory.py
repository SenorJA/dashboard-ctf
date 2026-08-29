"""
tests/test_episodic_memory.py — SQLite-backed episodic memory store.

Covers:
  * save_episodic_memory  — ok with id, auto key-decision extraction,
    explicit key decisions, redaction before storage, never raises.
  * get_episodic_memory   — empty DB, mixed sessions, per-session filter,
    limit clamp.
  * clear_episodic_memory — wipe all, wipe by session, count returned.
  * get_episodic_context  — formatted string, empty string when nothing.
  * LRU eviction          — 501 inserts → 500 rows remain.
  * Thread-safety         — concurrent saves don't crash.
  * _init_db idempotency  — repeated calls are safe.

Uses a temp directory for the DB so the real ``backend/data/`` is never
touched by the test suite.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.episodic_memory as em


# ════════════════════════════════════════════════════════════════════
#  Fixtures — isolate the SQLite DB to a temp file per test
# ════════════════════════════════════════════════════════════════════

@pytest.fixture()
def tmp_db(tmp_path: Path, monkeypatch) -> Path:
    """Redirect the episodic-memory DB to a temp path for the test."""
    db_path = tmp_path / "episodic_memory.db"
    monkeypatch.setattr(em, "_DB_PATH", db_path)
    # Make sure no stale state lingers between tests.
    em._init_db()
    yield db_path


# ════════════════════════════════════════════════════════════════════
#  1. _init_db
# ════════════════════════════════════════════════════════════════════

class TestInitDb:
    def test_creates_data_dir_and_table(self, tmp_path: Path, monkeypatch):
        db_path = tmp_path / "nested" / "dir" / "episodic.db"
        monkeypatch.setattr(em, "_DB_PATH", db_path)
        em._init_db()
        assert db_path.parent.exists()
        assert db_path.exists()

    def test_is_idempotent(self, tmp_db: Path):
        # Calling again should not raise nor duplicate the table.
        em._init_db()
        em._init_db()
        # Insert + count still works.
        em.save_episodic_memory("s1", "recon", "task", "resp")
        result = em.get_episodic_memory()
        assert result["ok"] is True
        assert len(result["memories"]) == 1


# ════════════════════════════════════════════════════════════════════
#  2. save_episodic_memory
# ════════════════════════════════════════════════════════════════════

class TestSave:
    def test_save_returns_ok_with_id(self, tmp_db: Path):
        result = em.save_episodic_memory("s1", "recon", "scan host", "ok response")
        assert result["ok"] is True
        assert isinstance(result["id"], int)
        assert result["session_id"] == "s1"
        # "ok response" has no decision markers → empty extraction.
        assert result["key_decisions"] == ""

    def test_save_with_explicit_key_decisions(self, tmp_db: Path):
        result = em.save_episodic_memory(
            "s1", "webvuln", "task", "resp",
            key_decisions="recommend running nmap",
        )
        assert result["ok"] is True
        assert result["key_decisions"] == "recommend running nmap"

    def test_auto_extracts_key_decisions_from_response(self, tmp_db: Path):
        response = (
            "Some intro text.\n"
            "I recommend doing X first.\n"
            "Next step: do Y.\n"
            "Important: avoid Z.\n"
            "key finding: port 22 open.\n"
            "I suggest also doing W.\n"
            "Another recommend line that should be dropped (6th).\n"
        )
        result = em.save_episodic_memory("s1", "recon", "task", response)
        assert result["ok"] is True
        decisions = result["key_decisions"]
        # Should keep at most 5 lines containing markers.
        assert "recommend doing X first" in decisions
        assert "Next step: do Y" in decisions
        assert "Important: avoid Z" in decisions
        assert "key finding: port 22 open" in decisions
        assert "I suggest also doing W" in decisions
        # 6th marker line must be dropped (cap = 5).
        assert "6th" not in decisions

    def test_auto_extraction_empty_when_no_markers(self, tmp_db: Path):
        result = em.save_episodic_memory("s1", "recon", "task", "just plain text no markers")
        assert result["ok"] is True
        assert result["key_decisions"] == ""

    def test_auto_extraction_skips_blank_lines(self, tmp_db: Path):
        response = "\n\n   \nrecommend doing X\n\n"
        result = em.save_episodic_memory("s1", "recon", "task", response)
        assert result["ok"] is True
        assert result["key_decisions"] == "recommend doing X"

    def test_redacts_secrets_in_task(self, tmp_db: Path):
        secret_task = "my github token ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = em.save_episodic_memory("s1", "recon", secret_task, "resp")
        assert result["ok"] is True
        got = em.get_episodic_memory("s1")
        stored_task = got["memories"][0]["task"]
        assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in stored_task
        assert "[GITHUB_TOKEN]" in stored_task

    def test_redacts_secrets_in_key_decisions(self, tmp_db: Path):
        decisions = "use key AKIAIOSFODNN7EXAMPLE to access bucket"
        result = em.save_episodic_memory(
            "s1", "recon", "task", "resp", key_decisions=decisions,
        )
        assert result["ok"] is True
        assert "AKIAIOSFODNN7EXAMPLE" not in result["key_decisions"]
        assert "[AWS_KEY]" in result["key_decisions"]

    def test_save_never_raises_on_bad_input(self, tmp_db: Path):
        # Non-string inputs should be tolerated (coerced via `or ""`).
        result = em.save_episodic_memory(None, None, None, None)  # type: ignore[arg-type]
        assert result["ok"] is True

    def test_save_returns_error_dict_when_db_unwritable(self, tmp_path: Path, monkeypatch):
        # Point the DB at a path whose parent is a file → mkdir / connect fails.
        blocker = tmp_path / "blocker_file"
        blocker.write_text("not a dir")
        monkeypatch.setattr(em, "_DB_PATH", blocker / "episodic.db")
        result = em.save_episodic_memory("s1", "recon", "task", "resp")
        assert result["ok"] is False
        assert "error" in result


# ════════════════════════════════════════════════════════════════════
#  3. get_episodic_memory
# ════════════════════════════════════════════════════════════════════

class TestGet:
    def test_empty_initially(self, tmp_db: Path):
        result = em.get_episodic_memory()
        assert result["ok"] is True
        assert result["memories"] == []

    def test_returns_inserted_entries(self, tmp_db: Path):
        em.save_episodic_memory("s1", "recon", "task1", "resp1")
        em.save_episodic_memory("s1", "webvuln", "task2", "resp2")
        result = em.get_episodic_memory()
        assert result["ok"] is True
        assert len(result["memories"]) == 2
        # Each memory has the expected keys.
        for m in result["memories"]:
            assert {"id", "session_id", "specialist", "task", "key_decisions", "timestamp"} <= set(m)

    def test_filter_by_session_id(self, tmp_db: Path):
        em.save_episodic_memory("s1", "recon", "task-a", "resp")
        em.save_episodic_memory("s2", "recon", "task-b", "resp")
        result = em.get_episodic_memory(session_id="s2")
        assert result["ok"] is True
        assert len(result["memories"]) == 1
        assert result["memories"][0]["session_id"] == "s2"

    def test_limit_is_respected(self, tmp_db: Path):
        for i in range(10):
            em.save_episodic_memory("s1", "recon", f"task{i}", "resp")
        result = em.get_episodic_memory(limit=3)
        assert len(result["memories"]) == 3

    def test_limit_clamped_to_max(self, tmp_db: Path):
        # Huge limit should be clamped, not crash.
        result = em.get_episodic_memory(limit=10_000)
        assert result["ok"] is True

    def test_returns_error_dict_on_failure(self, tmp_path: Path, monkeypatch):
        blocker = tmp_path / "blocker_file"
        blocker.write_text("x")
        monkeypatch.setattr(em, "_DB_PATH", blocker / "episodic.db")
        result = em.get_episodic_memory()
        assert result["ok"] is False
        assert result["memories"] == []


# ════════════════════════════════════════════════════════════════════
#  4. clear_episodic_memory
# ════════════════════════════════════════════════════════════════════

class TestClear:
    def test_clears_all(self, tmp_db: Path):
        em.save_episodic_memory("s1", "recon", "t1", "r")
        em.save_episodic_memory("s2", "recon", "t2", "r")
        result = em.clear_episodic_memory()
        assert result["ok"] is True
        assert result["cleared"] == 2
        assert em.get_episodic_memory()["memories"] == []

    def test_clears_specific_session(self, tmp_db: Path):
        em.save_episodic_memory("s1", "recon", "t1", "r")
        em.save_episodic_memory("s2", "recon", "t2", "r")
        result = em.clear_episodic_memory(session_id="s1")
        assert result["ok"] is True
        assert result["cleared"] == 1
        remaining = em.get_episodic_memory()["memories"]
        assert len(remaining) == 1
        assert remaining[0]["session_id"] == "s2"

    def test_clear_empty_returns_zero(self, tmp_db: Path):
        result = em.clear_episodic_memory()
        assert result["ok"] is True
        assert result["cleared"] == 0

    def test_clear_never_raises(self, tmp_path: Path, monkeypatch):
        blocker = tmp_path / "blocker_file"
        blocker.write_text("x")
        monkeypatch.setattr(em, "_DB_PATH", blocker / "episodic.db")
        result = em.clear_episodic_memory()
        assert result["ok"] is False
        assert result["cleared"] == 0


# ════════════════════════════════════════════════════════════════════
#  5. get_episodic_context
# ════════════════════════════════════════════════════════════════════

class TestContext:
    def test_empty_when_no_memories(self, tmp_db: Path):
        assert em.get_episodic_context() == ""
        assert em.get_episodic_context("s1") == ""

    def test_returns_formatted_string(self, tmp_db: Path):
        em.save_episodic_memory(
            "s1", "recon", "scan host", "resp",
            key_decisions="recommend nmap",
        )
        ctx = em.get_episodic_context("s1")
        assert ctx.startswith("<past_decisions>")
        assert ctx.endswith("</past_decisions>")
        assert "[recon]" in ctx
        assert "scan host" in ctx
        assert "recommend nmap" in ctx

    def test_context_without_key_decisions(self, tmp_db: Path):
        em.save_episodic_memory("s1", "recon", "plain task", "no markers here")
        ctx = em.get_episodic_context("s1")
        assert "[recon]" in ctx
        assert "plain task" in ctx

    def test_context_scoped_to_session(self, tmp_db: Path):
        em.save_episodic_memory("s1", "recon", "task-a", "r", key_decisions="d-a")
        em.save_episodic_memory("s2", "webvuln", "task-b", "r", key_decisions="d-b")
        ctx = em.get_episodic_context("s2")
        assert "task-b" in ctx
        assert "task-a" not in ctx

    def test_context_never_raises(self, tmp_path: Path, monkeypatch):
        blocker = tmp_path / "blocker_file"
        blocker.write_text("x")
        monkeypatch.setattr(em, "_DB_PATH", blocker / "episodic.db")
        assert em.get_episodic_context() == ""

    def test_context_empty_when_memories_have_no_text(self, tmp_db: Path):
        # A memory with neither task text nor key decisions yields no line.
        em.save_episodic_memory("s1", "recon", "", "no markers here")
        assert em.get_episodic_context("s1") == ""


# ════════════════════════════════════════════════════════════════════
#  6. LRU eviction
# ════════════════════════════════════════════════════════════════════

class TestLRUEviction:
    def test_caps_at_500_entries(self, tmp_db: Path):
        # Insert 501 → 50 oldest evicted → 500 remain... wait, spec says
        # evict batch of 50 when > 500, so 501 triggers eviction of 50
        # leaving 451. The contract is "max 500" — after eviction we are
        # below the cap. Insert enough to verify the cap holds.
        for i in range(501):
            em.save_episodic_memory("s1", "recon", f"task{i}", "resp")
        result = em.get_episodic_memory(limit=500)
        # After one eviction pass (501 > 500 → evict 50 → 451 rows).
        assert len(result["memories"]) <= em._MAX_ENTRIES
        assert len(result["memories"]) == 451

    def test_repeated_inserts_stay_under_cap(self, tmp_db: Path):
        for i in range(600):
            em.save_episodic_memory("s1", "recon", f"task{i}", "resp")
        result = em.get_episodic_memory(limit=500)
        assert len(result["memories"]) <= em._MAX_ENTRIES


# ════════════════════════════════════════════════════════════════════
#  7. Thread-safety
# ════════════════════════════════════════════════════════════════════

class TestThreadSafety:
    def test_concurrent_saves_do_not_crash(self, tmp_db: Path):
        errors: list[Exception] = []

        def _worker(idx: int) -> None:
            try:
                for j in range(20):
                    em.save_episodic_memory(
                        f"s{idx}", "recon", f"task-{idx}-{j}", "resp",
                    )
            except Exception as exc:  # pragma: no cover — failure indicator
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        # All 8 * 20 = 160 entries should be present (well under cap).
        total = len(em.get_episodic_memory(limit=500)["memories"])
        assert total == 160
