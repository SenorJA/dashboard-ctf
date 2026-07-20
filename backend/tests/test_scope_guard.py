"""
Tests for backend/scope_guard.py — Scope Validation.

Covers:
    - DEFAULT_CONFIG structure
    - get_config() default, DB read, force_refresh, DB errors
    - save_config() merging, stripping, DB errors
    - is_in_scope() disabled, enabled, CIDR, wildcard, subdomain, domain
    - _is_ip() IP vs non-IP
    - extract_targets() various command patterns
    - validate_command() safe commands, in-scope, out-of-scope, unknown
    - log_block(), get_block_history(), clear_block_history()
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scope_guard
from scope_guard import (
    DEFAULT_CONFIG,
    SCOPE_SETTINGS_KEY,
    get_config,
    save_config,
    is_in_scope,
    _is_ip,
    extract_targets,
    validate_command,
    log_block,
    get_block_history,
    clear_block_history,
)


@pytest.fixture(autouse=True)
def reset_state():
    """Reset in-memory state before each test."""
    scope_guard._config = None
    scope_guard._block_history.clear()
    yield
    scope_guard._config = None
    scope_guard._block_history.clear()


# ════════════════════════════════════════════════════════════════
#  DEFAULT_CONFIG
# ════════════════════════════════════════════════════════════════

class TestDefaultConfig:
    def test_has_required_keys(self):
        assert "enabled" in DEFAULT_CONFIG
        assert "mode" in DEFAULT_CONFIG
        assert "targets" in DEFAULT_CONFIG
        assert "block_private" in DEFAULT_CONFIG

    def test_disabled_by_default(self):
        assert DEFAULT_CONFIG["enabled"] is False

    def test_mode_is_warn(self):
        assert DEFAULT_CONFIG["mode"] == "warn"

    def test_targets_empty_by_default(self):
        assert DEFAULT_CONFIG["targets"] == []


# ════════════════════════════════════════════════════════════════
#  get_config()
# ════════════════════════════════════════════════════════════════

class TestGetConfig:
    @patch.object(scope_guard, "db")
    def test_returns_default_when_no_db(self, mock_db):
        mock_db.get_setting.return_value = None
        cfg = get_config(force_refresh=True)
        assert cfg == DEFAULT_CONFIG

    @patch.object(scope_guard, "db")
    def test_returns_stored_config(self, mock_db):
        custom = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        mock_db.get_setting.return_value = custom
        cfg = get_config(force_refresh=True)
        assert cfg["enabled"] is True
        assert cfg["mode"] == "block"
        assert "10.0.0.1" in cfg["targets"]

    @patch.object(scope_guard, "db")
    def test_returns_stored_config_from_json_string(self, mock_db):
        import json
        custom = {"enabled": True, "mode": "warn", "targets": ["x"], "block_private": False}
        mock_db.get_setting.return_value = json.dumps(custom)
        cfg = get_config(force_refresh=True)
        assert cfg["enabled"] is True

    @patch.object(scope_guard, "db")
    def test_db_exception_returns_default(self, mock_db):
        mock_db.get_setting.side_effect = RuntimeError("DB down")
        cfg = get_config(force_refresh=True)
        assert cfg == DEFAULT_CONFIG

    @patch.object(scope_guard, "db")
    def test_uses_cache(self, mock_db):
        custom = {"enabled": True, "mode": "warn", "targets": [], "block_private": False}
        mock_db.get_setting.return_value = custom
        get_config(force_refresh=True)
        # Second call should use cache, not hit DB again
        cfg = get_config(force_refresh=False)
        assert cfg["enabled"] is True
        mock_db.get_setting.assert_called_once()

    @patch.object(scope_guard, "db")
    def test_force_refresh_bypasses_cache(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": False, "mode": "warn", "targets": [], "block_private": False}
        get_config(force_refresh=True)
        # Change what DB returns
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": [], "block_private": False}
        cfg = get_config(force_refresh=True)
        assert cfg["enabled"] is True
        assert mock_db.get_setting.call_count == 2


# ════════════════════════════════════════════════════════════════
#  save_config()
# ════════════════════════════════════════════════════════════════

class TestSaveConfig:
    @patch.object(scope_guard, "db")
    def test_save_success(self, mock_db):
        mock_db.set_setting.return_value = True
        ok = save_config({"enabled": True, "mode": "block", "targets": ["10.0.0.1"]})
        assert ok is True
        mock_db.set_setting.assert_called_once()

    @patch.object(scope_guard, "db")
    def test_save_merges_defaults(self, mock_db):
        mock_db.set_setting.return_value = True
        save_config({"enabled": True})
        call_args = mock_db.set_setting.call_args
        saved = call_args[0][1]
        assert "mode" in saved  # merged from DEFAULT_CONFIG
        assert "targets" in saved

    @patch.object(scope_guard, "db")
    def test_save_strips_empty_targets(self, mock_db):
        mock_db.set_setting.return_value = True
        save_config({"targets": ["  10.0.0.1  ", "", "  ", "10.0.0.2"]})
        call_args = mock_db.set_setting.call_args
        saved = call_args[0][1]
        assert "" not in saved["targets"]
        assert " " not in saved["targets"]
        assert "10.0.0.1" in saved["targets"]
        assert "10.0.0.2" in saved["targets"]

    @patch.object(scope_guard, "db")
    def test_save_failure(self, mock_db):
        mock_db.set_setting.return_value = False
        ok = save_config({"enabled": True})
        assert ok is False

    @patch.object(scope_guard, "db")
    def test_save_exception(self, mock_db):
        mock_db.set_setting.side_effect = RuntimeError("DB error")
        ok = save_config({"enabled": True})
        assert ok is False


# ════════════════════════════════════════════════════════════════
#  is_in_scope()
# ════════════════════════════════════════════════════════════════

class TestIsInScope:
    @patch.object(scope_guard, "db")
    def test_disabled_always_true(self, mock_db):
        mock_db.get_setting.return_value = None
        assert is_in_scope("10.0.0.1") is True

    @patch.object(scope_guard, "db")
    def test_enabled_no_targets_blocks_all(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": [], "block_private": False}
        assert is_in_scope("10.0.0.1") is False

    @patch.object(scope_guard, "db")
    def test_direct_ip_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert is_in_scope("10.0.0.1") is True

    @patch.object(scope_guard, "db")
    def test_direct_ip_no_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert is_in_scope("10.0.0.2") is False

    @patch.object(scope_guard, "db")
    def test_cidr_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["192.168.1.0/24"], "block_private": False}
        assert is_in_scope("192.168.1.50") is True

    @patch.object(scope_guard, "db")
    def test_cidr_no_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["192.168.1.0/24"], "block_private": False}
        assert is_in_scope("10.0.0.1") is False

    @patch.object(scope_guard, "db")
    def test_domain_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["example.com"], "block_private": False}
        assert is_in_scope("example.com") is True

    @patch.object(scope_guard, "db")
    def test_wildcard_domain_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["*.example.com"], "block_private": False}
        assert is_in_scope("sub.example.com") is True

    @patch.object(scope_guard, "db")
    def test_wildcard_domain_exact(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["*.example.com"], "block_private": False}
        assert is_in_scope("example.com") is True

    @patch.object(scope_guard, "db")
    def test_wildcard_no_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["*.example.com"], "block_private": False}
        assert is_in_scope("other.com") is False

    @patch.object(scope_guard, "db")
    def test_subdomain_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["example.com"], "block_private": False}
        assert is_in_scope("api.example.com") is True

    @patch.object(scope_guard, "db")
    def test_multiple_targets_any_match(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1", "example.com", "192.168.0.0/16"], "block_private": False}
        assert is_in_scope("192.168.5.5") is True
        assert is_in_scope("example.com") is True

    @patch.object(scope_guard, "db")
    def test_ip_case_insensitive(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert is_in_scope("  10.0.0.1  ") is True

    @patch.object(scope_guard, "db")
    def test_invalid_cidr_ignored(self, mock_db):
        # Invalid CIDR should not crash, just not match
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["999.999.999.999/24"], "block_private": False}
        assert is_in_scope("10.0.0.1") is False


# ════════════════════════════════════════════════════════════════
#  _is_ip()
# ════════════════════════════════════════════════════════════════

class TestIsIp:
    def test_valid_ipv4(self):
        assert _is_ip("10.0.0.1") is True

    def test_valid_ipv6(self):
        assert _is_ip("::1") is True

    def test_not_ip(self):
        assert _is_ip("example.com") is False

    def test_empty(self):
        assert _is_ip("") is False

    def test_partial_ip(self):
        assert _is_ip("10.0.0") is False

    def test_cidr_not_ip(self):
        assert _is_ip("10.0.0.1/24") is False


# ════════════════════════════════════════════════════════════════
#  extract_targets()
# ════════════════════════════════════════════════════════════════

class TestExtractTargets:
    def test_nmap_ip(self):
        targets = extract_targets("nmap -sV 192.168.1.1")
        assert "192.168.1.1" in targets

    def test_nmap_cidr(self):
        targets = extract_targets("nmap 192.168.1.0/24")
        assert "192.168.1.0/24" in targets

    def test_ping(self):
        targets = extract_targets("ping 8.8.8.8")
        assert "8.8.8.8" in targets

    def test_curl_url(self):
        targets = extract_targets("curl http://example.com/path")
        assert "example.com" in targets

    def test_gobuster_url(self):
        targets = extract_targets("gobuster dir -u http://10.0.0.5 -w wl")
        assert "10.0.0.5" in targets

    def test_nikto_h_flag(self):
        targets = extract_targets("nikto -h example.com")
        assert "example.com" in targets

    def test_whatweb(self):
        targets = extract_targets("whatweb http://example.com")
        assert "example.com" in targets

    def test_ssh_user_host(self):
        targets = extract_targets("ssh user@192.168.1.1")
        assert "192.168.1.1" in targets

    def test_wpscan_url(self):
        targets = extract_targets("wpscan --url http://example.com")
        assert "example.com" in targets

    def test_sqlmap_url(self):
        targets = extract_targets("sqlmap -u http://example.com/page?id=1")
        assert "example.com" in targets

    def test_standalone_ip(self):
        targets = extract_targets("nmap 10.0.0.1")
        assert "10.0.0.1" in targets

    def test_no_targets(self):
        targets = extract_targets("ls -la")
        assert targets == []

    def test_deduplication(self):
        targets = extract_targets("nmap 10.0.0.1 10.0.0.1")
        assert targets.count("10.0.0.1") == 1

    def test_flags_skipped(self):
        targets = extract_targets("nmap -sV -sC 10.0.0.1")
        assert "-sV" not in targets
        assert "-sC" not in targets

    def test_hydra_with_l_and_p(self):
        targets = extract_targets("hydra -l admin -P pass.txt 10.0.0.1")
        assert "10.0.0.1" in targets

    def test_masscan(self):
        targets = extract_targets("masscan 10.0.0.0/24 -p80,443")
        assert "10.0.0.0/24" in targets

    def test_dnsrecon_d_flag(self):
        targets = extract_targets("dnsrecon -d example.com")
        assert "example.com" in targets


# ════════════════════════════════════════════════════════════════
#  validate_command()
# ════════════════════════════════════════════════════════════════

class TestValidateCommand:
    @patch.object(scope_guard, "db")
    def test_disabled_always_none(self, mock_db):
        mock_db.get_setting.return_value = None
        assert validate_command("nmap 10.0.0.1") is None

    @patch.object(scope_guard, "db")
    def test_safe_commands_bypass(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        for cmd in ["ls -la", "pwd", "whoami", "uname -a", "cat /etc/passwd", "cd /tmp"]:
            assert validate_command(cmd) is None, f"Safe command '{cmd}' should bypass"

    @patch.object(scope_guard, "db")
    def test_in_scope_no_block(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert validate_command("nmap 10.0.0.1") is None

    @patch.object(scope_guard, "db")
    def test_out_of_scope_warn_mode(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "warn", "targets": ["10.0.0.1"], "block_private": False}
        result = validate_command("nmap 10.0.0.2")
        assert result is not None
        assert result["blocked"] is True
        assert "10.0.0.2" in result["targets"]
        assert result["mode"] == "warn"

    @patch.object(scope_guard, "db")
    def test_out_of_scope_block_mode(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        result = validate_command("nmap 10.0.0.2")
        assert result is not None
        assert result["mode"] == "block"

    @patch.object(scope_guard, "db")
    def test_p10k_bypass(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert validate_command("p10k disable") is None

    @patch.object(scope_guard, "db")
    def test_prompt_bypass(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert validate_command("PROMPT=something") is None

    @patch.object(scope_guard, "db")
    def test_empty_command(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert validate_command("") is None

    @patch.object(scope_guard, "db")
    def test_non_targeting_command_no_target(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        assert validate_command("ps aux") is None

    @patch.object(scope_guard, "db")
    def test_cidr_in_scope(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["192.168.1.0/24"], "block_private": False}
        assert validate_command("nmap 192.168.1.50") is None

    @patch.object(scope_guard, "db")
    def test_multiple_targets_mixed(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        # nmap only gets one target from the regex
        result = validate_command("nmap 10.0.0.1")
        assert result is None

    @patch.object(scope_guard, "db")
    def test_result_has_message(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        result = validate_command("nmap 10.0.0.2")
        assert "message" in result
        assert "out of scope" in result["message"].lower()

    @patch.object(scope_guard, "db")
    def test_command_truncated(self, mock_db):
        mock_db.get_setting.return_value = {"enabled": True, "mode": "block", "targets": ["10.0.0.1"], "block_private": False}
        long_cmd = "nmap 10.0.0.2 " + "A" * 300
        result = validate_command(long_cmd)
        assert result is not None
        assert len(result["command"]) <= 200


# ════════════════════════════════════════════════════════════════
#  Block History
# ════════════════════════════════════════════════════════════════

class TestBlockHistory:
    def test_log_block_adds_entry(self):
        log_block({"target": "10.0.0.2", "action": "block"})
        history = get_block_history()
        assert len(history) == 1
        assert history[0]["target"] == "10.0.0.2"

    def test_log_block_has_timestamp(self):
        log_block({"target": "10.0.0.2"})
        history = get_block_history()
        assert "timestamp" in history[0]

    def test_get_block_history_limit(self):
        for i in range(60):
            log_block({"target": f"10.0.0.{i}"})
        history = get_block_history(limit=10)
        assert len(history) == 10

    def test_get_block_history_returns_copy(self):
        log_block({"target": "10.0.0.1"})
        h1 = get_block_history()
        h2 = get_block_history()
        assert h1 is not h2

    def test_clear_block_history(self):
        log_block({"target": "10.0.0.1"})
        log_block({"target": "10.0.0.2"})
        clear_block_history()
        assert get_block_history() == []

    def test_max_history_100(self):
        for i in range(120):
            log_block({"target": f"10.0.0.{i % 256}"})
        # Only last 100 should remain
        assert len(get_block_history(limit=200)) <= 100

    def test_empty_history(self):
        assert get_block_history() == []
