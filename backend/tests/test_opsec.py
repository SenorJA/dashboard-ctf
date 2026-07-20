"""
Tests for backend/opsec.py — OPSEC Levels Backend.

Covers:
    - LEVELS_INFO structure and completeness
    - TOOL_MODIFIERS completeness (all 3 levels for every tool)
    - _normalise_tool() edge cases
    - apply_opsec() happy path, blocked tools, passthrough, unknown tool/level
    - apply_opsec() legacy full-replacement path
    - apply_opsec() empty/None inputs
    - Target preservation during flags-only modifiers
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from opsec import (
    LEVEL_SILENT,
    LEVEL_COVERT,
    LEVEL_LOUD,
    LEVELS_INFO,
    TOOL_MODIFIERS,
    _normalise_tool,
    apply_opsec,
    _BLOCKED,
)


# ════════════════════════════════════════════════════════════════
#  LEVELS_INFO
# ════════════════════════════════════════════════════════════════

class TestLevelsInfo:
    def test_levels_info_has_three_entries(self):
        assert len(LEVELS_INFO) == 3

    def test_levels_info_contains_silent(self):
        ids = [l["id"] for l in LEVELS_INFO]
        assert LEVEL_SILENT in ids

    def test_levels_info_contains_covert(self):
        ids = [l["id"] for l in LEVELS_INFO]
        assert LEVEL_COVERT in ids

    def test_levels_info_contains_loud(self):
        ids = [l["id"] for l in LEVELS_INFO]
        assert LEVEL_LOUD in ids

    def test_levels_info_required_keys(self):
        required = {"id", "name", "color", "emoji", "description"}
        for entry in LEVELS_INFO:
            assert required.issubset(entry.keys()), f"Missing keys in {entry['id']}"

    def test_levels_info_colors_are_hex(self):
        for entry in LEVELS_INFO:
            assert entry["color"].startswith("#"), f"Color not hex: {entry['color']}"

    def test_level_constants_are_strings(self):
        assert isinstance(LEVEL_SILENT, str)
        assert isinstance(LEVEL_COVERT, str)
        assert isinstance(LEVEL_LOUD, str)


# ════════════════════════════════════════════════════════════════
#  TOOL_MODIFIERS
# ════════════════════════════════════════════════════════════════

class TestToolModifiers:
    def test_all_tools_have_three_levels(self):
        for tool, mods in TOOL_MODIFIERS.items():
            assert LEVEL_SILENT in mods, f"{tool} missing SILENT"
            assert LEVEL_COVERT in mods, f"{tool} missing COVERT"
            assert LEVEL_LOUD in mods, f"{tool} missing LOUD"

    def test_all_modifier_values_are_valid(self):
        """Modifier must be None, _BLOCKED, or a non-empty string."""
        for tool, mods in TOOL_MODIFIERS.items():
            for level, val in mods.items():
                if val is None:
                    continue
                assert isinstance(val, str), f"{tool}/{level} modifier is {type(val)}"
                assert val == _BLOCKED or len(val) > 0, f"{tool}/{level} empty string modifier"

    def test_known_tools_present(self):
        expected_tools = [
            "nmap", "masscan", "gobuster", "ffuf", "dirb", "nikto",
            "nuclei", "whatweb", "wpscan", "hydra", "wfuzz",
            "feroxbuster", "sqlmap", "curl", "searchsploit",
        ]
        for t in expected_tools:
            assert t in TOOL_MODIFIERS, f"Missing tool: {t}"

    def test_nmap_silent_has_stealth_flags(self):
        mod = TOOL_MODIFIERS["nmap"][LEVEL_SILENT]
        assert "-sS" in mod, "nmap silent should use SYN scan"
        assert "-T2" in mod, "nmap silent should use slow timing"

    def test_masscan_silent_is_blocked(self):
        assert TOOL_MODIFIERS["masscan"][LEVEL_SILENT] == _BLOCKED

    def test_nikto_silent_is_blocked(self):
        assert TOOL_MODIFIERS["nikto"][LEVEL_SILENT] == _BLOCKED

    def test_hydra_silent_is_blocked(self):
        assert TOOL_MODIFIERS["hydra"][LEVEL_SILENT] == _BLOCKED

    def testResponder_blocked_at_both_silent_and_covert(self):
        assert TOOL_MODIFIERS["responder"][LEVEL_SILENT] == _BLOCKED
        assert TOOL_MODIFIERS["responder"][LEVEL_COVERT] == _BLOCKED

    def test_responder_loud_allowed(self):
        assert TOOL_MODIFIERS["responder"][LEVEL_LOUD] is None

    def test_searchsploit_all_none(self):
        """Passive tool — all levels should be None (passthrough)."""
        for level in (LEVEL_SILENT, LEVEL_COVERT, LEVEL_LOUD):
            assert TOOL_MODIFIERS["searchsploit"][level] is None

    def test_wpscan_covert_has_stealthy(self):
        assert "stealthy" in TOOL_MODIFIERS["wpscan"][LEVEL_COVERT]

    def test_wpscan_loud_enumerates(self):
        assert "enumerate" in TOOL_MODIFIERS["wpscan"][LEVEL_LOUD]

    def test_hydra_covert_single_thread(self):
        mod = TOOL_MODIFIERS["hydra"][LEVEL_COVERT]
        assert "-t 1" in mod, "hydra covert should use single thread"

    def test_gobuster_silent_has_delay(self):
        mod = TOOL_MODIFIERS["gobuster"][LEVEL_SILENT]
        assert "delay" in mod.lower(), "gobuster silent should have delay"

    def test_ffuf_silent_has_rate_limit(self):
        mod = TOOL_MODIFIERS["ffuf"][LEVEL_SILENT]
        assert "rate" in mod, "ffuf silent should have rate limit"

    def test_total_tool_count_at_least_25(self):
        assert len(TOOL_MODIFIERS) >= 25, "Expected at least 25 tools"


# ════════════════════════════════════════════════════════════════
#  _normalise_tool()
# ════════════════════════════════════════════════════════════════

class TestNormaliseTool:
    def test_empty_string(self):
        assert _normalise_tool("") == ""

    def test_none_input(self):
        assert _normalise_tool(None) == ""

    def test_simple_tool(self):
        assert _normalise_tool("nmap") == "nmap"

    def test_uppercase(self):
        assert _normalise_tool("NMAP") == "nmap"

    def test_with_whitespace(self):
        assert _normalise_tool("  nmap  ") == "nmap"

    def test_suffix_nmap_fast(self):
        assert _normalise_tool("nmap-fast") == "nmap"

    def test_suffix_gobuster_dir(self):
        assert _normalise_tool("gobuster-dir") == "gobuster"

    def test_suffix_with_slash(self):
        assert _normalise_tool("nmap/extra") == "nmap"

    def test_unknown_tool_passthrough(self):
        assert _normalise_tool("my-custom-tool") == "my-custom-tool"

    def test_known_tool_no_suffix(self):
        assert _normalise_tool("ffuf") == "ffuf"

    def test_suffix_hydra_brute(self):
        assert _normalise_tool("hydra-brute") == "hydra"

    def test_suffix_unknown_head(self):
        # "randomtool-fast" — 'randomtool' not in TOOL_MODIFIERS
        assert _normalise_tool("randomtool-fast") == "randomtool-fast"

    def test_case_with_suffix(self):
        assert _normalise_tool("NMAP-FAST") == "nmap"


# ════════════════════════════════════════════════════════════════
#  apply_opsec() — happy path
# ════════════════════════════════════════════════════════════════

class TestApplyOpsecHappyPath:
    def test_loud_nmap_passthrough(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "loud")
        assert result["blocked"] is False
        assert result["modified_command"] == "nmap -sV 10.0.0.1"
        assert result["reason"] == ""

    def test_covert_nmap_adds_flags(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "covert")
        assert result["blocked"] is False
        assert "-sV" in result["modified_command"]
        assert "10.0.0.1" in result["modified_command"]
        assert "-T3" in result["modified_command"]

    def test_silent_nmap_adds_stealth_flags(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "silent")
        assert result["blocked"] is False
        assert "-T2" in result["modified_command"]
        assert "10.0.0.1" in result["modified_command"]

    def test_silent_masscan_blocked(self):
        result = apply_opsec("masscan", "masscan 10.0.0.0/24 -p80", "silent")
        assert result["blocked"] is True
        assert "blocked" in result["reason"].lower()
        assert result["modified_command"] == ""

    def test_covert_masscan_allowed(self):
        result = apply_opsec("masscan", "masscan 10.0.0.0/24 -p80", "covert")
        assert result["blocked"] is False
        assert "--rate=100" in result["modified_command"]

    def test_silent_gobuster_modifies(self):
        result = apply_opsec("gobuster", "gobuster dir -u http://x -w wordlist", "silent")
        assert result["blocked"] is False
        assert "--delay" in result["modified_command"]
        assert "-t 5" in result["modified_command"]

    def test_covert_hydra_single_thread(self):
        result = apply_opsec("hydra", "hydra -l admin -P pass.txt 10.0.0.1", "covert")
        assert result["blocked"] is False
        assert "-t 1" in result["modified_command"]
        assert "-W 5" in result["modified_command"]

    def test_silent_hydra_blocked(self):
        result = apply_opsec("hydra", "hydra -l admin -P pass.txt 10.0.0.1", "silent")
        assert result["blocked"] is True

    def test_covert_nuclei_rate_limited(self):
        result = apply_opsec("nuclei", "nuclei -u http://x", "covert")
        assert result["blocked"] is False
        assert "--rate-limit" in result["modified_command"]

    def test_silent_nuclei_blocked(self):
        result = apply_opsec("nuclei", "nuclei -u http://x", "silent")
        assert result["blocked"] is True

    def test_silent_whatweb_modifies(self):
        result = apply_opsec("whatweb", "whatweb http://x", "silent")
        assert result["blocked"] is False
        assert "-a 1" in result["modified_command"]

    def test_covert_whatweb_passthrough(self):
        result = apply_opsec("whatweb", "whatweb http://x", "covert")
        assert result["blocked"] is False
        assert result["modified_command"] == "whatweb http://x"

    def test_searchsploit_all_levels_passthrough(self):
        for level in (LEVEL_SILENT, LEVEL_COVERT, LEVEL_LOUD):
            result = apply_opsec("searchsploit", "searchsploit apache 2.4", level)
            assert result["blocked"] is False
            assert result["modified_command"] == "searchsploit apache 2.4"

    def test_curl_silent_adds_user_agent(self):
        result = apply_opsec("curl", "curl http://x", "silent")
        assert result["blocked"] is False
        assert "--user-agent" in result["modified_command"]

    def test_silent_sqlmap_blocked(self):
        result = apply_opsec("sqlmap", "sqlmap -u http://x", "silent")
        assert result["blocked"] is True

    def test_covert_sqlmap_allowed(self):
        result = apply_opsec("sqlmap", "sqlmap -u http://x", "covert")
        assert result["blocked"] is False
        assert "--batch" in result["modified_command"]

    def test_loud_hydra_threads(self):
        result = apply_opsec("hydra", "hydra -l admin -P pass.txt 10.0.0.1", "loud")
        assert result["blocked"] is False
        assert "-t 4" in result["modified_command"]


# ════════════════════════════════════════════════════════════════
#  apply_opsec() — unknown / edge cases
# ════════════════════════════════════════════════════════════════

class TestApplyOpsecEdgeCases:
    def test_unknown_tool_passthrough(self):
        result = apply_opsec("mytool", "mytool scan target", "silent")
        assert result["blocked"] is False
        assert result["modified_command"] == "mytool scan target"
        assert result["reason"] == ""

    def test_unknown_level_passthrough(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "turbo")
        assert result["blocked"] is False
        assert result["modified_command"] == "nmap -sV 10.0.0.1"

    def test_empty_command(self):
        result = apply_opsec("nmap", "", "silent")
        assert result["blocked"] is False
        assert result["modified_command"] == ""

    def test_none_command(self):
        result = apply_opsec("nmap", None, "silent")
        assert result["blocked"] is False

    def test_empty_level_defaults_to_loud(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "")
        assert result["blocked"] is False
        assert result["modified_command"] == "nmap -sV 10.0.0.1"

    def test_none_level_defaults_to_loud(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", None)
        assert result["blocked"] is False

    def test_none_tool(self):
        result = apply_opsec(None, "some command", "silent")
        assert result["blocked"] is False
        assert result["modified_command"] == "some command"

    def test_case_insensitive_level(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "SILENT")
        assert result["blocked"] is False
        assert "-T2" in result["modified_command"]

    def test_case_insensitive_tool(self):
        result = apply_opsec("NMAP", "nmap -sV 10.0.0.1", "silent")
        assert result["blocked"] is False
        assert "-T2" in result["modified_command"]

    def test_suffix_tool_normalisation(self):
        result = apply_opsec("nmap-fast", "nmap -sV 10.0.0.1", "silent")
        assert result["blocked"] is False
        assert "-T2" in result["modified_command"]

    def test_result_never_raises_on_garbage(self):
        result = apply_opsec(None, None, None)
        assert "blocked" in result
        assert "reason" in result
        assert "modified_command" in result


# ════════════════════════════════════════════════════════════════
#  apply_opsec() — target preservation
# ════════════════════════════════════════════════════════════════

class TestApplyOpsecTargetPreservation:
    def test_target_preserved_in_covert_nmap(self):
        result = apply_opsec("nmap", "nmap -sV 192.168.1.50", "covert", target="192.168.1.50")
        assert "192.168.1.50" in result["modified_command"]

    def test_target_preserved_in_silent_nmap(self):
        result = apply_opsec("nmap", "nmap -sV 192.168.1.50", "silent", target="192.168.1.50")
        assert "192.168.1.50" in result["modified_command"]

    def test_target_preserved_in_covert_gobuster(self):
        result = apply_opsec("gobuster", "gobuster dir -u http://10.0.0.5 -w wl", "covert")
        assert "10.0.0.5" in result["modified_command"]

    def test_target_preserved_in_silent_ffuf(self):
        result = apply_opsec("ffuf", "ffuf -u http://10.0.0.5 -w wl", "silent")
        assert "10.0.0.5" in result["modified_command"]


# ════════════════════════════════════════════════════════════════
#  apply_opsec() — reason strings
# ════════════════════════════════════════════════════════════════

class TestApplyOpsecReasons:
    def test_blocked_reason_mentions_tool(self):
        result = apply_opsec("masscan", "masscan -p80 10.0.0.1", "silent")
        assert "masscan" in result["reason"]

    def test_blocked_reason_mentions_level(self):
        result = apply_opsec("nikto", "nikto -h http://x", "silent")
        assert "silent" in result["reason"]

    def test_modified_reason_contains_opsec(self):
        result = apply_opsec("nmap", "nmap -sV 10.0.0.1", "covert")
        assert "OPSEC" in result["reason"]

    def test_passthrough_reason_is_empty(self):
        result = apply_opsec("searchsploit", "searchsploit x", "covert")
        assert result["reason"] == ""


# ════════════════════════════════════════════════════════════════
#  apply_opsec() — every known tool at every level
# ════════════════════════════════════════════════════════════════

class TestApplyOpsecAllTools:
    """Smoke test: apply_opsec must never raise on any tool × level."""
    @pytest.mark.parametrize("tool", list(TOOL_MODIFIERS.keys()))
    @pytest.mark.parametrize("level", [LEVEL_SILENT, LEVEL_COVERT, LEVEL_LOUD])
    def test_no_exception(self, tool, level):
        cmd = f"{tool} --help"
        result = apply_opsec(tool, cmd, level)
        assert isinstance(result, dict)
        assert "blocked" in result
        assert "reason" in result
        assert "modified_command" in result

    @pytest.mark.parametrize("tool", list(TOOL_MODIFIERS.keys()))
    @pytest.mark.parametrize("level", [LEVEL_SILENT, LEVEL_COVERT, LEVEL_LOUD])
    def test_blocked_has_empty_command(self, tool, level):
        result = apply_opsec(tool, f"{tool} test", level)
        if result["blocked"]:
            assert result["modified_command"] == ""

    @pytest.mark.parametrize("tool", list(TOOL_MODIFIERS.keys()))
    @pytest.mark.parametrize("level", [LEVEL_SILENT, LEVEL_COVERT, LEVEL_LOUD])
    def test_not_blocked_has_nonempty_command(self, tool, level):
        original = f"{tool} test"
        result = apply_opsec(tool, original, level)
        if not result["blocked"] and original:
            assert len(result["modified_command"]) > 0

    @pytest.mark.parametrize("tool", list(TOOL_MODIFIERS.keys()))
    @pytest.mark.parametrize("level", [LEVEL_SILENT, LEVEL_COVERT, LEVEL_LOUD])
    def test_target_in_modified_command(self, tool, level):
        """Target IP must survive in modified command when present."""
        target_ip = "192.168.1.100"
        cmd = f"{tool} {target_ip}"
        result = apply_opsec(tool, cmd, level, target=target_ip)
        if not result["blocked"] and target_ip in cmd:
            assert target_ip in result["modified_command"]


# ════════════════════════════════════════════════════════════════
#  apply_opsec() — immutability
# ════════════════════════════════════════════════════════════════

class TestApplyOpsecImmutability:
    def test_input_command_not_mutated(self):
        original = "nmap -sV 10.0.0.1"
        cmd_copy = original[:]
        apply_opsec("nmap", original, "covert")
        assert original == cmd_copy

    def test_input_tool_not_mutated(self):
        original = "NMAP"
        tool_copy = original[:]
        apply_opsec(original, "nmap -sV 10.0.0.1", "covert")
        assert original == tool_copy
