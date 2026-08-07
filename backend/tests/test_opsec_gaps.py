"""
Coverage-gap tests for backend/opsec.py.

Covers:
  - apply_opsec legacy full-replacement modifier path:
      * modifier starts with tool id but no target -> passthrough reason
      * modifier starts with tool id with target -> full replacement
"""

from unittest.mock import patch

from backend.opsec import apply_opsec


class TestFullReplacementPath:
    def _legacy_modifiers(self, tool, level="silent"):
        return {tool: {level: f"{tool} --stealth"}}

    def test_full_replace_without_target_passthrough(self):
        with patch("backend.opsec.TOOL_MODIFIERS",
                   self._legacy_modifiers("nmap")):
            res = apply_opsec("nmap", "nmap -sV 10.0.0.1", "silent", target="")
        assert res["blocked"] is False
        assert res["modified_command"] == "nmap -sV 10.0.0.1"
        assert "requires a target" in res["reason"]

    def test_full_replace_with_target(self):
        with patch("backend.opsec.TOOL_MODIFIERS",
                   self._legacy_modifiers("nmap")):
            res = apply_opsec("nmap", "nmap -sV 10.0.0.1", "silent",
                              target="10.0.0.5")
        assert res["blocked"] is False
        assert res["modified_command"] == "nmap --stealth 10.0.0.5"
        assert res["reason"]
