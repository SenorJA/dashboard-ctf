"""
Coverage-gap tests for backend/hash_cracker.py.

Covers:
  - identify_hash_type: broken regex pattern (re.error branch)
"""

from unittest.mock import patch

from backend.hash_cracker import identify_hash_type


class TestIdentifyRegexErrorGap:
    def test_bad_regex_skipped(self):
        bad = {"name": "Broken", "regex": r"^([a-f0-9]{32", "length": -1}
        with patch("backend.hash_cracker.HASH_PATTERNS", [bad]):
            matches = identify_hash_type("abcdef0123456789abcdef0123456789")
        # The broken pattern is skipped; no valid pattern matched.
        assert matches == []
