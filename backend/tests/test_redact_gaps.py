"""
Coverage-gap tests for backend/redact.py — edge branches.

Covers:
  - _luhn_check(): short digit counts
  - redact_dict/redact_list: non-container inputs, nested lists, max_depth
  - redact_json: non-str input, list input, primitive input
  - redact_log_line: non-str input
  - redact_ai_payload: non-list input, non-dict items, tool_calls arguments
  - redact_report: non-dict input, rich fields w/ list/other, nested dict/list,
    sensitive string keys
  - is_sensitive_value: credit-card non-Luhn continue
  - list_redaction_matches: non-str input, callable replacement, cc skip
  - RedactingStreamWrapper: fileno / isatty / writable / readable fallbacks
"""

import io
import json
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redact import (
    RedactingStreamWrapper,
    _luhn_check,
    is_sensitive_value,
    list_redaction_matches,
    redact_ai_payload,
    redact_dict,
    redact_json,
    redact_list,
    redact_log_line,
    redact_report,
    redact_string,
)


class TestLuhnGaps:
    def test_short_digit_count_returns_false(self):
        # Only 12 digits after stripping separators → < 13 → False
        assert _luhn_check("1234 5678 9012 3") is False

    def test_empty_returns_false(self):
        assert _luhn_check("") is False


class TestRedactDictListGaps:
    def test_dict_non_dict_input_returns_input(self):
        assert redact_dict("not a dict") == "not a dict"

    def test_list_non_list_input_returns_input(self):
        assert redact_list("not a list") == "not a list"

    def test_list_max_depth_zero_returns_input(self):
        lst = ["sk-123456789012345678901234"]
        assert redact_list(lst, max_depth=0) is lst

    def test_list_nested_and_other_types(self):
        result = redact_list(
            ["a", {"key": "sk-123456789012345678901234"}, [1, 2], 42]
        )
        assert result[0] == "a"
        assert "[OPENAI_KEY]" in result[1]["key"]
        assert result[2] == [1, 2]
        assert result[3] == 42


class TestRedactJsonGaps:
    def test_non_str_returns_empty(self):
        assert redact_json(123) == ""

    def test_json_list_redacts(self):
        out = redact_json('[1, "sk-123456789012345678901234", {"x": 2}]')
        parsed = json.loads(out)
        assert "[OPENAI_KEY]" in parsed[1]

    def test_json_primitive_round_trip(self):
        assert json.loads(redact_json("42")) == 42

    def test_empty_string_returns_empty(self):
        assert redact_json("") == ""


class TestRedactLogLineGaps:
    def test_non_str_returns_empty(self):
        assert redact_log_line(123) == ""


class TestRedactAiPayloadGaps:
    def test_non_list_returns_empty(self):
        assert redact_ai_payload("not a list") == []

    def test_non_dict_items_passed_through(self):
        out = redact_ai_payload([42, "hello"])
        assert out == [42, "hello"]

    def test_tool_calls_arguments_redacted(self):
        out = redact_ai_payload(
            [{
                "role": "assistant",
                "tool_calls": {"arguments": '{"password": "sk-123456789012345678901234"}'},
            }]
        )
        assert '"password"' in out[0]["tool_calls"]["arguments"]
        assert "sk-123456789012345678901234" not in out[0]["tool_calls"]["arguments"]

    def test_function_call_arguments_redacted(self):
        out = redact_ai_payload(
            [{
                "role": "assistant",
                "function_call": {"arguments": '{"api_key": "AKIA1234567890ABCDEF"}'},
            }]
        )
        assert "AKIA1234567890ABCDEF" not in out[0]["function_call"]["arguments"]

    def test_non_str_arguments_left_alone(self):
        out = redact_ai_payload(
            [{"role": "assistant", "tool_calls": {"arguments": {"a": 1}}}]
        )
        assert out[0]["tool_calls"]["arguments"] == {"a": 1}


class TestRedactReportGaps:
    def test_non_dict_returns_input(self):
        assert redact_report("nope") == "nope"

    def test_rich_field_list_and_other(self):
        out = redact_report({"detail": [1, 2], "raw": 42})
        assert out["detail"] == [1, 2]
        assert out["raw"] == 42

    def test_nested_dict_redacted(self):
        out = redact_report({"meta": {"password": "sk-123456789012345678901234"}})
        assert "sk-123456789012345678901234" not in out["meta"]["password"]

    def test_nested_list_redacted(self):
        out = redact_report({"meta": ["sk-123456789012345678901234"]})
        assert "[OPENAI_KEY]" in out["meta"][0]

    def test_sensitive_string_key_redacted(self):
        out = redact_report(
            {"password": "sk-123456789012345678901234", "secret": "AKIA1234567890ABCDEF"}
        )
        assert "[OPENAI_KEY]" in out["password"]
        assert "[AWS_KEY]" in out["secret"]

    def test_non_sensitive_scalar_preserved(self):
        out = redact_report({"title": "Scan report", "severity": "high"})
        assert out["title"] == "Scan report"
        assert out["severity"] == "high"


class TestIsSensitiveGaps:
    def test_credit_card_non_luhn_returns_false(self):
        # Matches the card regex but fails Luhn → pattern skipped
        assert is_sensitive_value("1234 5678 9012 3") is False


class TestListRedactionMatchesGaps:
    def test_non_str_returns_empty(self):
        assert list_redaction_matches(123) == []

    def test_callable_replacement_used(self):
        hits = list_redaction_matches("4111 1111 1111 1111")
        assert any(h["pattern_index"] == len(__import__("redact").REDACT_PATTERNS) - 1
                   for h in hits)
        assert any(h["replacement"] == "[CREDIT_CARD]" for h in hits)

    def test_non_luhn_card_skipped(self):
        hits = list_redaction_matches("1234 5678 9012 3")
        assert not any("CREDIT_CARD" in h["replacement"] for h in hits)


class TestStreamWrapperGaps:
    class _FullStream:
        def write(self, msg):
            return len(msg)

        def flush(self):
            pass

        def close(self):
            pass

        def fileno(self):
            return 42

        def isatty(self):
            return False

        def writable(self):
            return True

        def readable(self):
            return False

    class _MinimalStream:
        def write(self, msg):
            return len(msg)

    def test_fileno_delegates(self):
        w = RedactingStreamWrapper(self._FullStream())
        assert w.fileno() == 42

    def test_isatty_delegates(self):
        w = RedactingStreamWrapper(self._FullStream())
        assert w.isatty() is False

    def test_writable_delegates(self):
        w = RedactingStreamWrapper(self._FullStream())
        assert w.writable() is True

    def test_readable_delegates(self):
        w = RedactingStreamWrapper(self._FullStream())
        assert w.readable() is False

    def test_fallbacks_without_attrs(self):
        w = RedactingStreamWrapper(self._MinimalStream())
        assert w.isatty() is False
        assert w.writable() is True
        assert w.readable() is False
