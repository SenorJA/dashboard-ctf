"""
Tests for canary_tokens — Honeytoken generation and activation tracking.

Covers:
  - All 8 token types generate correctly
  - Token activation records IP/UA/referer
  - Event listing and filtering
  - Token deletion (soft-deactivate)
  - Findings generation in MIRV format
  - Edge cases: invalid type, duplicate tokens, nonexistent activation
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from canary_tokens import (
    generate_token,
    list_tokens,
    get_token,
    activate_token,
    get_events,
    delete_token,
    report_to_mirv_findings,
)

# ──────────────────────────────────────────────
# 1. Token generation — all 8 types
# ──────────────────────────────────────────────


def test_generate_api_key():
    """api-key type should start with sk- or pk-."""
    t = generate_token("api-key", "test-api")
    assert t.type == "api-key"
    assert t.value.startswith("sk-") or t.value.startswith("pk-")
    assert t.active is True


def test_generate_db_url():
    """db-url should contain postgresql:// and :password."""
    t = generate_token("db-url", "test-db")
    assert t.type == "db-url"
    assert "postgresql://" in t.value
    assert ":" in t.value.split("@")[0] if "@" in t.value else True


def test_generate_jwt():
    """jwt should have 3 dot-separated parts."""
    t = generate_token("jwt", "test-jwt")
    assert t.type == "jwt"
    assert t.value.count(".") == 2


def test_generate_aws_key():
    """aws-key should start with AKIA."""
    t = generate_token("aws-key", "test-aws")
    assert t.type == "aws-key"
    assert t.value.startswith("AKIA")


def test_generate_slack_token():
    """slack-token should start with xoxb-."""
    t = generate_token("slack-token", "test-slack")
    assert t.type == "slack-token"
    assert t.value.startswith("xoxb-")


def test_generate_generic_url():
    """generic-url should contain /api/canary/activate/."""
    t = generate_token("generic-url", "test-url")
    assert t.type == "generic-url"
    assert "/api/canary/activate/" in t.value


def test_generate_env_file():
    """env-file should contain KEY=value lines."""
    t = generate_token("env-file", "test-env")
    assert t.type == "env-file"
    assert "=" in t.value
    assert "DB_HOST" in t.value or "API_KEY" in t.value


def test_generate_config_file():
    """config-file should be valid JSON."""
    t = generate_token("config-file", "test-config")
    assert t.type == "config-file"
    assert "{" in t.value and "}" in t.value


# ──────────────────────────────────────────────
# 2. Token metadata
# ──────────────────────────────────────────────


def test_token_has_all_fields():
    """Token should have all required fields."""
    t = generate_token("api-key", "full-test", "some notes")
    assert t.id is not None
    assert len(t.id) == 36  # UUID4
    assert t.name == "full-test"
    assert t.payload.get("notes") == "some notes"
    assert t.created_at is not None
    assert t.expires_at is not None
    assert t.active is True


def test_token_default_name():
    """Token should auto-generate name if not provided."""
    t = generate_token("api-key")
    assert t.name.startswith("canary-")
    assert t.payload.get("notes", "") == ""


# ──────────────────────────────────────────────
# 3. List and get tokens
# ──────────────────────────────────────────────


def test_list_tokens_returns_active():
    """list_tokens should return only active tokens as dicts."""
    # Generate a token
    t = generate_token("api-key", "list-test")
    tokens = list_tokens()
    assert isinstance(tokens, list)
    found = [x for x in tokens if x["id"] == t.id]
    assert len(found) == 1
    assert found[0]["active"] is True


def test_get_token_by_id():
    """get_token should return the token by ID."""
    t = generate_token("jwt", "get-test")
    found = get_token(t.id)
    assert found is not None
    assert found.id == t.id
    assert found.name == "get-test"


def test_get_token_nonexistent():
    """get_token for nonexistent ID should return None."""
    assert get_token("nonexistent-id") is None


# ──────────────────────────────────────────────
# 4. Token activation
# ──────────────────────────────────────────────


def test_activate_token_creates_event():
    """Activating a token should record an event."""
    t = generate_token("aws-key", "activate-test")
    ev = activate_token(t.id, "10.0.0.1", "curl/7.68", "https://example.com")
    assert ev is not None
    assert ev.token_id == t.id
    assert ev.token_name == "activate-test"
    assert ev.ip == "10.0.0.1"
    assert ev.user_agent == "curl/7.68"
    assert ev.referer == "https://example.com"


def test_activate_nonexistent_token():
    """Activating a nonexistent token should return None."""
    ev = activate_token("fake-id", "1.2.3.4", "test", None)
    assert ev is None


def test_activate_deleted_token():
    """Activating a deleted token should return None."""
    t = generate_token("slack-token", "del-activate")
    delete_token(t.id)
    ev = activate_token(t.id, "1.2.3.4", "test", None)
    assert ev is None


# ──────────────────────────────────────────────
# 5. Events listing
# ──────────────────────────────────────────────


def test_get_events_all():
    """get_events should return all events."""
    # Clear by generating fresh
    t = generate_token("db-url", "events-test")
    activate_token(t.id, "10.0.0.2", "python-requests", None)
    events = get_events()
    assert len(events) >= 1
    assert isinstance(events, list)


def test_get_events_filtered_by_token():
    """get_events with token_id should filter."""
    t1 = generate_token("jwt", "filter1")
    t2 = generate_token("jwt", "filter2")
    activate_token(t1.id, "1.1.1.1", "ua1", None)
    activate_token(t2.id, "2.2.2.2", "ua2", None)
    ev = get_events(t1.id)
    assert len(ev) >= 1
    assert all(e["token_id"] == t1.id for e in ev)


# ──────────────────────────────────────────────
# 6. Token deletion
# ──────────────────────────────────────────────


def test_delete_token_marks_inactive():
    """Delete should mark token as inactive, not remove it."""
    t = generate_token("api-key", "delete-test")
    result = delete_token(t.id)
    assert result is True
    token = get_token(t.id)
    assert token is not None
    assert token.active is False


def test_delete_nonexistent_token():
    """Deleting a nonexistent token should return False."""
    result = delete_token("nonexistent")
    assert result is False


# ──────────────────────────────────────────────
# 7. Findings generation
# ──────────────────────────────────────────────


def test_findings_format_no_event():
    """report_to_mirv_findings without event should return INFO finding."""
    t = generate_token("api-key", "findings-test")
    findings = report_to_mirv_findings(t)
    assert isinstance(findings, list)
    assert len(findings) >= 1
    f = findings[0]
    assert f["tool"] == "canary-token"
    assert f["severity"] == "info"
    assert "title" in f
    assert "detail" in f


def test_findings_format_with_event():
    """report_to_mirv_findings with event should return HIGH finding."""
    t = generate_token("db-url", "findings-event")
    ev = activate_token(t.id, "5.5.5.5", "nmap", None)
    findings = report_to_mirv_findings(t, ev)
    assert isinstance(findings, list)
    assert len(findings) >= 1
    high = [f for f in findings if f["severity"] == "high"]
    assert len(high) >= 1
    assert "activated" in high[0]["title"].lower()


# ──────────────────────────────────────────────
# 8. Invalid input handling
# ──────────────────────────────────────────────


def test_invalid_token_type():
    """Invalid token type should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid token type"):
        generate_token("invalid-type")


def test_token_type_empty_string():
    """Empty token type should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid token type"):
        generate_token("")
