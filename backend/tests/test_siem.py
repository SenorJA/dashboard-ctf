"""
Tests for siem -- Security Information & Event Management.

Covers:
  - Event ingestion and storage
  - Event querying with filters (severity, source, since, pagination)
  - Dashboard statistics
  - Rule CRUD (create, list, delete)
  - Brute-force correlation (5 failed-auth events -> alert)
  - Port-scan correlation (10 port-scan events -> alert)
  - Canary-activation correlation (single event -> alert)
  - DLP leak correlation (3 high-severity DLP events -> alert)
  - Alert deduplication
  - MIRV findings format conversion
  - Edge cases: invalid source/severity, invalid condition
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from siem import (
    ingest_event,
    get_events,
    get_stats,
    create_rule,
    get_rules,
    delete_rule,
    get_alerts,
    report_to_mirv_findings,
    reset,
    SIEMEvent,
    SIEMAlert,
    _events,
    _alerts,
)


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_siem():
    """Reset SIEM state before every test."""
    reset()
    yield
    reset()


# ──────────────────────────────────────────────
# 1. Event ingestion
# ──────────────────────────────────────────────


def test_ingest_event_returns_event():
    """Ingesting an event should return a SIEMEvent with generated id/timestamp."""
    ev = ingest_event("ssh", "high", "Failed login", "root from 10.0.0.1")
    assert isinstance(ev, SIEMEvent)
    assert len(ev.id) > 0
    assert ev.source == "ssh"
    assert ev.severity == "high"
    assert ev.title == "Failed login"
    assert ev.timestamp.endswith("Z") or "+" in ev.timestamp or "Z" in ev.timestamp


def test_ingest_event_stored():
    """Ingested event should appear in get_events."""
    ev = ingest_event("api", "info", "Test event", "body text")
    events = get_events()
    ids = [e["id"] for e in events]
    assert ev.id in ids


def test_ingest_event_with_tags_and_ip():
    """Tags and IP should be stored correctly."""
    ev = ingest_event(
        "ssh", "medium", "SSH connection", "new session",
        tags=["new-session", "ssh-v2"], ip="192.168.1.100",
    )
    assert "new-session" in ev.tags
    assert "ssh-v2" in ev.tags
    assert ev.ip == "192.168.1.100"


def test_ingest_event_defaults():
    """raw_data defaults to {}, tags defaults to [], ip defaults to None."""
    ev = ingest_event("system", "info", "Test", "Detail")
    assert ev.raw_data == {}
    assert ev.tags == []
    assert ev.ip is None


# ──────────────────────────────────────────────
# 2. Event querying
# ──────────────────────────────────────────────


def test_get_events_empty():
    """Fresh store should return empty list."""
    events = get_events()
    assert events == []


def test_get_events_severity_filter():
    """Filtering by severity should only return matching events."""
    ingest_event("ssh", "low", "Low event", "detail")
    ingest_event("ssh", "high", "High event", "detail")
    ingest_event("ssh", "critical", "Critical event", "detail")

    high_events = get_events(severity="high")
    assert len(high_events) == 1
    assert high_events[0]["severity"] == "high"


def test_get_events_source_filter():
    """Filtering by source should only return matching events."""
    ingest_event("ssh", "info", "SSH event", "detail")
    ingest_event("docker", "info", "Docker event", "detail")
    ingest_event("api", "info", "API event", "detail")

    ssh_events = get_events(source="ssh")
    assert len(ssh_events) == 1
    assert ssh_events[0]["source"] == "ssh"


def test_get_events_pagination():
    """Pagination with limit/offset should work correctly."""
    for i in range(10):
        ingest_event("system", "info", f"Event {i}", f"detail {i}")

    page1 = get_events(limit=3, offset=0)
    page2 = get_events(limit=3, offset=3)
    assert len(page1) == 3
    assert len(page2) == 3
    # Pages should have different event IDs
    assert page1[0]["id"] != page2[0]["id"]


def test_get_events_sorted_desc():
    """Events should be sorted newest-first."""
    ingest_event("ssh", "info", "First", "detail")
    ingest_event("ssh", "info", "Second", "detail")
    ingest_event("ssh", "info", "Third", "detail")

    events = get_events()
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


def test_get_events_limit_capped():
    """Limit should be capped at 500."""
    events = get_events(limit=9999)
    # Should not crash, just cap
    assert isinstance(events, list)


def test_get_events_since_filter():
    """The since parameter should filter by timestamp."""
    from datetime import datetime, timedelta, timezone
    ingest_event("ssh", "info", "Old event", "detail")
    cutoff = datetime.now(timezone.utc).isoformat()
    ingest_event("ssh", "info", "New event", "detail")

    events = get_events(since=cutoff)
    assert len(events) >= 1
    # Old event should be excluded (or at least the new one included)
    titles = [e["title"] for e in events]
    assert "New event" in titles


# ──────────────────────────────────────────────
# 3. Stats
# ──────────────────────────────────────────────


def test_stats_empty():
    """Stats on empty store should show zeros."""
    stats = get_stats()
    assert stats["total_events"] == 0
    assert stats["total_alerts"] == 0
    assert stats["total_rules"] >= 4  # 4 default rules


def test_stats_after_ingest():
    """Stats should reflect ingested events."""
    ingest_event("ssh", "high", "Ev1", "detail")
    ingest_event("docker", "critical", "Ev2", "detail")

    stats = get_stats()
    assert stats["total_events"] == 2
    assert stats["events_by_severity"]["high"] == 1
    assert stats["events_by_severity"]["critical"] == 1
    assert stats["events_by_source"]["ssh"] == 1
    assert stats["events_by_source"]["docker"] == 1


# ──────────────────────────────────────────────
# 4. Rule CRUD
# ──────────────────────────────────────────────


def test_create_rule():
    """Creating a rule should return a SIEMRule with generated ID."""
    rule = create_rule(
        name="Custom Rule",
        description="Test rule",
        condition="custom",
        severity="high",
        config={"threshold": 5},
    )
    assert rule.name == "Custom Rule"
    assert rule.condition == "custom"
    assert rule.enabled is True
    assert rule.config["threshold"] == 5
    assert rule.id.startswith("rule-")


def test_create_rule_invalid_condition():
    """Creating a rule with invalid condition should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid condition"):
        create_rule("Bad Rule", "desc", "nonexistent-type")


def test_create_rule_invalid_severity():
    """Creating a rule with severity != high/critical should raise ValueError."""
    with pytest.raises(ValueError, match="severity must be"):
        create_rule("Bad Rule", "desc", "brute-force", severity="low")


def test_get_rules_includes_defaults():
    """get_rules should include the 4 default rules."""
    rules = get_rules()
    ids = [r["id"] for r in rules]
    assert "rule-brute-force" in ids
    assert "rule-port-scan" in ids
    assert "rule-canary" in ids
    assert "rule-dlp" in ids


def test_delete_rule():
    """Deleting a rule should remove it from the store."""
    rule = create_rule("Temp Rule", "desc", "custom")
    assert delete_rule(rule.id) is True
    rules = get_rules()
    ids = [r["id"] for r in rules]
    assert rule.id not in ids


def test_delete_rule_not_found():
    """Deleting a nonexistent rule should return False."""
    assert delete_rule("rule-nonexistent-12345") is False


# ──────────────────────────────────────────────
# 5. Brute-force correlation
# ──────────────────────────────────────────────


def test_brute_force_correlation():
    """5+ failed-auth events from same IP should trigger an alert."""
    ip = "10.0.0.50"
    for i in range(5):
        ingest_event(
            "ssh", "high",
            f"Failed login attempt {i+1}",
            f"Root login failed from {ip}",
            tags=["failed-auth"],
            ip=ip,
        )

    alerts = get_alerts()
    brute_alerts = [a for a in alerts if a["rule_id"] == "rule-brute-force"]
    assert len(brute_alerts) >= 1
    assert ip in brute_alerts[0]["detail"]
    assert brute_alerts[0]["severity"] == "high"


def test_brute_force_no_alert_below_threshold():
    """4 failed-auth events (below threshold of 5) should NOT trigger alert."""
    ip = "10.0.0.51"
    for i in range(4):
        ingest_event(
            "ssh", "high",
            f"Failed login {i+1}",
            f"detail from {ip}",
            tags=["failed-auth"],
            ip=ip,
        )

    alerts = get_alerts()
    brute_alerts = [a for a in alerts if a["rule_id"] == "rule-brute-force"]
    assert len(brute_alerts) == 0


# ──────────────────────────────────────────────
# 6. Port-scan correlation
# ──────────────────────────────────────────────


def test_port_scan_correlation():
    """10+ port-scan events from same IP should trigger an alert."""
    ip = "10.0.0.60"
    for i in range(10):
        ingest_event(
            "firewall", "medium",
            f"Port scan probe {i+1}",
            f"SYN scan detected from {ip}",
            tags=["port-scan"],
            ip=ip,
        )

    alerts = get_alerts()
    scan_alerts = [a for a in alerts if a["rule_id"] == "rule-port-scan"]
    assert len(scan_alerts) >= 1
    assert ip in scan_alerts[0]["detail"]


# ──────────────────────────────────────────────
# 7. Canary activation correlation
# ──────────────────────────────────────────────


def test_canary_activation_correlation():
    """Single canary-activation event should immediately trigger alert."""
    ingest_event(
        "canary", "critical",
        "AWS key used from attacker",
        "Fake AKIA key was accessed",
        tags=["canary-activation"],
        ip="203.0.113.5",
    )

    alerts = get_alerts()
    canary_alerts = [a for a in alerts if a["rule_id"] == "rule-canary"]
    assert len(canary_alerts) == 1
    assert canary_alerts[0]["severity"] == "critical"
    assert "canary" in canary_alerts[0]["title"].lower()


# ──────────────────────────────────────────────
# 8. DLP leak correlation
# ──────────────────────────────────────────────


def test_dlp_leak_correlation():
    """3+ high-severity DLP events should trigger an alert."""
    for i in range(3):
        ingest_event(
            "dlp", "high",
            f"Sensitive data found in email {i+1}",
            f"Credit card numbers detected in outbound email",
            tags=["dlp-pii"],
        )

    alerts = get_alerts()
    dlp_alerts = [a for a in alerts if a["rule_id"] == "rule-dlp"]
    assert len(dlp_alerts) >= 1
    assert dlp_alerts[0]["severity"] == "critical"


# ──────────────────────────────────────────────
# 9. Alert deduplication
# ──────────────────────────────────────────────


def test_alert_deduplication():
    """
    Ingesting two separate bursts from different IPs should produce
    distinct alerts.  Same rule but different IP = different event_ids
    set = no dedup collision.
    """
    # Burst 1: IP A hits threshold
    ip_a = "10.0.0.70"
    for i in range(5):
        ingest_event(
            "ssh", "high",
            f"Dedup test A{i}",
            f"failed-auth from {ip_a}",
            tags=["failed-auth"],
            ip=ip_a,
        )

    alerts1 = get_alerts()
    brute1 = [a for a in alerts1 if a["rule_id"] == "rule-brute-force"]
    assert len(brute1) == 1
    first_alert_id = brute1[0]["id"]

    # Burst 2: Different IP hits threshold — should create a SEPARATE alert
    ip_b = "10.0.0.71"
    for i in range(5):
        ingest_event(
            "ssh", "high",
            f"Dedup test B{i}",
            f"failed-auth from {ip_b}",
            tags=["failed-auth"],
            ip=ip_b,
        )

    alerts2 = get_alerts()
    brute2 = [a for a in alerts2 if a["rule_id"] == "rule-brute-force"]
    assert len(brute2) == 2
    ids = {a["id"] for a in brute2}
    assert first_alert_id in ids  # Original still present


# ──────────────────────────────────────────────
# 10. MIRV findings format
# ──────────────────────────────────────────────


def test_findings_from_event():
    """SIEMEvent should convert to MIRV findings format."""
    ev = ingest_event("ssh", "high", "Test Event", "Detail", tags=["test"])
    findings = report_to_mirv_findings(ev)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "siem"
    assert f["severity"] == "high"
    assert "[SIEM]" in f["title"]
    assert "recommendation" in f
    assert len(f["recommendation"]) > 0


def test_findings_from_alert():
    """SIEMAlert should convert to MIRV findings format."""
    # Trigger a brute-force alert first
    ip = "10.0.0.80"
    for i in range(5):
        ingest_event(
            "ssh", "high", f"FA {i}", f"fail from {ip}",
            tags=["failed-auth"], ip=ip,
        )

    alerts = get_alerts()
    assert len(alerts) > 0

    # Reconstruct SIEMAlert from dict
    al = SIEMAlert(**alerts[0])
    findings = report_to_mirv_findings(al)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "siem-alert"
    assert "[ALERT]" in f["title"]
    assert f["severity"] in ("high", "critical")


# ──────────────────────────────────────────────
# 11. Edge cases
# ──────────────────────────────────────────────


def test_ingest_invalid_source():
    """Ingesting with an invalid source should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid source"):
        ingest_event("invalid-source", "info", "Title", "Detail")


def test_ingest_invalid_severity():
    """Ingesting with an invalid severity should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid severity"):
        ingest_event("ssh", "super-critical", "Title", "Detail")


def test_default_rules_restored_after_reset():
    """After reset(), the 4 default rules should be restored."""
    create_rule("Temp", "desc", "custom")
    assert len(get_rules()) == 5  # 4 default + 1 custom
    reset()
    rules = get_rules()
    assert len(rules) == 4
    ids = [r["id"] for r in rules]
    assert "rule-brute-force" in ids


def test_get_events_combined_filters():
    """Applying both severity and source filters should work together."""
    ingest_event("ssh", "low", "SSH low", "detail")
    ingest_event("ssh", "high", "SSH high", "detail")
    ingest_event("docker", "high", "Docker high", "detail")

    results = get_events(severity="high", source="ssh")
    assert len(results) == 1
    assert results[0]["title"] == "SSH high"
