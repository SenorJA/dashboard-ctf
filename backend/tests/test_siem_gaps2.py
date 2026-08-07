"""
Coverage-gap tests for backend/siem.py.

Covers error/edge branches in the correlation rule checkers and alert
deduplication that the main suite does not exercise.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import backend.siem as siem
from backend.siem import (
    SIEMAlert,
    SIEMEvent,
    SIEMRule,
    ingest_event,
    reset,
    _run_correlations,
    _create_alert,
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _old(seconds=3600):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


def _rule(rule_id="r-custom", condition="custom"):
    return SIEMRule(id=rule_id, name="R", description="d",
                    condition=condition, severity="high")


def _ev(event_id, ip=None, tags=None, severity="high", source="ssh",
        timestamp=None, detail=""):
    return SIEMEvent(
        id=event_id,
        timestamp=timestamp or _now(),
        source=source,
        severity=severity,
        title="t",
        detail=detail,
        raw_data={},
        tags=tags or [],
        ip=ip,
    )


def test_run_correlations_handles_rule_error():
    reset()
    with patch("backend.siem._check_rule", side_effect=RuntimeError("boom")):
        ev = ingest_event("ssh", "medium", "t", "d")
    # Event still ingested despite correlation failure.
    assert ev.id in siem._events


class TestBruteForce:
    def test_missing_ip_returns(self):
        reset()
        ingest_event("ssh", "medium", "t", "d", tags=["failed-auth"], ip=None)

    def test_non_matching_tag_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", ip="10.0.0.1", tags=["other"])
        ingest_event("ssh", "medium", "t", "d", tags=["failed-auth"], ip="10.0.0.1")

    def test_invalid_timestamp_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", ip="10.0.0.1", tags=["failed-auth"],
                                 timestamp="not-a-date")
        ingest_event("ssh", "medium", "t", "d", tags=["failed-auth"], ip="10.0.0.1")


class TestPortScan:
    def test_missing_ip_returns(self):
        reset()
        ingest_event("firewall", "high", "t", "d", tags=["port-scan"], ip=None)

    def test_different_ip_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", ip="10.0.0.2", tags=["port-scan"])
        ingest_event("firewall", "high", "t", "d", tags=["port-scan"], ip="10.0.0.1")

    def test_missing_tag_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", ip="10.0.0.1", tags=["other"])
        ingest_event("firewall", "high", "t", "d", tags=["port-scan"], ip="10.0.0.1")

    def test_invalid_timestamp_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", ip="10.0.0.1", tags=["port-scan"],
                                 timestamp="not-a-date")
        ingest_event("firewall", "high", "t", "d", tags=["port-scan"], ip="10.0.0.1")


class TestDlpLeak:
    def test_non_high_severity_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", source="dlp", severity="low")
        ingest_event("dlp", "high", "t", "d")

    def test_invalid_timestamp_skipped(self):
        reset()
        siem._events["p1"] = _ev("p1", source="dlp", severity="high",
                                 timestamp="not-a-date")
        ingest_event("dlp", "high", "t", "d")


class TestCreateAlertDedupe:
    def test_different_rule_continues(self):
        reset()
        siem._alerts["a1"] = SIEMAlert(
            id="a1", rule_name="R1", rule_id="r1", severity="high",
            title="t", detail="d", timestamp=_now(), event_ids=["e1"],
        )
        _create_alert(rule=_rule("r2"), title="x", detail="y", event_ids=["e1"])
        assert len(siem._alerts) == 2  # a new alert was created

    def test_duplicate_skipped(self):
        reset()
        siem._alerts["a1"] = SIEMAlert(
            id="a1", rule_name="R", rule_id="r2", severity="high",
            title="t", detail="d", timestamp=_now(), event_ids=["e1"],
        )
        _create_alert(rule=_rule("r2"), title="x", detail="y", event_ids=["e1"])
        assert len(siem._alerts) == 1  # duplicate skipped

    def test_duplicate_invalid_timestamp_creates(self):
        reset()
        siem._alerts["a1"] = SIEMAlert(
            id="a1", rule_name="R", rule_id="r2", severity="high",
            title="t", detail="d", timestamp="not-a-date", event_ids=["e1"],
        )
        _create_alert(rule=_rule("r2"), title="x", detail="y", event_ids=["e1"])
        assert len(siem._alerts) == 2  # invalid timestamp -> not treated as dup
