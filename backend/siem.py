"""
siem.py -- MIRV Module

Lightweight SIEM (Security Information and Event Management) engine.

Stores security events in memory, runs correlation rules against incoming
events, and generates high-priority alerts when thresholds are exceeded.
Designed for real-time telemetry from the SSH proxy, Docker, canary tokens,
DLP scanner, firewall, and API layers.

Correlation rules shipped out-of-the-box:
  - Brute-force detection  (threshold on failed-auth events per IP)
  - Port-scan detection   (threshold on port-scan events per IP)
  - Canary token trigger  (single-event alert on canary activation)
  - DLP data-leak alert   (threshold on high-severity DLP events)

All functions are synchronous and thread-safe (module-level lock).
"""

import uuid
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

# ── Logger ──
logger = logging.getLogger("vulnforge.siem")


# ════════════════════════════════════════════════════════════════
#  Data classes
# ════════════════════════════════════════════════════════════════

@dataclass
class SIEMEvent:
    """A single security event ingested into the SIEM."""
    id: str
    timestamp: str           # ISO format with timezone
    source: str              # ssh | docker | api | canary | dlp | firewall | system
    severity: str            # info | low | medium | high | critical
    title: str
    detail: str
    raw_data: dict           # Original event payload
    tags: list[str]          # Freeform tags for correlation
    ip: str | None = None    # Source IP if applicable


@dataclass
class SIEMAlert:
    """A correlation alert triggered by one or more events."""
    id: str
    rule_name: str           # Which rule triggered
    rule_id: str
    severity: str            # high | critical
    title: str
    detail: str
    timestamp: str
    event_ids: list[str]     # Events that triggered this alert
    resolved: bool = False


@dataclass
class SIEMRule:
    """A correlation rule that inspects incoming events."""
    id: str
    name: str
    description: str
    condition: str           # brute-force | port-scan | canary-trigger | dlp-leak | custom
    severity: str            # high | critical
    enabled: bool = True
    config: dict = field(default_factory=dict)  # e.g. {"threshold": 5, "window_seconds": 60}


# ════════════════════════════════════════════════════════════════
#  In-memory store
# ════════════════════════════════════════════════════════════════

_events: dict[str, SIEMEvent] = {}
_alerts: dict[str, SIEMAlert] = {}
_rules: dict[str, SIEMRule] = {}
_lock = threading.Lock()


# ════════════════════════════════════════════════════════════════
#  Predefined rules (auto-created on import)
# ════════════════════════════════════════════════════════════════

_default_rules: list[SIEMRule] = [
    SIEMRule(
        id="rule-brute-force",
        name="Brute Force Detection",
        description="Detects repeated failed authentication attempts from a single IP within a time window.",
        condition="brute-force",
        severity="high",
        enabled=True,
        config={"threshold": 5, "window_seconds": 60},
    ),
    SIEMRule(
        id="rule-port-scan",
        name="Port Scan Detection",
        description="Detects rapid port scanning activity from a single IP.",
        condition="port-scan",
        severity="high",
        enabled=True,
        config={"threshold": 10, "window_seconds": 30},
    ),
    SIEMRule(
        id="rule-canary",
        name="Canary Token Triggered",
        description="Immediate alert when a planted canary token is accessed or used.",
        condition="canary-trigger",
        severity="critical",
        enabled=True,
        config={},
    ),
    SIEMRule(
        id="rule-dlp",
        name="DLP Data Leak",
        description="Detects bursts of high-severity DLP findings indicating data exfiltration.",
        condition="dlp-leak",
        severity="critical",
        enabled=True,
        config={"threshold": 3, "window_seconds": 300},
    ),
]


def _init_default_rules() -> None:
    """Seed the rules dict with defaults (called once on import)."""
    with _lock:
        for rule in _default_rules:
            if rule.id not in _rules:
                _rules[rule.id] = rule


_init_default_rules()


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

_VALID_SOURCES = {"ssh", "docker", "api", "canary", "dlp", "firewall", "system"}
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_CONDITIONS = {"brute-force", "port-scan", "canary-trigger", "dlp-leak", "custom"}

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _now_iso() -> str:
    """Current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _event_to_dict(ev: SIEMEvent) -> dict:
    """Serialize an event to a JSON-safe dict."""
    return asdict(ev)


def _alert_to_dict(al: SIEMAlert) -> dict:
    """Serialize an alert to a JSON-safe dict."""
    return asdict(al)


def _rule_to_dict(r: SIEMRule) -> dict:
    """Serialize a rule to a JSON-safe dict."""
    return asdict(r)


# ════════════════════════════════════════════════════════════════
#  Core: Ingest
# ════════════════════════════════════════════════════════════════

def ingest_event(
    source: str,
    severity: str,
    title: str,
    detail: str,
    raw_data: dict | None = None,
    tags: list[str] | None = None,
    ip: str | None = None,
) -> SIEMEvent:
    """
    Ingest a security event into the SIEM.

    1. Validate source and severity.
    2. Generate a UUID and timestamp.
    3. Store the event.
    4. Run correlation rules against recent events.
    5. Return the event.

    Raises ValueError on invalid source/severity.
    """
    source = source.lower().strip()
    severity = severity.lower().strip()

    if source not in _VALID_SOURCES:
        raise ValueError(
            f"Invalid source '{source}'. Must be one of: {', '.join(sorted(_VALID_SOURCES))}"
        )
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    event = SIEMEvent(
        id=str(uuid.uuid4()),
        timestamp=_now_iso(),
        source=source,
        severity=severity,
        title=title,
        detail=detail,
        raw_data=raw_data or {},
        tags=list(tags) if tags else [],
        ip=ip,
    )

    with _lock:
        _events[event.id] = event

    logger.info(
        "SIEM event ingested: id=%s src=%s sev=%s title=%s",
        event.id[:8], source, severity, title,
    )

    # Run correlations (outside lock to avoid deadlocks)
    _run_correlations(event)

    return event


# ════════════════════════════════════════════════════════════════
#  Core: Query Events
# ════════════════════════════════════════════════════════════════

def get_events(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    source: str | None = None,
    since: str | None = None,
) -> list[dict]:
    """
    Retrieve events with optional filtering.

    Args:
        limit:    Max events to return (default 50, max 500).
        offset:   Pagination offset.
        severity: Filter by exact severity level.
        source:   Filter by exact source.
        since:    ISO timestamp — only return events after this time.

    Returns:
        List of event dicts sorted by timestamp descending.
    """
    limit = min(max(limit, 1), 500)

    with _lock:
        candidates = list(_events.values())

    # Filter by severity
    if severity:
        severity = severity.lower().strip()
        candidates = [e for e in candidates if e.severity == severity]

    # Filter by source
    if source:
        source = source.lower().strip()
        candidates = [e for e in candidates if e.source == source]

    # Filter by timestamp
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            candidates = [
                e for e in candidates
                if datetime.fromisoformat(e.timestamp) >= since_dt
            ]
        except (ValueError, TypeError):
            pass  # ignore invalid since parameter

    # Sort by timestamp descending
    candidates.sort(key=lambda e: e.timestamp, reverse=True)

    # Paginate
    return [_event_to_dict(e) for e in candidates[offset: offset + limit]]


# ════════════════════════════════════════════════════════════════
#  Core: Stats
# ════════════════════════════════════════════════════════════════

def get_stats() -> dict:
    """
    Return aggregate SIEM statistics for the dashboard.

    Keys:
      - total_events
      - events_by_severity
      - events_by_source
      - total_alerts
      - unacknowledged_alerts
      - total_rules
      - enabled_rules
    """
    with _lock:
        all_events = list(_events.values())
        all_alerts = list(_alerts.values())
        all_rules = list(_rules.values())

    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}

    for ev in all_events:
        severity_counts[ev.severity] = severity_counts.get(ev.severity, 0) + 1
        source_counts[ev.source] = source_counts.get(ev.source, 0) + 1

    return {
        "total_events": len(all_events),
        "events_by_severity": severity_counts,
        "events_by_source": source_counts,
        "total_alerts": len(all_alerts),
        "unacknowledged_alerts": sum(1 for a in all_alerts if not a.resolved),
        "total_rules": len(all_rules),
        "enabled_rules": sum(1 for r in all_rules if r.enabled),
    }


# ════════════════════════════════════════════════════════════════
#  Core: Rules CRUD
# ════════════════════════════════════════════════════════════════

def create_rule(
    name: str,
    description: str,
    condition: str,
    severity: str = "high",
    config: dict | None = None,
) -> SIEMRule:
    """
    Create a new correlation rule.

    Raises ValueError if condition is not a supported type.
    """
    condition = condition.lower().strip()
    severity = severity.lower().strip()

    if condition not in _VALID_CONDITIONS:
        raise ValueError(
            f"Invalid condition '{condition}'. Must be one of: {', '.join(sorted(_VALID_CONDITIONS))}"
        )
    if severity not in ("high", "critical"):
        raise ValueError("Rule severity must be 'high' or 'critical'")

    rule = SIEMRule(
        id=f"rule-{uuid.uuid4().hex[:12]}",
        name=name,
        description=description,
        condition=condition,
        severity=severity,
        enabled=True,
        config=config or {},
    )

    with _lock:
        _rules[rule.id] = rule

    logger.info("SIEM rule created: id=%s name=%s", rule.id, name)
    return rule


def get_rules() -> list[dict]:
    """Return all correlation rules."""
    with _lock:
        return [_rule_to_dict(r) for r in _rules.values()]


def delete_rule(rule_id: str) -> bool:
    """
    Delete a correlation rule by ID.

    Returns True if deleted, False if not found.
    """
    with _lock:
        if rule_id in _rules:
            del _rules[rule_id]
            logger.info("SIEM rule deleted: id=%s", rule_id)
            return True
        return False


def toggle_rule(rule_id: str, enabled: bool) -> SIEMRule | None:
    """Enable or disable a rule. Returns the rule or None if not found."""
    with _lock:
        rule = _rules.get(rule_id)
        if rule is None:
            return None
        rule.enabled = enabled
        logger.info("SIEM rule %s: id=%s", "enabled" if enabled else "disabled", rule_id)
        return rule


# ════════════════════════════════════════════════════════════════
#  Core: Alerts
# ════════════════════════════════════════════════════════════════

def get_alerts(limit: int = 20, offset: int = 0) -> list[dict]:
    """
    Retrieve alerts sorted by timestamp descending.

    Args:
        limit:  Max alerts to return (default 20, max 200).
        offset: Pagination offset.
    """
    limit = min(max(limit, 1), 200)

    with _lock:
        all_alerts = list(_alerts.values())

    all_alerts.sort(key=lambda a: a.timestamp, reverse=True)
    return [_alert_to_dict(a) for a in all_alerts[offset: offset + limit]]


def resolve_alert(alert_id: str) -> bool:
    """Mark an alert as acknowledged/resolved."""
    with _lock:
        alert = _alerts.get(alert_id)
        if alert is None:
            return False
        alert.resolved = True
        logger.info("SIEM alert resolved: id=%s", alert_id)
        return True


# ════════════════════════════════════════════════════════════════
#  Correlation Engine
# ════════════════════════════════════════════════════════════════

def _run_correlations(new_event: SIEMEvent) -> None:
    """
    Run all enabled correlation rules against the new event.

    This is called after every ingest_event. It checks only the rule
    types relevant to the incoming event's tags/source for efficiency.
    """
    with _lock:
        enabled_rules = [r for r in _rules.values() if r.enabled]
        all_events_snapshot = list(_events.values())

    for rule in enabled_rules:
        try:
            _check_rule(rule, new_event, all_events_snapshot)
        except Exception as exc:
            logger.error("Correlation error on rule %s: %s", rule.id, exc)


def _check_rule(
    rule: SIEMRule,
    new_event: SIEMEvent,
    all_events: list[SIEMEvent],
) -> None:
    """Dispatch to the correct condition checker."""
    if rule.condition == "brute-force":
        _check_brute_force(rule, new_event, all_events)
    elif rule.condition == "port-scan":
        _check_port_scan(rule, new_event, all_events)
    elif rule.condition == "canary-trigger":
        _check_canary(rule, new_event)
    elif rule.condition == "dlp-leak":
        _check_dlp_leak(rule, new_event, all_events)
    # "custom" rules are left for future expansion


def _check_brute_force(
    rule: SIEMRule,
    new_event: SIEMEvent,
    all_events: list[SIEMEvent],
) -> None:
    """
    Brute-force: count events in the last `window_seconds` that share
    the same IP and have the tag ``failed-auth``.
    """
    if "failed-auth" not in new_event.tags:
        return
    if not new_event.ip:
        return

    threshold = rule.config.get("threshold", 5)
    window_secs = rule.config.get("window_seconds", 60)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_secs)

    matching = []
    for ev in all_events:
        if ev.ip != new_event.ip:
            continue
        if "failed-auth" not in ev.tags:
            continue
        try:
            ev_dt = datetime.fromisoformat(ev.timestamp)
            if ev_dt >= cutoff:
                matching.append(ev)
        except (ValueError, TypeError):
            continue

    if len(matching) >= threshold:
        _create_alert(
            rule=rule,
            title=f"Brute Force Detected from {new_event.ip}",
            detail=(
                f"Detected {len(matching)} failed authentication attempts from "
                f"IP {new_event.ip} within the last {window_secs}s "
                f"(threshold: {threshold})."
            ),
            event_ids=[e.id for e in matching],
        )


def _check_port_scan(
    rule: SIEMRule,
    new_event: SIEMEvent,
    all_events: list[SIEMEvent],
) -> None:
    """
    Port-scan: count events in the last `window_seconds` that share
    the same IP and have the tag ``port-scan``.
    """
    if "port-scan" not in new_event.tags:
        return
    if not new_event.ip:
        return

    threshold = rule.config.get("threshold", 10)
    window_secs = rule.config.get("window_seconds", 30)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_secs)

    matching = []
    for ev in all_events:
        if ev.ip != new_event.ip:
            continue
        if "port-scan" not in ev.tags:
            continue
        try:
            ev_dt = datetime.fromisoformat(ev.timestamp)
            if ev_dt >= cutoff:
                matching.append(ev)
        except (ValueError, TypeError):
            continue

    if len(matching) >= threshold:
        _create_alert(
            rule=rule,
            title=f"Port Scan Detected from {new_event.ip}",
            detail=(
                f"Detected {len(matching)} port-scan events from "
                f"IP {new_event.ip} within the last {window_secs}s "
                f"(threshold: {threshold})."
            ),
            event_ids=[e.id for e in matching],
        )


def _check_canary(rule: SIEMRule, new_event: SIEMEvent) -> None:
    """
    Canary trigger: immediate alert when any event carries the
    ``canary-activation`` tag. No threshold needed.
    """
    if "canary-activation" not in new_event.tags:
        return

    _create_alert(
        rule=rule,
        title=f"Canary Token Activated: {new_event.title}",
        detail=(
            f"A planted canary token was triggered. "
            f"Source: {new_event.source}, IP: {new_event.ip or 'unknown'}. "
            f"{new_event.detail}"
        ),
        event_ids=[new_event.id],
    )


def _check_dlp_leak(
    rule: SIEMRule,
    new_event: SIEMEvent,
    all_events: list[SIEMEvent],
) -> None:
    """
    DLP leak: count events in the last `window_seconds` with severity
    ``high`` (or above) and source ``dlp``.
    """
    if new_event.source != "dlp" or new_event.severity not in ("high", "critical"):
        return

    threshold = rule.config.get("threshold", 3)
    window_secs = rule.config.get("window_seconds", 300)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_secs)

    matching = []
    for ev in all_events:
        if ev.source != "dlp":
            continue
        if ev.severity not in ("high", "critical"):
            continue
        try:
            ev_dt = datetime.fromisoformat(ev.timestamp)
            if ev_dt >= cutoff:
                matching.append(ev)
        except (ValueError, TypeError):
            continue

    if len(matching) >= threshold:
        _create_alert(
            rule=rule,
            title="DLP Data Leak Suspected",
            detail=(
                f"Detected {len(matching)} high-severity DLP events "
                f"within the last {window_secs}s "
                f"(threshold: {threshold}). Possible data exfiltration."
            ),
            event_ids=[e.id for e in matching],
        )


def _create_alert(
    rule: SIEMRule,
    title: str,
    detail: str,
    event_ids: list[str],
) -> None:
    """
    Create a new alert if a duplicate (same rule + overlapping event_ids)
    does not already exist in the last 60 seconds.
    """
    now_iso = _now_iso()

    # Deduplication: skip if same rule already fired for these exact events
    with _lock:
        recent_cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
        for existing in _alerts.values():
            if existing.rule_id != rule.id:
                continue
            if set(existing.event_ids) == set(event_ids):
                try:
                    al_dt = datetime.fromisoformat(existing.timestamp)
                    if al_dt >= recent_cutoff:
                        return  # duplicate — skip
                except (ValueError, TypeError):
                    pass

        alert = SIEMAlert(
            id=str(uuid.uuid4()),
            rule_name=rule.name,
            rule_id=rule.id,
            severity=rule.severity,
            title=title,
            detail=detail,
            timestamp=now_iso,
            event_ids=event_ids,
            resolved=False,
        )
        _alerts[alert.id] = alert

    logger.warning(
        "SIEM ALERT: id=%s rule=%s sev=%s title=%s",
        alert.id[:8], rule.id, rule.severity, title,
    )


# ════════════════════════════════════════════════════════════════
#  MIRV Findings Integration
# ════════════════════════════════════════════════════════════════

def report_to_mirv_findings(event_or_alert) -> list[dict]:
    """
    Convert a SIEMEvent or SIEMAlert into MIRV-compatible findings list.

    Each event/alert becomes a dict with tool, severity, title, detail,
    and recommendation fields matching the MIRV findings schema.
    """
    findings: list[dict] = []

    if isinstance(event_or_alert, SIEMEvent):
        ev = event_or_alert
        findings.append({
            "tool": "siem",
            "severity": ev.severity,
            "title": f"[SIEM] {ev.title}",
            "detail": f"Source: {ev.source}. {ev.detail}",
            "recommendation": _recommendation_for_event(ev),
        })

    elif isinstance(event_or_alert, SIEMAlert):
        al = event_or_alert
        findings.append({
            "tool": "siem-alert",
            "severity": al.severity,
            "title": f"[ALERT] {al.title}",
            "detail": f"Rule: {al.rule_name}. {al.detail}",
            "recommendation": _recommendation_for_alert(al),
        })

    return findings


def _recommendation_for_event(ev: SIEMEvent) -> str:
    """Generate a recommendation string based on event source/severity."""
    recs = {
        "ssh": "Review SSH access logs and enforce key-based authentication.",
        "docker": "Audit Docker container activity and restrict privileged containers.",
        "api": "Review API access patterns and enforce rate limiting.",
        "canary": "Investigate which service accessed the canary token and isolate the source.",
        "dlp": "Review data classification policies and restrict sensitive data access.",
        "firewall": "Review firewall rules and tighten ingress/egress policies.",
        "system": "Review system logs for unauthorized activity.",
    }
    return recs.get(ev.source, "Investigate the event and consult security policy.")


def _recommendation_for_alert(al: SIEMAlert) -> str:
    """Generate a recommendation string based on alert rule type."""
    recs = {
        "rule-brute-force": "Block the source IP and review authentication policies. Enable account lockout thresholds.",
        "rule-port-scan": "Block the scanning IP at the firewall and audit exposed services.",
        "rule-canary": "Isolate the system that accessed the canary. Assume breach and begin incident response.",
        "rule-dlp": "Immediately review data exfiltration paths. Revoke compromised credentials and enforce DLP policies.",
    }
    return recs.get(al.rule_id, "Investigate the alert and follow incident response procedures.")


# ════════════════════════════════════════════════════════════════
#  Utility: Reset (for testing)
# ════════════════════════════════════════════════════════════════

def reset() -> None:
    """Clear all events, alerts, and restore default rules. For testing only."""
    global _events, _alerts, _rules
    with _lock:
        _events = {}
        _alerts = {}
        _rules = {}
    _init_default_rules()
    logger.info("SIEM store reset")
