"""
VulnForge — Scope Guard
Validates that commands only target authorized hosts/IPs/ranges.
Stores config in the database settings table.

Additionally, an Interactive Permission Prompts system (Phase X) layers on top
of the scope check to classify high-impact/risky commands and request operator
confirmation before they are dispatched. Pending requests live in memory with a
TTL; the frontend polls /api/permissions/pending and replies with allow-once /
allow-session / deny.

Attack vector mitigated:
  - Unauthorized lateral movement: prevents operators from scanning/attacking
    hosts outside the authorized engagement scope, avoiding legal liability
    and unintended collateral damage during penetration tests.
  - Accidental destructive actions: dangerously broad commands (rm -rf /,
    mkfs, dd of=/dev/..., fork bomb, full-range mass scans, pipe-to-shell,
    exploit-framework launches) trigger an interactive gate before execution.
"""

import re
import json
import uuid
import time
import logging
import threading
import ipaddress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional
from backend import database as db

# ── In-memory cache ──
_config = None  # (timestamp, dict)

# Settings keys
SCOPE_SETTINGS_KEY = "vulnforge_scope_config"

DEFAULT_CONFIG = {
    "enabled": False,
    "mode": "warn",       # "warn" | "block"
    "targets": [],         # list of IPs, CIDRs, domains
    "block_private": False, # block RFC1918 addresses outside scope
}


def get_config(force_refresh: bool = False) -> dict:
    """Get current scope configuration from DB (with in-memory cache)."""
    global _config
    if not force_refresh and _config is not None:
        return _config[1]

    try:
        raw = db.get_setting(SCOPE_SETTINGS_KEY)
        if raw:
            cfg = raw if isinstance(raw, dict) else json.loads(raw)
            _config = (datetime.utcnow(), cfg)
            return cfg
    except Exception:
        pass

    _config = (datetime.utcnow(), dict(DEFAULT_CONFIG))
    return _config[1]


def save_config(cfg: dict) -> bool:
    """Save scope configuration to DB."""
    global _config
    try:
        merged = {**DEFAULT_CONFIG, **cfg}
        # Ensure targets is a list of stripped strings
        merged["targets"] = [t.strip() for t in merged.get("targets", []) if t.strip()]
        ok = db.set_setting(SCOPE_SETTINGS_KEY, merged)
        if ok:
            _config = (datetime.utcnow(), merged)
        return bool(ok)
    except Exception as e:
        print(f"[scope] Save error: {e}")
        return False


def is_in_scope(target: str) -> bool:
    """Check if a target string is within the allowed scope."""
    cfg = get_config()
    if not cfg.get("enabled"):
        return True  # Scope check disabled

    allowed = cfg.get("targets", [])
    if not allowed:
        return False  # Scope enabled but no targets defined → block everything

    target = target.strip().lower()

    for allowed_target in allowed:
        at = allowed_target.strip().lower()

        # Direct IP match
        if target == at:
            return True

        # CIDR match (e.g., target is an IP, allowed is a CIDR)
        try:
            if "/" in at:
                network = ipaddress.ip_network(at, strict=False)
                addr = ipaddress.ip_address(target)
                if addr in network:
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass

        # Domain match
        if not _is_ip(target):
            # Exact domain
            if target == at:
                return True
            # Wildcard: *.example.com
            if at.startswith("*."):
                suffix = at[1:]  # .example.com
                if target.endswith(suffix) or target == at[2:]:
                    return True
            # Subdomain match
            if target.endswith("." + at):
                return True

    return False


def _is_ip(s: str) -> bool:
    """Check if a string is an IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── Command parsing ──

# Regex patterns to extract targets from commands
TARGET_PATTERNS = [
    # nmap, masscan: nmap 192.168.1.1, nmap 192.168.1.0/24
    (r'(?:nmap|masscan)\s+(?:-s\w+\s+)*([^\s]+)', 1),
    # ping: ping 8.8.8.8
    (r'ping\s+([^\s]+)', 1),
    # curl/wget: curl http://target
    (r'(?:curl|wget)\s+(?:https?://)?([^\s/:\'"]+)', 1),
    # gobuster/dirb/ffuf/wfuzz: -u http://target
    (r'(?:-u|--url|-h)\s+(?:https?://)?([^\s/:\'"]+)', 1),
    # nikto: -h target
    (r'nikto\s+(?:-h\s+)([^\s]+)', 1),
    # whatweb: whatweb target
    (r'whatweb\s+(?:-a\s+\d\s+)?([^\s]+)', 1),
    # ssh: user@host
    (r'ssh\s+(?:\w+@)?([^\s@]+)', 1),
    # hydra: hydra -t target
    (r'hydra\s+(?:-l\s+\w+\s+)?(?:-P\s+\S+\s+)?([^\s]+)', 1),
    # wpscan: --url target
    (r'wpscan\s+(?:--url\s+)(?:https?://)?([^\s/:\'"]+)', 1),
    # dnsrecon: -d domain
    (r'dnsrecon\s+(?:-d\s+)([^\s]+)', 1),
    # sqlmap: -u http://target
    (r'sqlmap\s+(?:-u\s+)(?:https?://)?([^\s/:\'"]+)', 1),
    # Generic IP/domain as standalone argument (no flag before it)
    (r'(?:^|\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)(?:\s|$)', 1),
]


def extract_targets(command: str) -> list:
    """Extract potential target IPs/domains from a command string."""
    targets = []
    command = command.strip()
    for pattern, group in TARGET_PATTERNS:
        for match in re.finditer(pattern, command, re.IGNORECASE):
            t = match.group(group).strip().rstrip("/")
            # Clean up URL prefixes
            t = re.sub(r'^https?://', '', t)
            # Remove trailing slashes
            t = t.rstrip("/")
            # Skip obvious flags
            if t.startswith("-") or t.startswith("--"):
                continue
            if t not in targets:
                targets.append(t)
    return targets


def validate_command(command: str) -> Optional[dict]:
    """
    Validate a command against the scope.
    Returns None if OK, or a dict with block info if out of scope.
    """
    cfg = get_config()
    if not cfg.get("enabled"):
        return None

    # Skip scope check for non-targeting commands
    safe_commands = ["ls", "cd", "pwd", "echo", "cat", "less", "more",
                     "head", "tail", "grep", "find", "whoami", "id",
                     "uname", "date", "clear", "history", "export",
                     "source", "alias", "type", "which", "help", "man",
                     "exit", "sudo", "su", "chmod", "chown", "cp",
                     "mv", "rm", "mkdir", "touch", "p10k", "PROMPT",
                     "RPROMPT", "cd"]

    first_word = command.strip().split()[0].lower() if command.strip() else ""
    if first_word in safe_commands:
        return None

    # Skip commands that are just shell control
    if command.strip().startswith("p10k") or "PROMPT=" in command or "RPROMPT=" in command:
        return None

    targets = extract_targets(command)
    if not targets:
        # Commands without obvious targets (ls, ps, etc.)
        # Check if first word is a known tool that doesn't take targets
        non_targeting = ["ps", "top", "htop", "df", "du", "free", "ifconfig",
                         "ip", "ss", "netstat", "route", "arp", "systemctl",
                         "service", "apt", "yum", "pip", "npm", "docker",
                         "kubectl", "screen", "tmux", "nano", "vim", "vi"]
        if first_word not in non_targeting and first_word not in safe_commands:
            # Unknown command with no target - let it through (false positives are worse than false negatives)
            pass
        return None

    # Check each target against scope
    blocked = []
    for target in targets:
        if not is_in_scope(target):
            blocked.append(target)

    if blocked:
        return {
            "blocked": True,
            "targets": blocked,
            "command": command[:200],
            "mode": cfg.get("mode", "warn"),
            "message": f"Target(s) out of scope: {', '.join(blocked)}"
        }

    return None


# ── Block history (in-memory + DB persistence) ──
_block_history = []  # list of dicts (in-memory fallback + fast access)

def log_block(block_info: dict):
    """Record a blocked/warned command (in-memory + DB)."""
    entry = {
        **block_info,
        "timestamp": datetime.utcnow().isoformat(),
    }
    _block_history.append(entry)
    if len(_block_history) > 100:
        _block_history.pop(0)

    # Also persist to Supabase if available (fire-and-forget)
    try:
        from backend.database import save_scope_event
        save_scope_event({
            "target": block_info.get("target", ""),
            "action": block_info.get("action", block_info.get("result", "block")),
            "tool":   block_info.get("tool", ""),
            "reason": block_info.get("reason", ""),
            "mode":   block_info.get("mode", "warn"),
        })
    except Exception:
        pass  # offline — in-memory is sufficient for basic operation

def get_block_history(limit: int = 50) -> list:
    """Get recent block/warn history."""
    return list(_block_history[-limit:])

def clear_block_history():
    _block_history.clear()


# ════════════════════════════════════════════════════════════════
#  Interactive Permission Prompts (Phase X)
# ════════════════════════════════════════════════════════════════
#
# In-memory pending permission requests with TTL. Layered on top of scope
# validation: lightweight danger-pattern classifier flags risky commands; if
# the risk is "critical" the command is auto-blocked, otherwise a pending
# PermissionRequest is created and the original dispatch waits (with timeout)
# for an operator decision delivered via the REST API.

# ── High-impact / dangerous command patterns ──
DANGER_PATTERNS = [
    # ── Destructive commands ──
    {"pattern": r"\brm\s+-rf?\s+[/~]", "category": "destructive", "severity": "critical",
     "summary": "Recursive delete of root/home"},
    {"pattern": r"\bmkfs\b", "category": "destructive", "severity": "critical",
     "summary": "Format filesystem"},
    {"pattern": r"\bdd\b.*of=/dev/", "category": "destructive", "severity": "critical",
     "summary": "Raw disk write"},
    {"pattern": r"\b(shutdown|reboot|halt|poweroff)\b", "category": "destructive",
     "severity": "critical", "summary": "System shutdown/reboot"},
    {"pattern": r":\(\)\s*\{\s*:\|:&\s*\};:", "category": "fork-bomb", "severity": "critical",
     "summary": "Fork bomb"},
    # ── Mass scanning / aggressive port scanning ──
    {"pattern": r"\bmasscan\b.*\s-p\s*1-65535", "category": "loud-scan", "severity": "high",
     "summary": "Full port range mass scan (very loud)"},
    {"pattern": r"\bnmap\b.*\s-p\s*1-65535", "category": "loud-scan", "severity": "high",
     "summary": "Full port nmap scan"},
    {"pattern": r"\bnmap\b.*\s-T[45]\b", "category": "aggressive", "severity": "high",
     "summary": "Aggressive nmap timing (T4/T5)"},
    {"pattern": r"\bsqlmap\b.*--batch.*--risk=[345]", "category": "aggressive",
     "severity": "high", "summary": "High-risk sqlmap automation"},
    {"pattern": r"\bhydra\b.*-L\s+\S+\s+-P\s+\S+", "category": "loud-brute", "severity": "high",
     "summary": "Hydra login brute with password list"},
    {"pattern": r"\bgobuster\b.*-t\s+([5-9][0-9]|100|2[0-9][0-9])", "category": "loud-brute",
     "severity": "medium", "summary": "High-rate directory brute"},
    # ── Data exfiltration / remote execution ──
    {"pattern": r"\bcurl\b.*\|\s*(bash|sh)\b", "category": "remote-exec", "severity": "high",
     "summary": "Pipe-to-shell remote execution"},
    {"pattern": r"\bwget\b.*\|\s*(bash|sh)\b", "category": "remote-exec", "severity": "high",
     "summary": "Pipe-to-shell remote execution"},
    # ── Exploitation frameworks ──
    {"pattern": r"\bmsfconsole\b", "category": "exploit-framework", "severity": "high",
     "summary": "Metasploit framework launch"},
    {"pattern": r"\bmetasploit\b", "category": "exploit-framework", "severity": "high",
     "summary": "Metasploit framework"},
]

# Pre-compile for speed
_DANGER_REGEX = [(re.compile(p["pattern"], re.IGNORECASE), p) for p in DANGER_PATTERNS]


@dataclass
class PermissionRequest:
    id: str                # uuid
    tool: str              # tool name
    command: str           # full command being evaluated
    target: str            # target scope (host/URL)
    summary: str           # human-readable summary of risk
    detail: str            # compact rule dump (dangerous patterns matched)
    cache_key: Optional[str] = None  # de-dup key for allow-session caching
    no_session_cache: bool = False   # if True, never session-cache even on allow-session
    created_at: str = ""
    expires_at: str = ""             # default 120s TTL
    status: str = "pending"          # pending | allowed-once | allowed-session | denied | expired
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None  # user / "timeout"


# ── In-memory state ──
_pending: "dict[str, PermissionRequest]" = {}   # id → request
_session_cache: "dict[str, str]" = {}             # cache_key → "allowed" status
_lock = threading.Lock()
_logger = logging.getLogger("vulnforge.permission")
_TTL_SECONDS = 120
_POLL_INTERVAL = 0.5  # polling interval for blocking waiters

# Valid operator decisions
_VALID_DECISIONS = {"allow-once", "allow-session", "deny"}

# Decision normalization map (frontend may send variants).
# Canonical status values stored on the request MUST match the spec:
#   "pending" | "allowed-once" | "allowed-session" | "denied" | "expired"
_DECISION_ALIASES = {
    "allow-once": "allowed-once",
    "allow_once": "allowed-once",
    "once": "allowed-once",
    "allow-session": "allowed-session",
    "allow_session": "allowed-session",
    "session": "allowed-session",
    "allow": "allowed-session",
    "deny": "deny",
    "denied": "deny",
    "block": "deny",
}


def _now_iso() -> str:
    """UTC ISO-8601 timestamp (no microseconds for readability)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_iso(ts: str) -> Optional[float]:
    """Parse ISO timestamp → epoch seconds. Returns None on failure."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _req_to_dict(req: PermissionRequest) -> dict:
    """Serialize a PermissionRequest to a JSON-safe dict."""
    return asdict(req)


def classify_command(tool: str, command: str, target: str) -> dict:
    """
    Classify a command for risk.

    Runs two layers of analysis:
      1. Existing scope validation against configured scope targets
         (returns block reasons if out of scope).
      2. High-impact danger pattern matching.

    Returns a dict:
        {
          "ok": True,
          "risk_level": "safe" | "needs-confirmation" | "blocked",
          "reasons": [...],
          "summary": str,
          "detail": str,
          "needs_permission": bool,
          "cache_key": str|None,
        }
    """
    reasons: list = []
    matched_patterns: list = []
    summaries: list = []
    details: list = []
    max_severity = "safe"

    severity_rank = {"safe": 0, "medium": 1, "high": 2, "critical": 3}

    # ── Layer 1: scope validation ──
    scope_result = validate_command(command)
    if scope_result and scope_result.get("blocked"):
        mode = scope_result.get("mode", "warn")
        target_list = scope_result.get("targets", [])
        msg = scope_result.get("message", "out of scope")
        reason = f"out-of-scope ({mode}): {msg}"
        reasons.append(reason)
        matched_patterns.append({
            "category": "out-of-scope",
            "severity": "critical" if mode == "block" else "high",
            "summary": msg,
            "targets": target_list,
        })
        summaries.append(f"Out of scope: {', '.join(target_list) or target}")
        details.append(f"scope.{mode} blocked_msg={msg}")
        if mode == "block":
            max_severity = "critical"
        elif severity_rank["high"] > severity_rank.get(max_severity, 0):
            max_severity = "high"

    # ── Layer 2: danger pattern matching ──
    for regex, pat in _DANGER_REGEX:
        if regex.search(command):
            sev = pat["severity"]
            cat = pat["category"]
            reasons.append(f"{cat}/{sev}: {pat['summary']}")
            matched_patterns.append({
                "category": cat,
                "severity": sev,
                "summary": pat["summary"],
            })
            summaries.append(pat["summary"])
            details.append(f"{cat}.{sev} pattern='{pat['pattern']}'")
            if severity_rank[sev] > severity_rank.get(max_severity, 0):
                max_severity = sev

    # ── Aggregate risk level ──
    if max_severity == "critical":
        risk_level = "blocked"
        needs_permission = False  # critical auto-blocks (no prompt)
    elif max_severity in ("high", "medium"):
        risk_level = "needs-confirmation"
        needs_permission = True
    else:
        risk_level = "safe"
        needs_permission = False

    # De-dup cache key: tool + command + target — only meaningful if needs permission.
    cache_key = None
    if needs_permission or risk_level == "blocked":
        cache_key = f"{tool or 'shell'}|{target or '*'}|{command[:128]}"

    summary_text = "; ".join(summaries) if summaries else "No risk patterns matched."
    detail_text = "\n".join(details) if details else "No danger patterns matched."

    return {
        "ok": True,
        "risk_level": risk_level,
        "reasons": reasons,
        "summary": summary_text,
        "detail": detail_text,
        "needs_permission": needs_permission,
        "cache_key": cache_key,
        "patterns": matched_patterns,
        "max_severity": max_severity,
    }


def request_permission(
    tool: str,
    command: str,
    target: str,
    summary: str,
    detail: str,
    cache_key: Optional[str] = None,
    no_session_cache: bool = False,
    ttl_seconds: int = _TTL_SECONDS,
) -> PermissionRequest:
    """
    Create a pending PermissionRequest and store it in memory.

    This function does NOT block — callers decide how to wait for the decision
    (see wait_for_decision).
    """
    req_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    created = now.replace(microsecond=0).isoformat()
    expires = (now + timedelta(seconds=ttl_seconds)).replace(microsecond=0).isoformat()
    req = PermissionRequest(
        id=req_id,
        tool=tool or "shell",
        command=command or "",
        target=target or "",
        summary=summary or "",
        detail=detail or "",
        cache_key=cache_key,
        no_session_cache=no_session_cache,
        created_at=created,
        expires_at=expires,
        status="pending",
    )
    with _lock:
        _pending[req_id] = req
    _logger.info(
        "permission.request id=%s tool=%s target=%s status=pending ttl=%ss",
        req_id, req.tool, req.target, ttl_seconds,
    )
    return req


def _is_expired(req: PermissionRequest) -> bool:
    if req.status != "pending":
        return False
    exp = _parse_iso(req.expires_at)
    return exp is not None and time.time() > exp


def wait_for_decision(request_id: str, timeout: Optional[float] = None) -> dict:
    """
    Block until a decision is reached or timeout expires.

    Polls the request status every _POLL_INTERVAL. If the request isn't found
    returns an "unknown" dict. If timeout expires before a decision, marks the
    request as expired (decided_by="timeout").
    """
    req = _pending.get(request_id)
    if req is None:
        return {"status": "unknown", "id": request_id, "ok": False,
                "error": "request not found"}

    # Determine effective timeout
    if timeout is None:
        exp = _parse_iso(req.expires_at)
        timeout = max(0.0, exp - time.time()) if exp else _TTL_SECONDS

    deadline = time.time() + max(0.0, timeout)
    while True:
        with _lock:
            cur = _pending.get(request_id)
            if cur is None:
                return {"status": "unknown", "id": request_id, "ok": False,
                        "error": "request removed"}
            if cur.status != "pending":
                return _req_to_dict(cur)
            if _is_expired(cur):
                cur.status = "expired"
                cur.decided_at = _now_iso()
                cur.decided_by = "timeout"
                _logger.info(
                    "permission.timeout id=%s expired (wait)", request_id,
                )
                return _req_to_dict(cur)
        if time.time() >= deadline:
            with _lock:
                cur = _pending.get(request_id)
                if cur is None:
                    return {"status": "unknown", "id": request_id, "ok": False,
                            "error": "request removed"}
                if cur.status == "pending":
                    cur.status = "expired"
                    cur.decided_at = _now_iso()
                    cur.decided_by = "timeout"
                    _logger.info(
                        "permission.timeout id=%s expired (deadline)", request_id,
                    )
            return _req_to_dict(_pending.get(request_id)) if request_id in _pending else \
                   {"status": "expired", "id": request_id, "decided_by": "timeout"}
        time.sleep(_POLL_INTERVAL)


def decide_permission(
    request_id: str,
    decision: str,
    user: str = "operator",
) -> dict:
    """
    Record an operator's permission decision.

    decision is normalized through _DECISION_ALIASES; accepted canonical values
    are "allow-once", "allowed-session", "deny". On allow-session the cache_key
    is recorded in _session_cache (unless no_session_cache was set on the request).

    Returns the updated request dict, or {"ok": False, "error": ...} on failure.
    """
    canonical = _DECISION_ALIASES.get(decision)
    if canonical is None:
        return {"ok": False, "error": f"invalid decision: {decision!r}"}

    with _lock:
        req = _pending.get(request_id)
        if req is None:
            return {"ok": False, "error": "request not found"}
        if req.status != "pending":
            return {"ok": False, "error": f"request already {req.status}",
                    "status": req.status}

        req.status = canonical
        req.decided_at = _now_iso()
        req.decided_by = user

        if canonical == "allowed-session" and req.cache_key and not req.no_session_cache:
            _session_cache[req.cache_key] = "allowed"

        _logger.info(
            "permission.decide id=%s decision=%s user=%s",
            request_id, canonical, user,
        )
        return _req_to_dict(req)


def check_session_cache(cache_key: str) -> Optional[str]:
    """Return cached decision ('allowed') or None."""
    with _lock:
        return _session_cache.get(cache_key)


def list_pending() -> list:
    """All requests with status='pending', sorted by created_at asc."""
    with _lock:
        pend = [r for r in _pending.values() if r.status == "pending"]
    pend.sort(key=lambda r: r.created_at)
    return [_req_to_dict(r) for r in pend]


def get_request(request_id: str) -> Optional[dict]:
    """Return a single request dict, or None if not found."""
    with _lock:
        req = _pending.get(request_id)
    return _req_to_dict(req) if req else None


def cleanup_expired() -> int:
    """Mark all expired pending requests as expired; return count purged."""
    count = 0
    with _lock:
        for req in _pending.values():
            if req.status == "pending" and _is_expired(req):
                req.status = "expired"
                req.decided_at = _now_iso()
                req.decided_by = "timeout"
                count += 1
    if count:
        _logger.info("permission.cleanup expired=%d", count)
    return count


def clear_decisions() -> None:
    """Clear all pending requests and the session cache."""
    with _lock:
        _pending.clear()
        _session_cache.clear()
    _logger.info("permission.clear all")


def validate_command_with_permission(
    command: str,
    tool: str = "shell",
    target: str = "",
) -> dict:
    """
    Combined scope + danger-pattern validation used by the dispatch layer.

    Returns a richer dict than the base validate_command:
      - ok bool
      - blocked True if scope-mode=block OR critical danger pattern
      - needs_permission True if high/medium danger pattern matched
        (caller should create a request and wait_for_decision)
      - request_id str|None  (NOT auto-created here — caller decides whether
        to invoke request_permission if needs_permission=True)
      - reasons, summary, detail, cache_key from classify_command
    """
    classification = classify_command(tool, command, target)

    # Auto-block on critical
    if classification["risk_level"] == "blocked":
        return {
            "ok": False,
            "blocked": True,
            "needs_permission": False,
            "request_id": None,
            "risk_level": "blocked",
            "reasons": classification["reasons"],
            "summary": classification["summary"],
            "detail": classification["detail"],
            "cache_key": classification["cache_key"],
        }

    if classification["needs_permission"]:
        # Check session cache first — if cached allow, no prompt needed
        cached = check_session_cache(classification["cache_key"]) \
            if classification["cache_key"] else None
        if cached == "allowed":
            return {
                "ok": True,
                "blocked": False,
                "needs_permission": False,
                "request_id": None,
                "risk_level": "safe",
                "reasons": ["session-cache: previously allowed-session"],
                "summary": classification["summary"],
                "detail": classification["detail"],
                "cache_key": classification["cache_key"],
                "cached": True,
            }
        return {
            "ok": True,
            "blocked": False,
            "needs_permission": True,
            "request_id": None,
            "risk_level": "needs-confirmation",
            "reasons": classification["reasons"],
            "summary": classification["summary"],
            "detail": classification["detail"],
            "cache_key": classification["cache_key"],
        }

    return {
        "ok": True,
        "blocked": False,
        "needs_permission": False,
        "request_id": None,
        "risk_level": "safe",
        "reasons": [],
        "summary": classification["summary"],
        "detail": classification["detail"],
        "cache_key": classification["cache_key"],
    }


def reset_permission_state() -> None:
    """Test helper — wipe pending + session cache + scopes for clean state."""
    with _lock:
        _pending.clear()
        _session_cache.clear()
