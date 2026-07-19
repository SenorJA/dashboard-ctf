"""
VulnForge — Scope Guard
Validates that commands only target authorized hosts/IPs/ranges.
Stores config in the database settings table.

Attack vector mitigated:
  - Unauthorized lateral movement: prevents operators from scanning/attacking
    hosts outside the authorized engagement scope, avoiding legal liability
    and unintended collateral damage during penetration tests.
"""

import re
import json
import ipaddress
from datetime import datetime
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
