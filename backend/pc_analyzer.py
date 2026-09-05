"""pc_analyzer -- PC health diagnostics & suggestions (phase 1).

Runs deterministic, local-only checks against the host where MIRV runs and
produces a health report: per-check status (ok / warn / critical / skip),
an A-F grade, a 0-100 score and an actionable suggestions list.

Design:
  - Pure stdlib; reuses ``system_monitor`` for CPU / RAM / disk / junk data.
  - Every check returns a dict so ``analyze()`` is trivially JSON-serializable.
  - No destructive action here: suggestions are advice; the operator still
    fixes things through ``/api/system/cleanup`` (Sys Monitor tab).
  - Fast path: on-demand calls only (button-triggered), never hot-polled.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from backend import system_monitor as sysmon

# Severity ordering used for the summary headline
_SEV_ORDER = {"critical": 3, "warn": 2, "ok": 1, "skip": 0}

# Penalties for the 0-100 score
_PENALTY = {"warn": 6, "critical": 20}

GRADE_BY_PENALTY = [
    (0, "A"),
    (10, "B"),
    (25, "C"),
    (50, "D"),
    (80, "E"),
]


@dataclass
class Check:
    """A single diagnostic with its finding and remedy."""

    id: str
    name: str
    category: str
    status: str  # ok | warn | critical | skip
    message: str
    details: str = ""
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "message": self.message,
            "details": self.details,
        }
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d


# ─────────────────────────────────────────────────────────────
#  Checks
# ─────────────────────────────────────────────────────────────
def _os_root() -> str:
    if os.name == "nt":
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"


def _check_host() -> Check:
    info = sysmon.platform_info()
    return Check(
        id="host",
        name="Host",
        category="host",
        status="ok",
        message=info.get("os", "Unknown") + " " + info.get("release", ""),
        details="Python {}".format(info.get("python", "?")),
    )


def _check_memory() -> Check:
    mem = sysmon.memory()
    percent = mem.get("percent") or 0.0
    used_gb = (mem.get("used") or {}).get("gb", 0.0)
    total_gb = (mem.get("total") or {}).get("gb", 0.0)
    if percent >= 92:
        status, msg = "critical", "RAM critically high ({:.0f}%)".format(percent)
        sug = "Close heavy apps or reboot; consider expanding RAM if persistent."
    elif percent >= 75:
        status, msg = "warn", "RAM is highly used ({:.0f}%)".format(percent)
        sug = "Close large applications or browsers with many tabs."
    else:
        status, msg = "ok", "RAM usage healthy ({:.0f}%)".format(percent)
        sug = None
    return Check(
        id="memory", name="Memory", category="memory", status=status, message=msg,
        details="{:.1f} GB used of {:.1f} GB".format(used_gb, total_gb),
        suggestion=sug,
    )


def _check_cpu() -> Check:
    cpus = sysmon.cpu()
    percent = cpus.get("percent") or 0.0
    cores = cpus.get("cores", 1)
    if percent >= 90:
        status, msg = "critical", "CPU load critically high ({:.0f}%)".format(percent)
        sug = "Inspect Task Manager for runaway processes."
    elif percent >= 75:
        status, msg = "warn", "CPU load high ({:.0f}%)".format(percent)
        sug = "Review heavy processes; check for background scans/indexing."
    else:
        status, msg = "ok", "CPU load healthy ({:.0f}%)".format(percent)
        sug = None
    return Check(
        id="cpu", name="CPU", category="cpu", status=status, message=msg,
        details="{} logical cores".format(int(cores)), suggestion=sug,
    )


def _check_system_disk() -> Check:
    parts = sysmon.disk_partitions()
    root = _os_root().upper().rstrip("\\")
    sysvol = None
    for p in parts:
        if (p.get("mount") or "").upper().rstrip("\\") == root:
            sysvol = p
            break
    if sysvol is None and parts:
        sysvol = min(parts, key=lambda p: (p.get("total") or {}).get("bytes", 0))
    if sysvol is None:
        return Check(id="system_disk", name="System disk", category="disk",
                     status="skip", message="No system volume detected.", details="")
    percent = sysvol.get("percent") or 0.0
    free_gb = (sysvol.get("free") or {}).get("gb", 0.0)
    if percent >= 95:
        status, msg = "critical", "System disk nearly full ({:.0f}% used)".format(percent)
        sug = "Free space now: delete junk via Sys Monitor or move data to another volume."
    elif percent >= 85:
        status, msg = "warn", "System disk getting full ({:.0f}% used)".format(percent)
        sug = "Scan for junk in Sys Monitor; move large files to another drive."
    else:
        status, msg = "ok", "System disk healthy ({:.0f}% used)".format(percent)
        sug = None
    return Check(
        id="system_disk", name="System disk", category="disk", status=status,
        message=msg, details="{:.1f} GB free".format(free_gb), suggestion=sug,
    )


def _check_other_disks() -> Check:
    parts = sysmon.disk_partitions()
    root = _os_root().upper().rstrip("\\")
    others = [
        p for p in parts
        if (p.get("mount") or "").upper().rstrip("\\") != root
        and (p.get("total") or {}).get("bytes", 0) > 0
    ]
    if not others:
        return Check(id="other_disks", name="Other volumes", category="disk",
                     status="ok", message="No additional volumes.", details="")
    worst = max(others, key=lambda p: p.get("percent") or 0)
    percent = worst.get("percent") or 0.0
    if percent >= 95:
        status, msg = "critical", "Volume {} nearly full ({:.0f}%)".format(worst.get("mount"), percent)
        sug = "Move or delete files on this volume before it runs out of space."
    elif percent >= 90:
        status, msg = "warn", "Volume {} is tight ({:.0f}%)".format(worst.get("mount"), percent)
        sug = "Consider freeing space on {}.".format(worst.get("mount"))
    else:
        status, msg = "ok", "All volumes have comfortable free space."
        sug = None
    labels = ", ".join(
        "{} {:.0f}%".format(pp.get("mount"), pp.get("percent") or 0) for pp in others
    )
    return Check(
        id="other_disks", name="Other volumes", category="disk", status=status,
        message=msg, details=labels, suggestion=sug,
    )


def _check_junk() -> Check:
    cands = sysmon.scan_candidates()
    cleanable = [c for c in cands if c.category in ("temp", "cache")]
    junk_bytes = sum(c.size_bytes for c in cleanable)
    gb = junk_bytes / (1024.0 ** 3)
    biggest = max(cleanable, key=lambda c: c.size_bytes) if cleanable else None
    if not cleanable:
        return Check(id="junk", name="Junk / cache", category="storage",
                     status="ok", message="No cleanable temp/cache found.", details="")
    if gb >= 8:
        status, msg = "critical", "Large amount of junk found (~{:.1f} GB)".format(gb)
        sug = "Open Sys Monitor → Scan for junk and delete the Temp/cache entries."
    elif gb >= 2:
        status, msg = "warn", "A meaningful amount of junk found (~{:.1f} GB)".format(gb)
        sug = "Open Sys Monitor → Scan for junk to reclaim a few GB."
    else:
        status, msg = "ok", "Minimal temp/cache footprint (~{:.1f} GB)".format(gb)
        sug = None
    detail = "Biggest: {} ({})".format(biggest.label, sysmon._human(biggest.size_bytes)) if biggest else ""
    return Check(
        id="junk", name="Junk / cache", category="storage", status=status,
        message=msg, details=detail, suggestion=sug,
    )


def _check_network() -> Check:
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            status, msg = "ok", "Outbound connectivity works."
            sug = None
    except OSError:
        status, msg = "warn", "No outbound internet connectivity detected."
        sug = "Check router/Wi-Fi or VPN; updates and AI features need internet."
    return Check(id="network", name="Network", category="network", status=status,
                 message=msg, details="", suggestion=sug)


def _check_uptime() -> Check:
    seconds = sysmon.uptime().get("seconds") or 0.0
    days = seconds / 86400.0
    if days >= 60:
        status, msg = "warn", "System has been up for {:.0f} days".format(days)
        sug = "A reboot applies pending updates and clears stale handles."
    else:
        status, msg = "ok", "Uptime {:.0f} days".format(days)
        sug = None
    return Check(id="uptime", name="Uptime", category="system", status=status,
                 message=msg, details="", suggestion=sug)


# ─────────────────────────────────────────────────────────────
#  Report assembly
# ─────────────────────────────────────────────────────────────
def _grade(checks: List[Check]) -> str:
    critical = sum(1 for c in checks if c.status == "critical")
    warns = sum(1 for c in checks if c.status == "warn")
    if critical >= 3:
        return "F"
    if critical == 2:
        return "D"
    if critical == 1:
        return "C"
    if warns >= 5:
        return "D"
    if warns >= 3:
        return "C"
    if warns == 2:
        return "B"
    if warns == 1:
        return "B"
    return "A"


def _score(checks: List[Check]) -> int:
    penalty = sum(_PENALTY.get(c.status, 0) for c in checks)
    return max(0, min(100, 100 - penalty))


def _summary(checks: List[Check]) -> str:
    critical = sum(1 for c in checks if c.status == "critical")
    warns = sum(1 for c in checks if c.status == "warn")
    skips = sum(1 for c in checks if c.status == "skip")
    if critical:
        return "{} critical, {} warning{}".format(critical, warns, "" if warns == 1 else "s")
    if warns:
        return "{} warning{}".format(warns, "" if warns == 1 else "s")
    if skips:
        return "Healthy ({} check{} skipped)".format(skips, "" if skips == 1 else "s")
    return "No issues detected — machine looks healthy."


def run_checks() -> List[Check]:
    """Execute every check in dependency order (host first)."""
    return [
        _check_host(),
        _check_memory(),
        _check_cpu(),
        _check_system_disk(),
        _check_other_disks(),
        _check_junk(),
        _check_network(),
        _check_uptime(),
    ]


def analyze() -> Dict[str, Any]:
    """Full diagnostic payload for ``/api/pc-analyzer``."""
    checks = run_checks()
    suggestions = [
        {"check_id": c.id, "message": c.message, "action": c.suggestion}
        for c in checks if c.suggestion
    ]
    return {
        "grade": _grade(checks),
        "score": _score(checks),
        "summary": _summary(checks),
        "host": sysmon.platform_info(),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "checks": [c.to_dict() for c in checks],
        "suggestions": suggestions,
    }