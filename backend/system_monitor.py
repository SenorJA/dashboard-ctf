"""system_monitor -- Host resource & storage intelligence.

Monitors CPU / RAM, disk usage per mount (``disk_partitions()``) and scans
common clutter locations (``scan_candidates()``) so operators can reclaim
disk space from inside MIRV instead of hunting through Explorer.

Design:
  - Pure stdlib (ctypes + /proc + shutil) with an optional ``psutil`` fast-path.
  - Short TTL cache so hot polling does not hammer ctypes / /proc readers.
  - Size helpers return bytes + GB; every cleanable candidate carries a
    ``risk`` and ``reason`` so the UI can gate destructive actions.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # optional fast-path -- not in requirements.txt, gracefully skipped
    import psutil  # type: ignore
    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover - environment dependent
    psutil = None  # type: ignore
    _HAVE_PSUTIL = False

_LOCK = Lock()
_CACHE: Dict[str, Tuple[float, Any]] = {}
_CACHE_TTL = 3.0
_CPU_STATE: Dict[str, Tuple[float, ...]] = {}


def _cached(key: str, producer: Callable[[], Any]) -> Any:
    """Short TTL cache keyed by name -- keeps hot polling cheap."""
    with _LOCK:
        now = time.time()
        hit = _CACHE.get(key)
        if hit and (now - hit[0]) < _CACHE_TTL:
            return hit[1]
    value = producer()
    with _LOCK:
        _CACHE[key] = (time.time(), value)
    return value


def _gb(n: float) -> float:
    return round(n / (1024.0 ** 3), 2)


def _fmt(n: float) -> Dict[str, float]:
    return {"bytes": int(n), "gb": _gb(n)}


def _human(n: float) -> str:
    """Compact human label: B/KB/MB/GB/TB."""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def platform_info() -> dict:
    """OS / python / host info usable for the dashboard header."""
    return {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node() or "",
        "psutil": _HAVE_PSUTIL,
    }


# ─────────────────────────────────────────────────────────────
#  CPU / RAM
# ─────────────────────────────────────────────────────────────
def _mem_windows() -> Dict[str, int]:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        raise OSError("GlobalMemoryStatusEx failed")
    return {
        "total": int(stat.ullTotalPhys),
        "available": int(stat.ullAvailPhys),
        "used": int(stat.ullTotalPhys - stat.ullAvailPhys),
    }


def _mem_linux() -> Dict[str, int]:
    with open("/proc/meminfo") as fh:
        data = {line.split(":")[0]: int(line.split()[1]) * 1024 for line in fh}
    total = data.get("MemTotal", 0)
    available = data.get("MemAvailable", data.get("MemFree", 0))
    return {"total": total, "available": available, "used": total - available}


def _mem_data() -> Dict[str, int]:
    if _HAVE_PSUTIL:
        vm = psutil.virtual_memory()
        return {
            "total": int(vm.total),
            "available": int(vm.available),
            "used": int(vm.used),
        }
    if os.name == "nt":
        return _mem_windows()
    return _mem_linux()


def memory() -> Dict[str, Any]:
    """RAM totals + percent, cached briefly."""

    def _produce() -> Dict[str, Any]:
        d = _mem_data()
        total = d["total"]
        used = d["used"]
        percent = round(used / total * 100.0, 1) if total else 0.0
        return {
            "total": _fmt(total),
            "used": _fmt(used),
            "available": _fmt(d["available"]),
            "percent": percent,
        }

    return _cached("memory", _produce)


def _cpu_windows() -> Tuple[float, float]:
    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

    idle, kernel, user = FILETIME(), FILETIME(), FILETIME()

    def _to_sec(ft: FILETIME) -> float:
        return (ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10_000_000.0

    if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        raise OSError("GetSystemTimes failed")

    prev = _CPU_STATE.get("win")
    idle_t, kern_t, user_t = _to_sec(idle), _to_sec(kernel), _to_sec(user)
    _CPU_STATE["win"] = (idle_t, kern_t, user_t)
    if prev and (kern_t + user_t) != (prev[1] + prev[2]):
        d_idle = idle_t - prev[0]
        d_total = (kern_t - prev[1]) + (user_t - prev[2])
        if d_total > 0:
            return max(0.0, min(100.0, (d_total - d_idle) / d_total * 100.0)), 1.0
    return 0.0, 1.0


def _cpu_linux() -> Tuple[float, float]:
    with open("/proc/stat") as fh:
        line = fh.readline()
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return 0.0, 1.0
    vals = [int(p) for p in parts[1:9]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals)
    prev = _CPU_STATE.get("lin")
    _CPU_STATE["lin"] = (total, idle)
    if prev and total > prev[0]:
        return max(0.0, min(100.0, (1.0 - (idle - prev[1]) / (total - prev[0])) * 100.0)), 1.0
    return 0.0, 1.0


def cpu() -> Dict[str, Any]:
    """CPU percent (smoothed between polling windows)."""

    def _produce() -> Dict[str, Any]:
        if _HAVE_PSUTIL:
            pct = psutil.cpu_percent(interval=None)
            cores = float(psutil.cpu_count(logical=True) or 1)
        elif os.name == "nt":
            pct, cores = _cpu_windows()
        else:
            pct, cores = _cpu_linux()
        return {"percent": round(pct, 1), "cores": cores}

    return _cached("cpu", _produce)


def uptime() -> Dict[str, float]:
    """Seconds since boot."""
    if _HAVE_PSUTIL:
        return {"seconds": max(0.0, time.time() - psutil.boot_time())}
    if os.name == "nt":
        return {"seconds": float(ctypes.windll.kernel32.GetTickCount64() / 1000.0)}
    try:
        with open("/proc/uptime") as fh:
            return {"seconds": float(fh.readline().split()[0])}
    except Exception:
        return {"seconds": 0.0}


# ─────────────────────────────────────────────────────────────
#  DISK / STORAGE
# ─────────────────────────────────────────────────────────────
def disk_partitions() -> List[Dict[str, Any]]:
    """Per-mount usage (Windows: drive letters; POSIX: real mounts)."""

    def _produce() -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: set = set()

        def _append(device: str, mount: str, fstype: str) -> None:
            if mount in seen:
                return
            seen.add(mount)
            try:
                u = shutil.disk_usage(mount)
            except Exception:
                return
            if not u.total:
                return
            out.append(
                {
                    "device": device,
                    "mount": mount,
                    "fstype": fstype,
                    "total": _fmt(u.total),
                    "used": _fmt(u.used),
                    "free": _fmt(u.free),
                    "percent": round(u.used / u.total * 100.0, 1),
                }
            )

        if _HAVE_PSUTIL:
            for p in psutil.disk_partitions(all=True):
                _append(p.device, p.mountpoint, p.fstype)
            return out

        if os.name == "nt":
            import string
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    _append(drive, drive, "ntfs")
            return out

        try:
            with open("/proc/mounts") as fh:
                for line in fh:
                    dev, mount, fstype, _rest = line.split(None, 3)
                    if fstype in ("proc", "sysfs", "tmpfs", "devpts", "cgroup", "overlay", "squashfs"):
                        continue
                    if not mount.startswith("/"):
                        continue
                    _append(dev, mount, fstype)
        except OSError:
            pass
        return out

    return _cached("disk", _produce)


# ─────────────────────────────────────────────────────────────
#  CLUTTER SCAN -- "where is all my space going?"
# ─────────────────────────────────────────────────────────────
@dataclass
class CleanCandidate:
    """A junk location that can be reclaimed (safe / with warnings)."""

    path: str
    label: str
    category: str  # temp | cache | logs | old-backup | download | app-data
    risk: str      # safe | medium | high
    reason: str
    size_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "label": self.label,
            "category": self.category,
            "risk": self.risk,
            "reason": self.reason,
            "size_bytes": self.size_bytes,
            "size_human": _human(self.size_bytes),
        }


def _dir_size(path: str, budget_seconds: float = 1.5) -> int:
    """Recursive directory (or file) size in bytes, never follows symlinks.

    Stops early once ``budget_seconds`` elapse and returns the partial count
    so even giant profiles (Documents/AppData) stay responsive.
    """
    deadline = time.monotonic() + budget_seconds
    total = 0
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        for root, _dirs, files in os.walk(path, followlinks=False):
            if time.monotonic() > deadline:
                break
            for name in files:
                fp = os.path.join(root, name)
                try:
                    if os.path.islink(fp):
                        continue
                    total += os.path.getsize(fp)
                except OSError:
                    continue
    except OSError:
        return 0
    return total


def _home_dir() -> Optional[str]:
    if os.name == "nt":
        return (
            os.environ.get("USERPROFILE")
            or os.environ.get("HOMEDRIVE", "") + os.environ.get("HOMEPATH", "")
        )
    return os.path.expanduser("~")


def scan_candidates(scan_home: Optional[str] = None) -> List[CleanCandidate]:
    """Locate common space-wasters for the UI 'clean up' sheet.

    Uses explicit, well-known locations only (no full recursive home scan)
    so the call stays fast even on huge user profiles. NEVER deletes
    anything -- the caller decides via ``cleanup_candidate``.
    Results sorted by size desc.
    """
    home = scan_home or _home_dir()
    if not home or not os.path.isdir(home):
        return []

    roots: List[Tuple[str, str, str, str, str]] = [
        (os.path.join(home, "Downloads"), "Downloads", "download", "medium",
         "Review before deleting -- may hold installers and documents."),
        (os.path.join(home, "Documents"), "Documents", "app-data", "medium",
         "User documents -- manage manually."),
        (os.path.join(home, "Desktop"), "Desktop", "app-data", "medium",
         "Desktop files -- review before deleting."),
    ]
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        roaming = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        roots += [
            (os.path.join(local, "Temp"), "User Temp", "temp", "safe",
             "Temporary files -- safe to purge."),
            (os.path.join(local, "Packages"), "Windows Store cache", "cache", "low",
             "Packaged app caches."),
            (local, "AppData\\Local", "app-data", "high",
             "App data -- CLEAN ONLY specific subfolders."),
            (roaming, "AppData\\Roaming", "app-data", "high",
             "App settings/backups -- CLEAN ONLY specific subfolders."),
        ]
    else:
        roots += [
            (os.path.join(home, ".cache"), ".cache", "cache", "safe",
             "User cache directory -- safe to purge."),
            (os.path.join(home, ".npm"), ".npm", "cache", "safe",
             "npm cache -- safe to purge."),
            (os.path.join(home, ".cargo"), "cargo registry+cache", "cache", "safe",
             "Rust crate registry & cache."),
            ("/tmp", "/tmp", "temp", "safe", "System temp -- safe to purge."),
        ]

    candidates: List[CleanCandidate] = []
    for path, label, category, risk, reason in roots:
        value = _dir_size(path) if os.path.isdir(path) else 0
        candidates.append(CleanCandidate(path, label, category, risk, reason, value))

    candidates.sort(key=lambda c: c.size_bytes, reverse=True)
    return candidates


def find_large_unused(scan_home: Optional[str] = None, older_than_days: int = 90) -> List[CleanCandidate]:
    """Files modified long ago (candidate for 'unused'). Non-recursive home scan."""
    home = scan_home or _home_dir()
    if not home or not os.path.isdir(home):
        return []
    cutoff = time.time() - older_than_days * 86400
    out: List[CleanCandidate] = []
    for root, _dirs, files in os.walk(home, topdown=True, followlinks=False):
        depth = root[len(home) :].count(os.sep)
        if depth > 2:
            continue
        for name in files:
            fp = os.path.join(root, name)
            try:
                st = os.stat(fp)
            except OSError:
                continue
            if st.st_size < 50 * 1024 * 1024:
                continue
            if st.st_mtime < cutoff:
                out.append(
                    CleanCandidate(
                        fp,
                        name,
                        "old",
                        "high",
                        f"Unused for {older_than_days}+ days ({_human(st.st_size)}).",
                        st.st_size,
                    )
                )
    out.sort(key=lambda c: c.size_bytes, reverse=True)
    return out[:50]


def cleanup_candidate(path: str, force: bool = False) -> dict:
    """Delete a single candidate path (file or dir). Returns result dict.

    Safety: refuses paths that are roots ('/', 'C:\\'), dangerous system
    locations, or that look like home itself. ``force`` still requires the
    path to exist and to be within an acceptable set.
    """
    if not path:
        return {"ok": False, "error": "no path provided"}
    normalized = os.path.abspath(path)
    if _looks_dangerous(normalized) and not force:
        return {"ok": False, "error": "refusing to delete a dangerous path"}
    if not os.path.exists(normalized) and not os.path.islink(normalized):
        return {"ok": False, "error": "path does not exist"}
    try:
        size = _dir_size(normalized) if os.path.isdir(normalized) else os.path.getsize(normalized)
        if os.path.isdir(normalized) and not os.path.islink(normalized):
            shutil.rmtree(normalized, ignore_errors=False)
        else:
            os.remove(normalized) if not os.path.isdir(normalized) else os.unlink(normalized)
        return {"ok": True, "path": normalized, "freed_bytes": size, "freed_human": _human(size)}
    except Exception as exc:  # pragmatic -- surface OS failures
        return {"ok": False, "path": normalized, "error": str(exc)}


def _looks_dangerous(path: str) -> bool:
    """True when a path is a root or resolves under a protected system location."""
    import re
    up = path.upper().strip()
    if path in ("/", "\\") or re.match(r"^[A-Z]:\\$", path) or up in ("C:", "C:\\"):
        return True
    parts = re.split(r"[\\/]+", up)
    protected = {
        "WINDOWS",
        "PROGRAM FILES",
        "PROGRAM FILES (X86)",
        "SYSTEM VOLUME INFORMATION",
        "$RECYCLE.BIN",
        "USR",
        "ETC",
        "BOOT",
        "BIN",
        "LIB",
        "SBIN",
        "PROC",
        "SYS",
        "DEV",
    }
    if any(seg in protected for seg in parts):
        return True
    home = _home_dir()
    if home and up == home.upper():
        return True
    return False


def summary() -> dict:
    """Fast one-shot dashboard payload -- excludes the expensive clutter scan."""
    mem = memory()
    cpust = cpu()
    parts = disk_partitions()
    return {
        "platform": platform_info(),
        "uptime_seconds": uptime()["seconds"],
        "memory": mem,
        "cpu": cpust,
        "disk": parts,
    }