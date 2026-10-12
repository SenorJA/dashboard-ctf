"""vpn.py -- MIRV Module (Pack 21)

Real VPN (WireGuard / OpenVPN) management for authorized audits.

Where :mod:`backend.privacy` covers **SOCKS/HTTP proxies**, this module drives a
full **tunnel** on the Kali tool host (where the scans actually run) so the
whole egress is routed through the provider instead of a single proxied
command:

* **WireGuard** -- writes ``/etc/wireguard/<name>.conf`` and runs
  ``wg-quick up|down <name>`` (kernel ``/dev/net/tun`` required).
* **OpenVPN** -- writes ``/etc/openvpn/client/<name>.conf`` and launches
  ``openvpn --daemon`` (pid tracked in ``/run/mirv-vpn-<name>.pid``).

The host runner is shared with :mod:`backend.privacy` (same SSH client that
``main.py`` injects via ``privacy.set_ssh_client``), so the backend only needs
one Kali connection.

Both need ``NET_ADMIN`` **and** a ``/dev/net/tun`` device; the shipped
``docker/kali-mcp.Dockerfile`` + ``docker-compose.yml`` install the tools
(``wireguard-tools``, ``openvpn``, ``iproute2``, ``iptables``,
``proxychains4``, ``openresolv``) and make sure the tun node exists.

The registry is in-memory and authoritative; opt-in persistence mirrors it
into the ``workspace_state`` table through :mod:`backend.workspace_store`
(env ``MIRV_PERSIST_WORKSPACE=1``). Private keys are never returned by the API
(``to_public()`` redacts ``PrivateKey``/PEM/``<key>`` blocks).
"""

from __future__ import annotations

import base64
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from backend import workspace_store
except Exception:  # pragma: no cover - defensive
    workspace_store = None  # type: ignore

try:
    from backend import privacy as _host
except Exception:  # pragma: no cover - defensive
    _host = None  # type: ignore

_DEFAULT_TIMEOUT = 45
_PERSIST_KEY = "vpn"

VALID_PROTOCOLS = ("wireguard", "openvpn")

_WG_DIR = "/etc/wireguard"
_OVPN_DIR = "/etc/openvpn/client"
_RUN_DIR = "/run"

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")
_IFACE_CLEAN = re.compile(r"[^A-Za-z0-9_-]")

_MASKED = "***"

# WireGuard key directives never returned to the API.
_WG_KEY_RE = re.compile(r"(?im)^(\s*(?:PrivateKey|PresharedKey)\s*=\s*)\S+.*$")
# Inline PEM blocks inside OpenVPN configs.
_PEM_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.S,
)
# OpenVPN <key>...</key> / <tls-auth> / <tls-crypt> inline blocks.
_OVPN_TAG_RE = re.compile(
    r"(<(?:key|tls-auth|tls-crypt|secret)>)(.*?)(</(?:key|tls-auth|tls-crypt|secret)>)",
    re.S,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def safe_iface(name: str) -> str:
    """Return a safe interface/file token (WireGuard limit: 15 chars)."""
    cleaned = _IFACE_CLEAN.sub("_", (name or "").strip())
    return cleaned[:15] or "mirv0"


def redact_config(protocol: str, config: str) -> str:
    """Return ``config`` with private keys / inline key blocks masked."""
    text = config or ""
    if protocol == "openvpn":
        text = _OVPN_TAG_RE.sub(lambda m: f"{m.group(1)}\n{_MASKED}\n{m.group(3)}", text)
        text = _PEM_RE.sub(_MASKED, text)
    text = _WG_KEY_RE.sub(lambda m: f"{m.group(1)}{_MASKED}", text)
    return text


@dataclass
class VPNProfile:
    vid: str
    name: str
    protocol: str = "wireguard"
    config: str = ""
    active: bool = False
    created_at: str = field(default_factory=_now_iso)

    @property
    def iface(self) -> str:
        return safe_iface(self.name)

    def to_public(self, include_config: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "vid": self.vid,
            "name": self.name,
            "iface": self.iface,
            "protocol": self.protocol,
            "active": self.active,
            "created_at": self.created_at,
            "has_config": bool(self.config),
            "config_lines": len(self.config.splitlines()) if self.config else 0,
        }
        if include_config:
            data["config"] = redact_config(self.protocol, self.config)
        return data


class VPNRegistry:
    """Thread-safe in-memory VPN profile store (in-memory authoritative)."""

    def __init__(self) -> None:
        self._items: Dict[str, VPNProfile] = {}
        self._lock = threading.Lock()

    def add(self, name: str, protocol: str, config: str) -> VPNProfile:
        vid = uuid.uuid4().hex[:8]
        profile = VPNProfile(vid=vid, name=name, protocol=protocol, config=config)
        with self._lock:
            self._items[vid] = profile
        _persist()
        return profile

    def get(self, vid: str) -> Optional[VPNProfile]:
        with self._lock:
            return self._items.get(vid)

    def list(self) -> List[VPNProfile]:
        with self._lock:
            return list(self._items.values())

    def delete(self, vid: str) -> bool:
        with self._lock:
            removed = self._items.pop(vid, None)
        if removed is not None:
            _persist()
            return True
        return False

    def set_active(self, vid: Optional[str]) -> Optional[VPNProfile]:
        with self._lock:
            target = self._items.get(vid) if vid else None
            for profile in self._items.values():
                profile.active = profile.vid == vid
        _persist()
        return target

    def active(self) -> Optional[VPNProfile]:
        with self._lock:
            for profile in self._items.values():
                if profile.active:
                    return profile
        return None

    def clear(self) -> int:
        with self._lock:
            n = len(self._items)
            self._items.clear()
        _persist()
        return n

    def export_state(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.__dict__.copy() for p in self._items.values()]

    def import_state(self, rows: List[Dict[str, Any]]) -> int:
        loaded = 0
        with self._lock:
            self._items.clear()
            for row in rows or []:
                try:
                    profile = VPNProfile(
                        vid=str(row.get("vid") or uuid.uuid4().hex[:8]),
                        name=str(row.get("name") or "imported"),
                        protocol=str(row.get("protocol") or "wireguard"),
                        config=str(row.get("config") or ""),
                        active=bool(row.get("active")),
                        created_at=str(row.get("created_at") or _now_iso()),
                    )
                except Exception:
                    continue
                self._items[profile.vid] = profile
                loaded += 1
        _persist()
        return loaded


registry = VPNRegistry()


def _persist() -> None:
    if workspace_store is None:
        return
    try:
        workspace_store.upsert(_PERSIST_KEY, registry.export_state())
    except Exception:  # pragma: no cover - defensive
        pass


def hydrate() -> int:
    """Load persisted profiles at startup (no-op unless persistence enabled)."""
    if workspace_store is None:
        return 0
    rows = workspace_store.load(_PERSIST_KEY)
    if not rows:
        return 0
    return registry.import_state(rows)


# ── Host command execution (shared with privacy) ────────────────────

def run_on_host(cmd: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[str, str, int]:
    """Run a shell command on the Kali host via the shared privacy runner."""
    if _host is None:
        return "", "vpn host runner unavailable (privacy module missing)", 1
    return _host.run_on_host(cmd, timeout)


# ── Command builders (pure, unit-tested) ────────────────────────────

def _pidfile(name: str) -> str:
    return f"{_RUN_DIR}/mirv-vpn-{name}.pid"


def _logfile(name: str) -> str:
    return f"/var/log/mirv-vpn-{name}.log"


def build_apply_commands(profile: VPNProfile) -> List[str]:
    """Shell commands (run on the host) that bring the tunnel up."""
    name = profile.iface
    conf = (profile.config or "").rstrip("\n") + "\n"
    encoded = _b64(conf)
    if profile.protocol == "openvpn":
        pidfile = _pidfile(name)
        log = _logfile(name)
        return [
            f"mkdir -p {_OVPN_DIR}",
            f"printf '%s' '{encoded}' | base64 -d > {_OVPN_DIR}/{name}.conf",
            f"{{ [ -f {pidfile} ] && kill \"$(cat {pidfile})\" 2>/dev/null; }} || true; "
            f"pkill -f 'openvpn.*{name}\\.conf' 2>/dev/null || true; sleep 1; true",
            f"openvpn --daemon --config {_OVPN_DIR}/{name}.conf "
            f"--writepid {pidfile} --log {log} || true",
            f"sleep 3; if [ -f {pidfile} ] && kill -0 \"$(cat {pidfile})\" 2>/dev/null; "
            f"then echo 'openvpn running pid '\"$(cat {pidfile})\"; "
            f"else echo 'openvpn failed to start'; tail -n 5 {log} 2>/dev/null; fi",
        ]
    return [
        f"mkdir -p {_WG_DIR}",
        f"printf '%s' '{encoded}' | base64 -d > {_WG_DIR}/{name}.conf && "
        f"chmod 600 {_WG_DIR}/{name}.conf",
        f"wg-quick down {name} >/dev/null 2>&1 || true",
        f"wg-quick up {name}",
        f"wg show {name} 2>&1 | head -n 6 || true",
    ]


def build_clear_commands(profile: VPNProfile) -> List[str]:
    """Shell commands that tear the tunnel down and remove its config."""
    name = profile.iface
    if profile.protocol == "openvpn":
        pidfile = _pidfile(name)
        return [
            f"{{ [ -f {pidfile} ] && kill \"$(cat {pidfile})\" 2>/dev/null; }} || true; "
            f"rm -f {pidfile}",
            f"pkill -f 'openvpn.*{name}\\.conf' 2>/dev/null || true",
            f"rm -f {_OVPN_DIR}/{name}.conf",
        ]
    return [
        f"wg-quick down {name} >/dev/null 2>&1 || true",
        f"rm -f {_WG_DIR}/{name}.conf",
    ]


# ── High-level operations ───────────────────────────────────────────

def validate(protocol: str, name: str, config: str) -> Optional[str]:
    """Return an error string when the profile is invalid, else None."""
    if protocol not in VALID_PROTOCOLS:
        return f"invalid protocol: {protocol!r} (use one of {', '.join(VALID_PROTOCOLS)})"
    if not _NAME_RE.match((name or "").strip()):
        return "invalid name (1-15 chars: letters, digits, _ or -)"
    if not (config or "").strip():
        return "empty config"
    if len(config) > 200_000:
        return "config too large (max 200000 chars)"
    text = config
    if protocol == "wireguard":
        if "[Interface]" not in text:
            return "wireguard config missing [Interface] section"
        if "PrivateKey" not in text:
            return "wireguard config missing PrivateKey"
    else:
        if not re.search(r"(?im)^\s*(remote\b|client\b|<connection>)", text):
            return "openvpn config missing 'client'/'remote' directive"
    return None


def apply_vpn(vid: str) -> Dict[str, Any]:
    """Bring the profile's tunnel up on the Kali host and mark it active."""
    profile = registry.get(vid)
    if profile is None:
        return {"ok": False, "error": "vpn profile not found"}
    results = []
    ok = True
    for cmd in build_apply_commands(profile):
        out, err, rc = run_on_host(cmd)
        if rc != 0 and "not configured" in (err or ""):
            return {"ok": False, "error": err.strip(), "steps": results}
        if "unavailable" in (err or "") and "vpn host runner" in (err or ""):
            return {"ok": False, "error": err.strip(), "steps": results}
        ok = ok and rc == 0
        results.append({"rc": rc, "out": out.strip()[:400], "err": err.strip()[:400]})
    if ok:
        registry.set_active(vid)
    return {"ok": ok, "active": vid, "profile": profile.to_public(), "steps": results}


def clear_vpn() -> Dict[str, Any]:
    """Tear down the active tunnel (if any) and deactivate profiles."""
    active = registry.active()
    results = []
    ok = True
    if active is not None:
        for cmd in build_clear_commands(active):
            out, err, rc = run_on_host(cmd)
            ok = ok and rc == 0
            results.append({"rc": rc, "out": out.strip()[:400], "err": err.strip()[:400]})
    registry.set_active(None)
    return {"ok": ok, "cleared": True, "steps": results}


def public_ip(via_vpn: bool = False, timeout: int = 20) -> Dict[str, Any]:
    """Return the host's current egress IP (VPN transparently if a tunnel is up)."""
    if _host is None:
        return {"ok": False, "ip": "", "via_vpn": via_vpn, "duration_ms": 0,
                "error": "vpn host runner unavailable"}
    result = _host.public_ip(via_proxy=False, timeout=timeout)
    return {
        "ok": result.get("ok", False),
        "ip": result.get("ip", ""),
        "via_vpn": via_vpn,
        "duration_ms": result.get("duration_ms", 0),
        "error": result.get("error"),
    }


def status(probe_ip: bool = True) -> Dict[str, Any]:
    """Active profile + current egress IP (through the tunnel when up)."""
    active = registry.active()
    current = public_ip(via_vpn=bool(active)) if probe_ip else None
    return {
        "ok": True,
        "active": active.to_public() if active else None,
        "profiles": len(registry.list()),
        "protocols": list(VALID_PROTOCOLS),
        "current_ip": current,
    }


def summary() -> Dict[str, Any]:
    active = registry.active()
    return {
        "profiles": len(registry.list()),
        "active": active.to_public(include_config=False) if active else None,
        "protocols": list(VALID_PROTOCOLS),
    }
