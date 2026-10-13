"""privacy.py -- MIRV Module

Privacy / egress-IP management for authorized audits.

The operator's real IP leaks whenever a tool reaches out to the target.
This module lets you register **SOCKS5 / SOCKS4 / HTTP(S) proxy** profiles,
apply one on the **Kali tool host** (where the scans actually run) and
verify that the public egress IP changed.

Mechanism (host-side, no root strictly required):

* Writes ``~/.proxychains/proxychains4.conf`` so any command can be wrapped
  with ``proxychains4 -q <tool> ...``.
* Writes a sourceable ``~/.config/mirv/proxy.env`` and best-effort exports
  ``http_proxy``/``https_proxy``/``all_proxy`` into ``/etc/environment``
  (idempotent marker block) so proxy-aware tools pick it up.

VPN (WireGuard/OpenVPN) is intentionally out of scope for this pack; it
needs ``NET_ADMIN`` + ``/dev/net/tun`` and is a separate workstream.

The registry is in-memory and authoritative; opt-in persistence mirrors it
into the ``workspace_state`` table through :mod:`backend.workspace_store`
(env ``MIRV_PERSIST_WORKSPACE=1``). Passwords are never returned by the API
(``to_public()`` masks them).
"""

from __future__ import annotations

import base64
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover - paramiko optional
    paramiko = None

try:
    from backend import workspace_store
except Exception:  # pragma: no cover - defensive
    workspace_store = None  # type: ignore

_DEFAULT_TIMEOUT = 30
_PERSIST_KEY = "privacy"

VALID_KINDS = ("socks5", "socks4", "http", "https")

_PROXYCHAIN_KIND = {
    "socks5": "socks5",
    "socks4": "socks4",
    "http": "http",
    "https": "http",
}

# Marker block used to make /etc/environment edits reversible + idempotent.
_ENV_BEGIN = "# >>> MIRV proxy >>>"
_ENV_END = "# <<< MIRV proxy <<<"

_IP_URL = "https://api.ipify.org"
_IP_FALLBACK = "https://ifconfig.me/ip"
_PROXYCHAINS_CONF = "~/.proxychains/proxychains4.conf"
_PROXY_ENV_FILE = "~/.config/mirv/proxy.env"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def mask_secret(value: str) -> str:
    """Shape-preserving mask for proxy credentials (never echo the secret)."""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


@dataclass
class ProxyProfile:
    pid: str
    name: str
    kind: str = "socks5"
    host: str = ""
    port: int = 1080
    username: str = ""
    password: str = ""
    active: bool = False
    created_at: str = field(default_factory=_now_iso)

    def to_public(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": mask_secret(self.password),
            "has_password": bool(self.password),
            "active": self.active,
            "created_at": self.created_at,
        }


class ProxyRegistry:
    """Thread-safe in-memory proxy profile store (in-memory authoritative)."""

    def __init__(self) -> None:
        self._items: Dict[str, ProxyProfile] = {}
        self._lock = threading.Lock()

    def add(self, name: str, kind: str, host: str, port: int,
            username: str = "", password: str = "") -> ProxyProfile:
        pid = uuid.uuid4().hex[:8]
        profile = ProxyProfile(pid=pid, name=name, kind=kind, host=host,
                               port=port, username=username, password=password)
        with self._lock:
            self._items[pid] = profile
        _persist()
        return profile

    def get(self, pid: str) -> Optional[ProxyProfile]:
        with self._lock:
            return self._items.get(pid)

    def list(self) -> List[ProxyProfile]:
        with self._lock:
            return list(self._items.values())

    def delete(self, pid: str) -> bool:
        with self._lock:
            removed = self._items.pop(pid, None)
        if removed is not None:
            _persist()
            return True
        return False

    def set_active(self, pid: Optional[str]) -> Optional[ProxyProfile]:
        with self._lock:
            target = self._items.get(pid) if pid else None
            for profile in self._items.values():
                profile.active = profile.pid == pid
        _persist()
        return target

    def active(self) -> Optional[ProxyProfile]:
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
                    profile = ProxyProfile(
                        pid=str(row.get("pid") or uuid.uuid4().hex[:8]),
                        name=str(row.get("name") or "imported"),
                        kind=str(row.get("kind") or "socks5"),
                        host=str(row.get("host") or ""),
                        port=int(row.get("port") or 1080),
                        username=str(row.get("username") or ""),
                        password=str(row.get("password") or ""),
                        active=bool(row.get("active")),
                        created_at=str(row.get("created_at") or _now_iso()),
                    )
                except Exception:
                    continue
                self._items[profile.pid] = profile
                loaded += 1
        _persist()
        return loaded


registry = ProxyRegistry()

_ssh_client: Optional[Any] = None


def set_ssh_client(client: Optional[Any]) -> None:
    """Inject the shared Kali SSH client (used by main.py)."""
    global _ssh_client
    _ssh_client = client


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


# ── Host command execution ──────────────────────────────────────────

def _env_ssh_client() -> Optional[Any]:  # pragma: no cover - host path
    """Own paramiko client from env (MIRV_PRIVACY_* then KALI_* then Kali default)."""
    if paramiko is None:
        return None
    host = (os.getenv("MIRV_PRIVACY_HOST") or os.getenv("KALI_IP") or "").strip()
    if not host:
        return None
    port = int(os.getenv("MIRV_PRIVACY_PORT") or os.getenv("KALI_PORT") or "22")
    user = (os.getenv("MIRV_PRIVACY_USER") or os.getenv("KALI_USER") or "root").strip()
    password = os.getenv("MIRV_PRIVACY_PASS") or os.getenv("KALI_PASS") or ""
    key_path = os.getenv("MIRV_PRIVACY_KEY")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            try:
                key = paramiko.Ed25519Key.from_private_key_file(key_path)
            except Exception:
                try:
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                except Exception:
                    key = None
            if key:
                client.connect(hostname=host, port=port, username=user, pkey=key, timeout=10)
                return client
        client.connect(hostname=host, port=port, username=user, password=password, timeout=10)
        return client
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return None


def run_on_host(cmd: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[str, str, int]:
    """Run a shell command on the Kali host. Graceful error when unreachable."""
    client = _ssh_client
    owns_client = False
    if client is None:
        client = _env_ssh_client()
        owns_client = True
    if client is None:
        return "", "privacy host not configured (set KALI_IP or MIRV_PRIVACY_HOST)", 1
    try:
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status() if hasattr(stdout, "channel") else 1
        return out, err, rc
    except Exception as exc:
        return "", str(exc), 1
    finally:
        if owns_client:
            try:
                client.close()
            except Exception:
                pass


# ── Command builders (pure, unit-tested) ────────────────────────────

def build_proxychains_conf(profile: ProxyProfile) -> str:
    """Return the ``proxychains4.conf`` body for a profile."""
    chain_kind = _PROXYCHAIN_KIND.get(profile.kind, "socks5")
    suffix = ""
    if profile.username:
        suffix = f" {profile.username} {profile.password}".rstrip()
    return (
        "strict_chain\n"
        "proxy_dns\n"
        "remote_dns_subnet 224\n"
        "tcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n"
        "[ProxyList]\n"
        f"{chain_kind} {profile.host} {profile.port}{suffix}\n"
    )


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _proxy_url(profile: ProxyProfile, with_export: bool) -> str:
    chain_kind = _PROXYCHAIN_KIND.get(profile.kind, "socks5")
    if profile.username:
        auth = f"{profile.username}:{profile.password}@"
    else:
        auth = ""
    url = f"{chain_kind}://{auth}{profile.host}:{profile.port}"
    lines = []
    for key in ("http_proxy", "https_proxy", "all_proxy",
                "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        prefix = "export " if with_export else ""
        lines.append(f"{prefix}{key}={url}")
    return "\n".join(lines)


def _env_block(profile: ProxyProfile) -> str:
    """Sourceable shell snippet (``export KEY=value``)."""
    return f"{_ENV_BEGIN}\n{_proxy_url(profile, True)}\n{_ENV_END}\n"


def _environment_block(profile: ProxyProfile) -> str:
    """``/etc/environment`` block (``KEY=value``, no ``export``)."""
    return f"{_ENV_BEGIN}\n{_proxy_url(profile, False)}\n{_ENV_END}\n"


# Python snippet shared by apply/clear that rewrites the marker block in
# ``/etc/environment`` idempotently (best-effort; needs write perms).
_ETC_ENV_SNIPPET = (
    "python3 - <<'PY'\n"
    "import os,re\n"
    "p='/etc/environment'\n"
    "begin={begin!r}; end={end!r}\n"
    "block={block!r}\n"
    "try:\n"
    "    s=open(p).read() if os.path.exists(p) else ''\n"
    "    s=re.sub(re.escape(begin)+r'.*?'+re.escape(end)+r'\\n?','',s,flags=re.S)\n"
    "    s=s.rstrip('\\n')\n"
    "    if block:\n"
    "        s=(s+'\\n' if s else '')+block\n"
    "    open(p,'w').write(s+'\\n' if s else '')\n"
    "except Exception as e:\n"
    "    print('WARN', e)\n"
    "PY"
)


def _etc_env_command(block: str) -> str:
    return _ETC_ENV_SNIPPET.format(begin=_ENV_BEGIN, end=_ENV_END, block=block)


def build_apply_commands(profile: ProxyProfile) -> List[str]:
    """Shell commands (run on the host) that install the proxy config."""
    conf = build_proxychains_conf(profile)
    return [
        "mkdir -p ~/.proxychains ~/.config/mirv",
        f"printf '%s' '{_b64(conf)}' | base64 -d > {_PROXYCHAINS_CONF}",
        f"printf '%s' '{_b64(_env_block(profile))}' | base64 -d > {_PROXY_ENV_FILE}",
        _etc_env_command(_environment_block(profile)),
        f"command -v proxychains4 >/dev/null 2>&1 && "
        f"curl -s --max-time 12 {_IP_URL} || echo 'proxychains4 missing'",
    ]


def build_clear_commands() -> List[str]:
    """Shell commands that remove the proxy config from the host."""
    return [
        f"rm -f {_PROXYCHAINS_CONF} {_PROXY_ENV_FILE}",
        _etc_env_command(""),
    ]


# ── High-level operations ───────────────────────────────────────────

def validate(kind: str, host: str, port: Any) -> Optional[str]:
    """Return an error string when the profile is invalid, else None."""
    if kind not in VALID_KINDS:
        return f"invalid kind: {kind!r} (use one of {', '.join(VALID_KINDS)})"
    if not host or not re.match(r"^[A-Za-z0-9_.:\-\[\]]+$", str(host)):
        return "invalid host"
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "invalid port"
    if not 1 <= p <= 65535:
        return "port out of range (1-65535)"
    return None


def apply_proxy(pid: str) -> Dict[str, Any]:
    """Install the profile's proxy config on the Kali host and mark it active."""
    profile = registry.get(pid)
    if profile is None:
        return {"ok": False, "error": "proxy profile not found"}
    results = []
    ok = True
    for cmd in build_apply_commands(profile):
        out, err, rc = run_on_host(cmd)
        if rc != 0 and "not configured" in (err or ""):
            return {"ok": False, "error": err.strip(), "applied": results}
        ok = ok and rc == 0
        results.append({"rc": rc, "out": out.strip()[:400], "err": err.strip()[:400]})
    if ok:
        registry.set_active(pid)
    return {"ok": ok, "active": pid if ok else None, "profile": profile.to_public(), "steps": results}


def clear_proxy() -> Dict[str, Any]:
    """Remove the proxy config from the host and deactivate profiles."""
    results = []
    ok = True
    for cmd in build_clear_commands():
        out, err, rc = run_on_host(cmd)
        ok = ok and rc == 0
        results.append({"rc": rc, "out": out.strip()[:400], "err": err.strip()[:400]})
    registry.set_active(None)
    return {"ok": ok, "cleared": True, "steps": results}


def _extract_ip(text: str) -> str:
    text = (text or "").strip()
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if match:
        return match.group(0)
    return text.splitlines()[0].strip() if text else ""


def public_ip(via_proxy: bool = False, timeout: int = 15) -> Dict[str, Any]:
    """Return the host's public egress IP (optionally through proxychains)."""
    curl = f"curl -s --max-time {max(5, timeout - 3)}"
    if via_proxy:
        cmd = f"proxychains4 -q {curl} {_IP_URL} || {curl} {_IP_FALLBACK}"
    else:
        cmd = f"{curl} {_IP_URL} || {curl} {_IP_FALLBACK}"
    start = time.monotonic()
    out, err, rc = run_on_host(cmd, timeout=timeout)
    ip = _extract_ip(out)
    return {
        "ok": rc == 0 and bool(ip),
        "ip": ip,
        "via_proxy": via_proxy,
        "duration_ms": int((time.monotonic() - start) * 1000),
        "error": None if rc == 0 else (err.strip() or "host unreachable"),
    }


def status() -> Dict[str, Any]:
    """Active profile + direct egress IP + (if active) proxied egress IP."""
    active = registry.active()
    direct = public_ip(via_proxy=False)
    proxied = public_ip(via_proxy=True) if active else None
    return {
        "ok": True,
        "active": active.to_public() if active else None,
        "profiles": len(registry.list()),
        "direct": direct,
        "proxied": proxied,
        "proxychains_conf": _PROXYCHAINS_CONF,
        "proxy_env_file": _PROXY_ENV_FILE,
    }


def summary() -> Dict[str, Any]:
    active = registry.active()
    return {
        "profiles": len(registry.list()),
        "active": active.to_public() if active else None,
        "kinds": list(VALID_KINDS),
    }
