"""Wireless audit via SSH to a physical Kali host (aircrack-ng suite).

Host-only: monitor mode requires direct access to Wi-Fi hardware.
Docker: unsupported. Configure MIRV_WIRELESS_* to use SSH.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import uuid

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover
    paramiko = None

_DEFAULT_TIMEOUT = 60

@dataclass
class WirelessSession:
    sid: str
    status: str = "ready"
    target_bssid: str = ""
    interface: str = "wlan0mon"
    channel: int = 0
    cmd_log: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class WirelessRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, WirelessSession] = {}
        self._lock = threading.Lock()

    def create(self) -> WirelessSession:
        sid = str(uuid.uuid4())[:8]
        s = WirelessSession(sid=sid)
        with self._lock:
            self._sessions[sid] = s
        return s

    def get(self, sid: str) -> Optional[WirelessSession]:
        with self._lock:
            return self._sessions.get(sid)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            out = []
            for s in self._sessions.values():
                d = s.__dict__.copy()
                out.append(d)
            return out

    def clear(self) -> int:
        with self._lock:
            n = len(self._sessions)
            self._sessions.clear()
            return n


registry = WirelessRegistry()


def _ssh_client() -> Optional[Any]:  # pragma: no cover - host-only path
    if paramiko is None:
        return None
    host = os.getenv("MIRV_WIRELESS_HOST")
    if not host:
        return None
    port = int(os.getenv("MIRV_WIRELESS_PORT", "22"))
    user = os.getenv("MIRV_WIRELESS_USER", "root")
    key_path = os.getenv("MIRV_WIRELESS_KEY")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            try:
                k = paramiko.Ed25519Key.from_private_key_file(key_path)
            except Exception:
                try:
                    k = paramiko.RSAKey.from_private_key_file(key_path)
                except Exception:
                    k = None
            if k:
                client.connect(hostname=host, port=port, username=user, pkey=k, timeout=10)
                return client
        pw = os.getenv("MIRV_WIRELESS_PASS")
        client.connect(hostname=host, port=port, username=user, password=pw, timeout=10)
        return client
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return None


def run_host_cmd(cmd: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[str, str, int]:
    c = _ssh_client()
    if not c:
        return "", "wireless host not configured (MIRV_WIRELESS_HOST)", 1
    try:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status() if hasattr(stdout, "channel") else 1
        return out, err, rc
    except Exception as e:
        return "", str(e), 1
    finally:
        try:
            c.close()
        except Exception:
            pass
