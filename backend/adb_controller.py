"""
VulnForge Mobile Lab — ADB / Frida Controller.

Executes ADB and Frida commands on Kali Linux via SSH.
Uses a lazy-imported SSH client from main module.
"""

import os
import re
import logging
from typing import Optional

logger = logging.getLogger("vulnforge.adb")

FRIDA_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts", "frida")

FRIDA_SCRIPTS_META = [
    {"name": "ssl-bypass.js", "description": "Universal SSL pinning bypass for Android"},
    {"name": "root-bypass.js", "description": "Bypass common root detection mechanisms"},
    {"name": "pin-bypass.js", "description": "Bypass PIN/pattern lock screen"},
    {"name": "template.js", "description": "Empty template for custom Frida scripts"},
]


def _get_ssh():
    """
    Get the SSH client from main module.
    Uses lazy import to avoid circular dependency.
    """
    try:
        from backend.main import get_active_ssh_client
        return get_active_ssh_client()
    except (ImportError, AttributeError):
        # Fallback: try the mobile_analyzer's reference
        try:
            from backend.mobile_analyzer import get_ssh_client
            return get_ssh_client()
        except ImportError:
            return None


def _ssh_exec(command: str, timeout: int = 30) -> str:
    """Run a command via SSH and return combined output."""
    client = _get_ssh()
    if not client:
        return "ERROR: No SSH connection available. Connect via WebSocket first."
    try:
        transport = client.get_transport()
        if not transport or not transport.is_active():
            return "ERROR: SSH transport is not active"
        chan = transport.open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        stdout = chan.recv(65536).decode("utf-8", errors="replace")
        stderr = chan.recv_stderr(65536).decode("utf-8", errors="replace") if hasattr(chan, 'recv_stderr') else ""
        chan.close()
        return stdout + stderr
    except Exception as e:
        logger.error("SSH exec failed: %s", e)
        return f"ERROR: {e}"


def _ssh_sftp_upload(local_path: str, remote_path: str) -> bool:
    """Upload a file via SFTP."""
    client = _get_ssh()
    if not client:
        return False
    try:
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        return True
    except Exception as e:
        logger.error("SFTP upload failed: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  ADB DEVICE MANAGEMENT
# ════════════════════════════════════════════════════════════════

def list_devices() -> list:
    """List ADB devices connected to Kali."""
    output = _ssh_exec("adb devices -l 2>/dev/null")
    if output.startswith("ERROR"):
        return []

    devices = []
    for line in output.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) >= 2 and "device" in parts[1]:
            device = {"serial": parts[0], "state": parts[1]}
            extra = " ".join(parts[2:])
            m = re.search(r'model:(\S+)', extra)
            if m:
                device["model"] = m.group(1)
            m = re.search(r'device:(\S+)', extra)
            if m:
                device["device"] = m.group(1)
            m = re.search(r'transport_id:(\S+)', extra)
            if m:
                device["transport_id"] = m.group(1)
            devices.append(device)
    return devices


def connect_device(serial: str = None) -> str:
    """Connect ADB to a device or emulator."""
    if serial:
        return _ssh_exec(f"adb connect {serial}", timeout=15)
    return _ssh_exec("adb devices", timeout=10)


def install_apk(device_serial: str, apk_path: str) -> str:
    """Install an APK on a connected device."""
    return _ssh_exec(f"adb -s {device_serial} install -r {apk_path}", timeout=120)


# ════════════════════════════════════════════════════════════════
#  FRIDA SCRIPT MANAGEMENT
# ════════════════════════════════════════════════════════════════

def get_available_scripts() -> list:
    """List available Frida scripts (local + remote defaults)."""
    scripts = []
    seen = set()

    # Scan local frida scripts directory
    if os.path.exists(FRIDA_SCRIPTS_DIR):
        for f in os.listdir(FRIDA_SCRIPTS_DIR):
            if f.endswith(".js"):
                desc = "Custom Frida script"
                for s in FRIDA_SCRIPTS_META:
                    if s["name"] == f:
                        desc = s["description"]
                        break
                scripts.append({"name": f, "description": desc})
                seen.add(f)

    # Add built-in scripts not yet on disk
    for s in FRIDA_SCRIPTS_META:
        if s["name"] not in seen:
            scripts.append(s)

    return scripts


def run_frida_script(device_serial: str, script_name: str, target_process: str = None) -> str:
    """
    Run a Frida script on a device via Kali SSH.
    Uploads the script, then executes frida CLI.
    """
    # Determine script path
    script_path = os.path.join(FRIDA_SCRIPTS_DIR, script_name)
    remote_script = f"/tmp/vfrida_{script_name}"

    # Create remote dir
    _ssh_exec("mkdir -p /tmp/vfrida_scripts", timeout=5)

    # Upload script if it exists locally
    if os.path.exists(script_path):
        uploaded = _ssh_sftp_upload(script_path, remote_script)
        if not uploaded:
            return "ERROR: Could not upload Frida script to Kali"
    else:
        # Script might already be on remote — check
        check = _ssh_exec(f"test -f {remote_script} && echo OK")
        if "OK" not in check:
            return f"ERROR: Script '{script_name}' not found locally or on Kali"

    # Build frida command
    if device_serial:
        base_cmd = f"frida -D {device_serial}"
    else:
        base_cmd = "frida -U"

    if target_process:
        cmd = f"{base_cmd} -f {target_process} -l {remote_script} --no-pause 2>&1"
    else:
        cmd = f"{base_cmd} -l {remote_script} 2>&1"

    # Execute with longer timeout for Frida
    output = _ssh_exec(cmd, timeout=60)
    return output[:5000]  # Limit output size
