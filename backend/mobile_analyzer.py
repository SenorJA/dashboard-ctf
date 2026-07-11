"""
VulnForge Mobile Lab — Static APK Analyzer.

Runs apktool, aapt, jadx via SSH on Kali Linux.
Falls back to local subprocess when SSH is unavailable.
"""

import os
import re
import json
import uuid
import hashlib
import subprocess
import shutil
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vulnforge.mobile")

# ── Analysis Rules ──

DANGEROUS_PERMISSIONS = {
    "CAMERA": "Access camera",
    "RECORD_AUDIO": "Record audio",
    "READ_SMS": "Read SMS",
    "SEND_SMS": "Send SMS",
    "READ_CONTACTS": "Read contacts",
    "WRITE_CONTACTS": "Write contacts",
    "READ_CALL_LOG": "Read call log",
    "ACCESS_FINE_LOCATION": "GPS location",
    "ACCESS_COARSE_LOCATION": "Network location",
    "READ_EXTERNAL_STORAGE": "Read external storage",
    "WRITE_EXTERNAL_STORAGE": "Write external storage",
    "INTERNET": "Internet access",
    "BIND_ACCESSIBILITY_SERVICE": "Accessibility service (keylogging risk)",
    "SYSTEM_ALERT_WINDOW": "Overlay on top of other apps",
    "REQUEST_INSTALL_PACKAGES": "Install unknown APKs",
    "READ_PHONE_STATE": "Read phone state / IMEI",
    "PROCESS_OUTGOING_CALLS": "Monitor outgoing calls",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Read notifications",
    "GET_ACCOUNTS": "Access device accounts",
    "USE_FINGERPRINT": "Use fingerprint hardware",
    "RECEIVE_BOOT_COMPLETED": "Run on boot",
}

SECRET_PATTERNS = [
    (r'(["\'"])https?://[^\s\'"]*api[^\s\'"]*\1', "API URL in code"),
    (r'(?i)(api[_-]?key|apikey|api_secret|apiSecret)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded API Key"),
    (r'(?i)(token|access_token|auth_token|bearer)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded Token"),
    (r'(?i)(password|passwd|pwd|secret)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded Credential"),
    (r'(?i)(jwt|eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)', "JWT Token in code"),
    (r'(sk-[A-Za-z0-9]{32,}|pk-[A-Za-z0-9]{32,})', "OpenAI API Key"),
    (r'(AKIA[0-9A-Z]{16})', "AWS Access Key"),
    (r'(-----BEGIN (RSA |EC )?PRIVATE KEY-----)', "Private Key embedded"),
]

WEAK_CRYPTO = [
    r'(?i)(DES|DESede)\s*[=(]',
    r'(?i)MD4',
    r'(?i)RC4',
    r'(?i)PBEWithMD5',
    r'(?i)Cipher\.getInstance\s*\(\s*["\'].*?ECB.*?["\']',
    r'(?i)SecretKeySpec\s*\(\s*[^,]+,\s*["\'](DES|DESede)["\']',
]

# ── In-memory store for analyzed APKs ──
_apk_store: dict = {}
_work_dir: str = "/tmp/vulnforge_mobile"

# ── SSH client reference (set by main.py after WS connects) ──
_ssh_client = None


def set_ssh_client(client):
    """Set the SSH client used for remote command execution."""
    global _ssh_client
    _ssh_client = client


def get_ssh_client():
    """Get the current SSH client."""
    return _ssh_client


def init_work_dir(base_dir: str = "/tmp/vulnforge_mobile"):
    """Initialize the working directory for mobile analysis."""
    global _work_dir
    _work_dir = base_dir
    try:
        os.makedirs(_work_dir, exist_ok=True)
        frida_dir = os.path.join(_work_dir, "frida")
        os.makedirs(frida_dir, exist_ok=True)
    except OSError:
        # On Windows / non-Linux, create locally
        _work_dir = os.path.join(os.path.dirname(__file__), "..", "tmp", "mobile")
        os.makedirs(_work_dir, exist_ok=True)
    return _work_dir


# ════════════════════════════════════════════════════════════════
#  COMMAND EXECUTION (local + SSH fallback)
# ════════════════════════════════════════════════════════════════

def _run_cmd_remote(command: str, timeout: int = 60) -> tuple:
    """Run a command via SSH on Kali. Returns (stdout, stderr)."""
    client = _ssh_client
    if not client:
        return "", "No SSH connection available"
    try:
        transport = client.get_transport()
        if not transport or not transport.is_active():
            return "", "SSH transport closed"
        chan = transport.open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        stdout = chan.recv(65536).decode("utf-8", errors="replace")
        stderr = chan.recv_stderr(65536).decode("utf-8", errors="replace") if hasattr(chan, 'recv_stderr') else ""
        chan.close()
        return stdout, stderr
    except Exception as e:
        logger.error("SSH command failed: %s", e)
        return "", str(e)


def _run_cmd_local(cmd: list, timeout: int = 60) -> tuple:
    """Run a local command, return (stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    except FileNotFoundError as e:
        return "", f"Tool not found: {e.filename}"
    except Exception as e:
        return "", str(e)


def _run_cmd(cmd_str_or_list, timeout: int = 60, use_ssh: bool = True) -> tuple:
    """
    Run a command — prefer SSH (Kali) when available, fall back to local.
    If cmd_str_or_list is a string, run via SSH.
    If it's a list, try local first, then SSH.
    Returns (stdout, stderr).
    """
    if isinstance(cmd_str_or_list, str):
        # String command → always SSH
        if use_ssh and _ssh_client:
            return _run_cmd_remote(cmd_str_or_list, timeout)
        return _run_cmd_local(cmd_str_or_list.split(), timeout)

    # List command → try local first, fallback to SSH
    stdout, stderr = _run_cmd_local(cmd_str_or_list, timeout)
    if not stdout and "Tool not found" in stderr and _ssh_client:
        # Tool not available locally, try SSH
        remote_cmd = " ".join(cmd_str_or_list)
        stdout, stderr = _run_cmd_remote(remote_cmd, timeout)
    return stdout, stderr


def _ssh_upload_file(local_path: str, remote_path: str) -> bool:
    """Upload a file via SFTP."""
    if not _ssh_client:
        return False
    try:
        sftp = _ssh_client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        return True
    except Exception as e:
        logger.error("SFTP upload failed: %s", e)
        return False


def _ssh_download_file(remote_path: str, local_path: str) -> bool:
    """Download a file via SFTP."""
    if not _ssh_client:
        return False
    try:
        sftp = _ssh_client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        return True
    except Exception as e:
        logger.error("SFTP download failed: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  HASHING & PARSING
# ════════════════════════════════════════════════════════════════

def _compute_hashes(filepath: str) -> dict:
    """Compute MD5 and SHA256 of a local file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _parse_aapt_output(aapt_out: str) -> dict:
    """Parse aapt dump badging output for APK metadata."""
    info = {}
    for line in aapt_out.split("\n"):
        if line.startswith("package:"):
            m = re.search(r"name='([^']+)'", line)
            if m:
                info["package"] = m.group(1)
            m = re.search(r"versionCode='([^']+)'", line)
            if m:
                info["version_code"] = m.group(1)
            m = re.search(r"versionName='([^']+)'", line)
            if m:
                info["version_name"] = m.group(1)
        elif line.startswith("sdkVersion:"):
            info["min_sdk"] = line.split(":")[1].strip()
        elif line.startswith("targetSdkVersion:"):
            info["target_sdk"] = line.split(":")[1].strip()
    return info


def _parse_manifest_for_permissions(manifest_path: str) -> list:
    """Extract permissions from AndroidManifest.xml."""
    perms = []
    if not os.path.exists(manifest_path):
        return perms
    with open(manifest_path, "r", errors="replace") as f:
        content = f.read()
    for perm in re.findall(r'android\.permission\.(\w+)', content):
        if perm not in perms:
            perms.append(perm)
    return perms


def _parse_manifest_components(manifest_path: str) -> dict:
    """Extract exported components from AndroidManifest.xml."""
    comps = {"activities": [], "services": [], "providers": [], "receivers": []}
    if not os.path.exists(manifest_path):
        return comps
    with open(manifest_path, "r", errors="replace") as f:
        content = f.read()

    for tag, key in [
        ("<activity", "activities"),
        ("<service", "services"),
        ("<provider", "providers"),
        ("<receiver", "receivers"),
    ]:
        for m in re.finditer(rf'{tag}[^>]*>', content):
            block = m.group()
            exported = 'android:exported="true"' in block
            name_m = re.search(r'android:name="([^"]+)"', block)
            name = name_m.group(1) if name_m else "?"
            comps[key].append({"name": name, "exported": exported})

    return comps


def _walk_smali_files(smali_dir: str):
    """Yield (filepath, relative_path, content) for all .smali files."""
    if not os.path.exists(smali_dir):
        return
    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
                rel = os.path.relpath(fpath, smali_dir)
                yield fpath, rel, content
            except Exception:
                continue


# ════════════════════════════════════════════════════════════════
#  VULNERABILITY CHECKS
# ════════════════════════════════════════════════════════════════

def _check_webview_insecurities(smali_dir: str) -> list:
    """Scan smali for insecure WebView usage."""
    findings = []
    for _, rel, content in _walk_smali_files(smali_dir):
        if re.search(r'setJavaScriptEnabled\s*\(\s*true\s*\)', content):
            findings.append({
                "severity": "high",
                "title": "WebView with JavaScript Enabled",
                "description": f"JavaScript is enabled in a WebView at {rel}. This can lead to XSS if user input reaches the WebView.",
                "category": "webview",
                "file": rel,
            })
        if re.search(r'setAllowFileAccess\s*\(\s*true\s*\)', content):
            findings.append({
                "severity": "medium",
                "title": "WebView with File Access",
                "description": f"File access is enabled in WebView at {rel}. Allows reading internal files.",
                "category": "webview",
                "file": rel,
            })
    return findings


def _check_secrets_in_smali(smali_dir: str) -> list:
    """Search for hardcoded secrets in smali files."""
    findings = []
    seen = set()
    for _, rel, content in _walk_smali_files(smali_dir):
        for pattern, desc in SECRET_PATTERNS:
            for i, line in enumerate(content.split("\n")):
                if re.search(pattern, line):
                    key = f"{rel}:{desc}"
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "severity": "critical",
                            "title": desc,
                            "description": f"Potential secret found in {rel}:{i+1}. Review this value.",
                            "category": "secrets",
                            "file": f"{rel}:{i+1}",
                        })
                    break
    return findings


def _check_weak_crypto(smali_dir: str) -> list:
    """Search for weak cryptography usage."""
    findings = []
    seen = set()
    for _, rel, content in _walk_smali_files(smali_dir):
        for pattern in WEAK_CRYPTO:
            if re.search(pattern, content):
                if rel not in seen:
                    seen.add(rel)
                    findings.append({
                        "severity": "high",
                        "title": "Weak Cryptography Algorithm",
                        "description": f"Use of weak crypto algorithm detected in {rel}. Consider using AES-GCM or ChaCha20.",
                        "category": "crypto",
                        "file": rel,
                    })
                break
    return findings


def _check_root_detection(smali_dir: str) -> list:
    """Check for root detection mechanisms."""
    patterns = [
        (r'(?i)(su|Superuser\.apk|magisk|rootbeer|rootBeer)', "Root detection library"),
        (r'(?i)(build\.TAGS.*test-keys|com\.devadvance\.rootchecker)', "Root check mechanism"),
    ]
    findings = []
    seen = set()
    for _, rel, content in _walk_smali_files(smali_dir):
        for pat, desc in patterns:
            if re.search(pat, content):
                if rel not in seen:
                    seen.add(rel)
                    findings.append({
                        "severity": "info",
                        "title": f"Root Detection: {desc}",
                        "description": "Root detection may block dynamic analysis or debugging. Can be bypassed with Frida.",
                        "category": "root_detection",
                        "file": rel,
                    })
                break
    return findings


def _check_strings_for_secrets(res_dir: str) -> list:
    """Search resource XML files for hardcoded secrets."""
    findings = []
    if not os.path.exists(res_dir):
        return findings
    import base64
    for root, _, files in os.walk(res_dir):
        for fname in files:
            if not fname.endswith(".xml"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            # Look for suspicious strings
            for pat, desc in SECRET_PATTERNS:
                if re.search(pat, content):
                    findings.append({
                        "severity": "high",
                        "title": f"Secret in Resources: {desc}",
                        "description": f"Potential secret found in resource file {fname}. Resources are easily extractable.",
                        "category": "secrets",
                        "file": fname,
                    })
                    break
            # Look for base64-encoded data
            b64_matches = re.findall(r'([A-Za-z0-9+/=]{40,})', content)
            for b in b64_matches[:3]:
                try:
                    decoded = base64.b64decode(b)
                    if any(32 <= c < 128 for c in decoded):
                        findings.append({
                            "severity": "medium",
                            "title": "Possible Base64-Encoded Data in Resources",
                            "description": f"Long base64 string found in {fname}. May contain encoded secrets or configuration.",
                            "category": "secrets",
                            "file": fname,
                        })
                except Exception:
                    pass
    return findings


def _check_manifest_flags(manifest_path: str) -> list:
    """Check AndroidManifest.xml for insecure flags."""
    findings = []
    if not os.path.exists(manifest_path):
        return findings
    with open(manifest_path, "r", errors="replace") as f:
        content = f.read()
    if 'android:allowBackup="true"' in content:
        findings.append({
            "severity": "medium",
            "title": "Backup Enabled (allowBackup)",
            "description": "android:allowBackup=true allows users to backup app data via ADB. Sensitive data could be extracted.",
            "category": "manifest",
            "file": "AndroidManifest.xml",
        })
    if 'android:debuggable="true"' in content:
        findings.append({
            "severity": "high",
            "title": "App is Debuggable",
            "description": "android:debuggable=true allows debugging the app. Should be false for release builds.",
            "category": "manifest",
            "file": "AndroidManifest.xml",
        })
    if 'android:usesCleartextTraffic="true"' in content:
        findings.append({
            "severity": "high",
            "title": "Cleartext HTTP Traffic Allowed",
            "description": "android:usesCleartextTraffic=true allows unencrypted HTTP traffic. Sensitive data may be intercepted.",
            "category": "manifest",
            "file": "AndroidManifest.xml",
        })
    return findings


def _check_ssl_pinning(smali_dir: str) -> list:
    """Check for SSL pinning implementation."""
    has_pinning = False
    patterns_ok = [r'(?i)(CertificatePinner|pinning|TrustManager|sslPinning|SSLPinning)']
    for _, _, content in _walk_smali_files(smali_dir):
        for pat in patterns_ok:
            if re.search(pat, content):
                has_pinning = True
                break
        if has_pinning:
            break
    if not has_pinning:
        return [{
            "severity": "medium",
            "title": "No SSL Pinning Detected",
            "description": "The app does not appear to implement SSL certificate pinning. This makes MITM attacks easier.",
            "category": "ssl",
            "file": "smali_analysis",
        }]
    return []


# ════════════════════════════════════════════════════════════════
#  MAIN ANALYSIS PIPELINE
# ════════════════════════════════════════════════════════════════

def analyze_apk(apk_path: str, apk_id: str = None) -> dict:
    """
    Full static analysis of an APK file.
    Runs aapt/apktool via SSH when available, falls back to local.
    Returns structured result with findings.
    """
    if not apk_id:
        apk_id = str(uuid.uuid4())[:8]

    extract_dir = os.path.join(_work_dir, f"extract_{apk_id}")

    result = {
        "apk_id": apk_id,
        "package": "",
        "version_name": "",
        "version_code": "",
        "min_sdk": "",
        "target_sdk": "",
        "findings": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "permissions": [],
        "components": {},
        "error": None,
    }

    # Step 1: Hashes + basic info (local file)
    try:
        hashes = _compute_hashes(apk_path)
        result["md5"] = hashes["md5"]
        result["sha256"] = hashes["sha256"]
        result["size"] = os.path.getsize(apk_path)
        result["filename"] = os.path.basename(apk_path)
    except Exception as e:
        result["error"] = f"Cannot read file: {e}"
        _apk_store[apk_id] = result
        return result

    # Step 2: Try aapt for APK metadata
    # If SSH is available, upload APK and run aapt remotely
    remote_apk = f"/tmp/vulnforge_mobile/{apk_id}.apk"
    used_ssh = False

    if _ssh_client:
        try:
            logger.info("Uploading APK to Kali for analysis: %s", apk_path)
            _ssh_upload_file(apk_path, remote_apk)
            used_ssh = True
            # Create work dir on remote
            _run_cmd_remote(f"mkdir -p /tmp/vulnforge_mobile/extract_{apk_id}")
        except Exception as e:
            logger.warning("SSH upload failed, trying local: %s", e)
            used_ssh = False

    if used_ssh:
        # Run aapt remotely
        stdout, stderr = _run_cmd_remote(
            f"aapt dump badging {remote_apk} 2>/dev/null", timeout=30
        )
    else:
        # Try locally
        stdout, stderr = _run_cmd_local(["aapt", "dump", "badging", apk_path], timeout=30)

    if stdout:
        info = _parse_aapt_output(stdout)
        result.update(info)
    else:
        result["error"] = f"aapt failed: {stderr[:200]}"

    # Step 3: Extract with apktool
    remote_extract = f"/tmp/vulnforge_mobile/extract_{apk_id}"
    if not os.path.exists(extract_dir) or not os.listdir(extract_dir) if os.path.exists(extract_dir) else True:
        if used_ssh:
            stdout, stderr = _run_cmd_remote(
                f"apktool d -f -o {remote_extract} {remote_apk}", timeout=120
            )
            # Download the extracted manifest for local analysis
            os.makedirs(extract_dir, exist_ok=True)
            _ssh_download_file(f"{remote_extract}/AndroidManifest.xml",
                               os.path.join(extract_dir, "AndroidManifest.xml"))
            # Download smali dir listing (we'll analyze strings locally)
            _run_cmd_remote(
                f"find {remote_extract}/smali -name '*.smali' | head -500 > /tmp/vf_smali_list_{apk_id}.txt",
                timeout=30
            )
            # Download smali files for local analysis
            smali_list_out, _ = _run_cmd_remote(
                f"cat /tmp/vf_smali_list_{apk_id}.txt", timeout=10
            )
            local_smali_dir = os.path.join(extract_dir, "smali")
            os.makedirs(local_smali_dir, exist_ok=True)
            for smali_path in smali_list_out.strip().split("\n"):
                if not smali_path.strip():
                    continue
                fname = os.path.basename(smali_path.strip())
                local_smali_path = os.path.join(local_smali_dir, fname)
                _ssh_download_file(smali_path.strip(), local_smali_path)
            # Download res/values for string analysis
            _run_cmd_remote(
                f"cp -r {remote_extract}/res/values {extract_dir}/res_values 2>/dev/null",
                timeout=10,
            )
            _run_cmd_remote(
                f"cp -r {remote_extract}/res {extract_dir}/res 2>/dev/null",
                timeout=10,
            )
        else:
            stdout, stderr = _run_cmd_local(
                ["apktool", "d", "-f", "-o", extract_dir, apk_path], timeout=120
            )
            if not os.path.exists(extract_dir):
                result["error"] = f"apktool extraction failed: {stderr[:300]}"
                _apk_store[apk_id] = result
                return result

    # ── Paths for analysis ──
    manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
    smali_dir = os.path.join(extract_dir, "smali")
    res_dir = os.path.join(extract_dir, "res", "values")
    res_dir_alt = os.path.join(extract_dir, "res")

    # Step 4: Permissions from manifest
    if os.path.exists(manifest_path):
        perms = _parse_manifest_for_permissions(manifest_path)
        result["permissions"] = perms
        for p in perms:
            for key, desc in DANGEROUS_PERMISSIONS.items():
                if key in p or p.endswith("." + key):
                    result["findings"].append({
                        "severity": "medium",
                        "title": f"Dangerous Permission: {key}",
                        "description": f"The app requests {desc} ({p}). Review if this permission is necessary.",
                        "category": "permissions",
                        "file": "AndroidManifest.xml",
                    })
                    break

    # Step 5: Components from manifest
    if os.path.exists(manifest_path):
        comps = _parse_manifest_components(manifest_path)
        result["components"] = comps
        for comp_type in ["activities", "services", "providers", "receivers"]:
            for comp in comps.get(comp_type, []):
                if comp.get("exported"):
                    result["findings"].append({
                        "severity": "high",
                        "title": f"Exported {comp_type[:-1].title()}: {comp['name']}",
                        "description": f"The {comp_type[:-1].lower()} '{comp['name']}' is exported. Any app can launch it.",
                        "category": "components",
                        "file": "AndroidManifest.xml",
                    })

    # Step 6: Manifest security flags
    if os.path.exists(manifest_path):
        result["findings"].extend(_check_manifest_flags(manifest_path))

    # Step 7: WebView insecurities
    result["findings"].extend(_check_webview_insecurities(smali_dir))

    # Step 8: Hardcoded secrets in smali
    result["findings"].extend(_check_secrets_in_smali(smali_dir))

    # Step 9: Secrets in resource strings
    target_res = res_dir if os.path.exists(res_dir) else res_dir_alt
    result["findings"].extend(_check_strings_for_secrets(target_res))

    # Step 10: Weak crypto
    result["findings"].extend(_check_weak_crypto(smali_dir))

    # Step 11: Root detection
    result["findings"].extend(_check_root_detection(smali_dir))

    # Step 12: SSL Pinning
    result["findings"].extend(_check_ssl_pinning(smali_dir))

    # Step 13: Compute summary
    for f in result["findings"]:
        sev = f.get("severity", "info")
        if sev in result["summary"]:
            result["summary"][sev] += 1

    # Store
    _apk_store[apk_id] = result
    logger.info("Analysis complete for %s — %d findings", apk_id, len(result["findings"]))
    return result


# ════════════════════════════════════════════════════════════════
#  CRUD HELPERS
# ════════════════════════════════════════════════════════════════

def list_apks() -> list:
    """List all analyzed APKs (summary view)."""
    return [
        {
            "apk_id": k,
            "filename": v.get("filename", ""),
            "package": v.get("package", ""),
            "version_name": v.get("version_name", ""),
            "version_code": v.get("version_code", ""),
            "size": v.get("size", 0),
            "findings_count": len(v.get("findings", [])),
            "summary": v.get("summary", {}),
        }
        for k, v in _apk_store.items()
    ]


def get_apk(apk_id: str) -> Optional[dict]:
    """Get full analysis result for an APK."""
    return _apk_store.get(apk_id)


def delete_apk(apk_id: str) -> bool:
    """Delete APK analysis and cleanup extracted files."""
    if apk_id not in _apk_store:
        return False

    del _apk_store[apk_id]

    # Clean up local extracted files
    extract_dir = os.path.join(_work_dir, f"extract_{apk_id}")
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir, ignore_errors=True)

    # Clean up remote extracted files
    if _ssh_client:
        _run_cmd_remote(f"rm -rf /tmp/vulnforge_mobile/extract_{apk_id}", timeout=10)
        _run_cmd_remote(f"rm -f /tmp/vulnforge_mobile/{apk_id}.apk", timeout=10)

    return True
