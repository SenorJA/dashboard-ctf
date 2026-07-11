"""
VulnForge Forensics Lab — File, Memory, Network & Steganography Analysis.
"""

import os, re, json, uuid, hashlib, subprocess, tempfile
from typing import Optional

# ── In-memory store (fallback when no DB) ──
_evidence_store: dict = {}

def _compute_hashes(filepath: str) -> dict:
    md5 = hashlib.md5(); sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

def _run_local(cmd: list, timeout: int = 60) -> tuple[str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    except FileNotFoundError as e:
        return "", f"Tool not found: {e.filename}"
    except Exception as e:
        return "", str(e)

def _id_file(filepath: str) -> dict:
    """Identify file type using 'file' command."""
    stdout, stderr = _run_local(["file", filepath])
    if stdout:
        parts = stdout.split(":", 1)
        return {"type": parts[1].strip() if len(parts) > 1 else stdout.strip()}
    return {"type": "unknown", "error": stderr[:200]}

def _run_strings(filepath: str, min_len: int = 6) -> dict:
    """Extract strings from file, search for interesting patterns."""
    stdout, stderr = _run_local(["strings", "-n", str(min_len), filepath], timeout=120)
    findings = []
    interesting_patterns = [
        (r'flag\{[^}]+\}', "CTF Flag found", "critical"),
        (r'(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+', "Potential credential", "high"),
        (r'https?://[^\s<>"\'{}|\\^`]+', "URL found", "info"),
        (r'[\w.]+@[\w.]+\.\w+', "Email address", "info"),
        (r'(\d{1,3}\.){3}\d{1,3}', "IP address", "info"),
        (r'(?i)(ek|sk)-[A-Za-z0-9]{32,}', "Potential API key", "high"),
    ]
    if stdout:
        lines = stdout.split("\n")
        for i, line in enumerate(lines):
            for pat, desc, sev in interesting_patterns:
                if re.search(pat, line):
                    findings.append({
                        "severity": sev, "title": desc,
                        "description": f"Line {i+1}: {line.strip()[:200]}",
                        "category": "strings", "file": os.path.basename(filepath)
                    })
                    break
    return {"total_strings": len(stdout.split("\n")) if stdout else 0, "findings": findings}

def _run_binwalk(filepath: str) -> dict:
    """Scan for embedded files and signatures."""
    stdout, stderr = _run_local(["binwalk", filepath], timeout=120)
    findings = []
    if stdout:
        for line in stdout.split("\n"):
            if re.search(r'(Zlib|LZMA|PNG|JPEG|ELF|ext|filesystem)', line, re.I):
                findings.append({
                    "severity": "medium", "title": "Embedded file detected",
                    "description": line.strip()[:200], "category": "binwalk",
                    "file": os.path.basename(filepath)
                })
    return {"output": stdout[:3000], "findings": findings, "error": stderr[:200] if stderr else ""}

def _run_foremost(filepath: str, output_dir: str) -> dict:
    """Carve files from disk image."""
    os.makedirs(output_dir, exist_ok=True)
    stdout, stderr = _run_local(["foremost", "-o", output_dir, "-i", filepath], timeout=300)
    carved = 0
    for root, _, files in os.walk(output_dir):
        carved += len([f for f in files if f != "audit.txt"])
    return {"carved_files": carved, "output_dir": output_dir, "output": stdout[:2000]}

def _run_exiftool(filepath: str) -> dict:
    """Extract metadata from file."""
    stdout, stderr = _run_local(["exiftool", filepath], timeout=30)
    findings = []
    if stdout:
        interesting_tags = ["Creator", "Author", "Software", "GPS", "Comment", "Description"]
        for line in stdout.split("\n"):
            for tag in interesting_tags:
                if tag.lower() in line.lower() and ":" in line:
                    key, val = line.split(":", 1)
                    findings.append({
                        "severity": "info", "title": f"Metadata: {key.strip()}",
                        "description": val.strip()[:200], "category": "metadata",
                        "file": os.path.basename(filepath)
                    })
                    break
    return {"metadata": stdout[:5000], "findings": findings}

def _run_hexdump(filepath: str, max_bytes: int = 1024) -> dict:
    """Show first bytes as hexdump."""
    stdout, stderr = _run_local(["xxd", "-l", str(max_bytes), filepath], timeout=10)
    return {"hexdump": stdout[:5000]}

# ── Main analysis orchestrator ──

def analyze_file(filepath: str, category: str = "file") -> dict:
    """
    Run automatic analysis based on file category.
    Returns structured result with findings.
    """
    ev_id = str(uuid.uuid4())[:8]
    hashes = _compute_hashes(filepath)
    file_type = _id_file(filepath)
    size = os.path.getsize(filepath)
    fname = os.path.basename(filepath)

    result = {
        "id": ev_id,
        "filename": fname,
        "file_type": file_type.get("type", "unknown"),
        "category": category,
        "size": size,
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "analysis": {},
        "findings": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "error": None,
    }

    # Always run: file ID + strings
    strings_result = _run_strings(filepath)
    result["analysis"]["strings"] = {
        "total": strings_result.get("total_strings", 0),
    }
    result["findings"].extend(strings_result.get("findings", []))

    # Run exiftool always
    exif = _run_exiftool(filepath)
    result["analysis"]["metadata"] = exif.get("metadata", "")
    result["findings"].extend(exif.get("findings", []))

    # Category-specific analysis
    cat = category.lower()

    if cat == "disk" or cat == "image":
        bw = _run_binwalk(filepath)
        result["analysis"]["binwalk"] = bw.get("output", "")
        result["findings"].extend(bw.get("findings", []))

    elif cat == "memory":
        stdout, stderr = _run_local(["strings", filepath], timeout=60)
        result["analysis"]["memory_notes"] = "Memory dump detected. Use volatility3 for deep analysis."
        result["findings"].append({
            "severity": "info", "title": "Memory dump analysis available",
            "description": f"Run volatility3 on Kali for full memory forensics (pslist, netscan, hashdump, etc.)",
            "category": "memory", "file": fname
        })

    elif cat == "network" or cat == "pcap":
        stdout, stderr = _run_local(["strings", filepath], timeout=120)
        http_req = re.findall(r'(GET|POST|PUT|DELETE) /[\w/]+ HTTP', stdout or "")
        dns_q = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', stdout or "")
        creds = re.findall(r'(?i)(password|passwd|login|user)[=:]\s*\S+', stdout or "")
        result["analysis"]["network"] = {
            "http_requests": len(http_req),
            "dns_queries": len(set(dns_q)) if dns_q else 0,
            "potential_creds": len(creds),
        }
        if creds:
            result["findings"].append({
                "severity": "high", "title": "Potential credentials in PCAP",
                "description": f"Found {len(creds)} potential credential strings. Use tshark for deep inspection.",
                "category": "network", "file": fname
            })

    elif cat == "stego" or cat == "image":
        bw = _run_binwalk(filepath)
        result["analysis"]["binwalk"] = bw.get("output", "")
        result["findings"].extend(bw.get("findings", []))
        if fname.lower().endswith((".png", ".bmp")):
            stdout, stderr = _run_local(["zsteg", filepath], timeout=60)
            if stdout:
                result["analysis"]["zsteg"] = stdout[:3000]
                for line in stdout.split("\n"):
                    if "flag" in line.lower() or "secret" in line.lower():
                        result["findings"].append({
                            "severity": "critical", "title": "Hidden data detected via zsteg",
                            "description": line.strip()[:200], "category": "stego", "file": fname
                        })

    # Compute summary
    for f in result["findings"]:
        sev = f.get("severity", "info")
        if sev in result["summary"]:
            result["summary"][sev] += 1

    _evidence_store[ev_id] = result
    return result


def list_evidence() -> list:
    return [{
        "id": k, "filename": v.get("filename", ""),
        "file_type": v.get("file_type", ""), "category": v.get("category", ""),
        "size": v.get("size", 0), "summary": v.get("summary", {}),
        "created_at": v.get("created_at", ""),
    } for k, v in _evidence_store.items()]


def get_evidence(ev_id: str) -> Optional[dict]:
    return _evidence_store.get(ev_id)


def delete_evidence(ev_id: str) -> bool:
    if ev_id in _evidence_store:
        del _evidence_store[ev_id]
        return True
    return False


def run_tool(filepath: str, tool: str, params: dict = None) -> dict:
    """Run a specific forensic tool on a file."""
    if not os.path.exists(filepath):
        return {"error": "File not found"}
    params = params or {}
    if tool == "strings":
        min_len = params.get("min_len", 6)
        return _run_strings(filepath, min_len)
    elif tool == "exiftool":
        return _run_exiftool(filepath)
    elif tool == "binwalk":
        return _run_binwalk(filepath)
    elif tool == "hexdump":
        max_bytes = params.get("max_bytes", 1024)
        return _run_hexdump(filepath, max_bytes)
    elif tool == "foremost":
        out_dir = params.get("output_dir", tempfile.mkdtemp(prefix="foremost_"))
        return _run_foremost(filepath, out_dir)
    elif tool == "zsteg":
        stdout, stderr = _run_local(["zsteg", filepath], timeout=60)
        return {"output": stdout[:5000], "error": stderr[:200]}
    elif tool == "steghide":
        passphrase = params.get("passphrase", "")
        cmd = ["steghide", "extract", "-sf", filepath, "-p", passphrase, "-f"]
        stdout, stderr = _run_local(cmd, timeout=30)
        return {"output": stdout[:2000] + stderr[:2000]}
    else:
        return {"error": f"Unknown tool: {tool}"}
