---
name: memory-forensics
description: "Memory forensics with Volatility3. Process extraction, network connections, injected code, malware artifacts from memory dumps."
category: forensics
allowed_tools:
  - volatility3
  - vol3
  - lime
  - strings
  - yara
  - gdb
version: "1.0.0"
author: "MIRV"
---

# Memory Forensics Methodology

## 1. When to Use
- A suspicious process is observed and you need to inspect its memory-resident artefacts (injected code, hidden threads).
- A system is compromised but disk artefacts were wiped, leaving memory as the only evidence source.
- Malware is suspected to be fileless (PowerShell, .NET in-memory, reflective DLL injection).
- You must extract credentials, keys, or network connections that only exist in RAM.
- An incident response requires reconstructing attacker activity from a live triage image.

## 2. Prerequisites
- Volatility 3 (`pip install volatility3`) available on the analysis workstation.
- A memory image acquired with a trusted tool: `LiME` (Linux), `winpmem` / `DumpIt` (Windows), or a hypervisor snapshot.
- Sufficient disk space (image is typically 50-100% of physical RAM).
- A symbol table matching the OS/kernel of the dump (Volatility 3 symbol store or `vol3 -s symbols/`).
- `yara` ruleset (e.g. Didier Stevens' pack or your own IOCs) for signature scanning.
- Chain-of-custody form and read-only mount of the image to prevent accidental writes.

## 3. Workflow
1. **Verify image integrity**
   - `sha256sum {image}` and record the hash in the case file before any plugin runs.
   - Mount the image read-only (`mount -o ro,loop {image} /mnt/mem`) if you must access it as a file.
2. **Identify the profile**
   - `vol3 -f {image} windows.info` (or `linux.info` / `mac.info`) to confirm OS, build, and kernel version.
   - If the symbol table is missing, download the matching ISF and place it under `volatility3/symbols/`.
3. **Process enumeration**
   - `vol3 -f {image} windows.pslist` — EPROCESS doubly-linked list (easy to evade).
   - `vol3 -f {image} windows.psscan` — pool-scanning, finds unlinked/hidden processes.
   - `vol3 -f {image} windows.pstree` — parent/child tree to spot orphaned or reparented processes.
   - Diff `pslist` vs `psscan`: processes present only in `psscan` are strong candidates for DKOM hiding.
4. **Network artefacts**
   - `vol3 -f {image} windows.netscan` (Win10+) or `vol3 -f {image} windows.netstat` to list sockets and connections.
   - Correlate each connection's PID with the process tree; flag unknown destinations and beaconing intervals.
5. **Code injection & malware**
   - `vol3 -f {image} windows.malfind` — detect `MZ`/`PAGE_EXECUTE_READWRITE` regions that indicate injected shellcode/DLLs.
   - `vol3 -f {image} windows.dlllist` and `windows.handles` per suspicious PID to enumerate loaded modules and resources.
   - Dump the suspect process: `vol3 -f {image} -o dumps/ windows.memmap --pid {pid} --dump`.
   - `vol3 -f {image} windows.cmdline --pid {pid}` and `windows.cmdscan` to recover executed commands.
6. **File & registry recovery**
   - `vol3 -f {image} windows.filescan` then `windows.dumpfiles --physaddr {addr}` to recover malware dropped to disk.
   - `vol3 -f {image} windows.registry.hivelist` + `windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"` for persistence.
7. **YARA & strings**
   - `vol3 -f {image} windows.vadinfo --pid {pid}` to enumerate VAD regions, then `yara -r rules.yar dumps/`.
   - `strings -a -t x {image} | grep -iE "http|powershell|cmd\.exe|base64"` for quick triage leads.
8. **Decision point**: if `malfind` flags a region and YARA matches a known malware family, escalate to reverse-engineering the dumped binary with `gdb`/IDA and freeze the host from the network.

## 4. Verification
- Confirm each IOC with at least two independent plugins (e.g. `malfind` + `yara`, or `psscan` + `netscan`).
- Map every artefact to a MITRE ATT&CK technique:
  - T1055 Process Injection → `malfind` RWX regions.
  - T1003 Credential Dumping → `lsadump`/`hashdump` output.
  - T1571 C2 Channel → anomalous `netscan` destinations.
  - T1547 Boot/Logon Autostart → registry Run keys recovered from hive dumps.
- Compare recovered IOCs against your SIEM/EDR telemetry for the same time window to validate the timeline.
- Produce a findings table `{pid, artefact, plugin, technique, confidence}` and attach the dumped binaries as evidence.

## IMPORTANT
- Only analyse memory images from systems you are authorised to investigate (owned, engagement scope, or IR retainer).
- Preserve evidence chain: hash the image, store on WORM media if available, and log every plugin invocation with timestamp and operator.
- Treat `{target}` and `{image}` placeholders literally — never substitute unvalidated paths.
- Never execute binaries extracted from memory on a production host; analyse them in an isolated sandbox.
- Redact credentials/keys recovered from memory in any shared report (MIRV `redact.py` applies on mission save).
- Volatility plugins can take hours on large images — run them on a dedicated analysis VM, not the analyst's laptop.
