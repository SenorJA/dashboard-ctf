---
name: ransomware-splunk
description: "Investigate ransomware with Splunk. Precursor detection, encryption events, recovery workflows."
category: defense
allowed_tools:
  - splunk
  - syslog
  - python
  - velharness
version: "1.0.0"
author: "MIRV"
---

# Ransomware Investigation with Splunk Methodology

## 1. When to Use
- A host displays mass file-extension changes (`.locked`, `.crypt`) and a ransom note appears.
- EDR alerts on a process performing rapid `WriteFile`/`CreateFile` operations across many directories.
- Backup servers were tampered with or VSS shadows deleted (`vssadmin delete shadows`).
- You must scope a ransomware incident across hundreds of hosts using centralised Splunk logs.
- Post-incident recovery requires mapping the precursor timeline (initial access → dwell → detonation).

## 2. Prerequisites
- Splunk index with Windows Security, Sysmon, PowerShell, and DNS logs (forwarded via UF/Heavy Forwarder).
- File-server audit logs (Event 4663 object access, 4656 handle request) for the affected shares.
- `velharness` (or Velociraptor) for live host triage if Splunk coverage is incomplete.
- `python` for Splunk REST queries (`splunk-sdk`) and CSV post-processing.
- A list of known ransomware IOCs (extension, ransom-note name, mutex, C2) for the suspected family.
- Authorisation for IR scope and a documented chain of custody for evidence preservation.
- A pre-staged containment runbook (network isolation, account disable, backup freeze).

## 3. Workflow
1. **Confirm detonation time & patient zero**
   - `index=wineventlog source="*Security" EventCode=4663 (ObjectName="*.locked" OR ObjectName="*README*.txt") | stats count by host, ComputerName, _time | sort _time | head 5`.
   - The earliest host + timestamp is patient zero; correlate with the user logged in at that moment (Event 4624).
   - Cross-check with Sysmon Event 1 (process create) on patient zero in the 30 min before detonation.
2. **Precursor TTPs (initial access & dwell)**
   - **T1566 Phishing**: Event 4624 type 9/10 (interactive) from an unusual geo, followed by Office child process (`winword.exe → cmd.exe`, Sysmon Event 1).
   - **T1190 Exploit Public App**: IIS/Apache logs with exploit URIs (`/cgi-bin/`) → webshell creation (Event 4663 write to `wwwroot`).
   - **T1078 Valid Accounts**: anomalous VPN logons from the same account in two geos (impossible travel).
   - **T1021 Remote Services**: SMB (445), WinRM (5985), RDP (3389) logons from patient zero to other hosts → lateral spread.
   - Build a `| makeresults` timeline of all precursor events sorted by `_time`.
3. **Encryption & impact events**
   - Mass file writes: `index=wineventlog EventCode=4663 AccessMask=0x2 | stats count by host, Image | sort -count` — a single process writing >10k files = ransomware.
   - VSS deletion: `source="*PowerShell" EventCode=4104 (ScriptBlockText="*vssadmin delete shadows*" OR ScriptBlockText="*wbadmin delete catalog*" OR ScriptBlockText="*bcdedit*")`.
   - Shadow copy deletion via `vssadmin` (Event 4663 on `vssvc.exe` spawning `vssadmin.exe`).
   - Service stop / Defender disable: `EventCode=7036` (`Microsoft Defender Antivirus Service stopped`) and `EventCode=5007` (Defender config changed).
4. **Lateral movement & credential abuse**
   - Pass-the-hash: Event 4624 type 3 with `AuthenticationPackageName=NTLM` and `LogonProcessName=NtLmSsp` from patient zero.
   - Kerberoasting / AS-REP: unusual `4769` (Kerberos ticket request) volume for SPNs with weak encryption (`0x17` RC4).
   - PsExec / WMI lateral: Sysmon Event 1 spawning `psexesvc.exe` or `wmiprvse.exe` with attacker command lines.
5. **Backup tampering**
   - Search backup server logs for service stops (`Event 7036` on `BackupExec`, `VeeamBackupSvc`), job deletions, and admin logons from non-admin accounts.
   - Veeam/Commvault REST API logs for bulk job deletion in the dwell window.
6. **IOC sweep & scoping**
   - Build an IOC list: ransom-note name, extension, mutex, C2 domains/IPs, dropped binary hashes.
   - `index=* (IOCs) | stats dc(host) as hosts by IOC` → scope of compromise across the estate.
   - Map each host to its last-known-good backup timestamp to prioritise recovery order.
7. **Recovery workflow**
   - Confirm backups are intact and offline-immutable BEFORE wiping any host (ransomware sometimes corrupts only live backups).
   - Recover from the last clean backup; do not pay ransom as a first option — coordinate with legal/law enforcement.
   - Re-image from golden image, rejoin domain with a new computer account, force password reset for every user who logged into affected hosts.
8. **Decision point**: if backups are confirmed compromised AND the family has no public decryptor, escalate to executive/legal for ransom decision; otherwise proceed with restore + rebuild.

## 4. Verification
- Confirm patient zero with at least two independent log sources (Security + Sysmon, or Splunk + EDR).
- Map findings to MITRE ATT&CK:
  - **TA0001** Initial Access (T1566/T1190).
  - **TA0008** Lateral Movement (T1021/T1077).
  - **TA0040** Impact (T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery).
  - **T1003** Credential Dumping (during dwell).
- Validate the family identification via the ransom-note content (ID Ransomware / NoMoreRansom) and the extension/mutex.
- Produce a per-host timeline `{_time, host, user, event, technique}` and a recovery tracker `{host, backup_status, restored?, validated?}`.

## IMPORTANT
- Containment first: isolate patient zero and known-compromised hosts before deep analysis — the ransomware may still be propagating.
- Preserve evidence: capture memory + disk images of patient zero BEFORE re-imaging; you lose attribution and detection-building material otherwise.
- Treat `{target}` / `{index}` placeholders literally — never substitute unvalidated values into SPL.
- Coordinate with legal: ransom payment, data-breach notification, and law-enforcement involvement have statutory deadlines.
- Do not run decryption tools on the only copy of encrypted data — test on a copy first.
- Redact user PII and credentials in any shared report; MIRV redaction applies on mission save.
- A Splunk "no results" search does NOT mean the event did not happen — verify log forwarding and retention for the window.
