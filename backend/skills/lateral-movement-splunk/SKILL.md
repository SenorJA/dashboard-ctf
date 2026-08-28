---
name: lateral-movement-splunk
description: "Detect lateral movement with Splunk. SMB/WinRM/RDP patterns, pass-the-hash, Kerberos ticket abuse."
category: defense
allowed_tools:
  - splunk
  - syslog
  - python
  - sysmon
version: "1.0.0"
author: "MIRV"
---

# Lateral Movement Detection with Splunk Methodology

## 1. When to Use
- An EDR/IDS alert references a process spawned on a remote host (PsExec, WMI, WinRM).
- A user account shows logons to many hosts in a short window outside their normal pattern.
- Post-compromise triage to scope how far an attacker moved from patient zero.
- A red-team report claims lateral movement and you must validate detection coverage.
- Kerberos ticket anomalies (overpass-the-hash, golden ticket) are suspected.

## 2. Prerequisites
- Splunk index with Windows Security (4624, 4625, 4672, 4688, 4624 type 3/10), Sysmon (1, 3, 5, 7, 11, 22), PowerShell (4104), and Kerberos (4768, 4769, 4770) events.
- Domain Controller logs forwarded to Splunk (essential for Kerberos analysis).
- `python` for Splunk REST queries and CSV post-processing.
- A baseline of normal user logon patterns (typical hosts, hours, geos) per user.
- Authorisation for IR scope and a documented chain of custody.
- Sigma rules for lateral movement (`win_lateral_movement_*`) imported into Splunk as SPL.

## 3. Workflow
1. **SMB share access (T1021.002 / T1077)**
   - `index=wineventlog EventCode=5140 OR EventCode=5145 | stats count by ComputerName, SubjectUserName, ShareName, _time | sort _time`.
   - Flag admin shares (`C$`, `ADMIN$`, `IPC$`) accessed by a user outside their normal host set.
   - Event 5145 (detailed file share) reveals the file written — correlate with `*.exe` / `*.bat` / `*.ps1` writes for tool staging.
   - Sysmon Event 11 (file create) on the target host in the same window confirms dropped payload.
2. **WinRM / WMI remote execution (T1021.006 / T1047)**
   - WinRM: `EventCode=4624 LogonType=3 AuthenticationPackageName=Negotiate LogonProcessName=WSMAP` on port 5985/5986.
   - Sysmon Event 3 (network connection) to `:5985` from a user workstation (not a management box).
   - WMI: Sysmon Event 1 `ParentImage=wmiprvse.exe` spawning `cmd.exe`/`powershell.exe` on the target host.
   - Event 4648 (explicit credential logon) with `ProcessName=wsmprovhost.exe` indicates WinRM with `-Credential`.
3. **RDP (T1021.001)**
   - `EventCode=4624 LogonType=10` (RemoteInteractive) — interactive RDP logon.
   - `EventCode=1149` (TerminalServices) for the source IP; correlate with VPN logs for the geo.
   - Sysmon Event 3 to `:3389` from a user host → if the user has never RDP'd before, high risk.
   - Flag RDP from outside corporate geo or outside business hours.
4. **Pass-the-hash / pass-the-ticket (T1075 / T1550)**
   - **PTH**: Event 4624 `LogonType=3 AuthenticationPackageName=NTLM LogonProcessName=NtLmSsp` from a user to many hosts in <5 min — NTLM across the estate is the PTH signature.
   - **Overpass-the-hash**: Kerberos TGT request (Event 4768) immediately after NTLM logon, with `TicketEncryptionType=0x12` (AES) where the user historically used RC4.
   - **Pass-the-ticket**: Event 4769 (TGS request) for a service the user has never requested, from a host they have never used.
   - `kerberos_event_id IN (4768,4769,4770)` per user per minute — bursts > 10/min are anomalous.
5. **Golden / silver ticket (T1558.001 / T1558.002)**
   - Golden ticket: TGT (Event 4768) for a user with no matching 4766 failure, but the user does not exist or was disabled (check `EventCode=4726` account deletion).
   - RC4-HMAC (`0x17`) tickets for accounts that should use AES — attacker forged with RC4 krbtgt hash.
   - Silver ticket: TGS (Event 4769) for an SPN from a host that never requests it, no prior TGT (4768) for that user in the window.
6. **Scheduled task / service remote creation (T1053 / T1543)**
   - `EventCode=4698` (task create) with `TaskName` matching attacker pattern AND `Creator` from a remote host (correlate 4624 type 3 in the same second).
   - `EventCode=7045` (service install) with `ServiceName` not in baseline, `ImagePath` in user-writable dir.
   - PsExec: Sysmon Event 1 `Image=psexesvc.exe` + Event 3 from the source host on `:445`.
7. **Anomaly scoring**
   - Per user: `dc(host)`, `dc(target_host)`, `count(LoadLibrary)` for `*mimikatz*`, earliest/latest logon.
   - Compare against the user's 30-day baseline; flag `z-score > 3` on host count or off-hours activity.
8. **Decision point**: if a user shows NTLM logons to > 5 new hosts in < 10 min OR a TGS request for an SPN from a never-seen host, treat as confirmed lateral movement, isolate the source host, and rotate the user's credentials.

## 4. Verification
- Confirm each indicator with at least two independent events (e.g. 4624 type 3 + Sysmon Event 3, or 4769 + 4770).
- Map findings to MITRE ATT&CK **TA0008 Lateral Movement**:
  - **T1021.001** RDP.
  - **T1021.002** SMB/Windows Admin Shares.
  - **T1021.006** WinRM.
  - **T1047** WMI.
  - **T1077** Windows Admin Shares (deprecated, use T1021.002).
  - **T1550.002** Pass the Hash.
  - **T1558.001** Golden Ticket.
  - **T1558.002** Silver Ticket.
  - **T1053.005** Scheduled Task (remote).
- Validate detection coverage by replaying Atomic Red Team T1021.001/T1550.002 in a lab and confirming the SPL alerts fire.
- Build a per-user drift report: `{user, baseline_hosts, observed_hosts, new_hosts, technique, confidence}`.

## IMPORTANT
- Hunt only on systems and logs you are authorised to access (owned, IR scope, explicit retainer).
- Document every finding with timestamp, host, user, event IDs, and raw event XML — reproducibility is mandatory.
- Never share or store recovered hashes/tickets in plaintext; MIRV redaction masks them on mission save.
- Treat `{target}` / `{index}` / `{user}` placeholders literally — never substitute unvalidated values into SPL.
- Detection gaps are common: if a log source is missing (no DC logs, no Sysmon), lateral movement can be invisible — note coverage in the report.
- Before isolating a host in production, confirm it is not a critical server (DC, file server) without coordination.
- Re-running the hunt on a long time range can be expensive — scope the time window tightly around the suspected activity.
