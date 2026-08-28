---
name: threat-hunting-lsass
description: "Hunt for LSASS credential dumping. Detect mimikatz, procdump, comsvcs via Event Logs and Sysmon."
category: defense
allowed_tools:
  - syslog
  - sysmon
  - vol3
  - kAPE
  - hayabusa
  - chainsaw
version: "1.0.0"
author: "MIRV"
---

# Threat Hunting — LSASS Credential Dumping Methodology

## 1. When to Use
- An endpoint EDR/alert indicates unexpected access to `lsass.exe`.
- Credentials were observed in attacker tooling or C2 traffic, suggesting a dump occurred.
- Post-compromise triage of a Windows host to confirm/deny credential theft (T1003.001).
- Proactive hunting during a red-team exercise to measure blue-team detection coverage.
- A user reports anomalous logins and you suspect pass-the-hash from a dumped NTLM hash.

## 2. Prerequisites
- Windows Security Event Log (forwarded to Splunk/SIEM or local `.evtx`).
- Sysmon Event Log (Event ID 1, 7, 8, 10, 22) — Sysmon config must capture image-load and process-access.
- `hayabusa` (Rust EVTX triage) and/or `chainsaw` (Rust Sigma engine) for offline Sigma hunting.
- `kAPE` (Kroll Artifact Parser) for targeted evidence collection from a live or dead host.
- Volatility 3 with Windows symbols if a memory image is available for confirmation.
- Access to the Sigma rule pack (SigmaHQ `proc_access_win_mimikatz*`, `lsass_access_*`).
- Audit policy enabled: `Audit Process Creation`, `Audit Object Access` (kernel object → LSASS).

## 3. Workflow
1. **Triage EVTX with hayabusa**
   - `hayabusa csv-timeline -d {evtx_dir} -o lsass_timeline.csv --level informational -r rules/`
   - Filter to LSASS-relevant IDs: `grep -iE "lsass|Credential Dumping|T1003" lsass_timeline.csv`.
   - Look for `Alert` / `Critical` level hits first — these are high-fidelity Sigma matches.
2. **Security Event Log — access patterns**
   - **Event ID 4656** (handle requested to LSASS): filter `ObjectName == LSASS` and `AccessMask` containing `0x1010` (read memory + query info) or `0x1410` (the classic mimikatz mask).
   - **Event ID 4663** (access attempted): correlate with 4656 on the same `SubjectLogonId`.
   - **Event ID 4673** (sensitive privilege use): `SeDebugPrivilege` requested by a non-system process → strong indicator.
   - Flag any 4656 where `SubjectUserName` is not `SYSTEM`/`LOCAL SERVICE` and the process is not a known EDR/AV binary.
3. **Sysmon correlation**
   - **Event 1** (process create): `Image == lsass.exe` should never be spawned by a user process — spawn = injection attempt.
   - **Event 7** (image load): `lsass.exe` loading `mimissrv.dll`, `samlib.dll` (unexpected), or unsigned DLLs.
   - **Event 8** (remote thread creation into `lsass.exe`) → classic `CreateRemoteThread` credential theft.
   - **Event 10** (process access): `TargetImage == lsass.exe` with `GrantedAccess` containing `0x10`, `0x40`, `0x1410`, `0x1010` — correlate with known-good EDR GUIDs.
   - **Event 22** (DNS): LSASS or the dumper process resolving C2 domains after exfil.
4. **Known dumper tooling signatures**
   - **mimikatz**: Event 10 with `SourceImage` ending `mimikatz.exe`, or `sekurlsa::logonpasswords` in command line (Event 1).
   - **procdump**: `procdump.exe -ma lsass.exe out.dmp` (Event 1 cmdline); `-ma` flag on `lsass.exe` is a hard alert.
   - **comsvcs.dll**: `rundll32 comsvcs.dll MiniDump {pid} out.dmp full` — silent and frequently abused, watch for `rundll32` + `MiniDump`.
   - **taskmgr**: GUI "Create dump file" on lsass — Event 10 access from `Taskmgr.exe` by an interactive user.
   - **nanodump / lsassy / PPLdump**: variants — match by `GrantedAccess` mask + unsigned module load (Event 7).
5. **Correlate to a user and time window**
   - Pivot from the dumper process (Event 1) to `SubjectUserName` and `LogonId`.
   - Search for lateral movement in the next 30-60 min: Event 4624 type 3 (network logon) from the same user to other hosts.
   - Check for new scheduled tasks (Event 4698) or service installs (Event 7045) created by the same user.
6. **Memory confirmation (optional)**
   - If a memory image exists: `vol3 -f {image} windows.lsadump` and `vol3 -f {image} windows.malfind --pid {lsass_pid}`.
   - Presence of `mimi bees` artefacts or RWX regions in lsass address space confirms active injection.
7. **Decision point**: if a confirmed dump is detected, immediately isolate the host, force a krbtgt rotation (if DC), and rotate all credentials of users logged into that host within the dump window.

## 4. Verification
- Require at least two independent events for a high-confidence call (e.g. Event 10 process-access + Event 1 cmdline match).
- Map detections to MITRE ATT&CK:
  - **T1003.001** LSASS Memory — primary technique.
  - **T1003** OS Credential Dumping — parent.
  - **T1055** Process Injection — for CreateRemoteThread (Event 8) cases.
  - **T1078** Valid Accounts — if dumped hashes are later used for lateral movement.
- Validate Sigma rule coverage with `Invoke-AtomicRedTeam` (T1003.001) on a lab host to confirm the alerts fire.
- Build a detection-gap matrix: `{event_id, technique, sigma_rule, fires?}` for each dumper variant tested.

## IMPORTANT
- Hunt only on systems and logs you are authorised to access (owned, IR scope, or explicit retainer).
- Document every finding with timestamp, host, user, event IDs, and raw event XML — reproducibility is mandatory.
- Never share or store recovered credentials/hashes in plaintext; the MIRV redaction layer masks them on mission save and audit log.
- Treat `{target}` and `{evtx_dir}` placeholders literally — never substitute unvalidated paths.
- If you confirm a dump, treat it as a live incident: contain first, hunt second, report to legal/management per policy.
- Do not run real dumpers on production to "test detections" — use a dedicated lab and Atomic Red Team.
