---
name: persistence-hunting
description: "Hunt for persistence mechanisms in Windows and Linux. Scheduled tasks, registry, services, LOTL techniques."
category: defense
allowed_tools:
  - syslog
  - sysmon
  - autoruns
  - winreg
  - python
version: "1.0.0"
author: "MIRV"
---

# Persistence Hunting Methodology

## 1. When to Use
- Post-compromise triage of a host to enumerate every persistence mechanism an attacker may have planted.
- Anomalous logons or recurring malicious processes reappear after a reboot/reimage → persistence suspected.
- Proactive hardening to baseline "known-good" autostart entries and detect drift.
- A red-team report claims persistence was achieved and you must validate/remediate.
- EDR alerts on a new autorun entry, scheduled task, or service that does not match the golden image.

## 2. Prerequisites
- Sysmon Event Log (Event 1, 7, 12, 13, 22) plus Windows Security Event Log.
- `Sysinternals Autoruns` (GUI or `autorunsc.exe -accepteula -a * -c -h -s -v`) for full autostart enumeration.
- `winreg` / `reg query` access to the live or offline registry hives.
- On Linux: `syslog`/`journald`, `/etc/cron*`, `/etc/systemd/system`, `~/.config/autostart`, `/etc/profile.d/`.
- A golden-image baseline of autoruns entries from a clean build of the same OS image.
- `python` for diffing and CSV manipulation; Volatility 3 if analysing an offline hive from a memory/disk image.

## 3. Workflow
1. **Capture the full autoruns baseline**
   - On the suspect host: `autorunsc.exe -accepteula -a * -c -h -s -v > autoruns.csv` (codesign + hash + verify).
   - On a clean reference host of the same image: capture the same output as `baseline.csv`.
   - `python -c` diff of the two CSVs by `Entry Location + Image Path`; new/changed/not-signed entries are the hunt scope.
2. **Registry autostart keys (Windows)**
   - High-value keys to enumerate (user + machine):
     - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce`
     - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce`
     - `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
     - `HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute`
     - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` / `Shell`
     - `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
     - `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` (look for unknown installed apps)
   - Flag entries pointing to `%AppData%`, `%Temp%`, `%Public%`, or unsigned binaries.
3. **Scheduled tasks**
   - `schtasks /query /fo CSV /v > tasks.csv` → review `TaskName`, `Task To Run`, `Run As User`, `Next Run Time`.
   - Suspicious patterns: tasks created in the last 30 days, running as `SYSTEM`, executing from user-writable paths, or with base64/encoded PowerShell (`-enc`, `-EncodedCommand`).
   - Sysmon Event 4698 (task create) correlates the creation actor and time.
4. **Services & drivers**
   - `sc query type=service state=all > services.txt` and `Get-CimInstance Win32_Service | Format-List`.
   - Flag services with `BinaryPathName` in user-writable dirs, empty description, or `StartMode=Auto` + non-Microsoft signer.
   - Kernel drivers: `Get-CimInstance Win32_SystemDriver` — vulnerable drivers (BYOVD) are a known T1068 escalation vector.
5. **WMI subscriptions & COM hijacking**
   - `Get-WmiObject -Namespace root\subscription -Class __EventConsumer` (and `__EventFilter`, `__FilterToConsumerBinding`).
   - `CommandLineEventConsumer` running an attacker command = high-fidelity persistence (T1546.003).
   - COM hijacking: HKCU `CLSID` entries that override HKLM defaults; diff `HKCU\Software\Classes\CLSID` against baseline.
6. **LOTL (Living-Off-The-Land) techniques**
   - **PowerShell profiles**: `$PROFILE` files (`AllUsersAllHosts`, `CurrentUserAllHosts`) loading attacker modules.
   - **WSB (Windows Sandbox)** config, **DISM** additions, **AppInit_DLLs** registry value.
   - **Image File Execution Options** debugger hijacks: `HKLM\...\Image File Execution Options\{exe}\Debugger`.
   - **BAM/DAM** (Background Activity Moderator) registry keys reveal last-run time of persisted binaries.
7. **Linux persistence map**
   - Cron: `crontab -l`, `ls -la /etc/cron*`, `/var/spool/cron/`, `/etc/anacrontab`.
   - Systemd: `systemctl list-unit-files --state=enabled`, custom units in `/etc/systemd/system`.
   - Shell rc: `~/.bashrc`, `~/.profile`, `/etc/profile.d/*.sh`, `~/.ssh/authorized_keys` (attacker key persistence).
   - PAM modules: `/etc/pam.d/*` referencing non-standard `.so` files; LD_PRELOAD in `/etc/ld.so.preload`.
   - udev rules `/etc/udev/rules.d/*` and rc.local for boot-time execution.
8. **Decision point**: any autorun entry not in the golden baseline AND pointing to a user-writable or unsigned binary is treated as persistence; isolate the host, capture the binary for RE, and remove the entry after imaging.

## 4. Verification
- Confirm each finding with a second source (autoruns + registry query, or Sysmon event + on-disk file).
- Map to MITRE ATT&CK **TA0003 Persistence**:
  - **T1547.001** Registry Run Keys / Startup Folder.
  - **T1547.009** Shortcut Modification.
  - **T1053.005** Scheduled Task (Windows).
  - **T1543.003** Windows Service.
  - **T1546.003** WMI Event Subscription.
  - **T1546.010** AppInit_DLLs.
  - **T1574.011** Registry hive modification.
  - **T1053.003** Cron (Linux).
- Validate removal: after deleting the entry, reboot (in a sandbox) and confirm the malicious process does not respawn.
- Build a per-host drift report: `{host, entry, location, signed?, baseline?, action}`.

## IMPORTANT
- Hunt only on systems you are authorised to investigate (owned, IR scope, or explicit retainer).
- Document every finding with the entry path, signer, hash, creation time, and the actor that created it (Sysmon Event 1/4698).
- Treat `{target}` placeholders literally — never substitute unvalidated registry paths.
- Before deleting persistence on a production host, image the binary first — you will need it for attribution and detection building.
- Do not run untrusted binaries found in autoruns entries; submit them to a sandbox (Cuckoo/AnyRun) instead.
- Redact PII (user paths, usernames) in shared reports; MIRV redaction applies on mission save.
- Re-enabling Sysmon or rebooting to test removal can tip off an attacker — coordinate with the IR team before acting.
