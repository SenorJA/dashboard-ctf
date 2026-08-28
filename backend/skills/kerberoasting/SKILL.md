---
name: kerberoasting
description: "Kerberoasting with Rubeus — extract and crack Kerberos service tickets. REQUIRES EXPLICIT AUTHORIZATION."
category: red-team
allowed_tools:
  - rubeus
  - hashcat
  - john
  - powershell
version: "1.0.0"
author: "MIRV"
requires_scope: true
ethical_warning: true
---

# Kerberoasting Methodology

## 1. When to Use
- An authorised red-team engagement or AD lab where you must demonstrate credential exposure via service tickets.
- You have a valid domain user credential and want to assess which service accounts have crackable passwords.
- A purple-team exercise to validate blue-team Kerberoasting detections (Event 4769 RC4 requests).
- A password/kerberos audit within an engagement scope to identify weak service-account passwords.
- REQUIRES EXPLICIT WRITTEN AUTHORIZATION — Kerberoasting is detectable and abuses live domain auth.

## 2. Prerequisites
- Written, signed authorisation covering the target domain and the named service accounts.
- A valid domain user account (any low-priv user can request TGS for SPN-enabled accounts).
- `Rubeus.exe` (or `Invoke-Kerberoast` / `GetUserSPNs.py` from Impacket) on a domain-joined host or with credentials.
- `hashcat` (GPU preferred) with mode `13100` (Kerberoast TGS) and a wordlist (`rockyou.txt`, `hashcat` rule sets).
- `john` (John the Ripper) as a CPU fallback with the `krb5tgs` format.
- Network reachability to a Domain Controller on TCP/UDP 88 (Kerberos) and 389/636 (LDAP for SPN enum).
- OPSEC awareness: this technique generates Event 4769 on every DC; expect detection by a mature blue team.

## 3. Workflow
1. **Confirm scope and authorization**
   - Re-read the signed scope letter: confirm the domain FQDN, the named service accounts in scope, and the time window.
   - If scope_guard cannot validate `{target}` against the engagement scope, STOP and request explicit permission.
2. **Enumerate SPN-enabled accounts**
   - PowerShell: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, MemberOf`.
   - Rubeus: `Rubeus.exe asreproast` (different attack) — for Kerberoasting use `Rubeus.exe kerberoast /stats`.
   - Impacket (Linux): `GetUserSPNs.py {domain}/{user}:{pass} -request` — lists SPN accounts and requests their TGS.
   - Flag high-value targets: SQL service accounts, backup accounts, any member of privileged groups.
3. **Request TGS tickets**
   - Rubeus: `Rubeus.exe kerberoast /outfile:hashes.txt /domain:{domain} /rc4opsec` — requests RC4-HMAC TGS for every SPN account.
   - `/rc4opsec` requests RC4 (`0x17`) which is crackable; AES tickets are far harder to crack.
   - Impacket: `GetUserSPNs.py {domain}/{user}:{pass} -request -outputfile hashes.txt`.
   - The output file contains `krb5tgs$23$...` hashes compatible with hashcat mode 13100.
4. **Crack the hashes**
   - `hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule --potfile-path pot.txt`.
   - If GPU is unavailable: `john --format=krb5tgs hashes.txt --wordlist=rockyou.txt`.
   - Use a targeted wordlist: company name, project names, seasons, years — service accounts often use predictable passwords.
   - Apply rules (`best64`, `d3ad0ne`, `OneRuleToRuleThemAll`) to maximise coverage without huge wordlists.
5. **Validate cracked credentials**
   - For each cracked account: confirm the password against a non-production test (e.g. `crackmapexec smb {dc} -u {user} -p {pass} --shares`).
   - Do NOT use cracked credentials to log into production systems without explicit scope approval.
   - Record the SPN account, the password length, complexity, and the time-to-crack for the report.
6. **Map to MITRE ATT&CK**
   - **T1558.003** Kerberoasting — primary technique.
   - **T1558** Steal or Forge Kerberos Tickets — parent.
   - **T1078** Valid Accounts — if cracked creds are then used for access (out of scope unless authorised).
7. **Decision point**: if a cracked service account is a member of a privileged group OR has admin rights on multiple hosts, escalate as a CRITICAL finding; recommend immediate password rotation to a 25+ char random string and gMSA migration.

## 4. Verification
- Confirm each cracked hash by re-requesting a TGS with the recovered password and validating the ticket.
- Validate the SPN enumeration count against the DC's actual SPN list (`setspn -Q */*` on the DC, if accessible).
- Map detections: collect DC Event 4769 logs for the attack window and confirm which requests your activity generated (purple-team value).
- Produce a findings table: `{spn_account, group_membership, password_length, time_to_crack, recommendation}`.
- Include the OPSEC footprint: Event 4769 count, RC4 ratio, source host — so the blue team can tune detections.

## IMPORTANT
- ⚠️ REQUIRES WRITTEN AUTHORIZATION — Kerberoasting abuses live domain authentication and is illegal without scope.
- `requires_scope: true` — this skill only renders if scope_guard validates `{target}` against the engagement scope.
- The technique is LOUD: every TGS request generates a DC Event 4769; assume a mature blue team detects it.
- OPSEC level: Loud. Do not attempt to hide — coordinated engagements declare this technique up-front.
- NEVER share or store cracked passwords in plaintext; MIRV `redact.py` masks them on mission save and audit log.
- Treat `{target}` / `{domain}` / `{user}` placeholders literally — never substitute unvalidated input.
- Cracked credentials must not be reused for lateral movement unless explicitly authorised in the scope letter.
- Recommend remediation in the report: long random passwords (25+ chars), gMSA (Group Managed Service Accounts), AES-only encryption, monitoring for RC4 TGS requests.
- If scope_guard denies the target, STOP and request explicit permission via the MIRV permission prompt system.
