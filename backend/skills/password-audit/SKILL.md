---
name: password-audit
description: "Educational password auditing. Hash identification, offline recovery strategies (wordlist, rules, mask, incremental), online authentication control-testing, Windows/AD review, file and key recovery for legitimate access loss, and defensive hardening evidence."
category: password-audit
allowed_tools:
  - hashcat
  - john
  - hydra
  - ncrack
  - medusa
  - patator
  - crowbar
  - ophcrack
  - rainbowcrack
  - crackmapexec
  - hashcat-utils
version: "1.0.0"
author: "MIRV"
---

# Password Auditing Methodology

## 1. Identificación de hashes
- Determine the hash format before running any recovery: the wrong mode wastes GPU time and produces false negatives.
- Inspect the sample: length, charset (hex vs Base64), prefix (`$2a$`/`$2b$`/`$2y$` bcrypt, `$6$` sha512crypt, `$1$` md5crypt, `$krb5tgs$` Kerberos, `{SSHA}`), and delimiter (`user:hash`, `hash$salt`).
- Run `hashid '<hash>'` or `john --format=auto` as a first guess; confirm with hashcat's self-test using `hashcat -m <mode> --identify` (hashcat 6.2.6+) on the actual sample.
- Common modes: MD5 `-m 0`, SHA1 `-m 100`, SHA256 `-m 1400`, NTLM `-m 1000`, bcrypt `-m 3200`, sha256crypt `-m 7400`, sha512crypt `-m 1800`, Kerberos 5 TGS-REP `-m 13100`, PBKDF2-HMAC-SHA512 (LUKS) `-m 13721`, descrypt `-m 1500`, WPA-EAPOL-PBKDF2 `-m 22000`.
- When multiple modes fit, bench a short wordlist on each candidate mode (`hashcat -m <mode> --benchmark`) and start with the slowest-to-crack that matches — a hash recovered with the correct mode confirms the format.
- Record the confirmed mode, the sample count, and whether salts are present in the finding notes; salted hashes cannot use rainbow tables.

## 2. Estrategias de recuperación offline
- Follow the cost ladder, cheapest candidate space first, and escalate only when a strategy exhausts without success:
  1. **Wordlist (dictionary)**: fast, catches reused/leaked passwords. Best first pass for any hash type.
  2. **Rules**: mutate wordlist candidates (leetspeak, capitalisation, trailing digits). Higher yield than a bigger raw list for modern password habits.
  3. **Mask**: positional patterns when the policy is known or the user leaks structure (e.g. `Capital8!`). Also the basis of PRINCE/`-a 1` combinator attacks.
  4. **Incremental / brute force**: last resort — explore a bounded candidate space by length; only feasible for short or low-entropy hashes (fast formats, <8 chars).
- Estimate cost before launching: `hashcat -b -m <mode>` gives candidate rate; compare against candidate count to predict elapsed time. Abort anything that would take longer than the engagement window allows.
- Recover in phases, saving intermediate state (`--restore` / `--session`): a partial result is evidence; a lost GPU session is not.
- For each recovered hash record: mode, strategy that succeeded, candidate count attempted, elapsed time, and the plaintext only as evidence (never share it in reports or logs — MIRV redaction applies on `/api/ai/chat` and `mission_store`).

## 3. Wordlists, reglas y máscaras
- Keep wordlists in `{target}/wordlists/`; standard corpora: `rockyou.txt` (best default), `SecLists/Passwords`, and org-specific leaks derived ONLY from authorised, scoped data.
- Shrink scope first: `hashcat-utils` `cap2hccapx`, `len` and `cut` operators filter candidate lists by length/charset to cut the search space before the heavy run.
- Custom wordlists from the target context (names, company, project, dates) are legitimate when derived from public/OSINT or engagement data in scope — build with `crunch` or a small generator script and dedupe with `sort -u`.
- Hashcat rules (file passed with `-r`): `:`, `l`, `u`, `c` (case ops), `$1`/`$2`…`$0` (append), `^!` (prepend), `sa@` (substitute), `D` (delete), `2` (duplicate). A baseline starter rule set can be authored as:
  - `c $1` → `Summer -> Summer1`
  - `c $2 $0 $2 $4` → `Summer -> Summer2024`
  - `c sa@` → `Summer -> Summ3r`
  - `l sa@ $1` → `summ3r1`
- Masks: `?l` lowercase, `?u` uppercase, `?d` digit, `?s` symbol, `?a` any, custom with `-1`/`-2`. Examples with `-a 3`:
  - 8 lowercase: `?l?l?l?l?l?l?l?l`
  - `Capital` + 4 digits: `?u?l?l?l?l?l?l?l?d?d?d?d`
  - wordlist + 2 digits (combinator `-a 1`): `dict.txt dict.txt`
- Rules and masks that match a *known policy* (length, complexity, rotation cadence) always outperform blind brute force; document the policy assumption in the finding.

## 4. Auditoría de autenticación online
- Online testing is a CONTROL TEST, not brute force: validate that rate-limiting, lockout, and logging actually work. It is only permitted against systems explicitly in scope with written authorisation, and NEVER against third parties.
- Services commonly tested: SSH (`hydra -L users -P pass ssh://{target}`), FTP, HTTP basic/forms (`http-post-form`), SMB, RDP (only with `crowbar` when NLA constraints apply), WinRM, database ports (MSSQL/MySQL/PostgreSQL), and SMTP/IMAP.
- Choose the tool by protocol: `hydra`/`medusa` for parallel multi-service, `ncrack` for service-focused timing, `patator` when you need custom request templates for non-standard auth endpoints.
- Apply the brakes from the first attempt: `-t 1` (or a single thread), delays via `-W`/`-d`, and a per-account attempt cap below the lockout threshold of the target policy.
- Test with a small authorised userlist and a short candidate list; the objective is to confirm whether the control triggers (lockout after N attempts, rate-limit response codes) — not to harvest valid credentials.
- Watch the logs: correlate your attempt windows against SIEM/auth events to measure detection latency; that detection gap is the actual finding.
- Abort immediately if lockouts occur or service health degrades, and report the trigger condition.

## 5. Windows y Active Directory
- `crackmapexec` (or the `netexec` fork) validates credentials and inspects posture across SMB/WinRM/LDAP/MSSQL/RDP — it is an assessment tool, not a cracker; pairs with hashcat for offline NTLM recovery.
- Extract the target hashes from an authorised DC/local dump and recover offline: NTLM `-m 1000`, Kerberos AS-REP `-m 18200` (when pre-auth is disabled) and Kerberoast TGS-REP `-m 13100` (SPN-targeted service tickets).
- Defensive checks that produce MIRV findings, not compromises:
  - Password policy: `net accounts /domain` / GPO review — length, complexity, lockout threshold, expiration.
  - Kerberoast exposure: how many service accounts have SPNs and weak/unchanging passwords; recommend Managed Service Accounts (gMSA) and 25+ char random service passwords.
  - Delegation flags and privileged group membership (`crackmapexec` `--shares` / LDAP queries) — over-privileged service accounts amplify any recovered password.
- Every offline NTLM/Kerberos hash recovered in a lab must be treated as evidence of a POLICY weakness: pair it with the GPO audit result in the finding so the fix is actionable.
- Keep the lab isolated: domain controllers and test accounts are disposable, never production.

## 6. Recuperación de archivos y claves
- Legitimate use cases: recovering your own forgotten files, restoring a team member's inaccessible document with authorisation, validating a backup, or CTF practice. Never recover files you do not own or that belong to third parties.
- Office documents (Word/Excel/PowerPoint): `john --format=office` (`-m 9600`/`-m 9810` in hashcat) on the extracted hash; modern OOXML uses iterative SHA-1/AES so expect a slower candidate rate — favour wordlist+rules, not mask.
- Archives: ZIP (`john` zip formats / `zip2john`, hashcat `-m 13600`), RAR (`rar2john`, `-m 13000`), 7z (`7z2john`, `-m 11600`). Test whether the archive actually enforces a password or just an encryption header; note weak/default passwords in the finding.
- PDF: `pdf2john`/hashcat `-m 10500` (PDF 1.4 RC4) and `-m 25400`/`-m 23700` for AES variants; if the file opens with an empty password the "protection" is cosmetic — report that.
- Databases: SQLite `sqlcipher`/`.db` extracts, MySQL/MSSQL credential hashes from a scoped backup — recover offline with the matching mode; never store the plaintext.
- Browsers and password managers: only for your own profiles / lab machines (e.g. decrypting `Login Data` with a known master key in a test VM); production credential stores are out of scope and out of bounds.
- Cloud: use vendor-released recovery paths (SSO reset, credential rotation) before any offline work; private SSH keys are recovered via passphrase offline (`-m 22921` for encrypted OpenSSH keys, `ssh2john`) only when you own the key or have explicit authorisation.
- Log every recovery: tool, format, mode, strategy, elapsed time, and outcome — it doubles as remediation evidence (the file *should* have used a stronger KDF).

## 7. Defensa y detección
- Every offline success is a defence finding: map the recovered password to policy (length, entropy, reuse) and to the KDF (MD5 vs bcrypt vs PBKDF2 iterations) and translate into a concrete recommendation.
- Online control-test results become detection evidence: whether lockout fired, whether the SIEM/MIRV audit log caught the attempts, and the alert-to-response latency.
- Audit the audit: confirm authentication events are structured, centralised, and correlated (MIRV SIEM correlation rules for failed-login spikes), and that brute-force detection rules exist before relying on them.
- Recommend, in order: MFA/2FA for every interactive account (incl. service accounts where possible), password managers for uniqueness, 12+ char passwords with a lockout policy of 5–10 attempts, Argon2/bcrypt/PBKDF2 with adequate cost, and credential-stuffing monitoring on public endpoints.
- Publish findings via MIRV (`POST /api/findings`) with severity, evidence (mode, rate, strategy, time), impact, and remediation — redacted so no plaintext password survives in any report, log, or LLM call.

## IMPORTANT
- Treat `{target}` literally — never substitute unvalidated input; apply scope_guard validation before any command.
- Online credential testing (Hydra/Medusa/Ncrack/Patator/Crowbar) ONLY against explicitly authorised systems; respect rate limits and lockout thresholds — one bad run can lock out a production account.
- Never attempt recovery of hashes, files, or credentials you do not own or that come from third parties without documented consent.
- MFA/2FA is assumed in real audits; the recovery of a password alone is NOT account compromise when MFA is enforced — test and document that boundary.
- Educational/defensive focus: recover in a lab or with consent, measure the controls, and turn every success into a hardening recommendation.
- Document results as MIRV findings with evidence and remediation; never persist or transmit plaintext passwords, and rely on the built-in redaction for AI/report paths.
