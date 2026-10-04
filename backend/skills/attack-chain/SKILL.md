---
name: attack-chain
description: "Full-scope offensive orchestration: plan and execute a complete attack chain (recon → delivery → exploitation → privilege escalation → lateral movement → C2 → exfiltration) as a single campaign, mapping TTPs to MITRE ATT&CK and coordinating tools (nuclei, crackmapexec, bloodhound, impacket, sliver/chisel pivots). Use for red-team operations, adversary emulation, kill-chain campaigns, pivoting/double-hop plans and end-to-end breach simulation."
category: red-team
allowed_tools:
  - nmap
  - nuclei
  - crackmapexec
  - metasploit
  - bloodhound
  - impacket
  - mimikatz
  - sliver
  - chisel
  - ligolo
  - beacon
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Attack Chain Orchestration Methodology

## 1. Campaign planning
- Define objective + authorized scope; map expected TTPs to MITRE ATT&CK tactics/techniques.
- Write an operations order: staging (C2/VPS), personas, timeboxes, communication plan, rollback).
- Gate each phase on scope: never touch out-of-scope assets; use engagement-safe red-team tools.

## 2. Chain stages (authorized)
- **Recon/delivery**: assset discovery (`nuclei`, `nmap`), phishing/exposed-service entry per scope.
- **Initial access / foothold**: weaponize within `pwn-chain`/`finding_poc` rules; persist deliberately (backdoors map to a documented technique).
- **Privilege escalation**: enumerate with BloodHound + `crackmapexec`; chain misconfig → privileged session (AD routes: `R20` skill).
- **Lateral movement**: `impacket`/`crackmapexec` pass-the-hash, `sliver`/`chisel` reverse SOCKS for **double-hop** pivots.
- **C2 + exfiltration**: staged exfil (staging → egress), keep to the agreed data-size/type cap.

## 3. Orchestrate handoffs
- Each stage produces state (credentials, sessions, findings) for the next; record in the mission log.
- Swarm/planner integration: dispatch per-phase operators, keep a single kill-chain timeline.

## 4. Cleanup & reporting
- Remove implants, restore hooks/persistences, rotate exposed creds, document everything.
- Evidence per ATT&CK technique: screenshots, commands, timestamps, tool hashes.

## 5. Findings
- One finding per validated technique with chain context; evidence hash + redacted logs.
- Reproducible PoC: step-by-step chain script scoped to the engagement host.