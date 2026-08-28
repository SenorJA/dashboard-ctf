---
name: bloodhound-collection
description: "BloodHound/SharpHound collection for Active Directory attack path mapping. REQUIRES EXPLICIT AUTHORIZATION."
category: red-team
allowed_tools:
  - bloodhound
  - sharphound
  - neo4j
  - python
version: "1.0.0"
author: "MIRV"
requires_scope: true
ethical_warning: true
---

# BloodHound Collection Methodology

## 1. When to Use
- An authorised red-team engagement or AD lab where you must map attack paths to domain admin.
- You have a domain user and want to enumerate ACLs, sessions, group memberships, GPO relationships visually.
- A purple-team exercise to validate blue-team BloodHound detections (LDAP enumeration, SharpHound signatures).
- An AD security audit to identify the shortest path from any user to Domain Admin / Enterprise Admin.
- REQUIRES EXPLICIT WRITTEN AUTHORIZATION — BloodHound performs heavy LDAP enumeration and is highly visible.

## 2. Prerequisites
- Written, signed authorisation covering the target domain and the collection time window.
- A valid domain user account (read access to AD is enough; no admin needed).
- `SharpHound.exe` / `SharpHound.ps1` (Windows) OR `bloodhound-python` (Linux) for collection.
- `neo4j` (community edition) running locally or on a dedicated analysis host (`neo4j start`).
- `BloodHound` GUI (Electron app) connected to Neo4j (`bolt://localhost:7687`).
- Network reachability to a Domain Controller on LDAP (389/636), SMB (445), and GC (3268).
- Disk space: a large domain's JSON can be hundreds of MB; Neo4j needs RAM (≥4 GB heap).
- OPSEC awareness: SharpHound generates thousands of LDAP queries in minutes; expect SOC detection.

## 3. Workflow
1. **Confirm scope and authorization**
   - Re-read the signed scope letter: confirm the domain FQDN, collection depth, and the time window.
   - If scope_guard cannot validate `{target}` against the engagement scope, STOP and request explicit permission.
2. **Choose the collector**
   - **SharpHound.exe** (Windows, domain-joined): fastest, supports all collection methods, signed binary available.
   - **SharpHound.ps1** (Windows, domain-joined): for restricted envs where EXE is blocked; `Import-Module .\SharpHound.ps1`.
   - **bloodhound-python** (Linux, any host with creds): `bloodhound-python -u {user} -p {pass} -d {domain} -ns {dc_ip} -c All`.
3. **Run collection**
   - SharpHound.exe: `SharpHound.exe -c All --outputdirectory C:\BH\ --zipfilename {domain}.zip` — all collection methods (Default, DCOnly, Session, ACL, Group, Trust, Container, Computer, GPOLocalGroup).
   - SharpHound.ps1: `Invoke-BloodHound -CollectionMethod All -ZipFileName {domain}.zip -OutputDirectory C:\BH\`.
   - bloodhound-python: `-c All,LoggedOn` for sessions; add `--collectionmethod DCOnly` for stealth (no computer enumeration).
   - For stealth: split into small windows, target a single DC, avoid `LoggedOn` (it enumerates active sessions on every computer = noisy).
4. **Import to Neo4j**
   - Start Neo4j and set a password: `neo4j-admin set-initial-password {pass}` then `neo4j start`.
   - Open BloodHound GUI, login to `bolt://localhost:7687` with `neo4j` / `{pass}`.
   - Drag the `{domain}.zip` into the BloodHound GUI → ingestion starts; watch the bottom-right progress.
   - Large domains can take 20-60 min to ingest; Neo4j heap tuning (`dbms.memory.heap.max_size=8G`) speeds it up.
5. **Query attack paths**
   - Built-in queries (left panel):
     - "Find Shortest Path to Domain Admins" — primary objective.
     - "Find All Domain Admins" — enumerate DA set.
     - "Map Domain Trusts" — cross-domain/forest paths.
     - "Shortest Paths to High Value Targets" — custom-defined HV targets.
   - Custom Cypher: `MATCH p=shortestPath((n:User {name:'{user}'})-[*1..]->(m:User {name:'DOMAIN ADMINS@{domain}'})) RETURN p`.
   - Identify: Kerberoastable users, AS-REP roastable users, users with `DCSync` rights, unconstrained delegation targets, GPO abuse paths.
6. **Validate and prioritise**
   - For each high-value path, manually verify the first edge (ACL/session/group) with native tools (`Invoke-ACLScanner`, `Get-ADUser`, `Get-NetSession`).
   - Prioritise paths that combine: low-priv starting user → 2-3 edges → DA. These are the reportable critical findings.
   - Tag each path with the MITRE technique per edge (T1078 valid accounts, T1003 credential dump, T1068 escalation).
7. **Map to MITRE ATT&CK**
   - **TA0008** Lateral Movement — paths via sessions/admin shares.
   - **T1078** Valid Accounts — group/ACL edges that grant account use.
   - **T1068** Exploitation for Privilege Escalation — ACL abuse edges.
   - **T1003** Credential Dumping — paths leading to DCSync/lsass.
   - **T1558** Kerberos tickets — Kerberoastable user nodes.
8. **Decision point**: if a 3-edge-or-shorter path to Domain Admin exists from a low-priv user, escalate as CRITICAL; recommend the exact edges to break (remove ACE, fix group nesting, disable unconstrained delegation).

## 4. Verification
- Cross-check the shortest path's first edge with a native AD query (PowerShell `Get-ACL` / `Get-ADUser`) — confirms the ACL/session is real, not stale.
- Confirm session edges are recent: BloodHound session data is a point-in-time snapshot; sessions from days ago may be inactive.
- Validate the DA set against `Get-ADGroupMember "Domain Admins"` on the DC (if accessible).
- Produce a findings table: `{start_user, end_target, edges, edge_techniques, remediation}` — one row per critical path.
- Include the OPSEC footprint: LDAP query count (DC event 1644 / Sysmon 22) and SharpHound binary hash for blue-team detection.

## IMPORTANT
- ⚠️ AUTHORIZATION REQUIRED — BloodHound performs heavy LDAP enumeration across the entire domain; illegal without scope.
- `requires_scope: true` — this skill only renders if scope_guard validates `{target}` against the engagement scope.
- Collection is OPSEC-sensitive: thousands of LDAP queries in minutes; a mature blue team detects SharpHound within minutes.
- Use `DCOnly` collection for stealth (no computer session enumeration) — it misses session edges but is far quieter.
- The dataset is large and may contain PII (user names, descriptions, last logon); store it encrypted and redact in shared reports.
- NEVER share the `.zip` dataset outside the engagement team; MIRV `redact.py` masks PII on mission save but the raw zip does not.
- Treat `{target}` / `{domain}` / `{user}` placeholders literally — never substitute unvalidated input.
- Document every finding with a screenshot of the BloodHound path AND the native AD verification — reproducibility is mandatory.
- Stale data is a risk: re-run collection if the engagement spans more than a few days; AD changes invalidate old paths.
- If scope_guard denies the target, STOP and request explicit permission via the MIRV permission prompt system.
