---
name: training-path
description: "Free cybersecurity learning curriculum. Red Team and Blue Team paths with hands-on labs from TryHackMe, HackTheBox, picoCTF, OverTheWire."
category: education
allowed_tools: []
version: "1.0.0"
author: "MIRV"
---

# Cybersecurity Training Path Methodology

## 1. When to Use
- You are starting in cybersecurity and need a structured, free, hands-on curriculum.
- A junior team member asks "where do I learn red team / blue team?" and you want a reproducible path.
- You are mentoring and want to track a learner's progress against known rooms/challenges.
- You need a refresher on a specific area (Linux, Windows AD, forensics, malware RE) with linked labs.
- You are planning a study group and want a shared checklist of resources.

## 2. Prerequisites
- A free TryHackMe account (https://tryhackme.com) — free tier grants several rooms; VIP unlocks more but is optional.
- A browser and a terminal (Linux VM recommended: VirtualBox + Ubuntu or Kali image).
- For HackTheBox: a free account (https://hackthebox.com) — Academy free tier + retired machines via VIP are optional.
- For picoCTF: a free account (https://picoctf.org) — no installation, browser-based for most challenges.
- For OverTheWire: only SSH access (`ssh {level}@{host}.overthewire.org -p {port}`), no account.
- Time commitment: ~2-4 hours/week for a beginner track; ~6-10 hours/week for advanced.
- A notebook or markdown log to record flags, writeups, and lessons learned.

## 3. Workflow — Red Team Path (6 levels)

### Level 1 — Linux Fundamentals
- **TryHackMe** "Linux Fundamentals 1, 2, 3" — file system, permissions, processes.
- **OverTheWrire Bandit** levels 0-15 — SSH, file manipulation, regex, basic scripting.
- Skills: navigate the FS, manage users, use `grep`/`find`/`awk`, understand `chmod`/`chown`.
- Exit criterion: complete Bandit 0-15 without external writeups; log each command used.

### Level 2 — Networking & Web Basics
- **TryHackMe** "Web Fundamentals", "HTTP in Detail", "What is Networking?".
- **picoCTF** Web Exploitation — easy challenges (Inspect HTML, cookies, GET/POST).
- Skills: read a pcap with Wireshark, craft HTTP requests with `curl`, understand TCP/IP layers.
- Exit criterion: solve 5 picoCTF web-easy challenges and write a 1-paragraph writeup each.

### Level 3 — Recon & Enumeration
- **TryHackMe** "Nmap Live Host Discovery", "Nmap Deep Dive", "Gobuster", "RustScan".
- **HackTheBox Academy** "Using Web Proxies" (Burp) — free tier.
- Skills: nmap `-sV -sC -p-`, gobuster/ffuf dir busting, vhost enumeration, Burp interception.
- Exit criterion: complete TryHackMe "Kenobi" or "Blue" using only nmap + gobuster, no walkthrough.

### Level 4 — Web Exploitation
- **TryHackMe** "OWASP Top 10", "Injection", "File Inclusion", "SQL Injection".
- **picoCTF** Web medium + **PortSwigger Web Security Academy** (free) — SQLi, XSS, SSRF, XXE.
- Skills: SQLi (union, blind), XSS (reflected, stored, DOM), SSRF, LFI/RFI, command injection.
- Exit criterion: complete 10 PortSwigger apprentice labs + solve "SQL Injection" TryHackMe room.

### Level 5 — Privilege Escalation
- **TryHackMe** "Linux PrivEsc", "Windows PrivEsc", "Sudo Security Bypass".
- **HackTheBox Academy** "Linux Privilege Escalation" path (free modules).
- Skills: SUID abuse, kernel exploits, cron job abuse, misconfigured sudo, Windows service paths, unquoted paths, token impersonation.
- Exit criterion: root 3 HackTheBox starting-point machines + complete TryHackMe "Linux PrivEsc" room.

### Level 6 — Active Directory Red Team
- **TryHackMe** "Active Directory Basics", "Attacktive Directory", "Kerberoasting".
- **HackTheBox Academy** "Active Directory Enumeration" + "Attack" paths.
- Skills: BloodHound, Kerberoasting, AS-REP roasting, GPP abuse, DCSync, constrained delegation.
- Exit criterion: complete TryHackMe "Attacktive Directory" and "Throwback" (or "HoloNetwork") without a walkthrough.

## 4. Workflow — Blue Team Path (5 levels)

### Level 1 — Digital Forensics
- **TryHackMe** "Digital Forensics", "Autopsy", "Windows Forensics 1, 2".
- Skills: filesystem timelines, registry analysis, prefetch, MFT, event log parsing.
- Exit criterion: complete TryHackMe "Benign" / "Volatility" room; recover 3 artefacts.

### Level 2 — Network Defence & SIEM
- **TryHackMe** "Cyber Defense", "Intro to SIEM", "Splunk Basics", "Zeek".
- Skills: write Splunk SPL queries, parse Zeek `conn.log`/`http.log`, build alerts.
- Exit criterion: complete TryHackMe "Investigating with Splunk" room; build 2 custom alerts.

### Level 3 — Threat Hunting
- **TryHackMe** "Yara", "Threat Hunting with Yara", "Sysmon".
- Skills: write YARA rules, deploy Sysmon with SwiftOnSecurity config, hunt for IOCs.
- Exit criterion: complete TryHackMe "Yara" room; write 3 YARA rules that match sample malware.

### Level 4 — Incident Response
- **TryHackMe** "Incident Response with Splunk", "SOC Level 1" path.
- Skills: NIST IR lifecycle, scoping, containment, evidence collection, lessons learned.
- Exit criterion: complete TryHackMe "Investigating with ELK" or "Cyber Forensics" room; produce an IR report.

### Level 5 — Malware Reverse Engineering
- **TryHackMe** "Malware Analysis", "Intro to x86-64", "REloaded".
- **picoCTF** Reverse Engineering — medium/hard challenges.
- Skills: static analysis with Ghidra/IDA Free, dynamic with x64dbg, unpacking, API hooking.
- Exit criterion: solve 5 picoCTF RE-medium + complete TryHackMe "Malware Analysis" room.

## 5. Bonus — CTF Practice
- **picoCTF** (year-round, beginner-friendly) — start with General Skills, then Web, Crypto, RE, Forensics.
- **OverTheWire** — Bandit (Linux), Narnia/Behemoth (binary exploitation), Krypton (crypto).
- **HackTheBox** — Starting Point (free), then seasonal machines; track your rank progression.
- **CTFtime.org** — register a team, join beginner-friendly events (e.g. PicoCTF, DownUnderCTF, BYUCTF).
- Goal: participate in at least 1 CTF event per month and publish a writeup for at least 1 challenge.

## 6. Verification
- Track progress in a markdown table: `{platform, room/challenge, status, date, takeaways}`.
- Earn the platform badges/certificates (TryHackMe completion badges, HackTheBox rank, picoCTF scoreboard).
- Cross-skill test: after each level, solve a challenge from a *different* platform covering the same skillset to confirm transfer.
- Pair with a mentor for monthly review: present 1 writeup and 1 lesson learned.

## IMPORTANT
- Use only free resources listed here — do not pay for content unless you consciously choose VIP.
- Ethical use only: practise on designated platforms and lab machines; never scan or attack systems you do not own or do not have explicit permission for.
- Respect each platform's Terms of Service — no sharing of VIP content, no cheating on scoreboards, no attacking other users.
- Treat `{target}` placeholders literally — this skill has no `{target}`; do not substitute live systems for labs.
- Writeups of active competition challenges are often embargoed until the event ends — wait before publishing.
- Cybersecurity skills can be misused; the intent of this path is defence and authorised testing only.
- MIRV redaction applies to any notes you import into a mission (credentials, flags, PII are masked on save).
