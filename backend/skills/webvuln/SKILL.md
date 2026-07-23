---
name: webvuln
description: "Web vulnerabilities: IDOR, broken access control, injection, auth and session logic."
category: webvuln
allowed_tools:
  - nikto
  - curl
  - gobuster
  - sqlmap
  - ffuf
version: "1.0.0"
author: "MIRV"
---

# Web Vulnerability Methodology

## 1. Broken access control (IDOR)
- Identify auth-relevant params (user_id, account, role)
- Replace ID with another user's ID (try sequential, UUID, base64)
- Test horizontal (same role, other user) and vertical (lower to higher role)
- Confirm cross-account impact with concrete response difference (status, body, headers)

## 2. SQL Injection
- Error-based: `'`, `"`, `\`, detect DBMS from error signature
- Union-based: `' UNION SELECT NULL,NULL-- -` (match column count)
- Blind: `' AND SLEEP(5)-- -` (time-based) / `' AND 1=1-- -` vs `' AND 1=2-- -`
- Use `sqlmap -u {url} --batch --risk=3` only after manual detection
- Pivot: load file `UNION SELECT LOAD_FILE('/etc/passwd')`; write via INTO OUTFILE only in-scope

## 3. XSS
- Reflected: inject `<svg onload=alert(1)>` in every input + URL params
- Stored: try comment/profile fields, username fields, file metadata
- Dom-based: inspect JS source for `location.hash`, `document.referrer`, `innerHTML` sinks
- Bypass filters: `jaVasCript:`, `"><img src=x onerror=...>`, template literals

## 4. Authentication / sessions
- Test password reset flow for token reuse / predictable tokens
- Session fixation: change session ID after login?
- Cookie attributes: HttpOnly, Secure, SameSite
- Test username enumeration via response timing / message divergence

## 5. SSRF surface within web app
- Any "fetch URL" / "import from URL" / "preview link" feature = SSRF candidate
- See `ssrf` skill for the bypass menu

## 6. Race conditions
- Concurrent requests against one-time tokens, coupon codes, balance ops
- Use ffuf / turbo intruder with single packet burst

## IMPORTANT
- Every finding must have concrete PoC + observed response impact
- No theoretical bugs — only reproducibles
- Document the request, the response delta, and the business impact