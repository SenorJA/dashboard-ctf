---
name: recon
description: "Reconnaissance and attack-surface mapping. Subdomains, fingerprinting, content discovery."
category: recon
allowed_tools:
  - nmap
  - gobuster
  - ffuf
  - whatweb
  - dnsrecon
  - curl
  - theHarvester
version: "1.0.0"
author: "MIRV"
---

# Recon Methodology

## 1. Subdomain enumeration
- Use `theHarvester -d {target} -b all` for passive sources
- Use `dnsrecon -d {target} -t std` for DNS records
- Cross-reference with crt.sh: `curl 'https://crt.sh/?q=%.{domain}&output=json'`
- Build a unique host list; resolve each to IP; note externalised vs internal IPs

## 2. Fingerprinting
- `whatweb {url}` → tech stack
- `nmap -sV -sC -p- {host}` → services + versions
- Inspect HTTP headers: `Server`, `X-Powered-By`, `Set-Cookie` names
- Map each detected technology to a CVE feed / HackTricks section

## 3. Content discovery
- `gobuster dir -u {url} -w common.txt -t 50`
- `ffuf -u {url}/FUZZ -w wordlist.txt -mc 200,301,302,403`
- Check common paths: `/admin`, `/api`, `/.git/`, `/.env`, `/swagger`
- Replay 403s with `X-Original-URL`, `X-Rewrite-URL`, trailing dots

## 4. Attack surface mapping
- List all endpoints found + tag by authentication state
- Note exposed technologies, frameworks, CDNs
- Cross-reference technologies against HackTricks for known issues
- Output: a table of `{host, port, service, version, auth_state, notes}`

## IMPORTANT
- Treat `{target}` placeholders literally — never substitute unvalidated input.
- Rate-limit yourself; respect `robots.txt` per engagement scope.