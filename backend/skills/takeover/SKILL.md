---
name: takeover
description: "Subdomain takeover — dangling DNS records, unclaimed cloud resources, expired CNAMEs."
category: takeover
allowed_tools:
  - nmap
  - curl
  - gobuster
  - dnsrecon
  - whatweb
version: "1.0.0"
author: "MIRV"
---

# Subdomain Takeover Methodology

## 1. Enumerate subdomains
- Passive: `curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq -r .[].name_value | sort -u`
- Passive alt: `curl -s 'https://api.hackertarget.com/hostsearch/?q={domain}'`
- Active: `gobuster dns -d {domain} -w subdomains-top1m.txt -q`
- `subfinder`, `amass enum -passive` if available
- Remove wildcard-only wildcards (resolve `rnd.{domain}` first)

## 2. Enum CNAMEs and records
```bash
dnsrecon -d {domain} -t std,axfr -c /tmp/dns.csv
for h in $(cat subs.txt); do
  echo -n "$h "; dig +short CNAME "$h"
done | tee cnames.txt
```
- Look for dangling CNAMEs returning NXDOMAIN HTTP / 404 with provider signature
- Check `dig +short A {sub}` → empty answer while CNAME resolves to a removed host

## 3. Match against vulnerable provider signatures
Probe with `curl -sI {sub}` and grep body for:
- **S3**: `404 NoSuchBucket` / `<Code>NoSuchBucket</Code>`
- **Heroku**: `No such app` / `404 Heroku`
- **GitHub Pages**: `There isn't a GitHub Pages site here`
- **Azure**: `404 Web Site not found` / `404 - Anybody`
- **Fastly**: `Fastly error: unknown domain`
- **Tumblr**: `Whatever you were looking for doesn't currently exist`
- **Shopify**: `Sorry, this shop is currently unavailable`
- **Pantheon**: `The gods are wise, but do not be fooled`
- **Tilda**: `Please change your DNS records`
- **WordPress.com**: `Do you find this information helpful?`
- **Unbounce**: `The requested URL was not found on this server`
- **Webflow**: `The pages you are looking for aren't here` / `no site configured`
- **Strikingly**: `page not found` + `strikingly.com`
- **Cargo Collective**: `If you're moving your domain away from Cargo`
- **StatusPage**: `You are being redirected` to `statprod` default
- **Sthree Group**: `Do you want to show this page?`
- **Short.io**: `Link not found` / `short.io` 404
- **Smartling**: `Domain is not configured` / `smartling.com`
- **Sendgrid**: `You've reached this page in error` / `sendgrid.net`
- **Wishery**: `Domain pointing to Wishery`
- **Vercel**: `The deployment could not be found` / `vercel.app`
- **Netlify**: `Not Found - Request ID` / `netlify.app`
- **Cloudfront**: `Bad request` with `x-amz-cf-id`
- **Google Cloud**: `The requested URL was not found on this server` legacy GAE
- **Ghost.io**: `The page you're looking for doesn't exist`
- **Forwarding.net**, **Ngrok**, **Surge**, **Readme.io**, **interrupt Office365**: full list at `can-i-take-over-xyz`

## 4. Verify claimability
1. Register a new account on the detected provider (free tier OK)
2. Create a new site / bucket / app with placeholder content
3. Add the FQDN as your custom domain / CNAME target
- Provider asks for DNS verification → since the CNAME already points there, takeover succeeds
4. Confirm by `curl -sL {sub}` returning YOUR placeholder content
5. Note the timestamp, evidence screenshots, and how long it took to claim

## 5. Report PoC with clear impact
- Each takeover allow attacking **all users who trust the parent domain**:
  newsletter recipients, SSO redirect targets, cookies via superior scope restoration
  (`.parent.com` session cookie bleed), TLS trust continuity, password-manager auto-submit
- Deliverable: PoC screenshot with your controlled content served on `{sub}.{domain}`,
  CVSS score, remediation ("reclaim the deleted resource or remove the DNS record")

## IMPORTANT
- Never serve phishing content; placeholder "PoC by {researcher}" only
- In-scope: confirm wildcard takeovers, corp subnets, and historical buyouts (DNS history)
- Each finding ≥ provider signature + claimable proof + impact prose
- Test for race-time re-registration — expired domain or stale account reuse