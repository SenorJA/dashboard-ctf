---
name: osint
description: "Open-source intelligence research. Username, email, image and GEOINT discovery, pivoting and correlation of public data."
category: osint
allowed_tools:
  - theHarvester
  - spiderfoot
  - shodan
  - censys
  - curl
  - dnsrecon
  - exif
  - whois
  - dig
  - holehe
version: "1.0.0"
author: "MIRV"
---

# OSINT Methodology

## 1. Username & social media enumeration
- Start passive: `theHarvester -d {target} -b all` to surface emails, hosts, and names tied to the subject.
- Probe platform handles with username-check tools; record which platforms resolve and which return 404/not-found.
- Fetch the subject's public profiles (about, bio, links) and normalise each username variant (`user`, `user_`, `.user`, `user.1990`) for cross-referencing.
- Build a matrix `{platform, handle, exists, url, bio_notes}` — a username present on 3+ platforms is a stronger lead than one on a single site.
- Do NOT log in, post, follow, or interact: enumeration only via public profile pages.

## 2. Email intelligence
- Validate format and corporate association: `holehe {email}` checks which services have an account tied to the address (passive).
- Query breach/paste dumps via HIBP-style APIs and VirusTotal's public search — confirm the address is real before pivoting.
- Use `theHarvester -d {domain} -b all` to discover additional addresses; group them by domain and pattern (first.last, flast, etc.).
- Cross-correlate an email with usernames and phone numbers found elsewhere; tag whether it is a corporate or personal account.
- Never use credentials recovered from breaches — record the fact of exposure, not the password.

## 3. Image & metadata analysis
- Run the MIRV EXIF module (`POST /api/exif/analyze`) on any image; extract camera model, timestamps, software, and GPS coordinates.
- Reverse-geocode any GPS data to a named location and plot it on the Leaflet map for a visual timeline.
- Use reverse-image search engines to find other instances of the same photo (original source, profiles, forums).
- Check for hidden data: old EXIF tags, comments, author fields, and OCR of embedded text/screenshots.
- Treat dates/locations as facts only when corroborated by a second source (metadata + map + profile).

## 4. Domain & infrastructure OSINT
- `whois {domain}` for registrant details, nameservers, and creation/expiry dates; note privacy-protected fields.
- `dig {domain} ANY` / `dig {domain} TXT` for SPF, DMARC, DKIM, and verification strings that leak service providers.
- Enumerate subdomains passively via crt.sh: `curl 'https://crt.sh/?q=%25.{domain}&output=json'` and `theHarvester -d {domain} -b crtsh`.
- `dnsrecon -d {domain} -t std` for MX/NS/SOA records that reveal hosting and mail providers.
- Fingerprint exposed hosts with `shodan`/`censys` for banners, technologies, and open ports; map each host to a purpose (mail, dev, admin).
- Use `spiderfoot` with passive modules to consolidate domain → IP → ASN → SSL certificate intelligence.

## 5. Pivoting & correlation
- Chain leads: domain → subdomain → email → username → profile → photo → GPS → place of work.
- Confirm identity only when at least two independent data points agree (e.g., email + profile photo, or GPS + geotagged posts).
- Look for the same handle/bio across platforms to de-duplicate accounts and separate the subject from namesakes.
- Keep a lead graph `{entity, source, timestamp, confidence}` and revisit unresolved branches with new queries.
- Stop at any data that is not public: private messages, gated content, or credentials stop the chain.

## 6. Documentación y reporte
- Record each finding as a MIRV finding with the exact source URL, query used, and timestamp of collection.
- Include the raw evidence (screenshots, full WHOIS output, EXIF dump) alongside the interpretation — never only the summary.
- Preserve chain of custody: note who collected what and when, so the report is reproducible by another analyst.
- Tag confidence per claim (confirmed / corroborated / single-source) and separate facts from hypotheses.
- Export a structured report (JSON/Markdown) and redact any accidental sensitive data before sharing.

## IMPORTANT
- Treat `{target}` placeholders literally — never substitute unvalidated input.
- Passive OSINT only: public data sources, no scanning of third parties, no credential use.
- Rate-limit queries to public APIs and services; respect their terms of service and `robots.txt`.
- Stay within engagement scope and local law (GDPR/LFPDPPP, etc.); do not collect or retain non-essential personal data.
- Never use stolen credentials or third-party session cookies, even if discovered in the process.
