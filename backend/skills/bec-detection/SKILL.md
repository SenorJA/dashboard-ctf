---
name: bec-detection
description: "Detect Business Email Compromise. SPF/DKIM/DMARC analysis, header forensics, sender impersonation patterns."
category: defense
allowed_tools:
  - curl
  - dig
  - python
  - mailheader
  - mxtoolbox
version: "1.0.0"
author: "MIRV"
---

# Business Email Compromise (BEC) Detection Methodology

## 1. When to Use
- A finance/user reports an email requesting urgent wire transfer, gift cards, or invoice redirection.
- Sender display name does not match the actual `From:` address.
- A vendor claims their bank details changed and you must verify the email's authenticity.
- Security awareness team flags a possible executive impersonation ("CEO fraud").
- You are hardening email posture and want to baseline SPF/DKIM/DMARC coverage across suppliers.

## 2. Prerequisites
- The raw email source (`.eml` / `.msg` exported with full headers — not a screenshot).
- `dig` and `curl` for SPF/DKIM/DMARC DNS lookups.
- `mxtoolbox` or equivalent for MX/SPF reputation checks.
- `python` with `email` and `dkim` libs for programmatic parsing.
- Access to the recipient mail gateway logs (Proofpoint, Mimecast, M365) to correlate routing.
- A list of legitimate executive/vendor domains and known sender patterns for comparison.

## 3. Workflow
1. **Extract and parse headers**
   - Save the message as `.eml` and parse with `python -c "import email; m=email.message_from_file(open('{eml}')); print(m.as_string())"`.
   - Read top-to-bottom: the **last** `Received:` header before the gateway is the originating IP; trace the hop chain for anomalies (e.g. a `Received` from a residential ISP before the corporate gateway).
   - Identify the `Return-Path`, `From`, `Reply-To`, `Sender`, and `Message-ID` — mismatches are the core BEC signal.
2. **Authentication results**
   - Look for `Authentication-Results-Original` / `Authentication-Results` headers from the gateway.
   - SPF: `spf=pass|fail|softfail|none`. `fail`/`softfail` on a purported vendor domain = high risk.
   - DKIM: `dkim=pass|fail|none` and the `d=` signing domain — a BEC often signs with a lookalike domain (`paypa1.com`) while spoofing `From: paypal.com`.
   - DMARC: `dmarc=pass|fail|none` and `policy` (`p=quarantine`/`reject`). A `fail` that was still delivered means the gateway did not enforce DMARC.
3. **DNS authentication audit of the spoofed domain**
   - `dig TXT {domain}` → SPF record; check `-all` vs `~all` vs `?all` (lax = spoofable).
   - `dig TXT _dmarc.{domain}` → DMARC policy; `p=none` means the domain allows spoofing.
   - DKIM selector lookup: from the `DKIM-Signature` `s=` field, `dig TXT {s}._domainkey.{d}` → public key present?
   - `mxtoolbox` SuperTool: `spf:{domain}`, `dkim:{domain}`, `dmarc:{domain}` for a consolidated view.
4. **Sender impersonation patterns**
   - **Display-name spoofing**: `From: "CEO Name" <attacker@freemail.tld>` — `From` address is a free provider but the name matches the executive.
   - **Lookalike domain**: `From: ceo@company-secure.com` vs legitimate `company.com` — check punycode (`xn--`), extra hyphens, TLD swaps.
   - **Reply-To mismatch**: `From: vendor@vendor.com` but `Reply-To: vendor@freemail.tld` — replies go to the attacker.
   - **Compromised account**: `From` is a real vendor address but the IP/language/timing differs from baseline — check the gateway's "impossible travel" alerts.
5. **Content & behaviour signals**
   - Urgency, secrecy, pressure to bypass normal approval ("don't call me, just process it").
   - Bank account / payment detail changes inside the email body or an attached "invoice".
   - Attachments: `.htm`, `.js`, password-protected `.zip`, or a fake login page — submit to sandbox, never open on a user mailbox.
   - Language quirks: mismatched signature, off-hours send time, reply-to in a different timezone.
6. **Correlate with gateway & logs**
   - Search the gateway for other messages from the same `Return-Path` / IP / `Message-ID` pattern in the last 30 days.
   - Cross-check sender IP geolocation vs the vendor's known country of operation.
   - If the account is compromised (not spoofed), look for inbox rules auto-deleting replies or forwarding to an external address.
7. **Decision point**: if SPF/DKIM/DMARC all `fail` OR a reply-to mismatch + payment request is present, classify as confirmed BEC, quarantine all matching messages, alert finance, and freeze any in-flight payment.

## 4. Verification
- A BEC is confirmed when at least one of: (a) auth results `fail` + spoofed display name, (b) reply-to mismatch + payment request, (c) lookalike domain with valid DKIM but DMARC `fail`.
- Map to MITRE ATT&CK:
  - **T1566.002** Phishing: Spearphishing Link — for fake login attachments.
  - **T1534** Internal Spearphishing — if a compromised vendor account sends to your org.
  - **T1586** Compromise Accounts — when the sender account itself is hijacked.
- Validate remediation: after DMARC enforcement, send a spoofed test (`mailspoof`) and confirm the gateway rejects/quarantines.
- Produce a per-domain scorecard: `{domain, spf, dkim, dmarc_policy, spoofable?, last_tested}` for your top 50 suppliers.

## IMPORTANT
- Investigate only emails you are authorised to analyse (mailbox owner consent or IR scope).
- Respect the privacy of communications: do not read unrelated messages in the same mailbox.
- Treat `{target}` / `{eml}` / `{domain}` placeholders literally — never substitute unvalidated input.
- Never click links or open attachments from a suspected BEC on a production workstation — use an isolated sandbox.
- Redact PII (recipient addresses, vendor contact details) before sharing findings; MIRV redaction applies on save.
- Report confirmed BEC to finance/legal immediately — wire recall windows are measured in hours, not days.
- Do not confront the sender directly if the account is compromised; coordinate with the vendor's security team.
