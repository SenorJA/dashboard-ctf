---
name: field-journal
description: "Maintain a structured field journal for each engagement: timeline, decisions, observations, errors, pivots and artifacts with timestamps, hashes and redaction. Use to keep an auditable trail across operators and phases."
category: automation
allowed_tools:
  - python3
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Field Journal Methodology

## 1. Structure per entry
- Timestamp (UTC), operator, phase, action, rationale, evidence path+hash, scope-impact.
- Mark pivots (changed hypothesis/route) and blockers explicitly.

## 2. Hygiene
- Auto-redact secrets/PII; never paste tokens/keys; store hashes, not raw dumps when avoidable.
- Link entries to findings (finding_id) and workitems.

## 3. Export/closeout
- Append-only log; export as Markdown/JSON for case-review and final report.
- Verify coverage against the full timeline at closeout.

## 4. Findings
- Evidence: journal excerpt + checksum of the journal file.
- Reproducible PoC: minimal logger that enforces redaction + UTC + required fields.