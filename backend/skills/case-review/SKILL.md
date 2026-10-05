---
name: case-review
description: "Evidence graph review and artifact fixity checks: validate scope→Evidence→Finding→Path traceability, workitems/timeline consistency, artifact hashes and chain-of-custody hygiene. Use after analysis to verify reproducibility and close findings cleanly."
category: automation
allowed_tools:
  - sha256sum
  - python3
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Case Review Methodology

## 1. Scope & traceability
- Verify findings map to in-scope assets only; each Finding links to ≥1 Evidence item with path + hash.
- Check Evidence→Finding→Path is bidirectionally consistent (no orphan evidence).

## 2. Fixity & timeline
- Recompute hashes (`sha256sum`) for attached artifacts; detect tampering/moves.
- Validate workitems/timeline order (triage→static→dynamic→synthesis) with timestamps.

## 3. Hygiene
- Ensure PoCs are minimal/reproducible and logs are redacted (no secrets/PII).
- Closeout gate: all required artifacts present, README/writeup references correct paths.

## 4. Findings
- Evidence: traceability matrix + hash verification log (pass/fail per artifact).
- Reproducible PoC: checklist script that validates the evidence graph deterministically.