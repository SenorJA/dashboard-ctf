---
name: docs-generator
description: "Generate technical documentation and reports: reverse engineering reports, penetration test reports, CTF write-ups, and signature-reverse reports with consistent Markdown/PDF-ready structure, TOC, evidence tables and redaction-aware exports."
category: automation
allowed_tools:
  - python3
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Documentation Generator Methodology

## 1. Structure
- Standard sections: Executive Summary, Scope, Methodology, Findings (with CVSS/PoC/Evidence), Impact, Recommendations, Appendix, References.
- TOC auto-generated; figures/tables numbered; each finding has Evidence table (path+hash).

## 2. Evidence & redaction
- Import findings (Finding PoC) and embed only redacted excerpts; never inline secrets/PII/tokens.
- Preserve artifact hashes and timestamps in the Appendix.

## 3. Export
- Markdown-first (single source of truth), export to HTML/PDF via existing lab/writeup renderers when available.
- Include reproducibility block (commands + environment + commit SHA).

## 4. Findings
- Evidence: generated report + template version used.
- Reproducible PoC: report-generation script that reads findings and emits deterministic Markdown.