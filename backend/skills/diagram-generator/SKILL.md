---
name: diagram-generator
description: "Generate diagrams for technical documentation: attack flow, data-flow, sequence diagrams, call graphs and network topology in Mermaid (or SVG) for reports and briefings. Use when explanation needs a clear visual."
category: automation
allowed_tools:
  - python3
  - node
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Diagram Generator Methodology

## 1. Choose diagram type
- Attack flow / kill-chain (MITRE ATT&CK mapping) → Mermaid flowchart/sequence.
- Call graph → sequence/flow from addresses/xrefs.
- Network → topology with trust boundaries.

## 2. Generate
- Emit Mermaid in Markdown (renderable in many viewers); fallback to SVG if needed.
- Keep node labels short; annotate edges with technique IDs where relevant.

## 3. Integrate
- Embed in `docs-generator` output; link back to findings and evidence paths.
- Version diagrams with the case (case-id + hash).

## 4. Findings
- Evidence: diagram source (.mmd) + rendered output + checksum.
- Reproducible PoC: script that emits deterministic Mermaid from findings/graph.