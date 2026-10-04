---
name: llm-security
description: "Security assessment of LLM/AI applications: prompt injection and indirect prompt injection, system-prompt leakage and exfiltration, RAG data poisoning, jailbreaks and guardrail bypass, training-data extraction, model extraction/theft, MCP and AI-agent prompt injection, chain-of-thought leakage. Use for AI/LLM penetration tests and secure-by-default LLM app reviews."
category: llm
allowed_tools:
  - python3
  - curl
  - garak
  - promptfoo
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# LLM / AI Security Testing Methodology

## 1. Map the AI surface
- Identify entry points: chat completions, RAG retrieval endpoints, MCP tools, agent scaffolding.
- Determine the trust boundary: what retrieved content/plugins can steer the model (indirect injection surface).

## 2. Prompt-level attacks
- **Direct**: role-play/ignoring instructions) and ensure the task states a clear objective, then craft robust injection probes (delimiter escape, payload-only, multi-turn).
- **Indirect**: poison retrieved docs/tool output; test whether injected instructions override system policy.
- Measure leakage: attempt system-prompt extraction, hidden-instruction recovery, CoT reasoning disclosure.

## 3. RAG & data security
- **RAG poisoning**: injected authoritative-looking chunks injected into the source store; evaluate answer corruption and data exfiltration via prompt output.
- **Training-data extraction**: probe for memorized PII/secrets; classify by sensitivity.

## 4. Guardrails & policy
- **Guardrail bypass**: orthogonal encoding (unicode/spacing), base64, nested XML/JSON, translation; verify persistence across turns.
- **Model extraction/theft**: query-proxy probing to fingerprint the model; API cost-side inference.

## 5. Findings
- Evidence: full conversation transcript + injection payload + what was extracted (redact PII).
- Reproducible PoC: minimal script (garak probe or promptfoo case) reproducing the failure deterministically.