---
name: binary-ninja-reverse
description: "Static reverse engineering with Binary Ninja: HLIL/MLIL/LLIL lifters, medium-level IL clean-up, custom BN plugins/scripts, headless analysis and type reconstruction across ELF/PE/Mach-O. Use when the task names Binary Ninja (binja), BN plugins, or High/Medium/Low-Level IL."
category: reverse
allowed_tools:
  - binaryninja
  - bn
  - python3
  - radare2
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Binary Ninja Reverse Methodology

## 1. Load & index
- `headless` mode: `binaryninja.headless.open_view` or CLI `bn` on stripped binaries.
- Let the auto-analysis run: BN tags functions, datarefs, strings, stack frames, indirect calls.
- Note the arch + `@variablecolor`: cross-check `binja --analysis` output.

## 2. Working at the right IL level
- **LLIL** (low): branch/goto clarity, exact instruction semantics, code patching.
- **MLIL** (medium): function-level dataflow, removes stack/register noise — default for logic review.
- **HLIL** (high): cleans if/else/loops and call arguments — best for reconstructing source intent.
- Promote/demote per function: `lift` then switch IL level with the `IL` drop-down.

## 3. Automation (BN API)
- `bn.plugin_manager.register_plugin_script` or standalone `python3` + `binaryninja` module.
- Batch scripts: enumerate functions → match patterns (`check_access`, string xrefs) → dump pseudo-IL.
- Report flows that survive MLIL clean-up (obfuscation candidates remain noisy at LLIL).

## 4. Decision vs other RE routes
- Rapid triage/decompilation at HLIL, or full plugin pipelines → this skill (preferred to Ghidra for large batch IL).
- IDA database/graft/xref depth → `ida-reverse`; radare2 CLI scripting → `binary-reverse`.

## 5. Findings
- Evidence: HLIL excerpt + BN analysis file (`.bndb`) path + xref context.
- Reproducible PoC: headless BN script + input binary snippet (redact embedded secrets).