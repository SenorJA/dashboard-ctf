---
name: dsl-vm-reverse
description: "Reverse engineering of custom DSL/custom virtual machines and bytecode obfuscation (JavaScript VM/opcode VM, wZ/jsvmp, Obfuscator-io style, EVM/wASM bytecode): recover the handler dispatch table, per-opcode semantics and reconstruct the source-level flow. Use when the code is dictated by a custom VM, opcode handlers, bytecode VMs or VM-based obfuscation."
category: reverse
allowed_tools:
  - node
  - python3
  - js-beautify
  - radare2
  - r2
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# DSL / Custom VM Reverse Methodology

## 1. Identify the VM
- Look for a `dispatch`/`switch(op)` loop + `opcode handler` table and an `exec` entry point.
- Distinguish wZ-style register VMs, jsvmp (JS-protect), Obfuscator VM (ExVM) and EVM/wASM bytecode.
- `strings`/variable-length opcode constants → recover the opcode encoding length and immediates.

## 2. Recover the handler table
- Locate the jump/call targets of the dispatcher (radare2: `pdf` on `switch`, `axt`), or beautify the JS source and index the handler functions.
- Tag each handler: opcode id, operand fetch, side effect (stack/reg/global), and control-flow effect.
- Dump the table to JSON (opcode → name, args, semantics) as working evidence.

## 3. Reconstruct semantics
- Emulate or deobfuscate: onion-layer eager execution (`node` micro-runtime) vs symbolic tracing.
- For each reconstructed function, map back to pseudo-code; note where the VM re-encodes strings/arithmetic.
- If the VM switches on string opcodes (JS), a simple AST rewriter often yields the raw logic.

## 4. Decision vs other RE routes
- Whole native binaries under a true `OLLVM`-style VM → `binary-reverse`/`ida-reverse`.
- `.NET` IL VM (IL2CPP) → `dotnet-reverse`; plain packed JS → `js-reverse`.

## 5. Findings
- Evidence: opcode table excerpt + reconstructed pseudo-code + handler addresses.
- Reproducible PoC: minimal script that drives the VM to the interesting state (no full decode needed).