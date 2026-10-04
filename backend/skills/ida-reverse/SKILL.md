---
name: ida-reverse
description: "IDA Pro static reverse engineering: database-driven triage (.idb), FLIRT signature matching, graft/xref navigation, pseudocode (F5) recovery, Hex-Rays decompiler output, function demangling and call-graph reconstruction for ELF/PE/Mach-O. Use when the task names IDA/idat/idapro, .idb databases, Hex-Rays, graft analysis or pseudocode extraction."
category: reverse
allowed_tools:
  - ida
  - idat
  - idapro
  - hex-rays
  - bindiff
  - qiling
  - ghidra
  - radare2
  - r2
  - readelf
  - objdump
  - nm
  - strings
  - capa
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# IDA Pro Reverse Methodology

## 1. Project / database setup
- `idat -A -L<log> -c -o<out>.i64 <binary>` — build an analysis database headless.
- Prefer fresh analysis over reuse; keep `.idb`/`.i64` with the sample (evidence hash).
- Load FLIRT signatures (`.sig`) for common libc/libstdc++/minizip; resolve known crypto.

## 2. Entry points & symbols
- AutoStructures → `nm`/`idat -S` to confirm imports/exports; Go/Rust/Python embedded runtimes first.
- `WinMain`/`main`/`init_array`/entrypoint → set entry point, split functions if needed.
- Demangle C++/Rust with `Decompile` demangler; dump names with `idat -S` + `nm -C`.

## 3. Analysis (graft / xref / pseudocode)
- Use xrefs tool (`x` on operand / `idat -C -t ... -x`) to trace caller chains to user input.
- F5 / Hex-Rays pseudocode on hot functions; cross-check with disassembly for patched-inline code.
- Annotate data-flow: `qiling` to emulate reachable paths, `bindiff` for version comparison.

## 4. Shared reverse-skill decisions
- `.NET/C#` assemblies (IL/CLR) → `dotnet-reverse` (dnSpy/de4dot), not IDA.
- Interactive/debugger triage on local samples → `binary-reverse` (Ghidra/radare2/gdb) is usually faster.
- Vendor patch diffing / N-day → `patch-diff-exploit` (BinDiff/Diaphora) after IDA loading.

## 5. Findings
- Record addresses, offsets and callgraph excerpt; save reconstructed types/structs as scripts.
- Reproducible PoC: IDA Python (`idaapi`/`idautils`) snippet + input bytes; redact keys/logs.