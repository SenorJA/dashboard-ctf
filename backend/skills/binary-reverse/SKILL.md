---
name: binary-reverse
description: "Static binary reverse engineering: ELF/PE/Mach-O triage (file, strings, hashes, entropy), symbol recovery (nm, ELF section headers, PDB/Go buildinfo), decompilation (Ghidra/IDA), radare2/Rizin scripting, GDB/ANGR-driven triage and obfuscation recovery (OLLVM, control-flow flattening, anti-debug). Use for native libraries (.so), stripped executables, malware defanging and unknown binary analysis."
category: reverse
allowed_tools:
  - file
  - strings
  - objdump
  - readelf
  - nm
  - ghidra
  - radare2
  - r2
  - gdb
  - angr
  - capa
  - strace
  - ldd
  - checksec
  - rabin2
  - rasm2
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Binary Reverse Methodology (static-first)

## 1. Triage (never skip)
- `file <binary>` → format (ELF/PE/Mach-O), arch, stripped?, static/dynamic
- `sha256sum` → hash (VT/Intelligence lookup), `ent` for packed/poly suspicion
- `strings -n 6` → paths, URLs, crypto keys, error strings
- `checksec --file=<binary>` → NX/PIE/RELRO/stack canaries
- `rabin2 -I` / `readelf -h -S -l` → headers + sections (upx? → `upx -d`)

## 2. Symbols & entry points
- `nm -C` / `rabin2 -s` → exposed/imported symbols; stripped → `capa` for capability maps
- Go binaries: `go version -m` from section buildinfo; Rust: `rustc` crate names in strings
- Locate WinMain/main or init_array → entry for decompiler

## 3. Static decompilation
- Ghidra headless: `analyzeHeadless /proj tmp -import <bin> -postScript ...`
- IDA: FLIRT signatures; radare2: `aaa; afl; pdf @ main`
- Rebuild calling conventions/types from ABI; note data-flow for crypto/serialization

## 4. Obfuscation / anti-debug
- OLLVM: look for opaque predicates, `sub_` sprawl + `b` (unconditional) patterns
- Control-flow flattening: reconstruct dispatcher loop → re-linearize states
- `strace -f` / `gdb` breakpoints only AFTER static pass; patch `ptrace` checks if needed

## 5. Findings
- Record → Finding (evidence hash, addresses, callgraph excerpt)
- Reproducible PoC: IDA/Ghidra script + input bytes; never paste keys/logs un-redacted