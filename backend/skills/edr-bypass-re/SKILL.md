---
name: edr-bypass-re
description: "EDR/AV evasion via reverse engineering of user-mode hooks: detect and restore ntdll trampolines (unhooking), direct syscall stubs, AMSI/ETW patching, import address table (IAT) hooks, reflective DLL loading, process hollowing and sleep obfuscation. Use when a sample or implant must survive on a defended host or when analyzing stealth/evasion binaries."
category: reverse
allowed_tools:
  - pe-sieve
  - pe-sieve64
  - pe-bear
  - mona
  - x64dbg
  - windbg
  - hyperdbg
  - frida
  - radare2
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# EDR / AV Evasion (RE-driven) Methodology

## 1. Enumerate hooks (defender / EDR context)
- Compare in-memory `ntdll`/kernel32 against a clean copy: `pe-sieve --scan` writes memory dump mapping.
- Detect IAT/import hooks (`pe-bear` IAT view), hot-patch 5-byte `jmp` stubs and inline hooks.
- Note hook offsets + original bytes for restoration evidence.

## 2. Choose the evasion primitive (RE-informed)
- **Direct syscalls**: resolve `syscall` indexes once, call via `syscall` stub in a manually curated section (beats trampoline patching).
- **Unhooking**: overwrite the hooked function with pristine `ntdll`/kernelbase bytes (restore-to-file).
- **AMSI / ETW**: patch `AmsiScanBuffer` and `EtwEventWrite` prologues (verify with `x64dbg`/`frida` breakpoints).
- **Reflective/redir DLL**: load from memory (reflective loader) to skip on-disk AV scanning.

## 3. Validate on the target
- Cold-start the implant in a sandboxed VM; confirm the defended-process program counter doesn't hit a hook trampoline.
- `hyperdbg`/`windbg` watch for anomalous breakpoints; check telemetry sources (ETW providers) are silenced only where intended.
- Re-run `pe-sieve` after execution: report which hooks were restored/patched.

## 4. Scope & legality
- Only test against engagement-authorized hosts. Evasion is a red-team/offensive capability:
  validate in your lab, document the baseline, never ship unmeasured implants.

## 5. Findings
- Evidence: hook diff (original vs patched bytes), syscall index table, patch prologues.
- Reproducible PoC: minimal binary + `hyperdbg`/`pe-sieve` verification script.