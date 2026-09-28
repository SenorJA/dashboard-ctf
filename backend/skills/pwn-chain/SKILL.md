---
name: pwn-chain
description: "Binary exploitation (CTF/authorized pentest): checksec hardening review, GDB/debugger triage, ROP/ret2libc/ret2win chains, pwntools scaffolding, format string and heap exploitation primers. Use for stack/heap overflow challenges, binary services, and exploit development."
category: pwn
allowed_tools:
  - pwntools
  - gdb
  - radare2
  - checksec
  - ropper
  - python3
requires_scope: true
version: "1.0.0"
author: "MIRV"
---

# Pwn / Binary Exploitation

## 0. Authorized only

Exploitation requires an asset inside assessed scope (CTF box, lab VM, or customer-owned service).
Never point exploitation tooling at third parties. Record scope in the Assessment before starting.

## 1. Recon of the binary

1. `file vuln` → arch, endianness, stripped, pie/non-pie.
2. `checksec --file=vuln` → `RELRO`, `CANARY`, `NX`, `PIE`, `FORTIFY`.
3. `strings vuln | grep -iE 'flag|system|/bin/sh|win|shell'` — common CTF helpers.
4. Run it: deterministic behavior? buffered input? leaks on error? (`nc` if it's a service).

## 2. Find the bug

- Idempotent fuzzing first: `gdb` + short python (pwntools) to vary length/format.
- Common patterns:
  - stack buffer overflow (`gets`, `strcpy`, `read` without bound)
  - format string (`printf(buf)`) → leaks / arbitrary write
  - heap (`free`→`double free`, `use after free`, Tcache poisoning)
  - off-by-one / integer overflow in index computations

## 3. Build the chain

- **ret2win**: overflow → return to win/flag function. Padding = `cyclic(200)` → crash offset via `cyclic_find`.
- **ret2libc** (NX): leak a libc GOT entry (`puts@got`) → compute `libc.base = leak - offset` → `system`+`/bin/sh`.
- **ROP**: `ropper --file vuln --search "pop rdi"` → chain gadgets; `ROP` class in pwntools assembles it.
- **Format string**: `%n$p` leaks → write GOT/return using `fmtstr_payload`.

## 4. Scaffold with pwntools

```python
from pwn import *
p = process('./vuln')          # or remote('host', port)
p.sendlineafter(b'> ', b'A'*off + payload)
win = p.recvall()
print(win)
```

Script it, then convert the reliable exploit into a Finding PoC (replayable).

## 5. ASLR / PIE notes

- PIE: partial overwrites of a known pointer to skip ASLR (especially `ret` at lower offset byte).
- No PIE + no canary = trivial ret-chain even on remote.

## 6. Deliverables (MIRV flow)

- Finding severity: code-exec → high/critical; info-leak-only → medium.
- Attach exploit .py as PoC + sha256 of binary + stack/ROP summary.
- Only high-severity, verified exploitation becomes a formal finding; log every connection to audit.