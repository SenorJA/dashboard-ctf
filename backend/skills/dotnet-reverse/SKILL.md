---
name: dotnet-reverse
description: ".NET/C# assembly reverse engineering: metadata + IL inspection (dnSpy/ILSpy), version/strong-name review (sn, monodis), deobfuscation (de4dot), ConfuserEx handling, Unity/IL2CPP metadata dumps and mscorlib/wrapper analysis. Use for .NET malware, GameCheat mods, license-check bypass and managed binary review."
category: reverse
allowed_tools:
  - dotnet
  - mono
  - monodis
  - ildasm
  - dnspy
  - ilspy
  - de4dot
  - sn
  - strings
  - file
  - pedump
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# .NET Reverse Methodology

## 1. Triage
- `file <dll/exe>` → PE32+ CLR; `pedump --clr` → metadata version, entrypoint
- `strings` → namespaces, embedded config, flags
- Strong-name/version review: `sn -T <asm>`; check deps (`monodis --assemblyref`)

## 2. IL / decompilation
- dnSpy/ILSpy: decompile to C#; view IL (`monodis` / `ildasm`)
- Identify bypasses: `if(Settings.ValidLicence)` patterns, GetMethod/Reflection calls
- Trace secrets: string decrypt → DPAPI/Rijndael, base64 config blobs

## 3. Obfuscation
- ConfuserEx: `de4dot -f <asm> -r <deps>` (auto-detect rename/strings/cflow)
- Post-deobfuscation: rerun decompiler; verify no method bodies dropped
- Unity/IL2CPP: metadata.dat + global-metadata.dat → Il2CppDumper; assemblies via BepInEx

## 4. Dynamic checks (authorized only)
- Injection/patching is red-team territory: keep evidence, flag scope
- Record control-flow + verdict as a reproducible PoC (byte patches + witness)