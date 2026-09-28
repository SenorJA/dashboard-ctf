---
name: apk-reverse
description: "Android APK static + dynamic reverse engineering: unpack, Java/Kotlin decompile (jadx), smali patch + repack (apktool), APK signature inspection (apksigner), dynamic hooking (Frida), emulator/device flows (adb, mobsf). Use for certificate pinning bypass, root detection, native (.so) analysis and security flags."
category: mobile
allowed_tools:
  - jadx
  - apktool
  - apksigner
  - frida
  - adb
  - mobsf
  - objection
  - java
requires_scope: true
version: "1.0.0"
author: "MIRV"
---

# APK Reverse Engineering

## 1. Triage (before touching anything)

1. `apksigner verify --print-certs app.apk` — signing cert + digest.
2. `aapt dump badging app.apk` (or `apkanalyzer`) — package, permissions, minSdk, activities/exported flags.
3. `unzip -l app.apk | grep -E '\.so$|classes\d*\.dex$|assets/'` — native blobs vs DEX.
4. Hash the sample (`sha256sum app.apk`) and record it — evidence hygiene.

## 2. Static decompile

- **jadx**: `jadx -d out/ app.apk` (`--show-bad-code` for obfuscated). Grep for:
  - hardcoded secrets: `password`, `api_key`, `secret`, `BEGIN.*PRIVATE KEY`, base64 blobs
  - together: `retrofit|okhttp|retrofit2|ktor` base URLs and endpoints
  - logic flags: `BuildConfig.DEBUG`, `root`, `debuggable`, `isRooted`
- **apktool**: `apktool d app.apk -o smali/` — decode the real `AndroidManifest.xml`;
  look at `application: debuggable`, `networkSecurityConfig`, exported receivers (`android:exported="true"`).

## 3. Certificate pinning bypass (common ask)

1. Identify the pinning library (okhttp3 `CertificatePinner`, `TrustManager` overrides, or native).
2. Passive: hook with Frida:
   - `frida-compile` `Objection`: `objection -g <app> patchapk -s <app.apk>` for SSL pin bypass
   - Manual: hook `okhttp3.CertificatePinner.check` / `X509TrustManager.checkServerTrusted`
3. Alternative: patch `network_security_config` (debug-overrides) or android:debuggable.

## 4. Root detection / repack

- Locate checks: `su`, `/system/bin/su`, `Magisk` paths, `ExecSQL`, `debugger` detection.
- Hook via Frida `Java.perform` overriding the check methods, or smali-NOP the branch in `apktool` output, then:
  `apktool b smali/ -o patched.apk` → `keytool`/`apksigner` sign → install on device.

## 5. Native (.so) path

- If DEX logic delegates to `.so`/JNI: extract and analyze with `ghidra`/`radare2` (see `pwn-chain`),
  or run `jadx` with `--show-bad-code` to map `native` method signatures to symbols.

## 6. Dynamic analysis (device emulator)

- Emulator: `adb devices` → `emulator -avd <name>`
- `adb install patched.apk` → start activity: `adb shell am start -n <pkg>/.<Activity>`
- Traffic: `adb shell settings put global http_proxy 127.0.0.1:8080` + Burp/SoReuse,
  or `frida-trace -i "recv" -U <app>` for TLS-tunnel bypass.
- Full automated mobile scan: `mobsf` (upload the sample; get manifest, permissions, code analysis).

## 7. Deliverables (MIRV flow)

- Save decompiled source + findings via Findings tab (`severity` + `tool=jadx/apktool/frida`).
- Reproduce pinning bypass as a finding PoC (curl replay not applicable — attach Frida script).
- Keep hashes and file paths; log to audit.