---
name: mobile-reverse
description: "iOS / Apple mobile application reverse engineering: ipa unpack and inspection (ipatool, idevice_id/iproxy), class-dump of Objective-C/Swift frameworks, Mach-O framework triage with otool/jtool2, frida/objection dynamic hooks (SSL pinning bypass, keychain dump, jailbreak detection) and app-store package analysis. Use for iphone/ipad/ipa, darwin/Mach-O Apple apps, objectíon, class-dump or keychain extraction."
category: mobile
allowed_tools:
  - objection
  - ipatool
  - idevice_id
  - iproxy
  - class-dump
  - class_dump
  - libimobiledevice
  - frida
  - otool
  - jtool2
  - lipo
  - nm
  - strings
  - bitcode_strip
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Mobile Reverse Methodology (iOS / Apple)

## 1. Package acquisition & probe
- `ipatool search/download --bundle-id <id>` or device: `idevice_id -l` + `iproxy`.
- Verify bundle: `unzip -l app.ipa` → `Payload/App.app/`; check entitlements profile.
- `file App` per Mach-O slice; `lipo -info` for arch, `otool -l` for encryptions (FAKE-ENTITLEMENTS risk).

## 2. Static (frameworks & classes)
- `class-dump -H App -o out/` → Objective-C interfaces; Swift: `nm`/strings for mangled symbols.
- `jtool2 --ent` / `codesign -d --entitlements` → exported entitlements (keychain-access-groups, aps-environment).
- Map third-party SDKs (analytics, ad, chat) that add attack surface or data leaks.

## 3. Dynamic (frida / objection)
- `frida -U -f com.app.xyz --no-pause` → hook methods; `objection patchipa`/`explore` for runtime.
- Bypass SSL pinning + jailbreak detection via frida bypass scripts (bundle-jailbreak, ssl-pinning).
- Keychain extraction: `objection ios keychain dump`; flag hardcoded secrets in `strings App`.

## 4. Android vs iOS decision
- Android APK / smali / jadx / adb → `apk-reverse` (R10). Mach-O / ipa / iphone / keychain → this skill.
- Shared dynamic tooling (frida/objection) — prefer OS of the binary, not the hook framework.

## 5. Findings
- Capture entitlements + reachable exported functions; evidence excerpt from Mach-O/capabilities.
- Reproducible PoC: frida/cloak-ios script + bundle id; no App Store credentials in artifacts.