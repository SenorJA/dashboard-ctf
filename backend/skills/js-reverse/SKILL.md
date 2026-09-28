---
name: js-reverse
description: "Frontend JavaScript reverse engineering: webpack/bundle re-engineering, minified+obfuscated logic recovery, cryptojs signature generation, Chrome DevTools Protocol (CDP) capture, browser automation and request replay. Use for encrypted request params, frontend signing, fake-device HTTP signatures and client-side crypto."
category: reverse
allowed_tools:
  - node
  - electron
  - chromium
  - cdpx
requires_scope: true
version: "1.0.0"
author: "MIRV"
---

# Frontend JS Reverse

## 1. Find the logic

1. Load the target in a browser; open DevTools → Sources.
2. Network tab → find the XHR/fetch that builds the **encrypted/signed param**.
3. Get the raw bundle(s): `/static/js/main.*.js`, webpack chunks, or inline `<script>`.
4. `node` one-liner to pull a bundle to disk: keep a copy (evidence).

## 2. Beautify & locate

- Prettify the bundle: `npx prettier --write bundle.js` (or DevTools “Pretty print”).
- Grep for the algorithm markers:
  - `cryptojs|CryptoJS`, `AES`, `DES`, `RSA`, `encodeURIComponent`
  - `md5|sha1|sha256|hmac` call sites, hex/base64 helpers
- Mark the function that transforms the plain request into the sent one — set a breakpoint there.

## 3. Reproduce outside the page

- **Extract the module**: prettified bundle → find the factory closure (`__d`/webpack runtime) →
  copy the function into a small Node harness that exports it.
- If it needs globals (`window`, `document`), stub them:
  ```js
  global.window = {}; global.document = { cookie: '' };
  ```
- Call it with your values and compare to a live request until byte-identical.

## 4. CDP capture / automation

- Launch headless with remote debugging: `chromium --remote-debugging-port=9222`,
  then drive via `Browser Capture` HAR import in MIRV,
  or automate with a CDP script to collect device-signed requests.
- Record HAR → import into **Browser Capture** → MIRV auto-runs the 10 security checks.

## 5. Fake-device behavior

- Once the signer is reproduced, build a tiny Node client that walks the login/API flow,
  changing the "device" fields to confirm server-side trust boundaries:
  - Device id, fingerprint, `X-Device-*` headers, timestamps.
- Confirm whether params are **server-verified** (tamper → rejection) or **only UI-obscured**.

## 6. Deliverables (MIRV flow)

- Report the weakness as a Finding: `tool=js-reverse`, severity depends on impact
  (e.g. broken anti-automation → medium; missing server-side integrity → high).
- Attach the reproduction harness as PoC (script) — not a curl one-liner.
- Keep the original bundle + prettified copy; log to audit.