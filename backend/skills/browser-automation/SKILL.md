---
name: browser-automation
description: "Browser and desktop automation for app-level testing: Playwright/Puppeteer/Selenium flows, headless Chrome/CDP control, request+cookies+localStorage capture, HAR export, and Windows UI Automation (uiautomation/pywinauto) for desktop applications. Use for end-to-end flows, frontend interception and automating UI verification."
category: automation
allowed_tools:
  - playwright
  - puppeteer
  - selenium
  - chromium
  - chromedriver
  - pywinauto
  - uiautomation
version: "1.0.0"
author: "MIRV"
requires_scope: true
---

# Browser / Desktop Automation Methodology

## 1. Choose the driver
- Web: Playwright (multi-context, network stubbing) for flow tests; Puppeteer/Selenium fit existing stacks.
- Desktop Windows: `pywinauto`/UIA for classic/WinUI apps; required when the app is not browser-based.

## 2. Build the flow
- Script the end-to-end journey (login → key action → data view → logout) in an idempotent, timeable way.
- Use unique IDs/data attributes as locators (avoid brittle CSS), wait on network-idle/assertions not sleeps.
- In headless mode (`headless.?browser`) keep the same engine version as production.

## 3. Capture & verify (security-aware)
- Intercept requests: log cookies, localStorage, Authorization headers, CSRF tokens — feed findings into `Burp Bridge`/findings.
- Save HAR for `browser_capture` analysis (R23 reviews traffic; `js-reverse` for front-end crypto).
- For auth-heavy flows, verify tokens don't leak to third-party origins during the scripted run.

## 4. Cleanup & scale
- Run in disposable contexts (incognito containers), clear credentials on teardown.
- Parallelize per-browser-instance; keep captured artifacts (HAR/PDF) out of git (attach to findings).

## 5. Findings
- Evidence: HAR excerpt + script + screenshots; tag auth/cookie/token issues to their findings.
- Reproducible PoC: shortheaded script + expected vs actual assertion output.