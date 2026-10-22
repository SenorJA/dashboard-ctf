# ATTRIBUTION

M.I.R.V. (Multi-platform Incident Response & Vulnerabilities) incorporates
adapted portions of the projects listed below. Each entry states the source,
the licence, the component in this repository and the modifications made.

---

## 1. `MadsLorentzen/ai-job-search`

* **Source**: <https://github.com/MadsLorentzen/ai-job-search>
* **Licence**: MIT License
* **Component**: `backend/ingest_guard.py` — the *Ingest Guard* module.
* **Adapted from**: `tools/posting_guard.py` (hidden-HTML / invisible-character
  detection used by that project to sanitise job posting content before
  feeding it to an LLM).
* **Modifications**:
  * Rewritten as a self-contained, stdlib-only Python module with no network
    access, no CLI and no third-party dependency.
  * Detection rules extended: off-screen positioning, collapsed overflow
    boxes, `clip-path`/`clip` cropping, `transform: scale(0)`, `aria-hidden`
    and `inert` attributes, visually-hidden class names, Unicode **TAG block**
    (`U+E0000`–`U+E007F`), variation selectors and `Cf`/`Cc` control
    characters.
  * Added homoglyph detection (Latin mixed with Cyrillic/Greek), hidden-URL
    extraction, instruction-like line heuristics, HTML comment stripping and
    a structured `findings` report with a `verdict` (`"ok"` / `"warn"`).
  * Integrated into `backend/main.py` (`_prepare_chat_messages`, endpoint
    `POST /api/ingest/guard`), `backend/browser_capture.py`,
    `backend/lab_sessions.py` and `backend/intelligence.py`.

Original MIT notice:

```
MIT License

Copyright (c) Mads Lorentzen and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. `agency-agents` (AI personas)

* **Source**: <https://github.com/msitarzewski/agency-agents>
* **Licence**: MIT License
* **Component**: `backend/agents/` — 39 vendored AI personas
  (`security/`, `testing/`, `engineering/`, `specialized/`).
* **Modifications**: frontmatter adapted to the MIRV persona schema
  (`slug`, `division`, `vibe`, `mandate`, `body`) and the bodies trimmed to
  the prompt budget enforced by `backend/agency_agents.py`.
* **Full notice**: `backend/agents/ATTRIBUTION.md`.

---

## 3. `Android-Pentesting-Skill`

* **Source**: <https://github.com/DragonJAR/Android-Pentesting-Skill> (v1.9.0)
* **Licence**: Apache License 2.0
* **Component**: `backend/skills/android-pentesting/` — vendored skill
  playbook (`references/`, `assets/frida-scripts/`, `scripts/`, `benchmarks/`).
* **Modifications**: `SKILL.md` frontmatter mapped to the MIRV skill schema
  (`category: mobile`, `allowed_tools:` list).
* **Full notice**: `backend/skills/android-pentesting/ATTRIBUTION.md`.

---

## 4. `airgorah` (reference only)

* **Source**: <https://github.com/martin-olivier/airgorah>
* **Licence**: MIT License
* **Component**: referenced — not vendored — by
  `backend/skills/wireless-audit/SKILL.md` as the reference GUI for the
  host-based `aircrack-ng` audit flow.

---

## 5. `llm-scanner` / `augustus` (reference only)

* **Source**: <https://github.com/praetorian-inc/augustus>
* **Licence**: see upstream repository
* **Component**: referenced — not vendored — as the design reference for
  `backend/llm_scanner.py` (probe families, detector set and report shape).

---

## 6. `exploitpath` (reference only)

* **Source**: <https://github.com/hexastack/exploitpath>
* **Licence**: see upstream repository
* **Component**: referenced — not vendored — as the data-model reference for
  `backend/flag_detection.py`, `backend/lab_sessions.py` and
  `backend/lab_writeup.py`.

---

*Last updated: F1 (Ingest Guard) — see `CHANGELOG.md`.*
