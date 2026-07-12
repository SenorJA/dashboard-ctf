# AGENTS.md — M.I.R.V. (Multi-platform Incident Response & Vulnerabilities)

## Architecture

Two-tier app: **FastAPI backend** serves static frontend + WebSocket SSH proxy + REST API.

```
Browser → WS (localhost:8000/ws) → FastAPI → Paramiko → Kali SSH
         ↑
   serves /static/* from frontend/
   REST API (65+ endpoints) → Supabase (PostgreSQL)
```

```
C:\Users\34678\Desktop\Proyecto ciber\
├── backend/
│   ├── main.py              # FastAPI app (~2270 lines, 80+ endpoints)
│   ├── database.py           # Supabase CRUD layer (17 tables)
│   ├── mcp_server.py         # MCP Server for AI agents
│   ├── swarm.py              # Multi-operator coordinator
│   ├── mobile_analyzer.py    # APK static + dynamic analysis
│   ├── forensics.py          # Digital forensics analysis
│   ├── knowledgebase.py      # CVE + MITRE ATT&CK DB
│   ├── scope_guard.py        # Scope validation (Warn/Block)
│   ├── adb_controller.py     # ADB device controller
│   ├── opsec.py              # OPSEC levels (30 tools)
│   ├── mission_store.py      # Self-Improvement Loop
│   └── requirements.txt
├── frontend/
│   ├── index.html           # SPA (Tailwind CDN, 15 tabs, ~1750 lines)
│   ├── css/
│   │   └── style.css         # Signal Intelligence + Monochrome theme (~873 lines)
│   ├── img/
│   │   ├── logo.svg           # Full logo (hexagon + radar + typography)
│   │   ├── favicon.svg        # Browser favicon
│   │   └── icon-192.svg       # PWA/desktop app icon
│   └── js/
│       ├── main.v2.js         # All frontend logic (~5370 lines)
│       ├── main.js            # Legacy version
│       ├── dataservice.js     # Supabase REST client
│       ├── mobile.js          # Mobile analysis UI
│       ├── forensics.js       # Forensics UI
│       └── swarm.js           # Swarm UI
├── .opencode/
│   └── agents/              # OpenCode agent definitions
└── docs: README.md, ROADMAP.md, PRODUCTION_PLAN.md, PERSISTENCE_AUDIT.md, MIRV_DESKTOP_PLAN.md, VULNFORGE_VS_T3MP3ST.md
```

## How to run

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

**Dependencies:** `fastapi`, `uvicorn`, `gunicorn`, `websockets`, `paramiko`, `supabase`, `reportlab`, `python-dotenv`, `python-multipart`.

## Backend modules (main.py + 8 modules)

| File | Lines | Purpose |
|------|-------|---------|
| `main.py` | ~2299 | FastAPI app, WebSocket SSH proxy, 85+ REST endpoints + CSP middleware |
| `database.py` | ~1344 | Supabase CRUD (connections, scripts, reports, findings, payloads, credentials, CTF, forensics, mobile) |
| `mcp_server.py` | ~620 | MCP Server exposes tools to AI agents (Claude Code, Cursor, etc.) |
| `swarm.py` | ~250 | Multi-operator swarm coordinator (Recon, Scanner, Exploiter, Report) |
| `mobile_analyzer.py` | ~707 | APK static analysis (apktool, jadx, mobsf) + dynamic (ADB/Frida) |
| `forensics.py` | ~253 | Digital forensics (memory, disk, Sleuth Kit) |
| `knowledgebase.py` | ~210 | CVE database + MITRE ATT&CK techniques |
| `scope_guard.py` | ~261 | Scope validation (Warn/Block modes) |
| `adb_controller.py` | ~205 | ADB device detection + Frida scripts (run/stop/clear) |
| `opsec.py` | ~400 | OPSEC Levels — 30 tools with Silent/Covert/Loud modifiers |
| `mission_store.py` | ~356 | Self-Improvement Loop — mission history + AI context |

## Backend quirks (main.py)

- **First WS message must be JSON auth**: `{"type":"auth","ip":"...","port":22,"user":"...","pass":"..."}`
- SSH uses `invoke_shell()` for interactive PTY session.
- `p10k disable` sent on connect → Powerlevel10k prompt disabled.
- sudo commands intercepted with `sudo -S` + password piped via heredoc.
- Static files served via `/css/`, `/js/`, and `/img/` routes (path traversal protected).
- `/favicon.ico` serves SVG favicon as fallback.
- `asyncio.to_thread()` for non-blocking SSH operations.
- AI chat endpoint: `/api/ai/chat` (OpenAI-compatible, supports multiple providers).
- AI suggestions: `/api/suggest` (receives findings, returns next-step suggestions).

## Frontend structure (15 tabs)

| Tab | ID | Purpose |
|-----|----|---------| 
| Terminal | `tab-terminal` | SSH interactive shell + command bar |
| Reports | `tab-reports` | Saved scan reports + export |
| Scripts | `tab-scripts` | Script builder + deploy to /tmp/ |
| Bounty | `tab-bounty` | Bug bounty report generator |
| AI Writeup | `tab-aiwriteup` | AI-powered vulnerability writeups |
| Findings | `tab-findings` | Parsed tool findings with severity filters |
| Op Admiral | `tab-opadmiral` | AI mission planner |
| Automation | `tab-automation` | n8n workflow integration |
| Swarm | `tab-swarm` | Multi-operator swarm visualization |
| Credentials | `tab-credentials` | Credential store (discovered creds) |
| KnowledgeBase | `tab-knowledgebase` | CVE + MITRE ATT&CK search |
| CTF | `tab-ctf` | CTF challenges with flag tracking |
| Mobile | `tab-mobile` | APK analysis lab (static + dynamic) |
| Forensics | `tab-forensics` | Digital forensics lab |
| Payload Studio | (external link) | Hak5 payload editor (opens new tab, X-Frame-Options blocked) |

- **Single HTML file** (`index.html`, ~1764 lines) — no build step, no bundler, no framework.
- **Tailwind via CDN** (`https://cdn.tailwindcss.com`). Custom colors: `neon`, `cyber`, `deep`, `void`, `blood`.
- **All JS in one file** (`main.v2.js`, ~5371 lines) — DOMContentLoaded closure, functions on `window.*`.
- **Mobile JS** (`mobile.js`, ~395 lines) — APK analysis + Frida console (run/stop/clear).
- **Forensics JS** (`forensics.js`, ~306 lines) — memory, disk, file analysis.
- **Swarm JS** (`swarm.js`, ~283 lines) — multi-operator pipeline UI.
- **DataService JS** (`dataservice.js`, ~228 lines) — Supabase REST client.
- **Vanilla JS**, no router, no package.json for frontend.

## Key JS globals (window.*)

| Function | Purpose |
|---|---|
| `launchTool(toolId)` | Main dispatcher — validates target, builds command, sends via WS, sets `currentToolRunning` |
| `sendPredefinedCmd(cmd)` | Sends command to WS with `▶` prefix |
| `sendCommand()` | Reads manual input and sends |
| `appendOutput(text)` | Terminal output (ANSI strip, \r handling, buffer accumulation, prompt detection) |
| `switchTab(name)` | Toggles among 15 panes |
| `toggleTheme()` | Toggles `body.monochrome` class, persists to localStorage |
| `switchLanguage()` | Toggles `window.currentLang` (en/es), calls `applyLanguage()` |
| `toggleCategory(header)` | Collapses/expands sidebar category groups |
| `exportFindings()` | Exports findings as `.txt`/`.md`/`.html`/PDF (reads `#findings-format`) |
| `clearFindings()` | Clears all findings |
| `generateBountyReport()` | Builds Markdown from form |
| `downloadBountyReport()` | Exports bounty report as MD/HTML/PDF (reads `#bounty-format`) |
| `generateAIWriteup()` | Calls AI API, renders result |
| `downloadAIWriteup()` | Exports AI writeup as MD/HTML/PDF (reads `#ai-format`) |
| `exportScanReport(index, format)` | Exports a single scan report |
| `exportAllReports()` | Exports all scan reports (reads `#reports-format`) |
| `deployScript()` | Writes script to `/tmp/` on Kali via SSH |
| `switchHak5Device(id)` | Switches between Bunny/OMG/M5/Shack payload editor |
| `saveHak5Payload()` | Saves payload to localStorage per device (`mirv_hak5_*`) |
| `clearTerminal()` | Clears terminal output |
| `handleFileUpload(input)` | Reads file and uploads to /tmp/ via SSH (chunked base64) |
| `filterArsenal(query)` | Filters arsenal tools by name/description |
| `opsecModalOpen()` | Opens OPSEC level selector modal |
| `opsecModalClose()` | Closes OPSEC modal |
| `opsecSave()` | Saves OPSEC level to localStorage + updates badge |
| `opsecApply(tool, command, target)` | Applies OPSEC transformations via backend (with local fallback) |
| `saveMission()` | Saves current mission (findings + tools + score) to history |
| `loadMissionHistory()` | Loads and renders mission history cards |
| `viewMissionDetails(id)` | Prints mission details to terminal |

## Findings parsing system

**Tools with parsers:** nmap, gobuster, dirb, ffuf, nikto, whatweb, wpscan, wfuzz, feroxbuster, cewl, dnsrecon, curl.

**Flow:**
1. `launchTool(toolId)` sets `currentToolRunning = tool` and `pendingTool = tool`
2. `appendOutput()` ALWAYS accumulates to `outputBuffer` (regardless of `currentToolRunning`)
3. Prompt detection: regex `with\s+\S+\s+at\s+\d{1,2}:\d{2}:\d{2}` triggers `finishToolOutput()`
4. `_toolParsed` flag prevents duplicate parsing per tool launch
5. Safety timer (30s) as fallback if prompt not detected
6. `parseToolOutput(tool, buf, target)` dispatches to tool-specific parser
7. Findings deduplicated by `key:val` (whatweb) or path (gobuster) etc.

**Parsers:**
- `parseNmapFindings` → ports, services, versions, OS
- `parseGobusterFindings` → directories with HTTP status
- `parseFfufFindings` → directories with status codes
- `parseNiktoFindings` → vulnerabilities
- `parseWhatwebFindings` → technologies (deduped across URLs)
- `parseWpscanFindings` → users, plugins

## Arsenal module system

51+ modules. Tool IDs must match between HTML `onclick="launchTool('my-id')"` and JS `case 'my-id':`.

**Adding a new tool requires changes in 2 files:**
1. `index.html` — add button in the appropriate Arsenal category
2. `main.v2.js` — add `case 'toolId':` in the `launchTool` switch

Tools that need target validation must be listed in the `needsTarget` array.

## REST API (65+ endpoints)

| Category | Endpoints |
|----------|-----------|
| WebSocket | `GET /ws` |
| AI | `POST /api/ai/chat`, `POST /api/suggest` |
| Connections | `GET/POST/DELETE /api/connections` |
| Reports | `GET/POST/DELETE /api/reports`, `POST /api/report/generate`, `POST /api/generate-pdf` |
| Scripts | `GET/POST/DELETE /api/scripts` |
| Findings | `GET/POST/DELETE /api/findings`, `POST /api/findings/bulk`, `GET /api/findings/stats` |
| Payloads | `GET/POST/DELETE /api/payloads` |
| Credentials | `GET/POST/DELETE /api/credentials` |
| CTF | `GET/POST/DELETE /api/ctf/challenges`, `POST /api/ctf/challenges/{id}/solve`, `GET /api/ctf/score` |
| Forensics | `GET /api/forensics/list`, `POST /api/forensics/upload`, `GET/POST /api/forensics/analyze/{id}` |
| Mobile | `GET /api/mobile/apks`, `POST /api/mobile/upload`, `GET /api/mobile/devices`, `POST /api/mobile/frida/run`, `POST /api/mobile/frida/stop`, `POST /api/mobile/frida/clear` |
| KnowledgeBase | `GET /api/knowledgebase/search`, `GET /api/knowledgebase/cve/{id}`, `GET /api/knowledgebase/mitre/{id}` |
| Swarm | `POST /api/swarm/start`, `GET /api/swarm/{id}`, `GET /api/swarm/list`, `POST /api/swarm/{id}/cancel`, `GET /api/swarm/{id}/report` |
| Swarm Sessions | `GET/POST /api/swarm/sessions`, `GET/DELETE /api/swarm/sessions/{id}` |
| Scope | `GET/POST /api/scope`, `POST /api/scope/validate`, `GET /api/scope/history`, `POST /api/scope/history/clear` |
| Scope Events | `GET/POST /api/scope/events`, `DELETE /api/scope/events` |
| OPSEC | `GET /api/opsec/levels`, `POST /api/opsec/apply` |
| Missions | `GET /api/missions`, `POST /api/missions/save`, `GET /api/missions/similar`, `DELETE /api/missions/{id}` |
| Mission Plans | `GET/POST /api/plans`, `DELETE /api/plans/{id}` |
| Secrets | `GET/POST /api/credentials/secrets/{key}`, `DELETE /api/credentials/secrets/{key}` |
| Upload | `POST /api/upload`, `GET /api/files` |
| Settings | `GET/POST /api/settings` |
| n8n | `POST /api/n8n/trigger`, `GET /api/n8n/status` |
| Health | `GET /api/health` |

## Persistent storage

### localStorage keys (frontend)
| Key | Type | Purpose |
|---|---|---|
| `mirv_connections` | JSON array | SSH connection profiles (legacy: `vulnforge_connections`) |
| `mirv_scripts` | JSON array | Saved RCE scripts |
| `mirv_ai_endpoint` | string | AI API URL |
| `mirv_ai_key` | string | AI API key |
| `mirv_ai_model` | string | AI model name |
| `mirv_theme` | "neon" \| "mono" | Color theme |
| `mirv_lang` | "en" \| "es" | Language |
| `mirv_hak5_bunny` | JSON array | Bash Bunny saved payloads |
| `mirv_hak5_omg` | JSON array | OMG Cable saved payloads |
| `mirv_hak5_m5` | JSON array | M5 Stack saved payloads |
| `mirv_hak5_shack` | JSON array | Shack Jack saved payloads |
| `mirv_ps_creds` | JSON object | Payload Studio credentials |
| `mirv_opsec` | "silent" \| "covert" \| "loud" | OPSEC level (default: loud) |

### Supabase (backend persistence)
Tables: `ssh_connections`, `scripts`, `reports`, `findings`, `hak5_payloads`, `app_settings`, `uploaded_files`, `credentials`, `ctf_challenges`, `ctf_solves`, `forensics_evidence`, `mobile_apks`, `mission_history`, `scope_events`, `swarm_sessions`, `mission_plans`, `app_credentials`.
Storage bucket: `vulnforge` for file uploads.
Storage bucket: `vulnforge` for file uploads.

## i18n system

- 150+ translation entries in `main.v2.js` `translations` object.
- Elements with `data-i18n="key"` auto-updated by `applyLanguage()`.
- Placeholders updated directly in `applyLanguage()`.
- Language default: `en`. Toggle in header button.
- State persisted in `localStorage` (`mirv_lang`).

## Report export system (MD / HTML / PDF)

Format selectors: `#findings-format`, `#bounty-format`, `#ai-format`, `#reports-format`.

```
<select id="findings-format">
  <option value="txt">.txt</option>
  <option value="md">.md</option>
  <option value="html">.html</option>
  <option value="pdf">📄 PDF</option>
</select>
```

- **MD** — downloads `.md` file via Blob
- **TXT** — plain text format (findings only)
- **HTML** — self-contained HTML doc with inline dark-theme styles
- **PDF** — HTML → popup → `window.print()` → "Save as PDF"

**Key export functions:** `downloadString()`, `mdToBasicHTML()`, `buildExportHTML()`, `openPDFPreview()`, `exportReport()`.

## Notable constraints

- **Backend assumes Kali Linux** is reachable on LAN.
- **No test files** in the repo.
- **No CI/CD**, no linter, no formatter config.
- `backend/main.py` uses `asyncio.to_thread()` for SSH (non-blocking).
- Script builder deploys to `/tmp/` on SSH target.
- `PRODUCTION_PLAN.md` describes Cloudflare Tunnel setup for remote access.

## Style conventions

- **Python**: Single files, docstrings, `await websocket.send_text()`, type hints where useful.
- **JS**: Functions on `window.*`, `const`/`let`, template literals, `camelCase`.
- **HTML**: Tailwind utility classes, `data-i18n` for translations, `onclick` for events.
- **CSS**: Custom properties for colors, `!important` in monochrome overrides.

## OpenCode agents

| File | Role |
|---|---|
| `agents/architect.md` | 🏗️ Orchestrator principal |
| `agents/backend-dev.md` | ⚙️ Backend Senior (FastAPI + Supabase) |
| `agents/frontend-dev.md` | 🖥️ Frontend Senior (Vanilla JS + Tailwind) |
| `agents/ui-auditor.md` | 🎨 Auditor de UI/contraste Signal Intelligence |
| `agents/cibersecurity_expert.md` | 🔐 Experto en ciberseguridad |
| `agents/security.md` | 🛡️ Seguridad |
| `agents/reviewer.md` | 👀 Revisor de código |
| `agents/traslator.md` | 🌐 Traductor |