# AGENTS.md — VulnForge CTF Dashboard

## Architecture

Two-tier app: **FastAPI backend** serves static frontend + WebSocket SSH proxy.

```
Browser → WS (localhost:8000/ws) → FastAPI → Paramiko → Kali SSH
         ↑
   serves /static/* from frontend/
```

```
C:\Users\34678\Desktop\Proyecto ciber\
├── backend/
│   └── main.py          # FastAPI app (single-file, ~130 lines)
├── frontend/
│   ├── index.html       # SPA (Tailwind CDN, 5 tabs, 31 modules, ~854 lines)
│   ├── js/main.js       # All frontend logic (~1480 lines)
│   └── css/style.css    # Hacker theme + monochrome override (~636 lines)
└── .opencode/
    └── agents/architect.md  # Primary orchestrator agent definition
```

## How to run

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

**Dependencies:** `fastapi`, `uvicorn`, `websockets`, `paramiko`.

## Backend quirks (main.py)

- **First WS message must be JSON auth** or backend falls back to hardcoded defaults:
  ```json
  {"type": "auth", "ip": "192.168.1.x", "user": "kali", "pass": "kali"}
  ```
- If first message is not valid JSON, backend treats it as an SSH command using defaults.
- Static files mount: `app.mount("/static", ...)` serves `frontend/` directory on `/static/` path.
- Only one WebSocket endpoint: `GET /ws`.
- Default credentials (`KALI_IP=192.168.214.142`, `KALI_USER=javi`, `KALI_PASS=javi`) are hardcoded fallbacks.

## Frontend structure

- **Single HTML file** (`index.html`) — no build step, no bundler.
- **Tailwind loaded via CDN** (`https://cdn.tailwindcss.com`). Custom colors (`neon`, `cyber`, `deep`, `void`, `blood`) defined in inline `<script>` in `<head>`.
- **All JS in one file** (`main.js`) — DOMContentLoaded closure, global functions on `window`.
- **No framework** (vanilla JS), no router, no package.json for frontend.

## Key JS globals (window.*)

| Function | Purpose |
|---|---|
| `launchTool(toolId)` | Main dispatcher — validates target, builds command, sends via WS |
| `sendPredefinedCmd(cmd)` | Sends command to WS with `▶` prefix |
| `sendCommand()` | Reads manual input and sends |
| `appendOutput(text)` | Terminal output + scroll-to-bottom |
| `switchTab(name)` | Toggles among 5 panes: terminal/reports/scripts/bounty/aiwriteup |
| `toggleTheme()` | Toggles `body.monochrome` class, persists to localStorage |
| `switchLanguage()` | Toggles `window.currentLang` (en/es), calls `applyLanguage()` |
| `toggleCategory(header)` | Collapses/expands sidebar category groups |
| `generateBountyReport()` | Builds Markdown from form, enables download |
| `downloadBountyReport()` | Exports bounty report as MD/HTML/PDF (reads `#bounty-format`) |
| `generateAIWriteup()` | Calls OpenAI-compatible API, renders result |
| `downloadAIWriteup()` | Exports AI writeup as MD/HTML/PDF (reads `#ai-format`) |
| `exportScanReport(index, format)` | Exports a single scan report (`'md'|'html'|'pdf'`) |
| `exportAllReports()` | Exports all scan reports in selected format (reads `#reports-format`) |
| `deployScript()` | Writes script-editor content to `/tmp/` on Kali via SSH |
| `switchHak5Device(id)` | Switches between Bunny/OMG/M5/Shack payload editor |
| `saveHak5Payload()` | Saves payload to localStorage per device (`vulnforge_hak5_*`) |
| `loadHak5Payload()` | Loads a saved payload by number prompt |
| `listHak5Payloads()` | Lists all saved payloads for active device |
| `clearHak5Editor()` | Clears the payload editor |

## Arsenal module system

31 modules: 24 SSH tools + 7 external resource links.

**Adding a new tool requires changes in 2 files:**
1. `index.html` — add button in the appropriate Arsenal category
2. `main.js` — add `case 'toolId':` in the `launchTool` switch

Tool IDs must match between HTML `onclick="launchTool('my-id')"` and JS `case 'my-id':`.

Tools that need target validation must be listed in the `needsTarget` array (~line 270 in main.js).

## WebSocket protocol

- Backend sends plain text (SSH stdout/stderr).
- JSON protocol messages (`{"type":"connected"|"error", "message":"..."}`) are parsed client-side.
- Tools that produce parseable output (`nmap`, `gobuster`) set `currentToolRunning` to buffer output, parsed when a new prompt pattern is detected.

## Persistent storage (localStorage keys)

| Key | Type | Purpose |
|---|---|---|
| `vulnforge_connections` | JSON array | SSH connection profiles |
| `vulnforge_scripts` | JSON array | Saved RCE scripts |
| `vulnforge_ai_endpoint` | string | AI API URL |
| `vulnforge_ai_key` | string | AI API key |
| `vulnforge_ai_model` | string | AI model name |
| `vulnforge_theme` | "neon" \| "mono" | Color theme |
| `vulnforge_lang` | "en" \| "es" | Language |

## i18n system

- Translations object in `main.js` with ~60 entries.
- Elements marked with `data-i18n="key"` get auto-updated by `applyLanguage()`.
- Placeholders (target IP, command input, connection form) updated directly in `applyLanguage()`.
- Language default: `en`. Toggle in header button.

## Theme system

- **Neon** (default): Dark with green/cyan/red accents, CRT scanlines, matrix BG.
- **Monochrome**: `body.monochrome` class, ~80 CSS overrides in `style.css` that force all colors to grayscale and hide decorative effects.

## Report export system (MD / HTML / PDF)

Three report types → each has a format selector (`#bounty-format`, `#ai-format`, `#reports-format`):

```
<select id="bounty-format">
  <option value="md">.md</option>
  <option value="html">.html</option>
  <option value="pdf">📄 PDF</option>
</select>
```

**How each format works:**
- **MD** — downloads a `.md` file directly via Blob
- **HTML** — generates a self-contained HTML doc with inline dark-theme styles, downloads as `.html`
- **PDF** — generates the same styled HTML, opens it in a new popup window, then triggers `window.print()` → user selects "Save as PDF"

**Key JS functions (not on `window.*`):**
- `mdToBasicHTML(text)` — converts markdown-like syntax (#, **, `, -, ---) to HTML
- `buildExportHTML(content, title, type)` — wraps content in a full HTML5 document with print/display CSS
- `openPDFPreview(htmlContent, title)` — popup + `print()` workflow
- `downloadString(content, filename, mimeType)` — generic Blob download
- `exportReport(content, filename, format, title, type)` — central dispatcher

**Scan reports** get per-export buttons (`.md`, `.html`, `.pdf`) next to each card, plus a bulk "Export all" using the shared format selector.

## Notable constraints

- **Git push fails** (403) — remote `origin` at `https://github.com/SenorJA/dashboard-ctf.git` needs PAT auth.
- **No test files** exist anywhere in the repo.
- **No CI/CD**, no linter, no formatter config.
- **Backend assumes Kali Linux** is reachable on the LAN. Default IP is `192.168.214.142`.
- `backend/main.py` uses `asyncio.to_thread()` for SSH connections (non-blocking).
- Script builder deploys to `/tmp/` on the SSH target.

## Style conventions

- Python: Single file, docstrings, `await websocket.send_text()` for all output.
- JS: All functions on `window.*`, `const`/`let`, template literals, `camelCase`.
- HTML: Tailwind utility classes, `data-i18n` for translations, `onclick` for events.
- CSS: Custom properties for colors, `!important` used in monochrome overrides.
