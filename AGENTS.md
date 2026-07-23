# AGENTS.md — M.I.R.V. (Multi-platform Incident Response & Vulnerabilities)

## Architecture

Two-tier app: **FastAPI backend** serves static frontend + WebSocket SSH proxy + REST API.

```
Browser → WS (localhost:8000/ws) → FastAPI → Paramiko → Kali SSH
         ↑
   serves /static/* from frontend/
   REST API (153+ endpoints) → Supabase (PostgreSQL)
   Plugin system (hot-reload) + Burp Bridge + Structured Audit Log
```

```
C:\Users\34678\Desktop\Proyecto ciber\
├── backend/
│   ├── main.py              # FastAPI app (~3900 lines, 153+ endpoints)
│   ├── database.py           # Supabase CRUD layer (17 tables, 85% coverage)
│   ├── exif_osint.py         # EXIF metadata extraction + GPS + reverse geocoding
│   ├── canary_tokens.py      # Honeytoken generator (8 types) + activation tracking
│   ├── dlp_scanner.py         # Data Loss Prevention (8 PII patterns + Luhn)
│   ├── siem.py                # SIEM engine (events, 4 correlation rules, alerts)
│   ├── plugin_manager.py      # Plugin system (hooks, hot-reload via watchdog)
│   ├── coverage.py            # Coverage tracking matrix (endpoint×param×vuln_class)
│   ├── skill_playbooks.py     # Markdown skill playbooks (SKILL.md frontmatter)
│   ├── redact.py              # Global redaction (20 patterns, shape-preserving)
│   ├── audit_log.py           # Structured JSONL audit log w/ rotation + SIEM forwarding
│   ├── burp_bridge.py         # Burp Suite ingest server (captured requests store)
│   ├── mcp_server.py          # MCP Server for AI agents
│   ├── kali_mcp_client.py     # Client for kali-mcp Docker integration
│   ├── swarm.py               # Multi-operator coordinator
│   ├── mobile_analyzer.py     # APK static + dynamic analysis
│   ├── forensics.py           # Digital forensics analysis
│   ├── knowledgebase.py       # CVE + MITRE ATT&CK DB
│   ├── scope_guard.py         # Scope validation (Warn/Block)
│   ├── adb_controller.py      # ADB device controller
│   ├── opsec.py               # OPSEC levels (30 tools)
│   ├── mission_store.py       # Self-Improvement Loop (auto-redacts on save)
│   ├── plugins/               # Plugin directory (example_plugin/)
│   ├── skills/                # Built-in skill playbooks (recon, webvuln, ssrf, jwt, supabase)
│   ├── burp_plugin/           # Jython Burp Suite plugin (mirv_burp.py)
│   ├── tests/                 # 1504+ tests across 25 test files
│   ├── Dockerfile             # Container image for mirv-backend
│   └── requirements.txt
├── frontend/
│   ├── index.html            # SPA (Tailwind CDN, 21 tabs, ~2300 lines)
│   ├── css/
│   │   └── style.css          # Signal Intelligence + Monochrome theme (~873 lines)
│   ├── img/
│   │   ├── logo.svg            # Full logo (hexagon + radar + typography)
│   │   ├── favicon.svg         # Browser favicon
│   │   └── icon-192.svg        # PWA/desktop app icon
│   └── js/
│       ├── main.v2.js          # All frontend logic (~7800 lines)
│       ├── main.js             # Legacy version
│       ├── dataservice.js      # Supabase REST client
│       ├── mobile.js           # Mobile analysis UI
│       ├── forensics.js        # Forensics UI
│       └── swarm.js            # Swarm UI
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # Tests + coverage + bandit on push/PR
│   │   └── deploy.yml         # Docker build → Docker Hub → SSH deploy to VPS
│   └── SECRETS.md             # Secrets/variables setup guide
├── framework/                  # Architecture plans per module (PLAN.md files)
├── .opencode/
│   └── agents/                 # OpenCode agent definitions
└── docs: README.md, ROADMAP.md, PRODUCTION_PLAN.md, PERSISTENCE_AUDIT.md, MIRV_DESKTOP_PLAN.md, VULNFORGE_VS_T3MP3ST.md, DOCKER_GUIDE.md, TOMORROW.md
```

## How to run

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

**Dependencies:** `fastapi`, `uvicorn`, `gunicorn`, `websockets`, `paramiko`, `Pillow>=10.0.0`, `supabase`, `reportlab`, `python-dotenv`, `python-multipart`, `psycopg2-binary` (optional), `httpx` (optional), `watchdog` (optional, plugin hot-reload).

**Tests:**
```bash
cd backend
python -m pytest tests/ -k "not test_slow_hook" -q  # 1504+ tests, ~72% coverage
```

## Backend modules (main.py + 21 modules)

| File | Lines | Purpose | Tests | Coverage |
|------|-------|---------|-------|----------|
| `main.py` | ~3900 | FastAPI app, WebSocket SSH proxy, 153+ REST endpoints + CSP middleware | ~333 | 53% |
| `database.py` | ~1344 | Supabase CRUD (17 tables) | 196 | 85% |
| `exif_osint.py` | ~812 | EXIF GPS extraction, camera metadata, reverse geocoding, Leaflet map | 21 | 63% |
| `canary_tokens.py` | ~442 | 8 honeytoken types, activation tracking, expiration | 24 | 99% |
| `dlp_scanner.py` | ~453 | 8 PII patterns, Luhn validation, risk scoring | 25 | 67% |
| `siem.py` | ~743 | SIEM engine: events, 4 correlation rules, alerts, thread-safe | 31 | 84% |
| `plugin_manager.py` | ~700 | Plugin discovery, hooks, hot-reload via watchdog | 47+18 | 88% |
| `coverage.py` | ~480 | Coverage matrix (endpoint×param×vuln_class), next_steps estimator | 33 | new |
| `skill_playbooks.py` | ~450 | Markdown skill playbooks, frontmatter parser, hot-reload | 67 | new |
| `redact.py` | ~430 | 20 redaction patterns, shape-preserving, AI/mission integration | 63 | new |
| `audit_log.py` | ~470 | JSONL audit log, 4MB rotation, SIEM forwarding, AuditLogHandler | 45 | new |
| `burp_bridge.py` | ~599 | Burp ingest server, LRU store, finding↔issue conversion | 72 | new |
| `mcp_server.py` | ~620 | MCP Server exposes tools to AI agents | — | — |
| `kali_mcp_client.py` | ~130 | Client for kali-mcp Docker integration | ~20 | 79% |
| `swarm.py` | ~250 | Multi-operator swarm coordinator (Recon, Scanner, Exploiter, Report) | ~30 | 73% |
| `mobile_analyzer.py` | ~707 | APK static analysis (apktool, jadx, mobsf) + dynamic (ADB/Frida) | — | — |
| `forensics.py` | ~253 | Digital forensics (memory, disk, Sleuth Kit) | ~30 | 99% |
| `knowledgebase.py` | ~210 | CVE database + MITRE ATT&CK techniques | 45 | 100% |
| `scope_guard.py` | ~261 | Scope validation (Warn/Block modes) | ~40 | 97% |
| `adb_controller.py` | ~205 | ADB device detection + Frida scripts (run/stop/clear) | ~25 | 98% |
| `opsec.py` | ~400 | OPSEC Levels — 30 tools with Silent/Covert/Loud modifiers | ~25 | 88% |
| `mission_store.py` | ~356 | Self-Improvement Loop — mission history + AI context (auto-redacts) | ~30 | 90% |

## Backend quirks (main.py)

- **First WS message must be JSON auth**: `{"type":"auth","ip":"...","port":22,"user":"...","pass":"..."}`
- SSH uses `invoke_shell()` for interactive PTY session.
- `p10k disable` sent on connect → Powerlevel10k prompt disabled.
- sudo commands intercepted with `sudo -S` + password piped via heredoc.
- Static files served via `/css/`, `/js/`, and `/img/` routes (path traversal protected).
- `/favicon.ico` serves SVG favicon as fallback.
- `asyncio.to_thread()` for non-blocking SSH operations.
- AI chat endpoint: `/api/ai/chat` (OpenAI-compatible, **auto-redacts secrets before LLM call**).
- AI suggestions: `/api/suggest` (receives findings + **coverage context**, returns next-step suggestions).
- **Plugin watcher auto-starts** on FastAPI startup (`auto_load_new=False` by default).
- **Audit log auto-init** on startup + existing `logger` wired with `AuditLogHandler`.
- **Swarm sessions route** registered BEFORE `/api/swarm/{session_id}` to avoid catch-all collision.

## Frontend structure (21 tabs)

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
| Payload Studio | (external link) | Hak5 payload editor (opens new tab) |
| EXIF OSINT | `tab-exif` | EXIF metadata + GPS map (Leaflet) |
| Canary Tokens | `tab-canary` | Honeytoken generator + activation log |
| DLP Scanner | `tab-dlp` | PII/secret detection (text/file/URL) |
| SIEM | `tab-siem` | Event feed + alerts + correlation rules |
| Plugins | `tab-plugins` | Plugin management (load/unload/enable/disable) |
| Coverage | `tab-coverage` | Coverage matrix + next steps + export |

- **Single HTML file** (`index.html`, ~2300 lines) — no build step, no bundler, no framework.
- **Tailwind via CDN** (`https://cdn.tailwindcss.com`). Custom colors: `neon`, `cyber`, `deep`, `void`, `blood`.
- **All JS in one file** (`main.v2.js`, ~7800 lines) — DOMContentLoaded closure, functions on `window.*`.
- **i18n**: 170+ entries (en/es), `data-i18n` attributes, `applyLanguage()`.
- **Vanilla JS**, no router, no package.json for frontend.

## Key JS globals (window.*)

| Function | Purpose |
|---|---|
| `launchTool(toolId)` | Main dispatcher — validates target, builds command, sends via WS |
| `sendPredefinedCmd(cmd)` | Sends command to WS with `▶` prefix |
| `sendCommand()` | Reads manual input and sends |
| `appendOutput(text)` | Terminal output (ANSI strip, \r handling, buffer accumulation, prompt detection) |
| `switchTab(name)` | Toggles among 21 panes (wraps refresh on tab switch) |
| `toggleTheme()` | Toggles `body.monochrome` class |
| `switchLanguage()` | Toggles `window.currentLang` (en/es) |
| `refreshSIEM()` | Fetches stats/events/alerts/rules, renders SIEM dashboard |
| `pluginAction(name, action)` | POST to /api/plugins/{name}/{action} |
| `refreshPlugins()` | Fetches and renders plugin cards |
| `refreshCoverage()` | Fetches coverage stats/entries/next-steps/sessions |
| `markCoverage()` | POST to /api/coverage/mark + refresh |
| `exportCoverageFile(format)` | Export coverage as JSON/CSV/Markdown |
| `refreshExif()` / `refreshCanary()` / `refreshDLP()` | Refresh respective modules |
| `dockerStatus()` / `dockerStart()` / `dockerStop()` / `dockerClean()` / `dockerBuild()` | Docker controls |
| `exportFindings()` / `exportAllReports()` / `generateBountyReport()` / `downloadBountyReport()` | Export functions |
| `saveMission()` / `loadMissionHistory()` / `viewMissionDetails(id)` | Mission history |
| `opsecModalOpen()` / `opsecSave()` / `opsecApply(tool, command, target)` | OPSEC controls |

## Findings parsing system

**Tools with parsers:** nmap, gobuster, dirb, ffuf, nikto, whatweb, wpscan, wfuzz, feroxbuster, cewl, dnsrecon, curl.

**Flow:**
1. `launchTool(toolId)` sets `currentToolRunning = tool` and `pendingTool = tool`
2. `appendOutput()` ALWAYS accumulates to `outputBuffer`
3. Prompt detection: regex triggers `finishToolOutput()`
4. Safety timer (30s) as fallback
5. `parseToolOutput(tool, buf, target)` dispatches to tool-specific parser
6. Findings deduplicated by `key:val` (whatweb) or path (gobuster) etc.

## Arsenal module system

83+ modules. Tool IDs must match between HTML `onclick="launchTool('my-id')"` and JS `case 'my-id':`.

**Adding a new tool:** changes in 2 files (index.html button + main.v2.js case).

## REST API (153+ endpoints)

| Category | Endpoints |
|----------|-----------|
| WebSocket | `GET /ws` |
| AI | `POST /api/ai/chat` (auto-redacts), `POST /api/suggest` (+ coverage context) |
| Connections | `GET/POST/DELETE /api/connections` |
| Reports | `GET/POST/DELETE /api/reports`, `POST /api/report/generate`, `POST /api/generate-pdf` |
| Scripts | `GET/POST/DELETE /api/scripts` |
| Findings | `GET/POST/DELETE /api/findings`, `POST /api/findings/bulk`, `GET /api/findings/stats` |
| Payloads | `GET/POST/DELETE /api/payloads` |
| Credentials | `GET/POST/DELETE /api/credentials` |
| CTF | `GET/POST/DELETE /api/ctf/challenges`, `POST /api/ctf/challenges/{id}/solve`, `GET /api/ctf/score` |
| Forensics | `GET /api/forensics/list`, `POST /api/forensics/upload`, `GET/POST /api/forensics/analyze/{id}` |
| Mobile | `GET /api/mobile/apks`, `POST /api/mobile/upload`, `GET /api/mobile/devices`, `POST /api/mobile/frida/{run,stop,clear}` |
| KnowledgeBase | `GET /api/knowledgebase/search`, `GET /api/knowledgebase/cve/{id}`, `GET /api/knowledgebase/mitre/{id}` |
| Swarm | `POST /api/swarm/start`, `GET /api/swarm/{id}`, `GET /api/swarm/list`, `POST /api/swarm/{id}/cancel`, `GET /api/swarm/{id}/report` |
| Swarm Sessions | `GET/POST /api/swarm/sessions`, `GET/DELETE /api/swarm/sessions/{id}` |
| Scope | `GET/POST /api/scope`, `POST /api/scope/validate`, `GET /api/scope/history`, `POST /api/scope/history/clear` |
| Scope Events | `GET/POST/DELETE /api/scope/events` |
| OPSEC | `GET /api/opsec/levels`, `POST /api/opsec/apply` |
| Missions | `GET /api/missions`, `POST /api/missions/save`, `GET /api/missions/similar`, `DELETE /api/missions/{id}` |
| Mission Plans | `GET/POST /api/plans`, `DELETE /api/plans/{id}` |
| Secrets | `GET/POST/DELETE /api/credentials/secrets/{key}` |
| Upload | `POST /api/upload`, `GET /api/files` |
| Settings | `GET/POST /api/settings` |
| n8n | `POST /api/n8n/trigger`, `GET /api/n8n/status` |
| kali-mcp | `GET /api/kali-mcp/{status,tools}`, `POST /api/kali-mcp/exec` |
| Docker | `GET /api/docker/status`, `POST /api/docker/{start,stop,clean,build}`, `GET /api/docker/task/{id}` |
| Health | `GET /api/health` |
| **EXIF OSINT** | `POST /api/exif/analyze`, `GET /api/exif/analyze?url=` |
| **Canary Tokens** | `POST /api/canary/token`, `GET /api/canary/tokens`, `GET /api/canary/activate/{id}`, `GET /api/canary/events`, `DELETE /api/canary/token/{id}` |
| **DLP Scanner** | `POST /api/dlp/scan`, `POST /api/dlp/scan-file`, `GET /api/dlp/scan-url` |
| **SIEM** | `POST /api/siem/event`, `GET /api/siem/events`, `GET /api/siem/stats`, `POST /api/siem/rules`, `GET /api/siem/rules`, `DELETE /api/siem/rules/{id}`, `GET /api/siem/alerts`, `GET /api/siem/findings` |
| **Plugins** | `GET /api/plugins`, `GET /api/plugins/{name}`, `POST /api/plugins/{name}/{load,unload,reload,enable,disable}`, `POST /api/plugins/hooks/{hook_name}` |
| **Plugin Watcher** | `POST /api/plugins/watcher/{start,stop}`, `GET /api/plugins/watcher/{events,status}` |
| **Coverage** | `POST /api/coverage/mark`, `GET /api/coverage/{list,summary,untested,next,sessions,export,vocab}`, `DELETE /api/coverage` |
| **Skills** | `GET /api/skills`, `GET /api/skills/{name}`, `GET /api/skills/{name}/render`, `POST /api/skills/{name}/{load,unload,enable,disable,reload}`, `POST /api/skills/create` |
| **Redaction** | `POST /api/redact`, `POST /api/redact/dict`, `GET /api/redact/patterns`, `POST /api/redact/check` |
| **Audit Log** | `GET /api/audit/logs`, `GET /api/audit/stats`, `POST /api/audit` |
| **Burp Bridge** | `POST /api/burp/ingest`, `GET /api/burp/{requests,requests/{id},endpoints,tasks,issues}`, `POST /api/burp/{tasks,issues,finding-to-issue,raw,export-findings,snapshot}`, `PATCH /api/burp/tasks/{id}`, `DELETE /api/burp/clear`, `GET /api/burp/status` |

## Plugin system

- **Discovery**: scans `backend/plugins/*/plugin.json` on startup.
- **Hooks**: 5 types — `on_startup`, `on_shutdown`, `on_tool_result`, `on_finding`, `on_event`.
- **Hot-reload**: watchdog (preferred) or mtime polling (fallback), 250ms debounce.
- **Auto-start** on FastAPI boot (`auto_load_new=False` by default for security).
- **Example plugin**: `backend/plugins/example_plugin/` (implements all 5 hooks).

## Skill playbooks system

- **Format**: `SKILL.md` with YAML frontmatter (`name`, `description`, `category`, `allowed_tools`).
- **Discovery** (later wins): `backend/skills/` → `./.mirv/skills/` → `~/.mirv/skills/` → env `MIRV_SKILLS_DIRS`.
- **Built-in skills**: recon, webvuln, ssrf, jwt, supabase.
- **Hot-reload**: live-reload on file change.
- **AI integration**: `GET /api/skills/{name}/render` returns markdown body for prompt injection.

## Redaction system

- **20 patterns**: AWS, GitHub, OpenAI, Google, Slack, Stripe, JWT (2/3-seg), Bearer, URL userinfo, PEM, Luhn cards, long-token fallback.
- **Shape-preserving**: keys intact, only sensitive values masked.
- **Integrations**: `/api/ai/chat` (redacts before LLM), `mission_store.save_mission()` (redacts before persist), `audit_log.py` (redacts every log entry).
- **Opt-in**: importing `redact.py` changes nothing until a caller wraps its data.

## Audit log system

- **Format**: JSON-lines (one JSON object per line).
- **Rotation**: 4MB max, 3 generations (`.log` → `.log.1` → `.log.2` → `.log.3`).
- **Auto-redacts** secrets via `redact.py`.
- **SIEM forwarding**: WARNING+ events auto-ingest into `siem.py`.
- **AuditLogHandler**: converts existing `logger.info()` calls to structured JSONL.
- **Location**: `backend/logs/audit.jsonl`.

## Burp Bridge system

- **Purpose**: bidirectional MIRV ↔ Burp Suite workflow.
- **Ingest**: `POST /api/burp/ingest` receives captured requests (token-guarded).
- **Store**: in-memory, LRU eviction at 5000 entries, endpoint summaries auto-deduped.
- **Conversion**: MIRV findings → Burp issues (with raw HTTP/1.1 request).
- **Plugin**: `backend/burp_plugin/mirv_burp.py` (Jython, right-click → "Send to MIRV").
- **Auth**: optional `X-MIRV-Token` header (env `MIRV_BURP_TOKEN`).

## CI/CD (GitHub Actions)

- **`ci.yml`**: on push/PR to main — pytest + coverage + bandit security scan + safety check.
- **`deploy.yml`**: on push to main — Docker build → push to Docker Hub → SSH deploy to VPS.
- **Graceful skip**: if `DOCKERHUB_USERNAME` / `VPS_HOST` not configured, steps skip silently.
- **Secrets**: documented in `.github/SECRETS.md` (Docker Hub token, VPS SSH key, etc.).

## Persistent storage

### localStorage keys (frontend)
| Key | Type | Purpose |
|---|---|---|
| `mirv_connections` | JSON array | SSH connection profiles |
| `mirv_scripts` | JSON array | Saved RCE scripts |
| `mirv_ai_endpoint` / `mirv_ai_key` / `mirv_ai_model` | string | AI API config |
| `mirv_theme` | "neon" \| "mono" | Color theme |
| `mirv_lang` | "en" \| "es" | Language |
| `mirv_hak5_{bunny,omg,m5,shack}` | JSON array | Hak5 payloads per device |
| `mirv_ps_creds` | JSON object | Payload Studio credentials |
| `mirv_opsec` | "silent" \| "covert" \| "loud" | OPSEC level |

### Supabase (backend persistence)
17 tables: `ssh_connections`, `scripts`, `reports`, `findings`, `hak5_payloads`, `app_settings`, `uploaded_files`, `credentials`, `ctf_challenges`, `ctf_solves`, `forensics_evidence`, `mobile_apks`, `mission_history`, `scope_events`, `swarm_sessions`, `mission_plans`, `app_credentials`.

## Notable constraints

- **Backend assumes Kali Linux** is reachable on LAN (or via Docker `kali-tools` container).
- **Docker-in-Docker**: Docker commands run from inside `mirv-backend` via mounted `/var/run/docker.sock`. All compose commands use `-p proyectociber`.
- **Container-safe operations**: Start/stop/clean only affect `kali-tools` (never self-destruct `mirv-backend`).
- **Plugin auto-load**: `auto_load_new=False` by default — never auto-execute new Python just because a file appeared.
- **GitHub Push Protection**: test files must not contain real-looking secrets (build strings in fragments if needed).

## Style conventions

- **Python**: Single files, docstrings, type hints where useful, `threading.Lock` for thread safety, dataclasses.
- **JS**: Functions on `window.*`, `const`/`let`, template literals, `camelCase`.
- **HTML**: Tailwind utility classes, `data-i18n` for translations, `onclick` for events.
- **CSS**: Custom properties for colors, `!important` in monochrome overrides.
- **Tests**: pytest, `unittest.mock` for external deps, `TestClient(app)` for endpoints, `@patch` for DB.

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

## Test summary

- **25 test files** in `backend/tests/`
- **1504+ tests** passing
- **~72% coverage** across measured backend modules
- **Key test files**: test_database (196), test_api_endpoints (333), test_main_coverage (165), test_burp_bridge (72), test_redact (63), test_skill_playbooks (67), test_audit_log (45), test_plugin_manager (47), test_plugin_watcher (18), test_siem (31), test_coverage (33), test_exif_osint (21), test_canary_tokens (24), test_dlp_scanner (25), test_opsec, test_scope_guard, test_forensics, test_adb_controller, test_kali_mcp_client, test_mission_store, test_knowledgebase, test_swarm, + scanner tools.