# 🗺️ M.I.R.V. — Roadmap de Mejoras

> Última actualización: 8 Ago 2026 — MIRV v5.0 | 30 módulos | 227 endpoints | 3834 tests | 25 tabs | main.py 100%

## ✅ Completado

### Fase 1 — Terminal + Findings Panel
- [x] Conexión SSH interactiva con `invoke_shell()` + PTY
- [x] Reconexión dinámica por WebSocket
- [x] Prompt limpio (Powerlevel10k desactivado)
- [x] Filtro ANSI completo (colores, OSC, DEC privados, Nerd Font/PUA)
- [x] Historial de comandos con flechas ↑/↓ (últimos 100)
- [x] Tab completion con detección de CWD real vía `/proc`
- [x] Subida de archivos chunked base64 (soporta binarios >1MB)
- [x] Responsive layout (mobile sidebar + command bar separada)
- [x] Pestaña **Findings** con tarjetas de severidad
- [x] Parsers: nmap, whatweb, gobuster, dirb, ffuf, nikto, wpscan, wfuzz, feroxbuster, cewl, dnsrecon, curl, masscan, hydra-ssh/ftp, wafw00f, sqlmap, enum4linux, smbclient, smbmap, searchsploit, theharvester (28 total)
- [x] Deduplicación de hallazgos por `key:val`
- [x] Filtros por severidad + export `.txt`/`.md`/`.html`/`PDF`
- [x] Persistencia en Supabase (CRUD via `/api/findings`)

### Fase 2 — AI Assistance
- [x] Endpoint `/api/suggest` + `/api/ai/chat` (auto-redacts secrets)
- [x] Multi-proveedor: OpenAI, Anthropic, Gemini, OpenRouter, DeepSeek, Groq
- [x] AI en 6 pestañas + AI Writeup + Bounty Reports
- [x] Auto-guardado de API keys en localStorage

### Fase 3 — Op Admiral (Planificador de Misión)
- [x] Describe target → AI genera plan paso a paso
- [x] Cada paso → botón "Ejecutar" o "Ejecutar todo"
- [x] Barra de progreso de la misión

### Fase 4 — Multi-operador (Swarm)
- [x] Operadores: Recon, Scanner, Exploiter, Report
- [x] Coordinador con pizarra compartida + cancelación

### Fase 5 — Hallazgos Persistentes + Reportes
- [x] CRUD hallazgos + `/api/report/generate` + `/api/generate-pdf`
- [x] Bounty Reports + AI Writeup

### Fase 6 — Scope Guard + OPSEC
- [x] Scope validation (Warn/Block) — `scope_guard.py` (755L)
- [x] Interactive Permission Prompts — `classify_command()`, 16 danger patterns, session cache, TTL 120s
- [x] OPSEC Levels — 30 tools con modificadores Silent/Covert/Loud
- [x] 7 permission endpoints + 4 scope endpoints

### Fase 7 — Producción + CI/CD
- [x] Docker Stack (mirv-backend + kali-tools)
- [x] GitHub Actions CI/CD (lint + test + deploy)
- [ ] Cloudflare Tunnel (dominio + cloudflared) — **pendiente infraestructura**

### Fase 8 — Docker + Tests + CI/CD
- [x] Dockerfile + docker-compose.yml
- [x] 3834 tests pytest (76 archivos)
- [x] ~95% coverage global — **`main.py` al 100%** (2847/2847 statements)
- [x] CI: lint + test-backend + docker-build + deploy
- [x] Cobertura > 80%

---

## ✅ PentesterFlow-Inspired Features (Jul 2026)

### Coverage Tracking
- [x] `backend/coverage.py` — matriz (endpoint×param×vuln_class), next_steps estimator
- [x] 10 endpoints: mark, list, summary, untested, next, sessions, export, vocab
- [x] Frontend tab #19: Coverage matrix + next steps + export JSON/CSV/Markdown

### Skill Playbooks
- [x] `backend/skill_playbooks.py` — Markdown playbooks with YAML frontmatter
- [x] 10 built-in: recon, webvuln, ssrf, jwt, supabase, graphql, race, takeover, deserialize, ssti
- [x] 9 endpoints: CRUD + load/unload/reload + render (AI prompt injection)
- [x] Frontend tab #22: Skill browser + create + render

### Global Redaction
- [x] `backend/redact.py` — 20 patterns (AWS, GitHub, JWT, PEM, etc.), shape-preserving
- [x] Integrations: `/api/ai/chat`, mission_store, audit_log
- [x] 4 endpoints: redact, dict, patterns, check

### Burp Bridge
- [x] `backend/burp_bridge.py` — Bidirectional MIRV↔Burp workflow
- [x] LRU store (5000 entries), finding↔issue conversion, token guard
- [x] `backend/burp_plugin/mirv_burp.py` — Jython plugin (right-click → "Send to MIRV")
- [x] 15 endpoints: ingest, requests, endpoints, tasks, issues, export

### Structured Audit Log
- [x] `backend/audit_log.py` — JSONL, 4MB rotation (3 gens), SIEM forwarding
- [x] `AuditLogHandler` for existing loggers
- [x] 3 endpoints: logs, stats, create

### Plugin Hot-Reload
- [x] Added to `backend/plugin_manager.py` — watchdog + polling fallback, 250ms debounce
- [x] 4 endpoints: watcher start/stop/events/status
- [x] 18 additional tests

### Session Compaction
- [x] Added to `backend/mission_store.py` — `SessionMemory` dataclass
- [x] auto-redacts on save, similarity search
- [x] 5 endpoints: compact, expand, search-similar, export-context, summary
- [x] 63 total tests for mission_store

---

## ✅ Continuous Intelligence (Jul 2026)

- [x] `backend/intelligence.py` (890L) — 6 watch types: http_headers, certificate, dns, port_scan, tech_stack, page_content
- [x] Snapshot → Diff → Alert pipeline with type-specific differ engines
- [x] Stdlib-only collectors (urllib, ssl, socket), 10s timeout, graceful fallback
- [x] 43 tests covering all collectors, diff engines, and alert generation
- [x] 11 endpoints: CRUD watches + snapshots + diff + alerts
- [x] Frontend tab #23: Intel dashboard with watch list + alerts + manual snapshot

---

## ✅ Finding PoC (Jul 2026)

- [x] `backend/finding_poc.py` (745L) — build_poc, parse_curl_to_poc, replay_poc (subprocess, never shell=True)
- [x] finding_to_markdown_report (self-contained evidence), poc_from_burp_request
- [x] Body-only evidence hash (HTTP headers stripped before replay)
- [x] 61 tests, 6 endpoints: build, parse-curl, finding-to-md, from-burp, validate, replay

---

## ✅ Browser Capture (Jul 2026)

- [x] `backend/browser_capture.py` (1334L) — HAR 1.2 parser + 10 security check categories
- [x] Checks: cookies, CSP, HSTS, XFO, XCTO, mixed content, sensitive URLs, insecure redirects, CORS, info leakage, large responses, WebSocket
- [x] Risk scoring 0–100, MIRV findings export, 9 REST endpoints (`/api/browser-capture/*`)
- [x] 95 tests covering all analysis categories
- [x] Frontend tab #26: HAR upload + session list + analysis dashboard

---

## ✅ Finding Parsers Expanded (Jul 2026)

- [x] 14 new parsers added to `frontend/js/main.v2.js` (+267 lines)
- [x] New tools: wfuzz, feroxbuster, cewl, dnsrecon, curl (security headers), masscan, hydra-ssh/ftp, wafw00f, sqlmap, enum4linux, smbclient, smbmap, searchsploit, theharvester
- [x] Total parsers: 28 (was 14)

---

## ✅ Professional PDF Engine (Aug 2026)

- [x] `backend/pdf_engine.py` (1323L) — PdfEngine + PdfReport/PdfSection/PdfFinding dataclasses
- [x] Cover page with MIRV branding (navy header, gold title, teal accents, watermark)
- [x] Auto table of contents + page numbers + header/footer per page
- [x] Severity color coding (critical/high/medium/low/info) + findings summary table sorted by severity
- [x] Code blocks with gray background, markdown tables, recursive sections, exec summary
- [x] New endpoint: `POST /api/generate-pdf-professional` (structured JSON) + legacy `/api/generate-pdf` routed through engine (backward compat)
- [x] Frontend: `exportProfessionalPdf()` + `generatePdfProfessional()` + "Professional PDF" button in Reports tab (i18n en/es)
- [x] 47 new tests (test_pdf_engine.py + test_pdf_api.py)

---

## ✅ Infraestructura completa

- [x] MCP Server + Kali MCP Client
- [x] Supabase persistence (17 tablas, offline-first)
- [x] i18n EN/ES (170+ traducciones)
- [x] Responsive + mobile sidebar
- [x] PDF generation server-side (ReportLab)
- [x] n8n Automation integration
- [x] Content-Security-Policy (CSP) middleware
- [x] Event delegation: 0 onclick, ACTION_MAP centralizado (~90 entries)

---

## ✅ Arsenal ampliado

- [x] 83+ modules total (19 CLI tools + 9 API-based tools + OSINT + Labs + Bug Bounty)
- [x] 6 OSINT CLI tools (TheHarvester, Mr.Holmes, Infoooze, BBOT, LinkedIn2Username, SpiderFoot)
- [x] 8 OSINT web links (Flare.io, Lenso AI, OSINT Framework, SpiderFoot, Shodan, Censys, VirusTotal, HIBP)
- [x] 10 Pentest Labs (DockerLabs, HTB, THM, VulnHub, Proving Grounds, HackMyVM, PortSwigger, OverTheWire, PicoCTF, RootMe)
- [x] 8 Bug Bounty platforms (HackerOne, Bugcrowd, Intigriti, YesWeHack, Secur0, Open Bug Bounty, Synack, Grey Hack)
- [x] Categorías colapsables + master toggle + Run All + badges + filter

---

## 🚧 Pendientes

### Prioridad ALTA
- [ ] **Configurar secrets GitHub** (manual, 15 min) → `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`
- [x] **Cobertura > 80%** — ~95% global, main.py 100%, database 100%, browser_capture 100%, plugin_manager 100%

### Prioridad MEDIA
- [x] ~~**Browser Capture MCP**~~ — 7 tools MCP envolviendo browser_capture (import/analyze/findings)
- [x] ~~**More finding parsers**~~ — 14 new parsers added (28 total)
- [x] ~~**Export PDF mejorado**~~ — professional PDF engine (cover, TOC, severity colors)

### Prioridad BAJA
- [ ] **Fase 7** — Cloudflare Tunnel (dominio + cloudflared)
- [x] ~~**Swarm** — más operadores (OSINT, Web, Vuln)~~ — 3 operadores nuevos, mode full/core
- [x] ~~**Dark mode toggle**~~ — theme real de 3 estados (neon/light/mono) con WCAG AA

## ✅ Browser Capture MCP + Swarm Ops + Light Theme (Aug 2026)

- [x] `backend/mcp_server.py` — 7 tools `vulnforge_browser_*`: import HAR, list/get sessions, analyze (10-checks), get_analysis, create_findings (→ session findings store), stats
- [x] Flujo encadenable: **import → analyze → findings_list** para agentes AI
- [x] 33 tests nuevos (`test_mcp_browser_tools.py`), 187 passed MCP/browser, `mcp_server.py` 100% coverage
- [x] `backend/operators/{osint,web,vuln}.py` — 3 operadores Swarm nuevos; `swarm.py` `_build_operators(mode)` full/core; frontend selector de modo + grid 3 cols
- [x] 89 tests Swarm, cobertura swarm 100% / osint 85% / web 85% / vuln 89%
- [x] Light theme real: `body.light` (tokens, WCAG AA 15.5:1 texto / 5.36:1 acentos), ciclo neon→light→mono, helpers JS theme-aware
- [x] Commits: `dedfda6` (swarm), `2f5ef00` (light theme), `022f349` (browser MCP)

---

## 📊 Resumen

| Phase | Description | Status |
|------|------------|--------|
| Fase 1 | Terminal + Findings Panel | ✅ |
| Fase 2 | AI Assistance | ✅ |
| Fase 3 | Op Admiral (planificador) | ✅ |
| Fase 4 | Multi-operador (Swarm) | ✅ |
| Fase 5 | Hallazgos persistentes + informes | ✅ |
| Fase 6 | Scope + OPSEC + Permissions | ✅ |
| Fase 7 | Producción (Cloudflare Tunnel) | 🚧 Infra |
| Fase 8 | Docker + Tests + CI/CD | ✅ (3834 tests, main.py 100%) |
| PentesterFlow | Coverage + Skills + Redact + Burp + Audit | ✅ |
| Plugin System | Hot-reload + Watcher + 5 hooks | ✅ |
| Session Compaction | Mission store + auto-redact | ✅ |
| Continuous Intelligence | Watch/snapshot/diff/alert | ✅ |
| Finding PoC | Reproducible PoC + replay + reports | ✅ |
| Permission Prompts | Interactive command gating | ✅ |
| Browser Capture | HAR + 10 security checks + 95 tests | ✅ |
| Finding Parsers | 28 tool parsers (was 14) | ✅ |
| Professional PDF | Cover + TOC + severity colors + 47 tests | ✅ |
| Arsenal OSINT | 83+ modules total | ✅ |
| CI/CD | lint + test + Docker + deploy | ✅ |

---

*Documento generado: 25 Jul 2026*
