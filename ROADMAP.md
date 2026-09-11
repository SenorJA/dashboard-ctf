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

---

## ✅ Host Health & Monitoring (Sep 2026)

### System Monitor
- [x] `backend/system_monitor.py` — CPU/RAM/uptime, per-volume disk usage, cleanup-candidate scan (explicit roots, 1.5s budget/dir, refuses root/system/home paths) + delete
- [x] 4 endpoints: `/api/system/stats`, `/api/system/disk`, `/api/system/cleanup` (GET + POST)
- [x] Frontend tab 🖥️ Sys Monitor (`tab-system`) — gauges, volume table, cleanup candidates con delete, polling 15s
- [x] 29 tests

### PC Analyzer
- [x] `backend/pc_analyzer.py` — deterministic local checks (host/memory/cpu/system disk/other volumes/junk/network/uptime), grade A–F, score 0–100, suggestions list (phase 1, no auto-fix)
- [x] Endpoint `GET /api/pc-analyzer` (reuses sysmon data)
- [x] Frontend tab 🩺 PC Analyzer (`tab-pcanalyzer`) — grade hero, checks grid, suggestions, AI explanation vía `/api/ai/chat`
- [x] 28 tests
- [x] Fase 2: auto-fix con confirmación (`POST /api/pc-analyzer/fix`, `cleanup_junk` gated) + EventLog (`wevtutil`) + actualizaciones pendientes (registry `RebootRequired`/`PendingFileRenameOperations`/WinUpdate `LastSuccessTime` en Windows, `apt list --upgradable` en Linux) + check reboot pendiente — 62 tests, 95% cobertura del módulo
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

## ✅ Ronda API-based #2 — 5 herramientas OSINT (9 Sep 2026)

- [x] Backend: 5 funciones nuevas en `backend/osint_recon.py` (818→1141L, sigue al **100%** cobertura):
  **dns_recon** (DNS-over-HTTPS dns.google, 6 tipos en paralelo), **rdap_whois** (RDAP rdap.org,
  registrar vcard + events + nameservers + abuse), **pwned_passwords** (HIBP range k-anonymity,
  rank critical/high/medium/clean, password nunca echo/log), **urlhaus_lookup** (abuse.ch URLhaus
  POST url/host, blacklists), **page_snapshot** (Jina Reader r.jina.ai, texto cap 60 KB)
- [x] Backend: 5 endpoints `POST /api/osint/{dns,whois,pwned,urlhaus,page}` con `_osint_guard`
  (rate-limit + token `MIRV_OSINT_TOKEN`) en `backend/main.py` (244→**249 endpoints**)
- [x] Frontend: 5 tarjetas nuevas en tab OSINT (before Correlate) + `window.osint{...}` +
  Enter-key bindings + i18n en/es (8 keys nuevas)
- [x] Tests: +41 (test_osint_recon.py → 115), osint_recon 100% cov, suite OSINT 168 passed
- [x] Fuente: cantera `cporter202/agentic-ai-apis` (todo keyless, stdlib-only, timeouts)

---

## ✅ Ronda API-based #3 — 5 herramientas OSINT (10 Sep 2026)

La cantera `cporter202/agentic-ai-apis` cambió de alcance (solo Agents/AI/MCP),
así que estas 5 vienen curadas de la misma canonía keyless y validadas con smoke
real antes de cerrar.

- [x] Backend: 5 funciones nuevas en `backend/osint_recon.py` (1141→1428L, **100%** cobertura):
  **code_search** (Sourcegraph streaming SSE — búsqueda pasiva de leaks en código público;
  grep.app quedó descartado tras 429 persistentes), **cert_transparency** (crt.sh Certificate
  Transparency — subdominios pasivos, dedupe + `*.` wildcards, cap 500), **sigstore_lookup**
  (Rekor `POST /log/entries/retrieve` — identidades de firma por email o sha256; notar que
  emailrep.io ya **exige API key**, por eso no entró), **urlscan_search** (urlscan.io search
  público por dominio: URL/IP/country/server/ASN), **mac_vendor_lookup** (maclookup.app OUI →
  fabricante; acepta 6/8/12 hex en `:`/`-` y normaliza a OUI)
- [x] Backend: 5 endpoints `POST /api/osint/{code,cert,sigstore,urlscan,mac}` con `_osint_guard`;
  límites conservadores en `rate_limiter.py` (urlscan 6/min, cert 6/min, sigstore 10/min) —
  `backend/main.py` (249→**254 endpoints**)
- [x] Frontend: 5 tarjetas nuevas en tab OSINT (before Correlate) + `window.osint{Code,Cert,Sigstore,Urlscan,Mac}` +
  Enter-key bindings + i18n en/es (8 keys nuevas)
- [x] Tests: +25 (test_osint_recon.py 115→140, función-fake para SSE), osint_recon **100%**
  cobertura (620 stmts), suite OSINT **266 passed**
- [x] Fuente: APIs públicas keyless validadas con smoke real (crt.sh es intermitente → error
  "flaky service, retry"; Sourcegraph → stream SSE)

---

## ✅ Pack de 5 mejoras de uso (11 Sep 2026)

Mejoras orientadas a flujo de trabajo real en la app (todos: sin dependencias externas).

- [x] **Terminal workflow**:
  - Historial de comandos **persistente** (`localStorage mirv_cmd_history`, flechas ↑/↓,
    `window.clearCmdHistory` + botón 🗑 History)
  - **Export de sesión** (`window.exportSession` → `.log`/`.md` descargable, botón ⬇ Export)
  - **Resumen IA de la sesión** (`window.aiSessionSummary` → `/api/ai/chat`, botón 🤖 Summary)
  - **Sugerencias next-step deterministas** (`computeNextSteps` + `renderNextStepSuggestions`,
    cero IA): tras cada tool, 1–4 comandos de continuación (nmap→whatweb/gobuster/hydra según
    puertos abiertos, gobuster/ffuf→nikto+wpscan si WP, whatweb→wpscan si wordpress, sqlmap→--dbs,
    dnsrecon AXFR→dig, enum4linux→smbmap, cewl→hydra, …) renderizados clickeables en el panel
    Findings→Suggestions + aviso en terminal
- [x] **Charts Overview en Findings**: 3 mini-gráficas canvas puro (sin librerías) por severidad
  (critical/high/medium/low/info con colores), top-8 tools y top-8 targets (`renderFindingsCharts`
  + `_drawBars`); panel `details` colapsable con estado persistido
- [x] **Cheatsheet integrada**: modal 📖 Cheat en terminal con ~50 comandos curados por categoría
  (scan/web/sql/auth/smb/telnet/dns/osint/pivot/jwt/files/servicios/info), buscador en vivo,
  clic precarga el comando en el input reemplazando `TARGET` por el target activo
- [x] **Assessments workspace**: módulo `backend/assessments.py` + 8 endpoints
  (`GET/POST /api/assessments`, `GET/PUT/DELETE /api/assessments/{id}`, targets add/remove,
  `by-target/{target}`) + tab 🗂️ Assessments. Status planning/in-scope/in-progress/done/archived,
  targets dedup, tags, notas, límites 200/100. Frontend: form inline + cards (chips de targets
  con ✕, add con Enter, status selector, ⚡ Scan first → lanza nmap, 🗑 Delete)
- [x] **Scheduler (escaneos programados)**: módulo `backend/scheduler.py` + 7 endpoints
  (`/api/scheduler/jobs` CRUD, `/api/scheduler/due`, `/api/scheduler/jobs/{id}/run`) + tab ⏰
  Scheduler. `due_jobs()` auto-avanza (single-trigger por ciclo), intervalos 10s–7d validados,
  `advance_to_now` para "run now". Frontend: countdown, ⏸/▶, ⚡ Run now, y **polling global cada
  10 s** que lanza `launchTool(tool_id)` en el terminal (target del job o el activo)
- Tests añadidos: 30 `test_assessments.py` + 37 `test_scheduler.py`. Suite completa (cmd CI):
  **4641 passed** ✅. Tabs 28→**31**, rutas registradas 254→**269** (+8 assessments, +7 scheduler).
- ⬜ Pre-existente no relacionado: `test_orchestrator.py::TestCallLlm::test_openai_provider_default_model_when_empty`
  (ambiental, falla igual en `ff057a8`)

## ✅ Improvements pack — 5 features (10 Sep 2026)

Las 6 ideas de mejora solicitadas: 5 implementadas en esta tanda (+ los 2 dispositivos Hak5
ya cerrados antes).

- [x] **Hak5 tools** (editor de payloads): plantillas por dispositivo (`window.insertHak5Template`,
  ídem 7 templates para Bunny/OMG/M5/Shark Jack/Squirrel/Shark Display), validador por lenguaje
  (`window.validateHak5Payload` — DuckyScript/bash/JS/MicroPython, warning no-bloqueante),
  descarga (`window.downloadHak5Payload`, blob con `.ext` del device). Botones `data-action`
  `tpl-hak5`/`val-hak5`/`dl-hak5` + `ACTION_MAP`; `populateHak5Templates()` en `switchHak5Device`
  e `initHak5`
- [x] **Dashboard Home** 🏠: tab `tab-home` (28→29 tabs). `refreshDashboard()` con 8 fetches
  paralelos (health, findings/stats, findings, coverage/summary, siem/stats, system/stats,
  system/disk, intel alerts) + wrapper `switchTab('home')`. KPIs: backend health+uptime,
  findings total+high+crit+targets+tools, coverage pass-ratio, SIEM events+alerts, intel alerts,
  CPU/RAM/disco; quick actions (data-action="tab") + toolkit strip
- [x] **Findings export estructurado**: `GET /api/findings/export?format=csv|sarif|html` —
  SARIF **2.1.0** (driver MIRV, severity→level error/warning/note), CSV plano, HTML
  self-contained (badges de severidad + summary chips). Botones ⬇ CSV/SARIF/HTML en tab
  Findings + `downloadFindingsExport(format)` (blob download, Content-Disposition). 400 para
  format inválido
- [x] **SIEM webhook externo**: `set_webhook_url`/`get_webhook_url` en `siem.py` (solo
  http/https, string vacío = clear, lock thread-safe) + `_notify_webhook` fire-and-forget
  disparada desde `_create_alert` (urllib daemon thread, 5 s timeout, payload JSON `siem-alert`
  con id/rule_id/rule_name/severity/title/detail/timestamp/event_ids). Endpoints
  `GET/POST/DELETE /api/siem/webhook` (400 URL inválida). Card UI en tab SIEM con input +
  save/clear + badge de estado, refresco dentro de `refreshSIEM`
- [x] **MCP OSINT #3**: `mcp_server.py` expone las 5 tools de la Ronda #3
  (`vulnforge_osint_code_search`, `vulnforge_osint_cert_transparency`, `vulnforge_osint_sigstore`,
  `vulnforge_osint_urlscan`, `vulnforge_osint_mac_lookup`) — definiciones TOOLS + handlers
  `_tool_osint_*` que delegan en `osint_recon`
- [x] Tests: **13 SIEM webhook** (validación, send JSON con mock síncrono de thread, disparo
  desde correlación) + **12 export endpoints** (3 formatos, con datos, 400) + **13 MCP OSINT**
  (routing + tools/list). Suites afectadas: **484 passed**. Falls pre-existente ambiental en
  `test_main_gaps.py::TestMobileApi::test_delete_not_found` (usa `db.delete_mobile_apk` real,
  sin relación con estas features)
- [x] UI checked: `node --check main.v2.js` ✅; timings: DOMContentLoaded

---

## 🚧 Pendientes

### Prioridad ALTA
- [ ] **Configurar secrets GitHub** (manual, 15 min) → `DOCKERHUB_USERNAME` ✅, `DOCKERHUB_TOKEN` ✅ (9 Ago 2026); `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` ⬜ — clave `~/.ssh/mirv_deploy` generada + docs en `.github/SECRETS.md` (14 Ago 2026); falta crear VPS + setear secrets
- [x] **Cobertura > 80%** — ~95% global, main.py 100%, database 100%, browser_capture 100%, plugin_manager 100%

### Prioridad MEDIA
- [x] ~~**Browser Capture MCP**~~ — 7 tools MCP envolviendo browser_capture (import/analyze/findings)
- [x] ~~**More finding parsers**~~ — 14 new parsers added (28 total)
- [x] ~~**Export PDF mejorado**~~ — professional PDF engine (cover, TOC, severity colors) + **14 Ago 2026**: detalle por finding + resumen ejecutivo automático + endpoint `POST /api/report/export-pdf` + frontend conectado (`92f4fa3`)

### Prioridad BAJA
- [ ] **Fase 7** — Cloudflare Tunnel (dominio + cloudflared) — plan en `PRODUCTION_PLAN.md`
- [x] ~~**Swarm** — más operadores (OSINT, Web, Vuln)~~ — 3 operadores nuevos, mode full/core
- [x] ~~**Dark mode toggle**~~ — theme real de 3 estados (neon/light/mono) con WCAG AA

## ✅ PDF profesional + secrets VPS (Aug 2026)

- [x] `backend/pdf_engine.py` — limpieza deuda (inner_table muerto, imports, utcnow, logger) + `PdfFinding` con `status/cve/cvss/evidence` + detalle por finding (KeepTogether + fallback plain) + resumen ejecutivo automático (severidad/herramienta/target) — cobertura 99%
- [x] `POST /api/report/export-pdf` — body tipado, fallback DB, 400/422/500, `mirv-report-YYYYMMDD-HHMMSS.pdf`; endpoints legacy intactos
- [x] Frontend: tab Findings PDF real + botón "Professional PDF" con findings vivos (fallback print)
- [x] Clave SSH deploy `~/.ssh/mirv_deploy` + `.github/SECRETS.md` actualizado (VPS pendiente usuario)
- [x] 21 tests nuevos; suite CI-emulada **3892 passed, 52 deselected**; commit `92f4fa3` — CI ✅ Deploy ✅

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
| Professional PDF v2 | Detalle por finding + auto exec summary + `export-pdf` (82 tests, 99%) | ✅ |
| Arsenal OSINT | 83+ modules total | ✅ |
| CI/CD | lint + test + Docker + deploy | ✅ |

---

*Documento generado: 25 Jul 2026*
