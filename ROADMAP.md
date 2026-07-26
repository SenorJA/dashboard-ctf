# 🗺️ M.I.R.V. — Roadmap de Mejoras

> Última actualización: 25 Jul 2026 — MIRV v4.0 | 28 módulos | 208 endpoints | 2647 tests | 25 tabs

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
- [x] Parsers: nmap, whatweb, gobuster, dirb, ffuf, nikto, wpscan
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
- [x] 2647 tests pytest (39 archivos)
- [x] ~72% coverage global
- [x] CI: lint + test-backend + docker-build + deploy
- [ ] Cobertura > 80%

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
- [ ] **Cobertura > 80%** — push más allá de 72% (main.py 53%, módulos specialty)

### Prioridad MEDIA
- [ ] **Browser Capture MCP** — capturar tráfico del navegador (esfuerzo ALTO)
- [ ] **More finding parsers** — curl, dnsrecon, ffuf extendido
- [ ] **Export PDF mejorado** — formato más profesional

### Prioridad BAJA
- [ ] **Fase 7** — Cloudflare Tunnel (dominio + cloudflared)
- [ ] **Swarm** — más operadores (OSINT, Web, Vuln)
- [ ] **Dark mode toggle** — no solo monochrome

---

## 📊 Resumen

| Fase | Descripción | Estado |
|------|------------|--------|
| Fase 1 | Terminal + Findings Panel | ✅ |
| Fase 2 | AI Assistance | ✅ |
| Fase 3 | Op Admiral (planificador) | ✅ |
| Fase 4 | Multi-operador (Swarm) | ✅ |
| Fase 5 | Hallazgos persistentes + informes | ✅ |
| Fase 6 | Scope + OPSEC + Permissions | ✅ |
| Fase 7 | Producción (Cloudflare Tunnel) | 🚧 Infra |
| Fase 8 | Docker + Tests + CI/CD | ✅ (2647 tests) |
| PentesterFlow | Coverage + Skills + Redact + Burp + Audit | ✅ |
| Plugin System | Hot-reload + Watcher + 5 hooks | ✅ |
| Session Compaction | Mission store + auto-redact | ✅ |
| Continuous Intelligence | Watch/snapshot/diff/alert | ✅ |
| Finding PoC | Reproducible PoC + replay + reports | ✅ |
| Permission Prompts | Interactive command gating | ✅ |
| Arsenal OSINT | 83+ modules total | ✅ |
| CI/CD | lint + test + Docker + deploy | ✅ |

---

*Documento generado: 25 Jul 2026*
