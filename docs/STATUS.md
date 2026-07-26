# M.I.R.V. — Estado Completo del Proyecto

> Última actualización: 26 Jul 2026 — MIRV v5.0 | 29 módulos | 226 endpoints | 2837 tests | 27 tabs

## Resumen General

| Área | Estado | Notas |
|------|--------|-------|
| Backend (main.py + 27 módulos) | ✅ 19,000+ líneas, 208 endpoints REST | FastAPI + Supabase |
| Frontend (SPA) | ✅ ~12,300 líneas (8729 JS + 2694 HTML) | Vanilla JS + Tailwind CDN |
| SSH Proxy WebSocket | ✅ | `invoke_shell()` async + PTY + sudo automático |
| Supabase Persistencia | ✅ | 17 tablas, offline-first con localStorage fallback |
| i18n EN/ES | ✅ | 170+ traducciones |
| Docker Stack | ✅ | mirv-backend + kali-tools (SSH) |
| MCP Server | ✅ | Tools para Claude Code, Cursor |
| Conexión Kali | ✅ | SSH vía LAN o Docker-in-Docker |
| CI/CD | ✅ | GitHub Actions (lint + test + deploy) |
| Plugin System | ✅ | Hot-reload + 5 hooks + watchdog |
| Skill Playbooks | ✅ | 10 built-in playbooks + custom |
| Continuous Intelligence | ✅ | Watch/snapshot/diff/alert system |
| Permission Prompts | ✅ | Interactive command gating |
| Finding PoC | ✅ | Reproducible proof-of-concept |

---

## Módulos Backend (28 módulos)

### Core de seguridad

| Archivo | Líneas | Tests | Propósito |
|---------|--------|-------|-----------|
| `scope_guard.py` | 755 | 56 | Scope validation + Interactive Permission Prompts (Warn/Block, 16 danger patterns, session cache, TTL) |
| `opsec.py` | ~400 | 25 | OPSEC Levels — 30 tools con modificadores Silent/Covert/Loud |
| `redact.py` | ~430 | 63 | 20 patrones de redacción (AWS, GitHub, JWT, PEM, etc.), shape-preserving |
| `audit_log.py` | ~470 | 45 | JSONL structure + 4MB rotation + SIEM forwarding |

### Inteligencia y monitoreo

| Archivo | Líneas | Tests | Propósito |
|---------|--------|-------|-----------|
| `siem.py` | ~743 | 31 | Eventos, 4 reglas de correlación, alerts, thread-safe |
| `intelligence.py` | 890 | 43 | Watch/snapshot/diff/alert — 6 tipos de monitor (headers, cert, DNS, ports, tech, content) |
| `exif_osint.py` | ~812 | 21 | GPS extraction, camera metadata, reverse geocoding, Leaflet map |
| `canary_tokens.py` | ~442 | 24 | 8 tipos de honeytokens + activation tracking |

### Herramientas de testing

| Archivo | Líneas | Tests | Propósito |
|---------|--------|-------|-----------|
| `dlp_scanner.py` | ~453 | 25 | 8 patrones PII + validación Luhn + risk scoring |
| `burp_bridge.py` | ~599 | 72 | Ingest server + LRU store + finding↔issue + Jython plugin |
| `finding_poc.py` | 745 | 61 | PoC builder, curl parser, replay (subprocess), markdown reports, evidence hash |
| `coverage.py` | ~480 | 33 | Matriz (endpoint×param×vuln_class) + next_steps estimator |

### Plugins y automatización

| Archivo | Líneas | Tests | Propósito |
|---------|--------|-------|-----------|
| `plugin_manager.py` | ~700 | 65 | Discovery + 5 hooks + hot-reload (watchdog + polling fallback) |
| `skill_playbooks.py` | ~450 | 67 | 10 playbooks MD (recon, webvuln, ssrf, jwt, supabase, graphql, race, takeover, deserialize, ssti) |

### Infraestructura

| Archivo | Líneas | Tests | Propósito |
|---------|--------|-------|-----------|
| `main.py` | 5235 | 333 | FastAPI app central, WebSocket SSH proxy, 208+ endpoints, CSP middleware |
| `database.py` | ~1344 | 196 | Supabase CRUD, 17 tablas, 85% coverage |
| `mission_store.py` | ~356 | 63 | Self-improvement loop, session compaction (SessionMemory dataclass) |
| `mcp_server.py` | ~620 | — | MCP Server para agentes IA |
| `kali_mcp_client.py` | ~130 | 20 | Cliente kali-mcp Docker |
| `swarm.py` | ~250 | 30 | Multi-operator coordinator |
| `mobile_analyzer.py` | ~707 | — | APK static + dynamic (ADB/Frida) |
| `forensics.py` | ~253 | 30 | Digital forensics (memory, disk, Sleuth Kit) |
| `knowledgebase.py` | ~210 | 45 | CVE + MITRE ATT&CK DB |
| `adb_controller.py` | ~205 | 25 | Device detection + Frida scripts |

### API-based tools (sin SSH)

| Archivo | Tests | Propósito |
|---------|-------|-----------|
| `headers_scanner.py` | 32 | HTTP Headers grade A–F, 7 security headers |
| `secrets_scanner.py` | 33 | 25 regex patterns |
| `port_scanner.py` | 18 | ~1600 puertos async |
| `subdomain_scanner.py` | 11 | ~700 prefijos DNS |
| `dns_lookup.py` | 9 | DoH, 7 record types, reverse DNS |
| `hash_cracker.py` | 58 | 20 hash types + rainbow table |
| `stego_tool.py` | 28 | PNG/BMP LSB + trailing data |
| `news_scraper.py` | 8 | 9 RSS feeds |
| `api_scanner.py` | 31 | 65+ paths, CORS, headers |

---

## Frontend (1 HTML + 3 JS + 1 CSS)

| Archivo | Líneas | Propósito |
|---------|--------|-----------|
| `index.html` | 2694 | SPA principal (25 tabs, Arsenal colapsable, Tailwind CDN) |
| `main.v2.js` | 8729 | Toda la lógica frontend (tools, findings, UI, i18n, eventos) |
| `dataservice.js` | ~228 | Supabase REST client |
| `style.css` | ~873 | Signal Intelligence + Monochrome theme |

### 25 Pestañas

| # | Tab | ID | Módulo backend |
|---|-----|----|----------------|
| 0 | Terminal | `tab-terminal` | main.py |
| 1 | Reports | `tab-reports` | main.py |
| 2 | Scripts | `tab-scripts` | main.py |
| 3 | Bounty | `tab-bounty` | main.py |
| 4 | AI Writeup | `tab-aiwriteup` | main.py |
| 5 | Findings | `tab-findings` | main.py |
| 6 | Op Admiral | `tab-opadmiral` | main.py |
| 7 | Automation | `tab-automation` | main.py |
| 8 | Swarm | `tab-swarm` | swarm.py |
| 9 | Credentials | `tab-credentials` | database.py |
| 10 | KnowledgeBase | `tab-knowledgebase` | knowledgebase.py |
| 11 | CTF | `tab-ctf` | main.py |
| 12 | Mobile | `tab-mobile` | mobile_analyzer.py |
| 13 | Forensics | `tab-forensics` | forensics.py |
| 14 | EXIF OSINT | `tab-exif` | exif_osint.py |
| 15 | Canary Tokens | `tab-canary` | canary_tokens.py |
| 16 | DLP Scanner | `tab-dlp` | dlp_scanner.py |
| 17 | SIEM | `tab-siem` | siem.py |
| 18 | Plugins | `tab-plugins` | plugin_manager.py |
| 19 | Coverage | `tab-coverage` | coverage.py |
| 20 | Burp Bridge | `tab-burp` | burp_bridge.py |
| 21 | Audit Log | `tab-audit` | audit_log.py |
| 22 | Skills | `tab-skills` | skill_playbooks.py |
| 23 | Intelligence | `tab-intelligence` | intelligence.py |
| 24 | Docker | — | main.py |

---

## Tests (pytest) — Julio 2026

| Categoría | Archivos | Tests | Cobertura |
|-----------|----------|-------|-----------|
| Core security (scope, opsec, redact, audit) | 4 | 188 | ~88% |
| Intelligence + SIEM + EXIF + Canary | 4 | 119 | ~80% |
| Burp + POC + Coverage + Skills | 4 | 233 | ~78% |
| Database | 1 | 196 | 85% |
| API endpoints | 1 | 333+ | 53% |
| Plugin system (manager + watcher) | 2 | 65 | 88% |
| Mission store (session compaction) | 1 | 63 | 90% |
| Scanner tools (9 modules) | 9 | 228 | — |
| Other modules (forensics, swarm, KB, ADB, etc.) | 7 | ~200 | — |
| **Total** | **40** | **2742** | **~72%** |

### Gestor de paquetes: pnpm

- Gestor obligatorio: `pnpm` v11.11.0
- `.npmrc` bloquea npm/npx por error
- `corepack enable` para activar

---

## CI/CD — GitHub Actions

| Job | Descripción |
|-----|-------------|
| **lint** | Ruff (check + format) sobre `backend/` |
| **test-backend** | pytest con 2837 tests en Python 3.11 |
| **test-frontend** | Playwright + tests con Chromium (pnpm) |
| **docker-build** | Buildx + push a Docker Hub (solo `main`) |
| **deploy** | SSH deploy a VPS (solo `main`) |

Secrets requeridos: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`

---

## Últimos Commits

```
fdd25fd feat: rebuild Docker from scratch (clean images + containers)
4412892 docs: AGENTS.md — 28 modules, 170+ endpoints, 25 tabs, 1660+ tests
7cb960a feat: Intelligence — 6 watch types, diff engine, alerts, 43 tests, 11 endpoints, frontend tab
c7f7917 fix: Finding PoC — body-only evidence hash (strip HTTP headers before replay)
b7cb262 feat: Permission Prompts — interactive command gating, classify + request + decide, 56 tests, 7 endpoints
d07ce37 feat: Finding PoC — build/poc/replay/markdown/curl parser, 61 tests, 6 endpoints
071ec39 fix: docker cp intelligence tab to running container
...
396f025 feat: Coverage Tracking + Skill Playbooks + Redaction + Burp Bridge + Audit Log + Plugin Watcher + Session Compaction (PentesterFlow-inspired)
```

---

*Documento generado: 25 Jul 2026*
