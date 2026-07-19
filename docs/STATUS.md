# M.I.R.V. — Estado Completo del Proyecto

## Resumen General

| Área | Estado | Notas |
|------|--------|-------|
| Backend (main.py + 13 módulos) | ✅ ~2500+ líneas, 88+ endpoints REST | FastAPI + Supabase |
| Frontend (SPA) | ✅ ~6500 líneas JS, 1 HTML, 900 líneas CSS | Vanilla JS + Tailwind CDN |
| SSH Proxy WebSocket | ✅ | `invoke_shell()` async + PTY + sudo automático |
| Supabase Persistencia | ✅ | 17 tablas, offline-first con localStorage fallback |
| i18n EN/ES | ✅ | 150+ traducciones |
| Docker Stack | ✅ | mirv-backend + kali-tools (SSH) |
| MCP Server | ✅ | Tools para Claude Code, Cursor |
| Conexión Kali | ✅ | SSH vía LAN o Docker-in-Docker |

---

## Módulos Backend (13 módulos + main.py)

| # | Archivo | Líneas | Propósito |
|---|---------|--------|-----------|
| — | `main.py` | ~2332 | FastAPI app, WebSocket SSH proxy, 88+ endpoints, CSP middleware |
| — | `database.py` | ~1344 | Supabase CRUD (17 tablas) |
| — | `mcp_server.py` | ~620 | MCP Server para agentes IA |
| — | `kali_mcp_client.py` | ~130 | Cliente kali-mcp Docker |
| — | `swarm.py` | ~250 | Multi-operator swarm coordinator |
| — | `mobile_analyzer.py` | ~707 | APK static + dynamic analysis |
| — | `forensics.py` | ~253 | Digital forensics |
| — | `knowledgebase.py` | ~210 | CVE + MITRE ATT&CK |
| — | `scope_guard.py` | ~261 | Scope validation (Warn/Block) |
| — | `adb_controller.py` | ~205 | ADB device + Frida scripts |
| — | `opsec.py` | ~400 | OPSEC Levels — 30 tools |
| — | `mission_store.py` | ~356 | Self-Improvement Loop |
| — | `headers_scanner.py` | nuevo | #1 HTTP Headers Scanner (grade A–F) |
| — | `secrets_scanner.py` | nuevo | #2 Secrets Scanner (25 regex) |
| — | `port_scanner.py` | nuevo | #3 Port Scanner (~1600 puertos async) |
| — | `subdomain_scanner.py` | nuevo | #4 Subdomain Scanner (~700 prefijos DNS) |
| — | `dns_lookup.py` | nuevo | #5 DNS Lookup (DoH, 7 tipos, reverse) |
| — | `hash_cracker.py` | nuevo | #6 Hash Cracker (20 tipos, rainbow table) |
| — | `stego_tool.py` | nuevo | #7 Steganography Tool (PNG/BMP LSB) |
| — | `news_scraper.py` | nuevo | #8 Security News Scraper (9 RSS feeds) |
| — | `api_scanner.py` | nuevo | #9 API Security Scanner (65+ paths) |

---

## Frontend (4 archivos JS + 1 HTML + 1 CSS)

| Archivo | Líneas | Propósito |
|---------|--------|-----------|
| `index.html` | ~1764 | SPA principal (15 tabs, Arsenal colapsable, Tailwind CDN) |
| `main.v2.js` | ~6530 | Toda la lógica frontend (tools, findings, UI, i18n, eventos) |
| `mobile.js` | ~395 | APK analysis + Frida console |
| `forensics.js` | ~306 | Forensics UI |
| `swarm.js` | ~283 | Swarm pipeline UI |
| `dataservice.js` | ~228 | Supabase REST client |
| `style.css` | ~873 | Signal Intelligence + Monochrome theme |

---

## Estado del Arsenal (septiembre 2026)

| Categoría | Tipo | Items | Badge |
|-----------|------|-------|-------|
| Web Recon | Tools API | 9 (#1–#9) | 9 |
| Web Recon | Tools CLI | 10 (nmap, gobuster, dirb, ffuf, nikto, etc.) | 10 |
| *Total Web Recon* | | *19* | *19* |
| Network | Tools CLI | 8 | 8 |
| SMB/Windows | Tools CLI | 7 | 7 |
| Pivoting | Tools CLI | 4 | 4 |
| Crypto/Decode | Tools CLI | 5 | 5 |
| Exploitation | Tools CLI | 9 | 9 |
| OSINT | Tools CLI | 6 | 6 |
| OSINT | Web Links | 8 | — |
| Extract/Compress | Tools CLI | 7 | 7 |
| Resources | Links | 8 | — |
| Utilities | Links | 1 (CyberChef) | — |
| Pentest Labs | Sites (badge) | 10 | — |
| Bug Bounty | Sites (badge) | 8 | — |
| Hardware Stores | Sites (badge) | 10 | — |
| **Total** | | **~112** | |

---

## Sistema de Eventos (onclick → addEventListener)

Estado: **✅ COMPLETADO — 0 onclick en toda la app**

- **126** onclick en `index.html` → reemplazados con `data-*` attributes
- **7** onclick + **1** onchange en cadenas JS en `main.v2.js` → reemplazados
- **0** onclick restantes en `index.html`
- **0** onclick restantes en `main.v2.js`

### Mecanismo

```javascript
// ACCION_MAP centralizado (90+ entries): data-action → handler function
app.addEventListener('click', (e) => {
  // Captura [data-action], [data-tool], [data-tab], [data-script], [data-device]
});
app.addEventListener('change', (e) => {
  // Captura select[data-action="report-export"]
});
```

---

## Features Recientes

### Arsenal UI (Julio 2026)
- Categorías colapsables (comienzan cerradas)
- Master toggle: Expand All / Collapse All
- Botón Run All por categoría
- Badges numéricos en categorías
- Filtro en tiempo real (filterArsenal) con auto-expand/collapse
- Fix: unificación cat-body duplicado en OSINT

### 9 Módulos desde Cybersecurity-Projects
- **#1** HTTP Headers Scanner — grade A–F + recomendaciones
- **#2** Secrets Scanner — 25 regex (tokens, keys, credenciales)
- **#3** Port Scanner — ~1600 puertos, banner grab, custom ports
- **#4** Subdomain Scanner — ~700 prefijos DNS
- **#5** DNS Lookup — DoH Cloudflare, 7 record types, reverse DNS
- **#6** Hash Cracker — 20 hash types ID + rainbow table
- **#7** Steganography Tool — pure-Python PNG/BMP LSB + trailing data
- **#8** Security News Scraper — 9 feeds RSS/Atom (35+ artículos)
- **#9** API Security Scanner — 65+ paths, headers, CORS, INFO disclosure

### Event Delegation (Julio 2026)
- Migración completa de `onclick` → `addEventListener`
- Sistema centralizado `ACTION_MAP` con ~90 entradas
- Event delegation en `document.body` para elementos estáticos y dinámicos
- `window.*` se conserva para compatibilidad (consola, IA, llamadas externas)
- **Bugfix**: Iba dirigido a `#app` (no existía) → cambiado a `document.body`

---

## Tests (pytest) — Julio 2026

| Archivo | Tests | Cobertura |
|---------|:-----:|-----------|
| `test_headers_scanner.py` | 32 | Grade A–F, score boundaries, live scan, MIRV findings format |
| `test_secrets_scanner.py` | 33 | 25 regex patterns, valid/invalid input, URL fetch |
| `test_port_scanner.py` | 18 | scanme.nmap.org, invalid targets, default ports, edge cases |
| `test_subdomain_scanner.py` | 11 | DNS enum, custom lists, result shape, MIRV findings |
| `test_dns_lookup.py` | 9 | A/MX/NS records, reverse DNS, NXDOMAIN, multiple record types |
| `test_hash_cracker.py` | 58 | 20 hash types identification, rainbow crack, MIRV format |
| `test_stego_tool.py` | 28 | PNG/BMP LSB, trailing data, invalid input, capacity estimation |
| `test_news_scraper.py` | 8 | 9 RSS feeds, article format, sorting, source consistency |
| `test_api_scanner.py` | 31 | httpbin/example.com scans, 65+ paths, CORS, headers |
| `test_api_endpoints.py` | 160 | 88+ endpoints REST (health, scope, settings, swarm, etc.) |
| **Total Tests Backend** | **388** | **0 fallos — 39% cobertura global (+8%)** |

## Tests Frontend — Playwright (Julio 2026)

| Archivo | Tests | Descripción |
|---------|:-----:|-------------|
| `smoke.spec.js` | 24 | Page load, 13 tabs, arsenal sidebar + filter, theme toggle, connection modal, i18n toggle, responsive 1024px + 375px |
| **Total Tests Frontend** | **24** | **0 fallos — Chromium** |

**Gran total: 412 tests, 0 fallos.**

## CI/CD — GitHub Actions

| Job | Descripción |
|-----|-------------|
| **lint** | Ruff (check + format) sobre `backend/` |
| **test-backend** | pytest con 388 tests en Python 3.11 |
| **test-frontend** | Playwright + 24 tests con Chromium (backend server inline) |
| **docker-build** | Buildx + push a Docker Hub (solo `main`) |
| **deploy** | SSH deploy a VPS (solo `main`) |

Secrets requeridos: `DOCKER_USERNAME`, `DOCKER_TOKEN`, `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`

## Pendientes

### Prioridad Media
- [ ] Cobertura de tests > 70% (requiere ~2500 líneas más cubiertas en main.py, database.py y módulos specialty)
- [ ] Configurar secrets de Docker Hub + VPS en GitHub repo

### Prioridad Baja (Infraestructura)
- [ ] Fase 7 — Cloudflare Tunnel (dominio, cloudflared, DNS)

### Ideas/Deseables
- [ ] Dark mode toggle mejorado (no solo monochrome)
- [ ] Más parsers de findings (curl, dnsrecon, ffuf extendido)
- [ ] Export findings a PDF con mejor formato
- [ ] Swarm: más operadores (OSINT, Web, Vuln)
- [ ] Plugin system para herramientas externas

---

## Últimos Commits

```
43b2e1d playwright+ci: frontend tests (24 Playwright) + CI/CD deploy + #app bugfix
9f03c1b tests+ci: pytest suite (228 tests) + GitHub Actions workflow
95a21dc event-delegation: onclick→addEventListener completo + docs STATUS.md/EVENTOS.md
f3fc7ef Fix OSINT section toggle + restructure cat-body
fabb8dd Add master toggle + collapsible categories + Run All buttons
8fdec75 Add API Scanner (#9) - REST API security scanner
3829b08 Add News Scraper (#8) - security RSS aggregator
cd29e26 Add Stego Tool (#7) - LSB steganography detection + trailing data
f0e5b2c Add Hash Cracker (#6) - hash ID + rainbow table crack
6cccb5f Add DNS Lookup (#5) - multi-record DNS queries + reverse DNS
34c51a8 Add Port Scanner (#3) and Subdomain Scanner (#4) API modules
159a856 secrets-scanner: modulo backend + endpoint REST + boton frontend
670c035 headers-scanner: modulo backend + endpoint REST + boton frontend
```

*Última actualización: Julio 2026*
