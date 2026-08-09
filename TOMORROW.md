# 🔮 TOMORROW.md — Roadmap de trabajo pendiente

> Última actualización: 8 Ago 2026 — MIRV v5.0 | 30 módulos | 227 endpoints | 3834 tests | 25 tabs | main.py 100%

---

## ✅ Estado actual del proyecto

| Métrica | Valor |
|---------|-------|
| Backend modules | 30 (main.py + 29 especializados) |
| REST endpoints | 227 |
| Test files | 76 |
| Tests collected | 3834 |
| Coverage | ~95% global — **main.py 100%** |
| Frontend tabs | 25 |
| Frontend JS | 9231 líneas (main.v2.js) |
| Frontend HTML | 2694 líneas (index.html) |
| GitHub Actions | 2 workflows (CI + Deploy) |
| Docker images | 2 (mirv-backend + kali-tools) |
| GitHub commits | 11+ esta serie |

---

## 📦 Módulos completados (todos funcionando en Docker)

### Core de seguridad
| # | Módulo | Archivo | Tests | Qué hace |
|---|--------|---------|-------|----------|
| 1 | **Scope Guard** | `scope_guard.py` (755L) | 56 | Validación de alcance + Permission Prompts interactivos (16 danger patterns, session cache, TTL) |
| 2 | **OPSEC Levels** | `opsec.py` (400L) | 25 | 30 tools con modificadores Silent/Covert/Loud |
| 3 | **Redaction** | `redact.py` (430L) | 63 | 20 patrones de redacción (AWS, GitHub, JWT, PEM, etc.), shape-preserving |
| 4 | **Audit Log** | `audit_log.py` (470L) | 45 | JSONL structure + 4MB rotation + SIEM forwarding |

### Inteligencia y monitoreo
| # | Módulo | Archivo | Tests | Qué hace |
|---|--------|---------|-------|----------|
| 5 | **SIEM** | `siem.py` (743L) | 31 | Eventos, 4 reglas de correlación, alerts, thread-safe |
| 6 | **Intelligence** | `intelligence.py` (890L) | 43 | Watch/snapshot/diff/alert — 6 tipos de monitor (headers, cert, DNS, ports, tech, content) |
| 7 | **EXIF OSINT** | `exif_osint.py` (812L) | 21 | GPS extraction, camera metadata, reverse geocoding, Leaflet map |
| 8 | **Canary Tokens** | `canary_tokens.py` (442L) | 24 | 8 tipos de honeytokens + activation tracking |

### Herramientas de testing
| # | Módulo | Archivo | Tests | Qué hace |
|---|--------|---------|-------|----------|
| 9 | **DLP Scanner** | `dlp_scanner.py` (453L) | 25 | 8 patrones PII + validación Luhn + risk scoring |
| 10 | **Burp Bridge** | `burp_bridge.py` (599L) | 72 | Ingest server + LRU store + finding↔issue + Jython plugin |
| 11 | **Finding PoC** | `finding_poc.py` (745L) | 61 | PoC builder, curl parser, replay (subprocess), markdown reports, evidence hash |
| 12 | **Coverage Tracker** | `coverage.py` (480L) | 33 | Matriz (endpoint×param×vuln_class) + next_steps estimator |
| 13 | **PDF Engine** | `pdf_engine.py` (1323L) | 47 | Profesional: cover, TOC, severity colors, findings table, code blocks |

### Plugins y automatización
| # | Módulo | Archivo | Tests | Qué hace |
|---|--------|---------|-------|----------|
| 14 | **Plugin Manager** | `plugin_manager.py` (700L) | 65 | Discovery + 5 hooks + hot-reload (watchdog + polling fallback) |
| 15 | **Skill Playbooks** | `skill_playbooks.py` (450L) | 67 | 10 playbooks MD (recon, webvuln, ssrf, jwt, supabase, graphql, race, takeover, deserialize, ssti) |

### Infraestructura
| # | Módulo | Archivo | Tests | Qué hace |
|---|--------|---------|-------|----------|
| 16 | **Database** | `database.py` (1344L) | 196 | Supabase CRUD, 17 tablas, 85% coverage |
| 17 | **Mission Store** | `mission_store.py` (356L) | 30 | Self-improvement loop, session compaction |
| 18 | **MCP Server** | `mcp_server.py` (620L) | — | Tools para agentes IA |
| 19 | **Kali MCP Client** | `kali_mcp_client.py` (130L) | 20 | Cliente Docker integration |
| 20 | **Swarm** | `swarm.py` (250L) | 30 | Multi-operator coordinator |
| 21 | **Mobile Analyzer** | `mobile_analyzer.py` (707L) | — | APK static + dynamic (ADB/Frida) |
| 22 | **Forensics** | `forensics.py` (253L) | 30 | Digital forensics (memory, disk, Sleuth Kit) |
| 23 | **KnowledgeBase** | `knowledgebase.py` (210L) | 45 | CVE + MITRE ATT&CK DB |
| 24 | **ADB Controller** | `adb_controller.py` (205L) | 25 | Device detection + Frida scripts |

### API-based tools (sin SSH)
| # | Módulo | Archivo | Tests | Qué hace |
|---|--------|---------|-------|----------|
| 25 | **HTTP Headers Scanner** | `headers_scanner.py` | 32 | Grade A–F, 7 security headers |
| 26 | **Secrets Scanner** | `secrets_scanner.py` | 33 | 25 regex patterns |
| 27 | **Port Scanner** | `port_scanner.py` | 18 | ~1600 puertos async |
| 28 | **Subdomain Scanner** | `subdomain_scanner.py` | 11 | ~700 prefijos DNS |
| 28+ | DNS Lookup, Hash Cracker, Stego, News, API Scanner | — | 126+ | Variados |

---

## 🖥️ Frontend — 27 pestañas

| # | Tab | ID | Módulo backend | Descripción |
|---|-----|----|----------------|-------------|
| 0 | Terminal | `tab-terminal` | main.py | SSH shell interactivo |
| 1 | Reports | `tab-reports` | main.py | Informes + export |
| 2 | Scripts | `tab-scripts` | main.py | Script builder |
| 3 | Bounty | `tab-bounty` | main.py | Bug bounty reports |
| 4 | AI Writeup | `tab-aiwriteup` | main.py | Writeups con AI |
| 5 | Findings | `tab-findings` | main.py | Hallazgos parseados |
| 6 | Op Admiral | `tab-opadmiral` | main.py | Planificador de misión |
| 7 | Automation | `tab-automation` | main.py | n8n integration |
| 8 | Swarm | `tab-swarm` | swarm.py | Multi-operador |
| 9 | Credentials | `tab-credentials` | database.py | Store de credenciales |
| 10 | KnowledgeBase | `tab-knowledgebase` | knowledgebase.py | CVE + MITRE |
| 11 | CTF | `tab-ctf` | main.py | Challenges + flags |
| 12 | Mobile | `tab-mobile` | mobile_analyzer.py | APK analysis lab |
| 13 | Forensics | `tab-forensics` | forensics.py | Forense digital |
| 14 | EXIF OSINT | `tab-exif` | exif_osint.py | Metadata + GPS map |
| 15 | Canary Tokens | `tab-canary` | canary_tokens.py | Honeytokens |
| 16 | DLP Scanner | `tab-dlp` | dlp_scanner.py | PII detection |
| 17 | SIEM | `tab-siem` | siem.py | Event feed + alerts |
| 18 | Plugins | `tab-plugins` | plugin_manager.py | Plugin management |
| 19 | Coverage | `tab-coverage` | coverage.py | Coverage matrix |
| 20 | Burp Bridge | `tab-burp` | burp_bridge.py | Burp ingest |
| 21 | Audit Log | `tab-audit` | audit_log.py | JSONL audit viewer |
| 22 | Skills | `tab-skills` | skill_playbooks.py | Skill playbooks |
| 23 | Intelligence | `tab-intelligence` | intelligence.py | Continuous monitoring |
| 24 | Docker | — | main.py | Container controls |
| 25 | **Browser Capture** | `tab-browsercapture` | browser_capture.py | HAR import + security analysis |

---

## 🔌 Endpoints REST por módulo

| Módulo | Endpoints | Métodos |
|--------|-----------|---------|
| Scope/Permissions | 7 | GET/POST/DELETE `/api/permissions/*`, `/api/scope/*` |
| Intelligence | 11 | CRUD watches + snapshots + diff + alerts |
| Finding PoC | 6 | build, parse-curl, finding-to-md, from-burp, validate, replay |
| Burp Bridge | 15 | ingest, requests, endpoints, tasks, issues, export |
| Audit Log | 3 | logs, stats, create |
| SIEM | 8 | events, stats, rules, alerts, findings |
| Skills | 9 | CRUD + load/unload/reload + render |
| Coverage | 10 | mark, list, summary, next, sessions, export, vocab |
| Plugins | 12 | CRUD + load/unload/reload + watcher |
| EXIF | 2 | analyze (POST/GET) |
| Canary | 5 | create, list, activate, events, delete |
| DLP | 3 | scan, scan-file, scan-url |
| Redaction | 4 | redact, dict, patterns, check |
| Missions | 5 | CRUD + similar |
| Plans | 3 | CRUD |
| Findings | 5 | CRUD + bulk + stats |
| Docker | 6 | status, start, stop, clean, build, task |
| MCP | 3 | status, tools, exec |
| AI | 2 | chat (auto-redacts), suggest (+ coverage context) |
| **Total** | **208** | |

---

## 📋 Pendiente

### Prioridad ALTA — Hecho ✅
- [x] ~~Docker rebuild + smoke test~~ — ✅ Rebuild completo, ambos containers healthy
- [x] ~~Finding PoC module~~ — ✅ 745L + 61 tests + 6 endpoints + frontend
- [x] ~~Permission Prompts~~ — ✅ scope_guard.py 755L + 56 tests + 7 endpoints
- [x] ~~Continuous Intelligence~~ — ✅ intelligence.py 890L + 43 tests + 11 endpoints + frontend tab

### Prioridad MEDIA
- [ ] **Configurar secrets GitHub** (manual, 15 min) — habilita deploy automático
  ```bash
  # Ir a https://github.com/SenorJA/dashboard-ctf/settings/secrets/actions
  # Añadir: DOCKERHUB_USERNAME, DOCKERHUB_TOKEN, VPS_HOST, VPS_USER, VPS_SSH_KEY
  ```
- [ ] **Verificar CI en GitHub** — tras secrets, push para disparar workflows
- [x] ~~**Browser Capture MCP**~~ — 7 tools MCP envolviendo browser_capture (022f349)
- [x] **Cobertura global > 80%** — ~95%; **main.py 100%** (2847/2847) vía test_main_gaps.py (295) + test_main_websocket_gaps.py (19)

### Prioridad BAJA
- [ ] Fase 7 — Cloudflare Tunnel (dominio + cloudflared)
- [ ] Export findings a PDF mejorado
- [x] ~~Swarm: más operadores (OSINT, Web, Vuln)~~ — 3 operadores nuevos + mode full/core (dedfda6)

---

## 🐛 Bugs conocidos / TODOs

1. **`test_slow_hook`** excluido de CI — tarda 35s
2. **Plugin watcher tests** — timers 250ms+ por debounce
3. **Module identity split** — tests importan `backend.modulo` vs `modulo`
4. **exif_osint.py coverage 63%** — requiere imágenes/reales
5. **dlp_scanner.py coverage 67%** — patrones archivo/URL
6. ~~**main.py coverage 53%**~~ — ✅ **100%** (2847/2847) con test_main_gaps.py + test_main_websocket_gaps.py
7. **`test_full_session` (websocket)** — flaky por contención de TestClient al correr el archivo completo; pasa al ejecutarlo en solitario

---

## 🔄 Cómo actualizar después de cambios

### Después de modificar backend/*.py
```bash
# 1. Tests locales
cd backend && python -m pytest tests/ -q --tb=short

# 2. Docker rebuild
docker compose -p proyectociber build --no-cache mirv-backend
docker compose -p proyectociber up -d

# 3. Verificar
curl http://localhost:8000/api/health
curl http://localhost:8000/api/intelligence/watches
```

### Después de modificar frontend/
```bash
# Copiar rápido sin rebuild
docker cp frontend/index.html mirv-backend:/app/frontend/index.html
docker cp frontend/js/main.v2.js mirv-backend:/app/frontend/js/main.v2.js
# Refrescar navegador (Ctrl+Shift+R)
```

### Commit y push
```bash
git add -A
git commit -m "feat(modulo): descripción"
git push origin main
```

---

*Documento generado: 25 Jul 2026*
