# 🗺️ M.I.R.V. — Roadmap de Mejoras

## ✅ Completado

### Conexión SSH
- [x] Conexión SSH interactiva con `invoke_shell()` + PTY
- [x] Reconexión dinámica por WebSocket
- [x] Gestión de conexiones guardadas (localStorage)
- [x] Puerto personalizable (no solo 22)
- [x] Sudo automático con `-S` + password (heredoc quoteado)

### Terminal
- [x] Prompt limpio (Powerlevel10k desactivado)
- [x] Filtro ANSI completo (colores, OSC, DEC privados, Nerd Font/PUA)
- [x] Manejo de `\r` en progresos tipo apt
- [x] Click en terminal → focus en input
- [x] Historial de comandos con flechas ↑/↓ (últimos 100)
- [x] Botón Stop (Ctrl+C / SIGINT)
- [x] Tab completion con detección de CWD real vía `/proc`
- [x] Subida de archivos chunked base64 (soporta binarios >1MB)
- [x] Responsive layout (mobile sidebar + command bar separada)

### Findings Panel (Fase 1)
- [x] Pestaña **🎯 Findings** con tarjetas de severidad
- [x] Parser para nmap, whatweb, gobuster, dirb, ffuf, nikto, wpscan
- [x] Detección de fin de comando por prompt pattern
- [x] Deduplicación de hallazgos por `key:val`
- [x] Filtros por severidad (critical/high/medium/low/info)
- [x] Export en `.txt` / `.md` / `.html` / `📄 PDF`
- [x] Persistencia en Supabase (CRUD via `/api/findings`)

### AI Assistance (Fase 2)
- [x] Endpoint `/api/suggest` que recibe findings y devuelve sugerencia
- [x] Multi-proveedor: OpenAI, Anthropic, Gemini, OpenRouter, DeepSeek, Groq
- [x] AI en 6 pestañas: Reports, Automation, Swarm, Credentials, KnowledgeBase, CTF
- [x] Auto-guardado de API keys en localStorage
- [x] AI Writeup para informes automáticos
- [x] Bounty Reports con AI

### Labs
- [x] **Mobile Analysis Lab** — APK static + dynamic (ADB/Frida)
- [x] **Forensics Lab** — memoria, disco, Sleuth Kit
- [x] **KnowledgeBase** — CVE + MITRE ATT&CK search
- [x] **CTF Mode** — challenges con flags y tracking
- [x] **Credential Store** — almacenamiento de credenciales descubiertas

### Multi-operador (Fase 4)
- [x] **Swarm** — operadores Recon, Scanner, Exploiter, Report
- [x] Coordinador con pizarra compartida
- [x] Sesiones de swarm con reportes
- [x] Cancelación de misiones

### Infraestructura
- [x] **MCP Server** — expone herramientas a agentes IA (Claude Code, Cursor)
- [x] **Scope Guard** — validación de alcance (modo Warn/Block)
- [x] Backend (11 módulos Python, 80+ endpoints REST)
- [x] Supabase persistence (17 tablas)
- [x] i18n (150+ traducciones EN/ES)
- [x] Responsive + mobile sidebar
- [x] PDF generation server-side (ReportLab)
- [x] n8n Automation integration

### Seguridad
- [x] Credenciales eliminadas del backend/frontend
- [x] WebSocket exige autenticación JSON obligatoria
- [x] No fallbacks a credenciales por defecto

### Despliegue
- [x] Backend local funcional (uvicorn + FastAPI)
- [x] Plan de producción guardado (`PRODUCTION_PLAN.md`)
- [x] cloudflared instalado en Kali (2026.6.1)

---

## 🚧 En Progreso / Pendientes

---

## FASE 3 — Op Admiral (Planificador de Misión) ✅

**Objetivo:** Describes el target en lenguaje natural, la IA genera un plan de ataque paso a paso.

### Frontend ✅
- [x] Campo de texto "Describe el objetivo:" con botón "Generar plan"
- [x] Plan de ataque en tarjetas expandibles
- [x] Cada paso del plan → botón "Ejecutar este paso" o "Ejecutar todo"
- [x] Barra de progreso de la misión
- [x] Integración con AI (multi-proveedor via `/api/ai/chat`)

---

## FASE 5 — Hallazgos Persistentes + Reportes Automáticos ✅

### Backend ✅
- [x] API REST para hallazgos (CRUD en `/api/findings`)
- [x] Almacenamiento persistente (Supabase, tabla `findings`)
- [x] Endpoint `/api/report/generate` que compila informe
- [x] Endpoint `/api/generate-pdf` (ReportLab)

### Frontend ✅
- [x] Hallazgos exportables (`.txt` / `.md` / `.html` / PDF)
- [x] Exportar informe completo con un clic
- [x] Bounty Reports con plantilla + AI
- [x] AI Writeup para informes automáticos

---

## FASE 6 — Contención de Alcance (Scope) ✅

### Backend ✅
- [x] Configuración de alcance (IP/rango/dominio) — `scope_guard.py`
- [x] Proxy wrapper que intercepta comandos y bloquea off-scope
- [x] Modo "solo target" y "red local permitida"
- [x] Modo Warn (avisa) y Block (bloquea)
- [x] Endpoints `/api/scope`, `/api/scope/validate`, `/api/scope/history`

### Frontend ✅
- [x] Modal de configuración de scope (`#scope-modal`)
- [x] Checkbox "Enable scope enforcement"
- [x] Selector modo (Warn / Block)
- [x] Textarea para definir targets permitidos
- [x] Badge en header indicando estado del scope
- [x] `js/scope.js` cargado en `index.html`

---

## FASE 7 — Producción + Cloudflare Tunnel 🚧

**Objetivo:** Acceso desde cualquier lugar sin Render.

### Pasos pendientes (infraestructura, no código)
- [ ] Comprar dominio (3-5€/año)
- [ ] Descargar e instalar cloudflared.exe en Windows
- [ ] Autenticar cloudflared
- [ ] Crear túnel nombrado permanente
- [ ] Configurar DNS
- [ ] Servicio/systemd para auto-arranque
- [ ] HTTPS automático por Cloudflare

### Documentación lista
- [x] `PRODUCTION_PLAN.md` — pasos detallados completos

---

## 🔴 OPSEC Levels (Silent / Covert / Loud) ✅

- [x] `backend/opsec.py` — 30 tools mapeadas con modifiers flags-only
- [x] `apply_opsec(tool, command, level, target)` preserva el target del operador
- [x] Bloqueo de tools no stealth (masscan, nikto, hydra, wpscan, responder...)
- [x] Endpoints `/api/opsec/levels`, `/api/opsec/apply` (con target opcional)
- [x] Badge en header (🟢/🟡/🔴) + modal con 3 niveles
- [x] `launchTool` ahora es async, aplica OPSEC antes de ejecutar
- [x] Fallback local `_OPSEC_RULES` si backend no responde
- [x] Persistencia en `localStorage.mirv_opsec`
- [x] i18n EN/ES (opsecModalTitle/Desc, opsecSilentDesc/CovertDesc/LoudDesc)

---

## 🧠 Self-Improvement Loop ✅

- [x] `backend/mission_store.py` — save_mission, list_missions, find_similar
- [x] Tabla `mission_history` en Supabase (con índices)
- [x] `get_suggestion_context()` — genera contexto de misiones previas para IA
- [x] `/api/suggest` ahora inyecta "Mission History Context" al system prompt
- [x] Endpoints `/api/missions`, `/api/missions/save`, `/api/missions/similar`, `DELETE /api/missions/{id}`
- [x] UI Mission History en Op Admiral tab (cards con score badges)
- [x] Tracking de tools usadas por sesión (`toolsUsedThisSession`)
- [x] `_detectOSFromFindings` con 50+ patrones (Apache, IIS, OpenSSH, Samba, Windows, Ubuntu, macOS, Cisco...)
- [x] Score calc: critical=100, high=50, medium=20, low=10, info=5 (clamped 0-100)
- [x] i18n EN/ES (missionHistoryTitle, saveMissionBtn, missionEmpty)

---

## ✅ 9 Módulos desde Cybersecurity-Projects (Julio 2026)

- [x] **#1 HTTP Headers Scanner** — `headers_scanner.py` + `GET /api/headers/scan`
- [x] **#2 Secrets Scanner** — `secrets_scanner.py` + `GET /api/secrets/scan`
- [x] **#3 Port Scanner** — `port_scanner.py` + `GET /api/port/scan`
- [x] **#4 Subdomain Scanner** — `subdomain_scanner.py` + `GET /api/subdomain/scan`
- [x] **#5 DNS Lookup** — `dns_lookup.py` + `GET /api/dns/lookup` + reverse
- [x] **#6 Hash Cracker** — `hash_cracker.py` + `GET /api/hash/crack`
- [x] **#7 Steganography Tool** — `stego_tool.py` + `POST /api/stego/analyze`
- [x] **#8 Security News Scraper** — `news_scraper.py` + `GET /api/news`
- [x] **#9 API Security Scanner** — `api_scanner.py` + `GET /api/apiscan`
- [x] **Documentación:** `docs/MODULOS_NUEVOS.md` con endpoints, clases, tests
- [x] **UI Arsenal:** Botones API-based, categorías colapsables, badges, Run All
- [x] **Integración:** Todos los endpoints registrados en `main.py`

## ✅ Modernización UI (Julio 2026)

- [x] **Categorías colapsables** — comienzan cerradas, toggle por categoría
- [x] **Master toggle** — Expand All / Collapse All
- [x] **Run All** — botón por categoría para ejecutar todas las tools API
- [x] **Badges** — contadores de herramientas por categoría
- [x] **Filter** — búsqueda en tiempo real con auto-expand/collapse
- [x] **Fix OSINT** — unificación de cat-body duplicado

## ✅ Event Delegation (Julio 2026)

- [x] **126 onclick** en `index.html` → `data-*` attributes
- [x] **7 onclick + 1 onchange** en `main.v2.js` → `data-*` attributes
- [x] **ACTION_MAP** centralizado (~90 entradas) para todas las acciones
- [x] **Event delegation** en `#app` (click + change)
- [x] **0 onclick** en toda la aplicación
- [x] **Documentación:** `docs/EVENTOS.md` con mapeo completo
- [x] **Backup** pre-refactor en `frontend/index.html.bak`

---

## 📝 Pendientes menores

- [ ] Probar findings con todos los parsers (nikto, dirb, ffuf, wpscan, etc.)
- [ ] Payload Studio: botón "Abrir en nueva pestaña" (X-Frame-Options bloquea iframe)
- [ ] Cobertura de tests > 70% (requiere ~2500 líneas más en main.py, database.py, módulos specialty)
- [ ] Configurar secrets de Docker Hub + VPS en el repo GitHub
- [ ] Escaneo de seguridad (bandit, safety) en CI

---

## FASE 8 — Docker, Tests, CI/CD (Próximo gran hito) 🚧

**Objetivo:** Contenerizar, automatizar pruebas, pipeline CI/CD completo.

### Backend
- [x] Dockerfile para uvicorn + dependencias ✅
- [x] docker-compose.yml (backend + kali-tools container) ✅
- [x] Imagen Kali con 50+ herramientas + SecLists + rockyou ✅
- [x] pytest con 388 tests endpoints + 9 módulos API (160 API endpoint tests) ✅
- [ ] Cobertura de tests > 70% (actual: 39% global)

### Frontend
- [x] El frontend se sirve estáticamente desde el contenedor backend ✅
- [x] Tests de integración (Playwright) — 24 tests, 0 fallos ✅
- [ ] Validación de parsers de findings

### CI/CD
- [x] **GitHub Actions: lint + test + build + deploy** — `.github/workflows/ci.yml` ✅
  - Ruff lint + format check
  - Backend: 388 tests pytest
  - Frontend: 24 tests Playwright (Chromium)
  - Docker Build + push a Docker Hub (solo main)
  - Deploy SSH a VPS (solo main)
- [ ] Configurar secrets del repo (DOCKER_USERNAME, DOCKER_TOKEN, VPS_HOST, VPS_USER, VPS_SSH_KEY)
- [ ] Escaneo de seguridad (bandit, safety) — pendiente de integrar

---

## ✅ Arsenal ampliado: OSINT + Pentest Labs + Bug Bounty (Julio 2026)

- [x] **6 herramientas OSINT CLI** con auto-instalación: TheHarvester, Mr.Holmes, Infoooze, BBOT, LinkedIn2Username, SpiderFoot
- [x] **8 enlaces OSINT web**: Flare.io, Lenso AI, OSINT Framework, SpiderFoot, Shodan, Censys, VirusTotal, HaveIBeenPwned
- [x] **10 Pentest Labs**: DockerLabs, HackTheBox, TryHackMe, VulnHub, Proving Grounds, HackMyVM, PortSwigger Academy, OverTheWire, PicoCTF, RootMe
- [x] **8 Bug Bounty platforms**: HackerOne, Bugcrowd, Intigriti, YesWeHack, Secur0, Open Bug Bounty, Synack, Grey Hack
- [x] **3 nuevas categorías sidebar**: OSINT, Pentest Labs, Bug Bounty
- [x] **i18n**: catOsint, catPentest, catBugbounty (EN/ES)
- [x] **Función `renderSiteButton`** con badges dinámicos (TOP/GRATIS/FREEMIUM/ES/PAGO/JUEGO)
- [x] **Total arsenal**: 51 → 83+ módulos (32 nuevos)

---

## ✅ Integración Kali Docker (Julio 2026)

- [x] **Docker Compose full stack** — `docker-compose.yml` con kali-tools + MIRV backend
- [x] **Imagen Kali personalizada** — `docker/kali-mcp.Dockerfile` con 50+ herramientas + SSH
- [x] **MIRV backend Dockerfile** — `backend/Dockerfile` para contenerizar el dashboard
- [x] **Cliente Kali** — `backend/kali_mcp_client.py` (modo SSH + modo MCP experimental)
- [x] **Detección automática** — health check al arrancar, integrado en `/api/health`
- [x] **Configuración auto-vía-env-vars** — `KALI_IP=kali-tools`, `KALI_PORT=22`, `KALI_USER=root`, `KALI_PASS=mirv`
- [x] **SecLists + rockyou.txt** incluidos en el contenedor
- [x] **Contenedores probados y funcionando** — ambos Up (kali-tools healthy, backend production)
- [x] **Documentación completa** — README con arquitectura, comandos de prueba, troubleshooting

---

## ✅ Mejoras Mobile: Frida Stop + Clear (Julio 2026)

- [x] **Botón Stop Frida** — mata procesos Frida en Kali vía `pkill` desde el frontend
- [x] **Botón Clear consola** — limpia el output de la consola Frida al instante
- [x] **Endpoint `POST /api/mobile/frida/stop`** — ejecuta `pkill -f "frida"` con/sin device serial
- [x] **Endpoint `POST /api/mobile/frida/clear`** — logging backend (acción de cliente)
- [x] **Mensajes de error mejorados** — `_ssh_sftp_upload()` ahora devuelve la causa exacta del fallo (SSH no conectado, archivo local no encontrado, permiso denegado en Kali, error SFTP)
- [x] **Content-Security-Policy (CSP)** — cabecera explícita que permite Tailwind CDN (con `unsafe-eval`), WebSocket, imágenes, y conexiones externas. Elimina el error de consola "Refused to execute code due to CSP"

---

## ✅ Persistence Audit & Fixes (Julio 2026)

- [x] **Auditoría completa de persistencia:** Documentados todos los gaps en `PERSISTENCE_AUDIT.md`
- [x] **DB bootstrap:** `_ensure_tables()` ahora crea tablas con 3 estrategias (psycopg2 directa, Mgmt API, fallback graceful)
- [x] **Schema sincronizado:** 17 tablas con índices en `supabase_schema.sql` y `SCHEMA_SQL` en `database.py`
- [x] **3 APIs muertas conectadas:** SSH connections (`/api/connections`), scripts (`/api/scripts`), payloads (`/api/payloads`) — offline-first pattern con localStorage fallback
- [x] **Bounty reports + AI writeups:** Auto-guardado en `reports` table via `_saveReportToDB()`
- [x] **15 nuevos endpoints:** `/api/plans` (CRUD), `/api/scope/events` (CRUD+clear), `/api/swarm/sessions` (CRUD), `/api/credentials/secrets` (CRUD)
- [x] **Scope events persistence:** `scope_guard.log_block()` ahora persiste a `scope_events` via `save_scope_event()` fire-and-forget
- [x] **Swarm sessions persistence:** `run_pipeline()` guarda sesión completa al finalizar
- [x] **Secrets fuera de localStorage:** AI keys y Payload Studio creds migradas a `app_credentials` via `/api/credentials/secrets`; caché en localStorage se limpia tras migración exitosa
- [x] **`backend/__init__.py` fix:** Añadido `sys.path` para evitar `ModuleNotFoundError` en subprocess de uvicorn reloader

---

## ✅ Bugs Corregidos (Julio 2026)

- [x] **CSP bloqueaba Tailwind CDN:** Añadida cabecera `Content-Security-Policy` explícita con `script-src 'unsafe-eval'` y permisos para WebSocket, imágenes, conexiones externas.
- [x] **Frida upload sin diagnóstico:** `_ssh_sftp_upload()` ahora devuelve el motivo exacto del fallo en lugar de un genérico "Could not upload".

- [x] **Duplicación de findings:** Race condition entre safety timer (30s) y detector de prompt. Añadida deduplicación por clave compuesta + `_toolParsed` flag.
- [x] **Findings no aparecían:** `currentToolRunning` solo se asignaba para nmap/gobuster. Fix: añadidos whatweb y otros 12 tools.
- [x] **Buffer vacío al parsear:** Timer de 800ms se disparaba antes de que llegara el output real. Fix: prompt detection + `pendingTool` que sobrevive al timer.
- [x] **Terminal: flechas ↑/↓:** Añadido `focus()` + `setSelectionRange()`.
- [x] **Upload file (>1MB):** Substituido heredoc por subida chunked base64.
- [x] **Reconexión prompt limpio:** `asyncio.sleep(0.3)` tras `invoke_shell()`.
- [x] **sudo -S caracteres especiales:** Heredoc con delimitador quoteado.
- [x] **Auto-scroll:** `setTimeout(0)` con debounce en vez de `requestAnimationFrame`.

---

## 📊 Resumen

| Fase | Descripción | Estado |
|------|------------|--------|
| Fase 1 | Parser de resultados + Findings Panel | ✅ Completado |
| Fase 2 | Sugerencias IA | ✅ Completado |
| Fase 3 | Op Admiral (planificador) | ✅ Completado |
| Fase 4 | Multi-operador (Swarm) | ✅ Completado |
| Fase 5 | Hallazgos persistentes + informes | ✅ Completado |
| Fase 6 | Contención de alcance | ✅ Completado |
| Fase 7 | Producción (dominio + tunnel) | 🚧 Pendiente (infraestructura) |
| Fase 8 | Docker + Tests + CI/CD | 🚧 En progreso (Docker OK, faltan tests) |
| Labs | Mobile + Forensics + KB + CTF + Creds | ✅ Completado |
| MCP | Server para agentes IA | ✅ Completado |
| OPSEC | Levels (Silent/Covert/Loud) | ✅ Completado |
| Self-Improvement | Mission History + AI context | ✅ Completado |
| Persistence Audit | 17 tablas, 15 endpoints, offline-first | ✅ Completado |
| Frida Stop/Clear | Stop + Clear console, CSP fix, error msgs | ✅ Completado |
| Arsenal OSINT | 6 tools OSINT + 8 web links + 10 labs + 8 BB platforms | ✅ Completado |
| 9 Cybersecurity Modules | #1–#9 desde CarterPerez-dev/Cybersecurity-Projects | ✅ Completado |
| UI Modernization | Categorías colapsables, master toggle, Run All, badges, filter | ✅ Completado |
| Event Delegation | 0 onclick en toda la app, ACTION_MAP centralizado | ✅ Completado |
| #app bugfix | document.body replaces #app (not found) in event delegation | ✅ Completado |
| Backend Tests (pytest) | 388 tests (228 módulos + 160 API endpoints), 0 fallos, 39% coverage | ✅ Completado |
| Frontend Tests (Playwright) | 24 tests (smoke, tabs, arsenal, i18n, responsive), 0 fallos | ✅ Completado |
| CI/CD | GitHub Actions (lint + test-backend + test-frontend + docker-push + deploy) | ✅ Completado |

---

*Última actualización: Julio 2026 — M.I.R.V. v3.0*