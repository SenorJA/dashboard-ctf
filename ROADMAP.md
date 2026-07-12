# 🗺️ M.I.R.V. — Roadmap de Mejoras

> Anteriormente VulnForge — v3.0

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

## 📝 Pendientes menores

- [ ] Probar findings con todos los parsers (nikto, dirb, ffuf, wpscan, etc.)
- [ ] Payload Studio: botón "Abrir en nueva pestaña" (X-Frame-Options bloquea iframe)
- [ ] Dockerizar backend + frontend (ver Fase 8 abajo)
- [ ] Tests automatizados (pytest para backend, vitest/cypress para frontend)
- [ ] CI/CD con GitHub Actions

---

## FASE 8 — Docker, Tests, CI/CD (Próximo gran hito) 🚧

**Objetivo:** Contenerizar, automatizar pruebas, pipeline CI/CD.

### Backend
- [ ] Dockerfile para uvicorn + dependencias
- [ ] docker-compose.yml (backend + Supabase local opcional)
- [ ] pytest con fixtures para endpoints REST + WebSocket
- [ ] Cobertura de tests > 70%

### Frontend
- [ ] Dockerfile nginx para SPA estática
- [ ] Tests de integración (Cypress/Playwright)
- [ ] Validación de parsers de findings

### CI/CD
- [ ] GitHub Actions: lint + test + build
- [ ] GitHub Actions: deploy a VPS o Docker Hub
- [ ] Escaneo de seguridad (bandit, safety)

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
| Fase 8 | Docker + Tests + CI/CD | ⏳ Próximo hito |
| Labs | Mobile + Forensics + KB + CTF + Creds | ✅ Completado |
| MCP | Server para agentes IA | ✅ Completado |
| OPSEC | Levels (Silent/Covert/Loud) | ✅ Completado |
| Self-Improvement | Mission History + AI context | ✅ Completado |
| Persistence Audit | 17 tablas, 15 endpoints, offline-first | ✅ Completado |

---

*Última actualización: Julio 2026 — M.I.R.V. v3.0*