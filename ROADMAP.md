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
- [x] Backend (9 módulos Python, 65+ endpoints REST)
- [x] Supabase persistence (11 tablas)
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

## FASE 3 — Op Admiral (Planificador de Misión)

**Objetivo:** Describes el target en lenguaje natural, la IA genera un plan de ataque paso a paso.

### Frontend
- [ ] Campo de texto "Describe el objetivo:" con botón "Generar plan"
- [ ] Plan de ataque en tarjetas expandibles
- [ ] Cada paso del plan → botón "Ejecutar este paso" o "Ejecutar todo"
- [ ] Barra de progreso de la misión

### Backend
- [ ] Agente "Op Admiral" que genera plan basado en target + findings
- [ ] Ejecución secuencial con aprobación humana por paso
- [ ] Almacenamiento de planes de misión (localStorage / SQLite)
- [ ] Detección de herramientas disponibles en Kali

### Archivos a crear
- `frontend/js/planner.js` — lógica del planificador
- `backend/planner.py` — agente Op Admiral
- `backend/mission_store.py` — almacén de misiones

---

## FASE 5 — Hallazgos Persistentes + Reportes Automáticos

**Objetivo:** Informes automáticos compilados con IA.

### Frontend
- [ ] Hallazgos guardados en localStorage + exportables
- [ ] Informe automático con Findings + outputs + sugerencias IA
- [ ] Exportar informe completo en MD/HTML/PDF con un clic

### Backend
- [x] API REST para hallazgos (CRUD)
- [x] Almacenamiento persistente (Supabase)
- [x] Endpoint `/api/report/generate` que compila informe
- [ ] Integración IA en generación de informes

---

## FASE 6 — Contención de Alcance (Scope)

**Objetivo:** Evitar que las herramientas escaneen hosts fuera del objetivo.

### Backend
- [x] Configuración de alcance (IP/rango/dominio)
- [x] Proxy wrapper que intercepta comandos y bloquea off-scope
- [x] Modo "solo target" y "red local permitida"
- [ ] UI mejorada para gestión de scope

---

## FASE 7 — Producción + Cloudflare Tunnel

**Objetivo:** Acceso desde cualquier lugar sin Render.

### Pasos
- [ ] Comprar dominio (3-5€/año)
- [ ] Configurar Cloudflare DNS
- [ ] Crear túnel nombrado permanente
- [ ] Servicio systemd para cloudflared (auto-arranque)
- [ ] HTTPS automático por Cloudflare

### Archivos de referencia
- `PRODUCTION_PLAN.md` — pasos detallados

---

## 📝 Pendientes menores

- [ ] Probar findings con todos los parsers (nikto, dirb, ffuf, etc.)
- [ ] Payload Studio: botón "Abrir en nueva pestaña" (X-Frame-Options bloquea iframe)
- [ ] Verificar contador de modules loaded (banner dice 15, debería ser 51)
- [ ] Hak5 Payload AI integration
- [ ] Self-improvement loop (aprender de misiones pasadas)
- [ ] OPSEC Levels (Silent/Covert/Loud)
- [ ] Evidence Vault (screenshots, requests, outputs)

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
| Fase 3 | Op Admiral (planificador) | 🚧 Pendiente |
| Fase 4 | Multi-operador (Swarm) | ✅ Completado |
| Fase 5 | Hallazgos persistentes + informes | 🚧 Parcial |
| Fase 6 | Contención de alcance | 🟡 Parcial (backend listo, UI falta) |
| Fase 7 | Producción (dominio + tunnel) | 🚧 Pendiente |
| Labs | Mobile + Forensics + KB + CTF + Creds | ✅ Completado |
| MCP | Server para agentes IA | ✅ Completado |

---

*Última actualización: Julio 2026 — M.I.R.V. v3.0*