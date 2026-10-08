# 🛡️ M.I.R.V. — Multi-platform Incident Response & Vulnerabilities

<div align="center">

**Panel táctico de ciberseguridad** • SSH Proxy Web • OSINT • Forense • Mobile • Automatización Multi-Agente

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Endpoints](https://img.shields.io/badge/endpoints-345-9cf)](#-api-resumen)
[![Tests](https://img.shields.io/badge/tests-5184_✔️-2ea44f?logo=pytest)](#-testing)
[![Coverage](https://img.shields.io/badge/coverage-~95%25-2ea44f)](#-testing)
[![Tabs](https://img.shields.io/badge/frontend%20tabs-35-9cf)](#-features-principales)
[![Kali](https://img.shields.io/badge/Kali-Linux-557C94?logo=kalilinux)](https://kali.org)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/SenorJA/dashboard-ctf/ci.yml?label=CI%2FCD&logo=githubactions)](https://github.com/SenorJA/dashboard-ctf/actions)

**Tema:** Signal Intelligence — ámbar `#d4a843` como acento, fondo oscuro `#0a0a0f`.

</div>

---

## 📋 Índice

- [¿Qué es M.I.R.V.?](#-qué-es-mirv)
- [Arquitectura](#-arquitectura)
- [Quick Start](#-quick-start-3-pasos)
- [Features principales](#-features-principales)
- [Configuración](#-configuración-opcional)
- [API resumen](#-api-resumen)
- [Testing](#-testing)
- [Docker](#-docker)
- [Production (próximamente)](#-production-próximamente)
- [FAQ](#-faq)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Capturas](#-capturas)
- [Documentación relacionada](#-documentación-relacionada)
- [Licencia y créditos](#-licencia-y-créditos)

---

## 🎯 ¿Qué es M.I.R.V.?

M.I.R.V. es una **plataforma modular todo-en-uno** para operaciones de ciberseguridad ofensiva y defensiva. Combina:

- **Terminal SSH interactivo** vía WebSocket (navegador → Kali Linux)
- **345 endpoints REST** (337 `/api/*` + 8 landings/estáticas) contra Supabase (PostgreSQL)
- **57 módulos backend** con ~95% de cobertura de tests (`main.py` al 100%)
- **35 tabs frontend** en una SPA vanilla JS + Tailwind
- **IA multi-proveedor** para informes, sugerencias, chat, análisis de laboratorios y **write-ups dark-mode** (HTML/PDF)
- **Lab Sessions** (Pack 11): máquinas → sesiones → evidencias con **detección determinista de flags** user/root y análisis IA sobre el historial completo
- **Code Agent** (Pack 10/12): puente headless multi-proveedor (**opencode · Claude Code · codex** a futuro) con salida redactada
- **Phishing Sim** (Pack 10): simulador de concienciación *training-only* (solo hashes, sin credenciales reales)
- **Análisis forense** (memoria, disco, archivos) y **móvil** (APK estático + dinámico con Frida)
- **Swarm multi-operador**, **CTF mode**, **OPSEC Levels**, **Self-Improvement Loop**

> **Versión:** v3.4.0 · Releases de escritorio firmadas (Tauri + updater `latest.json`)

---

## 🏗️ Arquitectura

```
┌──────────────┐   WebSocket   ┌──────────────┐    Paramiko    ┌──────────────┐
│   Navegador  │ ────────────► │   FastAPI    │ ─────────────► │  Kali Linux  │
│  (SPA + JS)  │ ◄──────────── │  (main.py)   │ ◄───────────── │  (50+ tools) │
└──────┬───────┘               └──────┬───────┘                └──────────────┘
       │                              │
       │  fetch() /api/* (337)        │  CRUD
       ▼                              ▼
┌──────────────────────────────────────────┐
│              Supabase (PostgreSQL)        │
│              18 tablas + Storage          │
└──────────────────────────────────────────┘
```

**Flujo de datos:**
1. **Frontend SPA** (HTML + vanilla JS + Tailwind CDN) — sin bundler, sin build step.
2. **WebSocket** (`/ws`) proxy SSH bidireccional: navegador ↔ FastAPI ↔ Kali (Paramiko).
3. **API REST** (`/api/*` + landings públicas) ~345 endpoints para operaciones CRUD y análisis.
4. **Supabase** (PostgreSQL) con 18 tablas + Storage bucket para archivos (+ `workspace_state` JSONB para registros opt-in).
5. **Módulos del backend** (57 archivos) operan vía SSH sobre Kali o vía HTTP directo.

---

## 🚀 Quick Start (3 pasos)

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

> Sin Supabase ni Kali, la app arranca en modo offline: las herramientas OSINT/API funcionan, las CLI requieren Kali SSH (tab **Terminal**).

---

## ✨ Features principales

35 tabs agrupados por categoría:

### Core
| Tab | Descripción |
|-----|-------------|
| **Home** | Command Center: KPIs (backend, findings, targets, cobertura, SIEM, intel, CPU/RAM/disco) + quick actions. |
| **Terminal** | Shell SSH interactivo vía WebSocket con PTY, tab-completion, historial y upload. |
| **Reports** | Reportes de escaneo guardados con export a `.md`, `.html`, `.txt` y PDF. |
| **Scripts** | Builder de scripts RCE con deploy a `/tmp/` vía SSH. |
| **Findings** | Hallazgos parseados automáticamente de 10+ herramientas, con filtros por severidad y ciclo de vida. |
| **AI Writeup** | Generación de informes CTF completos en Markdown con IA multi-proveedor. |
| **Bounty** | Generador de reportes de bug bounty con plantillas por plataforma. |
| **Op Admiral** | Planificador de misiones asistido por IA con persistencia de planes. |
| **Code Agent** | `opencode` CLI headless (plan/build/general): status, prompt, salida redactada/truncada. |
| **Lab Sessions** | Máquinas → sesiones → evidencias con detección de flags, análisis IA sobre el historial completo y write-up HTML/PDF dark mode. |
| **AI Personas** | 39 personas de experto (security/testing/engineering/specialized): detalle, build de prompt por tarea, crear/borrar personalizadas, export JSON; el campo `agent` del chat IA inyecta la persona como system prompt. |

### OSINT
| Tab | Descripción |
|-----|-------------|
| **OSINT Recon** | 19 herramientas OSINT pasivas + enlaces web. |
| **EXIF OSINT** | Extracción de metadatos EXIF + GPS + reverse geocoding + mapa Leaflet. |
| **Canary Tokens** | Generador de 8 tipos de honeytokens con tracking de activación. |
| **DLP Scanner** | Detección de PII/secretos (8 patrones + validación Luhn) en texto, archivo o URL. |
| **KnowledgeBase** | 80+ CVEs críticos + técnicas MITRE ATT&CK con búsqueda. |

### Security
| Tab | Descripción |
|-----|-------------|
| **SIEM** | Motor de eventos con 4 reglas de correlación y alertas en tiempo real. |
| **Audit Log** | Log estructurado JSONL con rotación 4MB y redacción automática de secretos. |
| **Coverage** | Matriz de cobertura endpoint×parámetro×clase de vulnerabilidad + próximos pasos. |
| **Plugins** | Sistema de plugins con hot-reload (watchdog) y 5 hooks. |
| **Skills** | **112 playbooks** de habilidades en Markdown + **Task Router** de 39 rutas en/es (hint→skill) con benchmark de regresión de 99 casos. |
| **Intelligence** | Monitorización continua de targets (headers, cert, DNS, puertos, tech stack). |
| **Burp Bridge** | Ingest bidireccional MIRV ↔ Burp Suite (plugin Jython incluido). |
| **Browser Capture** | Import de HAR + 10 checks de seguridad + scoring de riesgo. |

### Mobile / Forensics / Labs
| Tab | Descripción |
|-----|-------------|
| **Mobile** | Laboratorio APK: análisis estático (apktool, jadx, mobsf) + dinámico (ADB + Frida). |
| **Forensics** | Forense de memoria (Volatility), disco (Sleuth Kit) y archivos (strings, binwalk). |
| **CTF** | Challenges con categorías, dificultad, puntos, hints y tracking de flags. |

### Operaciones / Infra
| Tab | Descripción |
|-----|-------------|
| **Docker** | Control del stack Docker desde el dashboard (start/stop/clean/build + polling). |
| **Swarm** | Pipeline multi-operador (Recon → Scanner → Exploiter → Report) con visualización. |
| **Automation** | Integración con n8n para disparar workflows desde findings. |
| **Credentials** | Store de credenciales descubiertas con categorización (SSH, HTTP, DB, API). |
| **Assessments** | Workspace por engagement: estado, targets, tags, notas, export/import. |
| **Scheduler** | Escaneos programados: countdowns, run-now, daemon server-side e historial. |
| **Sys Monitor** | Recursos del host (CPU/RAM/uptime), volúmenes y candidatos de limpieza. |
| **PC Analyzer** | Diagnóstico de equipo (grado A–F) + sugerencias + auto-fix confirmado. |
| **Phishing Sim** | Campañas de concienciación (training-only): landing, clicks y submissions hasheadas. |

> Además, **Payload Studio** se abre como enlace externo (editor de payloads Hak5 para 12 dispositivos).

---

## ⚙️ Configuración (opcional)

Todas las configuraciones son **opcionales**. La app funciona sin ninguna de ellas.

### Supabase (free tier) — sincronización multi-device
Crea un proyecto gratis en [supabase.com](https://supabase.com) y configura `.env` en la raíz:
```bash
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_KEY=tu-service-role-key
```
Sin Supabase, los datos se guardan en localStorage (modo offline).

### AI endpoint — informes y sugerencias
Compatible con cualquier API OpenAI-compatible. Opciones:
- **Ollama local**: `http://localhost:11434/v1/chat/completions` (gratis, sin API key)
- **OpenRouter**: `https://openrouter.ai/api/v1/chat/completions` (multi-modelo)
- **OpenAI/Anthropic/Gemini/DeepSeek/Groq**: ver tabla en [AGENTS.md](AGENTS.md)

Configura el endpoint desde el tab **AI Writeup** o vía localStorage:
```js
localStorage.setItem('mirv_ai_endpoint', 'http://localhost:11434/v1/chat/completions');
localStorage.setItem('mirv_ai_model', 'llama3');
```

### Kali SSH — herramientas CLI
Desde el tab **Terminal**: añade un perfil (IP, puerto 22, usuario, contraseña) y conecta.
En Docker, las credenciales son `root:mirv` en el puerto `2222`.

### Token OSINT (opcional) — rate limiting / auth
```bash
MIRV_OSINT_TOKEN=tu-token-secreto   # protege endpoints OSINT públicos
```
Ver auditoría: [`docs/SECURITY_AUDIT_OSINT_2026-08-15.md`](docs/SECURITY_AUDIT_OSINT_2026-08-15.md).

---

## 📡 API resumen

~345 endpoints agrupados por categoría. **Documentación interactiva (Swagger):**
```
http://localhost:8000/docs      # Swagger UI
http://localhost:8000/redoc     # ReDoc
```

| Categoría | Endpoints | Ejemplo |
|-----------|:---------:|---------|
| WebSocket | 1 | `GET /ws` (proxy SSH) |
| AI | 2 | `POST /api/ai/chat`, `POST /api/suggest` |
| OSINT Recon | 19 | email, dork, DNS/DoH, RDAP, CT (crt.sh), urlscan, HIBP, urlhaus, code_search… |
| EXIF OSINT | 5 | `POST /api/exif/analyze` |
| Canary Tokens | 5 | `POST /api/canary/token` |
| DLP Scanner | 3 | `POST /api/dlp/scan` |
| SIEM | 9 | `POST /api/siem/event`, `GET /api/siem/alerts`, webhook |
| Audit Log | 3 | `GET /api/audit/logs` |
| Plugins | 8 | `GET /api/plugins`, watcher control |
| Coverage | 8 | `POST /api/coverage/mark`, export |
| Skills + Router | 16 | `GET /api/skills`, `POST /api/router/route`, `GET /api/router/routes`, `GET /api/router/tool-index`, `GET /api/router/benchmark` |
| Redaction | 4 | `POST /api/redact`, `GET /api/redact/patterns` |
| Burp Bridge | 14 | `POST /api/burp/ingest`, finding-to-issue |
| Browser Capture | 10 | `POST /api/browser-capture/import` |
| Finding PoC | 7 | `POST /api/poc/build`, `replay` |
| Permissions | 7 | `POST /api/permissions/classify` |
| Intelligence | 11 | watches, snapshots, alerts, diff |
| **Lab Sessions (Pack 11)** | 20 | `POST /api/labs/sessions/{sid}/analyze` (IA sobre historial), `writeup`, `export` html/pdf |
| **Code Agent (Pack 10/12)** | 4 | `GET /api/agents/status`, `POST /api/agents/run` (provider: opencode/claude/codex) + `/api/opencode/*` |
| **Phishing Sim (Pack 10)** | 13 | `POST /api/phishing/campaigns` + landings públicas `/phishing/{cid}` |
| **AI Personas (Pack 17)** | 9 | `GET /api/personas`, `GET /api/personas/{slug}`, `POST /api/personas/{slug}/prompt` |
| Assessments / Assets | 20 | `GET /api/assessments`, `POST /api/assets/ingest` |
| Scheduler | 10 | `GET /api/scheduler/jobs`, daemon `status`, `record` |
| Notifications | 4 | `POST /api/notifications/send`, Telegram/Discord/Slack/webhook |
| Auth (login) | 4 | `GET /api/auth/status`, `POST /api/auth/login` (guard token opt-in) |
| Findings lifecycle | 3 | `PATCH /api/findings/{id}`, filtros por assessment/estado |
| Connections | 3 | `/api/connections` |
| Reports | 5 | `POST /api/report/generate`, PDF |
| Scripts | 3 | `/api/scripts` |
| Findings | 6 | `POST /api/findings/bulk`, stats, export csv/sarif/html |
| Credentials | 4 | `/api/credentials` |
| CTF | 5 | `/api/ctf/challenges`, score |
| Forensics | 3 | `/api/forensics/upload` |
| Mobile | 6 | `/api/mobile/upload`, frida |
| KnowledgeBase | 3 | `/api/knowledgebase/search` |
| Swarm | 10 | `POST /api/swarm/start`, sessions, report |
| Scope / OPSEC | 7 | `POST /api/scope/validate`, `POST /api/opsec/apply` |
| Missions / Plans | 7 | `POST /api/missions/save`, `/api/plans` |
| Secrets | 3 | `/api/credentials/secrets` (Fernet at-rest) |
| Docker / kali-mcp / n8n | 12 | `POST /api/docker/start`, `POST /api/kali-mcp/exec` |
| Health/Settings/Upload | 4 | `/api/health`, `/api/settings`, `/api/upload` |

---

## 🧪 Testing

```bash
cd backend
python -m pytest tests/ -k "not test_slow_hook" -q
# 5164 passed, 2 failed (los 2 = fallos preexistentes por persistencia real de
#                       workspace, pasan con el env limpio / en CI)  ·  1 deselected
```

- **111 archivos de test**, **5184 tests** recolectados (~95% cobertura)
- `main.py` = **100%** de cobertura (statement-level)
- Pack 11 (Lab Sessions + flags + write-up): **89 tests nuevos** — detección de flags user/root (incl. transcripciones SSH y falsos positivos), recomputado al editar/borrar, invalidación de análisis obsoletos, escape XSS del HTML dark-mode, endpoints
- Usa `unittest.mock` + `TestClient(app)` para endpoints; hermético (sin red/DB real)
- CI corre bandit (security) + safety check además de pytest

---

## 🐳 Docker

```bash
docker compose -p proyectociber up -d
# mirv-backend (port 8000) + kali-tools (port 2222)
```

Levanta dos contenedores:
- **`mirv-backend`** — FastAPI + WebSocket + REST API (puerto 8000)
- **`mirv-kali-tools`** — Kali Linux con 50+ herramientas + SecLists + rockyou (SSH `root:mirv` en puerto 2222)

Conexión desde el dashboard: `localhost:2222`, usuario `root`, contraseña `mirv`.

```bash
docker compose -p proyectociber down       # parar
docker compose -p proyectociber up -d      # arrancar (caché)
docker compose -p proyectociber up -d --build  # reconstruir
```

Guía técnica completa: [`DOCKER_GUIDE.md`](DOCKER_GUIDE.md).

---

## 🌐 Production (próximamente)

- **VPS bootstrap**: `deploy/bootstrap-vps.sh`
- **Cloudflare Tunnel**: `deploy/cloudflared/setup-cloudflared.sh`
- Ver [`PRODUCTION_PLAN.md`](PRODUCTION_PLAN.md) para guía completa.

---

## ❓ FAQ

**¿Necesito Kali Linux?**
No para las herramientas OSINT/API (funcionan vía HTTP desde el backend). Sí para el tab **Terminal** y las herramientas CLI (nmap, gobuster, nikto, etc.) que requieren SSH a Kali. En Docker, el contenedor `kali-tools` lo incluye todo.

**¿Necesito Supabase?**
No. Sin Supabase, la app funciona con localStorage (conexiones SSH, scripts, payloads, preferencias). Sí recomendado para sincronización multi-device y persistencia de findings/reportes entre sesiones.

**¿La app es segura para exponer públicamente?**
Sí, con `MIRV_OSINT_TOKEN` + rate limiting + HTTPS (Cloudflare Tunnel). El backend redacta secretos automáticamente en logs/IA/misiones. Ver auditoría: [`docs/SECURITY_AUDIT_OSINT_2026-08-15.md`](docs/SECURITY_AUDIT_OSINT_2026-08-15.md).

**¿Puedo añadir mis propios plugins?**
Sí. Crea un directorio en `backend/plugins/<nombre>/` con `plugin.json` + `plugin.py` implementando los 5 hooks (`on_startup`, `on_shutdown`, `on_tool_result`, `on_finding`, `on_event`). Hot-reload automático. Por defecto `auto_load_new=False` por seguridad — debes cargarlo manualmente desde el tab **Plugins**.

**¿Cómo añado un skill playbook?**
Crea un `SKILL.md` con frontmatter YAML (`name`, `description`, `category`, `allowed_tools`) en `backend/skills/`, `./.mirv/skills/`, o `~/.mirv/skills/`. Hot-reload automático. Hay **112 built-in**, entre ellos: recon, webvuln, ssrf, jwt, supabase, graphql, race, takeover, deserialize, ssti, binary-reverse, ida-reverse, mobile-reverse, patch-diff-exploit, dsl-vm-reverse, edr-bypass-re, attack-chain, supply-chain-security, api-security, llm-security, browser-automation, case-review, docs-generator, diagram-generator y field-journal.

**¿Cómo funciona el Task Router?**
`backend/skills/router/routing.json` define **39 rutas bilingües** (`R0`–`R38`). Cada ruta agrupa bloques de keywords (`must` / `mustAll` / `exclude`); un bloque que acierta suma un hit, gana la ruta con más hits y los empates los resuelve el array `priority`. Sin coincidencias cae al fallback `R0`. El corpus `benchmarks.json` (**99 casos** hint→ruta esperada, en+es) acts como gate de regresión:

```bash
cd backend
python -c "from backend.skill_router import run_benchmarks as r; print(r())"
```

`GET /api/router/benchmark` devuelve lo mismo por HTTP, y `GET /api/router/tool-index` lista las **108 herramientas** detectadas en el host con `which`.

**¿Qué gestor de paquetes usa el frontend?**
Ninguno. El frontend es **vanilla JS sin build step**: un solo `index.html` (~3960 líneas) + `js/main.v2.js` (~14.000 líneas), Tailwind vía CDN. No hay `package.json` ni bundler. Solo el **desktop** (Tauri, `desktop/`) usa npm.

**¿Cómo configuro la IA?**
Cualquier endpoint compatible con OpenAI: Ollama local (gratis), OpenRouter, OpenAI, Anthropic, etc. Configúralo desde el tab **AI Writeup** o vía localStorage (`mirv_ai_endpoint`, `mirv_ai_model`).

---

## 📁 Estructura del proyecto

```
mirv/
├── backend/          # FastAPI + 57 módulos (main.py ~8280 líneas, database.py, opsec.py, ...)
│   ├── plugins/      # Sistema de plugins (hot-reload)
│   ├── skills/       # 112 skill playbooks (Markdown + frontmatter) + router/ (routing.json, benchmarks.json)
│   ├── burp_plugin/  # Plugin Jython para Burp Suite
│   └── tests/        # 111 archivos, 5184 tests (~95% cobertura)
├── frontend/         # SPA vanilla JS + Tailwind CDN (35 tabs)
│   ├── index.html    # SPA principal (~4065 líneas)
│   └── js/           # main.v2.js (~14.000 líneas), dataservice, mobile, forensics, swarm
├── desktop/          # App de escritorio (Tauri v2 + sidecar PyInstaller + updater firmado)
├── deploy/           # VPS bootstrap + Cloudflare Tunnel setup
├── docker/           # Dockerfiles (mirv-backend, kali-tools)
├── docs/             # Auditorías, guías, runbook de verificación manual
├── .github/          # CI/CD workflows (ci.yml, deploy.yml, desktop-build.yml)
├── docker-compose.yml
├── AGENTS.md         # Doc técnica para agentes IA
├── ROADMAP.md        # Roadmap de desarrollo
├── PRODUCTION_PLAN.md
└── README.md         # Este archivo
```

---

## 🖼️ Capturas

![Dashboard overview](docs/screenshots/dashboard.png)
<!-- TODO: añadir captura del dashboard overview (sidebar + tabs) -->

![Terminal tab](docs/screenshots/terminal.png)
<!-- TODO: añadir captura del tab Terminal (SSH shell interactivo) -->

![OSINT Recon tab](docs/screenshots/osint-recon.png)
<!-- TODO: añadir captura del tab OSINT Recon (10 herramientas) -->

![Findings tab](docs/screenshots/findings.png)
<!-- TODO: añadir captura del tab Findings (hallazgos parseados con filtros) -->

---

## 📚 Documentación relacionada

| Archivo | Contenido |
|---------|-----------|
| [`AGENTS.md`](AGENTS.md) | Documentación técnica completa para agentes IA (arquitectura, módulos, API) |
| [`TOMORROW.md`](TOMORROW.md) | Postmortems, siguientes pasos, lecciones aprendidas |
| [`docs/MANUAL_VERIFICATION.md`](docs/MANUAL_VERIFICATION.md) | Runbook de verificación manual E2E (Supabase, Docker, Packs 10/11) |
| [`PRODUCTION_PLAN.md`](PRODUCTION_PLAN.md) | Plan de despliegue en producción (VPS + Cloudflare) |
| [`ROADMAP.md`](ROADMAP.md) | Roadmap de desarrollo por fases |
| [`DOCKER_GUIDE.md`](DOCKER_GUIDE.md) | Guía técnica completa del stack Docker |
| [`docs/SECURITY_AUDIT_OSINT_2026-08-15.md`](docs/SECURITY_AUDIT_OSINT_2026-08-15.md) | Auditoría de seguridad de endpoints OSINT |
| [`PERSISTENCE_AUDIT.md`](PERSISTENCE_AUDIT.md) | Auditoría de persistencia de datos |
| [`MIRV_DESKTOP_PLAN.md`](MIRV_DESKTOP_PLAN.md) | Plan para app desktop con Tauri |

---

## 📄 Licencia y créditos

**Uso educativo y auditorías autorizadas exclusivamente.**

M.I.R.V. está diseñado para:
- Profesionales de ciberseguridad en pruebas de penetración autorizadas
- Estudiantes y educadores en entornos de laboratorio
- Entusiastas de la seguridad en CTFs y máquinas vulnerables (HackTheBox, VulnHub, etc.)

**No está permitido** usar M.I.R.V. contra sistemas sin autorización explícita por escrito.

**Créditos:**
- Desarrollado por [SenorJA](https://github.com/SenorJA)
- Stack: [FastAPI](https://fastapi.tiangolo.com) · [Paramiko](https://www.paramiko.org) · [Supabase](https://supabase.com) · [Tailwind CSS](https://tailwindcss.com)
- Inspirado en centros de operaciones Signal Intelligence
- Task Router y varios playbooks de reversing adaptados de [reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT)

---

<div align="center">

**M.I.R.V. v3.4.0** — 345 endpoints · 5184 tests · ~95% cobertura · 35 tabs · 57 módulos

[Reportar bug](https://github.com/SenorJA/dashboard-ctf/issues) · [Sugerir mejora](https://github.com/SenorJA/dashboard-ctf/issues) · [Documentación técnica](AGENTS.md)

</div>
