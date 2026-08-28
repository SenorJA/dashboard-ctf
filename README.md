# 🛡️ M.I.R.V. — Multi-platform Incident Response & Vulnerabilities

<div align="center">

**Panel táctico de ciberseguridad** • SSH Proxy Web • OSINT • Forense • Mobile • Automatización Multi-Agente

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-latest-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Endpoints](https://img.shields.io/badge/endpoints-238-9cf)](#-api-resumen)
[![Tests](https://img.shields.io/badge/tests-4164_✔️-2ea44f?logo=pytest)](#-testing)
[![Coverage](https://img.shields.io/badge/coverage-~97%25-2ea44f)](#-testing)
[![Tabs](https://img.shields.io/badge/frontend%20tabs-26-9cf)](#-features-principales)
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
- **238 endpoints REST** contra Supabase (PostgreSQL)
- **33 módulos backend** con ~97% de cobertura de tests
- **26 tabs frontend** en una SPA vanilla JS + Tailwind
- **IA multi-proveedor** para informes, sugerencias y chat
- **Análisis forense** (memoria, disco, archivos) y **móvil** (APK estático + dinámico con Frida)
- **Swarm multi-operador**, **CTF mode**, **OPSEC Levels**, **Self-Improvement Loop**

> **Versión:** v3.0

---

## 🏗️ Arquitectura

```
┌──────────────┐   WebSocket   ┌──────────────┐    Paramiko    ┌──────────────┐
│   Navegador  │ ────────────► │   FastAPI    │ ─────────────► │  Kali Linux  │
│  (SPA + JS)  │ ◄──────────── │  (main.py)   │ ◄───────────── │  (50+ tools) │
└──────┬───────┘               └──────┬───────┘                └──────────────┘
       │                              │
       │  fetch() /api/* (238)        │  CRUD
       ▼                              ▼
┌──────────────────────────────────────────┐
│              Supabase (PostgreSQL)        │
│              17 tablas + Storage          │
└──────────────────────────────────────────┘
```

**Flujo de datos:**
1. **Frontend SPA** (HTML + vanilla JS + Tailwind CDN) — sin bundler, sin build step.
2. **WebSocket** (`/ws`) proxy SSH bidireccional: navegador ↔ FastAPI ↔ Kali (Paramiko).
3. **API REST** (`/api/*`) 238 endpoints para operaciones CRUD y análisis.
4. **Supabase** (PostgreSQL) con 17 tablas + Storage bucket para archivos.
5. **Módulos del backend** (33 archivos) operan vía SSH sobre Kali o vía HTTP directo.

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

26 tabs agrupados por categoría:

### Core
| Tab | Descripción |
|-----|-------------|
| **Terminal** | Shell SSH interactivo vía WebSocket con PTY, tab-completion, historial y upload. |
| **Reports** | Reportes de escaneo guardados con export a `.md`, `.html`, `.txt` y PDF. |
| **Scripts** | Builder de scripts RCE con deploy a `/tmp/` vía SSH. |
| **Findings** | Hallazgos parseados automáticamente de 10+ herramientas, con filtros por severidad. |
| **AI Writeup** | Generación de informes CTF completos en Markdown con IA multi-proveedor. |
| **Bounty** | Generador de reportes de bug bounty con plantillas por plataforma. |
| **Op Admiral** | Planificador de misiones asistido por IA con persistencia de planes. |

### OSINT
| Tab | Descripción |
|-----|-------------|
| **OSINT Recon** | 10 herramientas OSINT (TheHarvester, Mr.Holmes, Infoooze, BBOT, SpiderFoot, etc.) + 8 enlaces web. |
| **EXIF OSINT** | Extracción de metadatos EXIF + GPS + reverse geocoding + mapa Leaflet. |
| **Canary Tokens** | Generador de 8 tipos de honeytokens con tracking de activación. |
| **DLP Scanner** | Detección de PII/secretos (8 patrones + validación Luhn) en texto, archivo o URL. |

### Security
| Tab | Descripción |
|-----|-------------|
| **SIEM** | Motor de eventos con 4 reglas de correlación y alertas en tiempo real. |
| **Audit Log** | Log estructurado JSONL con rotación 4MB y redacción automática de secretos. |
| **Coverage** | Matriz de cobertura endpoint×parámetro×clase de vulnerabilidad + próximos pasos. |
| **Plugins** | Sistema de plugins con hot-reload (watchdog) y 5 hooks. |
| **Skills** | Playbooks de habilidades en Markdown con frontmatter YAML. |
| **Intelligence** | Monitorización continua de targets (headers, cert, DNS, puertos, tech stack). |

### Mobile / Forensics
| Tab | Descripción |
|-----|-------------|
| **Mobile** | Laboratorio APK: análisis estático (apktool, jadx, mobsf) + dinámico (ADB + Frida). |
| **Forensics** | Forense de memoria (Volatility), disco (Sleuth Kit) y archivos (strings, binwalk). |
| **CTF** | Challenges con categorías, dificultad, puntos, hints y tracking de flags. |
| **KnowledgeBase** | 80+ CVEs críticos + técnicas MITRE ATT&CK con búsqueda. |

### Infra
| Tab | Descripción |
|-----|-------------|
| **Docker** | Control del stack Docker desde el dashboard (start/stop/clean/build + polling). |
| **Swarm** | Pipeline multi-operador (Recon → Scanner → Exploiter → Report) con visualización. |
| **Automation** | Integración con n8n para disparar workflows desde findings. |
| **Browser Capture** | Import de HAR + 10 checks de seguridad + scoring de riesgo. |
| **Burp Bridge** | Ingest bidireccional MIRV ↔ Burp Suite (plugin Jython incluido). |
| **Credentials** | Store de credenciales descubiertas con categorización (SSH, HTTP, DB, API). |

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

238 endpoints agrupados por categoría. **Documentación interactiva (Swagger):**
```
http://localhost:8000/docs      # Swagger UI
http://localhost:8000/redoc     # ReDoc
```

| Categoría | Endpoints | Ejemplo |
|-----------|:---------:|---------|
| WebSocket | 1 | `GET /ws` (proxy SSH) |
| AI | 2 | `POST /api/ai/chat`, `POST /api/suggest` |
| OSINT | 10 | Headers/Secrets/Port/Subdomain/DNS/Hash/Stego/News/API scanners |
| EXIF OSINT | 5 | `POST /api/exif/analyze` |
| Canary Tokens | 5 | `POST /api/canary/token` |
| DLP Scanner | 3 | `POST /api/dlp/scan` |
| SIEM | 8 | `POST /api/siem/event`, `GET /api/siem/alerts` |
| Audit Log | 3 | `GET /api/audit/logs` |
| Plugins | 8 | `GET /api/plugins`, watcher control |
| Coverage | 8 | `POST /api/coverage/mark`, export |
| Skills | 7 | `GET /api/skills`, render markdown |
| Redaction | 4 | `POST /api/redact`, `GET /api/redact/patterns` |
| Burp Bridge | 14 | `POST /api/burp/ingest`, finding-to-issue |
| Browser Capture | 10 | `POST /api/browser-capture/import` |
| Finding PoC | 7 | `POST /api/poc/build`, `replay` |
| Permissions | 7 | `POST /api/permissions/classify` |
| Intelligence | 11 | watches, snapshots, alerts, diff |
| Connections | 3 | `/api/connections` |
| Reports | 5 | `POST /api/report/generate`, PDF |
| Scripts | 3 | `/api/scripts` |
| Findings | 6 | `POST /api/findings/bulk`, stats |
| Credentials | 4 | `/api/credentials` |
| CTF | 5 | `/api/ctf/challenges`, score |
| Forensics | 3 | `/api/forensics/upload` |
| Mobile | 6 | `/api/mobile/upload`, frida |
| KnowledgeBase | 3 | `/api/knowledgebase/search` |
| Swarm | 6 | `POST /api/swarm/start`, report |
| Swarm Sessions | 4 | `/api/swarm/sessions` |
| Scope | 5 | `POST /api/scope/validate` |
| OPSEC | 2 | `/api/opsec/apply` |
| Missions | 4 | `/api/missions/save` |
| Mission Plans | 3 | `/api/plans` |
| Secrets | 3 | `/api/credentials/secrets` |
| Docker | 6 | `POST /api/docker/start` |
| kali-mcp | 3 | `/api/kali-mcp/exec` |
| Health/Settings/Upload/n8n | 7 | `/api/health`, `/api/upload` |

---

## 🧪 Testing

```bash
cd backend
python -m pytest tests/ -q --timeout=60 -m "not slow" -k "not test_slow_hook"
# 4086 passed, 78 deselected
```

- **76 archivos de test**, **4164 tests** (~97% cobertura)
- `main.py` = **100%** de cobertura (2847/2847 statements)
- Usa `unittest.mock` + `TestClient(app)` para endpoints
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
Crea un `SKILL.md` con frontmatter YAML (`name`, `description`, `category`, `allowed_tools`) en `backend/skills/`, `./.mirv/skills/`, o `~/.mirv/skills/`. Hot-reload automático. Ver skills built-in: recon, webvuln, ssrf, jwt, supabase, graphql, race, takeover, deserialize, ssti.

**¿Qué gestor de paquetes usa el frontend?**
**pnpm** (obligatorio, `.npmrc` bloquea npm). Actívalo con `corepack enable`. Los tests E2E usan Playwright.

**¿Cómo configuro la IA?**
Cualquier endpoint compatible con OpenAI: Ollama local (gratis), OpenRouter, OpenAI, Anthropic, etc. Configúralo desde el tab **AI Writeup** o vía localStorage (`mirv_ai_endpoint`, `mirv_ai_model`).

---

## 📁 Estructura del proyecto

```
mirv/
├── backend/          # FastAPI + 33 módulos (main.py, database.py, opsec.py, ...)
│   ├── plugins/      # Sistema de plugins (hot-reload)
│   ├── skills/       # Skill playbooks (Markdown + frontmatter)
│   ├── burp_plugin/  # Plugin Jython para Burp Suite
│   └── tests/        # 76 archivos, 4164 tests (~97% cobertura)
├── frontend/         # SPA vanilla JS + Tailwind CDN (26 tabs)
│   ├── index.html    # SPA principal (~2694 líneas)
│   └── js/           # main.v2.js (~8700 líneas), dataservice, mobile, forensics, swarm
├── deploy/           # VPS bootstrap + Cloudflare Tunnel setup
├── docker/           # Dockerfiles (mirv-backend, kali-tools)
├── docs/             # Auditorías, guías, status
├── .github/          # CI/CD workflows (ci.yml, deploy.yml)
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

---

<div align="center">

**M.I.R.V. v3.0** — 238 endpoints · 4164 tests · ~97% cobertura · 26 tabs

[Reportar bug](https://github.com/SenorJA/dashboard-ctf/issues) · [Sugerir mejora](https://github.com/SenorJA/dashboard-ctf/issues) · [Documentación técnica](AGENTS.md)

</div>
