# M.I.R.V. — Estado del Proyecto (snapshot)

> Última actualización: 13 Oct 2026 — MIRV **v3.5.0** | 61 módulos | **377 endpoints** (369 `/api/*` + 8 landings) | **5394 tests** | 38 tabs | 113 skills · 41 rutas · `main.py` 100%

> **Fuente de verdad viva:** [`AGENTS.md`](../AGENTS.md) (arquitectura, módulos, API, convenciones) y [`TOMORROW.md`](../TOMORROW.md) (bitácora + pendientes). Este documento es un **resumen puntual**; si hay divergencia, mandan esos dos.

## Resumen General

| Área | Estado | Notas |
|------|--------|-------|
| Backend | ✅ `main.py` 8921 L + 61 módulos | FastAPI + Supabase, 369 endpoints `/api/*` |
| Frontend (SPA) | ✅ 1 HTML + `main.v2.js` + `style.css` | Vanilla JS + Tailwind CDN, 38 tabs |
| SSH Proxy WebSocket | ✅ | `invoke_shell()` async + PTY + sudo automático |
| Supabase | ✅ | 18 tablas, offline-first con fallback en memoria |
| Docker | ✅ | `mirv-backend` (:8000) + `kali-tools` (:2222) |
| CI/CD | ✅ | CI + Deploy + Desktop Build (GitHub Actions) |
| Desktop | ✅ v3.5.0 | Tauri + sidecar PyInstaller + updater firmado (minisign) |
| Tests | ✅ 5394 | ~95% cobertura; `main.py` 100% |

## Módulos backend (61 + `main.py`)

Agrupados (detalle completo y tests por módulo en `AGENTS.md`):

- **Core de seguridad:** `scope_guard`, `opsec`, `redact`, `audit_log`, `secret_store`
- **Inteligencia / monitoreo:** `siem`, `intelligence`, `exif_osint`, `canary_tokens`, `system_monitor`, `pc_analyzer`
- **Testing / análisis:** `dlp_scanner`, `burp_bridge`, `finding_poc`, `coverage_matrix`, `browser_capture`, `pdf_engine`, `llm_scanner`, `flag_detection`
- **OSINT:** `osint_recon` (19 tools keyless), `osint_correlate`, `instagram_osint`, `subdomain_scanner`, `dns_lookup`, `secrets_scanner`, `headers_scanner`, `port_scanner`, `hash_cracker`, `stego_tool`, `news_scraper`, `api_scanner`
- **Plugins / skills / agentes:** `plugin_manager`, `skill_playbooks`, `skill_router`, `agency_agents`, `orchestrator`, `episodic_memory`, `mcp_server`, `opencode_agent`, `agent_bridge`
- **Operaciones:** `swarm`, `mobile_analyzer`, `forensics`, `adb_controller`, `knowledgebase`, `mission_store`, `assessments`, `scheduler`, `assets`, `workspace_store`, `lab_sessions`, `lab_writeup`, `phishing_sim`
- **Host-only (Kali físico):** `wireless_analyzer`, `privacy` (proxy), `vpn` (WireGuard/OpenVPN), `kali_mcp_client`
- **Infra:** `database`, `api_auth`, `notifications`, `rate_limiter`

## Frontend (38 tabs)

SPA de un solo `index.html` (~4300 L) + `main.v2.js` (~15.2k L) + `style.css` (~1.2k L). Tema *Signal Intelligence* + monochrome. i18n en/es con `data-i18n`.

Tabs: Home, Terminal, Reports, Scripts, Bounty, AI Writeup, Findings, Op Admiral, Automation, Swarm, Credentials, KnowledgeBase, CTF, Mobile, Forensics, Payload Studio (Hak5), EXIF OSINT, Canary Tokens, DLP, SIEM, Plugins, Coverage, Burp Bridge, Audit Log, Skills (+ Task Router), Intelligence, Browser Capture, Sys Monitor, PC Analyzer, Assessments, Scheduler, Code Agent, Phishing Sim, Lab Sessions, AI Personas, LLM Security, Privacy, VPN.

## Tests (pytest)

- **5394 tests** (5393 passed, 1 deselected — `test_slow_hook`, 35 s, excluido de CI adrede).
- Comando: `cd backend && python -m pytest tests/ -k "not test_slow_hook" -q`
- Cobertura ~95% global; `main.py` 100% vía `test_main_gaps.py` + `test_main_websocket_gaps.py`.

## CI/CD (GitHub Actions)

| Workflow | Descripción |
|----------|-------------|
| `ci.yml` | ruff (lint) + pytest + cobertura + bandit |
| `deploy.yml` | Docker build → Docker Hub → SSH deploy a VPS (salta si faltan secrets) |
| `desktop-build.yml` | sidecar PyInstaller + MSI Tauri firmado |

Secrets pendientes de setear por el usuario: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` (el resto ya configurado).

## Pendiente

Todo el trabajo de **código/datos** está cerrado. Lo que queda son **acciones manuales del usuario** (VPS/dominio, backups de claves, pruebas de instalación) y el **mantenimiento recurrente del vhdx Docker**. Lista detallada en `TOMORROW.md` § *Pendiente actual — acciones manuales del usuario*.

## Gestor de paquetes (frontend)

`pnpm` (`.npmrc` bloquea npm/npx). `corepack enable` para activarlo.

---

*Reescrito el 13 Oct 2026 para alinear con el estado real (antes decía v5.0 / 30 módulos / 227 endpoints / 25 tabs, de Ago 2026).*
