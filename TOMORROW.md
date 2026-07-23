# 🔮 TOMORROW.md — Roadmap de trabajo pendiente

> Última actualización: 24 Jul 2026 — MIRV v3.0+ con 27 módulos, 153+ endpoints, 1504+ tests

---

## ✅ Completado (hasta ahora)

### Módulos nuevos (esta sesión)
1. **EXIF OSINT** — extracción GPS + cámara + reverse geocoding + Leaflet map (21 tests)
2. **Canary Tokens** — 8 tipos de honeytokens + activación tracking (24 tests, 99% coverage)
3. **DLP Scanner** — 8 patrones PII + Luhn + risk score (25 tests)
4. **SIEM Dashboard** — 4 reglas correlación + event feed + alerts panel (31 tests, 84%)
5. **Plugin System** — hooks Python + hot-reload watchdog (47+18 tests, 88%)
6. **Coverage Tracking** — matriz (endpoint×param×vuln_class) + next_steps (33 tests)
7. **Skill Playbooks** — 5 playbooks MD (recon, webvuln, ssrf, jwt, supabase) (67 tests)
8. **Global Redaction** — 20 patrones + integración AI/mission/audit (63 tests)
9. **Burp Bridge** — ingest server + Jython plugin + finding↔issue (72 tests)
10. **Structured Audit Log** — JSONL + rotación 4MB + SIEM forwarding (45 tests)
11. **Plugin Hot-Reload** — fs.watch + debounce 250ms + auto-start (18 tests)

### Infraestructura
- **CI/CD GitHub Actions** — `ci.yml` (tests+coverage+bandit) + `deploy.yml` (Docker→VPS)
- **`.github/SECRETS.md`** — guía de configuración de secrets
- **Tests masivos** — 9 archivos nuevos de test, 1116→1504 tests, ~72% coverage
- **AGENTS.md actualizado** — documenta los 27 módulos + 153 endpoints

### Commits de la sesión
- `396f025` EXIF OSINT
- `cdd2910` Canary Tokens
- `afd22b0` DLP Scanner
- `00821d5` SIEM Dashboard
- `ceaad4d` Plugin System
- `eeee8e6` Coverage >70%
- `e608cde` CI/CD workflows
- `b35a806` Coverage + Skills + Redaction (3 módulos PentesterFlow)
- `cfc1236` Burp Bridge + Audit Log + Plugin Watcher

---

## 📋 Pendiente para mañana

### Prioridad ALTA

#### 1. 🔴 Docker rebuild + smoke test
```bash
docker compose -p proyectociber build --no-cache mirv-backend
docker compose -p proyectociber up -d
# Verificar: http://localhost:8000 funciona
# Verificar: las 6 pestañas nuevas cargan (EXIF, Canary, DLP, SIEM, Plugins, Coverage)
# Verificar: tests de integración con Docker funcionan
```
**Por qué**: Hemos añadido 11 módulos nuevos + 21 endpoints desde el último build. Hay que verificar que todo funciona dentro del contenedor (Pillow para EXIF, watchdog para plugins, etc.).

#### 2. 🔴 Configurar secrets GitHub (manual, web UI)
Ir a https://github.com/SenorJA/dashboard-ctf/settings/secrets/actions y añadir:
- **Variables** (tab Variables): `DOCKERHUB_USERNAME` = tu usuario Docker Hub
- **Secrets** (tab Secrets):
  - `DOCKERHUB_TOKEN` — Docker Hub → Account Settings → Security → New Access Token
  - `VPS_HOST` — IP o dominio del VPS
  - `VPS_USER` — usuario SSH
  - `VPS_SSH_KEY` — clave PRIVADA completa (incluyendo `-----BEGIN/END-----`)
  - `VPS_PORT` — opcional (default 22)
  - `VPS_DEPLOY_PATH` — opcional (default `/opt/mirv`)

**Sin estos secrets, CI funciona pero Deploy salta silenciosamente** (tests pasan, Docker build salta).

#### 3. 🔴 Verificar CI en GitHub
Tras configurar secrets, hacer un push dummy para disparar CI:
```bash
git commit --allow-empty -m "ci: trigger workflow check" && git push
# Ir a https://github.com/SenorJA/dashboard-ctf/actions
# Verificar que ci.yml pasa (tests + bandit)
# Verificar que deploy.yml corre (Docker build + push + SSH deploy)
```

---

### Prioridad MEDIA

#### 4. 🟡 Browser Capture MCP (inspirado en PentesterFlow)
- **Qué**: Capturar tráfico del navegador del pentester (como `browser_capture_*` tools + `pentesterflow-browser-mcp`).
- **Archivos**: `backend/browser_capture.py` + endpoints `/api/capture/*` + plugin Chrome/Firefox.
- **Valor**: Permite al pentester capturar requests del navegador y meterlos en MIRV findings sin Burp.
- **Esfuerzo**: ALTO (necesita browser extension + server ingest + store).

#### 5. 🟡 Session Compaction (inspirado en PentesterFlow)
- **Qué**: Resumir sesiones largas en `SessionMemory` (objectives, findings, credentials, todos) cuando crecen.
- **Archivos**: modificar `backend/mission_store.py` — añadir `compact_session(session_id)`.
- **Valor**: Evita que el contexto AI crezca sin límite. Permite sesiones largas sin perder calidad.
- **Esfuerzo**: MEDIO.

#### 6. 🟡 Continuous Intelligence (project + personal scopes)
- **Qué**: `scenarios.jsonl` con triggers, tecnologías detectadas, confidence 0-1. Distingue scope proyecto vs personal.
- **Archivos**: `backend/intelligence.py` + integración en `mission_store.py`.
- **Valor**: Mejora el self-improvement loop — el sistema "recuerda" lecciones entre sesiones.
- **Esfuerzo**: MEDIO.

---

### Prioridad BAJA

#### 7. 🟢 Permission prompts human-in-the-loop
- **Qué**: Confirmación interactiva antes de tools peligrosos (rm -rf, masscan, sqlmap).
- **Archivos**: modificar `backend/scope_guard.py` + frontend modal.
- **Valor**: MIRV ya tiene `scope_guard` Block mode — esto añade confirmación interactiva.
- **Esfuerzo**: BAJO.

#### 8. 🟢 Más skill playbooks
- **Qué**: Crear playbooks para `graphql`, `race`, `takeover`, `deserialize`, `ssti` (como PentesterFlow).
- **Archivos**: agregar `backend/skills/{graphql,race,takeover,deserialize,ssti}/SKILL.md`.
- **Valor**: Cobertura metodológica más completa.
- **Esfuerzo**: BAJO (solo escribir Markdown, sin código).

#### 9. 🟢 Frontend tabs para Burp + Audit + Skills
- **Qué**: Hemos creado los backends de Burp Bridge, Audit Log, Skills y Plugin Watcher pero NO tienen pestañas frontend.
- **Archivos**: añadir 2-3 pestañas nuevas en `frontend/index.html` + `main.v2.js`.
- **Valor**: UX — el usuario puede ver Burp requests capturados, audit logs, y skills desde el dashboard.
- **Esfuerzo**: MEDIO.

#### 10. 🟢 Findings reproducibles (ampliar schema)
- **Qué**: Añadir campos `method`, `curl`, `request_raw`, `response_excerpt` a findings para re-ejecutar PoCs.
- **Archivos**: modificar `backend/database.py` findings schema + frontend.
- **Valor**: Permite re-ejecutar el PoC desde MIRV con un click.
- **Esfuerzo**: BAJO.

---

## 🎯 Orden recomendado para mañana

1. **Docker rebuild + smoke test** (30 min) — verificar que TODO funciona en contenedor
2. **Configurar secrets GitHub** (15 min) — habilitar deploy automático
3. **Frontend tabs para Burp + Audit + Skills** (2-3 horas) — cerrar el gap UX de los 3 backends sin UI
4. **Más skill playbooks** (1 hora) — graphql, race, takeover, deserialize, ssti
5. **Session Compaction** (1-2 horas) — si sobra tiempo

---

## 📊 Estado actual del proyecto

| Métrica | Valor |
|---------|-------|
| Backend modules | 27 (main.py + 21 especializados + 5 plugin/skill dirs) |
| REST endpoints | 153+ |
| Test files | 25 |
| Tests passing | 1504+ |
| Coverage | ~72% |
| Frontend tabs | 21 |
| GitHub Actions | 2 workflows (CI + Deploy) |
| Docker images | 2 (mirv-backend + kali-tools) |
| Commits esta sesión | 9 |

---

## 🐛 Bugs conocidos / TODOs técnicos

1. **`test_slow_hook` excluido de CI** — tarda 35s, se skip con `-k "not test_slow_hook"`.
2. **Plugin watcher tests con timers** — algunos tests tardan 250ms+ por debounce; considerar `pytest-timeout`.
3. **Module identity split** — algunos tests necesitaban importar `backend.modulo` vs `modulo` (revisar conftest.py).
4. **`exif_osint.py` coverage 63%** — muchos code paths requieren imágenes reales o red.
5. **`dlp_scanner.py` coverage 67%** — patrones de archivo/URL necesitan más tests.
6. **`main.py` coverage 53%** — 832 statements sin cubrir (endpoints WS, startup code, middleware).

---

*Documento generado al final de la sesión del 24 Jul 2026. Ver `AGENTS.md` para arquitectura completa actualizada.*