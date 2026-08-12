# 🔮 TOMORROW.md — Roadmap de trabajo pendiente

> Última actualización: 11 Ago 2026 — MIRV v5.0 | 30 módulos | 227 endpoints | 3834 tests | 25 tabs | main.py 100%
> ✅ Hotfix CI #47/#48 (recursión `AuditLogHandler` en `tests/test_audit_log.py`) aplicado y verificado — ver § Postmortem al final.

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
- [x] ~~**Configurar secrets GitHub**~~ — DOCKERHUB_USERNAME + DOCKERHUB_TOKEN añadidos (9 Ago 2026); VPS pendiente
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
3. ~~**Module identity split** — tests importan `backend.modulo` vs `modulo`~~ — ✅ **RESUELTO AGO 2026**: unificados los 30+ tests a `from backend.X import …` + conftest aliasa `sys.modules["X"] = backend.X` para mantener compat con los ~216 `@patch("X.attr")` strings legacy. Ver § Postmortem Module-Identity al final.
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

---

## 🩺 Postmortem — CI runs #47/#48: recursión infinita en `AuditLogHandler`

> Fecha: 11 Ago 2026 — Hotfix aplicado y verificado (3908/3909 tests verdes; el único `F` restante es un test de DNS con bug de IPv6 unrelated).

### Síntomas
- CI rojo: ~12 tests `F` en `tests/test_audit_log.py` + 1 test colgado (`test_siem_forward_failure_is_swallowed`) matado por `pytest-timeout` a 60 s.
- El traceback interrumpido por el timeout mostraba pila recursiva:
  `AuditLogHandler.emit()` → `audit()` → `siem.ingest_event(boom)` → `logger.warning("SIEM forward failed")` → `vulnforge` handlers → `AuditLogHandler.emit()` → …
- Reproducción local fiel: `pytest tests/test_api_endpoints.py tests/test_audit_log.py` colgaba con `threading.wait()` bloqueado en el event loop del `TestClient`.

### Causa raíz (triple)

1. **Doble import de módulo (la verdadera causa)**
   - `tests/test_audit_log.py:39` importaba `from audit_log import (...)` (módulo top-level `audit_log`),
     mientras que **todo el backend** importa `from backend.audit_log import …` (módulo `backend.audit_log`).
   - Con `working-directory: backend` + `testpaths = tests`, ambos resolves apuntan al **mismo archivo `audit_log.py`** pero los mapean a **dos módulos Python distintos** con estado global y clases `AuditLogHandler` **independientes**.
   - Consecuencia: los handlers que `main.py` (startup) añadía a `vulnforge` eran instancias de `backend.audit_log.AuditLogHandler`, pero el fixture limpiaba con `isinstance(h, AuditLogHandler)` **de la otra clase** → `isinstance` devolvía `False` → **los handlers no se limpiaban nunca**.

2. **Acumulación de handlers sin idempotencia**
   - `main.py:2293` (en cada `@app.on_event("startup")`) ejecutaba `logger.addHandler(AuditLogHandler(category="system"))` **sin verificar si ya existía uno**.
   - Cada `TestClient` corre startup → añade un handler más a `vulnforge`. En CI, `test_api_endpoints.py` corre primero con ~333 `TestClient`s → cientos de handlers duplicados en `vulnforge` cuando arranca `test_audit_log.py`.

3. **Guard de reentrada per-instancia**
   - `audit_log.py` (commit `72c5db3`) intentó cortar la recursión con `self._local` (per-instancia, `threading.local`).
   - Eso corta la recursión de **un** handler consigo mismo, pero NO la de **N handlers duplicados**, porque cada uno lleva su propio `_local` y entra independientemente.
   - Resultado con N handlers: 1 warning → N emits → cada uno llama `audit()` → N warnings → N² emits → … explosión exponencial → recursión infinita → timeout.

### Fixes aplicados

| # | Archivo | Cambio | Tipo |
|---|---------|--------|------|
| 1 | `tests/test_audit_log.py` | Unificar imports a `backend.*` (`from backend.audit_log import …`, `import backend.audit_log as al_mod`, `from backend import siem`) + ampliar `vulnforge.audit` en el cleanup del fixture | **Causa raíz** |
| 2 | `audit_log.py` | Guard de reentrada **global** (`_emit_guard = threading.local()` a nivel de módulo) compartido por todas las instancias; reset en `_reset_state_for_tests()` | Defensa en profundidad |
| 3 | `audit_log.py` | Logger interno `_internal_warn_logger` con `propagate=False` + `NullHandler` para los warnings de rotación/SIEM-failure → ya no pueden re-entrar por el ancestro `vulnforge` | Defensa en profundidad |
| 4 | `main.py:2293` | Sustituir `logger.addHandler(AuditLogHandler(...))` por `al_logger("vulnforge", "system")` (ya idempotente por dentro) → nunca acumula handlers duplicados | Causa raíz #2 |

### Por qué las capas son complementarias
- Fix 1 + Fix 4 eliminan las causas que permiten que haya handlers duplicados en `vulnforge`.
- Fix 2 corta la recursión **al primer nivel** aunque en el futuro aparezcan duplicados por cualquier otra vía (p.ej. plugins, imports laterales). Es una red de seguridad.
- Fix 3 evita que los warnings del propio pipeline de audit vuelvan a entrar, **independientemente** del guard, porque no propagan a `vulnforge`. Garantiza que los handlers de root/consola nunca vuelvan a disparar `audit()`.

### Verificación
| Suite | Antes | Después |
|---|---|---|
| `test_api_endpoints.py + test_audit_log.py` (escenario CI exacto) | 🟥 TIMEOUT 60 s (colgado) | ✅ 378 passed, 87.72 s |
| `test_audit_log.py + gaps + test_siem + test_siem_gaps2` | 🟥 12 F + cuelgue | ✅ 109 passed, 1.68 s |
| `test_main_gaps.py + test_main_extra.py` | — | ✅ 415 passed, 13.90 s |
| **Suite completa CI** (`tests/ -k "not test_slow_hook"`) | 🟥 timeout rojo | ✅ **3908 passed**, 1 unrelated IPv6 fail, 397 s |

### Lecciones para el repo
1. **Convención de imports**: los tests deben importar SIEMPRE con el prefijo del paquete (`from backend.X import …`), igual que el código de aplicación. Mezclar `from audit_log …` con `from backend.audit_log …` crea dos módulos Python distintos para el mismo archivo → estados paralelos, clases incompatibles, fixtures que no limpian lo que deben. **Añadido como regla de estilo en AGENTS.md** (ver línea de tests).
2. **Re-entrada en logging**: cualquier `logging.Handler` que mute estado global o llame a una función que loguea a su vez necesita un guard de reentrada **compartido** (no per-instancia), y los warnings internos deben ir a un logger con `propagate=False` + `NullHandler` para no tocar la cadena principal.
3. **Idempotencia en startups**: añadir handlers/listeners en `on_event("startup")` SIEMPRE debe comprobar `any(isinstance(h, MiHandler) for h in log.handlers)` antes de `addHandler`.
4. **Reproducción de bugs de CI localmente**: cuando un test cuelga en CI pero no en local aislado, simular el **orden de archivos** completo (los que corren antes pueden mutar estado global persistente como loggers a través de `TestClient` startups).

### Estado CI esperado en próximo push
- ✅ Verde: `test_audit_log.py` suite completa, escenario `test_api_endpoints + test_audit_log`, y `tests/` completo.
- ⚠️ El único `F` residual (`test_subdomain_scanner.py::test_scan_example_com`) es un bug unrelated: el test asume que `example.com` sólo responde IPv4, pero Cloudflare sirve AAAA records (`2606:4700:10::ac42:93f3`) y el assert `len(octets) == 4` falla con IPv6. Se arreglará por separado extendiendo el parser a `ipaddress`/IPv6.

---

## 🩺 Postmortem — Module-identity split (bug #3 de TODOs, resuelto AGO 2026)

> Fecha: 11 Ago 2026 — Fixeado y verificado (3909/3910 tests verdes).

### Síntomas
- 30+ archivos de tests importaban sus módulos backend con el patrón **bare** `from X import …` (top-level) en lugar de `from backend.X import …`. Mismo archivo `.py`, **dos módulos Python distintos** con estado global y clases `incompatibles`.
- Síntoma descubiertos Tras audit_log fix #47/#48: identificación de que `from patch("X.attr")` strings + `from X import Y` style crearon dobles módulos.

### Causa raíz
- `pytest` arranca con `cd backend/` + `sys.path.insert(0, "..")` → `backend/` está en sys.path.
- `from X import Y` crea módulo top-level `"X"` apuntando a `backend/X.py`.
- `main.py` hace `from backend.X import …`  y crea módulo `"backend.X"` apuntando al mismo archivo.
- Python los trata como **dos módulos distintos** → estados paralelos, `isinstance` roto, y `@patch("X.attr")` parchea el módulo equivocado (production code usa `backend.X.attr` y no ve el patch).

### Fixes aplicados (defensa en profundidad)

1. **30+ test files — unificación de imports**:
   - `from X import …` → `from backend.X import …`
   - `import X as alias` → `import backend.X as alias`
   - En archivos que referencian `X.Y` como Python name (e.g. `@patch.object(X, …)` o `monkeypatch.setattr(X, …)`), se mantuvo el alias explícito: `import backend.X as X`

2. **`conftest.py` — aliasing de `sys.modules`** (red de seguridad):
   - Para los ~216 strings `@patch("X.attr")` legacy que ya están escritos, aliasa `sys.modules["X"] = backend.X` al arrancar los tests. Así `mock.patch("X.attr")` resuelve al módulo **compartido** y el patch afecta el código de production path.
   - Es la red que previene futuras regressiones: si alguien añade un test con `from X import Y` legacy, sigue funcionando.
   - Lista de 36 módulos `backend.*` aliasados al inicio.

### Verificación
| Suite | Resultado |
|---|---|
| Suite completa (`tests/ -k "not test_slow_hook"`) tras fixes | ✅ **3909 passed**, 0 failed, 409.92 s |
| test_adb_controller + hash_cracker + dns_lookup + stego + port_scanner | ✅ 160 passed |
| test_mission_store* + compaction + forensics + swarm | ✅ 265 passed |

### Lecciones (reforzadas)
- La regla de style import-prefix en tests (añadida tras audit_log fix) es **obligatoria**; el aliasing en conftest es **defensa secundaria**.
- Antes de cambiar imports masivamente, hay que revisar los `@patch("X.attr")` strings también: cambian significado si el namespace top-level desaparece. El aliasing en conftest lo cubre.
- Aislar un bug puede requerir **correr tests individualmente** vs **en grupo** para detectar fallos por estado compartido.

### Estado CI esperado en próximo push
- ⚠️ **NO green al 100% todavía**: el hotfix del `watchdog_gaps` teardown **desbloqueó** el resto de la suite (antes el `tail -10` del step diagnostic solo mostraba los primeros 11 fallos de watchdog_gaps). El fix los eliminó y ahora se ven **otros ~11 fallos pre-existentes** que siempre estuvieron ahí pero ocultos tras el cap. **No son regresiones introducidas por estos fixes** — son bugs de tests que asumen entorno inexistente en CI.

---

## 🩺 Postmortem — Failures "desenmascarados" por el fix del watchdog_gaps (post-525ea54)

> Fecha: 11 Ago 2026 — Tras corregir los 11 `test_plugin_manager_watchdog_gaps.py` (teardown erroneo `assert HAS_WATCHDOG is False`), CI Linux corre la suite completa y ahora se ven ~11 fallos pre-existentes en OTROS archivos.

### Por qué no se veían antes
- El step "Show failure summary" de `ci.yml` emite como máximo 10 annotations vía `grep ... | tail -10 | sed 's/^/::error::/'` (línea 67).
- Antes de 525ea54, las primeras 10 líneas de `FAILED` eran TODAS de `test_plugin_manager_watchdog_gaps.py` (alfabéticamente anterior a `test_plugin_watcher.py`, `test_main_coverage.py`, `test_crud_endpoints.py`, etc.), así que el resto nunca aparecía en annotations.
- Tras 525ea54, esos 11 pasan, y la cola — recién visible — muestra 11 fallos más en archivos diferentes.

### Los ~11 fallos pre-existentes desenmascarados

| # | Archivo | Test | Causa probable | Tipo |
|---|---|---|---|---|
| 1 | `test_plugin_watcher.py` | `test_concurrent_start_watcher_calls` | `assert 0 == 1` — polling-path assumption; con watchdog real, observer counters diffieren | watchdog_installed |
| 2 | `test_plugin_watcher.py` | `test_stop_watcher_thread_exits_cleanly` | `AttributeError: 'NoneType'.join` — `_watcher_thread is None` con watchdog (no usa polling thread) | watchdog_installed |
| 3 | `test_plugin_watcher.py` | `test_stop_watcher_clears_flag` | mismo AttributeError | watchdog_installed |
| 4 | `test_plugin_watcher.py` | `test_start_watcher_is_idempotent` | `assert None is not None` — polling-only path assumption | watchdog_installed |
| 5 | `test_plugin_manager_gaps.py` | `TestWatcherErrorBranches::test_start_watcher_thread_start_fails` | `assert True is False` — ThreadError mock expected pero watchdog lanza distinto | watchdog_installed |
| 6 | `test_main_websocket_gaps.py` | `TestWebSocketSsh::test_full_session` | `Expected 'resize_pty' to have been called once. Called 0 times` — flaky async timing (bug #7 conocido) | flaky_async |
| 7 | `test_main_coverage.py` | `TestSwarmStart::test_swarm_start_invalid_mode_falls_back_to_full` | "expected call not found" — mock call-order assumption, posiblemente platform-timing | mock_order |
| 8 | `test_main_coverage.py` | `TestSwarmStart::test_swarm_start_core_mode` | mismo pattern | mock_order |
| 9 | `test_crud_endpoints.py` | `TestPayloadsCRUD::test_get_payloads_returns_200` | `assert 503 == 200` — CI env `SUPABASE_URL=""` → "Database not configured" | db_not_configured |
| 10 | `test_api_endpoints.py` | `TestFilesEndpoint::test_files_has_data` | `assert 'data' in {'ok': False, 'error': 'Database not configured'}` | db_not_configured |

### Diagnóstico y próximos pasos sugeridos (en orden de facilidad)

1. **Aumentar cap de annotations** en `ci.yml` (línea 67) de `tail -10` a `tail -50` para no ocultar fallos futuros. ~2 min.
2. **watchdog-group (#1-5)**: misma familia que `test_plugin_manager_watchdog_gaps.py`. Aplicar el mismo patrón: skipcondicional cuando `watchdog is real-installed` o refactorizar los tests para que no asuman el polling fallback. Alternativa: instalar un `FakeObserver` global en conftest para neutralizar el real watchdog en TODOS los tests (no solo los que activamente lo usan). ~30-60 min.
3. **db_not_configured (#9-10)**: los tests que esperan datos reales deberían marcarse `@pytest.mark.slow` (que CI ya excluye) o mockear la capa `database` con fixture. Confirmaars si hay otros marcados que se ejecutan por error. ~15-30 min.
4. **flaky_async test_full_session (#6)**: bug #7 abierto hace rato — hacer skip no-destructivo en `after_deploy`, o esperar retry (`@pytest.mark.flaky(reruns=2)` con `pytest-rerunfailures`). ~30 min.
5. **mock_order swarm (#7-8)**: dos tests asumen orden de mock calls específica. Verificar si es problema en el test o en main.py swarm endpoint. ~1h.

### Estado actual CI
- `lint` ✅ _success_
- `build-and-deploy` ✅ _success_
- `test` 🟥 _failure_ (11 tests pre-existentes desenmascarados; no son regresiones)

### Lo que Sí está cerrado (verificado en cada paso del path)
- ✅ Audit-log recursión CI #47/#48 (commit `d8569d8`)
- ✅ Module identity split — imports unificados en 30+ tests + conftest aliasing (commit `25d6204`)
- ✅ IPv6 `test_scan_example_com` (commit `25d6204`)
- ✅ `watchdog_gaps` teardown assertion (commit `525ea54`)

Localmente (Windows, sin watchdog): `3909 passed` con `-k "not test_slow_hook"` (sin filtro `-m "not slow"` porque muchos de los marcados slow se excluían via deselect en Windows). Con `-m "not slow"` adicional: `3859 passed, 51 deselected, 0 failed`. CI Linux difiere por watchdog installed, db vacío, async timing.
