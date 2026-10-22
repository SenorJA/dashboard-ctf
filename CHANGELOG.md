# Changelog — M.I.R.V.

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/), auto-generated from Conventional Commits.

## [Unreleased]
### Fixed
- **fix(audit-2026-10-13)**: hallazgos de la auditoría de código (agentes `security` + `reviewer`):
  - `privacy.apply_proxy`: ya **no** marca el perfil como activo si algún paso falla (`ok=False`) —
    solo llama a `set_active(pid) if ok` (espejo de `vpn.apply_vpn`); antes el operador creía que su
    tráfico salía por el proxy aunque la aplicación hubiera fallado.
  - `assets.create_asset`: ahora llama a `_persist()` (antes el asset vivía solo en memoria y se
    perdía al reiniciar con `MIRV_PERSIST_WORKSPACE=1`); persistencia fuera del lock, cubre alta y merge.
  - `phishing_sim`: `_LOCK` era código muerto → ahora `RLock` que serializa `create/activate/archive/
    delete/record_click/record_submission` + `_hydrate`/`_persist` (snapshot bajo lock, escritura fuera);
    `_hydrate()` solo marca `_HYDRATED=True` tras un `load()` correcto (antes no reintentaba si el store fallaba).
  - `phishing_landing`: emitía **dos** eventos SIEM por click (`_ph_upgrade` + endpoint); eliminado el
    duplicado (el evento de click ahora incluye la IP).
  - `opencode_agent._resolve_cwd`: comparación de rutas con `os.path.normcase` (case-insensitive en Windows).
  - `system_monitor.cleanup_candidate`: valida también `os.path.realpath` contra `_looks_dangerous`
    (evita borrar un destino peligroso alcanzado vía symlink/junction).
  - `labs_update_session`: un título vacío devuelve **400** en lugar de 404 engañoso.
  - `/api/agents/run`: un `provider` desconocido devuelve **400** en lugar de 503.
  - `_exec_tool_command`: `recv_exit_status()` movido a `asyncio.to_thread` (no bloquea el event loop).
  - `tests/conftest.py`: alias `sys.modules["main"] = backend.main` (elimina el módulo dividido:
    31 ficheros importaban `main` top-level y 30 `backend.main` → dos apps/startup handlers).
  - `lab_sessions.import_state`: sincroniza `_step_counter` con el `order` máximo importado
    (antes, tras importar/hidratar, el siguiente `add_step` reutilizaba un `order` bajo y la nueva
    evidencia se ordenaba en medio de la cronología). Regression test añadido.
  - `finding_poc._evidence_hash`: normaliza saltos de línea finales (`rstrip("\r\n")`) para que el
    hash de un excerpt almacenado y el de una respuesta re-jugada (`curl`, que siempre añade
    newline) coincidan — `matches_original` ya no da falsos negativos. Regression test añadido.
  - **Ronda 2 (subagentes `security` + `reviewer`)**: `phishing_sim.stats/list_campaigns/get_campaign`
    leían `_REGISTRY` sin lock (riesgo de `RuntimeError: dictionary changed size during iteration`
    ante mutación concurrente de `create/delete`) → ahora leen bajo `_LOCK`; `_hydrate()` mueve el
    `_store.load()` **fuera** del lock (doble-check bajo `_LOCK`) para que un store lento/caído no
    serialice los clicks públicos de landing tras cada llamada; `frontend/index.html.bak` (134 KB,
    180 vars «gray-600» no servidas, 13 Jul) eliminado del repo y `*.bak/*.orig/*.rej` añadidos a
    `.gitignore`; tests de regresión: `assets.create_asset` persiste en alta **y** merge, no persiste
    en error, y `phishing_sim` reintenta la hidratación tras un fallo transitorio del store
    (`_HYDRATED` solo tras `load()` correcto).
  - Suite completa: **5393 passed, 1 deselected** (warnings 47→31).

### Added
- **feat(security-f0): gate de permisos interactivos en el canal SSH** — los comandos peligrosos ya no se ejecutan
  solos: el operador decide antes de que lleguen al shell del host Kali.
  - `backend/scope_guard.py`: `classify_command(...)` y `validate_command_with_permission(...)` aceptan
    `check_scope: bool = True`; con `check_scope=False` solo se evalúan los *danger patterns* (capa 2).
  - `backend/main.py`: `PERMISSION_TTL_SECONDS = 120` y gate de 2 capas en `@app.websocket("/ws")` —
    (1) validación de scope legacy preservada (`sudo` fuera del check de scope, `p10k`/`PROMPT` fuera del
    path; `warn` deja pasar, `block` corta), (2) `classify_command(..., check_scope=False)` → `blocked` corta
    con `scope_block`, `needs_permission` emite `permission_request` y espera `wait_for_decision` (TTL fail-safe
    120 s, `allow-session` cacheado por `cache_key`).
  - Protocolo WS: `permission_request` (id/tool/command/target/summary/detail/created_at/expires_at),
    `permission_denied` (id/status/message) y `scope_block` (razones).
  - `frontend/js/permissions.js` (nuevo): modal con cola de peticiones, botones *Deny* / *Allow session* /
    *Allow once*, countdown de expiración, `Escape` = denegar y poll 4 s a `GET /api/permissions/pending`.
  - `frontend/index.html`: modal `#permission-modal` + `frontend/js/main.v2.js`: handlers WS (canal principal y
    multi-consola) e i18n en/es (9 claves `perm*`).
  - Auditoría: el logger `vulnforge.permission` propaga al `AuditLogHandler` → `permission.request` /
    `permission.decide` quedan en `backend/logs/audit.jsonl`.
  - Tests: `backend/tests/test_permission_gate.py` (8). Suite completa **5468 passed**.
- **feat(security-f1): Ingest Guard — filtro anti prompt-injection para contenido de terceros** (`redact.py`
  filtra *secretos*; este módulo filtra *instrucciones embebidas*).
  - `backend/ingest_guard.py` (nuevo, **solo stdlib**, offline): `guard(raw, mode="auto", add_banner=True)`,
    `scan_text`, `strip_invisible`, `detect_invisible_chars`, `detect_instruction_like`, `detect_homoglyphs`,
    `find_hidden_urls`; verdict `ok`/`warn` (nunca bloquea: neutraliza y etiqueta, no destruye evidencia).
  - Detecta HTML oculto (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, `color:transparent`,
    `clip-path`/`clip`, off-screen, caja colapsada `overflow:hidden`, `transform: scale(0)`, `hidden`/`inert`/
    `aria-hidden`, clases `sr-only`, `<script>/<style>/<template>/<noscript>` y comentarios), caracteres
    invisibles (zero-width, bidi, soft hyphen, BOM, Hangul fillers, **bloque TAG `U+E0000`–`U+E007F`**,
    variation selectors, `Cf`/`Cc`), líneas con forma de instrucción, homoglifos latin+cirílico/griego y URLs
    que solo existen en bloques ocultos (canal C2).
  - Integraciones: `backend/main.py::_prepare_chat_messages` (solo mensajes no-system, antes de
    `redact_ai_payload`) + endpoint `POST /api/ingest/guard`; `backend/browser_capture.py` (nuevo check
    `prompt_injection` en `analyze_request`/`analyze_session`, severidad high/medium);
    `backend/lab_sessions.py::save_analysis` (evidencia y resumen saneados);
    `backend/intelligence.py::capture_snapshot` (contenido de páginas vigiladas saneado);
    `backend/osint_recon.py::page_snapshot` (texto de Jina Reader saneado + `ingest_guard` en la respuesta).
  - UI: badge **INGEST GUARD** en el panel de análisis de Browser Capture (`bc-ingest-guard`) + i18n en/es
    (`bcIngestGuardTitle`, `bcIngestGuardHint`) + helper genérico `window.t(key)` para widgets dinámicos.
  - Atribución: `backend/ATTRIBUTION.md` (MIT de `MadsLorentzen/ai-job-search` + personas/skills vendorizados).
  - Tests: `backend/tests/test_ingest_guard.py` (49) + `backend/tests/test_ingest_guard_integration.py` (17).
- **feat(security-f2): supply-chain guard para skills, personas y payloads** — el contenido ejecutable/instalable ya no se
  confía por defecto; toda skill, persona o payload se audita antes de habilitarse.
  - `backend/skill_supply_chain.py` (nuevo, **solo stdlib**, 504 L): allowlist canónica `ARSENAL_TOOL_IDS` (65 IDs del
    frontend) ∪ `REVIEWED_TOOL_BINARIES` (159 binarios) = **224 tools**; `PERSONA_ALLOWED_TOOLS` /
    `PERSONA_FORBIDDEN_TOOLS`, `LIFECYCLE_SCRIPTS` (`preinstall/install/postinstall/prepare/prepack`),
    `REQUIRED_GITIGNORE_PATTERNS`, patrón `_PIPE_TO_SHELL`; API `audit_allowed_tools`,
    `audit_skill_markdown`, `audit_persona_markdown`, `audit_package_json`, `audit_script_file`,
    `audit_payload(files)`, `has_blocking_issues`, `summarize`. Severidades **error** (bloquea) vs **info**
    (advisory, p.ej. `near_miss_tool` con distancia de edición ≤1 incl. transposición).
  - **Fail-closed**: `backend/skill_playbooks.py::call_skill_hook` ya no ejecuta hooks cuando `allowed_tools` está vacío
    (antes un `[]` significaba "todas"); `create_skill_template` valida `allowed_tools` y devuelve `issues`;
    `backend/agency_agents.py::_validate_persona_tools` rechaza tools prohibidas/desconocidas y `create_agent` escribe
    un `tools:` explícito (default read-only).
  - **Correcciones aplicadas por el guard**: `backend/skills/training-path/SKILL.md` (`allowed_tools: []` → `[curl]`);
    **39 personas** de `backend/agents/{security,testing,engineering,specialized}/` con frontmatter `tools:` read-only
    (`read, grep, glob, list_dir, search, web_fetch, report`; `engineering` sin `web_fetch`); `.gitignore` += `*.env`,
    `.env.*`, `backend/data/`.
  - Endpoint `GET /api/skills/supply-chain` (`{ok, skills: 113, personas: 39, allowlist: {arsenal: 65, total: 224},
    errors, infos, total}`); `POST /api/skills/create` adjunta el `supply_chain` al error de validación.
  - CI: step **Skill supply-chain guard (F2)** en `.github/workflows/ci.yml` (`test_skill_supply_chain.py` +
    `test_pack_purity.py`).
  - Tests: `backend/tests/test_skill_supply_chain.py` (46, incluye integridad de la allowlist contra
    `ARSENAL_GROUPS` del frontend). Suite completa **5514 passed**.
- **feat(ooda-f3): OODA core (Observe/Orient/Decide/Act)** — bucle asistido/guardarraíles con store JSONL
  + informe basado solo en evidencia.
  - `backend/ooda_store.py` (nuevo, JSONL + *write dual* index, thread-safe, sin tablas Supabase nuevas):
    runs/steps con `technique_id`, `confidence`, `ooda_status`, `findings[]` con campos enriquecidos.
  - `backend/ooda.py` (motor): `observe`/`orient`/`decide`/`act`, chequeo de scope, clasificación de comandos
    con hints de permisos (*needs-permission*), modo `assist|pentest`.
  - `backend/ooda_report.py`: informe Markdown con timeline y solo evidencia real.
  - Endpoints: `POST/GET /api/ooda/create|list|{id}|{id}/observe|orient|decide|act|done|report`.
- **feat(skills-f5): instalador remoto de skills (preview → confirm)** — instala desde repo/URL con auditoría de
  supply-chain obligatoria, sin auto-activación.
  - `backend/skills_installer.py` (nuevo, **solo stdlib**): `preview()` / `install()` / `uninstall()`,
    fetch de `SKILL.md` vía `urllib`, frontmatter tolerante mapeado a MIRV, `enabled=False` por defecto,
    escritura **únicamente** en `~/.mirv/skills/`, bloqueo si hay `errors` del guard, auditoría `audit_log` +
    evento `skills` en SIEM.
  - Endpoints: `POST /api/skills/install` (preview), `POST /api/skills/install/confirm` (instala),
    `DELETE /api/skills/{name}/uninstall` (borra solo desde `~/.mirv/skills/`).
  - UI: pestaña *Skills* — botones *Install from repo* / *Supply Chain Audit* + modales con preview de
    issues (block/allow), confirmación explícita.
- **feat(desktop-fase-4)**: Fase 4 del plan de escritorio — splash screen, título dinámico, página de error e iconos.
  - **Identifier** `com.mirv.app` → `com.mirv.desktop` (elimina el warning del bundler por terminar en `.app`).
  - **Splash screen** (`frontend/splash.html`, copiada al shell por `sync-frontend.mjs`): ventana `splash` sin
    decoraciones, centrada, radar con sweep CSS; la ventana `main` arranca `visible: false` y solo se muestra cuando el
    backend responde (`show_main_and_close_splash`), destruyendo la splash.
  - **Título dinámico** `refresh_status_title()`: `M.I.R.V. v{version} — {estado}` (iniciando → backend conectado/caído).
  - **Página de error** (`frontend/error.html`): si el backend no queda listo en 45 s, la ventana principal navega a
    `tauri://localhost/error.html` (botón reintentar + auto-poll cada 3 s + cerrar).
  - **Guards por ventana** en `on_window_event`: hide-to-tray y exit-on-destroy SOLO para la `main` (la splash se
    destruye al arrancar sin matar la app).
  - Iconos regenerados desde `frontend/img/icon-192.svg` (`npm run icons`).
  - `desktop/src/` sigue gitignored: splash/error viven en `frontend/` y `sync-frontend.mjs` las copia (`sources`).
  - Verificación: `cargo check` limpio + MSI construido localmente (config 2 ventanas + páginas embebidas).

### Added
- **feat(desktop-tray-updater)**: Feature E — calidad de vida del escritorio MIRV.
  - **System tray** (`desktop/src-tauri/src/main.rs::setup_tray`): cerrar la ventana ahora oculta a la bandeja
    (`CloseRequested` + `api.prevent_close()`) en lugar de salir; menú "Show MIRV" / "Quit" y left-click sobre el icono
    restauran la ventana; "Quit" flipa un `AtomicBool` que permite la salida real (mata el sidecar). Requiere features
    `tray-icon` + `image-png` en `tauri` (Cargo.toml).
  - **Auto-updater** (`tauri-plugin-updater = "2"`): `setup_updater()` hace check + download + install + restart en cada
    arranque contra GitHub Releases (`latest.json`). Config: `plugins.updater.pubkey` + `endpoints`, y
    `bundle.createUpdaterArtifacts: "v1Compatible"` (artefactos `.msi.zip` + `.sig`). Capability `updater:default` añadida.
  - **Signing minisign**: keypair generada (privada en `desktop/.tauri/` → gitignored; pubkey commiteada).
    `desktop-build.yml` pasa `TAURI_SIGNING_PRIVATE_KEY` / `_PASSWORD` a `tauri-action`, y `createUpdaterArtifacts`
    se inyecta vía `--config` **solo en tags `v*` + secrets** (siempre en config base el bundler falla al firmar sin
    clave — "public key found but no private key"); builds de `main` compilan sin firmar (secrets documentados en
    `.github/SECRETS.md`).
  - Verificación: compilación del shell Tauri vía el workflow **Desktop Build** en CI (`tauri-action --bundles msi`);
    API tray/updater contrastada contra docs.rs de Tauri 2.

### Added
- **feat(multi-terminal)**: Feature F — consolas extra en el tab Terminal (multi-sesión SSH paralela).
  - Backend: cada conexión `/ws` ya spawns un shell paramiko independiente (sin estado compartido) — garantizado por nuevo
    test `TestWebSocketMultiSession` (2 conexiones concurrentes, cada una con su canal: auth/connect por target, output
    aislado, comandos enrutados a su canal, `invoke_shell.call_count == 2`) en `test_main_websocket_gaps.py`.
  - Frontend (aditivo, sin tocar el terminal principal/parser): barra `➕ Console` + chips `📡 cN`; cada consola es un panel
    autocontenido (WebSocket propio sobre el perfil de conexión activo, output ANSI-stripped, input con Enter, ▶/⏹ toggle,
    ✕ cerrar). Limpieza automática de WS al cerrar.
  - Frontend no-verificable en CI → todas las extensiones en JS OK via `node --check`; backend cubierto por tests
    (`test_main_websocket_gaps.py`: 19 passed + 1 slow deselected).

## [Unreleased]

### Added
- **feat(notifications)**: hub de notificaciones multi-proveedor (Telegram/Discord/Slack/Pushover/webhook genérico).
  - `backend/notifications.py`: registro en memoria (API) con capa de fallback por env (`MIRV_NOTIFY_*`), enmascarado de tokens
    con `mask()`, builders de payload por proveedor (HTML-escape en Telegram, form-encoded en Pushover, JSON genérico en webhook),
    truncación a 4000 chars, `send()` fire-and-forget en daemon thread y `send_sync()` bloqueante para el endpoint de test.
  - Endpoints: `GET /api/notifications/providers` (masked), `POST /api/notifications/config`, `DELETE /api/notifications/config/{p}`,
    `POST /api/notifications/test` (síncrono, 200/502) y `POST /api/notifications/send`.
  - Hooks opt-in (no-op sin proveedores): findings high/critical (single + bulk) y runs de scheduler (endpoint record + daemon).
  - Frontend: KPI card 🔔 Notifications en Home + panel `<details>` con alta de Telegram/webhook, test, delete y envío manual.
  - Tests: `backend/tests/test_notifications.py` (37) — config/validación/masking, env fallback, payload builders, deliveries
    mockeadas, `send`/`send_sync`, endpoints REST y hooks. Suite: 4787 passed, 0 failed.
 — 18 Sep 2026

### Added
- `feat(api-auth)` — **guard opt-in de API tokens (Feature D)**: módulo `backend/api_auth.py` — pares token aceptados `Authorization: Bearer <t>` | `X-MIRV-Token: <t>` | cookie httpOnly `mirv_token` (set al servir el SPA en `/`, el frontend no cambia); configuración vía env `MIRV_API_TOKEN` (gana) o archivo `MIRV_API_TOKEN_FILE` (default `backend/data/api_token.txt`, primera línea); comparación constante-tiempo `hmac.compare_digest`, `token_source()` env/file, `mask()`, `is_exempt()` (`/api/health`, `/api/auth/status`). Middleware `ApiTokenMiddleware` en `main.py` (solo `/api/*`, 401 con `WWW-Authenticate: Bearer` + `X-MIRV-Auth: required`). Endpoints `GET /api/auth/status` (público: enabled/source/masked_token) y `GET /api/auth/token` (guardado: echo del token para copiar en herramientas externas). **Sin token configurado → guard desactivado, comportamiento idéntico al actual** (opt-in, tests herméticos intactos); `/ws` conserva su propio handshake JSON. Frontend: KPI card 🔐 API Auth en Home (dot+status+token masked, `copyApiToken()` copia el token vía `/api/auth/token`). Tests `test_api_auth.py` (17: disabled-default, env/file/missing-file, Bearer/X-header/cookie/invalid, exempt paths, status/token endpoints, mask, env-wins).
- `feat(asset-inventory)` — **inventario de assets por engagement (Feature C)**: módulo `backend/assets.py` (dataclass `Asset` dedup por `assessment_id+kind+address`, registry in-memory thread-safe con índice O(1), kinds host/domain/service/endpoint/other, status active/potential/out-of-scope/infrastructure/compromised, puertos abiertos, stack de servicios, tags, notas, `findings_count`, source manual/tool; `ingest_findings()` auto-popula desde findings — clasifica IP→host/hostname→domain, adjunta puertos `PORT/proto`, enriquece servicios `service version`, crea endpoints para `path`; classicación de URLs vía `urlparse`). Persistencia opt-in `workspace_store` (key `assets`) + `load_from_store()` en startup. Endpoints **11**: `GET /api/assets` (filtros), `POST /api/assets` (merge dedup / 400 assessment no existe / kind-status inválidos), `GET /api/assets/export` + `POST /api/assets/import` (rows/replace, valida y salta inválidos), `GET /api/assets/by-assessment/{id}` (inventario+summary por engagement), `GET /api/assets/summary`, `POST /api/assets/ingest` (batch de findings → `{created,updated,skipped,ports,services,errors}`), `GET/PUT/DELETE /api/assets/{id}` (PUT con whitelist, cambio de kind reindexa la dedup key) + cascade `delete_assets_for_assessment()` al borrar un assessment. Frontend: panel 🖧 **Asset Inventory** en el tab Assessments (chips de puertos `22/tcp · ssh 8.2p1`, servicios tech, badges de status, 🔎 findings_count, delete ✕), botones ⚡ Ingest findings (finds de la assessment activa) y 🔄 Refresh, **auto-ingest debounced** en `addFindings` cuando hay assessment activa. Tests `test_assets.py` (22: registry, dedup/merge, filtros, ingest heuristics, cascade, endpoints REST).
- `feat(scheduler-daemon)` — **daemon server-side de scheduler (Feature A)**: `backend/scheduler.py` `_TOOL_COMMANDS` (14 tools con templates `{target}` para nmap/whatweb/gobuster/nikto/wpscan/enum4linux/smbclient/ffuf/wfuzz/feroxbuster/theharvester/dnsrecon/masscan/dirb) + `get_command(tool_id, target)` (+ValueError si no mapeada) + `due_jobs(include_tools=∅, require_target=)` que solo auto-avanza los jobs que un consumidor va a disparar. `main.py`: `_exec_tool_command()` (SSH compartido vía `asyncio.to_thread`, stdout cap 8 KB + `truncated_out`, stderr 4 KB), `_count_findings_in_output()` (heurísticas por familia de tool), `_scheduler_loop()` (ciclo 5 s, spawn en startup, cancel en shutdown; solo tools mapeadas CON target fijo — los jobs unmapped o con target vacío quedan due para el poll del browser, sin perder el single-trigger) + `GET /api/scheduler/status` (daemon_running/mapped_tools/policy). Frontend: badge ⚙ de estado del daemon en tab Scheduler (`refreshSchedulerDaemon`). Tests `test_scheduler_daemon.py` (27: mapping, exec succ/fail/truncation, conteo, loop succ/failure, filtros due_jobs, status).
- `feat(finding-lifecycle)` — **ciclo de vida de findings + binding a assessment (Feature B)**: columnas `lifecycle_status` (open/confirmed/accepted/fixed/verified) + `assessment_id` en tabla findings (migración `ALTER TABLE findings ADD COLUMN IF NOT EXISTS …` en `SCHEMA_SQL`, `save_finding`/`save_findings_bulk`/`list_findings` con los campos nuevos); `database.update_finding(finding_id, updates)` con whitelist de campos; endpoints `PATCH /api/findings/{id}` (200 / 400 lifecycle inválido o campo desconocido / 404), `GET /api/findings/assessment/{id}` y filtros `lifecycle_status`+`assessment_id` en `GET /api/findings`. Frontend: badge de estado + select por finding (`setFindingLifecycle`), filtro 🗂 por estado en tab Findings, botón 📎/✓ bind a assessment activa (`bindFindingToAssessment`), rollback optimista si el PATCH falla. Tests `test_finding_lifecycle.py` (19: CRUD DB, whitelist, filtros, endpoints REST).
- `feat(workspace-persistence)` — **persistencia Supabase de assessments + scheduler**: tabla `workspace_state` (key/value JSONB) + capa opt-in `backend/workspace_store.py` (env `MIRV_PERSIST_WORKSPACE=1` + `database.is_available()`, cache en proceso, fail-silent; el registry in-memory sigue siendo autoritativo, tests herméticos). `assessments.py`/`scheduler.py`: `_persist()` en cada mutación + `load_from_store()` hidratado en startup. **Run history en Jobs**: `run_count`, `last_result`, `last_duration`, `last_findings`, `last_error` + `record_run()` (reportado por el frontend al terminar).
- `feat(import-export)` — **export/import JSON** de assessments y scheduler: endpoints `GET /api/assessments/export`, `POST /api/assessments/import`, `GET /api/scheduler/export`, `POST /api/scheduler/import` (body `{rows, replace}` — merge o reemplazo, valida y salta inválidos, reporta imported/skipped/rejected) + `POST /api/scheduler/jobs/{jid}/record`. Frontend: botones 📥 Import/📤 Export en ambas tabs (diálogo de confirmación replace-vs-merge, toasts de resumen).
- `feat(schedule-toast)` — **toasts de finalización de scans programados**: `schedulerPollDue` marca `window._lastScheduledRun`; `finishToolOutput` llama `_reportScheduledRun()` → POST `/record` con findings+duration y toast `✅ Scheduled 'X' finished — N findings in Ys`; tarjeta del job muestra historial `⚙ N runs • last: K findings in Zs` (+ `last_error` en rojo).
- `feat(campaign-presets)` — **presets de campaña en cadena** en tab Scheduler: dropdown 🔗 Presets (Full Recon 4 pasos / Web Scan 3 / SMB Audit 2 / Quick Recon 2), `launchCampaignPreset()` crea los jobs con intervalos ESCALONADOS vía nuevo parámetro `start_offset_seconds` en `create_job`/`POST /api/scheduler/jobs` (sin offset se conserva el comportamiento histórico: primer run a `now + interval`; con offset `now + offset`). Tests `test_scheduler.py` → 43.
- `feat(palette)` — **palette global `Ctrl+K`**: modal ⌘ (HTML `#palette-modal`) con búsqueda en vivo sobre tabs ▦, 50+ tools ⚡ (categorizadas) y acciones → (export findings, clear terminal, AI summary, export session, theme, language, save mission, cheatsheet, refresh dashboard); navegación ↑/↓ + ↵ (⇧↵ no cierra, aplica solo a tabs) + Esc + click-outside; `_paletteEsc`/`_paletteSearch`/`_paletteMove`/`_paletteRun`.
- `feat(active-assessment)` — **assessment activa (contexto por engagement)**: botón `☆ Set active`/`★ Active` por card (persistido en `localStorage mirv_active_assessment`), badge `⭐` en `assess-summary` y tarjeta resaltada con borde ámbar; `launchTool` auto-rellena el target desde la assessment activa cuando la herramienta lo requiere y no hay target (toast con contexto).
- `feat(i18n-tabs)` — **i18n completo de tabs nuevas**: 24 claves nuevas en/es (assessTitle/New/Import/Export/Empty/placeholders/Save/Cancel y schedTitle/New/Import/Export/Presets/Empty/placeholders/Save/Cancel/Pausar/Activar/Ejecutar ya/Eliminar + status labels planning/in-scope/in-progress/done/archived), `applyLanguage()` aplica IDs + placeholders + botones + empty-states.
- `feat(terminal-workflow)` — flujo de trabajo en terminal: **historial persistente** (`localStorage mirv_cmd_history`, flechas ↑/↓, `window.clearCmdHistory`, botón 🗑 History), **exportar sesión** (`window.exportSession` → `.log`/`.md` file, botón ⬇ Export), **resumen IA de sesión** (`window.aiSessionSummary` → `/api/ai/chat`, botón 🤖 Summary) y **sugerencias next-step deterministas** (`computeNextSteps()` + `renderNextStepSuggestions` — nmap→whatweb/gobuster/hydra, gobuster→nikto/wpscan, sqlmap→--dbs, etc., sin IA; se renderizan en el panel Findings→Suggestions y como aviso en terminal). Botones `data-action` `clear-cmd-history`/`export-session`/`ai-summary` + `ACTION_MAP`.
- `feat(findings-charts)` — **Charts Overview** en tab Findings: 3 mini-gráficas canvas puro (sin librerías) por severidad (colores), top tools y top targets (`renderFindingsCharts()` + `_drawBars`); panel `details` colapsable con estado persistido (`localStorage mirv_findings_charts_open`).
- `feat(cheatsheet)` — modal **📖 Cheat** en terminal toolbar: ~50 comandos curados por categoría (scan/web/sql/auth/smb/tel/dns/osint/pivot/jwt/files/svc/info), buscador en vivo, clic precarga el comando con `TARGET`→target activo (`window.openCheatSheet/closeCheatSheet/loadCheatCommand` + `renderCheatSheet`; modal fuera del script → eventos delegados).
- `feat(assessments)` — **Workspace/Assessments**: módulo `backend/assessments.py` (dataclass `Assessment`, registry in-memory thread-safe, status planning/in-scope/in-progress/done/archived, targets dedup, tags, notas, límites MAX_ASSESSMENTS/MAX_TARGETS, `assessments_by_target`, `summary`) + endpoints `GET/POST /api/assessments`, `GET/PUT/DELETE /api/assessments/{id}`, `POST /api/assessments/{id}/targets`, `DELETE /api/assessments/{id}/targets/{target}`, `GET /api/assessments/by-target/{target}`. Tab 🗂️ Assessments: form inline crear (nombre/descripción/status/targets/tags/notas), cards con status badge + chips de targets con remove ✕, add-target inline (Enter), selector de status, ⚡ Scan first (lanza nmap al primer target), 🗑 Delete. Tests `test_assessments.py` (30).
- `feat(scheduler)` — **Scheduled scans**: módulo `backend/scheduler.py` (dataclass `Job`, intervalos 10s–7d validados, `due_jobs()` auto-advance single-trigger por ciclo, `advance_to_now()` para "run now", thread-safe) + endpoints `GET/POST /api/scheduler/jobs`, `PUT/PATCH/DELETE /api/scheduler/jobs/{id}`, `GET /api/scheduler/due`, `POST /api/scheduler/jobs/{id}/run`. Tab ⏰ Scheduler: form crear (nombre/tool/intervalo/target opcional), lista con countdown, ⏸ Pause/▶ Enable, ⚡ Run now (avanza next_run → el poll lo dispara), 🗑 Delete; **polling global cada 10 s** (`schedulerPollDue`) que lanza `launchTool(tool_id)` en el terminal (target fijo del job o activo). Tests `test_scheduler.py` (37).
- `feat(hak5-tools)` — editor de payloads Hak5 mejorado: **plantillas por dispositivo** (select + `window.insertHak5Template`, 7 plantillas para Bunny/OMG/M5/Shark Jack/Squirrel/Shark Display), **validador por lenguaje** (`window.validateHak5Payload` — DuckyScript/bash/JS/MicroPython, warn sin bloquear) y **descarga** (`window.downloadHak5Payload` → blob `.ext` por dispositivo). Botones `data-action` `tpl-hak5`/`val-hak5`/`dl-hak5` + `ACTION_MAP`, `populateHak5Templates()` en `switchHak5Device` + `initHak5`.
- `feat(dashboard)` — pestaña **🏠 Home (Command Center)**: KPIs (backend health/uptime, findings, targets, coverage, SIEM, intel alerts, CPU/RAM/disco), quick actions (`data-action="tab"`), toolkit strip; `refreshDashboard()` con 8 fetches paralelos + wrapper `switchTab('home')`. Tab count 28→29.
- `feat(findings-export)` — export estructurado de findings: `GET /api/findings/export?format=csv|sarif|html` en `main.py` (`_export_findings_csv/sarif/html` + `_sarif_level` + `_findings_sev_rank`). SARIF 2.1.0 con `runs/tool/driver=MIRV`, level error/warning/note; HTML self-contained estilizado (severity badges + summary chips). Frontend: botones ⬇ CSV/SARIF/HTML (`downloadFindingsExport()`), Content-Disposition attachments.
- `feat(siem-webhook)` — alertas SIEM a webhook externo (Slack/Telegram/Teams/Make/Zapier): `set_webhook_url`/`get_webhook_url` en `siem.py` (validación http/s, vacío=clear, thread-safe), `_notify_webhook` fire-and-forget (urllib+daemon thread, 5s timeout, payload JSON `siem-alert` con id/rule/severity/title/detail/timestamp/event_ids) llamado desde `_create_alert`. Endpoints `GET/POST/DELETE /api/siem/webhook` + `SIEMWebhookRequest`. Frontend: card en tab SIEM (`siemWebhookSave/Clear/Refresh`) + badge estado.
- `feat(mcp-osint3)` — MCP Server expone las 5 herramientas OSINT Ronda #3: `vulnforge_osint_{code_search,cert_transparency,sigstore,urlscan,mac_lookup}` (definiciones TOOLS + handlers `_tool_osint_*` que delegan en `osint_recon`).
- `feat(hak5)` — 2 dispositivos nuevos en el editor de payloads: **Packet Squirrel Mark II** y **Shark Jack Display** (botones `data-device` en tab Hak5, entradas en `hak5Devices` de `main.v2.js`/`main.js`, tarjeta de repo `hak5/packetsquirrel-payloads`, fix typo "Shack Jack"→Shark Jack, texto de soporte actualizado; localStorage `vulnforge_hak5_{squirrel,shark}` sin migración — filas DB `device` libre)
- `feat(ronda-apibased3)` — 5 herramientas OSINT curadas keyless (cantera cambió de alcance; validadas con smoke real): `code_search` (Sourcegraph streaming SSE `/.api/search/stream` + `type:file`; grep.app descartado por 429 persistentes), `cert_transparency` (crt.sh CT — subdominios pasivos, dedupe + wildcards, cap 500), `sigstore_lookup` (Sigstore Rekor `POST /api/v1/log/entries/retrieve` — identidades por email/sha256; emailrep.io fuera: tier unauthenticated deshabilitado), `urlscan_search` (urlscan.io `search/?q=domain:`), `mac_vendor_lookup` (maclookup.app — `_normalize_mac` reduce a OUI). 5 endpoints `POST /api/osint/{code,cert,sigstore,urlscan,mac}` con `_osint_guard` + límites conservadores (`rate_limiter.py`: urlscan 6/min, cert 6/min, sigstore 10/min). Frontend: 5 tarjetas en tab OSINT + `window.osint{Code,Cert,Sigstore,Urlscan,Mac}` + Enter-bindings + i18n. Tests: `test_osint_recon.py` 115→140, suite OSINT 266 passed, `osint_recon` 100% cov (620 stmts).
- `feat(ronda-apibased2)` — 5 herramientas OSINT nuevas keyless (cantera `cporter202/agentic-ai-apis`): `dns_recon` (DNS-over-HTTPS dns.google, 6 tipos en paralelo), `rdap_whois` (RDAP rdap.org — registrar vcard, events, nameservers, abuse), `pwned_passwords` (HIBP range k-anonymity, prefijo SHA-1 + `Add-Padding`; password nunca echo/log, endpoint quita `length`), `urlhaus_lookup` (abuse.ch POST url/host — tags + blacklists), `page_snapshot` (Jina Reader, texto cap 60 KB). 5 endpoints `POST /api/osint/{dns,whois,pwned,urlhaus,page}` con `_osint_guard`. Frontend: 5 tarjetas en tab OSINT + `window.osint{Dns,Whois,Pwned,Urlhaus,Page}` + Enter-bindings + i18n. Tests: `test_osint_recon.py` 115, `osint_recon` 100% cov.
- `cf22015` — fix(pc_analyzer): pin `os.name=nt` en tests de registry Windows para que pasen en CI Linux (plataforma-portables)
- `55a3e60` — feat(pc_analyzer): Fase 2 — checks **eventlog** (`wevtutil` System/Application, Windows), **updates** (registry `RebootRequired`/`PendingFileRenameOperations`/`WindowsUpdate LastSuccessTime` en Windows; `apt list --upgradable` en Linux) y **reboot** (`/var/run/reboot-required`); **auto-fix con confirmación**: campo `fix` en `Check`, `apply_fix()` gated reusando `sysmon.scan_candidates()`/`cleanup_candidate()` (`cleanup_junk`), endpoint `POST /api/pc-analyzer/fix` (409 sin `confirm`, 400 acción desconocida, audit log). Frontend: botón ▶ Fix por sugerencia + `runPCAFix()` con diálogo nativo. Tests `test_pc_analyzer.py`: 28 → 62, cobertura del módulo 95%. Desktop Build (sidecar onefile) incluye la feature.
- `feat(pc_analyzer)` — PC Analyzer: salud del host local (RAM/CPU/disco/junk/red/uptime) con chequeos deterministas, grade A–F, score 0–100 y sugerencias accionables (phase 1, sin auto-fix), reutiliza `system_monitor`. Endpoint `GET /api/pc-analyzer` + pestaña 🩺 PC Analyzer con explicación IA vía `/api/ai/chat`. Tests: `test_pc_analyzer.py` (28).
- `feat(system_monitor)` — nueva herramienta in-app de monitorización del host: módulo `backend/system_monitor.py` (stdlib, `psutil` opcional) + endpoints `GET /api/system/stats`, `GET /api/system/disk`, `GET/POST /api/system/cleanup` (barrido seguro de candidatos — rechaza rutas raíz/sistema/home — con presupuesto 1.5 s/dir) + pestaña 🖥️ Sys Monitor en frontend (`tab-system`, `refreshSystem`/`runCleanupScan`/`deleteCleanupCandidate`, polling 15 s) + i18n en/es. Tests: `test_system_monitor.py` (29).
- `fd8aa7b` — feat(desktop): MIRV Desktop — PyInstaller sidecar + Tauri scaffold. Backend: `mirv-backend.spec` (bundles skills/plugins/frontend) + `build_backend.bat` + `main.py` `IS_PACKAGED`/`TAURI_MODE`/`_resolve_frontend_dir` (frozen-aware) + `__main__` con `--host/--port/MIRV_PORT` y app-object directo a uvicorn (fix "Could not import module main"). Frontend: `main.v2.js` detección `IS_TAURI` + `API_BASE`/`WS_URL` + monkeypatch condicional `window.fetch`. Desktop: scaffold Tauri completo (`desktop/`). Tests: 4387 passed.
- `ba21232` — feat(op-admiral + security + a11y): T4 auto-guardar/cargar planes Op Admiral (`Save Plan`/`📚`, `/api/plans`, auto-save/load/delete) + fix `list_mission_plans` parsea `steps` JSON. T7 rotación de key `secret_store` (`encrypt_with`/`decrypt_with` + `reencrypt_app_credentials` + `POST /api/credentials/reencrypt`). T6 contraste P1 residual en modules JS secundarios (`text-gray-600/700→400`). Tests: 4385 passed.
- `feat(security)` — `secret_store.py`: encriptación at-rest Fernet (AES-128-CBC+HMAC) para `app_credentials`; fail-closed si crypto no disponible; key env `MIRV_ENC_KEY`/derivada scrypt o archivo `backend/data/enc_secret.key` (0600); passthrough de rows legacy + re-cifrado
- `feat(orchestrator)` — hunt-* routing: webvuln detecta clase de vuln (`route_hunt`) y groundea prompt en playbook `hunt-<class>` + `GET /api/orchestrator/hunt` + badge 🎯 en Op Admiral
- `feat(skills)` — port 60 skills de Claude-BugHunter → 88 built-ins (58 `hunt-*` + `triage-validation` + `evidence-hygiene`), atribución CC-BY-4.0/MIT (Sachin Sharma), 22 skills `requires_scope`
- `28fad54` — feat(frontend): local models abstraction — modelo por especialista (ronda 6d, item 4 Fase D)
- `0693715` — feat(frontend): Op Admiral tab — multi-agent orchestrator UI (ronda 6c)
- `9b331df` — feat(orchestrator): memoria episódica SQLite + prompt caching (ronda 6b)
- `2cbb2b6` — feat(orchestrator): multi-agent orchestrator — Op Admiral v2 (ronda 6a)
- `9db256` — feat(ronda4): a11y + i18n completa + README + auditoria UI
- `408c717` — feat(ronda3): correlacion OSINT + docs rondas 1-3 + slow test fixes
- `4bb319d` — feat(ronda2): security hardening — fix P1+P2 de la auditoria OSINT
- `09680e8` — feat(ronda1): responsive OSINT tab + security audit + coverage 100% osint_recon
- `eb6542e` — feat(osint): fase 3 — skill `password-audit` + Instagram OSINT (ghostig port)
- `4918397` — feat(osint): passive OSINT recon suite — skill, subdomain passive sources (crt.sh + Wayback), módulo `osint_recon.py` + tab OSINT
- `b6a1d4b` — feat(deploy): VPS bootstrap + Cloudflare Tunnel scaffold (Hitos A/B) — `deploy/bootstrap-vps.sh`
- `92f4fa3` — feat(pdf): professional findings PDF export with per-finding detail + VPS secrets docs
- `022f349` — browser-capture-mcp: 7 MCP tools para importar/analizar HAR y convertir en findings del session store
- `2f5ef00` — feat: real light theme — bloque `body.light`, theme toggle de 3 estados (neon/light/mono), contraste WCAG AA, colores JS theme-aware
- `dedfda6` — feat: swarm full mode — operadores OSINT/Web/Vuln + selector de modo (pipeline de 7 ops)

### Fixed
- `09db256` — fix(a11y): P1 UI audit fixes + 2 plugin_watcher timing tests marcados slow
- `ee1d844` — fix(a11y): P1 UI audit — contraste WCAG AA + tab roles + labels + modales + arsenal
- `3cb20fb` — fix(ci): green suite on empty-env (no Supabase, `KALI_IP=""`, watchdog)
- `d8569d8` — fix(audit_log): stop runaway recursion in `AuditLogHandler.emit` (CI #47/#48)
- `4bb319d` — fix(security): hardening P1+P2 del audit OSINT (token, rate limit, `_safeUrl`, max_length, IPs privadas, dominio estricto, HTTPS, logger sin input)
- `cff28aa` — fix(ci): excluir `@pytest.mark.slow` por marker (`-m 'not slow'`)
- `72c5db3` — fix(audit_log): add re-entrancy guard to `AuditLogHandler.emit`
- `82e9fa0` — fix(ci): pytest-timeout 60s + timeout 20min — evitar que tests colgados (red/timers) bloqueen el pipeline horas
- `80cb2a0` — fix(deploy): usar `env.VPS_HOST` en `if:` — secrets no es válido en condiciones `if` de GitHub Actions

### Documentation
- `1be1583` — docs(tomorrow): ronda 4 documentada — a11y + i18n 100% + README + auditoria UI
- `c522089` — docs(tomorrow): corregir postmortem flake — causa real fue httpbin.org, no OOM (fix 90ca638)
- `dec0290` — docs(tomorrow): hito Fase 3 OSINT cerrado (eb6542e + 945b726) + postmortem runner flake
- `a0ac863` — docs(tomorrow): hito suite OSINT pasivo cerrado (4918397) — 31 módulos, 236 endpoints, 4030 tests, 26 tabs
- `59525b9` — docs(tomorrow): andamiaje Hitos A/B listo (b6a1d4b), pasos manuales usuario
- `910cb15` — docs(tomorrow/roadmap): hito PDF profesional cerrado (92f4fa3) + hitos abiertos VPS/Cloudflare
- `1947218` — docs(tomorrow): mark CI 100% green milestone + postmortem for 11 unmasked failures
- `b1a79d4` — docs(tomorrow): document 11 pre-existing CI failures unmasked after watchdog fix
- `8e7456a` — docs: secrets Docker Hub configurados (`DOCKERHUB_USERNAME` + TOKEN)
- `3fea21c` — docs: marcar browser MCP, swarm ops y light theme como completados en ROADMAP/TOMORROW
- `acf6a99` — docs: coverage refresh — main.py 100%, 3834 tests, 76 test files, pending phases updated

### Tests
- `90ca638` — test(api_scanner): mark 9 httpbin.org integration tests as `@pytest.mark.slow`
- `6cfa6e6` — test(watcher): accelerate plugin watcher tests 4.4s -> 1.8s + kill 2 latent races
- `2b2d227` — test(coverage): exif_osint + dlp_scanner to 100%
- `525ea54` — test(plugin_manager): fix watchdog_gaps teardown assertion (CI Linux installs watchdog)
- `25d6204` — test(imports): unify `backend.*` prefix + conftest `sys.modules` alias + fix IPv6 subdomain test
- `d9c0754` — test: main.py 100% — REST gap coverage (test_main_gaps 295) + websocket `read_shell`/`WebSocketDisconnect` paths (test_main_websocket_gaps 19)

### CI/CD
- `945b726` — ci: diagnostic `head+wc` of `pytest.log` on failure — job eb6542e killed mid-run (140s, no FAILED lines)
- `6de6c15` — ci: diagnostic `--cov-fail-under=0` (isolate coverage vs test failures) + upload pytest log artifact
- `800d9d7` — ci: emit pytest verdict as `::error::` annotations (queryable via API)
- `01492cd` — ci: add step-summary diagnostic for failing pytest run (log too large for UI)

[Unreleased]: https://github.com/SenorJA/dashboard-ctf/compare/main...HEAD
