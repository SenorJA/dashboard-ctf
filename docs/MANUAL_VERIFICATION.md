# Verificación manual E2E — M.I.R.V. + Kali (docker-compose)

Runbook paso a paso para comprobar que la app funciona con el stack completo
(`kali-tools` + `mirv-backend`) sin necesitar una VM de Kali. Cada comando tienen
el resultado esperado, tal y como se validó el **28 Sep 2026** (commit `1a991f2`).

> Prerrequisitos: Docker Desktop encendido, repo clonado, `.env` en la raíz con
> `MIRV_API_TOKEN=<token>` (ver Pack 8).

---

## 1. Levantar el stack

```bash
docker compose -p proyectociber up -d --build
```

- **Siempre `--build`** tras tocar backend/frontend: `docker compose up -d` a secas
  NO reconstruye la imagen y serviría código viejo.
- Espera 2 servicios *healthy*:

```bash
docker compose -p proyectociber ps
# NAME             STATUS
# mirv-backend     Up …(healthy)
# mirv-kali-tools  Up …(healthy)
```

- El backend tarda ~30–60 s en arrancar (verifica las 18 tablas de Supabase al
  boot). Si `curl` aún no responde, espera y reintenta.

---

## 2. Verificación baseline

```bash
curl -s http://localhost:8000/api/health
# {"status":"ok","mode":"production","version":"1.0.0","supabase":true,...}

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/          # 200 (SPA, ~310 KB)
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/css/style.css   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/js/main.v2.js   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/img/logo.svg    # 200
```

---

## 3. Login / API guard

El guard está **activo** cuando `MIRV_API_TOKEN` está en el `.env` (o archivo).

```bash
TOK=$(grep -m1 '^MIRV_API_TOKEN=' .env | cut -d= -f2-)

# Público: dice si el guard está on y si esta petición está autenticada
curl -s http://localhost:8000/api/auth/status
# {"ok":true,"enabled":true,"authenticated":false,"source":"env","masked_token":"c142•••9ed9"}

# SIN token -> 401
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/api/skills        # 401

# CON header -> 200
curl -s -o /dev/null -w "%{http_code}\n" -H "X-MIRV-Token: $TOK" http://localhost:8000/api/skills  # 200

# LOGIN (endpoint público) -> suelta la cookie httpOnly mirv_token
curl -c /tmp/mirv.cookies -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" -d "{\"password\":\"$TOK\"}"
# {"ok":true,"enabled":true,"authenticated":true}

# Con la cookie -> 200
curl -b /tmp/mirv.cookies -o /dev/null -w "%{http_code}\n" http://localhost:8000/api/skills         # 200

# LOGOUT -> borra la cookie
curl -b /tmp/mirv.cookies -X POST http://localhost:8000/api/auth/logout
```

---

## 4. Smoke REST (con token)

```bash
TOK=$(grep -m1 '^MIRV_API_TOKEN=' .env | cut -d= -f2-)
H="X-MIRV-Token: $TOK"

curl -s -H "$H" http://localhost:8000/api/skills | python -c "import sys,json;print(len(json.load(sys.stdin)['skills']),'skills')"   # 93 skills
curl -s -H "$H" http://localhost:8000/api/router/routes | python -c "import sys,json;d=json.load(sys.stdin);print(len(d['routes']),'rutas |',d['fallbackId'])"   # 21 rutas | R0
curl -s -H "$H" http://localhost:8000/api/router/tool-index  | python -c "import sys,json;d=json.load(sys.stdin);print(d['total'],'tools |',d['detected_count'],'detectadas')"
curl -s -H "$H" -X POST http://localhost:8000/api/router/route -H "Content-Type: application/json" -d '{"hint":"analiza el APK y los JSON Web Tokens","lang":"es"}' | python -c "import sys,json;p=json.load(sys.stdin)['primary'];print(p['id'],p['label'],'->',p['skill'])"
# R5 JWT / tokens -> jwt   (o la móvil correspondiente tras empate por priority)

curl -s -H "$H" -o /dev/null -w "%{http_code}\n" http://localhost:8000/api/findings/stats   # 200
curl -s -H "$H" -o /dev/null -w "%{http_code}\n" http://localhost:8000/api/siem/stats        # 200
```

---

## 5. Terminal E2E (WebSocket /ws → SSH → kali-tools)

El proxy WS acepta primero un JSON de auth; después los mensajes raw van al
shell PTY de Kali. Con el guard activo, el handshake exige la cookie `mirv_token`.

Credenciales del contenedor kali (definidas en `docker-compose.yml`):
**host `kali-tools`, puerto `22`, user `root`, pass `mirv`**.

### 5.1 Manual — desde el navegador

1. Abre `http://localhost:8000` → pantalla **AUTH REQUIRED** → pega el token.
2. Tab **Terminal** → configura/o selecciona el perfil de conexión:
   `kali-tools` : `22` — user `root` — pass `mirv`.
3. Ejecuta en el terminal:
   ```bash
   whoami; hostname
   nmap --version | head -1
   python3 --version
   ```
   - Esperado: `root`, un hostname X, `Nmap version …`, `Python 3.11.…`.
   - El terminal muestra el banner de Kali + el aviso "Kali developers" y un
     prompt limpio `$ ` (Powerlevel10k desactivado en la conexión).

### 5.2 Automatizado — script

```bash
# websockets >= 14 requerido (ya está en requirements.txt)
PYTHONIOENCODING=utf-8 python backend/tests/manual_e2e_ws_kali.py
```

Salida esperada (validada 28 Sep 2026):

```
login HTTP 200 -> cookie mirv_token=OK
PASS handshake autenticado
PASS conexion SSH OK
PASS comando echo ejecutado
PASS whoami=root
PASS hostname=kali
PASS python3 disponible
PASS nmap instalado
PASS hashcat instalado
RESULTADO: OK
exit=0
```

Qué hace el script:
1. `POST /api/auth/login` → cookie `mirv_token`.
2. `websockets.connect(ws://localhost:8000/ws, additional_headers={"Cookie": …})`.
3. Envía `{"type":"auth","ip":"kali-tools","port":22,"user":"root","pass":"mirv"}`.
4. Manda `echo/whoami/hostname/os-release/python3/nmap/hashcat` sobre el PTY real
   y comprueba la salida (8 checks, `\r\n` de PTY tenido en cuenta).

Equivalente con `curl` (sin interacción, documental):

```bash
TOK=$(grep -m1 '^MIRV_API_TOKEN=' .env | cut -d= -f2-)
curl -c /tmp/mirv.cookies -X POST http://localhost:8000/api/auth/login \
     -H "Content-Type: application/json" -d "{\"password\":\"$TOK\"}" >/dev/null
curl -b /tmp/mirv.cookies http://localhost:8000/ws   # handshake WS (aunque curl 8.x
                                                     # necesite --ws / --ws-raw para hablar)
```

---

## 6. Migración de esquema (ejecutar una vez)

**Importante (detectado en verificación E2E en vivo, 28 Sep 2026):** la tabla
`findings` de la base real **no tenía** las columnas `assessment_id` /
`lifecycle_status` (error PostgREST `PGRST204`); el INSERT de findings devolvía
`503` y el `PATCH` de lifecycle `404`. Los tests no lo pillan porque mockean la
DB — solo se ve contra Supabase real. También faltaba la tabla `workspace_state`
(persistencia opt-in de assessments/assets/scheduler).

El repo ya está corregido (`backend/supabase_schema.sql`, idempotente). Para
aplicarlo a tu proyecto Supabase: **SQL Editor** (Dashboard → *SQL* → *New query*),
pega y ejecuta:

```sql
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assessment_id TEXT DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS lifecycle_status TEXT DEFAULT 'open';
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_lifecycle ON findings(lifecycle_status);

CREATE TABLE IF NOT EXISTS workspace_state (
    key TEXT PRIMARY KEY,
    value JSONB DEFAULT '{}',
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

Alternativa sin dashboard: añade a `.env` una `DATABASE_URL` directa de Postgres
(*Dashboard → Connect → Connection string*,
`postgresql://postgres.<ref>:<pass>@aws-0-<region>.pooler.supabase.com:6543/postgres`)
y ejecuta en local:

```bash
psql "$DATABASE_URL" -f backend/supabase_schema.sql
```

**Opción automática (recomendado):** helper incluido que intenta `/pg/query`
(si el proyecto lo expone), luego `DATABASE_URL` de `.env`, y si no hay credenciales
imprime el SQL + las instrucciones:

```bash
cd backend && pip install psycopg2-binary   # solo si no esta
python tests/manual_schema_migrate.py       # exit 0 = aplicado; exit 2 = falta credencial
```

> Nota (28 Sep 2026): `/pg/query` está deshabilitado en este proyecto; la
> migración se aplicó correctamente vía **SQL Editor** (paste de
> `supabase_schema.sql` + Run) y quedó **verificada en vivo**: `workspace_state`
> responde 200 y el round-trip de findings devuelve 201/200/200 (abajo).

Tras migrar, el round-trip de persistencia (abajo) devuelve `201`/`200`.

### 6.1 Round-trip de persistencia (Supabase real)

```bash
PYTHONIOENCODING=utf-8 python backend/tests/manual_e2e_supabase_roundtrip.py  # o:
# POST /api/findings  -> 201 + id
# PATCH /api/findings/{id} {"lifecycle_status":"verified"} -> 200
# GET  /api/findings  -> contiene el finding
# DELETE /api/findings/{id} -> 200
# assessment create -> POST /api/assessments -> 200; DELETE -> 200
# GET  /api/audit/stats -> total_events > 0
```

El script lee el token del `.env` de la raíz del repo; no es recolectado por
pytest (prefijo `manual_`).

Validado el 28 Sep 2026 (SQL Editor aplicado + verificación en vivo): creado 201,
lifecycle 200, apparece en GET, borrado 200, assessment create/delete 200, audit
actualizado. `workspace_state` presente (REST 200).

## 7. Seguridad

```bash
cd backend
bandit -r . -ll -ii -x tests || true    # severidad media+ ; exit 0 = sin hallazgos
safety check -r requirements.txt || true
node --check ../frontend/js/main.v2.js  # sintaxis JS del SPA
```

- CI hace exactamente esto en cada push: `lint` (bandit + safety) y `test`
  (suite completa). En el último push del Pack 9 los **4 workflows pasaron**:
  `lint`, `test`, `build-and-deploy`, `build-windows`.

## 8. Tests completos (local)

```bash
cd backend
PYTHONIOENCODING=utf-8 python -m pytest tests/ -k "not test_slow_hook" -q
# 4821 passed, 1 deselected   (los ~53 marcados @slow necesitan red/SSH externos)
```

## 9. Comprobaciones adicionales del stack (docker-compose)

Estados de health del contenedor real, **validados en vivo el 28 Sep 2026** contra
`mirv-backend` (compose, guard activo). Todo con `-H "X-MIRV-Token: $TOK"`:

| Endpoint | Respuesta esperada | Verificado |
|---|---|---|
| `GET /api/docker/status` | `ok:true`, `kali_running:true`, `backend_running:true`, 2 containers | ✅ |
| `POST /api/docker/start` | idempotente: ejecuta `compose -p proyectociber start kali-tools` vía socket → `exit 0` | ✅ |
| `GET /api/kali-mcp/status` | `ok:true, available:false` (contendor kali-MCP no desplegado) | ✅ |
| `GET /api/kali-mcp/tools` | `503` elegante `"kali-mcp not available"` (no es fallo) | ✅ |
| `GET /api/scheduler/status` | daemon 🟢 `mapped_tools` (nmap, gobuster, nikto, …) | ✅ |
| `GET /api/plugins/watcher/status` | `watching:true`, `plugin_count:1`, `auto_load_new:false`, watchdog | ✅ |
| `GET /api/pc-analyzer` | `grade D`: esperado en contenedor slim (sin GUI/ups/etc.) | ✅ |
| `GET /api/coverage/summary` `intelligence/watches` `assessments` `notifications/providers` `burp/status` `ctf/score` | estados vacíos correctos | ✅ |
| DNS+SSH directo backend→kali | `kali-tools→172.18.0.x`; paramiko root/mirv OK; nmap 7.99, hashcat v7.1.2 | ✅ |

Comando equivalente (dentro del backend):

```bash
docker exec mirv-backend python -c "
import socket,paramiko
print(socket.gethostbyname('kali-tools'))
c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('kali-tools',22,'root','mirv',timeout=8,look_for_keys=False,allow_agent=False)
print(c.exec_command('nmap --version|head -1')[1].read().decode().strip())
"
```

## 10. Troubleshooting

| Síntoma | Causa / fix |
|---|---|
| `failed to connect to the docker API at npipe…` | Docker Desktop se cayó. Relanza `C:\Program Files\Docker\Docker\Docker Desktop.exe` y espera `docker info` (WSL tarda 30–60 s). |
| `Empty reply from server` justo tras recrear | El backend aún está en el arranque (tablas Supabase). Espera ~40 s y reintenta `curl /api/health`. |
| 401 en `/api/*` al probar con curl | Falta el token: añade `-H "X-MIRV-Token: <token>"`. |
| 401/1008 al abrir WebSocket | Falta la cookie `mirv_token` (haz login). |
| El terminal no conecta | El perfil debe apuntar a `kali-tools:22` (el proxy corre DENTRO del contenedor; `127.0.0.1` no resuelve ahí). |
| Cambios de backend/frontend no se ven | `docker compose -p proyectociber up -d --build` (reconstruye la imagen). |
| Tests locales dan 401 en masa | La suite limpia `MIRV_API_TOKEN(_FILE)` por test (autouse en conftest) → es independiente del `setx` del host. |
| `POST /api/findings` → 503 / `PATCH lifecycle` → `PGRST204` | Esquema sin migrar: aplica la sección 6 (SQL Editor o `DATABASE_URL` + psql). Los tests no lo detectan (mockean la DB); solo aparece en E2E real. |

## 11. Pack 10 — Code Agent + Phishing Sim (verificación rápida)

Validado en vivo el **30 Sep 2026** (host local, opencode v1.18.33 instalado). El guard
de `/api/*` exige token; las páginas públicas `/phishing/*` NO.

```bash
cd backend
PYTHONIOENCODING=utf-8 python tests/manual_e2e_opencode.py        # status + run real (77% de cobertura del pack)
PYTHONIOENCODING=utf-8 python tests/manual_e2e_supabase_roundtrip.py
```

| Endpoint | Respuesta esperada | Verificado |
|---|---|---|
| `GET /api/opencode/status` | 200 `{installed:true, version, allowed_agents:[...]}` | ✅ |
| `POST /api/opencode/run {prompt,agent:'plan',pure:true}` | 200, `ok:true`, `exit_code:0`, stdout redactado/truncado | ✅ ("Hola 👋") |
| `POST /api/findings` conceptual del submit | la subida crea finding `phishing-awareness` + evento SIEM + audit — ver `test_api_phishing_full_flow` | ✅ (TestClient) |
| `GET /phishing/{cid}` (pública, sin token) | 200 HTML o 410 si caducó; click count += 1 | ✅ |
| `POST /phishing/{cid}/submit` | 200 HTML de resultado; credenciales solo `sha256[:16]`, nunca en claro | ✅ |
| Borrado limpio end-to-end | nada roto en la suite: `4850 passed, 17 failed` (los 17 son `example.com` en vivo, sin red externa) | ✅ |

## 12. Pack 11 — Lab Sessions + write-up dark mode (verificación rápida)

Portado de `afsh4ck/exploitpath` (máquinas→sesiones→evidencias, detección de
flags, IA sobre el historial completo, write-up dark-mode). Todo con
`-H "X-MIRV-Token: $TOK"`. El registro es en memoria + persistencia opt-in
(`MIRV_PERSIST_WORKSPACE=1`, tabla `workspace_state`, clave `lab_sessions`).

```bash
cd backend
PYTHONIOENCODING=utf-8 python -m pytest tests/test_flag_detection.py tests/test_lab_sessions.py \
    tests/test_lab_writeup.py tests/test_labs_endpoints.py -q
# 89 passed
```

| Paso | Petición | Respuesta esperada | Verificado |
|---|---|---|---|
| Crear máquina | `POST /api/labs/machines {"name":"Academy","operating_system":"linux"}` | 200 con `id`, `status:"active"` | ✅ |
| Crear sesión | `POST /api/labs/sessions {"machine_id":…,"title":"Recon"}` | 200 con `phase:"recon"` | ✅ |
| Añadir evidencia con flag | `POST /api/labs/sessions/{sid}/steps {"command":"cat /home/x/user.txt","output":"<32hex>"}` | `step.detected_flag_type:"user"`, `session.phase:"foothold"` | ✅ |
| Editar evidencia (integridad) | `PUT /api/labs/steps/{id} {"command":"ls"}` | flags recomputados → `user_flag_captured:false`, análisis obsoletos invalidados | ✅ |
| Análisis IA | `POST /api/labs/sessions/{sid}/analyze` | JSON `{analysis:{current_phase,summary,evidence,safe_commands,rationale,cautions}}` | ✅ (mock) |
| Write-up narrado | `POST /api/labs/sessions/{sid}/writeup` | `steps:[{stepId,title,description}]` | ✅ (mock) |
| Export HTML/PDF | `POST /api/labs/sessions/{sid}/export {"format":"html"\|"pdf","narrative":[…]}` | HTML `#090d14`/`#9FEF00` escapado · PDF `%PDF` dark con tarjetas de terminal | ✅ |
| Export/Import estado | `GET /api/labs/export` → `POST /api/labs/import {"machines":[…],"replace":true}` | round-trip de máquinas/sesiones/evidencias/análisis | ✅ |
| Suite completa | `pytest tests/ -k "not test_slow_hook"` | `4938 passed, 17 failed` (los 17 = `example.com` sin red) | ✅ |
## 13. Pack 12 — Code Agent multi-proveedor (opencode · Claude Code)

Puente headless multi-agente (`backend/agent_bridge.py`). La imagen
`mirv-backend` instala **opencode** y **Claude Code** (nativos, fail-safe).

```bash
TOK=$(grep '^MIRV_API_TOKEN=' .env | cut -d= -f2-)
curl -s -H "X-MIRV-Token: $TOK" localhost:8000/api/agents/status | python -m json.tool
```

| Paso | Petición | Respuesta esperada | Verificado |
|---|---|---|---|
| Estado multi-proveedor | `GET /api/agents/status` | `providers.{opencode,claude,codex}` con `installed`/`version`/`busy` | ✅ |
| Run opencode | `POST /api/agents/run {"provider":"opencode","prompt":"…","agent":"plan"}` | 200 `ok:true`, `exit_code:0`, stdout redactado | ✅ ("ok opencode") |
| Run Claude Code | `POST /api/agents/run {"provider":"claude","prompt":"…","timeout":30}` | 200 si hay `ANTHROPIC_API_KEY`; si no, `exit_code:1` + `"Not logged in"` (degradación limpia) | ⚠️ requiere `ANTHROPIC_API_KEY` |
| codex (reservado) | `POST /api/agents/run {"provider":"codex"}` | error `not implemented` | ✅ |
| prompt vacío | `POST /api/agents/run {"prompt":""}` | 400 | ✅ |
| cwd fuera del root | `{"cwd":"/etc"}` | error `cwd escapes MIRV_OPENCODE_ROOT` | ✅ |
| Tests | `pytest tests/test_agent_bridge.py -q` | `24 passed` | ✅ |

> Claude Code en Docker: define `ANTHROPIC_API_KEY` en `.env` (la suscripción
> Pro/Max no se puede hornear en la imagen). `docker-compose.yml` ya la reenvía.

## 14. Pack 18 — LLM Security Scanner (verificación rápida)

Port de `praetorian-inc/augustus` a `backend/llm_scanner.py` (23 probes / 9 familias,
22 detectores, 8 buffs, Crescendo-lite). El modo **`stub` es determinista y sin red**
→ ideal para verificar el pipeline dentro de Docker. Los modos `self`/`openai` usan
la config del tab AI (API key). Todo con `-H "X-MIRV-Token: $TOK"`.

```bash
TOK=$(grep '^MIRV_API_TOKEN=' .env | cut -d= -f2-); H="X-MIRV-Token: $TOK"

curl -s -H "$H" localhost:8000/api/llm/probes | python -c "import sys,json;d=json.load(sys.stdin);print(d['total'],'probes',len(d['families']),'familias')"   # 23 probes 9 familias

# Scan determinista con stub (sin red) + push de findings vuln a DB+SIEM+audit
curl -s -H "$H" -X POST localhost:8000/api/llm/scan -H 'Content-Type: application/json' \
  -d '{"target":{"mode":"stub"},"probe_ids":["leak.ApiKey"],"create_findings":true}' | python -m json.tool
```

| Paso | Petición | Respuesta esperada | Verificado |
|---|---|---|---|
| Catálogo de probes | `GET /api/llm/probes` | `total:23`, 9 familias | ✅ |
| Scan stub (sin guardar) | `POST /api/llm/probe {"target":{"mode":"stub"},"probe_ids":["leak.ApiKey"]}` | `ok:true`, `report` con attempts | ✅ |
| Scan stub + push | `POST /api/llm/scan {...,"create_findings":true}` | `findings.pushed >= 1`; finding `tool=llm-scanner`, `service=llm` (201 en Supabase) + SIEM + audit | ✅ |
| Listar resultados | `GET /api/llm/results` | `reports:[…]`, `max_reports:20` (registry LRU) | ✅ |
| Detalle | `GET /api/llm/results/{id}` | `report` completo (404 si no existe) | ✅ |
| Push de un guardado | `POST /api/llm/results/{id}/findings` | `pushed` count | ✅ |
| Limpiar | `DELETE /api/llm/results` | `cleared:n` | ✅ |
| Tests | `pytest tests/test_llm_scanner.py tests/test_llm_endpoints.py -q` | `48 passed` | ✅ |

> `mode=self` reutiliza `_call_llm_sync` (config AI del usuario); `mode=openai` usa
> `base_url`+`api_key`; `mode=stub` es dry-run determinista. SIEM source `llm` en `_VALID_SOURCES`.
> Los resultados viven en un registry **en memoria** (LRU 20) — no hay tablas nuevas en Supabase.

## 15. Pack 19 — Android Pentesting Skill + wireless-audit host-only (verificación rápida)

Skill `android-pentesting` vendorizada (DragonJAR, **Apache-2.0**) + skill doc-only
`wireless-audit` (flujo aircrack-ng, referencia airgorah) + módulo `backend/wireless_analyzer.py`
(SSH a un Kali **físico**). El flujo real de Wi-Fi **no funciona en Docker** (sin adaptador
en monitor mode) pero la API **degrada elegante**. Router `R39 wireless-audit` + `R40 android-pentesting`.

```bash
TOK=$(grep '^MIRV_API_TOKEN=' .env | cut -d= -f2-); H="X-MIRV-Token: $TOK"

# Skills (113 total; las 2 nuevas presentes)
curl -s -H "$H" localhost:8000/api/skills | python -c "import sys,json;n=[s['name'] for s in json.load(sys.stdin)['skills']];print(len(n),'android-pentesting' in n,'wireless-audit' in n)"

# Router: 41 rutas + benchmark 105/105
curl -s -H "$H" localhost:8000/api/router/routes    | python -c "import sys,json;print(len(json.load(sys.stdin)['routes']),'rutas')"
curl -s -H "$H" localhost:8000/api/router/benchmark | python -c "import sys,json;d=json.load(sys.stdin);print(d['passed'],'/',d['total'],'failed',d['failed'])"
curl -s -H "$H" -X POST localhost:8000/api/router/route -H 'Content-Type: application/json' -d '{"hint":"auditar red wifi con aircrack ng monitor mode y handshake"}' | python -c "import sys,json;print(json.load(sys.stdin)['primary']['id'])"   # R39

# Wireless (degradación elegante sin host físico):
curl -s -H "$H" localhost:8000/api/wireless/sessions
curl -s -H "$H" -X POST localhost:8000/api/wireless/host/check
```

| Paso | Petición | Respuesta esperada | Verificado |
|---|---|---|---|
| Skills | `GET /api/skills` | 113 total; `android-pentesting` + `wireless-audit` presentes | ✅ |
| Cargar skill android | `POST /api/skills/android-pentesting/load` → `GET .../render` | `enabled:true`, `body` no vacío | ✅ |
| Router rutas | `GET /api/router/routes` | 41 rutas (R0–R40) | ✅ |
| Benchmark | `GET /api/router/benchmark` | `105/105`, `failed:0` | ✅ |
| Ruteo Wi-Fi | `POST /api/router/route {"hint":"…wifi…aircrack…"}` | primary `R39` wireless-audit | ✅ |
| Ruteo Android | `POST /api/router/route {"hint":"…MASVS/MASTG…"}` | primary `R40` android-pentesting | ✅ |
| No regresión APK+frida | `POST /api/router/route {"hint":"reverse apk … frida"}` | primary `R10` apk-reverse | ✅ |
| Wireless list/create | `GET/POST /api/wireless/sessions` | `ok:true`, sesión con `sid` / `interface:wlan0mon` | ✅ |
| Wireless host/check | `POST /api/wireless/host/check` | `ok:true`, `rc:1`, `wireless host not configured` (sin host) | ✅ |
| Wireless host/exec | `POST /api/wireless/host/exec {"cmd":""}` | `400` | ✅ |
| Tests | `pytest tests/test_wireless_analyzer.py -q` | `19 passed` | ✅ |
| Docker | `docker compose -p proyectociber up -d --build` | `mirv-backend` healthy, `supabase:true` | ✅ |

> **Verificación real (fuera de Docker):** requiere un **Kali físico con adaptador Wi-Fi
> en monitor mode**. Exporta `MIRV_WIRELESS_HOST/PORT/USER/KEY/PASS` y usa
> `/api/wireless/host/exec` con el flujo airmon-ng → airodump-ng → aireplay-ng → aircrack-ng
> (ver `backend/skills/wireless-audit/SKILL.md`). **Solo en alcance autorizado.** In-memory,
> sin tablas nuevas en Supabase.

## 16. Pack 20 — Privacy / egress-IP (proxy en el host Kali)

Gestor de **proxies SOCKS5/SOCKS4/HTTP(S)** aplicados en el **host de herramientas** (Kali vía
SSH compartido) para ocultar la IP durante auditorías autorizadas. Escribe
`~/.proxychains/proxychains4.conf` + `~/.config/mirv/proxy.env` (+ bloque idempotente en
`/etc/environment`) y verifica la IP pública directa vs con proxy. Todo con `-H "X-MIRV-Token: $TOK"`.

```bash
TOK=$(grep '^MIRV_API_TOKEN=' .env | cut -d= -f2-); H="X-MIRV-Token: $TOK"

# Crear un perfil de proxy (password se enmascara en la respuesta)
curl -s -H "$H" -X POST localhost:8000/api/privacy/proxies -H 'Content-Type: application/json' \
  -d '{"name":"proton","kind":"socks5","host":"10.2.0.1","port":1080,"username":"u","password":"secret"}'

# Activar (escribe proxychains + env en el Kali y comprueba la IP vía proxy)
curl -s -H "$H" -X POST localhost:8000/api/privacy/proxies/<PID>/activate | python -m json.tool

# Estado: IP directa vs IP con proxy
curl -s -H "$H" localhost:8000/api/privacy/status | python -m json.tool

# Desactivar y limpiar
curl -s -H "$H" -X POST localhost:8000/api/privacy/deactivate
```

| Paso | Petición | Respuesta esperada | Verificado |
|---|---|---|---|
| Resumen | `GET /api/privacy/summary` | `ok:true`, `profiles`, `kinds` | ✅ |
| Crear (masking) | `POST /api/privacy/proxies {password:"secret"}` | `201`, `password:"**cret"`, `has_password:true` | ✅ |
| Validación | `POST /api/privacy/proxies {kind:"bogus"}` | `400` | ✅ |
| Listar / Detalle / Borrar | `GET /api/privacy/proxies`, `GET/DELETE /api/privacy/proxies/{pid}` | lista / `proxy` / `deleted` (404 si falta) | ✅ |
| Activar | `POST /api/privacy/proxies/{pid}/activate` | `ok:true` (aplica proxychains+env en el host) | ✅ |
| Activar inexistente | `POST /api/privacy/proxies/nope/activate` | `404` | ✅ |
| Desactivar | `POST /api/privacy/deactivate` | `cleared:true` | ✅ |
| IP directa | `GET /api/privacy/ip` | `ip` del host (`api.ipify.org`/`ifconfig.me`) | ✅ |
| IP vía proxy | `GET /api/privacy/ip?via_proxy=true` | `proxychains4 -q curl …`, `via_proxy:true` | ✅ |
| Estado | `GET /api/privacy/status` | `active`, `direct`, `proxied` (null si no hay activo) | ✅ |
| Degradación | sin `KALI_IP`/`MIRV_PRIVACY_HOST` | `privacy host not configured` (no rompe) | ✅ |
| Tests | `pytest tests/test_privacy.py -q` | `64 passed` | ✅ |
| Docker | `docker compose -p proyectociber up -d --build` | `mirv-backend` healthy, `supabase:true` | ✅ |

> **Uso real en el Kali:** exporta `KALI_IP/USER/PASS` (o `MIRV_PRIVACY_*`) y actívalo desde el
> tab **Privacy**. Envuelve cada tool con `proxychains4 -q <tool> …` (el conf queda escrito), o
> usa las variables `http_proxy`/`all_proxy` del `~/.config/mirv/proxy.env`. La **VPN real
> (WireGuard/OpenVPN)** vive en el Pack 21 (§17): requiere `NET_ADMIN` + `/dev/net/tun`. In-memory +
> persistencia opt-in (`MIRV_PERSIST_WORKSPACE=1`, key `privacy`), sin tablas nuevas en Supabase.

## 17. Pack 21 — VPN real (WireGuard / OpenVPN) en el host Kali

Túneles **WireGuard / OpenVPN** aplicados en el **host de herramientas** (Kali vía SSH compartido,
mismo runner que Pack 20) para enrutar **todo** el tráfico de auditoría a nivel de red (no por-tool
como proxychains). WireGuard escribe `/etc/wireguard/<iface>.conf` y corre `wg-quick up|down`;
OpenVPN escribe `/etc/openvpn/client/<name>.conf` y lanza `openvpn --daemon` (pid en
`/run/mirv-vpn-<name>.pid`). Las **claves privadas se redactan** en todas las respuestas.
Todo con `-H "X-MIRV-Token: $TOK"`.

```bash
TOK=$(grep '^MIRV_API_TOKEN=' .env | cut -d= -f2-); H="X-MIRV-Token: $TOK"

# Crear un perfil WireGuard (config enmascarada en la respuesta)
curl -s -H "$H" -X POST localhost:8000/api/vpn/profiles -H 'Content-Type: application/json' \
  -d '{"name":"e2e","protocol":"wireguard","config":"[Interface]\nPrivateKey = ...\nAddress = 10.77.0.2/24\n[Peer]\n..."}'

# Activar (wg-quick up en el Kali) / desactivar (wg-quick down + borra config)
curl -s -H "$H" -X POST localhost:8000/api/vpn/profiles/<VID>/activate | python -m json.tool
curl -s -H "$H" -X POST localhost:8000/api/vpn/deactivate | python -m json.tool

# Estado: perfil activo + IP de salida actual (transparente con túnel)
curl -s -H "$H" localhost:8000/api/vpn/status | python -m json.tool
```

| Paso | Petición | Respuesta esperada | Verificado |
|---|---|---|---|
| Resumen | `GET /api/vpn/summary` | `ok:true`, `profiles`, `protocols`, `active` | ✅ |
| Crear (masking) | `POST /api/vpn/profiles {config:"...PrivateKey = ..."}` | `201`, `config` con `PrivateKey = ***`, `active:false` | ✅ |
| Validación protocolo | `POST /api/vpn/profiles {protocol:"pptp"}` | `400` (`invalid protocol`) | ✅ |
| Config vacía | `POST /api/vpn/profiles {config:""}` | `400` (`empty config`) | ✅ |
| Listar / Detalle / Borrar | `GET /api/vpn/profiles`, `GET/DELETE /api/vpn/profiles/{vid}` | lista / `profile` / `deleted` (`404` si falta) | ✅ |
| Activar | `POST /api/vpn/profiles/{vid}/activate` | `ok:true` (interfaz `e2e` 10.77.0.2/24 en Kali, `wg show` OK) | ✅ |
| Activar inexistente | `POST /api/vpn/profiles/nope/activate` | `404` | ✅ |
| Desactivar | `POST /api/vpn/deactivate` | `cleared:true` (túnel abajo + config borrada) | ✅ |
| IP de salida | `GET /api/vpn/ip` | `ip` actual (egress del túnel si está activo), `via_vpn` | ✅ |
| Estado | `GET /api/vpn/status` | `active`, `current_ip`, `profiles`, `protocols` | ✅ |
| Degradación | sin `KALI_IP`/`MIRV_PRIVACY_HOST` | `not configured` / `vpn host runner unavailable` (no rompe) | ✅ |
| Tests | `pytest tests/test_vpn.py -q` | `68 passed` | ✅ |
| Docker | `docker compose -p proyectociber up -d` | `mirv-backend` healthy, `supabase:true` | ✅ |

> **Requisitos:** `cap_add: NET_ADMIN` + `/dev/net/tun` en el servicio `kali-tools`
> (`docker-compose.yml`; el entrypoint de `docker/kali-mcp.Dockerfile` crea `/dev/net/tun` si falta) y
> paquetes `wireguard-tools` + `openvpn` en la imagen Kali. **Ojo:** `openresolv` y `resolvconf` no
> pueden coexistir (conflicto de asignación al instalar) — instalar **solo `openresolv`**. In-memory +
> persistencia opt-in (`MIRV_PERSIST_WORKSPACE=1`, key `vpn`), sin tablas nuevas en Supabase.
> **Solo en alcance autorizado.**
