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
(*Dashboard → Connect → Connection string*, `postgresql://postgres.<ref>:<pass>@aws-0-<region>.pooler.supabase.com:6543/postgres`) y ejecuta en local:

```bash
psql "$DATABASE_URL" -f backend/supabase_schema.sql
```

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

Validado el 28 Sep 2026 (tras corregir el esquema): creado 201, lifecycle 200,
apparece en GET, borrado 200, assessment create/delete 200, audit actualizado.

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