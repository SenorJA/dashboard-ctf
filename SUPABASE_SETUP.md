# 🗄️ MIRV — Guía de conexión desde móvil + Setup Supabase

## 📱 Conectar desde el móvil

### Requisitos
- PC y móvil en la **misma red WiFi**
- Servidor MIRV arrancado en el PC

### Paso 1 — Arrancar el servidor
Abre una terminal en la carpeta del proyecto y ejecuta:

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

> ⚠️ El `--host 0.0.0.0` es **obligatorio** para que se vea desde el móvil. Sin eso solo funciona en el propio PC.

### Paso 2 — Encontrar la IP del PC
En el PC, abre `cmd` y ejecuta:

```cmd
ipconfig
```

Busca la línea que diga **"Dirección IPv4"** en el adaptador **"Wi-Fi"** o **"Ethernet"**. Normalmente empieza por `192.168.`. Ejemplo:

```
Dirección IPv4. . . . . . . . . . . . . . : 192.168.8.123
```

### Paso 3 — Conectar desde el móvil
Abre el navegador del móvil y escribe:

```
http://<IP_DEL_PC>:8000
```

Ejemplo:

```
http://192.168.8.123:8000
```

### Solución de problemas

| Problema | Causa | Solución |
|----------|-------|----------|
| `ERR_CONNECTION_REFUSED` | El servidor no está corriendo | Ejecuta el comando del Paso 1 |
| `ERR_CONNECTION_TIMED_OUT` | IP incorrecta o no misma WiFi | Verifica IP con `ipconfig` y que ambos estén en la misma red |
| `ERR_CONNECTION_REFUSED` aunque el server esté running | El servidor está en `127.0.0.1` en vez de `0.0.0.0` | Asegúrate de usar `--host 0.0.0.0` al arrancar |
| No carga la página | Firewall de Windows bloqueando | Abre `cmd` como **Administrador** y ejecuta: `netsh advfirewall firewall add rule name="MIRV" dir=in action=allow protocol=TCP localport=8000` |

> 💡 La IP puede cambiar cada vez que el router se reinicia. Si quieres una IP fija, configura una IP estática en Windows o usa Cloudflare Tunnel.

---

## 🗄️ Configurar Supabase (crear tablas)

### Paso 1 — Abrir el SQL Editor
Haz clic en este enlace:

👉 **[Abrir Supabase SQL Editor](https://supabase.com/dashboard/project/klkbbyqbdmuxovpbmple/sql/new)**

(O ve al Dashboard de Supabase → Tu proyecto → **SQL Editor** → **New Query**)

### Paso 2 — Pegar el SQL
Copia y pega TODO el contenido de `backend/supabase_schema.sql` en el editor.

O copia directamente desde aquí:

```sql
-- ════════════════════════════════════════════════════════════════
--  MIRV — Full Schema (17 tablas)
-- ════════════════════════════════════════════════════════════════

-- ── SSH Connection Profiles ──
CREATE TABLE IF NOT EXISTS ssh_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── RCE Scripts ──
CREATE TABLE IF NOT EXISTS scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    language TEXT DEFAULT 'bash',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Scan Reports ──
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    title TEXT DEFAULT '',
    target TEXT DEFAULT '',
    raw_output TEXT DEFAULT '',
    parsed_data JSONB DEFAULT '{}',
    format TEXT DEFAULT 'md',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Hak5 Payloads ──
CREATE TABLE IF NOT EXISTS hak5_payloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device TEXT NOT NULL,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── App Settings ──
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Uploaded Files Metadata ──
CREATE TABLE IF NOT EXISTS uploaded_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    mime_type TEXT DEFAULT 'application/octet-stream',
    storage_path TEXT NOT NULL,
    public_url TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ════════════════════════════════════════════════════════════════
--  FINDINGS
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool TEXT NOT NULL,
    target TEXT DEFAULT '',
    type TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    title TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    port TEXT DEFAULT '',
    protocol TEXT DEFAULT '',
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    status INTEGER DEFAULT 0,
    path TEXT DEFAULT '',
    raw TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  CREDENTIALS
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS credentials (
    uuid UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    type VARCHAR(20) NOT NULL DEFAULT 'password',
    target VARCHAR(255) NOT NULL,
    username VARCHAR(255) DEFAULT '',
    password TEXT DEFAULT '',
    hash TEXT DEFAULT '',
    token TEXT DEFAULT '',
    service VARCHAR(100) DEFAULT '',
    port VARCHAR(10) DEFAULT '',
    source VARCHAR(100) DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_credentials_target ON credentials(target);
CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);

-- ════════════════════════════════════════════════════════════════
--  CTF CHALLENGES
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ctf_challenges (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT DEFAULT '',
    flags TEXT DEFAULT '',
    points INTEGER DEFAULT 100,
    target VARCHAR(255) DEFAULT '',
    hints TEXT DEFAULT '',
    difficulty VARCHAR(20) DEFAULT 'medium',
    solved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ctf_category ON ctf_challenges(category);
CREATE INDEX IF NOT EXISTS idx_ctf_solved ON ctf_challenges(solved);

-- ════════════════════════════════════════════════════════════════
--  CTF SOLVES
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ctf_solves (
    id SERIAL PRIMARY KEY,
    challenge_id INTEGER REFERENCES ctf_challenges(id),
    flag_value TEXT NOT NULL,
    solved_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ctf_solves_challenge ON ctf_solves(challenge_id);

-- ════════════════════════════════════════════════════════════════
--  MOBILE APK ANALYSES
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mobile_apks (
    apk_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    package TEXT DEFAULT '',
    version_name TEXT DEFAULT '',
    version_code TEXT DEFAULT '',
    min_sdk TEXT DEFAULT '',
    target_sdk TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    md5 TEXT DEFAULT '',
    sha256 TEXT DEFAULT '',
    findings JSONB DEFAULT '[]',
    summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}',
    permissions JSONB DEFAULT '[]',
    components JSONB DEFAULT '{}',
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mobile_created ON mobile_apks(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  FORENSICS EVIDENCE
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS forensics_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    file_type TEXT DEFAULT '',
    category TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    md5 TEXT DEFAULT '',
    sha256 TEXT DEFAULT '',
    analysis JSONB DEFAULT '{}',
    findings JSONB DEFAULT '[]',
    summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}',
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_forensics_category ON forensics_evidence(category);
CREATE INDEX IF NOT EXISTS idx_forensics_created ON forensics_evidence(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  MISSION HISTORY
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mission_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    os_detected TEXT DEFAULT '',
    tools_used JSONB DEFAULT '[]',
    findings_count INT DEFAULT 0,
    findings_summary JSONB DEFAULT '[]',
    plan_steps INT DEFAULT 0,
    success_score INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mission_history_target ON mission_history(target);

-- ════════════════════════════════════════════════════════════════
--  SCOPE EVENTS
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scope_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    tool TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    mode TEXT DEFAULT 'warn',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scope_events_target ON scope_events(target);
CREATE INDEX IF NOT EXISTS idx_scope_events_created ON scope_events(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  SWARM SESSIONS
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS swarm_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    mode TEXT DEFAULT 'auto',
    status TEXT DEFAULT 'running',
    phases JSONB DEFAULT '[]',
    total_findings INT DEFAULT 0,
    report_id UUID REFERENCES reports(id),
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_swarm_target ON swarm_sessions(target);
CREATE INDEX IF NOT EXISTS idx_swarm_status ON swarm_sessions(status);

-- ════════════════════════════════════════════════════════════════
--  MISSION PLANS
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mission_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    name TEXT DEFAULT '',
    steps JSONB DEFAULT '[]',
    total_steps INT DEFAULT 0,
    completed_steps INT DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_plans_target ON mission_plans(target);
CREATE INDEX IF NOT EXISTS idx_plans_status ON mission_plans(status);

-- ════════════════════════════════════════════════════════════════
--  APP CREDENTIALS (secretos: API keys, tokens)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS app_credentials (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Paso 3 — Ejecutar
Haz clic en **▸ Run** o pulsa `Ctrl+Enter`.

### Paso 4 — Verificar
Vuelve al dashboard y recarga la página (`F5`). Los errores de "404 Not Found" en consola deberían desaparecer.

---

## 🚀 Comandos rápidos

```bash
# Arrancar servidor (accesible desde móvil)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Arrancar solo local
uvicorn backend.main:app --reload

# Ver IP del PC
ipconfig | findstr "IPv4"

# Abrir firewall si no funciona desde móvil (cmd como Admin)
netsh advfirewall firewall add rule name="MIRV" dir=in action=allow protocol=TCP localport=8000
```
