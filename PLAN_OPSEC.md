# PLAN.md — OPSEC Levels (Silent / Covert / Loud)

## Objetivo

Añadir 3 modos de Operations Security que controlan el "ruido" que generan las herramientas en el target.

## Especificación

### Niveles

| Nivel | Color | Comportamiento |
|-------|-------|----------------|
| 🟢 Silent | `#3b8f8a` | Solo herramientas pasivas. Modifica comandos activos para ser stealth. Bloquea las más ruidosas. |
| 🟡 Covert | `#d4a843` | Permite herramientas activas pero con rate limiting y timing bajo. Warning al lanzar las más ruidosas. |
| 🔴 Loud | `#dc2828` | Todo permitido, máxima velocidad. Comportamiento actual (default). |

### Mapeo silencioso → sigiloso (por tool)

| Tool | Silent | Covert | Loud |
|------|--------|--------|------|
| nmap | `nmap -sS -T2 --max-rate 50 -sV` (sin -A, sin -O) | `nmap -sS -T3 -sV --max-rate 200` | `nmap -p- -sV -sC -O -A --min-rate=1000 -T4` (actual) |
| masscan | ❌ BLOQUEAR | `masscan -p1-65535 --rate=100 --wait 5` | `masscan -p1-65535 --rate=1000` (actual) |
| gobuster | `gobuster dir -t 5 -delay 500ms` | `gobuster dir -t 20` | `gobuster dir -t 50` (actual) |
| ffuf | `-t 2 -rate 10` | `-t 10 -rate 50` | actual |
| nikto | ❌ BLOQUEAR (demasiado ruidoso) | `-evasion 1 -timeout 5` | actual |
| hydra | ❌ BLOQUEAR | `-t 1 -W 1` | `-t 4` |
| nuclei | ❌ BLOQUEAR | `-rate-limit 10 -c 5` | actual |
| whatweb | `-a 1` (passive, 1 request) | `-a 3` (actual) | `-a 3` |
| wpscan | ❌ BLOQUEAR | `--stealthy` | `--enumerate u,vp` |
| dirb | `dirb -r -S` (recursive off, silent) | `-r` | actual |

### Frontend (implementación)

1. **Header**: 3 botones toggle al lado del badge de Scope, o dentro del mismo modal de Settings.
2. **Persistencia**: `localStorage.setItem('mirv_opsec', 'silent|covert|loud')`
3. **`launchTool()`**: al construir `finalCommand`, consultar `window.opsecLevel` y aplicar transformaciones:
   - Si tool está en `BLOCKED_IN_SILENT` y nivel = silent → `appendOutput('[OPSEC] ⛔ Blocked: ' + tool + ' is too noisy for Silent mode')` y `return`
   - Si tool está en `BLOCKED_IN_COVERT` y nivel = covert → warning (toast) pero permitir
   - Aplicar el mapeo de flags del nivel correspondiente
4. **Badge en header**: indicador visual del nivel activo (🟢 Silent / 🟡 Covert / 🔴 Loud)

### Backend (mínimo, opcional)

- `GET /api/opsec` → devuelve mapeo de modificaciones (para que AI lo sepa)
- `POST /api/opsec/apply` → `{tool, command, level}` → `{modified_command, blocked, reason}`
- Esto permite que MCP Server y AI Suggestions respeten OPSEC

### Archivos a modificar

- `frontend/index.html` — Selector OPSEC en header + modal
- `frontend/js/main.v2.js` — `window.opsecLevel`, transformaciones en `launchTool`, persistencia
- `backend/main.py` — endpoint `/api/opsec/apply` (opcional)
- `ROADMAP.md` — marcar P3 OPSEC como ✅