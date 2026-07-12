# PLAN.md — Self-Improvement Loop

## Objetivo

M.I.R.V. aprende de misiones pasadas para mejorar las sugerencias de IA basándose en qué funcionó antes.

## Concepto

```
Misión 1: Target A (Apache 2.4.49, puerto 80)
  → nmap → 80 → nikto → XSS → writeup
  ↓ Guardar: target, findings, plan, success_score, tools_used

Misión 2: Target B (Apache 2.4.49, puerto 80)
  ↓ IA recuerda: "en 3 misiones con Apache 2.4.49, searchsploit + nuclei -id CVE-2021-41773 funcionó"
  ↓ Sugerencia: "Prueba searchsploit 'apache 2.4.49' → nuclei -id CVE-2021-41773"
```

## Especificación

### Tabla `mission_history` (Supabase)

```sql
CREATE TABLE IF NOT EXISTS mission_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,            -- target host
    os_detected TEXT,                 -- OS o tecnología detectada
    tools_used JSONB DEFAULT '[]',   -- [{tool: 'nmap', command: '...', useful: true}]
    findings_count INT DEFAULT 0,
    findings_summary JSONB,           -- top 5 findings (severity, tool, title)
    plan_steps INT DEFAULT 0,
    success_score INT DEFAULT 0,      -- 0-100 (findings_count * severity_weight)
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Backend

**Nuevo archivo `backend/mission_store.py`:**
- `save_mission(data: dict) → dict` — guarda una misión completada
- `list_missions(limit=50, target=None) → list[dict]`
- `find_similar(target_os: str, tools: list) → list[dict]` — busca misiones con mismo OS/tech
- `get_suggestion_context(current_findings: list) → str` — genera texto de contexto para IA con misiones similares

**Endpoints en `main.py`:**
- `POST /api/missions/save` — recibe misión completada
- `GET /api/missions` — lista historial
- `GET /api/missions/similar` — `{target_os, findings_types}` → misiones similares
- `DELETE /api/missions/{id}` — borrar

**Modificar `/api/suggest`:**
- Antes de pasar al LLM, busca misiones similares vía `find_similar()`
- Inyecta contexto: "Misiones previas similares: ...\n Qué funcionó: ..."
- El LLM genera sugerencias informadas por el historial

### Frontend

**Nueva pestaña "Missions" o sección en Op Admiral:**
- Lista de misiones pasadas (target, fecha, score, findings_count)
- Click en misión → ver detalles (tools_used, findings_summary, plan)
- Botón "End Mission" → cuando terminas, guarda misión actual:
  - Recoge `findings` actuales + `Op Admiral` plan + OS detectado (de nmap findings)
  - Calcula `success_score` = sum(findings.score) where severity
  - POST a `/api/missions/save`

**El "End Mission" puede ser:**
- Botón en Op Admiral: "💾 Save Mission to History"
- Auto-guardar cuando usuario cambia de target (si hubo findings)

### Flujo de suggestions mejorado

```
1. User tiene findings: [Apache 2.4.49, puerto 80, Country UK]
2. User pulsa "🔍 Suggest"
3. Backend GET /api/missions/similar?os=Apache 2.4.49
4. Backend encuentra 3 misiones similares:
   - Mission #1: target A → searchsploit 'apache 2.4.49' → found CVE-2021-41773 (high)
   - Mission #5: target C → nuclei -id CVE-2021-41773 → found (critical)
   - Mission #8: target E → gobuster → backups/ found (high)
5. Backend injecta context al LLM system prompt
6. LLM sugiere: "Basado en 3 misiones similares con Apache 2.4.49,
   ejecuta: 1) searchsploit 'apache 2.4.49' 2) nuclei -id CVE-2021-41773"
```

### Archivos a crear/modificar

- `backend/mission_store.py` (NUEVO)
- `backend/database.py` — añadir CRUD para `mission_history`
- `backend/main.py` — endpoints `/api/missions/*` + modificar `/api/suggest`
- `frontend/index.html` — sección "Mission History" en Op Admiral tab
- `frontend/js/main.v2.js` — functions `saveMission()`, `loadMissionHistory()`, `findSimilar()`
- `ROADMAP.md` — marcar self-improvement como ✅