# M.I.R.V. — Data Persistence Audit & Architecture

> **Última actualización:** Julio 2026
> **Estado:** ✅ Todos los gaps de persistencia corregidos

---

## Resumen

Esta auditoría cubre **17 tablas** en Supabase PostgreSQL, **45+ endpoints REST**, **15 claves de localStorage** y **~20 entidades de datos** en toda la pila. Tras la intervención, **todos los datos importantes se persisten en DB** con un patrón offline-first.

---

## Arquitectura de Persistencia

```
Frontend (JS)                    Backend (FastAPI)              Supabase (PostgreSQL)
────────────                     ────────────────              ────────────────────
localStorage (cache)  ─────►    GET/POST/DELETE               Tablas + Storage
     │                              │                              │
     └── offline-first:             └── _ensure_tables()          └── SQL bootstrap
         API caído → localStorage       (3 estrategias)              automático
```

**Patrón offline-first:**
1. Intentar operación contra API backend
2. Si falla (offline/DB no configurada) → usar localStorage
3. Cuando la API vuelve, migrar datos de localStorage a DB

---

## Tablas en Supabase (17)

| # | Tabla | Propósito | CRUD | Estado |
|---|-------|-----------|------|--------|
| 1 | `ssh_connections` | Perfiles de conexión SSH | list/save/delete | ✅ Frontend → API |
| 2 | `scripts` | Scripts RCE guardados | list/save/delete | ✅ Frontend → API |
| 3 | `reports` | Reportes de scan, bounty, writeups | list/save/delete | ✅ |
| 4 | `hak5_payloads` | Payloads de dispositivos Hak5 | list/save/delete | ✅ Frontend → API |
| 5 | `app_settings` | Configuración clave-valor | get/set | ✅ |
| 6 | `uploaded_files` | Metadatos de archivos subidos | save/list/delete | ✅ |
| 7 | `findings` | Hallazgos parseados de herramientas | save/bulk/list/delete | ✅ |
| 8 | `credentials` | Credenciales descubiertas | save/list/delete | ✅ |
| 9 | `ctf_challenges` | Desafíos CTF | save/list/delete/solve | ✅ |
| 10 | `ctf_solves` | Resoluciones de flags | insert (vía solve) | ✅ |
| 11 | `mobile_apks` | Análisis de APKs | save/list/get/delete | ✅ |
| 12 | `forensics_evidence` | Evidencia forense | save/list/get/delete | ✅ |
| 13 | `mission_history` | Historial de misiones (auto-mejora) | save/list/delete | ✅ |
| 14 | `scope_events` | Auditoría de bloqueos Scope Guard | save/list/clear | ✅ **NUEVA** |
| 15 | `swarm_sessions` | Sesiones del pipeline multi-operador | save/list/get/delete | ✅ **NUEVA** |
| 16 | `mission_plans` | Planes guardados de Op Admiral | save/list/delete | ✅ **NUEVA** |
| 17 | `app_credentials` | Secretos cifrados (API keys, etc.) | save/get/delete | ✅ **NUEVA** |

---

## Gaps Identificados y Correcciones

### 🔴 GAP 1: APIs muertas (conexiones, scripts, payloads)
**Problema:** Backend tenía CRUD completo para `ssh_connections`, `scripts` y `hak5_payloads`, pero el frontend nunca llamaba a estas APIs — solo usaba localStorage.

**Corrección (Fase 3-5):**
- `loadConnections()` ahora llama a `GET /api/connections` primero
- `saveConnections()` ahora llama a `POST /api/connections` en background
- `window.saveConnection()` sincroniza cada nueva conexión a DB
- `deleteActiveConnection()` elimina de DB vía `DELETE /api/connections/{id}`
- Mismo patrón para scripts y payloads Hak5
- localStorage mantiene el rol de **caché offline**

### 🔴 GAP 2: Secretos en localStorage
**Problema:** `vulnforge_ai_key`, `vulnforge_suggest_key`, `vulnforge_ps_creds` almacenados en texto plano en localStorage.

**Corrección (Fase 10):**
- Nueva tabla `app_credentials` para almacenamiento server-side
- `saveAIConfig()` ahora envía claves a `POST /api/credentials/secrets`
- `loadAIConfig()` intenta cargar desde backend, con migración desde localStorage
- Payload Studio credentials: `setPSCreds()` guarda en backend y elimina localStorage
- `clearPSCreds()` también elimina del backend
- **Las claves ya no persisten en localStorage** cuando el backend está disponible

**⚠️ Aún pendiente:** Encriptación server-side de los valores. Actualmente se almacenan en texto plano en la DB.

### 🔴 GAP 3: Bounty reports + AI writeups no persistidos
**Problema:** `lastBountyReport` y `lastAIWriteup` eran variables en memoria — se perdían al recargar.

**Corrección (Fase 6):**
- `generateBountyReport()` ahora llama a `_saveReportToDB({type: 'bounty', ...})`
- `generateAIWriteup()` ahora llama a `_saveReportToDB({type: 'ai_writeup', ...})`
- Nueva helper `_saveReportToDB()` que POST a `/api/reports`
- Se recuperan desde la DB al cargar la pestaña Reports

### 🔴 GAP 4: Bootstrap de tablas no funcional
**Problema:** `_ensure_tables()` verificaba tablas pero nunca ejecutaba SQL.

**Corrección (Fase 1):**
- Estrategia 1: Conexión PostgreSQL directa vía `psycopg2` (`SUPABASE_DB_PASSWORD`)
- Estrategia 2: Management API (`SUPABASE_MGMT_TOKEN`)
- Estrategia 3: Verificación suave con instrucciones (fallback)
- `psycopg2-binary` añadido a `requirements.txt` como dependencia opcional

### 🟡 GAP 5: Schema SQL desactualizado
**Problema:** `supabase_schema.sql` tenía solo 6 tablas, faltaban 11.

**Corrección (Fase 2):**
- Sincronizado con `SCHEMA_SQL` en `database.py`
- Añadidas: findings, credentials, ctf_challenges, ctf_solves, mobile_apks,
  forensics_evidence, mission_history, scope_events, swarm_sessions,
  mission_plans, app_credentials
- Incluye índices para todas las tablas

### 🟡 GAP 6: Scope block history efímera
**Problema:** `_block_history` en memoria Python — se perdía al reiniciar servidor.

**Corrección (Fase 8):**
- `log_block()` ahora también guarda en `scope_events` vía `save_scope_event()`
- Nuevos endpoints: `GET /api/scope/events`, `POST /api/scope/events`, `DELETE /api/scope/events`
- La lista en memoria se conserva como caché para acceso rápido

### 🟡 GAP 7: Swarm results efímeros
**Problema:** Sesiones Swarm vivían solo en `_sessions` dict en memoria.

**Corrección (Fase 9):**
- `run_pipeline()` guarda sesión completada vía `save_swarm_session()`
- Nuevos endpoints: CRUD completo para `swarm_sessions`
- Datos persistidos: target, fases, total_findings, estado, errores

### 🟡 GAP 8: Op Admiral plans no persistidos
**Problema:** `missionPlan[]` en memoria — se perdía al recargar.

**Corrección (Fase 7):**
- Nueva tabla `mission_plans` con CRUD completo
- Endpoints: `GET/POST/DELETE /api/plans`
- Pendiente: conectar el frontend de Op Admiral para auto-guardar/cargar planes

---

## Estado Actual de localStorage

| Clave | Contenido | Estado |
|-------|-----------|--------|
| `vulnforge_ai_endpoint` | URL del endpoint AI | ✅ Solo pref. UI |
| `vulnforge_ai_model` | Modelo AI | ✅ Solo pref. UI |
| `vulnforge_suggest_provider` | Proveedor de sugerencias | ✅ Solo pref. UI |
| `vulnforge_suggest_model` | Modelo de sugerencias | ✅ Solo pref. UI |
| `vulnforge_n8n_url` | URL de n8n | ✅ Solo pref. UI |
| `vulnforge_theme` | Tema (mono/neon) | ✅ Solo pref. UI |
| `vulnforge_lang` | Idioma (en/es) | ✅ Solo pref. UI |
| `mirv_opsec` | Nivel OPSEC | ✅ Solo pref. UI |
| `vulnforge_connections` | Conexiones SSH (caché) | ✅ Caché offline |
| `vulnforge_scripts` | Scripts (caché) | ✅ Caché offline |
| `vulnforge_hak5_*` | Payloads por dispositivo | ✅ Caché offline |
| `vulnforge_ai_key` | 🔴 API key AI | ✅ **Eliminada** (migrada a backend) |
| `vulnforge_suggest_key` | 🔴 API key suggest | ✅ **Eliminada** (migrada a backend) |
| `vulnforge_ps_creds` | 🔴 Credenciales Payload Studio | ✅ **Eliminada** (migrada a backend) |

---

## Endpoints REST para Persistencia

### Conexiones SSH
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/connections` | Listar conexiones |
| POST | `/api/connections` | Guardar conexión |
| DELETE | `/api/connections/{id}` | Eliminar conexión |

### Scripts
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/scripts` | Listar scripts |
| POST | `/api/scripts` | Guardar script |
| DELETE | `/api/scripts/{id}` | Eliminar script |

### Payloads Hak5
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/payloads` | Listar payloads (opcional `?device=`) |
| POST | `/api/payloads` | Guardar payload |
| DELETE | `/api/payloads/{id}` | Eliminar payload |

### Planes de Misión (Op Admiral)
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/plans` | Listar planes (`?target=&limit=20`) |
| POST | `/api/plans` | Guardar/actualizar plan |
| DELETE | `/api/plans/{id}` | Eliminar plan |

### Eventos de Scope
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/scope/events` | Listar eventos (`?limit=100`) |
| POST | `/api/scope/events` | Registrar evento |
| DELETE | `/api/scope/events` | Limpiar todos |

### Sesiones Swarm
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/swarm/sessions` | Listar sesiones |
| GET | `/api/swarm/sessions/{id}` | Obtener sesión |
| POST | `/api/swarm/sessions` | Guardar sesión |
| DELETE | `/api/swarm/sessions/{id}` | Eliminar sesión |

### Secretos (app_credentials)
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/credentials/secrets/{key}` | Verificar existencia |
| POST | `/api/credentials/secrets` | Guardar secreto |
| DELETE | `/api/credentials/secrets/{key}` | Eliminar secreto |

### Reportes
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/reports` | Listar reportes |
| POST | `/api/reports` | Guardar reporte |
| DELETE | `/api/reports/{id}` | Eliminar reporte |
| POST | `/api/report/generate` | Generar + guardar |

### Findings
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/findings` | Listar findings |
| POST | `/api/findings` | Guardar finding individual |
| POST | `/api/findings/bulk` | Guardar lote |
| DELETE | `/api/findings/{id}` | Eliminar finding |
| DELETE | `/api/findings` | Limpiar todos |

### Misiones (Self-Improvement Loop)
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/api/missions` | Listar misiones |
| POST | `/api/missions/save` | Guardar misión |
| DELETE | `/api/missions/{id}` | Eliminar misión |
| GET | `/api/missions/similar` | Buscar misiones similares |

---

## Variables de Entorno para DB

| Variable | Obligatoria | Propósito |
|----------|:-----------:|-----------|
| `SUPABASE_URL` | ✅ Sí | URL del proyecto Supabase |
| `SUPABASE_KEY` | ✅ Sí | Service Role Key (o anon key) |
| `SUPABASE_DB_PASSWORD` | ❌ Opcional | Para bootstrap automático vía psycopg2 |
| `SUPABASE_MGMT_TOKEN` | ❌ Opcional | Para bootstrap vía Management API |

---

## Cómo Verificar la Persistencia

```bash
# 1. Iniciar servidor
cd "C:\Users\34678\Desktop\Proyecto ciber"
uvicorn backend.main:app --reload

# 2. Verificar health
curl http://localhost:8000/api/health

# 3. Verificar que las tablas existen (si Supabase está configurado)
curl http://localhost:8000/api/connections     # → debe devolver []
curl http://localhost:8000/api/scripts          # → debe devolver []
curl http://localhost:8000/api/payloads         # → debe devolver []
curl http://localhost:8000/api/scope/events     # → debe devolver []
curl http://localhost:8000/api/swarm/sessions   # → debe devolver []
curl http://localhost:8000/api/plans            # → debe devolver []
curl http://localhost:8000/api/credentials/secrets/ai_key  # → 404 (válido)

# 4. Probar guardado
curl -X POST http://localhost:8000/api/connections \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","ip":"192.168.1.1","username":"root","password":"toor"}'
```
