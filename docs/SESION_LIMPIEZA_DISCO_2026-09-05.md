# Sesión de Limpieza de Disco — 2026-09-05

Registro completo de la sesión de recuperación de espacio en `C:` y del
arreglo del problema de arranque de Docker Desktop. Resultado neto: **`C:` pasó
de ~11 GB a ~80 GB libres** y Docker/Ollama quedaron confirmados sobre el disco
extraíble `F:`.

---

## 1. Diagnóstico

| Elemento | Antes | Localización | Resultado |
|----------|-------|--------------|-----------|
| Backups iOS | **55 GB** | `C:\Users\34678\AppData\Roaming\Apple Computer\MobileSync\Backup` | Borrado (aprobado) |
| Temp Windows | ~3 GB | `%TEMP%` (usuario) | Limpiado |
| Cachés Chrome | ~5.4 GB | `AppData\Local\Google\Chrome\User Data` (incl. `OptGuideOnDeviceModel` 4 GB) + `SoftwareMetrics` de perfiles | Limpiado |
| Postman antigua | 380 MB | `AppData\Local\Postman\app-11.65.4` | Borrado |
| Docker Desktop app | **44 MB** | `AppData\Local\Docker` | Intacto (no era el problema) |
| Disco Docker | 58.22 GB | `F:\Docker\wsl\disk\docker_data.vhdx` | Intacto — Docker **ya montaba desde F:** |
| Modelos Ollama | 26 GB | `F:\OllamaModels` | Intacto — `OLLAMA_MODELS` ya apuntaba a F: |
| VM Kali | 123 GB | `Documents\Virtual Machines` | No se mueve (decisión del usuario) |

### Hallazgo clave: el junction de Docker

`C:\Users\34678\AppData\Local\Docker\wsl\disk` es un **junction** (link simbólico
de directorio) cuyo Target es `C:\docker\wsl\disk`, que **no existe** (el vhdx
real está en `F:\Docker\wsl\disk`). El log de Docker lo confirma:

```
\\?\F:\docker\wsl\disk\docker_data.vhdx
```

=> Docker Desktop **se ejecuta desde F:** desde hace tiempo; la migración ya
estaba hecha y no requería movimiento adicional.

> ⚠️ El junction roto `C:\docker\wsl\disk` NO se toca. No ocupa espacio y
> tocarlo rompería la ruta de arranque de WSL/Docker.

---

## 2. Incidencia: Docker no arrancaba (`ERROR_SHARING_VIOLATION`)

Tras las limpiezas, Docker Desktop fallaba al arrancar con:

```
ERROR_SHARING_VIOLATION ... MountVhd/HCS ... F:\docker\wsl\disk\docker_data.vhdx
("el archivo está siendo utilizado por otro proceso")
```

### Causa raíz

Una compactación previa de `docker_data.vhdx` (diskpart compact, sesión
anterior) dejó la imagen de disco **adjunta sin montar** a nivel de
hipervisor/HCS. `Get-Disk` mostraba un disco fantasma **"Msft Virtual Disk" de
1024 GB (File Backed)**. `handle.exe` no lo veía porque el lock es del kernel
(WSL/HCS), no de un proceso de usuario.

### Fix aplicado

Script `diskpart` **elevado** (UAC) con:

```
select vdisk file="F:\docker\wsl\disk\docker_data.vhdx"
detach vdisk
```

Resultado: **`VHDX LIBRE`**, el disco fantasma desapareció de `Get-Disk`
(solo quedaron C/D/F reales) y Docker Desktop arrancó v29.6.1 en ~15 s.

### Reproducción futura

Si `Get-Disk` vuelve a mostrar un "Msft Virtual Disk" fantasma o Docker falla
con `ERROR_SHARING_VIOLATION` en el vhdx, repetir el `detach` elevado del paso
anterior. Es idempotente y seguro (no borra datos).

---

## 3. Estado final verificado

- `C:` ≈ **80 GB libres**; `F:` ≈ 66 GB libres (Ollama 26 GB + Docker vhdx).
- Docker Desktop v29.6.1 en marcha; `mirv-backend` Up; `mirv-kali-tools`
  healthy; 3 volúmenes `proyectociber_*` intactos.
- `Get-Disk`: solo discos físicos reales (C/D/F), sin fantasmas.

---

## 4. Nueva herramienta: System Monitor (MIRV)

Como parte de esta sesión se implementó una herramienta in-app de
**monitorización del equipo** (RAM/ROM + análisis y limpieza de disco):

- **Módulo**: `backend/system_monitor.py` (stdlib-only; `psutil` opcional).
- **Endpoints**:
  - `GET /api/system/stats` — CPU, RAM, uptime, plataforma.
  - `GET /api/system/disk` — particiones/volúmenes con porcentaje de uso.
  - `GET /api/system/cleanup` — barrido de candidatos a limpiar (raíces
    explícitas: home, Temp, Docker dirs, Ollama models, etc.), con
    presupuesto de tiempo (1.5 s/dir), escaneo seguro (rechaza rutas raíz/
    sistema y el home del usuario).
  - `POST /api/system/cleanup` — borrado recursivo de un candidato (controlled
    por el usuario en el frontend).
- **Frontend**: nueva pestaña **🖥️ Sys Monitor** (`tab-system`) en
  `frontend/index.html` + lógica en `frontend/js/main.v2.js`
  (`refreshSystem`, `runCleanupScan`, `deleteCleanupCandidate`, polling 15 s
  mientras la pestaña está abierta) + i18n en/es.
- **Tests**: `backend/tests/test_system_monitor.py` — 29 tests.

> El frontend "Scan for junk" levanta la lista de candidatos; el botón 🗑️ de
> cada candidato borra esa ruta con confirmación del operador.

### Verificación de la suite

`pytest tests/ -k "not test_slow_hook"` → **4415 passed, 2 failed** (estos 2
fallos son **ambientales/pre-existentes** y NO están relacionados con este
feature):

| Test | Causa |
|------|-------|
| `test_main_gaps::TestMobileApi::test_delete_not_found` | La máquina local tiene Supabase **conectada de verdad** (`Supabase connected: https://klkbbyqbdmuxovpbmple.supabase.co`); el delete idempotente devuelve 200 en vez del 404 que espera el test. En CI (env vacío, sin credenciales) pasa. |
| `test_orchestrator::TestCallLlm::test_openai_provider_default_model_when_empty` | El modelo local configurado es `qwen2.5-coder:7b` (Ollama en `F:`), no el `gpt-4o-mini` default del test. Depende de la configuración de la máquina. |

---

### PC Analyzer (idea implementada)

Extensión de la sesión: herramienta que **analiza el PC y dice qué falla, qué
hacer y cómo arreglarlo** (fase 1: diagnóstico + soluciones, sin auto-fix).

- **Módulo**: `backend/pc_analyzer.py` — 8 checks deterministas del host local
  (host, RAM, CPU, disco sistema, resto de volúmenes, basura/caché, red,
  uptime) reutilizando `system_monitor`.
- **Resultado**: grade A–F + score 0–100 + lista de sugerencias accionables.
- **Endpoint**: `GET /api/pc-analyzer`.
- **Frontend**: pestaña 🩺 **PC Analyzer** (`tab-pcanalyzer`) con hero de
  puntuación, grid de checks, soluciones sugeridas y botón "🤖 Explain with AI"
  que pasa el diagnóstico a `/api/ai/chat` (auto-redact).
- **Tests**: `backend/tests/test_pc_analyzer.py` (28).
- **Fase 2 (a futuro)**: auto-fix con confirmación, EventLog/WMI,
  actualizaciones pendientes.

---

## 5. Pendientes

- Commitear `.github/workflows/desktop-build.yml` + `desktop/BUILD_INSTRUCTIONS.md`
  (T5 desktop, heredado de la sesión anterior).
- Verificar CI del commit de documentación previo (`93ba5f1`).