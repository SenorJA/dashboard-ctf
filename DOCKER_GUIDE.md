# 🐳 Guía Docker de M.I.R.V.

> ⚠️ **NOTA:** Si Docker Desktop se queda sin espacio en C: o las distros WSL se dañan, sigue la guía de migración al final de este documento.

---

## Arquitectura Docker

M.I.R.V. se ejecuta en **dos contenedores Docker** coordinados por `docker-compose.yml`:

```
┌──────────────────────────────────────────────────────────────┐
│  docker-compose.yml (proyecto: proyectociber)                 │
│                                                               │
│  ┌─────────────────────┐     SSH (2222→22)   ┌─────────────┐ │
│  │  mirv-kali-tools    │◄───────────────────►│ mirv-backend │ │
│  │  ─────────────      │    Puerto 22        │ ───────────  │ │
│  │  Kali Linux         │                     │ FastAPI      │ │
│  │  +50 herramientas   │                     │ WebSocket    │ │
│  │  SecLists + rockyou │                     │ REST API     │ │
│  │                     │                     │              │ │
│  │  root / mirv        │                     │ Puerto 8000  │ │
│  └─────────────────────┘                     └──────┬───────┘ │
│                                                     │         │
│                                            Volumenes │         │
│              ┌───────────────────────────────────────┤         │
│              │                                       │         │
│              ▼                                       ▼         │
│   ./backend/* (código)                  /var/run/docker.sock   │
│   ./frontend/* (static)                 ./docker-compose.yml   │
│   ./docker-compose.yml (read-only)                            │
└──────────────────────────────────────────────────────────────┘
```

### Contenedores

| Contenedor | Imagen | Propósito | Puerto expuesto |
|------------|--------|-----------|:---------------:|
| `mirv-backend` | `proyectociber-mirv-backend` | FastAPI + WebSocket + REST API | `8000` |
| `mirv-kali-tools` | `proyectociber-kali-tools` | Kali Linux con 50+ herramientas | `2222 → 22` |

### Volúmenes

| Volumen | Monta en | Propósito |
|---------|----------|-----------|
| `kali-sessions` | `/home/kali/sessions` | Sesiones y outputs de herramientas |
| `kali-wordlists` | `/usr/share/wordlists` | Diccionarios (rockyou, etc.) |
| `mirv-logs` | `/app/backend/logs` | Logs del servidor |

### Montajes bind (bind mounts)

| Host | Contenedor (mirv-backend) | Propósito |
|------|--------------------------|-----------|
| `./backend/` | `/app/backend/` | Código Python en vivo (hot-reload) |
| `./frontend/` | `/app/frontend/` | Frontend estático |
| `./docker-compose.yml` | `/app/docker-compose.yml` (ro) | Para comandos Docker desde dentro |
| `/var/run/docker.sock` | `/var/run/docker.sock` (ro) | Socket Docker (Docker-in-Docker) |

---

## Panel de Control Docker desde el UI

El dashboard incluye un **panel de control Docker** accesible desde la insignia en el header (junto a OPSEC), que permite gestionar el stack sin usar la terminal.

### Acceso

1. Abre `http://localhost:8000`
2. En el header busca la insignia 🐳 con un punto verde/gris
   - **Punto verde** + "🐳 Stack UP" → ambos contenedores funcionando
   - **Punto gris** + "🐳 Stack DOWN" → kali-tools detenido
3. Haz clic en la insignia → se abre el modal de control Docker

### Modal de Control

El modal muestra:

- **Estado actual**: 🟢 Running / 🔴 Stopped / ❌ Docker no instalado
- **Lista de contenedores**: nombre + estado de cada uno
- **Log de operaciones**: historial de acciones realizadas
- **Botones de acción**:
  - **▶ Start** — Arranca kali-tools (no afecta a mirv-backend)
  - **⏹ Stop** — Detiene kali-tools (mirv-backend sigue funcionando)
  - **🧹 Clean** — Detiene kali-tools + elimina sus volúmenes (⚠️ pérdida de datos)
  - **🔨 Rebuild** — Reconstruye las imágenes desde cero (tarda 10+ min, en background)

### Estados de los botones

| Estado del stack | Start | Stop | Clean | Rebuild |
|------------------|:----:|:----:|:-----:|:-------:|
| 🟢 Running | ❌ deshabilitado | ✅ disponible | ✅ disponible | ✅ disponible |
| 🔴 Stopped | ✅ disponible | ❌ deshabilitado | ❌ deshabilitado | ❌ deshabilitado |
| ❌ No instalado | ❌ deshabilitado | ❌ deshabilitado | ❌ deshabilitado | ❌ deshabilitado |

---

## API de Control Docker

Endpoints REST para gestionar el stack desde el backend:

| Método | Ruta | Descripción | Comportamiento |
|--------|------|-------------|----------------|
| `GET` | `/api/docker/status` | Estado del stack Docker | Síncrono. Lista todos los contenedores con su estado |
| `POST` | `/api/docker/start` | Arranca kali-tools | Síncrono. Crea e inicia kali-tools |
| `POST` | `/api/docker/stop` | Detiene kali-tools | Síncrono. Detiene kali-tools (no toca mirv-backend) |
| `POST` | `/api/docker/clean` | Limpia kali-tools + volúmenes | Síncrono. `stop + rm -v kali-tools` |
| `POST` | `/api/docker/build` | Reconstruye imágenes (sin caché) | **Asíncrono** (task_id). Solo build, no restart |
| `GET` | `/api/docker/task/{task_id}` | Estado de una tarea asíncrona | Usado por el frontend para polling del build |

### Endpoints síncronos

`start`, `stop` y `clean` responden **inmediatamente** con el resultado de la operación:

```json
{
  "ok": true,
  "exit": 0,
  "stdout": "...",
  "stderr": "Container mirv-kali-tools  Started",
  "msg": "Kali tools started"
}
```

### Endpoint asíncrono (build)

`build` responde inmediatamente con un `task_id`. El frontend hace polling a `/api/docker/task/{task_id}` cada 1 segundo hasta que la tarea termina (máx 2 minutos):

```json
{
  "ok": true,
  "msg": "Build started in background (not restarting). When done, restart from terminal: docker compose up -d",
  "task_id": "build_4031.327952981"
}
```

Consulta de estado:

```json
{
  "ok": true,
  "task": {
    "status": "running",
    "action": "build"
  }
}
```

Cuando termina:

```json
{
  "ok": true,
  "task": {
    "status": "done",
    "action": "build",
    "result": {
      "ok": true,
      "exit": 0,
      "stdout": "...",
      "stderr": ""
    }
  }
}
```

---

## Problemas Encontrados y Soluciones

A continuación se detallan los problemas de arquitectura Docker-in-Docker que surgieron durante el desarrollo y cómo se resolvieron.

### Problema 1: Docker CLI no instalado en el contenedor

**Síntoma:** El endpoint `/api/docker/status` devolvía `installed: false`.

**Causa:** El contenedor `mirv-backend` corre Python, pero no incluye el cliente Docker. Para ejecutar comandos Docker desde dentro del contenedor, necesita el binario `docker`.

**Solución:** En el `Dockerfile` del backend:

```dockerfile
# Docker CLI (static binary)
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz | \
    tar xz -C /usr/local/bin --strip-components=1 docker/docker

# docker-compose plugin
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -fsSL https://github.com/docker/compose/releases/download/v2.32.1/docker-compose-linux-x86_64 -o \
    /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
```

### Problema 2: Docker socket no montado

**Síntoma:** `docker ps` desde el contenedor devolvía `Cannot connect to the Docker daemon`.

**Causa:** El contenedor no tenía acceso al socket de Docker del host. Sin él, el cliente Docker dentro del contenedor no puede comunicarse con el daemon de Docker Desktop.

**Solución:** Montar el socket Docker en `docker-compose.yml`:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

### Problema 3: `docker compose ps` fallaba

**Síntoma:** `docker compose ps` devolvía error `can't find a suitable configuration file`.

**Causa:** `docker compose ps` busca `docker-compose.yml` en el directorio actual. El contenedor tiene el código en `/app/backend/`, no en la raíz del proyecto.

**Solución:** 
1. Montar `docker-compose.yml` en el contenedor: `./docker-compose.yml:/app/docker-compose.yml:ro`
2. En el código Python, ejecutar los comandos desde `_PROJECT_ROOT = /app` (la raíz del proyecto dentro del contenedor)
3. Cambiar el endpoint de status de `docker compose ps` a `docker ps --format json` (más robusto, no necesita el compose file)

```python
async def _run_docker_cmd(*args, timeout: int = 30) -> dict:
    """Run a docker command and return parsed result."""
    cmd = ["docker", *args]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return {
        "ok": proc.returncode == 0,
        "exit": proc.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }
```

### Problema 4: Auto-destrucción del contenedor (self-destruct)

**Síntoma:** Al hacer clic en "Stop" o "Rebuild", el servidor respondía pero el resultado nunca llegaba — el contenedor `mirv-backend` se detenía a mitad de la operación.

**Causa:** `docker compose down` detiene TODOS los contenedores del proyecto, incluido `mirv-backend`. Cuando el contenedor que ejecuta el comando es detenido, el proceso Python se mata inmediatamente, perdiendo el resultado.

**Solución:** Rediseñar todos los endpoints para que **nunca afecten al contenedor actual**:

- **start**: Solo opera sobre `kali-tools` → `docker compose up -d kali-tools`
- **stop**: Solo opera sobre `kali-tools` → `docker compose stop kali-tools`
- **clean**: Solo opera sobre `kali-tools` → `docker compose stop kali-tools && docker compose rm -v kali-tools`
- **build**: Solo construye imágenes sin reiniciar → `docker compose build --no-cache`

```python
@app.post("/api/docker/stop")
async def docker_stop():
    result = await _docker_compose("stop", "kali-tools", timeout=30)
    msg = "Kali tools stopped" if result["ok"] else f"Stop failed: {result.get('stderr', '')}"
    return JSONResponse(result | {"msg": msg}, ...)

@app.post("/api/docker/start")
async def docker_start():
    result = await _docker_compose("up", "-d", "kali-tools", timeout=60)
    msg = "Kali tools started" if result["ok"] else f"Start failed: {result.get('stderr', '')}"
    return JSONResponse(result | {"msg": msg}, ...)
```

**Para reconstruir completely el stack** (incluyendo mirv-backend), el usuario debe ejecutar desde la terminal:

```bash
docker compose up -d --build
```

### Problema 5: Nombre de proyecto incorrecto

**Síntoma:** `docker compose up -d` desde el contenedor creaba un proyecto llamado `app` en lugar de `proyectociber`.

**Causa:** Docker Compose infiere el nombre del proyecto del nombre del directorio padre del `docker-compose.yml`. Dentro del contenedor, el archivo está en `/app/docker-compose.yml`, por lo que el proyecto se llama `app`.

**Solución:** Pasar explícitamente el nombre del proyecto con `-p`:

```python
_DOCKER_COMPOSE_PROJECT = "proyectociber"

async def _docker_compose(*args, timeout: int = 300) -> dict:
    cmd = ["docker", "compose", "-p", _DOCKER_COMPOSE_PROJECT, *args]
    # ...
```

Y también `COMPOSE_PROJECT_NAME=proyectociber` como variable de entorno:

```yaml
environment:
  - COMPOSE_PROJECT_NAME=proyectociber
```

### Problema 6: Truncamiento de stdout

**Síntoma:** El endpoint `/api/docker/status` mostraba solo 1 contenedor (faltaba `kali-tools`).

**Causa:** El buffer de stdout se truncaba a 2000 caracteres para evitar respuestas enormes, pero `docker ps` con 2 contenedores ocupaba más de 2000 caracteres.

**Solución:** Eliminar el truncamiento y devolver el stdout completo. Mejor aún, parsear el JSON línea por línea y devolver solo los campos relevantes:

```python
containers = []
for line in result["stdout"].strip().split("\n"):
    if not line.strip():
        continue
    try:
        c = json.loads(line)
        containers.append({
            "name": c.get("Names", "?"),
            "service": c.get("Names", "?"),
            "state": c.get("State", "unknown"),
            "ports": c.get("Ports", ""),
        })
    except json.JSONDecodeError:
        continue
```

### Problema 7: Build asíncrono con auto-destrucción

**Síntoma:** `docker compose up -d --build` desde el endpoint reconstruía la imagen y reiniciaba el contenedor, matando el proceso Python a mitad de la respuesta.

**Solución:** Separar build de restart:
- **Build**: `docker compose build --no-cache` → solo construye imágenes (no reinicia). Se ejecuta en background (`asyncio.create_task`) con polling.
- **Restart manual**: El usuario debe reiniciar desde la terminal: `docker compose up -d`

El endpoint build devuelve un `task_id` para que el frontend pueda hacer polling y mostrar el progreso:

```python
@app.post("/api/docker/build")
async def docker_build():
    tid = f"build_{asyncio.get_event_loop().time()}"
    asyncio.create_task(_docker_task_runner(tid, "build", "build", "--no-cache", timeout=1200))
    return JSONResponse({"ok": True, "msg": "Build started...", "task_id": tid})
```

---

## Frontend: Componentes Docker

### Insignia en el Header

La insignia Docker en el header muestra el estado del stack en tiempo real:

```html
<div id="docker-badge" onclick="window.dockerModalOpen()"
     class="flex items-center gap-1.5 px-2 py-1 rounded cursor-pointer bg-deep border border-void hover:border-cyber/30 transition-colors">
  <span id="docker-dot" class="inline-block w-1.5 h-1.5 rounded-full bg-gray-700"></span>
  <span id="docker-text" class="text-xs text-gray-400 hidden sm:inline">Docker N/A</span>
</div>
```

- **Punto verde** (`bg-neon`) → Stack UP
- **Punto gris** (`bg-gray-600`) → Stack DOWN
- **Punto gris oscuro** (`bg-gray-700`) → Docker no instalado

### Modal de Control

El modal se abre al hacer clic en la insignia. Incluye:
- Estado actual del stack
- Lista de contenedores con su estado individual
- Log de operaciones (scrollable)
- 4 botones de acción con feedback visual

### Funciones JavaScript

| Función | Propósito |
|---------|-----------|
| `_dockerApi(endpoint, method)` | Llamada fetch genérica a los endpoints Docker |
| `_dockerUpdateBadge(status)` | Actualiza el punto de color y texto de la insignia |
| `_dockerUpdateModal(status)` | Actualiza el contenido del modal según el estado |
| `_dockerRefresh()` | Obtiene el estado y actualiza badge + modal |
| `_dockerLog(msg, isError)` | Añade una línea al log de operaciones |
| `_dockerAction(endpoint, label, btnId)` | Ejecuta acción. Si hay task_id → polling; si no → muestra resultado directo |
| `_dockerPollTask(taskId, label, btn)` | Polling cada 1s hasta que la tarea termina (máx 120 intentos = 2 min) |
| `_dockerPollLoop()` | Bucle de 30s que refresca el estado automáticamente |

### Flujo de una acción

1. Usuario hace clic en "Stop" → `window.dockerStop()`
2. → `_dockerAction('/api/docker/stop', 'Stop stack', 'docker-btn-stop')`
3. → Botón se deshabilita, log muestra "⏳ Stop stack..."
4. → `fetch('POST /api/docker/stop')` → respuesta: `{"ok":true, "msg":"Kali tools stopped"}`
5. → Log: "✅ Stop stack — Kali tools stopped"; Toast: notificación
6. → Botón se rehabilita; `_dockerRefresh()` tras 1.5s

Si hay `task_id` (build):
3. → Log: "⏳ Rebuild stack — background task started"
4. → `_dockerPollTask(taskId, ...)` empieza a hacer polling
5. → Cuando `status === 'done'` → Log: "✅ Rebuild stack — completed"
6. → Botón se rehabilita; `_dockerRefresh()` tras 1.5s

---

## Traducciones i18n

Claves de traducción para el panel Docker:

```javascript
const translations = {
  es: {
    'docker.start': '▶ Start',
    'docker.stop': '⏹ Stop',
    'docker.clean': '🧹 Clean',
    'docker.build': '🔨 Rebuild',
    'docker.status.running': '🟢 Running',
    'docker.status.stopped': '🔴 Stopped',
    'docker.status.na': '❌ Docker no instalado',
    'docker.log.starting': 'Iniciando kali-tools...',
    'docker.log.stopping': 'Deteniendo kali-tools...',
    'docker.log.cleaning': 'Limpiando kali-tools...',
    // ...
  },
  en: {
    'docker.start': '▶ Start',
    'docker.stop': '⏹ Stop',
    'docker.clean': '🧹 Clean',
    'docker.build': '🔨 Rebuild',
    'docker.status.running': '🟢 Running',
    'docker.status.stopped': '🔴 Stopped',
    'docker.status.na': '❌ Docker not installed',
    // ...
  }
};
```

---

## Solución de problemas

### Error: "Docker not installed" en el UI

1. Verifica que Docker Desktop esté instalado y corriendo
2. Verifica el montaje del socket: `docker exec mirv-backend ls -la /var/run/docker.sock`
3. Verifica el cliente Docker: `docker exec mirv-backend docker version`
4. Reconstruye el contenedor: `docker compose up -d --build mirv-backend`

### Error: "docker-compose.yml not found"

1. Verifica el montaje: debe estar `./docker-compose.yml:/app/docker-compose.yml:ro` en `docker-compose.yml`
2. Verifica dentro del contenedor: `docker exec mirv-backend ls -la /app/docker-compose.yml`

### Error: El build no termina nunca

El build es una tarea asíncrona. El frontend hace polling por 2 minutos máximo. Si el build tarda más:
- El build sigue ejecutándose en background aunque el frontend deje de hacer polling
- Verifica el progreso manualmente: `docker exec mirv-backend docker compose -p proyectociber build --no-cache`

### Error: Docker Desktop consume todo el disco C:

**Síntoma:** Docker Desktop deja de funcionar, WSL distros se corrompen, no se puede hacer `docker compose up`.

**Causa:** Docker Desktop almacena sus imágenes, contenedores y volúmenes en `C:\Users\Public\ProgramData\Docker\windowsfilter` (o `C:\ProgramData\Docker\windowsfilter`). Con múltiples imágenes grandes (Kali Linux, Python, etc.), el disco C: se llena rápidamente.

**Solución: Migrar docker-desktop-data a otra unidad (F:)**

1. **Abrir PowerShell como Administrador**

2. **Detener Docker Desktop** (ciérralo desde la bandeja del sistema)

3. **Verificar que WSL está detenido:**
   ```powershell
   wsl --shutdown
   ```

4. **Exportar la distro docker-desktop-data:**
   ```powershell
   wsl --export docker-desktop-data F:\docker\data\docker-desktop-data.tar
   ```
   (Si no existe `F:\docker\data\`, créalo primero)

5. **Desregistrar la distro original:**
   ```powershell
   wsl --unregister docker-desktop-data
   ```

6. **Importar la distro a la nueva ubicación:**
   ```powershell
   wsl --import docker-desktop-data F:\docker\data\ F:\docker\data\docker-desktop-data.tar --version 2
   ```

7. **(Opcional) Migrar también `C:\ProgramData\Docker` a F:**
   ```powershell
   # Como Administrador
   robocopy "C:\ProgramData\Docker" "F:\ProgramData\Docker" /E /COPYALL
   # Renombrar el original (para verificar que funciona)
   ren "C:\ProgramData\Docker" "C:\ProgramData\Docker.old"
   # Crear symlink
   cmd /c mklink /J "C:\ProgramData\Docker" "F:\ProgramData\Docker"
   ```

8. **Iniciar Docker Desktop** — debería arrancar normal, usando F:\

9. **Verificar:**
   ```powershell
   wsl --list -v
   ```
   Deberías ver `docker-desktop-data` corriendo.

10. **Limpiar archivos temporales del C:**
    ```powershell
    # Eliminar el tar exportado (ya no hace falta)
    del F:\docker\data\docker-desktop-data.tar
    # Eliminar el backup del ProgramData (si el symlink funciona)
    # rm -r "C:\ProgramData\Docker.old" -Force -Recurse
    # Limpiar temporales de Windows
    cleanmgr /sageset:1  # selecciona qué limpiar
    cleanmgr /sagerun:1
    ```

**Resultado:** El VHDX de Docker ahora vive en `F:\docker\data\ext4.vhdx` en lugar de `C:\Users\...\AppData\Local\Docker\wsl\data\`. Se liberan ~30-40 GB en C:.

**Para solucionar Docker Desktop dañado (WSL distro corrupta):**
```powershell
wsl --shutdown
wsl --unregister docker-desktop
wsl --unregister docker-desktop-data
# Luego en Docker Desktop: Troubleshoot → Reset to factory defaults
# Esto recrea las distros desde cero
```

### Error: "Container mirv-kali-tools not found" al hacer Start

El contenedor fue eliminado (con Clean o manualmente). El endpoint Start lo recrea automáticamente.

### Error: No se puede conectar a Kali después de Stop

Es normal. Stop detiene kali-tools. Haz clic en **Start** para arrancarlo de nuevo. Espera 5 segundos a que el servicio SSH esté listo.

### Error: Los cambios en el código no se reflejan

El backend monta `./backend/` en `/app/backend/` con hot-reload (`--reload`). Si los cambios no se reflejan:
1. Verifica que el contenedor está usando `--reload`: revisa el `CMD` en el `Dockerfile`
2. Forzar reconstrucción: `docker compose up -d --build mirv-backend`

---

## Comandos Útiles

```bash
# Ver logs del backend en vivo
docker compose logs -f mirv-backend

# Ver logs de kali-tools
docker compose logs -f kali-tools

# Entrar al contenedor backend
docker exec -it mirv-backend sh

# Verificar conectividad con kali-tools
docker exec mirv-backend sh -c "ssh -o StrictHostKeyChecking=no root@kali-tools echo OK"

# Reconstruir solo el backend (rápido)
docker compose up -d --build mirv-backend

# Reconstruir todo (lento, incluye kali-tools)
docker compose up -d --build

# Parar todo (desde terminal, no desde el UI)
docker compose down

# Parar todo y borrar volúmenes
docker compose down -v

# Ver recursos de los contenedores
docker stats mirv-backend mirv-kali-tools
```
