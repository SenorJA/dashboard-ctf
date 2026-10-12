# 🧹 Mantenimiento de disco — Docker (`vhdx`) y el "disco fantasma" de VDS

> **Caso real (12 Oct 2026):** `docker_data.vhdx` **73,43 GB → 26,13 GB** (−48,4 GB) y `F:`
> pasó de **0,36 GB → 65,65 GB libres**, sin perder ninguna imagen ni contenedor.
> Esta guía existe porque el problema **se repite**: el vhdx de Docker **nunca encoge solo** y
> compactarlo mal (matar `diskpart` a mitad) deja un **estado fantasma** en el servicio VDS que
> bloquea `attach`/`detach`. Aquí está el procedimiento seguro + la recuperación.

---

## 1. Cómo está montado Docker en este equipo

- Docker Desktop guarda sus discos en `%LOCALAPPDATA%\Docker\wsl` — en este equipo eso es un
  **junction de Windows** que apunta a **`F:\docker\wsl`** (lo creó `F:\docker\setup_docker.bat`).
  Todo lo que "llena C:" conceptualmente vive en **F:** (el disco extraíble).
- El disco de datos es `F:\docker\wsl\disk\docker_data.vhdx`: **dinámico** — crece al escribir y
  **NO se encoge nunca solo** (ni con `docker prune`).
- `docker image/container/system prune` libera espacio **dentro** del vhdx, pero el fichero en F:
  sigue igual de grande. El espacio se recupera **compactando** el vhdx.

**Diagnóstico rápido:**

```powershell
(Get-Item "F:\docker\wsl\disk\docker_data.vhdx").Length/1GB   # tamaño real en disco
(Get-PSDrive F).Free/1GB                                      # espacio libre en F:
docker system df                                              # uso real dentro de Docker
```

Si `vhdx` ≈ 50–80 GB pero `docker system df` muestra solo ~10–15 GB → **toca compactar**.

---

## 2. El "disco fantasma" (por qué pasa tan a menudo)

**Causa raíz: `diskpart` se queda a medias.** Ocurre cuando el proceso se mata o interrumpe durante
`attach vdisk` / `compact vdisk`:

- cerrar la consola o matarlo desde el Administrador de tareas,
- **timeout del wrapper** que lo lanzó (p. ej. un comando que "parece" colgado),
- cancelar/denegar el UAC a mitad,
- quedarse sin espacio en el destino **durante** la compactación,
- reiniciar Windows con el disco todavía expuesto.

Consecuencia: **VDS** (Virtual Disk Service) deja el vhdx como **"Expuesto no abierto"** — aparece
como `Disco 2 — Msft Virtual Disk` en `Get-Disk`, sin proceso dueño. Síntomas típicos:

- `Get-Disk` muestra un disco extra `Msft Virtual Disk` (fantasma).
- `diskpart attach vdisk` → *"El disco virtual ya está expuesto"*.
- `diskpart detach vdisk` → *"El disco virtual ya está oculto"*.
- A veces el prompt queda bloqueado en *"Compactando..."* indefinidamente.

### Receta de recuperación (en orden)

1. **Limpiar un "Compactando" colgado** (PowerShell **elevado**):
   ```powershell
   Stop-Service vds -Force; Start-Service vds
   ```
2. **Detach del disco fantasma** — una sola sesión `diskpart` (**no toca los datos**):
   ```
   select vdisk file="F:\docker\wsl\disk\docker_data.vhdx"
   detach vdisk
   ```
   → debe responder: *"DiskPart ocultó correctamente el archivo de disco virtual."*
3. **Verificar**: `Get-Disk` debe mostrar solo el SSD y el disco externo (sin `Msft Virtual Disk`).
4. Si el fantasma persiste tras 1–2 intentos → **reiniciar Windows** (VDS arranca limpio) y
   compactar después con el script.

### Reglas de oro (para que NO vuelva a pasar)

- ❗ **NUNCA matar `diskpart`** a mitad de `attach`/`compact`. Sobre USB puede tardar **horas**; un
  valor de porcentaje clavado (p. ej. 84 %) durante mucho tiempo **es normal** mientras mueve bloques.
- ❗ Compactar **siempre** con Docker parado y `wsl --shutdown` hecho.
- ❗ Hacer `attach vdisk readonly` + `compact vdisk` + `detach vdisk` en **UNA sola sesión de
  diskpart** (lo hace el script) — nunca pasos manuales intercalados.
- ❗ Aceptar el UAC y **no cerrar** esa ventana hasta el final.
- ❗ Nunca lanzar dos `diskpart` a la vez sobre el mismo vhdx.

---

## 3. Procedimiento correcto (script one-shot)

[`scripts/compact-docker-vhdx.ps1`](../scripts/compact-docker-vhdx.ps1) hace todo en orden:

```powershell
# desde la raíz del repo, en PowerShell normal (el script se auto-eleva por UAC)
powershell -ExecutionPolicy Bypass -File scripts\compact-docker-vhdx.ps1
```

Pasos internos:

1. Localiza el vhdx (`F:\docker\wsl\disk\docker_data.vhdx` o vía el junction de `%LOCALAPPDATA%`).
2. Para Docker Desktop + `wsl --shutdown`.
3. **Una sola sesión** `diskpart /s`: `select vdisk` → `attach vdisk readonly` → `compact vdisk` → `detach vdisk`.
4. Informa antes/después + espacio libre y vuelve a arrancar Docker Desktop.

**¿Está trabajando o colgado?** Con el porcentaje aparentemente clavado, mide I/O de F: — si hay
lectura+escritura (aunque la CPU de `diskpart` sea ~0), está avanzando:

```powershell
Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk |
  Where-Object Name -eq "F:" | Select-Object DiskReadBytesPersec, DiskWriteBytesPersec
```

---

## 4. Cronología del caso real (12 Oct 2026)

| Fase | Qué pasó | Lección |
|---|---|---|
| 1 | C: y F: casi llenos (2,5 GB / 0,6 GB). vhdx 73,43 GB con solo ~11 GB reales | Diagnosticar con `docker system df` vs tamaño del vhdx |
| 2 | `docker image/builder prune` (13 GB liberados) + temps + papelera (C: → 13,4 GB); `F:\ISOS` borrado (14 GB) | El prune **NO** encoge el vhdx |
| 3 | Primer `diskpart compact` colgado en "Compactando" → **matado** → apareció `Disco 2` fantasma | Nunca matar diskpart |
| 4 | `attach` → "ya está expuesto"; `detach` → "ya está oculto" | Estado VDS corrupto |
| 5 | `Stop-Service vds -Force` + `Start-Service vds` limpió "Compactando"; `detach vdisk` limpió el fantasma | Receta de recuperación §2 |
| 6 | Compact en proceso separado (sin matarlo): 10 % → 84 % → 97 % → 100 % en ~3 h, CPU ~0 pero I/O continuo en F: | Dejarlo trabajar; medir I/O para distinguir "lento" de "colgado" |
| 7 | vhdx 73,43 → 26,13 GB; F: 0,36 → 65,65 GB. `detach` final + Docker arrancado: ambos contenedores `healthy` | Post-check siempre: `Get-Disk` sin fantasma + `docker ps` |

---

## 5. Mantenimiento preventivo recomendado

- **Mensual**, o cuando **F: baje de 20 GB libres**: ejecutar
  `docker image prune -a -f` + `docker builder prune -a -f`; si el vhdx supera ~35 GB, lanzar el
  script de compactación.
- Antes de cerrar sesiones largas de auditoría: `docker system prune -f`.
- **No mover el junction de Docker** sin actualizar esta guía: el vhdx debe vivir en un disco con
  espacio y compactable.
- Al borrar datos manuales (ISOs, VMs), verificar después que el espacio se recuperó y que
  `Get-Disk` no muestra discos fantasma.

### Checklist rápido

```text
[ ] ¿Docker parado?            docker desktop stop  +  wsl --shutdown
[ ] ¿UAC aceptado?             ventana elevada abierta, no cerrarla
[ ] ¿Una sola sesión diskpart? attach readonly + compact + detach
[ ] ¿Paciencia?                puede tardar horas (USB) — NO MATAR diskpart
[ ] ¿Post-check?               Get-Disk sin fantasma + docker ps healthy
```

---

> **Relacionado:** [`DOCKER_GUIDE.md`](../DOCKER_GUIDE.md) (stack Docker) ·
> [`docs/MANUAL_VERIFICATION.md`](MANUAL_VERIFICATION.md) (verificación E2E) ·
> [`TOMORROW.md`](../TOMORROW.md) § Postmortem — Docker vhdx/disco fantasma.