<#
.SYNOPSIS
    Compacta el docker_data.vhdx de Docker Desktop de forma SEGURA.

.DESCRIPTION
    Evita el clasico "disco fantasma" del servicio VDS ejecutando
    attach readonly + compact + detach en UNA SOLA sesion de diskpart,
    con Docker Desktop y WSL parados.

    Ver docs/DISK_MAINTENANCE.md para el procedimiento completo y la
    recuperacion si el estado fantasma ya existe.

    IMPORTANTE: sobre USB la compactacion puede tardar HORAS. NO matar
    diskpart a mitad; un porcentaje clavado es normal mientras mueve bloques.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\compact-docker-vhdx.ps1

.EXAMPLE
    # ruta explicita + no reiniciar Docker al terminar
    powershell -ExecutionPolicy Bypass -File scripts\compact-docker-vhdx.ps1 -Vhd "F:\docker\wsl\disk\docker_data.vhdx" -NoStart
#>
param(
    [string]$Vhd,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'

# ── 0. Auto-elevacion (attach/compact requieren admin) ─────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host 'Pidiendo elevacion (UAC)... acepta el prompt, no cierres la ventana.'
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Vhd) { $argsList += @('-Vhd', "`"$Vhd`"") }
    if ($NoStart) { $argsList += '-NoStart' }
    Start-Process powershell -Verb RunAs -ArgumentList $argsList
    exit 0
}

# ── 1. Localizar el vhdx ───────────────────────────────────────────
if (-not $Vhd) {
    $candidates = @(
        'F:\docker\wsl\disk\docker_data.vhdx',
        (Join-Path $env:LOCALAPPDATA 'Docker\wsl\disk\docker_data.vhdx')
    )
    $Vhd = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Vhd -or -not (Test-Path $Vhd)) {
    Write-Error "No encuentro docker_data.vhdx. Pasa la ruta con -Vhd 'X:\ruta\docker_data.vhdx'"
}
$real = (Get-Item $Vhd).FullName
Write-Host "VHDX: $real"

$freeBefore = (Get-PSDrive (Split-Path -Qualifier $real)).Free
$before = (Get-Item $real).Length
Write-Host ("Antes: {0:N2} GB  |  disco libre {1:N2} GB" -f ($before / 1GB), ($freeBefore / 1GB))

# ── 2. Pre-check de disco fantasma ─────────────────────────────────
$ghost = Get-Disk | Where-Object { $_.FriendlyName -eq 'Msft Virtual Disk' }
if ($ghost) {
    Write-Warning "Hay un disco virtual expuesto (posible fantasma: $($ghost.Number)). Si el compact falla, aplica docs/DISK_MAINTENANCE.md seccion 2 (Stop-Service vds + detach)."
}

# ── 3. Parar Docker Desktop + WSL ──────────────────────────────────
Write-Host 'Parando Docker Desktop...'
& docker desktop stop 2>$null
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Process 'com.docker.backend' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
}
if (Get-Process 'com.docker.backend' -ErrorAction SilentlyContinue) {
    Write-Error 'com.docker.backend sigue vivo. Abortando: no compactar con Docker activo.'
}
Write-Host 'wsl --shutdown'
& wsl --shutdown
Start-Sleep -Seconds 5

# ── 4. UNA sola sesion diskpart (sin estados intermedios) ──────────
$scriptFile = Join-Path $env:TEMP 'mirv-compact-vhdx.txt'
$outFile    = Join-Path $env:TEMP 'mirv-compact-vhdx.out'
@(
    "select vdisk file=`"$real`"",
    'attach vdisk readonly',
    'compact vdisk',
    'detach vdisk',
    'exit'
) | Out-File -Encoding ascii $scriptFile

Write-Host 'Compactando... (puede tardar horas sobre USB; NO cerrar ni matar diskpart)'
$p = Start-Process -FilePath "$env:SystemRoot\System32\diskpart.exe" `
     -ArgumentList '/s', $scriptFile `
     -RedirectStandardOutput $outFile -PassThru
while (-not $p.HasExited) {
    $last = Get-Content $outFile -Tail 1 -ErrorAction SilentlyContinue
    Write-Host ("  {0}  vhdx={1:N2} GB  [{2}]" -f (Get-Date -Format 'HH:mm:ss'), ((Get-Item $real).Length / 1GB), $last)
    Start-Sleep -Seconds 30
}
$p.WaitForExit()
Write-Host '--- salida diskpart ---'
Get-Content $outFile

# ── 5. Resultado + post-check ──────────────────────────────────────
$after = (Get-Item $real).Length
$freeAfter = (Get-PSDrive (Split-Path -Qualifier $real)).Free
Write-Host ("Despues: {0:N2} GB  (liberado {1:N2} GB)  |  disco libre {2:N2} GB" -f ($after / 1GB), (($before - $after) / 1GB), ($freeAfter / 1GB))
Write-Host 'Discos actuales (no debe aparecer "Msft Virtual Disk" fantasma):'
Get-Disk | Format-Table Number, FriendlyName, OperationalStatus, Size -AutoSize

if (-not $NoStart) {
    Write-Host 'Arrancando Docker Desktop...'
    $dd = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path $dd) { Start-Process $dd } else { & docker desktop start }
    Write-Host 'Docker Desktop lanzado. Verifica con: docker ps'
}
Write-Host 'Listo. Guia completa: docs/DISK_MAINTENANCE.md'