@echo off
title VulnForge — Production Mode
cd /d "%~dp0.."

echo ════════════════════════════════════════════
echo   VulnForge — Production Mode
echo ════════════════════════════════════════════
echo.

:: ── Ensure logs directory exists ──
if not exist "backend\logs" mkdir "backend\logs"

:: ── Check prerequisites ──
where uvicorn >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [✕] uvicorn not found. Run: pip install uvicorn fastapi
    pause
    exit /b 1
)

set "CLOUDFLARED_MISSING=0"
if not exist "C:\cloudflared\cloudflared.exe" (
    echo [⚠] cloudflared not found at C:\cloudflared\cloudflared.exe
    echo     Download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
    echo     The tunnel will NOT start, but the backend will still run locally.
    echo.
    set "CLOUDFLARED_MISSING=1"
)

:: ── Start backend (no reload, production mode) ──
echo [*] Starting VulnForge backend on http://0.0.0.0:8000 ...

start "VulnForge-Backend" /B uvicorn backend.main:app --host 0.0.0.0 --port 8000 --log-level info

:: Wait for backend to initialize
timeout /t 3 /nobreak >nul

:: ── Start Cloudflare Tunnel (if available) ──
if "%CLOUDFLARED_MISSING%"=="0" (
    echo [*] Starting Cloudflare tunnel...
    start "VulnForge-Tunnel" /B C:\cloudflared\cloudflared.exe tunnel run vulnforge
    echo [✓] Tunnel started
) else (
    echo [⚠] Cloudflared not installed — skipping tunnel.
    echo     Local access only: http://localhost:8000
)

echo.
echo ════════════════════════════════════════════
echo   VulnForge is RUNNING
echo   Local:   http://localhost:8000
echo   Remote:  https://vulnforge.YOUR-DOMAIN.com
echo ════════════════════════════════════════════
echo.
echo   Press any key to STOP all services...
pause >nul

:: ── Clean shutdown ──
echo.
echo [*] Stopping services...
taskkill /F /FI "WINDOWTITLE eq VulnForge-Backend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq VulnForge-Tunnel*" >nul 2>&1
echo [✓] Stopped.

timeout /t 2 /nobreak >nul
