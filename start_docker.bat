@echo off
title MIRV — Docker Stack (kali-mcp + Backend)
echo ======================================
echo   M.I.R.V. + kali-mcp Full Stack
echo ======================================
echo.
echo Building and starting containers...
echo   - kali-mcp : Kali Linux with 50+ security tools
echo   - mirv-backend : MIRV FastAPI dashboard
echo.
echo First build may take 10-20 minutes (Docker image).
echo.
docker compose up -d --build
echo.
if %errorlevel% equ 0 (
    echo ✅ Stack started!
    echo.
    echo   Dashboard: http://localhost:8000
    echo   kali-mcp:  http://localhost:666/mcp
    echo.
    echo To view logs:
    echo   docker compose logs -f
    echo.
    echo To stop:
    echo   docker compose down
) else (
    echo ❌ Failed to start. Check Docker is running.
)
pause
