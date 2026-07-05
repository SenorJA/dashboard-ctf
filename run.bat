@echo off
cd /d "%~dp0"
echo ==================================================
echo   VulnForge - Red Team Dashboard
echo   Abre http://localhost:8000 en tu navegador
echo ==================================================
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
pause
