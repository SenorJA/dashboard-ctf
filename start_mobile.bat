@echo off
title MIRV — Server (Mobile)
echo ======================================
echo   M.I.R.V. — Arrancando servidor...
echo   Accesible desde el movil en la misma WiFi
echo ======================================
echo.
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
