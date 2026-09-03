@echo off
REM ────────────────────────────────────────────────────────────────────────
REM  MIRV — build backend sidecar with PyInstaller
REM
REM  Builds dist\mirv-backend\mirv-backend.exe (one-dir layout) including
REM  built-in skills/, plugins/ and the frontend/ assets for standalone mode.
REM
REM  Usage:
REM    build_backend.bat                    -> build one-dir binary
REM    build_backend.bat --onefile          -> build single .exe
REM
REM  After building, copy the binary into the Tauri project:
REM    xcopy /E /I /Y dist\mirv-backend ..\desktop\src-tauri\binaries\mirv-backend
REM ────────────────────────────────────────────────────────────────────────

setlocal
cd /d "%~dp0"

echo [*] Installing PyInstaller...
python -m pip install --quiet pyinstaller
if errorlevel 1 goto :fail

if "%1"=="--onefile" (
    echo [*] Building single-file mirv-backend.exe ...
    python -m PyInstaller --noconfirm --clean ^
        --onefile ^
        --name mirv-backend ^
        --paths . ^
        --add-data "skills;backend/skills" ^
        --add-data "plugins;backend/plugins" ^
        --add-data "..\frontend;frontend" ^
        --hidden-import paramiko ^
        --hidden-import cryptography ^
        --hidden-import websockets ^
        --hidden-import reportlab ^
        --hidden-import supabase ^
        --hidden-import python-dotenv ^
        --hidden-import python-multipart ^
        --exclude-module tkinter ^
        --exclude-module pytest ^
        main.py
) else (
    echo [*] Building one-dir mirv-backend (spec) ...
    python -m PyInstaller --noconfirm --clean mirv-backend.spec
)

if errorlevel 1 goto :fail

echo.
echo [OK] Build complete.
echo   -> dist\mirv-backend\mirv-backend.exe
echo.
echo Copy it to the Tauri sidecar dir:
echo   xcopy /E /I /Y dist\mirv-backend ..\desktop\src-tauri\binaries\mirv-backend
exit /b 0

:fail
echo [FAIL] Build failed.
exit /b 1
