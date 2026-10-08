@echo off
REM ────────────────────────────────────────────────────────────────────────
REM  MIRV — build backend sidecar with PyInstaller
REM
REM  Builds dist\mirv-backend.exe (one-file layout) bundling the built-in
REM  skills/, plugins/, agents/ (Pack 17 AI personas) and the frontend/ assets
REM  so the frozen binary finds them under sys._MEIPASS.
REM
REM  Usage:
REM    build_backend.bat                    -> build via mirv-backend.spec (default)
REM    build_backend.bat --onefile          -> same one-file build, CLI flags only
REM
REM  After building, copy the binary into the Tauri project (target-triple name
REM  required by tauri.conf.json "externalBin": binaries/mirv-backend):
REM    copy /Y dist\mirv-backend.exe ..\desktop\src-tauri\binaries\mirv-backend-x86_64-pc-windows-msvc.exe
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
        --add-data "agents;backend/agents" ^
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
    echo [*] Building one-file mirv-backend.exe (mirv-backend.spec) ...
    python -m PyInstaller --noconfirm --clean mirv-backend.spec
)

if errorlevel 1 goto :fail

echo.
echo [OK] Build complete.
echo   -^> dist\mirv-backend.exe
echo.
echo Copy it to the Tauri sidecar dir (see desktop\build_desktop.bat step 2):
echo   copy /Y dist\mirv-backend.exe ..\desktop\src-tauri\binaries\mirv-backend-x86_64-pc-windows-msvc.exe
exit /b 0

:fail
echo [FAIL] Build failed.
exit /b 1
