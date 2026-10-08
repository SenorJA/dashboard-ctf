@echo off
REM ────────────────────────────────────────────────────────────────────────
REM  MIRV Desktop — end-to-end build (backend sidecar + Tauri shell)
REM
REM  1. Builds backend with PyInstaller -> dist\mirv-backend.exe (one-file)
REM  2. Copies the sidecar as src-tauri\binaries\mirv-backend-<triple>.exe
REM  3. Syncs the canonical frontend into src\
REM  4. Builds the Tauri installer (msi by default)
REM
REM  Prereqs: Python, Node 18+, Rust toolchain, WebView2.
REM ────────────────────────────────────────────────────────────────────────

setlocal
cd /d "%~dp0"

echo ==========================================
echo  [1/4] Build backend sidecar (PyInstaller)
echo ==========================================
call ..\backend\build_backend.bat
if errorlevel 1 goto :fail

echo.
echo ==========================================
echo  [2/4] Copy sidecar into src-tauri\binaries
echo ==========================================
mkdir "src-tauri\binaries" 2>nul
REM tauri.conf.json "externalBin": ["binaries/mirv-backend"] resolves to the
REM target-triple name, and mirv-backend.spec emits a one-file .exe — copy it
REM there directly (build_backend.bat always builds dist\mirv-backend.exe).
set "SIDECAR=src-tauri\binaries\mirv-backend-x86_64-pc-windows-msvc.exe"
if not exist "..\backend\dist\mirv-backend.exe" (
    echo   [FAIL] ..\backend\dist\mirv-backend.exe not found — run build_backend.bat first
    goto :fail
)
copy /Y "..\backend\dist\mirv-backend.exe" "%SIDECAR%" >nul
if errorlevel 1 goto :fail
if not exist "%SIDECAR%" (
    echo   [FAIL] %SIDECAR% missing after copy
    goto :fail
)
echo   -^> %SIDECAR% (skills/ plugins/ agents/ van in the .exe)

echo.
echo ==========================================
echo  [3/4] Sync canonical frontend into src\
echo ==========================================
call npm install --silent
if errorlevel 1 goto :fail
call node scripts\sync-frontend.mjs
if errorlevel 1 goto :fail

echo.
echo ==========================================
echo  [4/4] Build Tauri installer
echo ==========================================
REM Generate app icons from the SVG (one-time; commit the generated files).
if not exist "src-tauri\icons\32x32.png" (
    echo   generating icons from frontend/img/icon-192.svg ...
    call npx tauri icon "..\frontend\img\icon-192.svg" "src-tauri\icons"
    if errorlevel 1 echo   [warn] icon generation failed — supply icons manually.
)

call npm run tauri build -- --bundles msi
if errorlevel 1 goto :fail

echo.
echo [OK] MIRV Desktop installer:
echo   src-tauri\target\release\bundle\msi\MIRV_3.5.0_x64_en-US.msi
exit /b 0

:fail
echo [FAIL] MIRV Desktop build failed.
exit /b 1
