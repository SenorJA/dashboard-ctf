# 💻 MIRV Desktop

Instalable desktop app (Windows `.msi`) que empaqueta el backend FastAPI de
MIRV (Python → `mirv-backend.exe` vía PyInstaller) y lo lanza como *sidecar*
de una shell **Tauri** (WebView2) que carga el SPA.

```
┌──────────────────────────────────────────┐
│            Tauri App (.exe/.msi)          │
│  ┌──────────────┐     ┌────────────────┐  │
│  │  WebView2    │     │  Python sidecar│  │
│  │  desktop/src │◄──► │ mirv-backend   │  │
│  │  (SPA)       │ REST│ (localhost:8000)│  │
│  └──────────────┘  WS └────────┬───────┘  │
│                                │ SSH       │
│                          Kali VM (LAN)     │
└──────────────────────────────────────────┘
```

## Requisitos

- **Windows 10/11** con WebView2 (viene preinstalado en Win11)
- **Python 3.11+** (para compilar el sidecar con PyInstaller)
- **Node.js 18+** y npm
- **Rust toolchain** (`rustup`, `cargo`) — <https://rustup.rs>
- MSVC Build Tools (C++ linker) para compilar Tauri

## Cómo construir

```bash
desktop\build_desktop.bat          # build completo -> .msi
```

Equivale a:

```bash
# 1. Backend sidecar (backend/)
cd backend
pip install -r requirements.txt pyinstaller
pyinstaller mirv-backend.spec        # -> dist\mirv-backend\

# 2. Copiar sidecar al proyecto Tauri
copy dist\mirv-backend\* ..\desktop\src-tauri\binaries\mirv-backend\
copy dist\mirv-backend\*.dll ..\desktop\src-tauri\binaries\mirv-backend\

# 3. Sincronizar frontend canónico
cd ..\desktop
npm install
node scripts\sync-frontend.mjs      # copia frontend/ -> src/

# 4. Iconos (una vez)
npx tauri icon ..\frontend\img\icon-192.svg src-tauri\icons

# 5. Build del instalador
npm run tauri build -- --bundles msi
```

Output: `src-tauri\target\release\bundle\msi\MIRV_3.0.0_x64_en-US.msi`

## Estructura

```
desktop/
├── build_desktop.bat        # orquestación completa
├── package.json             # scripts npm + @tauri-apps/cli
├── scripts/
│   └── sync-frontend.mjs    # copia frontend/ canónico -> src/
├── src/                     # (generado, gitignored) SPA copiado
└── src-tauri/
    ├── Cargo.toml           # dependencias Rust
    ├── tauri.conf.json      # ventana + CSP + sidecar
    ├── build.rs
    ├── icons/               # (generados) iconos de la app
    ├── binaries/mirv-backend # (generado) sidecar .exe + dll + data
    └── src/main.rs          # lanza sidecar, health-check, muestra UI
```

## Arquitectura de red

- El sidecar arranca en `http://localhost:8000` (puerto por env `MIRV_PORT`/`PORT`).
- El frontend Tauri detecta el entorno (`window.__TAURI_INTERNALS__`) en
  `frontend/js/main.v2.js` y remapea:
  - `fetch('/api…')` → `http://localhost:8000/api…` (monkeypatch automático)
  - `WebSocket` → `ws://localhost:8000/ws` (`window.WS_URL`)
- El backend se lanza con `--tauri-mode` (no sirve el SPA, no auto-reload).
- Al cerrar la ventana, Tauri mata el sidecar.

## Prueba en desarrollo (sin empaquetar)

```bash
# 1. Arranca el backend normal
cd backend
uvicorn main:app --port 8000

# 2. Carga el SPA desde el navegador sirviéndolo por otro origen,
#    o corre el WebView en modo dev:
cd desktop
npm install @tauri-apps/cli
npm run prebuild && npm run tauri dev
```

## Notas

- **CSP**: permite `connect-src http://localhost:8000 ws://localhost:8000`
  para API/WS del backend y Tailwind CDN. Si se migra Tailwind a build local,
  eliminar `https://cdn.tailwindcss.com` de `script-src`/`style-src`.
- **Windows redirects**: el sidecar `.exe` puede requerir el sufijo de triple
  target (`mirv-backend-x86_64-pc-windows-msvc.exe`). El `build_desktop.bat`
  copia el binario; renómbralo al sufijo target si Tauri no lo resuelve.
- **Distribución**: subir el `.msi` a GitHub Releases; un auto-updater con
  `tauri-plugin-updater` puede añadirse en el futuro.
