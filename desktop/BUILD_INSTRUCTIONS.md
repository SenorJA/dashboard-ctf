# 🔧 MIRV Desktop — Instrucciones exactas de build

Guía paso a paso para compilar el instalable de escritorio MIRV
(sidecar Python + shell Tauri), tanto **localmente en Windows** como **en CI**
(GitHub Actions).

---

## 1. Resumen de la arquitectura

```
MIRV Desktop = shell Tauri (WebView2) + sidecar Python (FastAPI)
```

- **Sidecar** = el backend FastAPI empaquetado a un `.exe` con **PyInstaller**
  (`backend/mirv-backend.spec`). Se lanza con `--tauri-mode` (no sirve el SPA,
  no auto-reload, puerto configurable).
- **Shell** = una app **Tauri v2** (`desktop/src-tauri/`) que arranca el sidecar,
  hace health-check a `http://localhost:8000/api/health` y muestra el SPA.
- **Frontend** = el SPA canónico (`frontend/`) copiado a `desktop/src/` por
  `desktop/scripts/sync-frontend.mjs` y servido por el WebView de Tauri.

Rutas de red remapeadas en `frontend/js/main.v2.js` (cuando detecta Tauri):
- `fetch('/api…')`  → `http://localhost:8000/api…`
- `WebSocket`       → `ws://localhost:8000/ws`

---

## 2. Pre-requisitos (Windows, una sola vez)

| Requisito | Instalación | Mínimo |
|-----------|-------------|--------|
| WebView2 Runtime | Viene preinstalado con Windows 11 / Edge. Si falta, descargar de <https://developer.microsoft.com/microsoft-edge/webview2/> | — |
| Python + pip | <https://www.python.org/downloads/> (marcar **"Add to PATH"**) | 3.11 |
| Node.js + npm | <https://nodejs.org/> (LTS) | 18+ |
| Rust / Cargo | <https://rustup.rs> (instalar **MSVC toolchain**) | stable |
| MSVC Build Tools | `rustup` instala el linker automáticamente vía `stable-x86_64-pc-windows-msvc`. Si no, instalar "Visual Studio Build Tools → C++ workload". | — |

Verifica desde un terminal:

```powershell
python --version
node --version
npm --version
cargo --version
rustc --version
```

---

## 3. Build local en Windows

### Opción A — Todo con un solo script (recomendado)

```powershell
cd desktop
.\build_desktop.bat
```

Genera `desktop/src-tauri/target/release/bundle/msi/MIRV_3.0.0_x64_en-US.msi`.

### Opción B — Manual paso a paso (para depurar)

```bash
# 1) Backend sidecar
cd backend
pip install -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --clean mirv-backend.spec
#    -> backend/dist/mirv-backend/  (carpeta one-dir con el .exe) 

# 2) Copiar el sidecar a Tauri
cd ..\desktop
mkdir src-tauri\binaries\mirv-backend
xcopy /E /I /Y ..\backend\dist\mirv-backend  src-tauri\binaries\mirv-backend\
#    Tauri a veces requiere el sufijo target:
#    ren src-tauri\binaries\mirv-backend\mirv-backend.exe mirv-backend-x86_64-pc-windows-msvc.exe

# 3) Dependencias npm
npm install

# 4) Sincronizar el frontend canónico -> src
node scripts\sync-frontend.mjs

# 5) Build del instalador MSI
npm run tauri build -- --bundles msi
```

> **Iconos:** si `src-tauri/icons/` está vacío, generar una vez:
> `npx tauri icon ..\frontend\img\icon-192.svg src-tauri\icons`

### Opción C — Desarrollo en vivo (hot reload del WebView)

```bash
cd desktop
npm install
npm run prebuild     # copia frontend/ -> src/
npm run tauri dev    # abre la ventana Tauri; el sidecar se lanza solo
```

---

## 4. Build en CI (GitHub Actions)

El workflow **`.github/workflows/desktop-build.yml`** compila automáticamente:

- **En cualquier push/PR a `main`**: build de verificación + sube el `.msi`
  como artefacto (`mirv-desktop-msi`) al run.
- **En un tag `v*`**: además crea/adjunta una **GitHub Release** con el `.msi`.

Para lanzarlo manualmente sin esperar un push: Actions → **Desktop Build** →
"Run workflow".

Flujo interno del job (`windows-latest`):
1. `setup-python` (cache) → `pip install` deps + pyinstaller
2. `PyInstaller mirv-backend.spec` → sidecar
3. Copia el sidecar a `desktop/src-tauri/binaries/mirv-backend/`
4. `setup-node` + `npm install`
5. `node scripts/sync-frontend.mjs`
6. `dtolnay/rust-toolchain@stable` + `Swatinem/rust-cache@v2`
7. `tauri-apps/tauri-action@v0` → build MSI (y Release en tags)

> **Para subir un release manualmente:** crea un tag y haz push:
> ```bash
> git tag v3.0.0
> git push origin v3.0.0
> ```
> El workflow genera el `.msi` y lo adjunta al Release `v3.0.0`.

---

## 5. Solución de problemas

| Síntoma | Causa / Fix |
|---------|-------------|
| `Could not import module 'main'` (exe) | Version vieja del sidecar; **recompilar** con PyInstaller. La versión actual pasa el app object directo en modo frozen. |
| Tauri no encuentra el sidecar | Falta el sufijo target: renombrar a `mirv-backend-x86_64-pc-windows-msvc.exe`. |
| `cargo: not found` | Instalar Rust (rustup) y reabrir el terminal. |
| **MSB error / linker** | Instalar MSVC Build Tools "C++ workflow". |
| CORS en dev | El `api_origin` server usa 8000; el CSP del `tauri.conf.json` ya permite `localhost:8000` + `ws://localhost:8000`. |
| El MSI pide "WebView2' | Instalar WebView2 Runtime. |
| El puerto 8000 ocupado | `set MIRV_PORT=8199` antes de lanzar; el frontend usa `window.MIRV_API_URL`. |

---

## 6. Puertos y variables de entorno

| Variable | Default | Descripción |
|----------|---------|-------------|
| `PORT` / `MIRV_PORT` | `8000` | Puerto del backend (sidecar) |
| `MIRV_HOST` | `0.0.0.0` | Bind del backend |
| `MIRV_API_URL` | `http://localhost:8000` | Forzar base API en el WebView Tauri |
| `MIRV_WS_URL` | `ws://localhost:8000/ws` | Forzar WebSocket en el WebView Tauri |
| `SUPABASE_URL`/`SUPABASE_KEY` | — | Persistencia (si vacíos → localStorage) |
| `KALI_IP`/`KALI_MCP_URL` | — | Conexión a Kali |

---

## 7. Verificación post-build

```powershell
# 1) Lanzar el .exe/instalado
.\mirv-backend.exe --tauri-mode --host 127.0.0.1 --port 8199
#    -> arranca; health en http://127.0.0.1:8199/api/health

# 2) Comprobar que responde (deberia devolver JSON)
curl http://localhost:8000/api/health
# {"status":"degraded","mode":"production",...} es NORMAL si no hay Supabase/Kali

# 3) En la app Tauri, ver que la ventana muestra el SPA y el sidecar sube
#    (barra de terminal / pestañas cargan).
```

> El estado `"status":"degraded"` **no es un fallo** — solo indica que faltan
> credenciales externas (Supabase/Kali). La app funciona en modo local.
