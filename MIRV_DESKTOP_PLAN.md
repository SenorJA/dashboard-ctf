# 💻 MIRV Desktop — Plan de Implementación

> App de escritorio instalable con Tauri + backend Python embebido
> Última actualización: Julio 2026

---

## Arquitectura

```
┌──────────────────────────────────────────┐
│            Tauri App (.exe/.msi)          │
│                                           │
│  ┌──────────────┐    ┌────────────────┐  │
│  │  WebView     │    │  Python        │  │
│  │  (frontend)  │◄──►│  Sidecar       │  │
│  │  index.html  │WS  │  main.py       │  │
│  │  main.v2.js  │REST│  (localhost)   │  │
│  └──────────────┘    └────────┬───────┘  │
│                               │ SSH       │
│                               ▼           │
│                         Kali VM (LAN)     │
└──────────────────────────────────────────┘
```

- **Frontend** embebido en Tauri como archivos estáticos
- **Backend Python** compilado a .exe con PyInstaller, lanzado como sidecar
- **Tauri** orquesta: abrir app → arrancar backend → cargar frontend → cerrar → matar backend

---

## Fase 1 — Backend compilable con PyInstaller (3 días)

### Cambios en backend/main.py

```python
import sys
import os

# Detectar si corremos como .exe empaquetado
if getattr(sys, 'frozen', False):
    # PyInstaller runtime: los paths son diferentes
    BASE_DIR = sys._MEIPASS
    IS_PACKAGED = True
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    IS_PACKAGED = False

# Flag --tauri-mode: omite mount de archivos estáticos
TAURI_MODE = '--tauri-mode' in sys.argv
if TAURI_MODE:
    # No montar /static/ — el frontend va en Tauri
    pass
else:
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

# Puerto configurable
PORT = int(os.environ.get('MIRV_PORT', 8000))
```

### Script de compilación

```bash
# build_backend.bat
pip install pyinstaller
pyinstaller --onefile ^
    --name mirv-backend ^
    --add-data "backend/operators;operators" ^
    --hidden-import paramiko ^
    --hidden-import websockets ^
    --hidden-import reportlab ^
    --hidden-import supabase ^
    --hidden-import python-dotenv ^
    --hidden-import python-multipart ^
    main.py
```

**Nota:** Pueden aparecer hidden imports adicionales. Probar con `--debug` si falla.

### Verificación

```bash
dist/mirv-backend.exe --tauri-mode
# Debería arrancar en localhost:8000 sin servir frontend
```

---

## Fase 2 — Frontend standalone (2 días)

### Cambios en frontend/js/main.v2.js

```javascript
// 1. Detectar Tauri
const IS_TAURI = !!(window.__TAURI_INTERNALS__);

// 2. Configurar URLs base
const API_BASE = IS_TAURI ? 'http://localhost:8000' : '';
const WS_BASE = IS_TAURI ? 'ws://localhost:8000' : `ws://${location.host}`;

// 3. Reemplazar llamadas API
// Antes:
fetch('/api/findings')
// Después:
fetch(`${API_BASE}/api/findings`)

// 4. Reemplazar WebSocket
// Antes:
new WebSocket(`ws://${location.host}/ws`)
// Después:
new WebSocket(`${WS_BASE}/ws`)
```

### Archivos a copiar para Tauri

```
desktop/src/
├── index.html          <- copia de frontend/index.html
├── js/
│   ├── main.v2.js     <- copia con cambios de rutas
│   ├── dataservice.js <- copia
│   ├── mobile.js      <- copia
│   ├── forensics.js   <- copia
│   └── swarm.js       <- copia
└── css/
    └── style.css      <- copia
```

---

## Fase 3 — Proyecto Tauri (5 días)

### Prerrequisitos

```bash
# Windows: instalar WebView2 (viene con Windows 11)
# Rust: https://rustup.rs
# Node.js 18+
# Clang: https://github.com/llvm/llvm-project/releases

# Verificar
rustc --version
cargo --version
node --version
npm --version
```

### Crear proyecto

```bash
mkdir desktop
cd desktop
npm create tauri-app@latest -- --template vanilla
# Responde: "MIRV" como nombre, "vanilla" como template
```

### Estructura resultante

```
desktop/
├── package.json
├── src/                    # Frontend (copiar aquí frontend/)
│   ├── index.html
│   ├── js/
│   └── css/
├── src-tauri/
│   ├── Cargo.toml          # Dependencias Rust
│   ├── tauri.conf.json     # Configuración de la app
│   ├── build.rs
│   ├── icons/              # Iconos de la app
│   └── src/
│       └── main.rs         # Lógica nativa
└── src-tauri/binaries/     # Aquí va mirv-backend.exe
```

### tauri.conf.json (config clave)

```json
{
  "productName": "MIRV",
  "version": "3.0.0",
  "identifier": "com.mirv.app",
  "build": {
    "frontendDist": "../src",
    "devUrl": "http://localhost:5173",
    "beforeDevCommand": "",
    "beforeBuildCommand": ""
  },
  "app": {
    "windows": [
      {
        "title": "M.I.R.V. — Multi-platform Incident Response & Vulnerabilities",
        "width": 1200,
        "height": 800,
        "minWidth": 800,
        "minHeight": 600,
        "resizable": true,
        "fullscreen": false
      }
    ],
    "security": {
      "csp": "default-src 'self'; connect-src 'self' http://localhost:8000 ws://localhost:8000; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com"
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/32x32.png",
      "icons/128x128.png",
      "icons/128x128@2x.png",
      "icons/icon.icns",
      "icons/icon.ico"
    ]
  },
  "plugins": {
    "shell": {
      "sidecar": [
        {
          "name": "mirv-backend",
          "args": ["--tauri-mode"]
        }
      ]
    }
  }
}
```

### main.rs (Rust — lógica del sidecar)

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use std::time::Duration;
use std::thread;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let shell = app.shell();

            // 1. Lanzar backend sidecar
            let sidecar_command = shell.sidecar("mirv-backend")
                .expect("Failed to create sidecar command")
                .args(["--tauri-mode"]);

            let (mut rx, _child) = sidecar_command
                .spawn()
                .expect("Failed to spawn backend sidecar");

            // 2. Health check: esperar a que responda
            let backend_url = "http://localhost:8000/api/health";
            let client = reqwest::blocking::Client::new();

            for i in 0..30 {
                if let Ok(resp) = client.get(backend_url).send() {
                    if resp.status().is_success() {
                        println!("Backend ready after {}s", i);
                        break;
                    }
                }
                thread::sleep(Duration::from_secs(1));
            }

            // 3. Mostrar ventana principal
            let window = app.get_webview_window("main").unwrap();
            window.show().unwrap();
            window.set_focus().unwrap();

            // 4. Escuchar stdout del sidecar (para logs)
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        tauri_plugin_shell::process::CommandEvent::Stdout(line) => {
                            println!("[backend] {}", String::from_utf8_lossy(&line));
                        }
                        tauri_plugin_shell::process::CommandEvent::Stderr(line) => {
                            eprintln!("[backend:err] {}", String::from_utf8_lossy(&line));
                        }
                        tauri_plugin_shell::process::CommandEvent::Terminated(status) => {
                            eprintln!("Backend terminated with: {:?}", status);
                            // Opción: reiniciar backend
                        }
                        _ => {}
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Matar backend
                // La shell sidecar se encarga automáticamente al cerrar la app
            }
        })
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

### Cargo.toml

```toml
[package]
name = "mirv-desktop"
version = "3.0.0"
description = "M.I.R.V. — Multi-platform Incident Response & Vulnerabilities"
authors = ["SenorJA"]
edition = "2021"

[lib]
name = "mirv_desktop_lib"
crate-type = ["lib", "cdylib", "staticlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-shell = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
reqwest = { version = "0.12", features = ["blocking"] }
```

---

## Fase 4 — Calidad de vida (3 días)

| Característica | Implementación |
|----------------|----------------|
| **System tray** | `tauri-plugin-tray` con menú: "Abrir MIRV" / "Salir" |
| **Auto-updater** | `tauri-plugin-updater` + GitHub Releases para distribución de updates |
| **Splash screen** | Ventana temporal con logo mientras arranca el backend |
| **Iconos** | Generar con `cargo tauri icon` desde un PNG 1024x1024 |
| **Error handling** | Diálogo con `tauri::api::dialog::message()` si backend no arranca |
| **Título dinámico** | `window.set_title("MIRV — " + target_ip)` al conectar SSH |

---

## Fase 5 — Distribución (2 días)

```bash
# Compilar backend primero
cd backend
pip install pyinstaller
pyinstaller --onefile --name mirv-backend main.py
copy dist\mirv-backend.exe ..\desktop\src-tauri\binaries\

# Construir instalador
cd desktop
npm run tauri build -- --bundles msi    # Windows
npm run tauri build -- --bundles dmg    # macOS
npm run tauri build -- --bundles appimage # Linux
```

### Outputs esperados

```
desktop/src-tauri/target/release/bundle/
├── msi/MIRV_3.0.0_x64_en-US.msi    ~80MB
├── dmg/MIRV_3.0.0_x64.dmg          ~60MB
└── appimage/MIRV_3.0.0_x64.AppImage ~70MB
```

### GitHub Releases

```bash
gh release create v3.0.0 \
    desktop/src-tauri/target/release/bundle/msi/MIRV_3.0.0_x64_en-US.msi \
    desktop/src-tauri/target/release/bundle/dmg/MIRV_3.0.0_x64.dmg \
    --title "MIRV v3.0.0" \
    --notes "Primera versión desktop de MIRV"
```

---

## Notas técnicas importantes

### CSP (Content Security Policy)
Tauri requiere CSP estricto. Necesitamos permitir:
- `connect-src 'self' http://localhost:8000 ws://localhost:8000` — API y WebSocket del backend
- `style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com` — Tailwind CDN (idealmente migrar a local)
- `script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com` — Tailwind CDN

**Mejora futura:** Migrar Tailwind de CDN a build local para eliminar dependencia de red.

### Sidecar en Windows
El sidecar .exe debe nombrarse con el triple target:
`mirv-backend-x86_64-pc-windows-msvc.exe`

Tauri busca el binario con ese naming automáticamente.

### Puerto del backend
- Por defecto: `8000`
- Configurable via `MIRV_PORT` env var
- El frontend Tauri debe usar el mismo puerto (pasar como argumento al sidecar)

### Logs
- Backend: `backend/logs/mirv.log`
- Tauri: `console.log()` del WebView + stdout del sidecar

---

## Resumen

| Fase | Tarea | Estado |
|:----:|-------|:------:|
| 1 | Backend PyInstaller | ⏳ Pendiente |
| 2 | Frontend rutas absolutas | ⏳ Pendiente |
| 3 | Proyecto Tauri | ⏳ Pendiente |
| 4 | System tray, updater, iconos | ⏳ Pendiente |
| 5 | Distribución (.msi, GitHub) | ⏳ Pendiente |

> **Primero probar la app actual, después implementar este plan.**
