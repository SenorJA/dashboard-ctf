# VulnForge — Red Team Dashboard

🌐 Plataforma modular de ciberseguridad con panel táctico, SSH proxy y automatización.

> **Tema**: Signal Intelligence — inspirado en centros de operaciones SIGINT, ámbar (#d4a843) como acento principal, teal (#3b8f8a) secundario.

---

## ✨ Cambios recientes

### 🔒 Seguridad
- **Eliminadas credenciales hardcodeadas** del backend y frontend (`192.168.214.142`, `javi`/`javi`).
- El WebSocket ahora **exige autenticación JSON** obligatoria (`{"type":"auth","ip":"...","user":"...","pass":"..."}`).
- El frontend **bloquea la conexión** si no hay un perfil seleccionado en el gestor de conexiones.
- Ya no hay fallbacks a credenciales por defecto — todo pasa por el formulario de conexiones.

### 🎨 UI/UX
- Añadido **monochrome mode** (tema blanco y negro) mediante `body.monochrome` + `!important` overrides.
- **Sistema de traducciones** i18n (inglés/español) con `data-i18n` y `applyLanguage()`.
- Nuevos agentes de desarrollo para OpenCode (`.opencode/agents/`).

### 🗄️ Base de datos (Supabase)
- Integración completa con **Supabase** (PostgreSQL).
- **6 tablas**: `ssh_connections`, `scripts`, `reports`, `hak5_payloads`, `app_settings`, `uploaded_files`.
- **Storage** para archivos subidos (bucket `vulnforge`).
- API REST: `/api/reports`, `/api/scripts`, `/api/connections`, `/api/payloads`, `/api/settings`, `/api/upload`, `/api/generate-pdf`.

### 🤖 Automatización
- Proxy **n8n** para orquestar escaneos (`/api/n8n/trigger`, `/api/n8n/status`).
- Generación de **PDF** server-side con ReportLab.

### 🛠️ Nuevas herramientas en el Arsenal
- **Web Recon**: feroxbuster, cewl, wafw00f, cors-check
- **Network**: socat
- **SMB/Windows**: evil-winrm, impacket, smbmap, ldapsearch, bloodhound
- **Pivoting**: chisel-client, proxychains
- **Exploitation**: responder, burpsuite
- **Extract/Compress**: unzip, tar-gz, tar-xz, 7z-extract, unrar, gunzip, bunzip2

### 📦 Agentes OpenCode (`.opencode/`)
| Archivo | Rol |
|---|---|
| `agents/architect.md` | 🏗️ Orchestrator principal |
| `agents/backend-dev.md` | ⚙️ Backend Senior (FastAPI + Supabase) |
| `agents/frontend-dev.md` | 🖥️ Frontend Senior (Vanilla JS + Tailwind) |
| `agents/ui-auditor.md` | 🎨 Auditor de UI/contraste Signal Intelligence |
| `agents/cibersecurity_expert.md` | 🔐 Experto en ciberseguridad |
| `agents/security.md` | 🛡️ Seguridad |
| `agents/reviewer.md` | 👀 Revisor de código |
| `agents/traslator.md` | 🌐 Traductor |
| `commands/auditor-seguridad.md` | 🔍 Auditor de seguridad y rendimiento |
| `commands/super-commit.md` | 📦 Git commit automático |

---

## 🚀 Inicio rápido

```bash
# 1. Clonar
git clone https://github.com/SenorJA/dashboard-ctf.git
cd dashboard-ctf

# 2. Dependencias
pip install -r backend/requirements.txt

# 3. Configurar .env (copiar desde .env.example)
cp .env.example .env
# Editar .env con SUPABASE_URL y SUPABASE_KEY

# 4. Ejecutar
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 5. Abrir http://localhost:8000
```

## 🐳 Requisitos

- Python 3.11+
- Kali Linux (o cualquier máquina con SSH) para ejecutar herramientas
- Supabase project (gratuito en [supabase.com](https://supabase.com))

## 📁 Estructura

```
├── backend/
│   ├── main.py              # FastAPI + WebSocket + SSH proxy
│   ├── database.py           # Capa Supabase (CRUD)
│   ├── requirements.txt
│   ├── supabase_schema.sql   # Schema SQL para Supabase
│   └── workflows/            # Exports n8n
├── frontend/
│   ├── index.html            # SPA (Tailwind CDN)
│   ├── css/style.css         # Tema Signal Intelligence + Monochrome
│   └── js/
│       ├── main.js           # Toda la lógica frontend
│       └── dataservice.js    # Cliente API REST
└── .opencode/
    └── agents/               # Agentes OpenCode
```

## 🔌 WebSocket

Conectar al panel:
1. Ve a la pestaña **Connections**
2. Añade un perfil (nombre, IP, usuario, contraseña SSH)
3. Selecciona el perfil y haz clic en **Connect**
4. El terminal muestra la salida en tiempo real

## 📄 Licencia

Uso educativo y auditorías autorizadas.
