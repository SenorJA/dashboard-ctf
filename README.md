# M.I.R.V. — Multi-platform Incident Response & Vulnerabilities

🌐 Plataforma modular de ciberseguridad con panel táctico, SSH proxy, análisis forense, análisis móvil y automatización multi-agente.

> **Tema**: Signal Intelligence — inspirado en centros de operaciones SIGINT, ámbar (#d4a843) como acento principal.
> **Versión**: v3.0 (anteriormente VulnForge v2.0)

---

## ✨ Características principales

### 🔴 Terminal SSH interactivo
- WebSocket bidireccional en tiempo real (Browser → FastAPI → Paramiko → Kali SSH)
- Shell interactivo con `invoke_shell()` + PTY
- Filtro ANSI completo (colores, OSC, DEC privados, Nerd Font/PUA)
- Manejo de `\r` para barras de progreso
- Historial de comandos con flechas ↑/↓ (últimos 100)
- Botón Stop (Ctrl+C / SIGINT)
- Sudo automático con `-S` + password
- Subida de archivos vía SSH (chunked base64, soporta binarios)
- Tab completion con detección de CWD real vía `/proc`

### 🎯 Findings Panel
- Parseo automático de output de herramientas (nmap, whatweb, gobuster, dirb, ffuf, nikto, wpscan)
- Detección de fin de comando por prompt pattern (`with javi@kali at HH:MM:SS`)
- Deduplicación de hallazgos por `key:val`
- Tarjetas con severidad (🔴 critical, 🟠 high, 🟡 medium, 🔵 low, ℹ️ info)
- Filtros por severidad
- Export en `.txt` / `.md` / `.html` / `📄 PDF`
- Persistencia en Supabase (CRUD via `/api/findings`)

### 🤖 IA multi-proveedor
- OpenAI, Anthropic, Gemini, OpenRouter, DeepSeek, Groq (gratis)
- AI Suggestions basadas en findings (`/api/suggest`)
- AI Writeup para informes automáticos
- AI en 6 pestañas: Reports, Automation, Swarm, Credentials, KnowledgeBase, CTF
- Auto-guardado de API keys en localStorage

### 🛠️ Arsenal (51+ módulos)
| Categoría | Herramientas |
|-----------|-------------|
| Web Recon | gobuster, dirb, wfuzz, ffuf, feroxbuster, nikto, whatweb, wpscan, cewl |
| Network | nmap, masscan, netcat, dnsrecon, curl, socat |
| SMB/Windows | enum4linux, smbclient, evil-winrm, impacket, smbmap, ldapsearch, bloodhound |
| Pivoting | ligolo, nc-listener, chisel-client, proxychains |
| Crypto/Decode | jwt-decode, b64-encode, b64-decode, john, hashcat |
| Exploitation | hydra-ssh, hydra-ftp, sqlmap, searchsploit, responder, burpsuite |
| Extract/Compress | unzip, tar-gz, tar-xz, 7z-extract, unrar, gunzip, bunzip2 |
| Resources | HackTricks, PortSwigger, PayloadsAllTheThings, Chisel, RevShells, Exploit-DB, BurpSuite, GTFOBins |
| Utilities | CyberChef |

### 📱 Mobile Analysis Lab
- Análisis estático de APKs (apktool, jadx, mobsf)
- Análisis dinámico con ADB + Frida
- Detección de dispositivos conectados
- Scripts Frida predefinidos

### 🔍 Forensics Lab
- Análisis de evidencias digitales
- Captura y análisis de memoria
- Análisis de disco con Sleuth Kit
- Persistencia de evidencias en Supabase

### 🌐 Swarm (Multi-operador)
- Operadores: Recon, Scanner, Exploiter, Report
- Coordinador con pizarra compartida
- Sesiones de swarm con reportes
- Cancelación de misiones

### 🎖️ CTF Mode
- Challenges con flags
- Tracking de progreso y puntuación
- Sandbox de pruebas

### 🔐 Credential Store
- Almacenamiento seguro de credenciales descubiertas
- Categorización (SSH, HTTP, DB, API, Other)
- Persistencia en Supabase

### 📚 KnowledgeBase
- Base de datos local de CVEs críticos
- Técnicas MITRE ATT&CK
- Búsqueda de vulnerabilidades

### 📋 Reportes
- Export en `.md` / `.html` / `📄 PDF`
- Bounty Reports con plantilla
- AI Report generation (`/api/report/generate`)
- n8n Automation integration

### 🎨 UI/UX
- **Tema Signal Intelligence** (ámbar/teal) + **Monochrome mode**
- **i18n** (inglés/español) con 150+ traducciones
- Responsive (mobile sidebar, command bar adaptativa)
- Hak5 Payload Editor (Bash Bunny, OMG, M5, Shark Jack)
- Payload Studio launcher (externo por X-Frame-Options)

### 🔒 Seguridad
- Credenciales eliminadas del backend/frontend
- WebSocket exige autenticación JSON
- Scope Guard (modo Warn / Block)
- No fallbacks a credenciales por defecto

### 🗄️ Backend
- **FastAPI** + **Supabase** (PostgreSQL)
- **65+ endpoints REST**
- MCP Server (`backend/mcp_server.py`) — expone herramientas a agentes IA
- PDF generation server-side con ReportLab
- n8n proxy para automatización

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
- Opcional: ADB + Frida para análisis móvil

## 📁 Estructura

```
├── backend/
│   ├── main.py              # FastAPI + WebSocket + SSH proxy (~1900 lines, 65+ endpoints)
│   ├── database.py           # Capa Supabase (CRUD)
│   ├── mcp_server.py         # MCP Server para agentes IA
│   ├── swarm.py              # Coordinador multi-operador
│   ├── mobile_analyzer.py    # Análisis APK + ADB/Frida
│   ├── forensics.py          # Análisis forense
│   ├── knowledgebase.py      # CVE + MITRE ATT&CK
│   ├── scope_guard.py        # Validación de alcance
│   ├── adb_controller.py     # Controlador ADB
│   ├── requirements.txt
│   └── supabase_schema.sql   # Schema SQL
├── frontend/
│   ├── index.html            # SPA (Tailwind CDN, 15 tabs, ~1673 lines)
│   ├── css/style.css         # Tema Signal Intelligence + Monochrome (~873 lines)
│   └── js/
│       ├── main.v2.js        # Toda la lógica frontend (~4716 lines)
│       └── dataservice.js    # Cliente API REST (Supabase)
├── .opencode/
│   └── agents/               # Agentes OpenCode
└── docs/
    ├── ROADMAP.md            # Roadmap de mejoras (7 fases)
    ├── PRODUCTION_PLAN.md    # Plan de producción (Cloudflare Tunnel)
    └── VULNFORGE_VS_T3MP3ST.md # Comparativa con T3MP3ST
```

## 🔌 WebSocket

Conectar al panel:
1. Ve a la pestaña **Connections**
2. Añade un perfil (nombre, IP, puerto, usuario, contraseña SSH)
3. Selecciona el perfil y haz clic en **Connect**
4. El terminal muestra la salida en tiempo real

**Protocolo:**
- Primer mensaje debe ser JSON auth: `{"type":"auth","ip":"...","port":22,"user":"...","pass":"..."}`
- Backend envía texto plano (SSH stdout/stderr)
- JSON protocol messages: `{"type":"connected"|"error","message":"..."}`

## 🎯 Findings

Los resultados de las herramientas se parsean automáticamente:
1. Lanza una herramienta desde el Arsenal (nmap, whatweb, etc.)
2. El sistema detecta cuando termina (prompt pattern)
3. Los hallazgos aparecen en la pestaña **🎯 Findings**
4. Filtra por severidad, exporta en `.txt` / `.md` / `.html` / PDF

## 🌍 i18n

- Toggle EN/ES en el header
- 150+ traducciones con `data-i18n` keys
- `applyLanguage()` actualiza todos los elementos marcados
- Default: EN

## 📄 Licencia

Uso educativo y auditorías autorizadas.

---

*M.I.R.V. v3.0 — anteriormente VulnForge*