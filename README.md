# 🛡️ M.I.R.V. — Multi-platform Incident Response & Vulnerabilities

<div align="center">

**Panel táctico de ciberseguridad** • SSH Proxy Web • OSINT • Análisis Forense • Mobile • Automatización Multi-Agente

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3FCF8E?logo=supabase)](https://supabase.com)
[![Kali](https://img.shields.io/badge/Kali-Linux-557C94?logo=kalilinux)](https://kali.org)
[![GitHub](https://img.shields.io/github/last-commit/SenorJA/dashboard-ctf?color=%23d4a843)](https://github.com/SenorJA/dashboard-ctf)

**Tema:** Signal Intelligence — inspirado en centros de operaciones SIGINT, ámbar `#d4a843` como acento principal.

</div>

---

## 📋 Índice

- [¿Qué es M.I.R.V.?](#-qué-es-mirv)
- [Arquitectura](#-arquitectura)
- [Características](#-características)
- [Primeros pasos](#-primeros-pasos)
- [Despliegue en producción](#-despliegue-en-producción)
- [Variables de entorno](#-variables-de-entorno)
- [API REST (80+ endpoints)](#-api-rest-80-endpoints)
- [Base de datos (17 tablas)](#-base-de-datos-17-tablas)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Módulos del backend](#-módulos-del-backend)
- [WebSocket SSH](#-websocket-ssh)
- [Persistencia de datos](#-persistencia-de-datos)
- [Seguridad](#-seguridad)
- [Roadmap](#-roadmap)
- [Licencia](#-licencia)

---

## 🎯 ¿Qué es M.I.R.V.?

M.I.R.V. es una **plataforma modular todo-en-uno** para operaciones de ciberseguridad ofensiva y defensiva. Combina:

- **Terminal SSH interactivo** via WebSocket (navegador → Kali Linux)
- **Panel de hallazgos** con parseo automático de +10 herramientas
- **Arsenal de 51+ herramientas** lanzables con un clic
- **IA multi-proveedor** para escribir informes, sugerir ataques y responder preguntas
- **Análisis forense** de memoria, disco y archivos
- **Análisis móvil** de APKs (estático + dinámico con Frida)
- **Swarm multi-operador** (Recon → Scanner → Exploiter → Report)
- **CTF Mode** con tracking de flags y puntuación
- **OPSEC Levels** para controlar el ruido en el target
- **Self-Improvement Loop** que aprende de misiones pasadas

> **Versión:** v3.0

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                    NAVEGADOR                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ index.html│  │ main.v2.js│  │ dataservice.js   │  │
│  │ (SPA)     │  │ (lógica)  │  │ (cliente REST)   │  │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
│       │              │                  │            │
│       ▼              ▼                  ▼            │
│    WebSocket      fetch()           fetch()         │
└───────┼──────────────┼──────────────────┼───────────┘
        │              │                  │
        ▼              ▼                  ▼
┌─────────────────────────────────────────────────────┐
│                   FASTAPI (Python)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ /ws      │  │ /api/*   │  │ main.py          │  │
│  │ SSH Proxy │  │ REST     │  │ (70+ endpoints)  │  │
│  └────┬─────┘  └────┬─────┘  └──────────────────┘  │
│       │              │                              │
│       ▼              ▼                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Paramiko │  │ Supabase  │  │ Módulos:         │  │
│  │ (SSH)    │  │ (DB)      │  │ opsec, swarm,    │  │
│  └────┬─────┘  └──────────┘  │ mobile, forensics│  │
│       │                      └──────────────────┘  │
└───────┼─────────────────────────────────────────────┘
        │
        ▼
┌──────────────────┐     ┌──────────────────┐
│   Kali Linux     │     │   Supabase       │
│  (VM/LAN)        │     │  (PostgreSQL)    │
│  ─────────       │     │  ─────────       │
│  nmap, gobuster  │     │  17 tablas       │
│  whatweb, nikto  │     │  Storage bucket  │
│  hydra, sqlmap   │     │  (archivos)      │
│  ... 51+ tools   │     └──────────────────┘
└──────────────────┘
```

### Flujo de datos

1. **Frontend SPA** (HTML + vanilla JS + Tailwind CDN) sin bundler ni build step
2. **WebSocket** (`/ws`) proxy SSH bidireccional: navegador ↔ FastAPI ↔ Kali (Paramiko)
3. **API REST** (`/api/*`) 80+ endpoints para operaciones CRUD contra Supabase
4. **Supabase** (PostgreSQL) con 17 tablas + Storage bucket para archivos
5. **Los módulos del backend** (swarm, opsec, mobile, forensics) operan vía SSH sobre Kali

---

## ✨ Características

### 🔴 Terminal SSH Interactivo
| Función | Detalle |
|---------|---------|
| **Proxy WebSocket** | Tiempo real, bidireccional: Browser → FastAPI → Paramiko → Kali SSH |
| **Shell interactivo** | `invoke_shell()` con PTY, soporte para `sudo -S` con password |
| **Filtro ANSI** | Colores, OSC, DEC, Nerd Font/PUA, barras de progreso con `\r` |
| **Historial** | Últimos 100 comandos con flechas ↑/↓, búsqueda |
| **File Upload** | Subida chunked base64 vía SSH a `/tmp/` |
| **Tab completion** | Detección de CWD real vía `/proc` |
| **Stop button** | Ctrl+C / SIGINT sin cerrar sesión |
| **Múltiples conexiones** | Perfiles guardados en localStorage + DB |

### 🎯 Findings Panel
| Función | Detalle |
|---------|---------|
| **Parseo automático** | nmap, gobuster, dirb, ffuf, nikto, whatweb, wpscan, wfuzz, feroxbuster, dnsrecon, curl |
| **Detección de fin** | Prompt pattern `with user@host at HH:MM:SS` + safety timer 30s |
| **Deduplicación** | Por `key:val` compuesto (tool + target + type + detail) |
| **Severidad** | 🔴 critical · 🟠 high · 🟡 medium · 🔵 low · ℹ️ info |
| **Filtros** | Por severidad, tool, target |
| **Export** | `.txt` · `.md` · `.html` · `📄 PDF` (vía `window.print()`) |
| **Persistencia** | Supabase + sincronización automática cada 2s |

### 🛠️ Arsenal (51+ herramientas)
| Categoría | Herramientas |
|-----------|-------------|
| **Web Recon** | gobuster, dirb, wfuzz, ffuf, feroxbuster, nikto, whatweb, wpscan, cewl, nuclei |
| **Network** | nmap (6 perfiles), masscan, netcat, dnsrecon, curl, socat |
| **SMB/Windows** | enum4linux, smbclient, evil-winrm, impacket, smbmap, ldapsearch, bloodhound |
| **Pivoting** | ligolo, nc-listener, chisel-client, proxychains |
| **Crypto** | jwt-decode, b64-encode, b64-decode, john, hashcat |
| **Exploitation** | hydra (SSH/FTP), sqlmap, searchsploit, responder, xsstrike, dalfox, cors-check |
| **WAF/TLS** | wafw00f, testssl |
| **Extract/Compress** | unzip, tar-gz, tar-xz, 7z-extract, unrar, gunzip, bunzip2 |
| **Resources** | HackTricks, PortSwigger, PayloadsAllTheThings, Chisel, RevShells, Exploit-DB, GTFOBins |
| **Utilities** | CyberChef |

### 🤖 IA Multi-Proveedor
| Proveedor | Endpoint por defecto | Modelo |
|-----------|---------------------|--------|
| **OpenAI** | `https://api.openai.com/v1/chat/completions` | gpt-4, gpt-4o, gpt-3.5-turbo |
| **Anthropic** | `https://api.anthropic.com/v1/messages` | claude-3-opus, claude-3-sonnet |
| **Gemini** | `https://generativelanguage.googleapis.com/v1beta/models/` | gemini-pro |
| **OpenRouter** | `https://openrouter.ai/api/v1/chat/completions` | multi-modelo |
| **DeepSeek** | `https://api.deepseek.com/v1/chat/completions` | deepseek-chat |
| **Groq** | `https://api.groq.com/openai/v1/chat/completions` | mixtral, llama |
| **Local** | Cualquier endpoint compatible con OpenAI | cualquier modelo local |

Funcionalidades IA:
- **AI Suggestions** (`/api/suggest`) — recibe findings, sugiere próximos pasos
- **AI Writeup** — genera informes CTF completos en Markdown
- **AI Chat** — 6 pestañas: Reports, Automation, Credentials, KnowledgeBase, CTF, Op Admiral
- **Self-Improvement Loop** — la IA recuerda misiones pasadas y reusa técnicas

### 📱 Mobile Analysis Lab
- **Análisis estático**: apktool, jadx, mobsf (descompilación, permisos, componentes)
- **Análisis dinámico**: ADB + Frida (scripting, hooking, stop/clear console)
- **Consola Frida**: botones ▶ Run, ⏹ Stop (mata procesos en Kali), ✕ Clear (limpia output)
- **Detección**: WebView inseguro, ofuscación, root detection, crypto débil
- **Dashboard**: lista de APKs, resumen de severidad, detalle de hallazgos

### 🔍 Forensics Lab
- **Análisis de archivos**: strings, binwalk, foremost, exiftool, hexdump
- **Análisis de memoria**: Volatility (perfilado, procesos, conexiones, cmdline)
- **Análisis de disco**: Sleuth Kit (fls, icat, mmls)
- **Reportes**: resumen por severidad, evidencias persistentes en DB

### 🌐 Swarm (Multi-Operator Pipeline)
| Operador | Función |
|----------|---------|
| **Recon** | nmap + whatweb + dnsrecon + feroxbuster |
| **Scanner** | nikto + wpscan + nuclei |
| **Exploiter** | Búsqueda de exploits (searchsploit) |
| **Report** | Compilación + guardado en DB |

Características: pipeline secuencial, cancelación, logging en tiempo real, persistencia en DB.

### 🎖️ CTF Mode
- Challenges con categorías, dificultad, puntos, hints
- Tracking de flags resueltos
- Scoring automático
- Sandbox para pruebas

### 🔐 Credential Store
- Credenciales descubiertas durante las auditorías
- Categorización: SSH, HTTP, DB, API, Other
- Hash, token, password, notas
- Persistencia en Supabase

### 📚 KnowledgeBase
- 80+ CVEs críticos embebidos
- Técnicas MITRE ATT&CK
- Búsqueda por CVE ID, palabra clave, técnica MITRE

### 🎨 UI/UX
- **Tema Signal Intelligence**: ámbar `#d4a843`, teal `#3b8f8a`, fondo oscuro
- **Monochrome Mode**: alto contraste para operaciones tácticas
- **i18n**: 150+ traducciones EN/ES con `data-i18n`
- **15 tabs**: Terminal, Reports, Scripts, Bounty, AI Writeup, Findings, Op Admiral, Automation, Swarm, Credentials, KnowledgeBase, CTF, Mobile, Forensics, Payload Studio
- **Responsive**: sidebar colapsable en móvil
- **Hak5 Payload Editor**: Bash Bunny, OMG Cable, M5 Stack, Shark Jack
- **Toast notifications**: feedback visual no obstructivo

### 🏷️ Branding y logo

El logo de M.I.R.V. sigue la estética **Signal Intelligence** con un diseño táctico/militar:

| Elemento | Archivo | Propósito |
|----------|---------|-----------|
| **Logo completo** | [`frontend/img/logo.svg`](frontend/img/logo.svg) | Hexágono + ondas de radar + tipografía "M.I.R.V." + tagline |
| **Favicon** | [`frontend/img/favicon.svg`](frontend/img/favicon.svg) | Icono de pestaña del navegador (16×16–32×32) |
| **App Icon** | [`frontend/img/icon-192.svg`](frontend/img/icon-192.svg) | Icono para PWA / Tauri / escritorio (192×192) |

**Símbolo:** Hexágono con arcos de señal de radar concéntricos y un punto central — representa detección, análisis y respuesta.

**Paleta:**
| Color | Código | Uso |
|-------|:------:|-----|
| Ámbar | `#d4a843` | Acento principal, texto M.I.R.V., trazos |
| Ámbar oscuro | `#b8922e` | Degradado, hover |
| Teal | `#3b8f8a` | Acento secundario, bordes sutiles |
| Fondo oscuro | `#0a0a0f` | Fondo del logo, theme-color del navegador |

El logo se renderiza inline en el header del dashboard y también se sirve como archivo estático via `/img/*`. El favicon se muestra en la pestaña del navegador y es compatible con iOS (apple-touch-icon).

### 🔒 OPSEC Levels
| Nivel | Color | Comportamiento |
|-------|:-----:|----------------|
| **🟢 Silent** | `#3b8f8a` | Solo pasivo. Bloquea masscan, nikto, hydra, nuclei, responder, wpscan |
| **🟡 Covert** | `#d4a843` | Rate limiting, timing reducido, flags stealth |
| **🔴 Loud** | `#dc2828` | Máximo rendimiento. Sin restricciones | 

30 herramientas mapeadas con modificadores flags-only (nunca reemplazan el comando completo para preservar el target).

### 🧠 Self-Improvement Loop
1. Ejecutas herramientas contra un target
2. El sistema detecta OS + tecnologías (50+ patrones)
3. Guardas la misión → se calcula `success_score` (0-100)
4. En futuras misiones, `/api/suggest` inyecta contexto de misiones similares
5. La IA recomienda técnicas que funcionaron antes

---

## 🚀 Primeros pasos

### Requisitos

- **Python 3.11+**
- **Kali Linux** (o cualquier Linux con SSH) — para ejecutar herramientas
- **Supabase project** gratuito en [supabase.com](https://supabase.com) (opcional pero recomendado)
- Opcional: **ADB** + **Frida** para análisis móvil

### Desarrollo local

```bash
# 1. Clonar
git clone https://github.com/SenorJA/dashboard-ctf.git
cd dashboard-ctf

# 2. Dependencias
pip install -r backend/requirements.txt

# 3. Configurar .env
# Crea un archivo .env en la raíz del proyecto:
cat > .env << 'EOF'
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_KEY=tu-service-role-key
SUPABASE_DB_PASSWORD=tu-db-password  # opcional (bootstrap automático)
EOF

# 4. Iniciar servidor
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# 5. Abrir navegador
# http://localhost:8000
```

### Conectar a Kali

1. Abre el panel en `http://localhost:8000`
2. Ve a la pestaña **Connections**
3. Añade perfil: nombre, IP de Kali, puerto 22, usuario, contraseña
4. Selecciona el perfil → **Connect**
5. ¡Terminal interactiva lista!

### Sin Supabase (modo offline)

Si no configuras Supabase, la app funciona con normalidad:
- Los findings se guardan en memoria (se pierden al recargar)
- Las conexiones SSH, scripts y payloads se guardan en localStorage
- El bootstrap de tablas se salta gracefulmente
- Todos los endpoints devuelven fallback limpio

---

## 🌐 Despliegue en producción

### Opción 1: Servidor directo (recomendado para laboratorio)

```bash
# En el servidor (puede ser una VPS o máquina local)
git clone https://github.com/SenorJA/dashboard-ctf.git
cd dashboard-ctf

# Dependencias
pip install -r backend/requirements.txt

# Sin --reload = modo producción
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Opción 2: Cloudflare Tunnel (acceso remoto seguro)

Sigue la guía detallada en [`PRODUCTION_PLAN.md`](PRODUCTION_PLAN.md):

```bash
# 1. Comprar dominio (3-5€/año en Namecheap o Cloudflare)
# 2. Descargar cloudflared
# 3. Autenticar y crear tunnel
cloudflared tunnel create mirv-tunnel
# 4. Configurar DNS
cloudflared tunnel route dns mirv-tunnel tu-dominio.com
# 5. Ejecutar
cloudflared tunnel run mirv-tunnel
```

### Opción 3: Docker (próximamente)

```dockerfile
# Pendiente de implementar — ver ROADMAP.md
```

---

## 🔐 Variables de entorno

| Variable | ¿Obligatoria? | Defecto | Propósito |
|----------|:------------:|:-------:|-----------|
| `SUPABASE_URL` | ❌ | — | URL del proyecto Supabase (ej: `https://xxx.supabase.co`) |
| `SUPABASE_KEY` | ❌ | — | Service Role Key (permite escritura en todas las tablas) |
| `SUPABASE_DB_PASSWORD` | ❌ | — | Password de la DB PostgreSQL para bootstrap automático |
| `SUPABASE_MGMT_TOKEN` | ❌ | — | Management API token para bootstrap alternativo |
| `PORT` | ❌ | `8000` | Puerto del servidor HTTP |

Todas son opcionales. Sin Supabase, la app funciona en modo offline.

---

## 📡 API REST (80+ endpoints)

### WebSocket
| Ruta | Descripción |
|------|-------------|
| `GET /ws` | WebSocket SSH proxy (primer msg: auth JSON) |

### AI
| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/ai/chat` | Chat con IA multi-proveedor |
| POST | `/api/suggest` | Sugerencias basadas en findings + misión history |

### Conexiones SSH
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/connections` | Listar perfiles |
| POST | `/api/connections` | Guardar perfil |
| DELETE | `/api/connections/{id}` | Eliminar perfil |

### Scripts
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/scripts` | Listar scripts |
| POST | `/api/scripts` | Guardar script |
| DELETE | `/api/scripts/{id}` | Eliminar script |

### Reportes
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/reports` | Listar reportes |
| POST | `/api/reports` | Guardar reporte |
| DELETE | `/api/reports/{id}` | Eliminar reporte |
| POST | `/api/report/generate` | Generar reporte desde findings |
| POST | `/api/generate-pdf` | Generar PDF desde Markdown |

### Findings
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/findings` | Listar (filtros: target, tool, severity) |
| POST | `/api/findings` | Guardar uno |
| POST | `/api/findings/bulk` | Guardar lote |
| GET | `/api/findings/stats` | Estadísticas |
| DELETE | `/api/findings/{id}` | Eliminar uno |
| DELETE | `/api/findings` | Limpiar todos |

### Credenciales
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/credentials` | Listar |
| POST | `/api/credentials` | Guardar |
| DELETE | `/api/credentials/{id}` | Eliminar |
| DELETE | `/api/credentials` | Limpiar |

### Payloads Hak5
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/payloads` | Listar (`?device=bunny`) |
| POST | `/api/payloads` | Guardar |
| DELETE | `/api/payloads/{id}` | Eliminar |

### CTF
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/ctf/challenges` | Listar challenges |
| POST | `/api/ctf/challenges` | Crear challenge |
| DELETE | `/api/ctf/challenges/{id}` | Eliminar |
| POST | `/api/ctf/challenges/{id}/solve` | Resolver flag |
| GET | `/api/ctf/score` | Puntuación total |

### Forensics
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/forensics/list` | Listar evidencias |
| POST | `/api/forensics/upload` | Subir + analizar |
| GET | `/api/forensics/analyze/{id}` | Ver análisis |
| POST | `/api/forensics/analyze/{id}` | Re-analizar |

### Mobile
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/mobile/apks` | Listar APKs |
| POST | `/api/mobile/upload` | Subir + analizar |
| GET | `/api/mobile/devices` | Dispositivos ADB |
| POST | `/api/mobile/frida/run` | Ejecutar script Frida |
| POST | `/api/mobile/frida/stop` | Matar procesos Frida en Kali |
| POST | `/api/mobile/frida/clear` | Clear consola (endpoint logging) |

### KnowledgeBase
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/knowledgebase/search` | Buscar CVE + MITRE |
| GET | `/api/knowledgebase/cve/{id}` | Detalle CVE |
| GET | `/api/knowledgebase/mitre/{id}` | Detalle MITRE ATT&CK |

### Swarm
| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/swarm/start` | Iniciar pipeline |
| GET | `/api/swarm/{id}` | Estado del swarm |
| GET | `/api/swarm/list` | Listar sesiones activas |
| POST | `/api/swarm/{id}/cancel` | Cancelar |
| GET | `/api/swarm/{id}/report` | Reporte final |

### Swarm Sessions (persistencia)
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/swarm/sessions` | Listar sesiones históricas |
| GET | `/api/swarm/sessions/{id}` | Detalle |
| POST | `/api/swarm/sessions` | Guardar |
| DELETE | `/api/swarm/sessions/{id}` | Eliminar |

### Scope Guard
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/scope` | Configuración actual |
| POST | `/api/scope` | Guardar configuración |
| POST | `/api/scope/validate` | Validar target |
| GET | `/api/scope/history` | Historial de bloqueos |
| POST | `/api/scope/history/clear` | Limpiar historial |

### Scope Events (persistencia)
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/scope/events` | Listar eventos |
| POST | `/api/scope/events` | Registrar evento |
| DELETE | `/api/scope/events` | Limpiar |

### OPSEC
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/opsec/levels` | Información de niveles |
| POST | `/api/opsec/apply` | Aplicar transformación |

### Misiones (Self-Improvement)
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/missions` | Listar histórico |
| POST | `/api/missions/save` | Guardar misión |
| GET | `/api/missions/similar` | Buscar similares |
| DELETE | `/api/missions/{id}` | Eliminar |

### Planes (Op Admiral)
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/plans` | Listar planes |
| POST | `/api/plans` | Guardar/actualizar |
| DELETE | `/api/plans/{id}` | Eliminar |

### Secretos (app_credentials)
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/credentials/secrets/{key}` | Verificar existencia |
| POST | `/api/credentials/secrets` | Guardar secreto |
| DELETE | `/api/credentials/secrets/{key}` | Eliminar |

### Utilidades
| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/upload` | Subir archivo (a Storage) |
| GET | `/api/files` | Listar archivos |
| GET | `/api/settings` | Obtener setting |
| POST | `/api/settings` | Guardar setting |
| POST | `/api/n8n/trigger` | Disparar workflow n8n |
| GET | `/api/n8n/status` | Estado n8n |
| GET | `/api/health` | Health check |

---

## 🗄️ Base de datos (17 tablas)

Todas en Supabase PostgreSQL:

| # | Tabla | Propósito | 
|---|-------|-----------|
| 1 | `ssh_connections` | Perfiles de conexión SSH |
| 2 | `scripts` | Scripts RCE guardados |
| 3 | `reports` | Reportes de scan, bounty, writeups |
| 4 | `hak5_payloads` | Payloads de dispositivos Hak5 |
| 5 | `app_settings` | Configuración clave-valor |
| 6 | `uploaded_files` | Metadatos de archivos subidos |
| 7 | `findings` | Hallazgos parseados (10+ herramientas) |
| 8 | `credentials` | Credenciales descubiertas |
| 9 | `ctf_challenges` | Desafíos CTF |
| 10 | `ctf_solves` | Flags resueltos |
| 11 | `mobile_apks` | Análisis de APKs |
| 12 | `forensics_evidence` | Evidencia forense |
| 13 | `mission_history` | Auto-mejora de IA |
| 14 | `scope_events` | Auditoría de bloqueos |
| 15 | `swarm_sessions` | Resultados de Swarm |
| 16 | `mission_plans` | Planes de Op Admiral |
| 17 | `app_credentials` | Secretos (API keys, etc.) |

**Storage:** Bucket `vulnforge` para archivos subidos.

---

## 📁 Estructura del proyecto

```
C:\Users\34678\Desktop\Proyecto ciber\
├── backend/
│   ├── main.py              # FastAPI app (WebSocket + 80+ REST endpoints)
│   ├── database.py          # Capa Supabase (17 tablas CRUD)
│   ├── opsec.py             # OPSEC Levels (30 herramientas)
│   ├── mission_store.py     # Self-Improvement Loop
│   ├── mcp_server.py        # MCP Server para agentes IA
│   ├── swarm.py             # Coordinador multi-operador
│   ├── mobile_analyzer.py   # Análisis APK (estático + dinámico)
│   ├── forensics.py         # Análisis forense
│   ├── knowledgebase.py     # CVE + MITRE ATT&CK (80+ entradas)
│   ├── scope_guard.py       # Validación de alcance
│   ├── adb_controller.py    # Controlador ADB + Frida
│   ├── requirements.txt     # Dependencias Python
│   ├── supabase_schema.sql  # Schema SQL completo (17 tablas)
│   ├── operators/           # Operadores del Swarm
│   │   ├── base.py
│   │   ├── recon.py
│   │   ├── scanner.py
│   │   ├── exploiter.py
│   │   └── report.py
│   └── logs/                # Logs del servidor
├── frontend/
│   ├── index.html           # SPA (Tailwind CDN, 15 tabs)
│   ├── css/
│   │   └── style.css         # Signal Intelligence + Monochrome
│   ├── img/
│   │   ├── logo.svg           # Logo completo (hexágono + radar + tipografía)
│   │   ├── favicon.svg        # Favicon del navegador
│   │   └── icon-192.svg       # App icon para PWA/Tauri
│   └── js/
│       ├── main.v2.js       # Toda la lógica frontend (~5200 lines)
│       ├── main.js          # Versión anterior
│       ├── dataservice.js   # Cliente REST Supabase
│       ├── mobile.js        # UI de mobile analysis
│       ├── forensics.js     # UI de forense
│       └── swarm.js         # UI de Swarm
├── .env                     # Variables de entorno
├── README.md                # Este archivo
├── AGENTS.md                # Documentación técnica para agentes IA
├── ROADMAP.md               # Roadmap de desarrollo
├── PRODUCTION_PLAN.md       # Plan de despliegue Cloudflare
├── PERSISTENCE_AUDIT.md     # Auditoría de persistencia de datos
├── VULNFORGE_VS_T3MP3ST.md  # Comparativa con T3MP3ST
└── .opencode/
    └── agents/              # Agentes OpenCode
```

---

## 🧩 Módulos del backend

| Módulo | Líneas | Propósito |
|--------|:------:|-----------|
| `main.py` | ~2299 | FastAPI app, WebSocket SSH, 85+ endpoints |
| `database.py` | ~1344 | CRUD para 17 tablas Supabase |
| `opsec.py` | 400 | OPSEC Levels para 30 herramientas |
| `mission_store.py` | 356 | Auto-mejora: historial de misiones |
| `mcp_server.py` | 620 | MCP Server para Claude/Cursor/agentes |
| `swarm.py` | 250 | Pipeline multi-operador |
| `mobile_analyzer.py` | 707 | Análisis APK (apktool, jadx, mobsf) |
| `forensics.py` | 253 | Forense (memoria, disco, archivos) |
| `knowledgebase.py` | 210 | Base de datos de CVEs + MITRE |
| `scope_guard.py` | 261 | Validación de alcance Warn/Block |
| `adb_controller.py` | 205 | ADB + Frida scripting (stop/run/clear) |

---

## 🔌 WebSocket SSH

### Conectar

```javascript
// Primer mensaje (obligatorio):
{
  "type": "auth",
  "ip": "192.168.1.100",
  "port": 22,
  "user": "kali",
  "pass": "password"
}
```

### Protocolo

- **Cliente → Servidor**: texto plano (comandos shell) o JSON `{"type":"auth"|"stop"}`
- **Servidor → Cliente**: texto plano (stdout/stderr) o JSON `{"type":"connected"|"error"|"pong"}`

### Características

- `invoke_shell()` con PTY interactivo
- Powerlevel10k prompt desactivado (`p10k disable`) en conexión
- Sudo automático con `-S` + password vía heredoc
- `asyncio.to_thread()` para operaciones SSH no bloqueantes
- Detección de prompt tool-finish: `with user@host at HH:MM:SS`

---

## 💾 Persistencia de datos

### Patrón offline-first

Todas las operaciones de escritura siguen este orden:

1. **Intentar API backend** (Supabase)
2. **Si falla** → usar localStorage como fallback
3. **Cuando la API vuelve** → migrar datos de localStorage a DB

### Datos en localStorage

| Clave | Contenido | ¿Persiste en DB? |
|-------|-----------|:----------------:|
| `vulnforge_connections` | Conexiones SSH (caché) | ✅ `/api/connections` |
| `vulnforge_scripts` | Scripts (caché) | ✅ `/api/scripts` |
| `vulnforge_hak5_*` | Payloads por dispositivo | ✅ `/api/payloads` |
| `vulnforge_ai_endpoint` | URL endpoint AI | ❌ Preferencia UI |
| `vulnforge_ai_model` | Modelo AI | ❌ Preferencia UI |
| `vulnforge_suggest_provider` | Proveedor suggest | ❌ Preferencia UI |
| `vulnforge_n8n_url` | URL n8n | ❌ Preferencia UI |
| `vulnforge_theme` | Tema (mono/neon) | ❌ Preferencia UI |
| `vulnforge_lang` | Idioma (en/es) | ❌ Preferencia UI |
| `mirv_opsec` | Nivel OPSEC | ❌ Preferencia UI |

> **Nota:** Las API keys ya no se guardan en localStorage. Se almacenan en `app_credentials` en Supabase.

Para más detalles, ver [`PERSISTENCE_AUDIT.md`](PERSISTENCE_AUDIT.md).

---

## 🔒 Seguridad

### Medidas implementadas

| Medida | Descripción |
|--------|-------------|
| **WebSocket auth** | Primer mensaje debe ser JSON con credenciales |
| **Scope Guard** | Valida targets contra lista permitida (Warn/Block) |
| **OPSEC Levels** | Controla ruido de herramientas en producción |
| **Sin defaults** | No hay credenciales por defecto en backend/frontend |
| **Secretos en DB** | API keys almacenadas en backend (no localStorage) |
| **CORS** | Middleware configurable para origen del frontend |
| **CSP** | Content-Security-Policy explícita que permite Tailwind CDN + WebSocket |
| **Path traversal** | sys.path protegido contra imports maliciosos |
| **Flags-only OPSEC** | Modificadores nunca reemplazan el target |

### Prácticas recomendadas

- Usa HTTPS en producción (Cloudflare Tunnel lo provee automáticamente)
- No compartas URLs de producción sin autenticación
- Rota las API keys de IA periódicamente
- Usa el Scope Guard en modo Block para entornos de producción

---

## 🗺️ Roadmap

| Fase | Estado | Descripción |
|:----:|:------:|-------------|
| 1 | ✅ | Proxy SSH + Findings panel + Arsenal básico |
| 2 | ✅ | Supabase CRUD + Export informes |
| 3 | ✅ | Análisis móvil + forense |
| 4 | ✅ | Swarm multi-operador + CTF mode |
| 5 | ✅ | AI multi-proveedor + Automation (n8n) |
| 6 | ✅ | Mobile responsive + i18n (EN/ES) |
| 7 | ✅ | OPSEC Levels + Self-Improvement Loop |
| **8** | 🚧 **Próximo** | **Docker, tests automatizados, CI/CD** |

Para detalles, ver [`ROADMAP.md`](ROADMAP.md).

---

## 📄 Licencia

**Uso educativo y auditorías autorizadas exclusivamente.**

M.I.R.V. está diseñado para:
- Profesionales de ciberseguridad en pruebas de penetración autorizadas
- Estudiantes y educadores en entornos de laboratorio
- Entusiastas de la seguridad en CTFs y máquinas vulnerables (HackTheBox, VulnHub, etc.)

**No está permitido** usar M.I.R.V. contra sistemas sin autorización explícita por escrito.

---

<div align="center">

**M.I.R.V. v3.0**

[Reportar bug](https://github.com/SenorJA/dashboard-ctf/issues) · [Sugerir mejora](https://github.com/SenorJA/dashboard-ctf/issues) · [Documentación](AGENTS.md)

</div>
