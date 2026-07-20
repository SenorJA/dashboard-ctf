# 🛡️ M.I.R.V. — Multi-platform Incident Response & Vulnerabilities

<div align="center">

**Panel táctico de ciberseguridad** • SSH Proxy Web • OSINT • Análisis Forense • Mobile • Automatización Multi-Agente

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3FCF8E?logo=supabase)](https://supabase.com)
[![Kali](https://img.shields.io/badge/Kali-Linux-557C94?logo=kalilinux)](https://kali.org)
[![Tests](https://img.shields.io/badge/tests-412_✔️-2ea44f?logo=pytest)](https://github.com/SenorJA/dashboard-ctf/actions)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/SenorJA/dashboard-ctf/ci.yml?label=CI%2FCD&logo=githubactions)](https://github.com/SenorJA/dashboard-ctf/actions)
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

### 🛠️ Arsenal (100+ módulos)

Arsenal con **categorías colapsables**, **badges numéricos**, **filtro en tiempo real**, **master toggle** (Expand/Collapse All) y **botón Run All** por categoría.

| Categoría | Herramientas | API? |
|-----------|-------------|:----:|
| **Web Recon API** | Headers Scanner, Secrets Scanner, Port Scanner, Subdomain Scanner, DNS Lookup, Hash Cracker, Stego Tool, News Scraper, API Scanner | ✅ #1–#9 |
| **Web Recon CLI** | gobuster, dirb, wfuzz, ffuf, feroxbuster, nikto, whatweb, wpscan, cewl, nuclei | ❌ |
| **Network** | nmap (6 perfiles), masscan, netcat, dnsrecon, curl, socat | ❌ |
| **SMB/Windows** | enum4linux, smbclient, evil-winrm, impacket, smbmap, ldapsearch, bloodhound | ❌ |
| **Pivoting** | ligolo, nc-listener, chisel-client, proxychains | ❌ |
| **Crypto** | jwt-decode, b64-encode, b64-decode, john, hashcat | ❌ |
| **Exploitation** | hydra (SSH/FTP), sqlmap, searchsploit, responder, xsstrike, dalfox, cors-check | ❌ |
| **OSINT** | TheHarvester, Mr.Holmes, Infoooze, BBOT, LinkedIn2Username, SpiderFoot | ❌ |
| **WAF/TLS** | wafw00f, testssl | ❌ |
| **Extract/Compress** | unzip, tar-gz, tar-xz, 7z-extract, unrar, gunzip, bunzip2 | ❌ |
| **Resources** | HackTricks, PortSwigger, PayloadsAllTheThings, Chisel, RevShells, Exploit-DB, GTFOBins | ❌ |
| **Utilities** | CyberChef | ❌ |
| **OSINT Web** | Flare.io, Lenso AI, OSINT Framework, SpiderFoot, Shodan, Censys, VirusTotal, HaveIBeenPwned | ❌ |
| **Pentest Labs** | DockerLabs, HackTheBox, TryHackMe, VulnHub, Proving Grounds, HackMyVM, PortSwigger Academy, OverTheWire, PicoCTF, RootMe | ❌ |
| **Bug Bounty** | HackerOne, Bugcrowd, Intigriti, YesWeHack, Secur0, Open Bug Bounty, Synack, Grey Hack | ❌ |
| **Hardware Stores** | Hak5, Flipper Zero, Great Scott Gadgets, M5Stack, Lab 401, Hacker Warehouse, HackmoD, KSEC Labs, Firewire Revolution, SAPSAN | ❌ |

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

### 🔍 OSINT Toolkit
6 herramientas CLI con auto-instalación + 8 enlaces web:

| Herramienta | Tipo | Comando | Auto-instala |
|-------------|------|---------|:------------:|
| **TheHarvester** | CLI | `theHarvester -d <target> -b google,bing,linkedin` | Pre-instalado en Kali |
| **Mr.Holmes** | CLI | `MrHolmes.py --username <target>` | `git clone` + `install.sh` |
| **Infoooze** | CLI | `infoooze -s <target>` | `npm install -g infoooze` |
| **BBOT** | CLI | `bbot -t <target> -p subdomain-enum` | `pip install bbot` |
| **LinkedIn2Username** | CLI | `linkedin2username.py -c <company>` | `git clone` + `pip install` |
| **SpiderFoot** | CLI | `spiderfoot -s <target> -t INTERNET_NAME` | `pip install spiderfoot` |

**Enlaces OSINT web:** Flare.io, Lenso AI, OSINT Framework, SpiderFoot, Shodan, Censys, VirusTotal, HaveIBeenPwned

### 🎯 Pentest Labs (10 plataformas)
Acceso directo desde el arsenal a las mejores plataformas de práctica:

| Plataforma | URL | Badge |
|------------|-----|-------|
| DockerLabs | `dockerlabs.es` | GRATIS |
| HackTheBox | `hackthebox.com` | FREEMIUM |
| TryHackMe | `tryhackme.com` | FREEMIUM |
| VulnHub | `vulnhub.com` | GRATIS |
| Proving Grounds | `offsec.com/labs` | PAGO |
| HackMyVM | `hackmyvm.eu` | GRATIS |
| PortSwigger Academy | `portswigger.net/web-security` | GRATIS |
| OverTheWire | `overthewire.org` | GRATIS |
| PicoCTF | `picoctf.org` | GRATIS |
| RootMe | `root-me.org` | FREEMIUM |

### 💰 Bug Bounty (8 plataformas)
| Plataforma | URL | Badge |
|------------|-----|-------|
| HackerOne | `hackerone.com` | TOP |
| Bugcrowd | `bugcrowd.com` | TOP |
| Intigriti | `intigriti.com` | TOP |
| YesWeHack | `yeswehack.com` | TOP |
| Secur0 | `app.secur0.com` | ES |
| Open Bug Bounty | `openbugbounty.org` | GRATIS |
| Synack | `synack.com` | PAGO |
| Grey Hack | `store.steampowered.com` (juego MMO) | JUEGO |

### 🛒 Hardware Stores (10 tiendas)
Hak5, Flipper Zero, Great Scott Gadgets, M5Stack (oficiales) + Lab 401, Hacker Warehouse, HackmoD, KSEC Labs, Firewire Revolution, SAPSAN (re-sellers) — para comprar gear de pentesting (Rubber Ducky, WiFi Pineapple, HackRF, Flipper, etc.)

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
- **pnpm** — gestor de paquetes para tests frontend → `corepack enable` (Windows) o `npm i -g pnpm`
- Opcional: **ADB** + **Frida** para análisis móvil

### Desarrollo local

```bash
# 1. Clonar
git clone https://github.com/SenorJA/dashboard-ctf.git
cd dashboard-ctf

# 2. Dependencias Python
pip install -r backend/requirements.txt

# 3. Dependencias Frontend (pnpm, NO npm)
corepack enable    # solo primera vez
pnpm install       # instala Playwright y dependencias

# 4. Configurar .env
# Crea un archivo .env en la raíz del proyecto:
cat > .env << 'EOF'
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_KEY=tu-service-role-key
SUPABASE_DB_PASSWORD=tu-db-password  # opcional (bootstrap automático)
EOF

# 5. Iniciar servidor
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

### Opción 3: Docker (recomendado — no requiere Kali VM)

M.I.R.V. corre en Docker con un **contenedor Kali Linux** que incluye 50+ herramientas de seguridad pre-instaladas. **Elimina la necesidad de una VM Kali separada** — todo funciona con un solo comando.

**¿Cómo cambia respecto a la VM de Kali?**

| | Antes (VM Kali) | Ahora (Docker) |
|---|---|---|
| **Requisitos** | VMware/VirtualBox + ISO Kali | Docker Desktop |
| **Setup** | Instalar VM, configurar red, SSH | `docker compose up -d --build` |
| **Tiempo primera vez** | 30-45 min | ~20 min (build auto) |
| **Recursos** | 4-8 GB RAM dedicados | ~2 GB RAM bajo demanda |
| **Mantenimiento** | Actualizar tools manualmente | Reconstruir imagen |
| **Portabilidad** | Solo en tu PC | Cualquier PC con Docker |

**Un comando levanta todo:**

```bash
# 1. Asegúrate de tener Docker Desktop (v24+) instalado y corriendo
# 2. Desde la raíz del proyecto:
docker compose up -d --build

# 3. El primer build tarda ~15-20 min (descarga Kali + instala 50+ tools)
#    Las siguientes veces es instantáneo (caché)
# 4. Abrir dashboard: http://localhost:8000
```

**Arquitectura Docker:**

```
┌─────────────────────────────────────────────────────────────┐
│  docker-compose.yml                                          │
│                                                              │
│  ┌─────────────────────┐    SSH     ┌─────────────────────┐ │
│  │  kali-tools         │◄──────────►│  mirv-backend       │ │
│  │  ─────────          │  Puerto 22 │  ────────────       │ │
│  │  Kali Linux + 50+  │            │  FastAPI + WebSocket │ │
│  │  tools (nmap,       │            │  + REST API (88+)   │ │
│  │  gobuster, nikto,   │            │  + Findings Panel   │ │
│  │  sqlmap, hydra...) │            │                     │ │
│  │                     │            │                     │ │
│  │  Port 2222 → 22     │            │  Port 8000          │ │
│  │  SSH root:mirv      │            │                     │ │
│  │  SecLists + rockyou │            │  → Supabase (nube)  │ │
│  └─────────────────────┘            └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**El contenedor Kali incluye:**
- 🔧 **50+ herramientas**: nmap, masscan, gobuster, ffuf, nikto, whatweb, wpscan, nuclei, sqlmap, hydra, john, hashcat, enum4linux, crackmapexec, smbclient, impacket, responder, commix, arjun, wfuzz, theHarvester, dnsrecon, amass, sublist3r, wafw00f, cewl, crunch, binwalk, foremost, steghide, exiftool, tshark, tcpdump...
- 📂 **SecLists + rockyou.txt** incluidos
- 🔑 **SSH root:mirv** — el dashboard se conecta automáticamente

**Conexión automática:** Docker Compose pasa `KALI_IP=kali-tools`, `KALI_PORT=22`, `KALI_USER=root`, `KALI_PASS=mirv` al backend. El dashboard se conecta por SSH al contenedor.

### Probar el stack Docker — paso a paso

#### Paso 1: Verificar que Docker está corriendo
```bash
docker version
```
Si ves `Server: Docker Desktop` en la salida, seguimos. Si no, abre Docker Desktop y espera a que diga "running".

#### Paso 2: Levantar todo el stack (un comando)
```bash
# Desde la raíz del proyecto (C:\Users\34678\Desktop\Proyecto ciber\)
docker compose up -d --build
```
La **primera vez** tarda ~20 min (descarga Kali + instala 50+ herramientas). Las siguientes es instantáneo.

#### Paso 3: Verificar contenedores
```bash
docker ps
```
Debes ver **dos contenedores**:
- `mirv-kali-tools` → Status: `Up (healthy)` → Puerto 2222
- `mirv-backend` → Status: `Up (healthy)` → Puerto 8000

#### Paso 4: Verificar health del backend
```bash
curl http://localhost:8000/api/health
```
Devuelve: `{"status":"ok","supabase":true,"database":"supabase",...}`

#### Paso 5: Abrir el dashboard
```
http://localhost:8000
```

#### Paso 6: Conectar al Kali del contenedor
En el dashboard:
1. Ve a la pestaña **Connections** (icono de enlace en el sidebar)
2. Añade una conexión nueva:
   - **Name:** `Kali Docker`
   - **IP:** `localhost`
   - **Port:** `2222` *(¡importante! 2222, no 22)*
   - **Username:** `root`
   - **Password:** `mirv`
3. Click **Connect**
4. ¡Terminal lista!

> ⚠️ **Nota:** El **Puerto es 2222** (NO 22). Docker mapea el 2222 del host al 22 del contenedor. Si pones 22 no conectará.

#### Paso 7: Probar herramientas desde el terminal
```bash
# Escaneo de puertos:
nmap -sV -Pn scanme.nmap.org

# Detección de tecnologías web:
whatweb example.com

# Enumeración de directorios:
gobuster dir -u http://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -q

# Escaneo de vulnerabilidades web:
nikto -h http://example.com
```
Los findings se parsean automáticamente y aparecen en el panel **🎯 Findings**.

#### Paso 8: Ver logs en vivo (opcional)
```bash
docker compose logs -f
```

### Parar / reiniciar el stack
```bash
docker compose down          # parar (no se borra nada)
docker compose up -d         # arrancar (instantáneo, sin rebuild)
docker compose up -d --build # reconstruir tras cambios en el código
```

### 🎮 Control de Docker desde el Dashboard

M.I.R.V. incluye un **panel de control Docker** en el propio dashboard. Puedes gestionar el stack sin abrir una terminal:

- **Insignia en el header** — punto verde (UP) / gris (DOWN) + texto "🐳 Stack UP/DOWN"
- **Modal de control** — haz clic en la insignia para abrirlo
- **4 botones**: Start, Stop, Clean, Build
- **Log de operaciones** — historial de acciones realizadas
- **Polling automático** — el estado se refresca cada 30 segundos

| Acción | ¿Qué hace? | ¿A quién afecta? |
|--------|-----------|:-----------------:|
| **▶ Start** | Arranca kali-tools | Solo kali-tools |
| **⏹ Stop** | Detiene kali-tools | Solo kali-tools |
| **🧹 Clean** | Detiene + borra volúmenes de kali-tools | Solo kali-tools (⚠️ pérdida de datos) |
| **🔨 Rebuild** | Reconstruye imágenes en background (sin reiniciar) | No afecta contenedores corriendo |

> ⚠️ **Importante:** Los botones del UI **nunca afectan a mirv-backend** (el contenedor que ejecuta el dashboard). Para reiniciar el backend (por ejemplo, tras rebuild), usa la terminal: `docker compose up -d`

Para documentación técnica detallada (arquitectura, problemas encontrados, soluciones, API, frontend, migración a otra unidad), consulta [`DOCKER_GUIDE.md`](DOCKER_GUIDE.md).

### Resumen en un golpe
```bash
# 1. Levantar todo:
docker compose up -d --build

# 2. Abrir en el navegador:
#    http://localhost:8000

# 3. Conectar en el dashboard:
#    IP: localhost  Port: 2222  User: root  Pass: mirv
```
Sin VM, sin VirtualBox, sin configurar redes. Un comando y ya.

> 📖 **Documentación técnica completa del stack Docker** (arquitectura, problemas encontrados, soluciones, API, componentes frontend) en [`DOCKER_GUIDE.md`](DOCKER_GUIDE.md).

---

## 🔐 Variables de entorno

| Variable | ¿Obligatoria? | Defecto | Propósito |
|----------|:------------:|:-------:|-----------|
| `SUPABASE_URL` | ❌ | — | URL del proyecto Supabase (ej: `https://xxx.supabase.co`) |
| `SUPABASE_KEY` | ❌ | — | Service Role Key (permite escritura en todas las tablas) |
| `SUPABASE_DB_PASSWORD` | ❌ | — | Password de la DB PostgreSQL para bootstrap automático |
| `SUPABASE_MGMT_TOKEN` | ❌ | — | Management API token para bootstrap alternativo |
| `PORT` | ❌ | `8000` | Puerto del servidor HTTP |
| `KALI_IP` | ❌ | — | IP del Kali Linux (VM o `kali-tools` en Docker) |
| `KALI_PORT` | ❌ | `22` | Puerto SSH de Kali (`2222` en Docker local) |
| `KALI_USER` | ❌ | `javi` | Usuario SSH de Kali (`root` en Docker) |
| `KALI_PASS` | ❌ | `javi` | Contraseña SSH (`mirv` en Docker) |
| `KALI_MCP_URL` | ❌ | — | URL del kali-mcp MCP server (experimental, ej: `http://localhost:666/mcp`) |

Todas son opcionales. Sin Supabase, la app funciona en modo offline. En Docker Compose, las credenciales SSH se pasan automáticamente.

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

### Docker Control
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/docker/status` | Estado del stack Docker (síncrono) |
| POST | `/api/docker/start` | Arranca kali-tools (síncrono) |
| POST | `/api/docker/stop` | Detiene kali-tools (síncrono) |
| POST | `/api/docker/clean` | Elimina kali-tools + volúmenes (síncrono) |
| POST | `/api/docker/build` | Reconstruye imágenes en background (asíncrono) |
| GET | `/api/docker/task/{task_id}` | Estado de tarea asíncrona (build) |

### kali-mcp (Docker Kali alternativo)
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/kali-mcp/status` | Estado del contenedor kali-mcp |
| POST | `/api/kali-mcp/exec` | Ejecutar comando en kali-mcp |
| GET | `/api/kali-mcp/tools` | Listar herramientas MCP disponibles |

### Utilidades
| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/upload` | Subir archivo (a Storage) |
| GET | `/api/files` | Listar archivos |
| GET | `/api/settings` | Obtener setting |
| POST | `/api/settings` | Guardar setting |
| POST | `/api/n8n/trigger` | Disparar workflow n8n |
| GET | `/api/n8n/status` | Estado n8n |
| GET | `/api/health` | Health check (+ status kali-mcp) |

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
├── .npmrc                   # Forzar pnpm (bloquea npm)
├── package.json             # pnpm + Playwright devDependency
├── pnpm-lock.yaml           # Lockfile de pnpm
├── .github/workflows/
│   └── ci.yml               # CI/CD: lint → test → build → push → deploy
├── docs/
│   ├── STATUS.md            # Estado completo del proyecto
│   ├── EVENTOS.md           # Mapeo onclick → data-action
│   ├── SECRETS_GITHUB.md    # Configurar secrets del CI/CD
│   ├── PLAYWRIGHT_TESTS.md  # Tests frontend con Playwright
│   ├── MODULOS_NUEVOS.md    # 9 módulos API security
│   ├── PAT_WORKFLOW_SCOPE.md# Solucionar error de workflow scope
│   ├── MIRV_DESKTOP_PLAN.md # App desktop con Tauri
│   └── DOCKER_GUIDE.md      # Guía de Docker en español
├── frontend/
│   ├── tests/
│   │   ├── playwright.config.js  # Config Playwright
│   │   └── smoke.spec.js         # 24 tests E2E
│   └── ...                       # HTML, CSS, JS
└── .opencode/
    └── agents/              # Agentes OpenCode
```

---

## 🧩 Módulos del backend

| Módulo | Líneas | Propósito |
|--------|:------:|-----------|
| `main.py` | ~2985 | FastAPI app, WebSocket SSH, 88+ endpoints |
| `database.py` | ~697 | CRUD para 17 tablas Supabase |
| `opsec.py` | ~400 | OPSEC Levels para 30 herramientas |
| `mission_store.py` | ~356 | Auto-mejora: historial de misiones |
| `mcp_server.py` | ~620 | MCP Server para Claude/Cursor/agentes |
| `swarm.py` | ~250 | Pipeline multi-operador |
| `mobile_analyzer.py` | ~707 | Análisis APK (apktool, jadx, mobsf) |
| `forensics.py` | ~253 | Forense (memoria, disco, archivos) |
| `knowledgebase.py` | ~210 | Base de datos de CVEs + MITRE |
| `scope_guard.py` | ~261 | Validación de alcance Warn/Block |
| `adb_controller.py` | ~205 | ADB + Frida scripting (stop/run/clear) |
| `headers_scanner.py` | ~95 | #1 HTTP Headers Scanner (grade A–F) |
| `secrets_scanner.py` | ~140 | #2 Secrets Scanner (25 regex) |
| `port_scanner.py` | ~79 | #3 Port Scanner (~1600 puertos async) |
| `subdomain_scanner.py` | ~75 | #4 Subdomain Scanner (~700 prefijos) |
| `dns_lookup.py` | ~94 | #5 DNS Lookup (DoH, 7 tipos, reverse) |
| `hash_cracker.py` | ~90 | #6 Hash Cracker (20 tipos, rainbow table) |
| `stego_tool.py` | ~209 | #7 Steganography Tool (PNG/BMP LSB) |
| `news_scraper.py` | ~146 | #8 Security News Scraper (9 RSS feeds) |
| `api_scanner.py` | ~140 | #9 API Security Scanner (65+ paths) |

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

## 🧪 Tests

### Backend — 388 tests (pytest)

| Archivo | Tests | Descripción |
|---------|:-----:|-------------|
| `test_headers_scanner.py` | 32 | HTTP Headers Scanner (grade A–F) |
| `test_secrets_scanner.py` | 33 | Secrets Scanner (25 regex) |
| `test_port_scanner.py` | 18 | Port Scanner (~1600 puertos) |
| `test_subdomain_scanner.py` | 11 | Subdomain Scanner (~700 prefijos) |
| `test_dns_lookup.py` | 9 | DNS Lookup (DoH, 7 tipos) |
| `test_hash_cracker.py` | 58 | Hash Cracker (20 tipos) |
| `test_stego_tool.py` | 28 | Steganography Tool (LSB) |
| `test_news_scraper.py` | 8 | Security News Scraper (9 RSS) |
| `test_api_scanner.py` | 31 | API Security Scanner (65+ paths) |
| `test_api_endpoints.py` | 160 | 88+ endpoints REST |
| **Total** | **388** | **0 fallos — 39% cobertura** |

```bash
docker exec mirv-backend python -m pytest backend/tests/ -q
```

### Frontend — 24 tests (Playwright + pnpm)

| Archivo | Tests | Descripción |
|---------|:-----:|-------------|
| `smoke.spec.js` | 24 | Page load, 13 tabs, arsenal, filter, theme, i18n, responsive |
| **Total** | **24** | **0 fallos — Chromium** |

```bash
pnpm playwright test --config=frontend/tests/playwright.config.js
```

> ⚠️ **pnpm** es el gestor obligatorio (`.npmrc` bloquea npm).  
> `package.json` incluye `"packageManager": "pnpm@11.11.0"`.  
> Sin pnpm → `corepack enable` para activarlo.

---

## 🤖 CI/CD — GitHub Actions

```yaml
lint (ruff) → test-backend (388 pytest) → test-frontend (24 Playwright)
                                          ↓
                                    docker-build (push Docker Hub)
                                          ↓
                                    deploy (SSH VPS)
```

| Job | ¿Cuándo corre? | Descripción |
|-----|----------------|-------------|
| `lint` | Siempre | Ruff check + format |
| `test-backend` | Siempre | pytest 388 tests |
| `test-frontend` | Siempre | Playwright 24 tests + backend inline |
| `docker-build` | Solo `main` | Buildx + push a Docker Hub |
| `deploy` | Solo `main` | SSH pull + restart en VPS |

**Secrets requeridos:** `DOCKER_USERNAME`, `DOCKER_TOKEN`, `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`  
→ Guía completa: [`docs/SECRETS_GITHUB.md`](docs/SECRETS_GITHUB.md)

---

## 📚 Documentación

| Archivo | Contenido |
|---------|-----------|
| [`ROADMAP.md`](ROADMAP.md) | Roadmap completo del proyecto |
| [`docs/STATUS.md`](docs/STATUS.md) | Estado detallado (tests, cobertura, módulos) |
| [`docs/EVENTOS.md`](docs/EVENTOS.md) | Mapeo completo onclick → data-action |
| [`docs/SECRETS_GITHUB.md`](docs/SECRETS_GITHUB.md) | Configurar secrets de CI/CD |
| [`docs/PLAYWRIGHT_TESTS.md`](docs/PLAYWRIGHT_TESTS.md) | Tests frontend con Playwright |
| [`docs/MODULOS_NUEVOS.md`](docs/MODULOS_NUEVOS.md) | 9 módulos API security |
| [`docs/PAT_WORKFLOW_SCOPE.md`](docs/PAT_WORKFLOW_SCOPE.md) | Solucionar error de workflow scope |
| [`docs/PRODUCTION_PLAN.md`](docs/PRODUCTION_PLAN.md) | Despliegue en producción |
| [`docs/PERSISTENCE_AUDIT.md`](docs/PERSISTENCE_AUDIT.md) | Auditoría de persistencia |

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
| 8 | ✅ | 9 Módulos API (#1–#9) desde Cybersecurity-Projects |
| 9 | ✅ | UI Modernization (categorías colapsables, badges, filter, master toggle) |
| 10 | ✅ | Event Delegation (0 onclick, ACTION_MAP centralizado) |
| 11 | 🚧 | Tests + CI/CD (388 pytest + 24 Playwright + Docker push + VPS deploy) |
| 12 | ⏳ | Producción (Cloudflare Tunnel + dominio) |
| **8** | ✅ | **Docker**: stack Docker + panel de control desde el UI |
| **9** | 🚧 **Próximo** | **Tests automatizados, CI/CD** |

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
