# ⚔️ M.I.R.V. vs T3MP3ST — Comparativa y GAP Analysis

> Comparación objetiva entre **M.I.R.V.** v3.0 (anteriormente VulnForge) y **T3MP3ST** (v1.0, GitHub @elder-plinius/T3MP3ST).
> Fecha del análisis: Julio 2026

---

## 📊 Visión General

| Aspecto | VulnForge | T3MP3ST |
|---------|-----------|---------|
| **Lenguaje** | Python + Vanilla JS | TypeScript (Node.js) |
| **Backend** | FastAPI + WebSocket | Express.js |
| **Frontend** | HTML/Tailwind/vanilla JS | HTML/Tailwind/vanilla JS |
| **Base de datos** | Supabase (PostgreSQL) | Archivos + Conf lib |
| **SSH** | Paramiko (a Kali VM) | No tiene SSH directo |
| **Licencia** | Propietaria | AGPL-3.0 |
| **CLI** | No | Sí (Node.js interactivo) |
| **Código total** | ~12.400 líneas | ~15.000+ líneas |
| **Estrellas GitHub** | Privado | 4.4k ⭐ |
| **Enfoque** | Dashboard táctico + terminal | Framework autónomo multi-agente |

---

## 🏗️ Arquitectura

| Componente | VulnForge | T3MP3ST |
|------------|-----------|---------|
| **Orquestador** | FastAPI + WebSocket | TempestCommand (EventEmitter) |
| **Frontend** | SPA con 10 tabs | SPA con 11 páginas + sidebar |
| **Terminal** | ✅ SSH interactivo en vivo | ❌ Solo CLI local |
| **WebSocket** | ✅ Tiempo real bidireccional | ❌ No tiene |
| **MCP Server** | ❌ No tiene | ✅ `security_recon` tool |
| **API REST** | ✅ Completa (40+ endpoints) | ✅ Express.js (básica) |
| **CLI interactiva** | ❌ No tiene | ✅ Inquirer + chalk + figlet |

---

## 🧠 Operadores / Swarm

| Operador | VulnForge | T3MP3ST | Notas |
|----------|-----------|---------|-------|
| **Recon** | ✅ nmap, whatweb, dns, dirb | ✅ nmap, DNS, HTTP, fingerprint | Ambos funcionales |
| **Scanner** | ✅ nikto, wpscan, nuclei | ✅ Nuclei, scanners varios | Similares |
| **Exploiter** | ✅ searchsploit, port→exploit | ⚠️ Experimental | Ambos experimentales |
| **Infiltrator** | ❌ No tiene | ⚠️ Experimental | Solo T3MP3ST |
| **Exfiltrator** | ❌ No tiene | ⚠️ Experimental | Solo T3MP3ST |
| **Ghost** | ❌ No tiene | ⚠️ Experimental | Solo T3MP3ST |
| **Coordinator** | ✅ SwarmCoordinator | ✅ TempestCommand | Similares |
| **Analyst / Report** | ✅ Report operator | ✅ Analyst | Ambos funcionales |

---

## 🛠️ Arsenal de Herramientas

| Herramienta | VulnForge | T3MP3ST |
|-------------|-----------|---------|
| nmap | ✅ | ✅ |
| gobuster | ✅ | ✅ (opt-in) |
| ffuf | ✅ | ✅ (opt-in) |
| feroxbuster | ✅ | ✅ (opt-in) |
| nikto | ✅ | ✅ (opt-in) |
| whatweb | ✅ | ❌ |
| wpscan | ✅ | ❌ |
| sqlmap | ✅ | ✅ (opt-in) |
| hydra | ✅ | ✅ (approval-gated) |
| searchsploit | ✅ | ❌ Directo |
| nuclei | ✅ | ✅ (opt-in) |
| metasploit | ❌ | ✅ (approval-gated) |
| curl | ✅ | ✅ |
| socat | ✅ | ❌ |
| evil-winrm | ✅ | ❌ |
| impacket | ✅ | ❌ |
| bloodhound | ✅ | ✅ (import-only) |
| chisel | ✅ | ❌ |
| ligolo | ✅ | ❌ |
| responder | ✅ | ❌ |
| **Total herramientas SSH** | **44** | **83** (35 default + 48 opt-in) |
| **Enlaces externos** | **9** | **0** |

---

## 🤖 Inteligencia Artificial

| Característica | VulnForge | T3MP3ST |
|----------------|-----------|---------|
| OpenAI | ✅ | ✅ |
| Anthropic | ✅ | ✅ |
| Gemini | ✅ | ❌ |
| OpenRouter | ✅ | ✅ |
| DeepSeek | ✅ | ✅ |
| Groq (gratis) | ✅ | ❌ |
| **Local/Ollama** | ❌ No tiene | ✅ Ollama, LM Studio |
| **Keyless agents** | ❌ No tiene | ✅ Claude Code, Codex, Hermes |
| **AI Suggestions** | ✅ | ❌ No tiene |
| **Op Admiral (plan)** | ✅ | ✅ "Op Admiral" |
| **AI Writeup** | ✅ | ❌ No tiene |
| **Bounty report AI** | ✅ | ❌ No tiene |
| **Hak5 payload AI** | ✅ | ❌ No tiene |

---

## 🎯 Alcance y Seguridad

| Característica | VulnForge | T3MP3ST |
|----------------|-----------|---------|
| **Scope Guard** | ✅ En WebSocket + endpoints | ✅ Egress scope (on by default) |
| **Modo Warn** | ✅ | ❌ (solo block) |
| **Modo Block** | ✅ | ✅ |
| **OPSEC Levels** | ✅ Silent/Covert/Loud | ✅ Silent/Covert/Loud |
| **Detection tracking** | ❌ No tiene | ✅ Detection events + cooldown |
| **IOC tracking** | ❌ No tiene | ✅ |
| **Credential store** | ❌ No tiene | ✅ |

---

## 📋 Reportes y Findings

| Característica | VulnForge | T3MP3ST |
|----------------|-----------|---------|
| **Findings panel** | ✅ Con severidad y colores | ✅ Evidence Vault |
| **Persistencia** | ✅ Supabase DB | ❌ En memoria / archivos |
| **Severidades** | ✅ critical/high/medium/low/info | ✅ critical/high/medium/low/info |
| **Reportes MD** | ✅ | ✅ |
| **Reportes HTML** | ✅ | ✅ |
| **Reportes PDF** | ✅ (ReportLab) | ❌ |
| **Export findings** | ✅ MD/HTML/PDF | ✅ JSON/MD |
| **Bounty reports** | ✅ (con template) | ❌ |
| **CVSS scoring** | ❌ No tiene | ✅ |
| **Evidence vault** | ❌ No tiene | ✅ Screenshots, requests, outputs |
| **AI Report gen** | ✅ /api/report/generate | ❌ |

---

## 🔬 Domínios de prueba

| Dominio | VulnForge | T3MP3ST |
|---------|-----------|---------|
| **Web apps** | ✅ | ✅ **XBEN 90.1%** |
| **CTF** | ❌ No tiene | ✅ **Cybench 23/40** |
| **Source code** | ❌ No tiene | ✅ CVE-Zero 8/10 |
| **Smart contracts** | ❌ No tiene | ⚠️ Damn Vulnerable DeFi |
| **Cloud (IaC)** | ❌ No tiene | 🚧 En desarrollo |
| **Mobile** | ❌ No tiene | 🚧 En desarrollo |
| **Binary/RE** | ❌ No tiene | 🚧 En desarrollo |
| **Robotics/OT** | ❌ No tiene | ✅ Pipeline coordinado |

---

## 🏆 Lo que VulnForge tiene y T3MP3ST no

1. **✅ Terminal SSH interactivo** — T3MP3ST no tiene shell remota
2. **✅ WebSocket bidireccional** — T3MP3ST no tiene tiempo real
3. **✅ Múltiples proveedores IA** — Gemini, Groq gratis, DeepSeek
4. **✅ Supabase persistence** — Datos persistentes en la nube
5. **✅ Exportación PDF** — ReportLab integration
6. **✅ i18n EN/ES** — Interfaz en dos idiomas
7. **✅ Hak5 Payload Editor** — Bash Bunny, OMG, M5, Shark Jack
8. **✅ Bounty Reports** — Plantillas para bug bounty
9. **✅ n8n Automation** — Integración con workflows n8n
10. **✅ Interrupt (Ctrl+C)** — Botón para detener procesos en SSH
11. **✅ Scope Guard con Warn/Block** — Dos modos de contención
12. **✅ File Upload** — Subida de archivos a Kali vía SSH

---

## ⚡ Lo que T3MP3ST tiene y VulnForge no (GAPS)

Priorizado por **valor para el usuario**:

### P0 — Crítico (implementar ya)

| # | Feature | Por qué es valioso |
|---|---------|-------------------|
| 1 | **🔌 MCP Server** | Permite que CUALQUIER agente IA (Claude Code, Cursor, Cline) controle VulnForge directamente. Esto convierte VulnForge en un backend de herramientas para cualquier AI coding agent. **Máximo impacto con mínimo esfuerzo.** |
| 2 | **🔑 Keyless Local AI** | Soporte para Ollama / LM Studio. Los usuarios sin API key pueden usar IA local gratis. |
| 3 | **🏆 CTF Mode** | Estructurar challenges con flags, tracking de progreso, y sandbox. Alineado con el nombre "VulnForge". |
| 4 | **🔐 Credential Store** | Almacenar contraseñas, hashes, tokens descubiertos durante las pruebas. |
| 5 | **📊 Reproducible Benchmarks** | Sistema `verify-claims` para demostrar que las herramientas funcionan. |

### P1 — Alta

| # | Feature | Descripción |
|---|---------|-------------|
| 6 | **Source Code Analysis** | Escaneo de repositorios en busca de vulnerabilidades (semgrep, gitleaks) |
| 7 | **Multi-language SAST** | Análisis de código fuente en Python, JS, Java, Go, Rust, C/C++, Solidity |
| 8 | **KnowledgeBase (CVE/MITRE)** | Base de datos local de CVEs críticos y técnicas MITRE ATT&CK |
| 9 | **OPSEC Levels** | Modos Silent/Covert/Loud con detección de contramedidas |

### P2 — Media

| # | Feature | Descripción |
|---|---------|-------------|
| 10 | **Smart Contract Analysis** | Análisis de vulnerabilidades en Solidity (slither, mythril) |
| 11 | **Cloud Security** | Escaneo de AWS/GCP/Azure (scoutsuite, cloudfox) |
| 12 | **Mobile Analysis** | Escaneo de APKs (mobsf, apktool, jadx) |
| 13 | **Binary/RE Analysis** | Análisis de binarios (radare2, ghidra) |
| 14 | **Self-improvement Loop** | Aprender de misiones pasadas para mejorar sugerencias |

---

## 🎯 Recomendación: Próximos pasos

Basado en el análisis, estos son los **5 features que más valor aportarían** a VulnForge, ordenados por esfuerzo/impacto:

```
Fácil ─────────────────────────────────────────── Difícil
  │
  ├─ 1. MCP Server  🟢 (1-2 días) ← MÁXIMO IMPACTO
  ├─ 2. Keyless AI  🟢 (1 día)
  ├─ 3. Credential Store 🟡 (2-3 días)
  ├─ 4. CTF Mode    🟡 (3-5 días)
  └─ 5. Benchmarks  🔴 (5-7 días)
```

### 🔥 Feature #1 recomendado: MCP Server

Un **MCP (Model Context Protocol) Server** expondría las herramientas de VulnForge como herramientas que cualquier agente IA compatible con MCP puede usar (Claude Code, Cursor, Cline, etc.).

**Arquitectura propuesta:**
```
AI Agent (Claude Code, Cursor, etc.)
  └─ MCP Protocol (stdio/SSE)
       └─ VulnForge MCP Server (Python)
            ├─ security_recon  → nmap, whatweb, dns
            ├─ port_scan       → escaneo de puertos
            ├─ web_scan        → nikto, gobuster, nuclei
            ├─ exploit_search  → searchsploit
            └─ scope_guard     → validación de alcance
```

Esto convertiría a VulnForge en el **backend de herramientas** para cualquier agente IA, manteniendo el dashboard como interfaz visual.

---

## 📈 Resumen de capacidades

| Categoría | VulnForge | T3MP3ST |
|-----------|:---------:|:--------:|
| Terminal SSH interactivo | ✅ | ❌ |
| Findings en tiempo real | ✅ | ❌ |
| IA multi-proveedor | ✅ | ❌ |
| Export PDF | ✅ | ❌ |
| Supabase persistencia | ✅ | ❌ |
| i18n | ✅ | ❌ |
| Hak5 payloads | ✅ | ❌ |
| MCP Server | ❌ | ✅ |
| Keyless AI local | ❌ | ✅ |
| CTF Mode | ❌ | ✅ |
| Source code analysis | ❌ | ✅ |
| CLI interactiva | ❌ | ✅ |
| Smart contracts | ❌ | ⚠️ |
| Binary/RE | ❌ | 🚧 |
| Cloud security | ❌ | 🚧 |
| OPSEC tracking | ❌ | ✅ |
| Benchmark reproducible | ❌ | ✅ |
| CVE hunting pipeline | ❌ | ✅ |
| KnowledgeBase (CVE/MITRE) | ❌ | ✅ |

---

*Documento generado el Julio 2026 para planificación de desarrollo.*
