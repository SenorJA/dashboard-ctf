# Análisis de Repos Externos — Propuesta de Integración (15 Ago 2026)

> Análisis de 3 repositorios GitHub evaluados para integración en MIRV.
> Incluye propuesta para un "Red Team Lab" con skills ofensivas bajo scope_guard obligatorio.

---

## Repos analizados

| Repo | Estrellas | Enfoque | Valor para MIRV |
|---|---|---|---|
| `mukul975/Anthropic-Cybersecurity-Skills` | 31.5k | 818 skills AI estructuradas (MITRE ATT&CK + NIST CSF + ATLAS + D3FEND + AI RMF + F3) | ⭐⭐⭐ ALTA — portar skills al sistema de playbooks de MIRV |
| `brootware/awesome-cyber-security-university` | 3.4k | Currículo educativo gratuito (TryHackMe, HTB, picoCTF, OverTheWire) | ⭐ BAJA-MEDIA — solo como referencia/documentación |
| `SenteLabsAI/OpenExecutive` | 2.3k | Orchestrator multi-agente AI + RAG + memoria episódica | ⭐⭐ MEDIA — inspiración arquitectónica para Op Admiral |

---

## Repo 1: Anthropic-Cybersecurity-Skills

### Qué es
818 skills de ciberseguridad estructuradas para agentes AI, con YAML frontmatter + Markdown body. Mapeadas a 6 frameworks: MITRE ATT&CK v19.1 (805 skills), NIST CSF 2.0 (804), MITRE ATLAS (93), D3FEND (139), NIST AI RMF (97), MITRE F3 Fight Fraud (94). 34 dominios. Formato agentskills.io. Apache 2.0.

### Compatibilidad con MIRV: ALTA
MIRV ya tiene 12 skill playbooks (`backend/skills/*/SKILL.md`) con YAML frontmatter (`name`, `description`, `category`, `allowed_tools`, `version`, `author`) + metodología Markdown + sección `## IMPORTANT`. El formato es casi idéntico al agentskills.io standard.

### Skills candidatas a portar (selección de 15)

#### Defensivas/Analíticas (sin concerns éticos) — portar directamente
| Skill | Dominio | Complementa módulo MIRV |
|---|---|---|
| `performing-memory-forensics-with-volatility3` | Digital Forensics | `forensics.py` |
| `hunting-for-credential-dumping-lsass` | Threat Hunting | Tab SIEM + findings |
| `detecting-business-email-compromise` | Phishing Defense | `dlp_scanner.py` + OSINT |
| `analyzing-network-traffic-of-malware` | Network Security | Tab Forensics |
| `hunting-for-persistence-mechanisms` | Threat Hunting | Tab SIEM |
| `investigating-ransomware-with-splunk` | SOC Operations | Tab SIEM + Intelligence |
| `aws-cloud-security-audit` | Cloud Security | (nueva área) |
| `azure-cloud-security-hardening` | Cloud Security | (nueva área) |
| `kubernetes-rbac-audit` | Container Security | (nueva área) |
| `detecting-lateral-movement-splunk` | SOC Operations | Tab SIEM |

#### Ofensivas/Red Team — requieren apartado separado + scope_guard (ver § Red Team Lab)
| Skill | Dominio | Concern ético |
|---|---|---|
| `adcs-certificate-services-exploitation` | Red Teaming | Escalada de privilegios en AD |
| `ntlm-relay-attacks` | Red Teaming | Ataque de red activo |
| `kerberoasting-with-rubeus` | Red Teaming | Ataque de credenciales |
| `bloodhound-collection` | Red Teaming | Enumeración de AD |
| `c2-infrastructure-with-sliver` | Red Teaming | Command & Control |

### Adaptación del frontmatter
MIRV usa `allowed_tools` (tools del arsenal). Este repo usa `tags` + `atlas_techniques` + `d3fend_techniques` + `nist_csf`. Adaptación:
- `allowed_tools` → mapear a tools del arsenal MIRV (nmap, gobuster, hashcat, john, etc.)
- `tags` → mantener como campo opcional
- `atlas_techniques`/`d3fend_techniques`/`nist_csf` → omitir (MIRV no tiene integración con esos frameworks aún)
- `category` → usar `red-team` para skills ofensivas, `defense` para defensivas, `forensics` para forenses

### No portar
- Skills de AI security (LLM red-teaming, prompt injection) — muy específicas, fuera del alcance actual
- Skills de OT/ICS, blockchain, wireless — nicho, requieren hardware/especialización
- Las 818 skills en su totalidad — excesivo, diluiría el catálogo

---

## Repo 2: awesome-cyber-security-university

### Qué es
Lista curada de recursos educativos gratuitos (TryHackMe rooms, picoCTF, HackTheBox, OverTheWire). 6 niveles: Intro → Red Team → Blue Team → CTF → Windows → Hard rooms. Currículo de aprendizaje, no código.

### Compatibilidad con MIRV: BAJA-MEDIA
No hay código que portar. Solo links educativos.

### Qué coger
- Crear 1 skill `training-path` con links a los recursos gratuitos organizados por nivel (Red Team path, Blue Team path)
- Los badges de completitud como inspiración para gamification del tab CTF
- Estructura del currículo como referencia para un futuro tab "Learning Paths"

### Skill propuesta
```
backend/skills/training-path/SKILL.md
---
name: training-path
description: "Free cybersecurity learning curriculum. Red Team and Blue Team paths with hands-on labs."
category: education
allowed_tools: []
version: "1.0.0"
author: "MIRV"
---
```
Body: links a TryHackMe rooms por nivel, picoCTF challenges, OverTheWire wargames, HackTheBox, organizados en Red Team path (6 niveles) y Blue Team path (5 niveles).

---

## Repo 3: OpenExecutive

### Qué es
Sistema AI de "executivo virtual" — 8 agentes especialistas coordinados por un orchestrator. FastAPI + Next.js + ChromaDB (RAG) + SQLite (memoria episódica). Integraciones con Slack/Email/Telegram/Discord. Deploy en Fly.io.

### Compatibilidad con MIRV: MEDIA
Stack muy diferente (Next.js vs vanilla JS, ChromaDB vs sin vector store, enfoque business vs security). No portar código directo.

### Qué coger (inspiración arquitectónica para futura ronda)
1. **Orchestrator multi-agente** — MIRV tiene `swarm.py` (multi-operator coordinator) y Op Admiral (planificador simple). El patrón de OpenExecutive (orchestrator que enruta a especialistas + memoria episódica) podría convertir Op Admiral en un orchestrator que enruta a agentes especialistas de pentest (recon agent, webvuln agent, privesc agent).
2. **Memoria episódica con SQLite** — MIRV tiene `mission_store.py` (self-improvement loop) pero no tiene memoria episódica entre sesiones. El patrón de OpenExecutive (extraer decisiones clave tras cada respuesta con un modelo rápido) podría mejorar el mission_store.
3. **Prompt caching** — MIRV usa `/api/ai/chat` con auto-redacción pero no hace prompt caching. El patrón (cached system prompt separado del dynamic context) podría ahorrar tokens.
4. **Local models abstraction** — MIRV ya soporta Ollama; OpenExecutive tiene un abstraction layer más maduro (per-agent model selection, OpenRouter, hibrido local/hosted).

### No portar
- Stack completo (Next.js, ChromaDB, Honcho) — demasiada complejidad para MIRV
- Enfoque business (CFO, CSO, CMO) — fuera del dominio de MIRV
- Deploy en Fly.io — MIRV usa Docker + VPS bootstrap propio

---

## Red Team Lab — Propuesta de apartado separado para skills ofensivas

### El problema
Las skills ofensivas (C2, NTLM relay, Kerberoasting, ADCS exploitation) son legítimas para educación e investigación de seguridad, pero requieren **salvaguardas éticas explícitas** para no ser usadas contra sistemas sin autorización.

### La solución: apartado "Red Team" con scope_guard obligatorio

MIRV ya tiene la infraestructura ética necesaria:
- **Scope Guard** (`scope_guard.py`) — valida que el target está en el alcance autorizado
- **OPSEC Levels** (`opsec.py`) — 30 tools con modificadores Silent/Covert/Loud
- **Permission Prompts** — prompts interactivos (Warn/Block) para comandos peligrosos
- **CTF tab** — challenges educativos con flag tracking
- **Audit Log** — JSONL con redacción automática de secrets

### Implementación propuesta

#### 1. Categoría `red-team` en el sistema de skills
```
backend/skills/kerberoasting/SKILL.md
---
name: kerberoasting
description: "Kerberoasting with Rubeus — extract and crack Kerberos service tickets. REQUIRES AUTHORIZATION."
category: red-team
allowed_tools:
  - rubeus
  - hashcat
  - john
requires_scope: true          # NUEVO: exige scope_guard validación
ethical_warning: true          # NUEVO: advertencia ética obligatoria
version: "1.0.0"
author: "MIRV"
---

## IMPORTANT
- ⚠️ REQUIRES EXPLICIT WRITTEN AUTHORIZATION. This skill attacks Active Directory credentials.
- Use ONLY against systems you own or have documented permission to test.
- {target} MUST be validated by scope_guard before execution.
- Kerberoasting is detectable — OPSEC level Loud recommended.
- Cracked passwords are evidence, never share them. MIRV redaction applies.
```

#### 2. Skills de red-team con `requires_scope: true` (campo nuevo)
Añadir al `skill_playbooks.py` un campo opcional `requires_scope` en el frontmatter. Si es `true`, el endpoint `GET /api/skills/{name}/render` verifica `scope_guard.is_in_scope(target)` antes de devolver el contenido. Sin scope configurado → el skill no se renderiza (403).

#### 3. Frontend: tab "Red Team Lab" separado
No mezclar skills ofensivas con las defensivas en el tab Skills existente. Crear una sección claramente marcada dentro del tab Skills (o un tab separado) con:
- Header con advertencia ética visible
- Lista de skills red-team con badge ⚠️
- Botón "Load" que requiere scope configurado (si no hay scope → toast "Configure scope first")
- Al cargar, mostrar el `## IMPORTANT` del skill con la advertencia ética

#### 4. Skills red-team candidatas (5 iniciales)
| Skill | Herramientas | Descripción |
|---|---|---|
| `kerberoasting` | rubeus, hashcat, john | Extracción y crack de TGS tickets |
| `ntlm-relay` | ntlmrelayx, crackmapexec | Relay NTLM a otros servicios |
| `adcs-exploitation` | certipy, certutil | ESC1-8 vulnerabilities en Certificate Services |
| `bloodhound-collection` | bloodhound, sharphound | Mapeo de rutas de ataque en AD |
| `c2-sliver` | sliver, havoc | Infraestructura Command & Control para simulación |

#### 5. Diferenciación clara en el catálogo
```
backend/skills/
├── recon/           # ✅ defensivo (ya existe)
├── webvuln/         # ✅ defensivo (ya existe)
├── osint/           # ✅ defensivo (ya existe)
├── password-audit/  # ✅ defensivo (ya existe)
├── ...
├── memory-forensics/     # ✅ defensivo (nuevo, port repo 1)
├── threat-hunting/       # ✅ defensivo (nuevo, port repo 1)
├── bec-detection/        # ✅ defensivo (nuevo, port repo 1)
├── training-path/        # ✅ educativo (nuevo, del repo 2)
└── red-team/             # ⚠️ ofensivo (nuevo, apartado separado)
    ├── kerberoasting/
    ├── ntlm-relay/
    ├── adcs-exploitation/
    ├── bloodhound-collection/
    └── c2-sliver/
```

### Por qué este enfoque es correcto para MIRV

1. **La app ya es ética por diseño**: Scope Guard, OPSEC, Permission Prompts, Audit Log, redacción automática. Un apartado red-team no rompe este modelo — lo extiende con `requires_scope`.

2. **Educación real requiere práctica ofensiva**: No se puede aprender Kerberoasting solo leyendo teoría. Un skill con metodología paso a paso + herramientas + advertencias éticas + scope obligatorio es más responsable que dejar que el operador busque tutoriales en internet sin salvaguardas.

3. **Separación visual**: Un tab/sección "Red Team Lab" claramente marcado como ⚠️ ofensivo evita que un operador cargue accidentalmente un skill ofensivo pensando que es defensivo.

4. **Trazabilidad**: El Audit Log ya registra todas las acciones. Cargar un skill red-team se loguearía como evento `skill_load` con `category=red-team` — auditoría completa.

5. **Consistente con el password-audit**: MIRV ya tiene `password-audit` (skill 12) que cubre Hydra/Medusa/Ncrack — herramientas ofensivas de brute force. El patrón ético ya está establecido: `## IMPORTANT` con advertencias + scope + autorización.

---

## Plan de implementación propuesto

### Fase A — Skills defensivas (10 skills, sin concerns éticos)
1. Portar 10 skills defensivas del repo 1 al formato MIRV
2. Adaptar frontmatter (sin `atlas_techniques`/`d3fend_techniques`)
3. Actualizar `BUILTIN_NAMES` (12→22) en `test_skill_playbooks.py`
4. Tests de discovery

### Fase B — Skill educativa (1 skill)
5. Crear `training-path` con links a recursos gratuitos

### Fase C — Red Team Lab (5 skills ofensivas + infraestructura)
6. Añadir campo `requires_scope` al `skill_playbooks.py` (frontmatter parser + validación en render)
7. Crear 5 skills red-team con `requires_scope: true` + `## IMPORTANT` con advertencias éticas
8. Frontend: sección "Red Team Lab" en el tab Skills (o tab separado) con badge ⚠️ + validación de scope
9. Tests: skill red-team sin scope → 403, con scope → 200

### Fase D — Documentación (inspiración OpenExecutive)
10. Documentar en TOMORROW.md la inspiración arquitectónica de OpenExecutive como futura mejora del Op Admiral + mission_store + prompt caching
11. NO implementar ahora — guardar como roadmap

### Verificación
- Suite completa CI-emulada verde
- `node --check` frontend OK
- CI GitHub ✅ Deploy ✅
- `BUILTIN_NAMES` actualizado (12→~18 con Fases A+B, ~23 con Fase C)

---

## Estado: propuesta pendiente de aprobación

- ✅ Análisis completado
- ✅ Documentación creada (este archivo)
- ⬜ Fase A (skills defensivas) — pendiente de "SÍ"
- ⬜ Fase B (skill educativa) — pendiente de "SÍ"
- ⬜ Fase C (Red Team Lab) — pendiente de "SÍ"
- ⬜ Fase D (docs OpenExecutive) — pendiente de "SÍ"

*Análisis generado: 15 Ago 2026*
