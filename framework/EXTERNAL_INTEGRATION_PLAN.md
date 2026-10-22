# Plan de integración — 5 repositorios externos revisados

> Fecha: 2026-10-21 · Estado: propuesta para revisión · Autor: análisis automático
> Repos analizados: `MadsLorentzen/ai-job-search`, `marichu-kt/DucKeyLogger`,
> `deepseek-ai/DeepInfer`, `irraz/vulnerator-ai`, `vercel-labs/skills`.

---

## 1. Veredicto por repositorio

| # | Repo | Producto | Veredicto | Lo que realmente nos interesa |
|---|------|----------|-----------|-------------------------------|
| 1 | `ai-job-search` | Búsqueda de empleo con IA | ❌ **No es relevante** · ✅ **Patrón donante** | `posting_guard.py` (gate anti-inyección), `security_guards.py` (guardas de supply-chain), drafter-reviewer, verificación de PDF |
| 2 | `DucKeyLogger` | Keylogger Rubber Ducky → Telegram | ⚠️ **Parcial** | Rubber Ducky como 13º dispositivo Hak5 + **encoder DuckyScript→inject.bin**; el keylogger se reorienta a **detección defensiva/forense** |
| 3 | `DeepInfer` | Motor de inferencia DeepSeek (SM100/Ascend) | ❌ **No integrar** | Solo el *patrón* "backend OpenAI-compatible propio": añadir `provider: custom` + `base_url` libre |
| 4 | `vulnerator-ai` | Agente OODA sobre Kali vía MCP | ✅ **El más relevante** | Bucle OODA con criterio de parada cualitativo, findings-store con ciclo de vida, **ATT&CK como lenguaje de Orient**, navegador real vía Playwright MCP |
| 5 | `vercel-labs/skills` | CLI `npx skills` (registro de skills) | ✅ **Integrar** (en Python, sin Node) | Instalador de skills remotas con verificación de supply-chain y activation manual |

**Veredicto global: 3 de 5 aportan código reutilizable; 2 (ai-job-search, DeepInfer) aportan patrones;
1 (DucKeyLogger) aporta una feature de dispositivo + una de detección defensiva.**

---

## 2. Estado real del proyecto (precondiciones)

Verificado contra el código, no contra la documentación. Estos son los hechos que condicionan
cada decisión del plan:

| Hecho | Evidencia | Impacto en el plan |
|-------|-----------|--------------------|
| El gate de permisos interactivos **está muerto en producción** | `scope_guard.validate_command_with_permission` (`backend/scope_guard.py:676`) no lo llama nadie; el WS solo hace `validate_command` (`backend/main.py:5847`). El frontend hace **0** llamadas a `/api/permissions/*` | **P0 global**: si el OODA ejecuta comandos reales, debe poder bloquearlos. Hay que cablear el gate **antes** del OODA |
| `allowed_tools` de las skills se parsea pero **nunca se valida** | `skill_playbooks.py:248` lo lee; `call_skill_hook` lo comprueba (`:555`); no hay allowlist contra los IDs del arsenal (65 tools en `main.v2.js:2984`) | Una skill puede declarar `allowed_tools: [rm -rf]` y se acepta |
| Los findings **no tienen estado epistemológico ni procedencia** | `findings` table (`database.py:171-187`): `tool/target/type/severity/title/detail/...` — sin `technique_id`, sin `confidence`, sin `evidence{cmd,rc,output}` | El OODA de vulnerator-ai necesita un store con `hypothesis\|partial\|confirmed\|discarded` |
| ATT&CK existe pero **nada lo etiqueta** | `knowledgebase.py` con ~80 técnicas MITRE; ningún `technique_id` en findings ni en `coverage_matrix.py` | El "Orient language" de vulnerator-ai es el gap más barato de cerrar |
| `orchestrator.py` es **single-pass**; `swarm.py` es **pipeline lineal** | `orchestrator.execute()` (`:424`) = route + 1 llamada LLM. `swarm.py` = Recon→Scanner→Exploiter→Report sin iteración | Falta el bucle OODA. Es la pieza central de vulnerator-ai |
| **No hay navegador automatizado en backend** | `browser_capture.py` importa HAR *a posteriori*; `playwright` solo aparece en `frontend/tests/` | Vulnerator-ai aporta Playwright MCP: navegación/DOM/XSS en SPA. Es el delta de capability #1 |
| `_call_llm_sync` tiene **6 providers hardcodeados**, sin `base_url` libre | `main.py:707-832` (`openai, openrouter, deepseek, groq, gemini, anthropic, local`) | Puerta de entrada a DeepInfer / vLLM / TGI / cualquier servidor OpenAI-compatible |
| `pdf_engine.py` genera PDF **sin verificación posterior** | ReportLab `doc.build()` y nada más; no hay extracción de capa de texto ni conteo de páginas | Patrón "verificar el PDF compilado" de ai-job-search |
| El router de skills tiene 113 playbooks y **no hay forma de instalar uno remoto** | `skill_playbooks.py` tiene `create_skill_template()` (local) pero nada de fetch remoto | `vercel-labs/skills` llena este hueco |
| 80 rutas API nunca las llama el frontend | Auditoría previa: Burp (8), Permissions (7), PoC (6), Missions (6), Phishing (6), Wireless (5)… | El gap de Permissions es funcional; el resto es deuda de UI |
| Playwright e2e existe pero **no está en CI** y cubre 14 de 39 tabs | `frontend/tests/smoke.spec.js:35-50`; `package.json` apunta a `playwright test` sin config en raíz | Si añadimos tabs, hay que arreglar el selector (`#tab-${id}`, no `#tab-${id}-panel`) |

---

## 3. Plan por repositorio

### 3.1 `irraz/vulnerator-ai` — Bucle OODA + findings store + ATT&CK + navegador  ⭐ PRIORIDAD 1

**Por qué entra:** es el único de los cinco que describe un *pentest autónomo*, que es exactamente
el producto de MIRV. Pero su diseño es el **opuesto** del nuestro: "no guardrails, no scope-guard,
no consent". MIRV ya tiene `scope_guard` + `scope_guard` + `opsec` + `audit_log` + `redact` +
permisos. **No adoptamos su arquitectura; adoptamos su bucle.**

**Qué NO se toma:** Hermes como cerebro (tenemos `orchestrator` + `agent_bridge` con opencode/claude/codex),
el stack Docker completo, y —sobre todo— su ausencia de guardrails.

#### 3.1.1 `backend/ooda.py` — motor OODA (P1, ~3 días)

```
observe() → ejecuta un paso vía kali_mcp_client / _exec_tool_command, captura evidencia
orient()  → technique_id ATT&CK de la táctica actual + coverage_matrix + findings store
decide()  → pide 2-3 alternativas al LLM, las puntúa de forma determinista, elige una
act()     → ejecuta el paso elegido
stop      → objetivo alcanzado | 3 pasos sin progreso | max_steps | scope bloqueado
```

- Reusa `orchestrator._build_system_prompt` y `orchestrator.route()` — no duplica el enrutado.
- **Criterio de parada cualitativo** (el de vulnerator-ai, no un contador): el LLM debe emitir
  `progress: true|false` + `goal_reached: true|false`. Es la idea que ellos dicen haber improved
  sobre `rooda`.
- **Decide con alternativas explícitas**: 2-3 candidatos con motivo, el motor puntúa y registra
  la descartada en la evidencia (auditable).
- **Contexto fresco por ronda**: cada `act()` se ejecuta con un contexto de sistema limpio +
  el estado del store, no con la conversación completa.
- **Todo output de herramienta es dato no confiable**: pasar por `ingest_guard` (§3.2.1).

Ficheros: `backend/ooda.py` (nuevo) · `backend/main.py` (endpoints) ·
`backend/tests/test_ooda.py` (nuevo, ~20 tests)

Endpoints nuevos:
```
POST /api/ooda/start      {target, goal, mode: pentest|redteam|ctf, max_steps}
GET  /api/ooda/{run_id}
GET  /api/ooda/{run_id}/steps
POST /api/ooda/{run_id}/stop
```
`mode` replica su semántica: `pentest` = parar en evidencia de explotabilidad (sin root);
`redteam`/`ctf` = compromiso completo.

#### 3.1.2 `backend/ooda_store.py` — findings store con ciclo de vida (P1, ~2 días)

Esquema (fiel al `finding_store.py` de ellos, adaptado a nomenclatura MIRV):

```jsonl
{"id":"...","phase":"observe","technique_id":"T1190","target":"host:443/path",
 "status":"hypothesis|partial|confirmed|discarded",
 "evidence":{"command":"nmap -sV ...","returncode":0,"output_ref":"artifact://..."},
 "confidence":0.0-1.0,"timestamp":"...","tags":["mirv"],"remediation":"...",
 "engagement_id":"...","finding_id":null}
```

- Un fichero JSONL por engagement (`backend/data/ooda/<engagement_id>/findings.jsonl`).
- **Escritura dual**: se appendea al JSONL *y* se llama a `database.save_finding` → Supabase.
  Así el store sobrevive a un outage de Supabase y el audit log sigue siendo la fuente de verdad.
- `status` estrictamente monotónico hacia `discarded` (nunca un finding confirmado vuelve a hipótesis).
- Migrar `findings` con 2 columnas nuevas (`technique_id TEXT`, `ooda_status TEXT`) — **sin tabla nueva**
  (respeta la regla de "18 tablas" de AGENTS.md).

#### 3.1.3 `backend/knowledgebase.py` + `coverage_matrix.py` — ATT&CK como lenguaje de Orient (P1, ~1 día)

- `GET /api/attack/techniques` → lista las ~80 técnicas con tactic/technique_id.
- `GET /api/attack/coverage` → qué técnicas se han ejercitado por assessment (lee `technique_id` de findings).
- `GET /api/attack/gap?assessment_id=` → siguientes técnicas a probar, priorizadas.
- El `orient()` del OODA usa esto: "táctica actual → técnica probable → skill de hunt existente".
  ⚠️ `coverage_matrix.py` hoy indexa `endpoint×param×vuln_class`; **no** lo rompas — la vista ATT&CK
  es un eje adicional, no un reemplazo.

#### 3.1.4 `backend/browser_automation.py` + sidecar Playwright MCP (P2, ~4 días)

El mayor delta de capacidad. Ahora solo importamos HAR a posteriori; con un navegador real podemos:

- navegar la SPA y extraer rutas/DOM no links en JS,
- sondear XSS/DOM-XSS sobre los sinks que encontremos,
- capturar el HAR **en vivo** y alimentar `browser_capture.py` (que ya tiene 10 checks de seguridad),
- descubrimiento de endpoints SPA (routes en el bundle).

Integración: contenedor `playwright-mcp` (imagen oficial de Microsoft, headless Chromium) junto a
`kali-tools` en `docker-compose.yml`,profile opcional, igual que `cloudflared`. El backend habla MCP
como ya hace `kali_mcp_client.py` (JSON-RPC `tools/call`) — **patrón ya existente, no inventamos otro**.

```
docker/kali-mcp.Dockerfile  →  nuevo docker/playwright-mcp.Dockerfile
docker-compose.yml          →  nuevo servicio + profile "web"
backend/browser_automation.py (nuevo)
```

**Guardarraíl obligatorio:** todo lo que salga del navegador pasa por `ingest_guard` (§3.2.1) antes de
entrar al contexto del LLM. Una SPA atacante no puede hablar con nuestro modelo.

#### 3.1.5 Generador de informes (P2, ~1 día)

`report_gen.py` de ellos (Markdown desde el store) → `backend/ooda_report.py`, adaptado al estilo
de MIRV (`pdf_engine.py` + `finding_poc.finding_to_markdown_report()` ya existen). Es un formateador,
no una invención; pero no lo mezcles con el drafter-reviewer (§3.2.3) hasta tener el store estable.

---

### 3.2 `MadsLorentzen/ai-job-search` — 4 patrones reutilizables

El producto (buscador de empleo) es **irrelevante**. Los *patrones* de sus `tools/` no.

#### 3.2.1 `backend/ingest_guard.py` — gate anti-inyección para contenido no confiable ⭐ PRIORIDAD 0

**Este es el hallazgo más valioso de los cinco repos.** `posting_guard.py` (~700 líneas, stdlib puro)
resuelve un problema que MIRV **no tiene**: hoy redaction (`redact.py`) filtra *secretos*, pero no
*instrucciones incrustadas*.

MIRV ingiere contenido de terceros en puntos donde ese contenido acaba frente al LLM:

| Punto de entrada | Dónde | Hoy |
|------------------|-------|------|
| HAR de Browser Capture | `browser_capture.py` (analyze) | el body va al LLM **sin sanear** |
| Salida de herramientas Kali | `main.py` → `parseToolOutput` → `/api/ai/chat` | idem |
| Snapshots de página | `intelligence.py` (`page_content`) | idem |
| Pasos de Lab Session | `lab_sessions.py` `save_analysis()` | idem |
| Texto de OSINT (Jina Reader, Wayback) | `osint_recon.py` | idem |

Clases de payload que el guard detecta y que `llm_scanner.py` (Pack 18) **no** cubre — porque aquel
*ataca* al LLM objetivo, no protege el nuestro:

- HTML oculto (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, `color:transparent`,
  `clip-path:inset(100%)`, caja colapsada con `overflow:hidden`, atributo `hidden`, `aria-hidden`)
- Caracteres invisibles: zero-width, controles bidi, soft hyphen, BOM
- **Caracteres Unicode TAG (U+E0000–U+E007F)** — un segundo alfabeto invisible al usuario y legible
  por el modelo. Es el vector más peligroso y **no lo cubre ningún scanner actual**
- Líneas con forma de instrucción (`ignore previous instructions`, `you are now…`, `### system:`,
  `<|im_start|>`, `[INST]`, `run the following command`)
- URLs que solo existen en contenido oculto
- Palabras con mezcla de escritura (homoglifos latin/cirílico)

**Port a MIRV**: `backend/ingest_guard.py`, stdlib puro, con la misma API:
```python
clean_text, findings = guard(raw, mode="html"|"text"|"auto")
# findings: {hidden_blocks, instruction_like, hidden_urls, homoglyph_runs,
#             invisible_chars, invisible_flagged, verdict}
```
El `verdict` es informativo (⚠), nunca bloqueante — coherente con que MIRV es una herramienta de
análisis, no un filtro de correo.

Puntos de integración (mínimos, no invasivos):
1. `main.py::_prepare_chat_messages` → sanear el contenido de usuario antes de mandarlo al LLM.
2. `browser_capture.py::analyze` → sanear bodies antes del análisis.
3. `lab_sessions.py::save_analysis` → sanear la evidencia.
4. `intelligence.py` → sanear el snapshot de página.
5. `POST /api/ingest/guard` (nuevo) + badge visual en la UI cuando hay verdict ⚠.

**Tests:** `backend/tests/test_ingest_guard.py` (~25 tests) — herméticos, sin red.
⚠️ Los patrones de `posting_guard.py` están cubiertos por **MIT** (repo: LICENSE MIT). Copiar el
regex con atribución en `backend/ingest_guard.py` header + `backend/ATTRIBUTION.md`.

#### 3.2.2 `backend/tests/test_skill_supply_chain.py` — guardas de supply-chain de skills ⭐ PRIORIDAD 1

`security_guards.py` (de ellos) es un linter que falla el build cuando alguien **amplía** permisos.
Traducción directa a MIRV:

| Check de ellos | Traducción a MIRV |
|----------------|-------------------|
| `allowed-tools` debe estar en una allowlist revisada | Cada `allowed_tools` de un SKILL.md debe ser un **ID real del arsenal** (65 IDs) — hoy no se valida |
| Sin wildcards (`Bash(*)`) | Prohibir `*`, `?`, `**` en `allowed_tools` y en `requires_scope` |
| Sin lifecycle scripts en `package.json` | La skill `android-pentesting` vendorizada puede traer `package.json` → prohibir `preinstall/install/postinstall/prepare/prepack` |
| `.gitignore` con reglas de datos personales | Verificar que `.gitignore` sigue ignorando `backend/data/`, `*.env`, `backend/logs/` |
| Agentes con `tools:` explícito | Las 39 personas de `agency_agents/` deben declarar herramientas permitidas y noEdit/Write/Bash libre |

Nuevo test file: `backend/tests/test_skill_supply_chain.py` (~15 tests). Se integra al CI existente
(`ci.yml` ya corre pytest + bandit). Precedente: `test_pack_purity.py` (17 tests) ya valida que los
packs no importen BD/red.

**Extra**: el guard debe correr también en el **endpoint de instalación remota** (§3.5) antes de
permitir activar una skill.

#### 3.2.3 Drafter-reviewer para informes (P2, ~2 días)

Su `/apply` escribe con un agente y revisa con **otro agente en contexto fresco**, luego revisa.
Traducción a MIRV:

- `backend/draft_review.py`: `draft(evidence) → review(draft, evidence) → revise(draft, review)`.
- El revisor es una **persona de `agency_agents`** (ya hay 39; crear/ajustar una "reviewer" de
  pentest) → no hace falta un framework de agentes nuevo.
- Se aplica a: `lab_writeup.py` (narrativa), `ooda_report.py` (§3.1.5), `finding_poc` markdown.
- Regla de honestidad que ellos aplican y debemos conservar: *una keyword que el perfil no soporta
  se declara como gap, nunca se rellena*. Aquí: *una vulnerabilidad que no sale de la evidencia
  real no se escribe en el informe*. Encaja con nuestra `redact`/`audit` cultura.

#### 3.2.4 Verificación del PDF compilado (P2, ~1 día)

`pdf_engine.py` compila y no comprueba nada. Adoptamos su loop:
- tras `doc.build()`, extraer la capa de texto y verificar: nº de páginas dentro del rango esperado,
  títulos/CVSS/evidencia presentes y no corruptos, orden de lectura correcto.
- `pypdf` es opcional (ya está en `requirements-dev.txt`? verificar) o `pdftotext` como fallback.
- Si falla → regenerar con ajustes (mismo mecanismo que su `verify_layout.py`).

### 3.3 `marichu-kt/DucKeyLogger` — dispositivo Rubber Ducky + detección defensiva

**División**: el repo contiene (a) el **vector de entrega** USB HID y (b) el **keylogger** con
exfiltración a Telegram. Se adopta (a) y se **reorienta** (b).

#### 3.3.1 Rubber Ducky como 13º dispositivo Hak5 (P2, ~1 día)

`hak5Devices` (`main.v2.js:6043-6056`) tiene 12 dispositivos. `bunny` es "Bash Bunny" (DuckyScript),
pero **no existe el Rubber Ducky clásico** ni hay encoder a `.bin`.

Añadir `ducky`:
1. `main.v2.js:6043` → entrada `{ name:'Rubber Ducky', icon:'🦆', ext:'bin', lang:'ducky script v3', desc:... }`
2. `main.v2.js:6059` → `HAK5_DESC_ES['ducky']`
3. `main.v2.js:6087` → `HAK5_TEMPLATES.ducky` (payloads DuckyScript reales)
4. `index.html:1306-1341` → `<button class="hak5-device-btn" data-device="ducky">`
5. `main.v2.js:6213` → rama de validación para `ducky script v3` (⚠️ si no, el validador dice
   "✓ válido" siempre — el bug está documentado en la auditoría)
6. `style.css:490` → color de acento opcional

Backend: **cero cambios** — `hak5_payloads.device` es `TEXT` libre.

#### 3.3.2 Encoder DuckyScript → `inject.bin` (P2, ~2 días)

Implementar en Python stdlib un encoder que convierta DuckyScript (`DELAY/GUI/STRING/RUN/KEY/ENTER`)
al flujo de bytes que consume un Rubber Ducky original.

⚠️ **El formato exacto hay que verificarlo contra el firmware `duckylog`**, no contra el README del
repo: el `inject.bin` que ellos publican es un artefacto ya compilado, no una especificación. Antes
de escribir código: leer el firmware Arduino de referencia y *round-trip* contra el `inject.bin`
del repo (el `STRING powershell -w hidden...` debe producir los mismos bytes). Si no cuadra, se
implementa solo el **exportador DuckyScript** (`.txt`, formato legible, que es lo que consume el
Ducky Encoder de schlomo) y se documenta el flujo manual.

Esto es honesto y útil: el 90% del valor es "generar DuckyScript correcto y exportarlo", y la
compilación a `.bin` puede quedarse en un paso opcional.

#### 3.3.3 `keylogger.ps1` → **NO se adopta**. Se reorienta a detección (P2, ~2 días)

Razones para no incluir el keylogger tal cual:
- Es un **capturador de credenciales con exfiltración a Telegram**. El precedente del propio proyecto
  es `phishing_sim.py`: *"awareness simulation (training-only, NOT credential theft)"*. Mantener esa
  línea es una decisión de producto, no un detalle.
- Riesgo de distribución: GitHub Push Protection, imágenes Docker, repositorio público.
- Es redundante: ya existen `keycroc` (keystroke logging) y `omg` (XHR keylog JS) en Payload Studio.

Lo que **sí** se implementa, y es más útil para un pentest/blue-team:

**a) `backend/hid_detect.py` — detección de implantes HID/USB**
Analiza un payload DuckyScript / `.bin` / `.ps1` y produce un finding con severidad cuando detecta:
- secuencias `RUN`/`STRING` con `powershell`/`cmd` ocultos (`-WindowStyle Hidden`),
- `ExecutionPolicy Bypass`, `-enc`/`-EncodedCommand` (base64),
- descarga+ejecución (`IEX`, `DownloadString`, `iwr`/`curl|bash`),
- persistencia (`HKCU\...\Run`, `schtasks`),
- extracción de datos hacia un canal externo (Telegram/Discord/Pastebin/webhook).

Esto es **defensa pura**: analiza un artefacto sospechoso, no implanta nada. Produce finding + SIEM
(`source=hid`) + audit log, como ya hacen `dlp_scanner`, `canary_tokens` y `secrets_scanner`.

**b) Parser forense de exportación de Telegram** (equivalente a `decoder-B64/decoder.py`)
`decoder.py` de ellos decodifica un export JSON de Telegram Desktop (base64+gzip) a texto legible.
Trasladado al **Forensics tab** es puramente defensivo: "dame el export de Telegram del incidente y
te reconstruyo la línea temporal de teclas capturadas". Se integra como un parser más del pipeline
de `forensics.py`.

⚠️ Legal: el propio repo exige autorización escrita explícita. En MIRV esto se respeta con lo que
ya tenemos: `scope_guard` (target en scope), `permission prompts` (§P0) y `opsec` levels.

### 3.4 `deepseek-ai/DeepInfer` — No integrar; abrir la puerta (P3, ~0,5 día)

**Por qué no:** DeepInfer requiere Linux + GCC≥13 + Python 3.12 + **CUDA 13 + GPUs NVIDIA SM100**
(o NPUs Ascend 950). La release actual **no incluye el servicio de inferencia completo** (falta el
sistema de KV cache y el disaggregation VE/Prefill/Decode) — solo `examples/offline_inference.py`.
MIRV corre en Docker sobre hardware general y ya habla con 6 proveedores cloud.

**Lo que sí sale de aquí** (es el único aporte, y es genérico):

Añadir a `_call_llm_sync` (`main.py:707-832`) un provider `custom` con `base_url` libre:
```
provider="custom", base_url="http://host.docker.internal:8000/v1"  →  {base_url}/chat/completions
```
Eso habilita **cualquier** servidor OpenAI-compatible propio: DeepInfer, vLLM, TGI, LM Studio, un
proxy corporativo, o un modelo local para despliegues air-gapped. ~15 líneas.

UI: en la config de IA (`mirv_ai_endpoint` ya existe en localStorage) permitir `base_url` explícito
en vez de sobreescribir con `OLLAMA_URL`. **No añadir nada específico de DeepSeek** — ya existe
`provider=deepseek` para la API cloud.

### 3.5 `vercel-labs/skills` — Instalador de skills remotas (P2, ~3 días)

**Qué es**: `npx skills` — CLI para descubrir e instalar skills de un registro (skills.sh) en tu
agente. Soporta OpenCode, Claude Code, Codex, Cursor + 75 más.

**Por qué encaja**: MIRV tiene 113 playbooks built-in y `POST /api/skills/create` (que solo crea
plantillas locales). **No hay forma de instalar una skill remota**, y el ecosistema de skills es
enorme.

**Por qué no usamos su CLI**: `npx skills` requiere **Node 22.20+**. El backend de MIRV es Python puro
(sin `package.json` en frontend). Implementamos el instalador **en Python stdlib** (`urllib`).

#### Diseño: `POST /api/skills/install`

```
{ source: "owner/repo" | "owner/repo/path/to/skill" | "https://raw.../SKILL.md" }
```
1. **Fetch** del `SKILL.md` (+ `references/`, `scripts/`, `assets/` opcionales) vía `urllib` con
   timeout y límite de tamaño.
2. **Mapear frontmatter** ajeno → nuestro `SkillManifest`:
   - `allowed-tools` → `allowed_tools` (mapeado a IDs del arsenal)
   - `category` ausente → inferir por keywords, si no → `custom`
   - `requires_scope` → **`true` por defecto** si el texto menciona ejecución/red/credenciales
   - `version`, `author` → default
   - ⚠️ Nuestro parser (`skill_playbooks._parse_skill_md`, `:134`) es un subconjunto YAML; si el
     frontmatter ajeno usa YAML completo, añadir un parser tolerante **o** reject explícito.
3. **Verificar supply-chain** con el guard de §3.2.2: `allowed_tools` ⊆ arsenal, sin wildcards,
   sin lifecycle scripts, sin `Bash(*)`.
4. **Instalar** en `~/.mirv/skills/<name>/` — **nunca** en `backend/skills/` (los bundled son
   read-only por convención de `agency_agents`).
5. **`enabled=False`** por defecto. El usuario la activa explícitamente.
   Coherente con nuestra postura `auto_load_new=False` (plugins) y con la de ellos: *"la copia es
   manual a propósito… hay que leer el código primero"*.
6. **Auditar**: la instalación genera entrada en `audit_log` + evento SIEM.

Endpoints:
```
POST   /api/skills/install     { source }      → preview (NO instala): manifest parseado + guard + diff
POST   /api/skills/install/confirm { name }    → escribe en disco
GET    /api/skills/registry?q=                 → búsqueda en skills.sh (opcional, P3)
DELETE /api/skills/{name}/uninstall            → borra de ~/.mirv/skills/
```
El flujo de **preview + confirm** replica su `/add-portal`: se investiga, se genera un test, y
solo después se registra. Nada se auto-instala.

⚠️ `vercel-labs/skills` es **MIT**. `npx skills` además tiene telemetría → si se usa el CLI externo
alguna vez, `DISABLE_TELEMETRY=1`. Nuestra implementación Python no hereda su telemetría.

---

## 4. Fases de ejecución

| Fase | Contenido | Esfuerzo | Depende de |
|------|-----------|----------|-----------|
| **F0 — Desbloqueo (P0)** | Cablear el gate de permisos: `scope_guard.request_permission` + `wait_for_decision` dentro del flujo WS, **y** el panel de UI que hace polling a `/api/permissions/pending` (7 rutas backend ya existen, 0 en frontend). Sin esto, el OODA puede ejecutar comandos que el operador no puede aprobar | 2 d | — |
| **F1 — Endurecimiento (P0)** | `backend/ingest_guard.py` + integrar en `browser_capture`, `_prepare_chat_messages`, `lab_sessions`, `intelligence` + `POST /api/ingest/guard` + badge UI | 3 d | — |
| **F2 — Supply-chain (P1)** | `backend/tests/test_skill_supply_chain.py` (allowlist arsenal, sin wildcards, sin lifecycle scripts, personas con `tools:` explícito) + job en `ci.yml` | 2 d | — |
| **F3 — OODA core (P1)** | `backend/ooda_store.py` (JSONL + write dual) → `backend/ooda.py` (motor) → endpoints → `ooda_report.py`. En este orden: el store antes que el motor | 6 d | F0, F1 |
| **F4 — ATT&CK (P1)** | `technique_id` en findings + `/api/attack/{techniques,coverage,gap}` + `orient()` del OODA usándolo | 1 d | F3 |
| **F5 — Supply-chain de skills (P2)** | `POST /api/skills/install` (preview→confirm) con el guard de F2 + uninstall + i18n en la tab Skills | 3 d | F2 |
| **F6 — Navegador (P2)** | `docker/playwright-mcp.Dockerfile` + servicio en compose + `backend/browser_automation.py` → findings a `browser_capture.py` | 4 d | F1 |
| **F7 — Rubber Ducky + HID detect (P2)** | 13º dispositivo `ducky` + export DuckyScript (y encoder `.bin` si el round-trip cuadra) + `backend/hid_detect.py` + parser Telegram en Forensics | 5 d | — |
| **F8 — Calidad de informes (P2)** | `backend/draft_review.py` (drafter-reviewer con personas de `agency_agents`) + verificación post-build en `pdf_engine.py` | 3 d | F3 |
| **F9 — Puertas abiertas (P3)** | `provider="custom"` con `base_url` libre + UI de `base_url`; búsqueda en skills.sh | 1 d | — |

**Total estimado: 30 días de trabajo** (secuencial) o ~4 semanas con 1 persona a tiempo completo.
F0–F2 (7 días) son los de mayor relación valor/riesgo y **no dependen de ningún repo externo**.

---

## 5. Lo que explícitamente NO se hace

| Decisión | Motivo |
|----------|--------|
| No se bifurca ni se forkea ningún repo | Todos son patrones; el código se reescribe en la arquitectura MIRV (`backend/*.py` + `frontend/js/main.v2.js`) |
| No se añade el keylogger de Telegram | Captura de credenciales + exfiltración. Precedente `phishing_sim.py`: training-only. Se reorienta a detección (`hid_detect`) |
| No se instala DeepInfer | Requiere SM100/Ascend; la release actual no incluye el servicio completo. Se abre `provider="custom"` y listo |
| No se usa `npx skills` | Requiere Node 22.20+; el backend es Python. Se implementa el instalador en Python stdlib |
| No se adopta la ausencia de guardrails de vulnerator-ai | Es su punto débil declarado y nuestra ventaja diferencial (`scope_guard` + permisos + `opsec` + audit) |
| No se añade Hermes como cerebro | Ya tenemos `orchestrator` + `agent_bridge` (opencode/claude/codex) + `agency_agents` (39 personas) |
| No se instalan skills remotas automáticamente | Coherente con `auto_load_new=False`; preview+confirm |
| No se crean tablas Supabase nuevas | Regla de AGENTS.md: 18 tablas. `technique_id`/`ooda_status` son columnas nuevas; el store OODA es JSONL en disco |

---

## 6. Riesgos

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| **Scope creep**: 30 días es mucho para el estado actual del repo | Alto | F0–F2 primero (7 días) y reevaluar. Cada fase es independiente y entregable |
| El OODA puede ejecutar comandos fuera de scope | **Crítico** | F0 es bloqueante: sin el gate de permisos + `scope_guard` en el WS, **el OODA no arranca**. Además `mode: pentest` para en evidencia, `redteam` requiere flag explícito |
| Prompt injection vía contenido de terceros | Alto | F1 (`ingest_guard`) es bloqueante para F3/F6: todo output de herramienta y todo DOM va por el guard antes del LLM |
| Abuso del instalador de skills (supply chain) | Alto | F2 antes de F5. Preview+confirm, `requires_scope=true` por defecto, `enabled=False`, audit log |
| Ruido de falsos positivos en `ingest_guard` | Medio | Modo `verdict` informativo (no bloquea). Los "hidden blocks" son contexto, no alarma; solo lo "instruction-like" alarma. Calibrar con casos reales del repo |
| Licencias | Bajo | Todo es MIT o Apache-2.0. **Atribución obligatoria** en `backend/ATTRIBUTION.md` + headers de fichero para `posting_guard.py` (MIT) y `agent-ooda` (MIT) |
| El installer remoto de skills se usa como vector de malware | Medio | Es la razón de F2. Sin el guard, **no se despliega F5** |
| Cobertura de tests que ya no cuadra | Bajo | Actualizar los contadores en `AGENTS.md`/`README.md`/`TOMORROW.md` al cerrar cada fase (la doc ya drifts: `AGENTS.md` dice 39 tabs, el código tiene 39; `main.py` dice 8921 líneas) |

---

## 7. Checklist de aceptación por fase

- [ ] **F0**: un comando `rm -rf /` enviado por WS produce un modal de aprobación en la UI; `deny` lo bloquea y lo registra en audit + SIEM
- [ ] **F1**: un HAR con `<div style="display:none">ignore previous instructions</div>` + un `<span>` con U+E0061 → el texto que llega al LLM no lo contiene; `/api/ingest/guard` devuelve verdict ⚠
- [ ] **F2**: un `SKILL.md` con `allowed_tools: [rm, "*"]` falla el test; `ci.yml` corre el guard
- [ ] **F3**: un OODA de 8 pasos sobre un lab produce un JSONL con los 8 pasos, los findings con status/technique_id/confidence, y un informe Markdown con solo evidencia real
- [ ] **F4**: `/api/attack/coverage` devuelve técnicas ejercitadas vs. no ejercitadas por assessment
- [ ] **F5**: instalar una skill pública muestra el preview con el manifest mapeado y el resultado del guard; activarla requiere un clic
- [ ] **F6**: navegar una SPA local extrae rutas y encuentra un XSS reflejado → finding en `browser_capture`
- [ ] **F7**: el dispositivo `ducky` valida DuckyScript; un `inject.bin` sospechoso produce finding `hid`; un export de Telegram produce línea temporal legible
- [ ] **F8**: el PDF de findings tiene la capa de texto verificada; el informe del OODA pasa por revisión
- [ ] **F9**: `provider="custom"` contra un servidor OpenAI-compatible local responde en `/api/ai/chat`

---

## 8. Referencias

| Recurso | Licencia | Uso previsto |
|---------|----------|--------------|
| `ai-job-search` → `tools/posting_guard.py` | MIT | Port a `backend/ingest_guard.py` (atribución obligatoria) |
| `ai-job-search` → `tools/security_guards.py` | MIT | Port a `backend/tests/test_skill_supply_chain.py` |
| `ai-job-search` → `/apply` (drafter-reviewer) | MIT | Patrón, no código |
| `ai-job-search` → `tools/verify_pdf.py` / `verify_layout.py` | MIT | Patrón para `pdf_engine.py` |
| `vulnerator-ai` → `agent-ooda/skills/pentest-ooda/` | MIT | Patrón del bucle OODA (reimplementar, no copiar: arquitectura distinta) |
| `vulnerator-ai` → `docs/design.md` (esquema del findings store) | MIT | Referencia del esquema JSONL |
| `vulnerator-ai` → `docker/kali/report_gen.py` | MIT | Referencia del formateador de informe |
| `vulnerator-ai` → `docker/kali/finding_store.py` | MIT | Referencia del store |
| `DucKeyLogger` → `keylogger.ps1` | Licencia educativa propia | **No se copia.** Solo se toma el flujo DuckyScript→payload |
| `DucKeyLogger` → `decoder-B64/decoder.py` | Licencia educativa propia | Parser forense de export de Telegram (reimplementar) |
| `DeepInfer` | Apache-2.0 | No se copia. Solo el patrón "backend OpenAI-compatible" |
| `vercel-labs/skills` | MIT | Especificación de UX del flujo install/find/list; implementación propia en Python |

---

## 9. Nota sobre el estado previo del proyecto

Este plan se apoya en la auditoría previa del mismo día, que encontró **80 rutas API nunca invocadas
por el frontend**. La más grave es el bloque de permisos (7 rutas) y ya está tratada como **F0**.
Las demás —Burp tasks/export (8), Finding PoC (6), Missions memory (6), Phishing (6), Wireless (5),
Scope events (4), Redaction (4), Router benchmark (1)— son deuda de UI de menor urgencia y quedan
fuera de este plan; conviene tackledas en un sprint aparte **después** de F0–F2.

Además, dos deudas rápidas que este plan no cubre pero que conviene arreglar de paso:
- `package.json` define `"test:e2e": "playwright test"` sin `playwright.config.js` en la raíz → el
  script **falla**; el comando correcto es `npx playwright test --config=frontend/tests/playwright.config.js`.
- El smoke test busca `#tab-${id}-panel` / `.tab-panel[data-tab]` pero el markup real es
  `#tab-${id}` con clase `.tab-pane` → la aserción es un no-op silencioso en las 14 tabs.
