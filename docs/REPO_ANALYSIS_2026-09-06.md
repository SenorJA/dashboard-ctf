# Análisis de Repos Externos — Documentación (6 Sep 2026)

> Documentación de 2 repositorios recomendados por el operador (Javi) para
> integración/inspiración en MIRV.
> - `elder-plinius/CL4R1T4S` — colección pública de system prompts de modelos de IA
> - `cporter202/agentic-ai-apis` — recurso masivo de APIs para agent builders

---

## Repos documentados

| Repo | Enfoque | Valor para MIRV |
|---|---|---|
| `elder-plinius/CL4R1T4S` | Colección pública de system prompts (leaked/disclosed) de modelos de IA populares (Anthropic Claude, OpenAI, etc.) | ⭐⭐ MEDIA — banco de material para hardening de prompts + testing de prompt-injection | 
| `cporter202/agentic-ai-apis` | Catálogo masivo de APIs útiles para construir agentes AI (LLMs, RAG, vectores, búsqueda, web, datos, tooling) | ⭐⭐⭐ ALTA — fuente de integraciones para `/api/ai/chat`, MCP server, herramientas OSINT/API-based |

---

## Repo 1: elder-plinius/CL4R1T4S

### Qué es
Repositorio con system prompts (algunos divulgados/filtrados y otros reconstruidos vía
extraction) de modelos de IA comerciales: la referencia concreta compartida es
`ANTHROPIC/Claude-Fable-5.1.md`. Uso común: investigación de seguridad de IA
(prompt extraction, prompt-injection, alignment, jailbreak). Todo el material es público
en GitHub.

### Compatibilidad con MIRV: MEDIA
MIRV no implementa modelos de IA propios — consume endpoints externos (`/api/ai/chat`,
OpenAI-compatible, con auto-redacción). Por tanto no hay prompts que "ejecutar",
pero el repo es valioso como **banco de casos**:

### Qué coger
1. **Separadores de contexto/instrucción**: estudiar cómo los prompts reales delimitan
   system/user/tools (p. ej. delimitadores de sección) para reforzar los prompts que MIRV
   inyecta vía `GET /api/skills/{name}/render` (prompt injection de skills) y el system
   prompt de `/api/ai/chat` (anti-exfiltración de secrets tras la redacción).
2. **Casos de prompt-injection**: usar ejemplos del repo como dataset para un
   test de robustez del `prompt` inyectado cuando se usan skills renderizadas.
3. **Hardening del escalation in /api/ai/chat**: las defensas documentadas en el repo
   (instrucciones de no-exfiltración, avisos de "ignore previous instructions") son
   material para el mensaje que rodea al contexto redactado.

### No portar / precaución ética
- **No usar para eludir restricciones de proveedores** — MIRV respeta ToS de los
  modelos que consume. El material es de investigación/defensa (entender la postura de
  prompt de los adversarios y proteger la propia).
- **No redactar/system prompts copiados como "nuestros"** — referencia de estudio, no
  bienes integrables en el producto.

---

## Repo 2: cporter202/agentic-ai-apis

### Qué es
Índice curado y actualizado ("massive resource") de APIs REST para agent builders:
proveedores LLM, embeddings/vectores, RAG, búsqueda web, scraping, datos, email,
rastreo, herramientas de observabilidad/tooling de agentes, etc. Recopila endpoints y
servicios listos para llamar desde código.

### Compatibilidad con MIRV: ALTA
MIRV ya pivota a herramientas **API-based** (OSINT Recon usa llamadas HTTP directas
desde el frontend con `fetch()`). El catálogo es una cantera de nuevas integraciones.

### Qué coger (candidatos por módulo MIRV)
| Candidata | Tipo API | Ubicación en MIRV |
|---|---|---|
| Búsqueda web / scraping (SERP, DuckDuckGo, trafilatura…) | lookup web | Herramientas OSINT API-based / `webvuln` recon / Intelligence (page_content) |
| Geolocalización IP / WHOIS / DNS | datos de red | OSINT Recon (IP, dominio) |
| Email breach/OSINT (haveibeenpwned-like) | lookup | `dlp_scanner.py` + OSINT |
| Análisis de URLs (URLhaus, VirusTotal-likes) | seguridad | `browser_capture.py` security checks |
| OCR / extracción de documentos | IA-utilidades | `forensics.py` evidence parsing |
| TTS/STT/multimodal | IA-utilidades | (futuro asistente de voz del dashboard) |
| Embeddings / vector store | RAG | futuro prompt-caching / memoria `mission_store.py` |

### Implementación propuesta mínima (sin tocar nada ahora)
1. Crear un documento de índice `docs/AGENTIC_APIS.md` con las APIs preseleccionadas
   (endpoint, auth, rate limit, costo) lista para cuando se abra una ronda de
   integraciones.
2. Guardar como roadmap: "Ronda API-based #2 — 5 nuevas herramientas OSINT desde
   `cporter202/agentic-ai-apis`".

### No portar
- No copiar el repo entero; es un índice, no código de runtime.
- Validar ToS/rate-limits de cada API antes de integrar (varias requieren key).

---

## Estado

- ✅ Documentación creada (este archivo)
- ✅ Ronda API-based #2 (5 herramientas OSINT) — implementada, testeada y verde en CI
  (backend `osint_recon.py` + 5 endpoints `/api/osint/*` + tab OSINT del frontend)
- ⬜ Importar ejemplos CL4R1T4S a un test de robustez de prompts — pendiente de "SÍ"
- ⬜ Crear `docs/AGENTIC_APIS.md` con APIs preseleccionadas — pendiente de "SÍ"

*Documentado: 6 Sep 2026 — actualizado 9 Sep 2026*