# PLAN — Browser Capture MCP Integration

> Módulo: `framework/browser_capture_mcp` — Fecha: 9 Ago 2026
> Feature: exponer el análisis de tráfico del navegador (browser_capture)
> como tools MCP para que los agentes AI puedan importar HARs, analizarlos
> y convertir hallazgos en findings del session store.

## Contexto

- `backend/browser_capture.py` (~1334 líneas, 100% coverage): importa HAR
  (`import_har(bytes, filename)`), analiza sesiones con 10 checks
  (`analyze_session(session_id) -> Optional[CaptureAnalysis]`), lista
  sesiones (`list_sessions(limit, offset)`), las consulta
  (`get_session(session_id)`), convierte issues a findings MIRV
  (`report_to_mirv_findings(analysis)`) y expone `status()`.
- `backend/mcp_server.py` (~620 líneas, 100% coverage): servidor MCP
  JSON-RPC stdio. `TOOLS` (lista de schemas), `handle_tool_call(name, args)`
  (dict de dispatcher a `_tool_*`), `_add_finding()` (store en
  `_session_findings`), `handle_message()` (initialize/tools/list/tools/call).

## Arquitectura — 7 tools nuevas en mcp_server.py

| Tool | Args | Handler | Comportamiento |
|------|------|---------|----------------|
| `vulnforge_browser_import` | `har_content` (str, req), `filename` (str, default "har_capture.har") | `_tool_browser_import` | codifica `har_content` a bytes utf-8 → `browser_capture.import_har()`; devuelve session_id/target/request_count o el error como texto |
| `vulnforge_browser_list_sessions` | `limit` (int, default 50), `offset` (int, default 0) | `_tool_browser_list_sessions` | `list_sessions()` formateado a texto |
| `vulnforge_browser_get_session` | `session_id` (str, req) | `_tool_browser_get_session` | `get_session()`; si no existe → mensaje claro |
| `vulnforge_browser_analyze` | `session_id` (str, req) | `_tool_browser_analyze` | `analyze_session()`; si hay issues, cada uno → `_add_finding("browser-capture", ...)`; devuelve resumen con risk_score + nº issues |
| `vulnforge_browser_get_analysis` | `session_id` (str, req) | `_tool_browser_get_analysis` | análisis completo (issues + risk_score + recommendations) como texto estructurado |
| `vulnforge_browser_create_findings` | `session_id` (str, req) | `_tool_browser_create_findings` | `report_to_mirv_findings(analysis)` → cada finding → `_add_finding(...)`; devuelve conteo por severidad |
| `vulnforge_browser_stats` | — | `_tool_browser_stats` | `status()` formateado |

Integración clave: `vulnforge_browser_analyze` y
`vulnforge_browser_create_findings` alimentan `_session_findings`, así un
agente puede encadenar: import → analyze → findings_list.

## Cambios en mcp_server.py

1. Añadir 7 entradas a `TOOLS` (name/description/inputSchema con types).
2. Añadir handlers `_tool_browser_*` (async) al final de la sección de tools.
3. Registrar en el dict de `handle_tool_call`.
4. Importar `from backend import browser_capture` (import perezoso dentro de
   handlers si hay riesgo de ciclo, pero no lo hay — browser_capture no
   importa mcp_server).
5. Manejo de errores: nunca lanzar excepción no controlada; devolver texto
   con el error (import_har ya devuelve `{"ok": False, "error": ...}`).
6. Máximo de texto devuelto razonable (p.ej. truncar análisis a 6000 chars).

## Tests

- ACTUALIZAR `backend/tests/test_mcp_server.py::test_tools_defined_with_expected_schema`
  para incluir los 7 nombres nuevos (el test actual compara lista exacta).
- NUEVO `backend/tests/test_mcp_browser_tools.py`:
  - fixture HAR mínimo válido (log.version "1.2", 1-2 entries con request/response).
  - `_tool_browser_import` con HAR válido → session creada; con JSON inválido → texto de error; con version "2.0" → error de versión.
  - `_tool_browser_list_sessions` lista la sesión importada.
  - `_tool_browser_get_session` con session real y con id inexistente.
  - `_tool_browser_analyze` → devuelve risk_score y puebla `_session_findings`; sesión inexistente → mensaje.
  - `_tool_browser_get_analysis` → contiene issues.
  - `_tool_browser_create_findings` → puebla `_session_findings` con tool "browser-capture".
  - `_tool_browser_stats` → contiene "sessions".
  - `handle_tool_call` enruta los 7 nombres (y "Unknown tool" para otros).
  - Limpiar `mcp._session_findings` y el store de browser_capture entre tests
    (usar `browser_capture.reset()` o fixture autouse).

## Criterios de aceptación

1. `test_mcp_browser_tools.py` 100% verde; `test_mcp_server.py` sigue verde.
2. `mcp_server.py` coverage ≥ 95% (con los tests nuevos + existentes).
3. `TOOLS` contiene los 7 nuevos; `tools/list` los devuelve.
4. Análisis alimenta el session findings store (integración real).

## Entregables

- `backend/mcp_server.py` (7 tools + handlers + dispatch)
- `backend/tests/test_mcp_server.py` (lista de tools actualizada)
- `backend/tests/test_mcp_browser_tools.py` (nuevo)
- `framework/browser_capture_mcp/PLAN.md`
