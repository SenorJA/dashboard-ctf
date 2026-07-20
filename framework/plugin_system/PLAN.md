# Plugin System — Plan de Implementación

## Objetivo
Sistema de plugins modular que permita cargar, gestionar y ejecutar módulos externos (`.py`) en tiempo de ejecución, con hooks en el pipeline de MIRV (eventos, findings, herramientas, WebSocket).

## Arquitectura

```
backend/
├── plugin_manager.py       ← Core: loader, registry, hooks, sandbox
├── plugins/                ← Directorio de plugins instalados
│   ├── __init__.py
│   ├── example_plugin/     ← Plugin de ejemplo documentado
│   │   ├── __init__.py
│   │   ├── plugin.json     ← Metadata (nombre, versión, autor, hooks)
│   │   └── main.py
│   └── ...
├── main.py                 ← + endpoints REST para gestión de plugins
└── tests/
    └── test_plugin_manager.py

frontend/
├── index.html              ← Pestaña "Plugins" (#19)
└── js/main.v2.js           ← UI: listar, instalar, activar/desactivar, configurar
```

## Plugin Manifest (`plugin.json`)
```json
{
  "name": "example-plugin",
  "version": "1.0.0",
  "author": "MIRV",
  "description": "Plugin de ejemplo documentado",
  "hooks": ["on_tool_result", "on_finding", "on_event"],
  "dependencies": [],
  "config_schema": {
    "enabled": {"type": "boolean", "default": true},
    "api_key": {"type": "string", "default": ""}
  }
}
```

## Hook System
| Hook | Firma | Disparo |
|------|-------|---------|
| `on_tool_result` | `(tool: str, target: str, output: str) -> None` | Cuando un tool termina |
| `on_finding` | `(finding: dict) -> dict \| None` | Antes de guardar un finding (puede modificarlo) |
| `on_event` | `(event: dict) -> None` | Cuando se ingesta un evento SIEM |
| `on_startup` | `() -> None` | Cuando arranca el servidor |
| `on_shutdown` | `() -> None` | Cuando se apaga el servidor |
| `on_websocket_message` | `(msg: dict) -> dict \| None` | Mensaje entrante por WS |
| `register_routes` | `(app: FastAPI) -> None` | Registrar rutas adicionales |

## Plugin Manager API
| Función | Descripción |
|---------|-------------|
| `discover_plugins()` | Escanea `plugins/` en busca de `plugin.json` |
| `load_plugin(name)` | Importa el módulo y registra hooks |
| `unload_plugin(name)` | Elimina hooks y libera recursos |
| `reload_plugin(name)` | Unload + load (hot-reload) |
| `get_plugin_info(name)` | Retorna metadata del plugin |
| `list_plugins()` | Lista todos los plugins + estado |
| `call_hook(hook_name, *args, **kwargs)` | Invoca todos los hooks registrados |
| `enable_plugin(name)` | Activa hooks |
| `disable_plugin(name)` | Desactiva hooks sin descargar |

## Endpoints REST
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | /api/plugins | Listar plugins |
| GET | /api/plugins/{name} | Info de un plugin |
| POST | /api/plugins/{name}/load | Cargar plugin |
| POST | /api/plugins/{name}/unload | Descargar plugin |
| POST | /api/plugins/{name}/reload | Hot-reload |
| POST | /api/plugins/{name}/enable | Activar hooks |
| POST | /api/plugins/{name}/disable | Desactivar hooks |
| POST | /api/plugins/install | Instalar plugin desde GitHub o tarball |

## Seguridad
- Los plugins corren en el mismo proceso (sin sandbox por ahora)
- Validación estricta del `plugin.json` (campos requeridos)
- Timeout de 30s por hook para evitar bloqueos
- Los plugins NO pueden acceder a `os.system`, `subprocess` sin registro explícito
- Logging obligatorio de todas las operaciones de plugins
