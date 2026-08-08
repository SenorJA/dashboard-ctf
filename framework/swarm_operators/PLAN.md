# PLAN — Swarm Operators Expansion (OSINT, Web, Vuln)

> Módulo: `framework/swarm_operators` — Fecha: 8 Ago 2026
> Feature: ampliar el pipeline multi-operador del Swarm de 4 a 7 operadores.

## Objetivo

Añadir tres operadores nuevos al Swarm coordinator:

| Operador | Nombre | Fase | Herramientas |
|----------|--------|------|--------------|
| `osint` | 🌐 OSINT Recon | Después de Recon | theHarvester, whois, dig/host/dnsrecon, subfinder, curl security headers |
| `web` | 🕸️ Web App Scanner | Después de Scanner | whatweb, nikto, dirb/feroxbuster, wafw00f, curl headers, check-ssl |
| `vuln` | 🧨 Vuln Researcher | Después de Web | nuclei, nmap `--script vulners`, searchsploit |

Pipeline final (modo `full`): **Recon → OSINT → Scanner → Web → Vuln → Exploiter → Report**

## Arquitectura

```
backend/operators/
├── base.py      # BaseOperator (sin cambios)
├── recon.py     # existente
├── scanner.py   # existente
├── exploiter.py # existente
├── report.py    # existente
├── osint.py     # NUEVO — OSINTOperator
├── web.py       # NUEVO — WebOperator
├── vuln.py      # NUEVO — VulnOperator
└── __init__.py  # exportar los 3 nuevos
```

`backend/swarm.py`:
- `SwarmCoordinator.__init__(..., mode="full")` — `mode` ∈ `{"full", "core"}`
  - `full` → 7 operadores (nuevo default)
  - `core` → 4 operadores (compatibilidad con la UI/estado anterior)
- `_build_operators(mode)` devuelve la lista; `run_pipeline` la usa.
- Progreso: cada operador = `100 / total` (ya genérico con `len(self.operators)`).

`backend/main.py`:
- `SwarmStartRequest.mode: str = "full"` (validar: `full|core`, fallback `full`).
- Pasar `mode` al `SwarmCoordinator`.

## Frontend

`frontend/index.html` (tab-swarm):
- Selector de modo junto al target: `Full (7 ops)` / `Core (4 ops)`.
- `id="swarm-mode"`.

`frontend/js/swarm.js`:
- `swarmStart()` envía `mode` en el body.
- `swarmRender()`: añadir `opIcons`, `opLabels`, `opDesc` para `osint`, `web`, `vuln`.
- Grid a 3 columnas (md:grid-cols-3) para 7 tarjetas.

## Tests

- `backend/tests/test_operators_new.py` (NUEVO): unit tests de cada operador nuevo
  (run con swarm mockeado: `exec()` devuelve fixtures, verificar `findings`).
- `backend/tests/test_swarm.py` (ACTUALIZAR):
  - `test_pipeline_completes_and_persists` → parchear también los 3 operadores nuevos; expect 7 findings.
  - Nuevos: `test_pipeline_full_mode_has_7_operators`, `test_pipeline_core_mode_has_4_operators`,
    `test_invalid_mode_falls_back_to_full`.
- `backend/tests/test_main_gaps.py` o `test_main_coverage.py` (ACTUALIZAR):
  - `swarm_start` con `mode="core"` y `mode` inválido.

## Criterios de aceptación

1. `backend/tests/test_operators_new.py` + `test_swarm.py` verdes.
2. `python -m coverage report --include="backend/swarm.py,backend/operators/*"` ≥ 95%.
3. UI renderiza 7 tarjetas con icono/descripción correctos.
4. Compatibilidad: `mode="core"` mantiene los 4 operadores originales.

## Entregables

- `backend/operators/osint.py`, `backend/operators/web.py`, `backend/operators/vuln.py`
- `backend/operators/__init__.py` (actualizado)
- `backend/swarm.py` (actualizado)
- `backend/main.py` (actualizado: `SwarmStartRequest.mode`)
- `frontend/index.html`, `frontend/js/swarm.js` (actualizados)
- `backend/tests/test_operators_new.py` (nuevo), `backend/tests/test_swarm.py` (actualizado)
