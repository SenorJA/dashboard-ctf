# Sistema de Eventos — onclick → addEventListener

## Estado: ✅ COMPLETADO (Julio 2026)

**0 onclick** en toda la aplicación.

---

## Resumen de la Migración

| Archivo | onclick antes | onclick después |
|---------|:------------:|:---------------:|
| `index.html` | 126 | **0** |
| `main.v2.js` | 7 | **0** |
| `onchange` | 2 (1 index + 1 JS) | **0** |

---

## Principios

1. **No más `onclick`** en HTML ni en cadenas renderizadas por JS
2. **Event delegation** para todos los elementos (estáticos y dinámicos)
3. **`data-*` attributes** para identificar elementos y parámetros
4. **`window.*`** se mantiene solo para funciones invocadas desde consola o IA
5. **`ACTION_MAP`** centralizado (~90 entradas) como única fuente de verdad

---

## Arquitectura

### 1. `index.html` — Atributos `data-*`

Todos los `onclick="fn()"` se reemplazaron con:

| Atributo | Propósito | Ejemplo |
|----------|-----------|---------|
| `data-action="..."` | Acción genérica mapeada en ACTION_MAP | `data-action="save-hak5"` |
| `data-tab="..."` | Cambio de pestaña | `data-tab="terminal"` |
| `data-tool="..."` | Lanzar herramienta (arsenal) | `data-tool="nmap"` |
| `data-script="..."` | Seleccionar plantilla de script | `data-script="bash-rev"` |
| `data-device="..."` | Seleccionar dispositivo Hak5 | `data-device="bunny"` |
| `data-category="..."` | Identificar categoría (Run All) | `data-category="web-recon"` |
| `data-idx="..."` | Índice para listas dinámicas | `data-idx="0"` |
| `data-mission-id="..."` | ID de misión | `data-mission-id="abc123"` |

### 2. `main.v2.js` — ACTION_MAP

Objeto central de ~90 entradas en `initEventListeners()`:

```javascript
const ACTION_MAP = {
    'theme':           () => toggleTheme(),
    'lang':            () => switchLanguage(),
    'toggle-category': (el) => toggleCategory(el),
    'toggle-all':      () => toggleAllCategories(),
    'run-all':         (el) => runAllInCategory(el.dataset.category),
    'save-hak5':       () => saveHak5Payload(),
    'report-view':     (el) => viewReport(parseInt(el.dataset.idx)),
    // ... ~80 más
};
```

### 3. Event Delegation

Un solo listener en `#app` captura todos los clicks:

```javascript
app.addEventListener('click', (e) => {
    const actionEl = e.target.closest('[data-action]');
    if (actionEl) {
        const handler = ACTION_MAP[actionEl.dataset.action];
        if (handler) { handler(actionEl); e.preventDefault(); return; }
    }
    // ... data-tool, data-tab, data-script, data-device
});

app.addEventListener('change', (e) => {
    // Maneja select[data-action="report-export"]
});
```

---

## Detalle de Reemplazos

### index.html (126 onclick)

| Grupo | Cantidad | Atributo usado |
|-------|:--------:|----------------|
| Sidebar (tabs) | 15 | `data-tab` |
| Sidebar controls (theme, lang, sidebar) | 3 | `data-action` |
| Categorías (toggle) | 13 | `data-action="toggle-category"` |
| Categorías (Run All) | 10 | `data-action="run-all"` + `data-category` |
| Master toggle | 1 | `data-action="toggle-all"` |
| Conexión SSH | 5 | `data-action` |
| Terminal | 3 | `data-action` |
| Reports | 5 | `data-action` |
| Scripts | 5 | `data-script`, `data-action` |
| Bounty | 3 | `data-action` |
| AI Writeup | 2 | `data-action` |
| Hak5 | 9 | `data-device`(4) + `data-action`(5) |
| n8n | 5 | `data-action` |
| Op Admiral | 5 | `data-action` |
| Swarm | 4 | `data-action` |
| Findings | 5 | `data-action` |
| Scope | 4 | `data-action` |
| OPSEC | 3 | `data-action` |
| Docker | 6 | `data-action` |
| Forensics | 2 | `data-action` |
| Mobile | 6 | `data-action` |
| Credentials | 3 | `data-action` |
| CTF | 2 | `data-action` |
| KnowledgeBase | 3 | `data-action` |
| File upload | 1 | `data-action="file-upload"` |
| Payload Studio | 3 | `data-action` |
| **Total** | **126** | |

### main.v2.js (7 onclick + 1 onchange)

| Ubicación | Línea (aprox) | Reemplazo |
|-----------|:------------:|-----------|
| Reports view | 164 | `data-action="report-view"` + `data-idx` |
| Reports export | 165 | `data-action="report-export"` + `data-idx` (change event) |
| Reports delete | 171 | `data-action="report-delete"` + `data-idx` |
| Suggestions copy | 4538 | `data-action="copy-clipboard"` |
| Plan copy command | 6068 | `data-action="plan-copy-cmd"` + `data-idx` |
| Plan execute step | 6073 | `data-action="plan-exec-step"` + `data-idx` |
| Mission view | 6409 | `data-action="view-mission"` + `data-mission-id` |

---

## `window.*` Functions Conservadas

Todas las funciones JS se mantienen en `window.*` para compatibilidad con:
- Consola del navegador (debug)
- Llamadas desde AI Assistant
- Llamadas desde otros módulos JS

Ejemplos: `window.launchTool()`, `window.sendCommand()`, `window.switchTab()`, `window.toggleTheme()`, `window.saveHak5Payload()`, etc.

---

## Archivos Modificados

| Archivo | Cambio |
|---------|--------|
| `frontend/index.html` | 126 onclick → data-* attributes |
| `frontend/js/main.v2.js` | ACTION_MAP + initEventListeners + 7 onclick JS → data-* |
| `frontend/index.html.bak` | Backup pre-refactor |

---

## Verificación

```bash
# Comprobar que no quedan onclick
grep -c "onclick=" frontend/index.html    # → 0
grep -c "onclick=" frontend/js/main.v2.js # → 0
grep -c "onchange=" frontend/index.html   # → 0
grep -c "onchange=" frontend/js/main.v2.js # → 0
```
