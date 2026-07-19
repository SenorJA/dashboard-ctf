# Frontend — Arquitectura y Eventos

## Estructura del Arsenal

El Arsenal se compone de:

1. **Categorías colapsables** (`cat-header` + `cat-body`)
2. **Tool buttons** individuales dentro de cada categoría
3. **Master toggle** para expandir/colapsar todo
4. **Filtro** para búsqueda en tiempo real
5. **Run All** por categoría para tools API-based

### Categorías

```
Web Recon     [19]  ← API tools + SSH tools
Network       [8]   ← 1 API tool (dns-lookup) + SSH tools
SMB/Windows   [7]   ← SSH tools
Pivoting      [4]   ← SSH tools
Crypto/Decode [5]   ← SSH tools
Exploitation  [9]   ← SSH tools
OSINT         [6]   ← SSH tools + Web links (Flare.io, etc.)
Pentest Labs  [10]  ← Enlaces externos
Bug Bounty    [8]   ← Enlaces externos
Resources     [8]   ← Enlaces externos
Utilities     [1]   ← Enlaces externos
Extract       [7]   ← SSH tools
Hardware      [10]  ← Enlaces externos
```

### Tool buttons

Cada botón es generado por `renderToolButton(t)` o `renderLinkButton(l)`:

```html
<button class="tool-btn w-full ..." data-tool="gobuster">
  <span class="text-... font-bold"># Gobuster</span>
  <span class="text-[9px] text-gray-600">directorios web</span>
</button>
```

## Sistema de Eventos

### Eventos actuales (antes del refactor)

Actualmente los eventos se asignan de dos formas:

1. **Inline `onclick`** en `index.html` y en HTML renderizado por JS
2. **`addEventListener`** en algunas partes del init code

La aplicación está en proceso de migrar de `onclick` a `addEventListener`.

### Mapa de eventos (post-refactor)

| Elemento | Selector | Evento | Handler |
|----------|----------|--------|---------|
| Tool buttons | `[data-tool]` | click | `launchTool(e)` |
| Category headers | `.cat-header` | click | `toggleCategory(e)` |
| Master toggle | `#master-toggle` | click | `toggleAllCategories()` |
| Run All buttons | `[data-run-category]` | click | `runAllInCategory(e)` |
| Filter input | `#arsenal-search` | input | `filterArsenal(val)` |
| Tab buttons | `[data-tab]` | click | `switchTab(name)` |
| Theme toggle | `[data-action="theme"]` | click | `toggleTheme()` |
| Language switch | `[data-action="lang"]` | click | `switchLanguage()` |

### Patrón para nuevos elementos

```javascript
// En el init block (DOMContentLoaded):
document.querySelectorAll('[data-action="algo"]').forEach(el => {
  el.addEventListener('click', (e) => {
    const param = el.dataset.param;
    // handler logic
  });
});
```

## API-based Tools Handlers

Las herramientas API-based (las 9 nuevas) se ejecutan mediante `fetch()` directamente desde el frontend, sin pasar por SSH. El patrón es:

```javascript
if (tool === 'mi-herramienta') {
    const url = `/api/mi-endpoint?param=${encodeURIComponent(target)}`;
    try {
        const resp = await fetch(url);
        const data = await resp.json();
        if (!data.ok) { /* error */ return; }
        // Mostrar resultados
        appendOutput(`  resultado: ${data.campo}`);
        if (data.findings && typeof window.addFindings === 'function') {
            window.addFindings(data.findings);
        }
    } catch (e) {
        appendOutput(`  ❌ Error: ${e.message}`);
    }
    return; // ← IMPORTANTE: evitar que caiga en SSH
}
```

El `return` al final es crítico: evita que el flujo continúe al bloque de ejecución SSH.

## Run All por categoría

El botón "▶ Run All" dentro de cada categoría ejecuta secuencialmente todas las herramientas API-based de esa categoría. Usa `window.runAllInCategory(categoryId)`.

```javascript
const API_TOOLS = [
    'headers-scan', 'secrets-scan', 'port-scan', 'subdomain-scan',
    'dns-lookup', 'hash-crack', 'stego-tool', 'news-scraper', 'api-scanner',
];
```

Las herramientas que requieren SSH (nmap, gobuster, etc.) se omiten en el batch.

## Findings

Todas las tools API-based generan findings en el mismo formato:

```javascript
{
    tool: "nombre-herramienta",
    severity: "high" | "medium" | "low" | "info",
    title: "Resumen del hallazgo",
    detail: "Descripción detallada",
    target: "url/ip analizada",
    type: "vuln" | "tech",
    extra: { /* metadatos específicos */ }
}
```

Los findings se añaden mediante `window.addFindings(data.findings)` que:
1. Los muestra en la tabla de Findings (tab)
2. Los persiste en Supabase vía `DataService`
3. Los usa para el sistema de reportes

## OPSEC

Todas las herramientas API-based tienen regla OPSEC `null` (sin modificación):

```javascript
'herramienta': { silent: null, covert: null },
```

Esto significa que la herramienta se ejecuta igual en todos los niveles (silent, covert, loud).
