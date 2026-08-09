# PLAN — Real Light Theme (Dark Mode real)

> Módulo: `framework/light_mode` — Fecha: 9 Ago 2026
> Feature: añadir un tema **claro** de verdad al frontend. Hoy la app es
> oscura por defecto y el toggle solo alterna a monocromo (`body.monochrome`).

## Objetivo

Añadir un tercer estado de tema al ciclo del botón:

```
neon (oscuro, default) → light (claro) → mono (monocromo) → neon ...
```

Patrón probado: el bloque `body.monochrome` de `frontend/css/style.css`
(líneas ~511-650) con overrides `!important`. Se replica con `body.light`.

## Arquitectura

### 1. `frontend/css/style.css` — bloque `body.light` (nuevo, al final)
Variables light:
- `--light-bg: #f2f4f8` (fondo página, reemplaza `bg-deep`/`#0b0e14`)
- `--light-surface: #ffffff` (reemplaza `bg-void`/`#111520`)
- `--light-border: #d7dce4` (reemplaza bordes `gray-800`/`#1a1f2e`)
- `--light-text: #1f2430` (reemplaza `text-gray-300/400`)
- `--light-text-dim: #5a6474` (reemplaza `text-gray-500/600`)
- `--light-text-dark: #8a93a3` (reemplaza `text-gray-700/800`)
- `--light-accent: #8f6a1e` (ámbar oscuro con contraste ≥4.5:1 sobre blanco)
- `--light-accent-strong: #6d4f12` (hover/estados activos)
- `--light-cyber: #25635f` (teal oscuro)
- `--light-blood: #9b2c24` (rojo oscuro)

Mirror del bloque monochrome: `bg-neon/10/20/5`, `bg-cyber/10/20`,
`bg-blood/10/20`, `text-neon/70/90`, `text-cyber/60/70`, `text-blood/60/70`,
`border-neon/30/40`, `border-cyber/30/40`, `border-blood/30`,
`bg-slate-800/900`, `bg-[#0f172a]`, `bg-[#1e293b]`, `text-sky-400`,
`text-violet-400`, `text-amber-400`, `text-fuchsia-400`, `text-yellow-400`,
`text-red-400`, `text-cyan-400`, `text-emerald-400/500`, `shadow-*`,
`terminal-glow/amber-glow/teal-glow`, `cursor-blink`, `port-badge`,
`service-tag`, `report-card`, `conn-card`, `status-dot`, `hak5-device-btn*`.

Ajustes específicos:
- `body.light body::before` — mantener la franja ámbar pero con ámbar oscuro.
- Scrollbar: track `#e8ebf1`, thumb `#b9c2d1`.
- Terminal: fondo `#ffffff`, texto `#1f2430`, caret ámbar oscuro.

### 2. `frontend/index.html` — inline `<style>` (líneas 48-61)
Añadir overrides `body.light` para los `!important` inline:
```css
body.light .text-neon { color: #8f6a1e !important; }
body.light .bg-neon\/10 { background: rgba(143,106,30,0.10) !important; }
body.light .bg-neon\/20 { background: rgba(143,106,30,0.16) !important; }
body.light .bg-neon\/5 { background: rgba(143,106,30,0.05) !important; }
body.light .border-neon\/30 { border-color: rgba(143,106,30,0.28) !important; }
body.light .status-dot.online { background: #8f6a1e !important; box-shadow: 0 0 8px rgba(143,106,30,0.35) !important; }
body.light .tab-btn.active { color: #8f6a1e !important; border-bottom-color: #8f6a1e !important; }
body.light ::-webkit-scrollbar-thumb { background: #b9c2d1 !important; }
```

### 3. `frontend/js/main.v2.js`
- `window.toggleTheme()` (línea ~5827): pasar a ciclo de 3 estados.
  ```js
  const THEME_STATES = ['neon', 'light', 'mono'];
  function getTheme() { ... leer body classes + localStorage ... }
  window.toggleTheme = function () { const next = ...; setTheme(next); };
  ```
- `setTheme(state)`: quita `monochrome`/`light`, añade la clase del estado,
  guarda `localStorage.vulnforge_theme = state`, actualiza `#theme-icon`:
  - neon → `☾`, light → `☀`, mono → `◇`.
- Carga inicial (línea ~5835): soportar `'light'` además de `'mono'`.
- `buildExifHTML` (línea ~7375): `isDark` debe ser false también con `light`:
  `const isDark = !document.body.classList.contains('monochrome') && !document.body.classList.contains('light');`
- Teclado `theme` (línea 3528) ya llama a `toggleTheme()` — sin cambios.

## Consideraciones

- No tocar la config de Tailwind CDN (neon/cyber/deep/void/blood) — los
  overrides `!important` ya ganan en ambos bloques.
- `body.light .text-neon` (0,1,1) gana a `.text-neon` (0,1,0) en igualdad de
  `!important`.
- El tema claro debe mantener la identidad SIGINT (ámbar sobre blanco).

## Criterios de aceptación

1. `body.light` aplicado → fondo claro, texto legible, acentos ámbar/teal oscuros.
2. Contraste texto normal ≥ 4.5:1, texto secundario ≥ 3:1 (WCAG AA).
3. Ciclo neon → light → mono → neon funcionando; estado persistido en
   `localStorage.vulnforge_theme`; icono correcto.
4. EXIF report usa colores light cuando el tema es light.
5. Sin regresiones en el tema oscuro/monocromo actual.

## Entregables

- `frontend/css/style.css` (bloque `body.light`)
- `frontend/index.html` (inline style light overrides)
- `frontend/js/main.v2.js` (toggle 3 estados + carga + buildExifHTML)
- `framework/light_mode/PLAN.md`
