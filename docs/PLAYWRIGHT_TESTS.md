# 🎭 Playwright — Tests de Frontend

Suite de tests E2E para MIRV usando **Playwright** con **pnpm** (no npm).

---

## 📁 Estructura

```
frontend/tests/
├── playwright.config.js   ← Config (baseURL, timeout, reporter)
├── smoke.spec.js          ← 24 tests: smoke, tabs, arsenal, i18n, responsive
```

## 🚀 Ejecutar localmente

### 1. Backend running

```bash
# El backend debe estar corriendo en localhost:8000
docker compose -p proyectociber up -d
curl http://localhost:8000/   # Debe responder 200
```

### 2. Instalar dependencias

```bash
pnpm install
pnpm playwright install chromium
```

### 3. Ejecutar tests

```bash
pnpm test:e2e              # Headless (CLI)
pnpm test:e2e:ui           # UI mode (interactivo)
pnpm test:e2e:debug        # Modo debug
```

### 4. Ver reporte

```bash
pnpm playwright show-report playwright-report/
```

---

## 📋 Tests incluidos

### Smoke Tests (24 tests)

| Categoría | Tests | Lo que verifica |
|-----------|-------|-----------------|
| **Page Load** | 3 | Título "M.I.R.V.", terminal visible, input visible |
| **Tab Switching** | 13 | Cada tab (terminal→aiwriteup) se activa sin errores |
| **Arsenal** | 2 | Sidebar visible + filtro "nmap" funciona |
| **Theme** | 1 | Master toggle agrega/quita clase `monochrome` al body |
| **Connection** | 1 | Modal de conexión se abre |
| **i18n** | 1 | Botón de idioma cambia `window.currentLang` |
| **Responsive** | 2 | 1024px (sidebar visible) + 375px (no crash) |

---

## ⚙️ Config (playwright.config.js)

| Opción | Valor |
|--------|-------|
| `baseURL` | `http://localhost:8000` (o `$BASE_URL`) |
| `timeout` | 30s por test |
| `retries` | 2 en CI, 0 local |
| `workers` | 1 (secuencial) |
| `reporter` | HTML (playwright-report/) + list |
| `trace` | retener en fallo |
| `screenshot` | solo en fallo |
| Proyecto | Chromium Desktop 1920×1080 |

---

## 🤖 CI/CD (GitHub Actions)

El job `test-frontend` en `.github/workflows/ci.yml`:

```yaml
- name: Enable pnpm
  run: corepack enable

- name: Cache pnpm store
  uses: actions/cache@v4
  with:
    path: ~/.local/share/pnpm/store
    key: ${{ runner.os }}-pnpm-${{ hashFiles('pnpm-lock.yaml') }}

- name: Install dependencies (pnpm)
  run: pnpm install --frozen-lockfile

- name: Install Playwright browsers
  run: pnpm playwright install chromium

- name: Run Playwright tests
  run: pnpm playwright test --config=frontend/tests/playwright.config.js
  env:
    BASE_URL: http://localhost:8000
```

Flujo completo:

```
lint → test-backend ─→ test-frontend ─→ docker-build ─→ deploy
       (388 pytest)    (24 Playwright)
```

---

## 📝 Escribir nuevos tests

### Buscar elementos

```javascript
// data-* attributes (recomendado)
page.locator('[data-tab="terminal"]')
page.locator('[data-action="switchLanguage"]')
page.locator('[data-tool="nmap"]')

// IDs
page.locator('#terminal-output')

// Text content
page.locator('button:has-text("Connect")')
```

### Interacciones comunes

```javascript
await page.click('[data-tab="reports"]');
await page.fill('#arsenal-filter', 'nmap');
await expect(page.locator('#terminal-output')).toBeVisible();
```

### Añadir test al smoke suite

1. Abrir `frontend/tests/smoke.spec.js`
2. Añadir dentro del `test.describe('MIRV — Smoke Tests', ...)`
3. Usar `test.beforeEach` ya definido (navega a baseURL)
4. Usar `await page.waitForLoadState('networkidle')` si es necesario

---

## ❌ Troubleshooting

### "No #app element"

El frontend NO tiene un wrapper `#app`. La event delegation usa `document.body`. En tests, localiza elementos por ID directamente.

### Tests pasan local pero fallan en CI

- Asegurar `BASE_URL` apunta al server correcto
- El backend debe estar levantado antes que Playwright
- Los navegadores deben instalarse con `pnpm playwright install chromium`

### pnpm: comando no encontrado

```bash
corepack enable
pnpm --version   # Debe mostrar 11.11.0+
```

### npm / npx detectado

Si usas npm por error, `.npmrc` con `package-manager-strict=true` lo bloquea:
```
Usage Error: This project is configured to use pnpm
```
