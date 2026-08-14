# 🚀 Plan de Producción — M.I.R.V. (Windows)

## Estado 14 Ago 2026 — Andamiaje VPS/Cloudflare preparado

> **Nuevo andamiaje de despliegue ya incluido en el repo** (no sustituye el flujo Windows de abajo, lo complementa con un stack Docker en VPS):
>
> | Artefacto | Descripción |
> |-----------|-------------|
> | `deploy/bootstrap-vps.sh` | Bootstrap idempotente del VPS: instala Docker + Compose, clona el repo en `/opt/mirv`, crea `.env`, levanta el stack y comprueba `http://localhost:8000/api/health` |
> | `deploy/README.md` | Flujo completo del Hito A (VPS + secrets de GitHub Actions: `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`) |
> | `deploy/cloudflared/setup-cloudflared.sh` | Instala cloudflared, hace `tunnel login`, crea el túnel `mirv` y muestra `CF_TUNNEL_TOKEN` |
> | `docker-compose.yml` | Servicio `cloudflared` opcional bajo el **profile `cloudflared`** — solo arranca con `docker compose --profile cloudflared up -d`; el stack normal (kali-tools + mirv-backend) no se ve afectado |

**Pasos que siguen siendo 100% manuales del usuario:**
1. Comprar el dominio y añadirlo a Cloudflare (Paso 3)
2. `cloudflared tunnel login` — autenticación interactiva en el navegador
3. Copiar `CF_TUNNEL_TOKEN=<token>` al `.env` del VPS
4. `docker compose -p proyectociber --profile cloudflared up -d` en el VPS
5. `cloudflared tunnel route dns mirv mirv.TU-DOMINIO.com` — enrutar DNS (requiere dominio)

Los pasos 1 (descargar cloudflared), 4 (crear túnel), 5 (configurar túnel) y 8 (auto-arranque) quedan **automatizados** por el andamiaje cuando se despliega en el VPS.

---

## Escenario

```
Portátil (cualquier sitio)
  └─ https://mirv.TU-DOMINIO.com
       └─ Cloudflare (SSL + WAF + CDN)
            └─ Cloudflare Tunnel (cloudflared.exe)
                 └─ Windows — localhost:8000 (uvicorn)
                      └─ FastAPI + Dashboard
                           └─ SSH ──> Kali VM (192.168.214.142)
```

**No se abre ningún puerto en el router.** Cloudflare Tunnel crea un túnel saliente directo a Cloudflare. El backend y Kali siguen en la LAN.

---

## Prerrequisitos

| Recurso | Coste | Estado |
|---------|-------|--------|
| Cuenta Cloudflare (gratis) | 0€ | ✅ |
| cloudflared.exe en Windows | 0€ | ❌ Pendiente descarga |
| Túnel creado y autenticado | 0€ | ❌ Pendiente |
| Dominio (Namecheap / Cloudflare Registrar) | 3-5€/año | ❌ Pendiente compra |
| DNS apuntando a Cloudflare | 0€ | ❌ Pendiente config |

> **Nota:** El backend local ya funciona ✅. La app es completamente funcional en localhost:8000. Solo falta comprar el dominio y configurar el túnel Cloudflare para acceso remoto.

---

## Paso 1 — Descargar cloudflared

> ✅ **Automatizado (VPS/Linux/macOS):** `deploy/cloudflared/setup-cloudflared.sh` descarga e instala cloudflared (amd64/arm64) solo. En Windows sigue siendo manual.

1. Ir a: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
2. Descargar `cloudflared.exe` para Windows (64-bit)
3. Crear carpeta `C:\cloudflared\` y copiar el `.exe` ahí
4. Verificar:
   ```cmd
   C:\cloudflared\cloudflared.exe version
   ```

---

## Paso 2 — Autenticar cloudflared

> ⚠️ **Sigue siendo manual e interactivo** (abre el navegador): `cloudflared tunnel login`. El script `deploy/cloudflared/setup-cloudflared.sh` lo invoca automáticamente, pero la autenticación en sí la haces tú.

```cmd
C:\cloudflared\cloudflared.exe tunnel login
```
Se abrirá el navegador. Inicia sesión en Cloudflare y autoriza el túnel. Se generará un certificado en `C:\Users\TU_USUARIO\.cloudflared\cert.pem`.

---

## Paso 3 — Comprar dominio + configurar Cloudflare

> ⚠️ **100% manual** — requiere comprar el dominio y añadirlo a Cloudflare (no automatizable).

1. Comprar un dominio (ej: `tudominio.com`) en Namecheap o Cloudflare Registrar (3-5€/año)
2. En el panel de Cloudflare → Añadir sitio → introducir el dominio
3. Cloudflare te dará dos nameservers (ej: `dana.ns.cloudflare.com`, `hoyt.ns.cloudflare.com`)
4. En tu registrador de dominio, cambiar los nameservers por los de Cloudflare
5. Esperar propagación (minutos-horas)

---

## Paso 4 — Crear el túnel

> ✅ **Automatizado:** `deploy/cloudflared/setup-cloudflared.sh` crea el túnel `mirv` si no existe. En Windows sigue siendo manual (comando de abajo).

```cmd
C:\cloudflared\cloudflared.exe tunnel create mirv
```

Esto devuelve un **ID de túnel** (UUID) y crea un archivo JSON en:
`C:\Users\TU_USUARIO\.cloudflared\<UUID>.json`

Guarda el UUID. Lo necesitas para los siguientes pasos.

---

## Paso 5 — Configurar el túnel

> ✅ **Automatizado (VPS):** el túnel se configura con `CF_TUNNEL_TOKEN` en el `.env` del VPS — no se necesita `config.yml`. El servicio `cloudflared` de `docker-compose.yml` (profile `cloudflared`) lo arranca. El `config.yml` de abajo sigue siendo válido para el flujo Windows.

Editar `C:\Users\TU_USUARIO\.cloudflared\config.yml`:

```yaml
tunnel: mirv
credentials-file: C:\Users\TU_USUARIO\.cloudflared\UUID.json

ingress:
  - hostname: mirv.TU-DOMINIO.com
    service: http://localhost:8000
  - service: http_status:404
```

---

## Paso 6 — Enrutar DNS

> ⚠️ **Manual (requiere dominio):** el script `deploy/cloudflared/setup-cloudflared.sh` imprime el comando exacto, pero no lo ejecuta.

```cmd
C:\cloudflared\cloudflared.exe tunnel route dns mirv mirv.TU-DOMINIO.com
```

Cloudflare crea automáticamente un registro CNAME desde `mirv.TU-DOMINIO.com` a tu túnel.

---

## Paso 7 — Probar el túnel

> ✅ **Automatizado (VPS):** `docker compose -p proyectociber --profile cloudflared up -d` arranca el túnel tras el healthcheck de `mirv-backend`. Para Windows sigue valiendo el comando de abajo.

```cmd
C:\cloudflared\cloudflared.exe tunnel run mirv
```

Abre `http://localhost:8000` para verificar que funciona en local.
Abre `https://mirv.TU-DOMINIO.com` para verificar que funciona por el túnel.

**Nota:** El WebSocket usará `wss://` automáticamente cuando la página se cargue por HTTPS.

---

## Paso 8 — Auto-arranque en Windows

> ✅ **Automatizado (VPS):** el servicio `cloudflared` de `docker-compose.yml` usa `restart: unless-stopped`, así que se auto-reinicia tras reinicios del VPS junto al stack. En Windows sigue valiendo lo de abajo.

### Opción A: Script directo (recomendado)

Usa `scripts/start_production.bat`:

```cmd
scripts\start_production.bat
```

Este script:
1. Inicia uvicorn sin `--reload` en modo producción
2. Inicia cloudflared tunnel
3. Muestra las URLs de acceso
4. Espera a que pulses una tecla para detener todo

### Opción B: Task Scheduler (arranque automático al iniciar sesión)

1. Abrir **Task Scheduler** (taskschd.msc)
2. Crear tarea → "M.I.R.V. Production"
   - **Trigger:** "At log on"
   - **Action:** Start a program → `scripts\start_production.bat`
   - **Run whether user is logged on or not:** Sí
   - **Run with highest privileges:** Sí

Cuando enciendas el PC, el dashboard arrancará solo.

---

## Seguridad adicional (opcional)

### Cloudflare Access (recomendado)

Añade una pantalla de login ANTES del dashboard:

1. Panel Cloudflare → Zero Trust → Access → Applications
2. Crear aplicación → Self-hosted
3. Domain: `mirv.TU-DOMINIO.com`
4. Policy → Email OTP (código de un solo uso al email)
5. Guardar

Ahora, al abrir `https://mirv.TU-DOMINIO.com`, Cloudflare pedirá tu email y te enviará un código antes de dejarte pasar.

### WAF Rules

En Cloudflare → Security → WAF, puedes crear reglas para:
- Bloquear tráfico de ciertos países
- Rate limiting
- Bloquear peticiones sin User-Agent

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| `cloudflared` no se reconoce | Añadir `C:\cloudflared\` al PATH |
| Tunnel falla con "invalid config" | Verificar YAML (espacios, no tabs) |
| No se ve el dashboard por el túnel | Esperar 1-2 min a que DNS propague |
| Error 526 / SSL | Cloudflare → SSL/TLS → Full (strict) |
| Quiero cambiar el dominio | `cloudflared tunnel route dns` de nuevo |
| El túnel se cae solo | Revisar conexión a internet / VPN |
| WebSocket no conecta por HTTPS | Verificar que usa `wss://` (automático) |

---

## Comandos rápidos

```cmd
:: Probar túnel
C:\cloudflared\cloudflared.exe tunnel run mirv

:: Listar túneles
C:\cloudflared\cloudflared.exe tunnel list

:: Eliminar túnel
C:\cloudflared\cloudflared.exe tunnel delete mirv

:: Ver logs
type "backend\logs\mirv.log"
```

---

## 📚 Documentación relacionada

| Documento | Descripción |
|-----------|-------------|
| [`AGENTS.md`](AGENTS.md) | Arquitectura técnica completa (80+ endpoints, 17 tablas, frontend JS) |
| [`PERSISTENCE_AUDIT.md`](PERSISTENCE_AUDIT.md) | Auditoría de persistencia de datos |
| [`ROADMAP.md`](ROADMAP.md) | Roadmap de desarrollo y mejoras |
| [`README.md`](README.md) | Documentación principal del proyecto |

---

## Diagrama final

```
┌──────────────┐     ┌─────────────┐     ┌──────────────────┐     ┌──────────┐
│  Portátil    │────>│ Cloudflare  │────>│  Windows         │────>│ Kali VM  │
│  (navegador) │     │ (SSL+WAF)   │     │  localhost:8000  │     │  SSH:22  │
└──────────────┘     └─────────────┘     │  + cloudflared   │     └──────────┘
                                           │  + uvicorn       │
                                           └──────────────────┘
```

*Última actualización: 14 Ago 2026 — M.I.R.V. v3.0 — Andamiaje VPS + Cloudflare Tunnel listo (hito A + hito B). Pendiente usuario: comprar dominio, `tunnel login`, setear `CF_TUNNEL_TOKEN` y secrets de GitHub `VPS_*`.*