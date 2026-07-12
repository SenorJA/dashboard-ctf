# 🚀 Plan de Producción — M.I.R.V. (Windows)

> Anteriormente VulnForge

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

1. Ir a: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
2. Descargar `cloudflared.exe` para Windows (64-bit)
3. Crear carpeta `C:\cloudflared\` y copiar el `.exe` ahí
4. Verificar:
   ```cmd
   C:\cloudflared\cloudflared.exe version
   ```

---

## Paso 2 — Autenticar cloudflared

```cmd
C:\cloudflared\cloudflared.exe tunnel login
```
Se abrirá el navegador. Inicia sesión en Cloudflare y autoriza el túnel. Se generará un certificado en `C:\Users\TU_USUARIO\.cloudflared\cert.pem`.

---

## Paso 3 — Comprar dominio + configurar Cloudflare

1. Comprar un dominio (ej: `tudominio.com`) en Namecheap o Cloudflare Registrar (3-5€/año)
2. En el panel de Cloudflare → Añadir sitio → introducir el dominio
3. Cloudflare te dará dos nameservers (ej: `dana.ns.cloudflare.com`, `hoyt.ns.cloudflare.com`)
4. En tu registrador de dominio, cambiar los nameservers por los de Cloudflare
5. Esperar propagación (minutos-horas)

---

## Paso 4 — Crear el túnel

```cmd
C:\cloudflared\cloudflared.exe tunnel create mirv
```

Esto devuelve un **ID de túnel** (UUID) y crea un archivo JSON en:
`C:\Users\TU_USUARIO\.cloudflared\<UUID>.json`

Guarda el UUID. Lo necesitas para los siguientes pasos.

---

## Paso 5 — Configurar el túnel

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

```cmd
C:\cloudflared\cloudflared.exe tunnel route dns mirv mirv.TU-DOMINIO.com
```

Cloudflare crea automáticamente un registro CNAME desde `mirv.TU-DOMINIO.com` a tu túnel.

---

## Paso 7 — Probar el túnel

```cmd
C:\cloudflared\cloudflared.exe tunnel run mirv
```

Abre `http://localhost:8000` para verificar que funciona en local.
Abre `https://mirv.TU-DOMINIO.com` para verificar que funciona por el túnel.

**Nota:** El WebSocket usará `wss://` automáticamente cuando la página se cargue por HTTPS.

---

## Paso 8 — Auto-arranque en Windows

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

*Última actualización: Julio 2026 — M.I.R.V. v3.0 — Pendiente: comprar dominio + descargar cloudflared + configurar túnel*