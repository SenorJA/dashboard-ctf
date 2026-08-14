# 🚀 Hito A — Despliegue a VPS (andamiaje)

Guía exacta para llevar M.I.R.V. a un VPS con auto-deploy desde GitHub Actions.

## Visión general

```
[GitHub] push a main ──► buildx + push mirv-backend (Docker Hub)
        │
        └──► appleboy/ssh-action ──► VPS: git pull && docker compose up -d --build
                                          └─► http://TU_VPS:8000  (o vía Cloudflare Tunnel, Hito B)
```

El backend usa **Supabase** (no hay DB local), así que solo hace falta:

1. Un VPS con Docker (lo instala `bootstrap-vps.sh`)
2. El repositorio clonado en `/opt/mirv` (lo hace `bootstrap-vps.sh`)
3. Un `.env` con `SUPABASE_URL` / `SUPABASE_KEY` reales (paso 4)
4. Los secrets `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` en GitHub (paso 5)

---

## Contenido de `deploy/`

| Fichero | Propósito |
|---------|-----------|
| `bootstrap-vps.sh` | Bootstrap idempotente del VPS (instala Docker/Compose, clona el repo, crea `.env`, levanta el stack, health check) |
| `cloudflared/setup-cloudflared.sh` | Setup del túnel Cloudflare (Hito B) |
| `README.md` | Este documento |

---

## Paso 1 — Crear el VPS

- Cualquier VPS con Ubuntu/Debian 22.04+ (1 vCPU / 1-2 GB RAM es suficiente para empezar).
- El stack Kali + backend se construye en el propio VPS (el build de `kali-tools` tarda varios minutos la primera vez).
- Recomendado: 2 vCPU / 4 GB RAM para builds razonables.

## Paso 2 — Autorizar la clave SSH deploy

En el VPS (por ejemplo como `root`):

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMfYY8p9+rQyqhQ18lCL6i9ch413e95i0SMsHqreo7Hc mirv-deploy-ci' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

> La clave pública ya está documentada en `.github/SECRETS.md`. Si tu VPS soporta `ssh-copy-id`, equivale a:
> `ssh-copy-id -i ~/.ssh/mirv_deploy.pub root@TU_VPS`

## Paso 3 — Ejecutar el bootstrap

Desde tu equipo (Windows con Git Bash, WSL o cualquier terminal con `bash`):

```bash
ssh root@TU_VPS "bash -s" < deploy/bootstrap-vps.sh
```

El script (idempotente, seguro re-ejecutar) hará:

1. Instalar Docker (get.docker.com) si falta → plugin `docker compose`
2. Clonar `https://github.com/SenorJA/dashboard-ctf.git` en `/opt/mirv` (o `git pull` si ya existe)
3. Crear `/opt/mirv/.env` desde `.env.example` **solo si no existe**
4. `docker compose -p proyectociber up -d --build`
5. Health check: `curl -sf http://localhost:8000/api/health` → OK/FAIL

> ⚠️ Si no eres `root`, el script usa `sudo`; sin root ni sudo aborta con un mensaje claro.

## Paso 4 — Editar `.env` en el VPS

```bash
ssh root@TU_VPS
nano /opt/mirv/.env
```

Pon los valores reales (los sacas de https://supabase.com/dashboard/project/<tu-proyecto>/settings/api):

```dotenv
SUPABASE_URL=https://<tu-proyecto>.supabase.co
SUPABASE_KEY=<anon/public key>
```

Después reinicia el stack:

```bash
cd /opt/mirv
docker compose -p proyectociber up -d --build
```

> El secret key de Supabase **nunca** se commitea. Vive solo en el `.env` del VPS y en GitHub Secrets si lo usas para CI.

## Paso 5 — Setear secrets en GitHub

Vía web: **Settings → Secrets and variables → Actions → New repository secret**

| Secret | Valor |
|--------|-------|
| `VPS_HOST` | IP o dominio público del VPS |
| `VPS_USER` | `root` (o el usuario SSH del VPS) |
| `VPS_SSH_KEY` | Contenido de `~/.ssh/mirv_deploy` (clave **privada**) |
| `VPS_PORT` | (opcional) puerto SSH, si no es 22 |
| `VPS_DEPLOY_PATH` | (opcional) ruta del repo, por defecto `/opt/mirv` |

Con `gh` CLI:

```bash
gh secret set VPS_HOST
gh secret set VPS_USER
gh secret set VPS_SSH_KEY < ~/.ssh/mirv_deploy
# Opcionales:
gh secret set VPS_PORT
gh secret set VPS_DEPLOY_PATH
```

> 🔐 **NUNCA** commitees la clave privada `~/.ssh/mirv_deploy`. El público va en el VPS; el privado va solo como secret de GitHub. `chmod 600 ~/.ssh/mirv_deploy`.

## Paso 6 — Verificar el auto-deploy

1. El próximo `git push` a `main` dispara `.github/workflows/deploy.yml`.
2. En **Actions** verás: build + push a Docker Hub → paso "Deploy to VPS".
3. Comprueba en el VPS: `docker ps` muestra `mirv-kali-tools` y `mirv-backend` levantados.
4. Abre `http://TU_VPS:8000` → dashboard de M.I.R.V.
5. `docker compose -p proyectociber ps` → ambos servicios `healthy`.

Si `VPS_HOST` aún no está seteado, `deploy.yml` **salta el paso VPS** sin romper el build/push (comportamiento documentado en `.github/SECRETS.md`).

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| Bootstrap falla en "docker not found" | Asegúrate de ser `root` o tener `sudo`; reinicia sesión si `docker` no aparece en PATH |
| Health check FAIL | `docker compose -p proyectociber logs mirv-backend`; revisa `SUPABASE_URL/KEY` en `.env` |
| `git pull` falla en el VPS | `git -C /opt/mirv reset --hard origin/main && git -C /opt/mirv pull` |
| Puerto 8000 ya ocupado | Cambia `MIRV_PORT` en el `.env` del VPS |
| SSH deploy con timeout | Revisa `VPS_HOST` / `VPS_USER` / `VPS_SSH_KEY`; prueba `ssh root@TU_VPS` con `-i ~/.ssh/mirv_deploy` |
| Build lento | La primera vez compila la imagen Kali (varios minutos). Las siguientes usan caché |

---

## Siguiente paso (Hito B)

Con el dashboard accesible en `http://TU_VPS:8000`, exponlo en HTTPS sin abrir puertos con el túnel Cloudflare:

1. `bash deploy/cloudflared/setup-cloudflared.sh` (instala cloudflared, `tunnel login`, crea túnel `mirv`, muestra `CF_TUNNEL_TOKEN`)
2. Añade `CF_TUNNEL_TOKEN=...` al `/opt/mirv/.env` del VPS
3. `docker compose -p proyectociber --profile cloudflared up -d`
4. `cloudflared tunnel route dns mirv mirv.TU-DOMINIO.com` (requiere dominio)

Detalle completo: ver sección "Estado 14 Ago 2026" en `PRODUCTION_PLAN.md`.
