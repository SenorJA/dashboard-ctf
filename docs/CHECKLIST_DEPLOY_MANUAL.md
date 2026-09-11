# ✅ Checklist — Despliegue manual de M.I.R.V. (pasos pendientes de usuario)

> Estado al **11 Sep 2026**: todo el código está implementado, documentado y en GitHub
> (suite interna **4642 passed / 0 fallos**, workflows CI / Deploy / Desktop Build verdes).
> Los únicos pendientes son los pasos **manuales** de producción recogidos aquí.

---

## ✔️ Lo que YA está hecho (no requiere acción)

| Ítem | Estado |
|------|--------|
| Código de la app (FastAPI + frontend + 31 tabs) | ✅ Implementado |
| Docs: AGENTS / CHANGELOG / ROADMAP / TOMORROW | ✅ Actualizados |
| Tests completos (`pytest tests/`, 4642 passed) | ✅ Verde |
| Workflows CI ✅ Deploy ✅ Desktop Build ✅ (último push `68115b8`) | ✅ Verdes |
| Secrets Docker Hub (`DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN`) | ✅ Configurados |
| Clave SSH deploy `~/.ssh/mirv_deploy` (par ed25519) | ✅ Generada |
| Andamiaje VPS (`deploy/bootstrap-vps.sh`) | ✅ Listo |
| Andamiaje Cloudflare (`deploy/cloudflared/setup-cloudflared.sh`) | ✅ Listo |
| Build MSI Desktop (artefacto `mirv-desktop-msi`) | ✅ Generado (37.3 MB) |

---

## ⬜ Tarea 1 — Testear el instalador MSI Desktop (~15 min)

El workflow **Desktop Build** genera un artefacto `mirv-desktop-msi`
(`.msi` de 37.3 MB) en cada push a `main`.

**Pasos:**
1. Abre https://github.com/SenorJA/dashboard-ctf/actions?query=workflow%3A%22Desktop+Build%22
2. Entra en el run más reciente (commit `68115b8`) → sección **Artifacts**
3. Descarga **`mirv-desktop-msi`** y descomprime el `.msi`
4. Instala el MSI en Windows (Windows Defender puede tardar 1–2 min en el primer arranque)
5. Verifica que la app abre el dashboard y que el sidecar `mirv-backend` responde (terminal funcional)

> Si el MSI da error de sidecar, comprueba que `desktop/src-tauri/mirv-desktop.toml` tenga
> `MIRV_BACKEND_PY` apuntando a `../binaries/mirv-backend-x86_64-pc-windows-msvc.exe`.
> El layout de `binaries/` se documentó en `TOMORROW.md` (commit `b072429`).

---

## ⬜ Tarea 2 — Hito A: desplegar a VPS (~1–2 h)

**Referencias:** `deploy/README.md` (guía completa) y `.github/SECRETS.md` (claves).

### 2.1 — Crear el VPS
- Ubuntu/Debian 22.04+, 2 vCPU / 4 GB RAM (el build de Kali tarda varios minutos la 1ª vez).
- Anota la IP pública.

### 2.2 — Autorizar la clave SSH deploy (en el VPS)
```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMfYY8p9+rQyqhQ18lCL6i9ch413e95i0SMsHqreo7Hc mirv-deploy-ci' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### 2.3 — Ejecutar el bootstrap (desde tu equipo, con bash)
```bash
ssh root@TU_VPS "bash -s" < deploy/bootstrap-vps.sh
```
Instala Docker, clona el repo en `/opt/mirv`, crea el `.env`, levanta el stack y hace health check.

### 2.4 — Editar `.env` del VPS
```bash
ssh root@TU_VPS
nano /opt/mirv/.env
```
Pon los valores reales (Supabase → Project Settings → API):
```dotenv
SUPABASE_URL=https://<tu-proyecto>.supabase.co
SUPABASE_KEY=<anon/public key>
# Opcional (recomendado): MIRV_ENC_KEY=<frase o Fernet>  → cifrado determinista en reposo
```
Reinicia: `cd /opt/mirv && docker compose -p proyectociber up -d --build`

### 2.5 — Setear secrets en GitHub (web UI)
**Settings → Secrets and variables → Actions → New repository secret**

| Secret | Valor |
|--------|-------|
| `VPS_HOST` | IP o dominio público del VPS |
| `VPS_USER` | `root` (o usuario SSH del VPS) |
| `VPS_SSH_KEY` | Contenido de `~/.ssh/mirv_deploy` (clave **privada**, nunca se commitea) |
| `VPS_PORT` | (opcional) si SSH no usa 22 |
| `VPS_DEPLOY_PATH` | (opcional) por defecto `/opt/mirv` |

> En la máquina actual **no hay `gh` CLI** → hacerlo por web UI.

### 2.6 — Verificar el auto-deploy
1. El próximo `git push` a `main` ejecuta `deploy.yml` → Docker push + paso "Deploy to VPS".
2. En el VPS: `docker ps` muestra `mirv-kali-tools` y `mirv-backend`.
3. Abre `http://TU_VPS:8000` → dashboard de M.I.R.V.

> Hasta que `VPS_HOST` no esté seteado, `deploy.yml` **salta el paso VPS** sin romper nada.

---

## ⬜ Tarea 3 — Fase 7: exponer en HTTPS con Cloudflare Tunnel (~30 min + dominio)

**Referencia:** `deploy/cloudflared/setup-cloudflared.sh` y `PRODUCTION_PLAN.md` ("Estado 14 Ago 2026").

1. **Comprar / añadir un dominio** a la cuenta Cloudflare (requerido para DNS).
2. Ejecutar el setup (en el VPS o un host Linux):
   ```bash
   bash deploy/cloudflared/setup-cloudflared.sh
   ```
   - Instala `cloudflared`
   - `cloudflared tunnel login` (**interactivo**: abre navegador y autoriza Cloudflare)
   - Crea el túnel `mirv` si no existe
   - Imprime el `CF_TUNNEL_TOKEN`
3. Añadir al `.env` del VPS:
   ```dotenv
   CF_TUNNEL_TOKEN=<token del paso anterior>
   ```
4. Levantar el túnel:
   ```bash
   cd /opt/mirv
   docker compose -p proyectociber --profile cloudflared up -d
   ```
5. Enrutar el subdominio (en cualquier host con cloudflared autenticado):
   ```bash
   cloudflared tunnel route dns mirv mirv.TU-DOMINIO.com
   ```
6. Abrir `https://mirv.TU-DOMINIO.com` → dashboard con HTTPS, sin abrir puertos.

---

## ✅ Estado de verificación final (rellenar cuando esté)

| Tarea | Estado |
|-------|--------|
| 1. MSI Desktop instalado y probado | ⬜ |
| 2. VPS desplegado (`http://TU_VPS:8000`) | ⬜ |
| 3. Cloudflare Tunnel HTTPS activo (`https://mirv.TU-DOMINIO.com`) | ⬜ |

Al terminar: `git status` limpio (si no modificaste nada) y los 3 workflows siguen verdes tras
el último push de validación del deploy.

---

## Referencias
- Despliegue VPS paso a paso: `deploy/README.md`
- Secrets GitHub: `.github/SECRETS.md`
- Plan de producción completo: `PRODUCTION_PLAN.md`
- Historial de trabajo: `TOMORROW.md` (Hito A / Fase 7 / Desktop MSI)