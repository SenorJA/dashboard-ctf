# 🔐 Configuración de Secrets en GitHub

El pipeline CI/CD (`ci.yml`) necesita 5 secrets para los jobs de **docker-build** y **deploy**. Sin estos secrets, esos jobs se saltan automáticamente (solo corren en `main` cuando los secrets existen).

---

## 1. Docker Hub — `DOCKER_USERNAME` + `DOCKER_TOKEN`

Necesitas una cuenta en [Docker Hub](https://hub.docker.com/) (gratuita).

### Obtener Token de acceso

1. Ir a [hub.docker.com/settings/security](https://hub.docker.com/settings/security)
2. **New Access Token**
3. Nombre: `MIRV-CI`
4. Permisos: **Read & Write** (necesita `docker push`)
5. Copiar el token **inmediatamente** (solo se muestra una vez)

### Añadir a GitHub

```bash
# 1. Ir al repo en GitHub
# 2. Settings → Secrets and variables → Actions
# 3. New repository secret

Nombre: DOCKER_USERNAME
Valor:  (tu usuario de Docker Hub, ej: "tunombre")

Nombre: DOCKER_TOKEN
Valor:  (el token que copiaste de Docker Hub)
```

> ⚠️ Si solo pones `DOCKER_USERNAME`, el job `docker-build` usará ese nombre como imagen.
> Sin `DOCKER_TOKEN`, el `docker login` falla y el build no se pushea.

---

## 2. VPS — `VPS_HOST` + `VPS_USER` + `VPS_SSH_KEY`

### Requisitos del VPS

- Tener Docker + docker-compose instalado
- El proyecto clonado o un `docker-compose.yml` desplegado
- Las imágenes de `proyectociber` ya buildadas o accesibles
- Puerto SSH abierto (por defecto 22)

### Preparar SSH Key

```bash
# En tu máquina LOCAL (no en el VPS)
ssh-keygen -t ed25519 -f ~/.ssh/mirv-deploy-key -N ""
# → genera mirv-deploy-key (privada) y mirv-deploy-key.pub (pública)

# Copiar la clave pública al VPS
ssh-copy-id -i ~/.ssh/mirv-deploy-key.pub usuario@IP_DEL_VPS

# Verificar que funciona
ssh -i ~/.ssh/mirv-deploy-key usuario@IP_DEL_VPS "docker ps"
```

### Añadir a GitHub

```bash
# En GitHub: Settings → Secrets and variables → Actions → New repository secret

Nombre: VPS_HOST
Valor:  IP o dominio del VPS (ej: "123.123.123.123" o "mirv.midominio.com")

Nombre: VPS_USER
Valor:  Usuario SSH (ej: "root" o "ubuntu")

Nombre: VPS_SSH_KEY
Valor:  Contenido COMPLETO de la clave privada (~/.ssh/mirv-deploy-key)
        Incluye las líneas -----BEGIN OPENSSH PRIVATE KEY----- y -----END...
        Copiar textual:

  cat ~/.ssh/mirv-deploy-key | clip   # Windows
  cat ~/.ssh/mirv-deploy-key | pbcopy  # macOS
  cat ~/.ssh/mirv-deploy-key           # Linux (copiar manualmente)

Nombre: VPS_PORT (OPCIONAL)
Valor:  Puerto SSH si no es 22 (ej: "2222")
```

### Script de deploy (lo que ejecuta en el VPS)

El job `deploy` del CI/CD ejecuta en el VPS:

```bash
set -e
docker pull <usuario>/mirv-backend:latest
docker compose -p proyectociber down mirv-backend
docker compose -p proyectociber up -d mirv-backend
```

Si tu VPS necesita pasos adicionales (ej: migraciones de DB, recargar nginx), edita el `script:` en `.github/workflows/ci.yml`.

---

## 3. Tabla resumen

| Secret | Obligatorio | Dónde obtenerlo |
|--------|-------------|-----------------|
| `DOCKER_USERNAME` | Sí (para docker push) | Docker Hub → Account Settings → Username |
| `DOCKER_TOKEN` | Sí (para docker push) | Docker Hub → Security → New Access Token |
| `VPS_HOST` | Sí (para deploy) | IP o dominio del VPS |
| `VPS_USER` | Sí (para deploy) | Usuario SSH del VPS |
| `VPS_SSH_KEY` | Sí (para deploy) | `cat ~/.ssh/mirv-deploy-key` (clave privada ed25519) |
| `VPS_PORT` | No (default 22) | Puerto SSH si personalizado |

---

## 4. Verificar que los secrets están bien

```bash
# Probar manualmente el SSH (desde tu máquina)
ssh -i ~/.ssh/mirv-deploy-key -p 22 usuario@IP_VPS "docker ps"

# Probar que Docker Hub acepta push
echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin
docker push $DOCKER_USERNAME/mirv-backend:test
```

Si ambos comandos funcionan, los secrets están listos. El próximo push a `main` ejecutará el pipeline completo: lint → tests → build → push → deploy.
