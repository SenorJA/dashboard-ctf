#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  M.I.R.V. — VPS bootstrap (idempotente, ejecutar UNA vez por VPS)
#
#  Uso desde tu equipo:
#      ssh root@TU_VPS "bash -s" < deploy/bootstrap-vps.sh
#
#  Qué hace:
#    1. Instala Docker (método oficial get.docker.com) si falta
#    2. Instala el plugin docker compose si falta
#    3. Clona https://github.com/SenorJA/dashboard-ctf.git en /opt/mirv
#       (si ya existe → git pull)
#    4. Crea /opt/mirv/.env desde .env.example si NO existe (nunca lo sobreescribe)
#    5. docker compose -p proyectociber up -d --build
#    6. Health check final: curl http://localhost:8000/api/health
#
#  Seguridad: NO contiene secrets. Las credenciales viven en /opt/mirv/.env
#  que se edita manualmente después del primer bootstrap.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_URL="https://github.com/SenorJA/dashboard-ctf.git"
DEPLOY_DIR="${MIRV_DEPLOY_DIR:-/opt/mirv}"
PROJECT="proyectociber"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"
HEALTH_URL="http://localhost:8000/api/health"

say()  { printf '[mirv] %s\n' "$*"; }
warn() { printf '[mirv] [WARN] %s\n' "$*" >&2; }
die()  { printf '[mirv] [ERROR] %s\n' "$*" >&2; exit 1; }

# ── Comprobación de permisos ───────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
  SU=""
else
  if command -v sudo >/dev/null 2>&1; then
    SU="sudo"
    say "No se ejecuta como root — se usará 'sudo' para los pasos privilegiados."
  else
    die "Necesitas permisos root (o sudo disponible) para instalar Docker y arrancar el stack."
  fi
fi

# ── 1. Docker engine ───────────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1; then
  say "Docker ya instalado: $(docker --version)"
else
  say "Docker no encontrado — instalando con el script oficial (get.docker.com)..."
  TMP_DOCKER="$(mktemp)"
  curl -fsSL https://get.docker.com -o "$TMP_DOCKER" || die "No se pudo descargar get.docker.com (¿internet?)."
  $SU sh "$TMP_DOCKER" || die "La instalación de Docker falló. Instálalo manualmente: https://docs.docker.com/engine/install/"
  rm -f "$TMP_DOCKER"
  command -v docker >/dev/null 2>&1 || die "Docker se instaló pero no aparece en el PATH. Reinicia sesión y vuelve a ejecutar."
  say "Docker instalado: $(docker --version)"
fi

# ── 2. Plugin docker compose ───────────────────────────────────────────────
if docker compose version >/dev/null 2>&1; then
  say "Docker Compose ya disponible: $(docker compose version)"
else
  say "Plugin docker compose faltante — instalándolo..."
  $SU mkdir -p /usr/local/lib/docker/cli-plugins
  $SU curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  $SU chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  docker compose version >/dev/null 2>&1 || die "La instalación del plugin compose falló."
  say "Docker Compose instalado: $(docker compose version)"
fi

# ── 3. Clonar / actualizar el repositorio ──────────────────────────────────
if [ -d "$DEPLOY_DIR/.git" ]; then
  say "$DEPLOY_DIR ya existe — haciendo git pull de origin/main..."
  if $SU git -C "$DEPLOY_DIR" pull origin main; then
    say "Repositorio actualizado."
  else
    warn "git pull falló (¿cambios locales no commiteados?). Se continúa con el código existente."
  fi
else
  say "Clonando $REPO_URL en $DEPLOY_DIR..."
  $SU mkdir -p "$(dirname "$DEPLOY_DIR")"
  $SU git clone "$REPO_URL" "$DEPLOY_DIR" || die "El clonado del repositorio falló."
  say "Repositorio clonado."
fi

# ── 4. Fichero .env ────────────────────────────────────────────────────────
ENV_FILE="$DEPLOY_DIR/.env"
if [ -f "$ENV_FILE" ]; then
  say ".env ya existe — no se toca."
else
  say "Creando $ENV_FILE a partir de .env.example..."
  $SU cp "$DEPLOY_DIR/.env.example" "$ENV_FILE"
  warn "════════════════════════════════════════════════════════════════════"
  warn "EDITA $ENV_FILE y pon los valores REALES antes de usar el dashboard:"
  warn "  SUPABASE_URL=https://<tu-proyecto>.supabase.co"
  warn "  SUPABASE_KEY=<anon/public key del dashboard de Supabase>"
  warn "  (Opcional) CF_TUNNEL_TOKEN=<token del túnel Cloudflare>  → Hito B"
  warn "Después, vuelve a ejecutar este script (es idempotente) o:"
  warn "  docker compose -p $PROJECT -f $COMPOSE_FILE up -d --build"
  warn "════════════════════════════════════════════════════════════════════"
fi

# ── 5. Arrancar el stack ───────────────────────────────────────────────────
say "Levantando el stack ($PROJECT)..."
$SU docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

# ── 6. Health check final ──────────────────────────────────────────────────
say "Esperando a $HEALTH_URL ..."
OK=0
for i in $(seq 1 60); do
  if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    OK=1
    break
  fi
  sleep 5
done

if [ "$OK" -eq 1 ]; then
  say "HEALTH CHECK OK — dashboard accesible en http://localhost:8000"
  say "Bootstrap completado."
  exit 0
else
  die "HEALTH CHECK FALLIDO. Revisa: docker compose -p $PROJECT -f $COMPOSE_FILE logs mirv-backend"
fi
