#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  M.I.R.V. — Setup Cloudflare Tunnel (mirv)
#
#  Ejecutar en Linux/macOS (el VPS o cualquier host Linux).
#  Automatiza:
#    1. Instalación de cloudflared (descarga oficial amd64/arm64)
#    2. cloudflared tunnel login  (INTERACTIVO — abre el navegador)
#    3. Creación del túnel "mirv" si no existe
#    4. Muestra el CF_TUNNEL_TOKEN para copiar al .env del VPS
#
#  NO automatiza el enrutado DNS (requiere dominio) — imprime las instrucciones.
#  Idempotente: reinstalar/reejecutar no rompe nada.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

TUNNEL_NAME="${CF_TUNNEL_NAME:-mirv}"
BIN_DIR="${CLOUDFLARED_BIN_DIR:-/usr/local/bin}"
DOMAIN_SUFFIX="${CF_DOMAIN_SUFFIX:-mirv.TU-DOMINIO.com}"

say()  { printf '[mirv] %s\n' "$*"; }
warn() { printf '[mirv] [WARN] %s\n' "$*" >&2; }
die()  { printf '[mirv] [ERROR] %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then SU=""; else SU="sudo"; fi

# ── 1. Instalar cloudflared ─────────────────────────────────────────────────
if command -v cloudflared >/dev/null 2>&1; then
  say "cloudflared ya instalado: $(cloudflared --version | head -1)"
else
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) CF_ARCH="amd64" ;;
    aarch64|arm64) CF_ARCH="arm64" ;;
    *) die "Arquitectura no soportada: $ARCH" ;;
  esac

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  if [ "$OS" = "linux" ]; then
    ASSET="cloudflared-linux-${CF_ARCH}"
    say "Descargando $ASSET (Cloudflare GitHub releases)..."
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/$ASSET" -o "$TMP/cloudflared-bin"
  elif [ "$OS" = "darwin" ]; then
    ASSET="cloudflared-darwin-${CF_ARCH}.tgz"
    say "Descargando $ASSET (Cloudflare GitHub releases)..."
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/$ASSET" -o "$TMP/cf.tgz"
    tar -xzf "$TMP/cf.tgz" -C "$TMP"
    mv "$TMP/cloudflared" "$TMP/cloudflared-bin"
  else
    die "SO no soportado: $OS (usa Linux o macOS)"
  fi

  chmod +x "$TMP/cloudflared-bin"
  say "Instalando cloudflared en $BIN_DIR/cloudflared..."
  $SU install -m 0755 "$TMP/cloudflared-bin" "$BIN_DIR/cloudflared"
  if ! command -v cloudflared >/dev/null 2>&1; then
    $SU ln -sf "$BIN_DIR/cloudflared" /usr/local/bin/cloudflared
  fi
  say "Instalado: $(cloudflared --version | head -1)"
fi

# ── 2. Login (INTERACTIVO) ─────────────────────────────────────────────────
if [ -f "$HOME/.cloudflared/cert.pem" ]; then
  say "Ya autenticado (encontrado $HOME/.cloudflared/cert.pem)."
else
  warn "A continuación se abre el navegador — AUTENTÍCATE en tu cuenta Cloudflare"
  warn "y autoriza el acceso (paso interactivo, no se puede automatizar)."
  cloudflared tunnel login
fi

# ── 3. Crear el túnel "mirv" si no existe ──────────────────────────────────
if cloudflared tunnel list 2>/dev/null | grep -qw "$TUNNEL_NAME"; then
  say "El túnel '$TUNNEL_NAME' ya existe — se omite la creación."
else
  say "Creando el túnel '$TUNNEL_NAME'..."
  cloudflared tunnel create "$TUNNEL_NAME"
fi

# ── 4. Mostrar el token del túnel ──────────────────────────────────────────
TOKEN="$(cloudflared tunnel token "$TUNNEL_NAME")"
say "Token del túnel '$TUNNEL_NAME' generado. Cópialo al .env del VPS:"
printf '\n  CF_TUNNEL_TOKEN=%s\n\n' "$TOKEN"
say "Luego, en el VPS:"
say "  docker compose -p proyectociber --profile cloudflared up -d"
say "El dashboard quedará expuesto sin abrir puertos en el firewall."

# ── 5. Enrutado DNS (manual — requiere dominio) ─────────────────────────────
say "El enrutado DNS NO se automatiza: necesitas un dominio añadido a Cloudflare."
say "Cuando tengas el dominio, ejecuta esto para apuntar un subdominio al túnel:"
say "  cloudflared tunnel route dns $TUNNEL_NAME $DOMAIN_SUFFIX"
say "Reemplaza TU-DOMINIO.com por tu dominio real."

say "Setup completado."
