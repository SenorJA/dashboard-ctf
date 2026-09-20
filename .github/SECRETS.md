# 🔐 GitHub Actions Configuration — Secrets & Variables

## Must install BEFORE enabling CI/CD

### Repository Variables (Settings → Secrets and variables → Actions → Variables tab)

| Name | Example | Purpose |
|------|---------|---------|
| `DOCKERHUB_USERNAME` | `senorja` | Docker Hub account name |

### Repository Secrets (Settings → Secrets and variables → Actions → Secrets tab)

| Name | Example | Where to get it | Purpose |
|------|---------|-----------------|---------|
| `DOCKERHUB_TOKEN` | `dckr_pat_xxxxxxxx` | Docker Hub → Account Settings → Security → New Access Token (read/write) | Push images to Docker Hub |
| `VPS_HOST` | `1.2.3.4` or `mirv.example.com` | Your VPS public IP/domain | Deploy target |
| `VPS_USER` | `root` or `mirv` | SSH user on VPS | SSH login |
| `VPS_SSH_KEY` | `-----BEGIN OPENSSH PRIVATE KEY-----\n...` | `ssh-keygen` on local, copy PRIVATE key here, add PUBLIC key to VPS `~/.ssh/authorized_keys` | SSH auth |
| `VPS_PORT` | optional (default 22) | only if SSH runs on non-standard port | SSH port override |
| `VPS_DEPLOY_PATH` | optional (default `/opt/mirv`) | path where repo is cloned on VPS | git pull target |
| `TAURI_SIGNING_PRIVATE_KEY` | `-----BEGIN MIRV SIGNATURE PRIVATE KEY-----...` | `desktop/.tauri/mirv-updater.key` (see below) | Sign updater artifacts (Desktop .msi) |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | `m1rv-d3skt0p-...` | password chosen when generating the key | Password for the signing key |

## Workflow behavior

- **`ci.yml`**: always runs (push or PR) — installs deps, runs pytest + coverage, bandit security scan
- **`deploy.yml`**: only on push to `main` — Docker build → push to Docker Hub → SSH → pull + `docker compose up -d --build` on VPS
- deploy gracefully SKIPS Docker push step if `DOCKERHUB_USERNAME` var not set
- deploy gracefully SKIPS VPS step if `VPS_HOST` secret not set (so first run just tests locally)

## Current status (20 Sep 2026)

| Secret / Variable | Status |
|-------------------|--------|
| `DOCKERHUB_USERNAME` (variable) | ✅ Configured |
| `DOCKERHUB_TOKEN` (secret) | ✅ Configured |
| `VPS_HOST` (secret) | ⬜ Pending — no VPS provisioned yet |
| `VPS_USER` (secret) | ⬜ Pending |
| `VPS_SSH_KEY` (secret) | ⬜ Pending — key pair already generated (see below) |
| `VPS_PORT` / `VPS_DEPLOY_PATH` | ⬜ Optional — set only if non-default |
| `TAURI_SIGNING_PRIVATE_KEY` (secret) | ⬜ Pending — keypair generated 20 Sep 2026 (see below) |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (secret) | ⬜ Pending — set to the `m1rv-d3skt0p-...` password used to generate the key |

> ⚠️ Until `VPS_HOST` is set, `deploy.yml` runs Docker build + push only and **gracefully skips** the VPS step.

### SSH deploy key pair (already generated, 14 Aug 2026)

- **Private:** `~/.ssh/mirv_deploy` — paste as GitHub secret `VPS_SSH_KEY` (NEVER commit this file)
- **Public:** `~/.ssh/mirv_deploy.pub` — add to VPS `~/.ssh/authorized_keys`

Public key (mirv-deploy-ci):
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMfYY8p9+rQyqhQ18lCL6i9ch413e95i0SMsHqreo7Hc mirv-deploy-ci
```

### Desktop updater signing key (generated 20 Sep 2026)

- **Private:** `desktop/.tauri/mirv-updater.key` — paste content as GitHub secret `TAURI_SIGNING_PRIVATE_KEY` (NEVER commit this file; `.tauri/` is gitignored)
- **Password:** use `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — must match the password chosen at generation time
- **Public (pubkey — SAFE to commit, already in `tauri.conf.json`):**
```
dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDg1N0RFQTZEMjREMDU1MDAKUldRQVZkQWtiZXA5aGFaMC9nSm00aFRJd09sWFdBS3ZsV2RCY05wcGFuNGFlTVlKMkxsZ2x3b0kK
```
- Without these secrets the Desktop Build still compiles and runs, but releases (tags `v*`) produce **unsigned** updater artifacts, which Tauri's updater will reject. Set both secrets before publishing the first `v*` release.
- Regenerate (losing any copy of the private key/password breaks future updates): `npx tauri signer generate --ci -p "PASS" -w desktop/.tauri/mirv-updater.key` and update `pubkey` in `desktop/src-tauri/tauri.conf.json`.

## Required setup steps

### 1. Create Docker Hub access token
1. Sign in to hub.docker.com
2. Account Settings → Security → New Access Token
3. Scopes: Public, Read-only and Read/Write
4. Copy token (never shown again)

### 2. Add secrets/variables to GitHub repo
1. Go to https://github.com/SenorJA/dashboard-ctf/settings/secrets/actions
2. Click "New repository secret" for each of above
3. Switch to "Variables" tab, add `DOCKERHUB_USERNAME`

### 3. Prepare VPS (one-time, manual)
```bash
# On VPS:
mkdir -p /opt/mirv
cd /opt/mirv
git clone https://github.com/SenorJA/dashboard-ctf.git .
cp .env.example .env
# Edit .env with SUPABASE_URL, SUPABASE_KEY, etc.
# Optionally set MIRV_ENC_KEY (a Fernet key, or any passphrase derived via scrypt)
# for deterministic at-rest encryption; otherwise a key is generated once at
# backend/data/enc_secret.key. Keep either safe — losing it makes stored
# secrets unrecoverable by design.
docker compose -p proyectociber up -d --build
```

### 4. Add SSH public key to VPS
```bash
# On your workstation (ALREADY DONE — key pair exists):
# ~/.ssh/mirv_deploy          (private)
# ~/.ssh/mirv_deploy.pub      (public, printed above)

# On VPS, append the PUBLIC key to authorized_keys:
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMfYY8p9+rQyqhQ18lCL6i9ch413e95i0SMsHqreo7Hc mirv-deploy-ci' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# On GitHub, paste the PRIVATE key content as secret VPS_SSH_KEY.
# With gh CLI installed this is: gh secret set VPS_SSH_KEY < ~/.ssh/mirv_deploy
```

### 5. (Alternative) Set the VPS secrets via gh CLI
```bash
# Once a VPS exists and the public key is in authorized_keys:
gh secret set VPS_HOST
gh secret set VPS_USER
gh secret set VPS_SSH_KEY < ~/.ssh/mirv_deploy
# Optional: gh secret set VPS_PORT; gh secret set VPS_DEPLOY_PATH
```
> The `gh` CLI is not installed on the current dev machine, so these must be set
> via the GitHub web UI (Settings → Secrets and variables → Actions → New repository secret).

## Optional Codecov
For coverage tracking, sign up at codecov.io, link the GitHub repo, add `CODECOV_TOKEN` secret (optional — CI uploads without it).