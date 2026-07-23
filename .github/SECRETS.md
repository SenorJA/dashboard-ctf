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

## Workflow behavior

- **`ci.yml`**: always runs (push or PR) — installs deps, runs pytest + coverage, bandit security scan
- **`deploy.yml`**: only on push to `main` — Docker build → push to Docker Hub → SSH → pull + `docker compose up -d --build` on VPS
- deploy gracefully SKIPS Docker push step if `DOCKERHUB_USERNAME` var not set
- deploy gracefully SKIPS VPS step if `VPS_HOST` secret not set (so first run just tests locally)

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
docker compose -p proyectociber up -d --build
```

### 4. Add SSH public key to VPS
```bash
# On your workstation:
ssh-keygen -t ed25519 -f ~/.ssh/mirv_deploy
# Copy ~/.ssh/mirv_deploy.pub content to VPS ~/.ssh/authorized_keys
# Paste ~/.ssh/mirv_deploy (PRIVATE) as GitHub secret VPS_SSH_KEY
```

## Optional Codecov
For coverage tracking, sign up at codecov.io, link the GitHub repo, add `CODECOV_TOKEN` secret (optional — CI uploads without it).