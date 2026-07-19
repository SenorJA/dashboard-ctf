# ── M.I.R.V. Backend — Dockerfile ──
FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz -o /tmp/docker.tgz \
    && tar xzf /tmp/docker.tgz -C /usr/local/bin --strip-components=1 docker/docker \
    && rm /tmp/docker.tgz \
    && chmod +x /usr/local/bin/docker \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL "https://github.com/docker/compose/releases/download/v2.32.1/docker-compose-linux-x86_64" -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
    && ln -sf /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

# Copy project (use .dockerignore to control what gets copied)
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY scripts/ /app/scripts/
# .env is excluded by .dockerignore; pass via env vars in compose

# Install Python deps
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
