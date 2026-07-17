# ── M.I.R.V. Backend — Dockerfile ──
FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

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
