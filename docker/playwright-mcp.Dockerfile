# ── playwright-mcp for M.I.R.V. (F6) ──────────────────────
# Headless Chromium for browser automation / SPA recon
FROM mcr.microsoft.com/playwright:v1.48.2-jammy

USER root
WORKDIR /app

# Install playwright MCP server (if available) or just keep playwright
RUN npm init -y && \
    npm install --no-save @playwright/mcp@0.0.26 2>/dev/null || true

# Expose simple HTTP if needed; MCP can run stdio
ENV NODE_ENV=production
ENV DISPLAY=:99

USER pwuser

CMD ["npx", "-y", "@playwright/mcp", "--headless", "--port", "8931", "--host", "0.0.0.0"]
