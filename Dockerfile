# AIVault - Docker Deployment
# Multi-stage build for smaller production image
# ⚠️  WARNING: This image contains INTENTIONALLY VULNERABLE code for educational purposes
# DO NOT deploy to production or expose to untrusted networks

FROM node:22-slim AS builder

LABEL org.opencontainers.image.title="AIVault"
LABEL org.opencontainers.image.description="Intentionally vulnerable lab covering OWASP Top 10 - Web, API, Mobile, LLM"
LABEL org.opencontainers.image.source="https://github.com/susheel-cybercode/aivault"
LABEL org.opencontainers.image.documentation="https://github.com/susheel-cybercode/aivault/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY . .

FROM node:22-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV AIVAULT_SAFE_MODE=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 --gid 1001 nodejs

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/src ./src
COPY --from=builder --chown=nodejs:nodejs /app/package.json ./
COPY --from=builder --chown=nodejs:nodejs /app/data ./data
# Harden filesystem: make app read‑only except for data directory (DB, uploads)
RUN chmod -R 555 /app && chmod -R 777 /app/data && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "src/app.js"]