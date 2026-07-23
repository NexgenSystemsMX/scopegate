# syntax=docker/dockerfile:1
# ScopeGate gateway — production image (Railway / any OCI runtime).
#
#   docker build -t scopegate .
#   docker run -p 8080:8080 \
#     -e SCOPEGATE_HTTP_TOKEN=<long-random-token> \
#     -e SCOPEGATE_SEED_DEMO=1 \
#     -v scopegate-data:/data \
#     scopegate
#
# Multi-stage: stage 1 installs ALL deps and compiles TypeScript; stage 2
# carries only production deps + dist + runtime assets, and runs as the
# non-root `node` user. Persistent state (config, vault, audit) lives in the
# /data volume (SCOPEGATE_HOME).

# ---------------------------------------------------------------------------
# Stage 1 — build
# ---------------------------------------------------------------------------
FROM node:20-slim AS build
WORKDIR /app

# Install the full dependency tree (dev included) from the lockfile.
COPY package.json package-lock.json ./
RUN npm ci

# Compile TypeScript → dist/, then prune dev deps so stage 2 copies a
# production-only node_modules.
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM node:20-slim

ENV NODE_ENV=production \
    SCOPEGATE_HOME=/data

WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# Demo/health fixture used by docker/seed-demo.mjs (and harmless in prod).
COPY fake-upstream.mjs ./
# Bundled signed registry (scopegate_register_upstream from_registry).
COPY registry ./registry
COPY docker ./docker

# Entrypoint must be executable even when the build context lost the bit
# (Windows checkouts). /data belongs to the runtime user.
RUN chmod +x docker/entrypoint.sh \
    && mkdir -p /data \
    && chown -R node:node /data /app

USER node
VOLUME /data
EXPOSE 8080

# No curl/wget in node:*-slim — probe with Node's global fetch instead.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["start", "--http", "--port", "8080", "--host", "0.0.0.0"]
