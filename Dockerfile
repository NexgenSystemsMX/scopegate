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

# Sources come in BEFORE `npm ci` on purpose. package.json has a `prepare`
# script (`npm run build`, added so the package can be installed straight from
# git), and npm runs `prepare` as part of `npm ci` — so with sources copied
# afterwards, `npm ci` invoked tsc against an empty /app and the image build
# died at that step. It failed on three consecutive master pushes and nobody
# saw it, because nothing built this image outside master; production kept
# running the last image that happened to succeed. The ci workflow now builds
# it on every branch for exactly this reason.
#
# Cost of the ordering: a source-only edit invalidates the npm ci layer. That
# is the cheaper problem.
COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
RUN npm ci

# `prepare` already compiled during npm ci; build again so the layer does not
# depend on that side effect, then prune dev deps so stage 2 copies a
# production-only node_modules.
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
# The curl|sh installer, served publicly at GET /install.sh.
COPY install ./install
# Cloud control plane assets: the landing site (served at /) and the product
# panel (served at /panel) — read from the source tree at runtime by
# src/cloud/server/index.ts (tsc does not copy non-TS assets).
COPY site ./site
COPY src/cloud/dashboard ./src/cloud/dashboard

# Entrypoint must be executable even when the build context lost the bit
# (Windows checkouts). NOTE: runs as root on purpose — the Railway volume at
# /data was created by earlier root containers (root-owned files, 0600), and
# the bootstrap seeds secrets with vault semantics (0600) anyway.
RUN chmod +x docker/entrypoint.sh && mkdir -p /data

VOLUME /data
EXPOSE 8080

# No curl/wget in node:*-slim — probe with Node's global fetch instead.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["start", "--http", "--port", "8080", "--host", "0.0.0.0"]
