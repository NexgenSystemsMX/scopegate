#!/bin/sh
# ScopeGate container entrypoint (POSIX sh).
#
#   1. Optional DEMO seed: when SCOPEGATE_SEED_DEMO=1 and $SCOPEGATE_HOME has
#      no scopegate.yaml yet, seed a fully-fake demo home (idempotent — real
#      config present ⇒ no-op). Everything the seed creates is fake; it never
#      touches real secrets.
#   2. exec the gateway with the image CMD (or whatever args were passed).
set -eu

SCOPEGATE_HOME="${SCOPEGATE_HOME:-/data}"

if [ "${SCOPEGATE_SEED_DEMO:-0}" = "1" ] && [ ! -f "$SCOPEGATE_HOME/scopegate.yaml" ]; then
  echo "[entrypoint] SCOPEGATE_SEED_DEMO=1 and no config at $SCOPEGATE_HOME — seeding demo home" >&2
  node /app/docker/seed-demo.mjs
fi

# Production bootstrap (EPIC-19): deposits staged secrets into the vault and
# wires the real ecosystem upstreams. No-op unless SCOPEGATE_BOOTSTRAP_SECRETS
# is set; idempotent per item (keep-first).
node /app/docker/bootstrap-prod.mjs

exec node dist/cli.js "$@"
