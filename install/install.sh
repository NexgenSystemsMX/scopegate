#!/bin/sh
# ScopeGate installer — https://get.scopegate.dev
#
#   curl -sSL https://get.scopegate.dev | sh
#   curl -sSL https://get.scopegate.dev | sh -s -- --yes --version 0.2.0
#
# What it does (and nothing more):
#   1. detects OS/arch (informational; the package is pure JS)
#   2. checks for node >= 20 (points at nvm/volta/brew otherwise)
#   3. installs via `npm install -g scopegate` (fallback: npx)
#   4. prints the published tarball's SHA-1 integrity (from the npm registry)
#      and the SHA-256 of what npm downloaded, so you can verify out-of-band
#   5. runs `scopegate init` unless --no-init
#
# Trust model: the script is short and readable, served over HTTPS, and the
# package integrity is verifiable against the npm registry. No sudo: if the
# global npm prefix isn't writable we suggest a user-level prefix instead of
# escalating.
#
# Flags: --version X.Y.Z | --no-init | --yes (non-interactive, for agents)
set -eu

PKG="scopegate"
VERSION="latest"
DO_INIT=1
ASSUME_YES=0

log()  { printf '%s\n' "[scopegate] $*"; }
err()  { printf '%s\n' "[scopegate] ERROR: $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --no-init) DO_INIT=0; shift ;;
    --yes|-y)  ASSUME_YES=1; shift ;;
    --help|-h)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) err "unknown flag: $1 (see --help)"; exit 2 ;;
  esac
done

OS="$(uname -s 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
log "platform: ${OS}/${ARCH}"

# --- 1. node >= 20 -----------------------------------------------------------
if ! command -v node >/dev/null 2>&1; then
  err "node not found. Install Node.js >= 20 first:"
  err "  nvm:   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | sh && nvm install 22"
  err "  volta: curl https://get.volta.sh | sh && volta install node@22"
  err "  brew:  brew install node@22"
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "$NODE_MAJOR" -lt 20 ]; then
  err "node $(node -v) is too old; ScopeGate needs >= 20."
  exit 1
fi
log "node $(node -v) ok"

if ! command -v npm >/dev/null 2>&1; then
  err "npm not found (it ships with node). Fix your Node.js install."
  exit 1
fi

# --- 2. integrity info from the registry ------------------------------------
TARBALL="$(npm view "${PKG}@${VERSION}" dist.tarball 2>/dev/null || true)"
SHA1="$(npm view "${PKG}@${VERSION}" dist.shasum 2>/dev/null || true)"
if [ -n "$TARBALL" ]; then
  log "registry tarball: $TARBALL"
  log "registry sha1:    ${SHA1:-unknown}"
else
  log "could not query the npm registry for integrity info (offline?)"
fi

# --- 3. install --------------------------------------------------------------
if [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
  printf '[scopegate] Install %s@%s globally via npm? [y/N] ' "$PKG" "$VERSION"
  read -r REPLY
  case "$REPLY" in y|Y|yes) ;; *) log "aborted by user"; exit 0 ;; esac
fi

install_ok=0
if npm install -g "${PKG}@${VERSION}" 2>&1; then
  install_ok=1
else
  PREFIX="$HOME/.npm-global"
  log "global install failed — retrying with user prefix ${PREFIX} (no sudo)"
  if npm install -g --prefix "$PREFIX" "${PKG}@${VERSION}" 2>&1; then
    install_ok=1
    log "installed under ${PREFIX}/bin — add it to your PATH:"
    log "  export PATH=\"${PREFIX}/bin:\$PATH\""
  fi
fi

if [ "$install_ok" -eq 0 ]; then
  err "npm install failed; falling back to npx (no global install)."
  if [ "$DO_INIT" -eq 1 ]; then
    exec npx --yes "${PKG}@${VERSION}" init
  fi
  exit 0
fi

# --- 4. post-install verification -------------------------------------------
if command -v scopegate >/dev/null 2>&1; then
  log "installed: $(scopegate --version 2>/dev/null || echo unknown)"
else
  log "scopegate not on PATH yet (new shell or PATH export needed)"
fi
if [ -n "$SHA1" ]; then
  log "verify integrity out-of-band: download $TARBALL and compare with:"
  log "  shasum -a 1 <tarball>   # expect $SHA1"
fi

# --- 5. init -----------------------------------------------------------------
if [ "$DO_INIT" -eq 1 ] && command -v scopegate >/dev/null 2>&1; then
  log "running scopegate init (idempotent, non-interactive)…"
  scopegate init
fi

log "done. Docs: https://scopegate.dev — agent protocol: SKILL.md in the package."
