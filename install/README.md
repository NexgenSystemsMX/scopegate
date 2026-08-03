# ScopeGate installer (`curl | sh`)

`install.sh` is served at `https://scopegate.io/install.sh` (canonical):

```bash
curl -sSL https://scopegate.io/install.sh | sh                    # interactive
curl -sSL https://scopegate.io/install.sh | sh -s -- --yes        # non-interactive (agents, CI)
curl -sSL https://scopegate.io/install.sh | sh -s -- --version 0.2.0 --no-init
```

Domain note: **`scopegate.io` is the only canonical domain** (landing, docs
and this installer). `get.scopegate.dev` is unowned and must never be
linked — the production e2e (`e2e-landing-prod.mjs`) fails if it appears.
`scopegate.dev` is only the default telemetry endpoint
(`telemetry.scopegate.dev`), nothing else.

## What the script does

1. Detects OS/arch (informational — the package is pure JavaScript).
2. Requires **node ≥ 20**; if missing, prints per-platform install hints
   (nvm / volta / brew) and exits non-zero.
3. Installs with `npm install -g scopegate`. If the global prefix isn't
   writable it retries with a user-level prefix (`~/.npm-global`) — **never
   sudo**. Last-resort fallback: `npx scopegate init`.
4. Prints the package integrity from the npm registry
   (`npm view scopegate dist.tarball` + `dist.shasum`) so you can verify the
   artifact out-of-band.
5. Runs `scopegate init` (idempotent) unless `--no-init`.

Flags: `--version X.Y.Z` · `--no-init` · `--yes` (skip the confirmation
prompt; implied when stdin is not a TTY). Exit code is non-zero on any hard
failure.

## Trust model (why curl|sh is acceptable here)

- **Readable**: the script is ~120 lines of POSIX sh, no obfuscation, no
  eval, no base64. Read it before piping: `curl -sSL https://scopegate.io/install.sh -o install.sh && less install.sh`.
- **HTTPS-only**, served as `text/plain` with a short cache.
- **Verifiable**: the actual code is delivered by npm, not by the script.
  The script prints the registry SHA-1; verify with
  `shasum -a 1 <tarball>` after downloading the printed tarball URL.
- **No privilege escalation**: user-level npm prefix fallback instead of sudo.
- **Alternatives**: you never *need* the script —
  `npm install -g scopegate && scopegate init` is equivalent and always
  supported, as is `npx scopegate@latest init`.

## Self-hosting

Serve this file statically anywhere (any static host or
`npx serve install/`) and point users at your URL. The script has no
dependency on the serving domain.
