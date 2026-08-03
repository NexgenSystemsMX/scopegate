# CLAUDE.md — ScopeGate

Guidance for AI coding agents (Claude Code, Kimi Code, and any MCP harness)
working **in this repository**. If you want to *use* ScopeGate as a
gateway, read [SKILL.md](SKILL.md) and [docs/agents/](docs/agents/README.md)
instead — this file is for developing the gateway itself.

## Purpose

ScopeGate is an **ephemeral-credentials MCP gateway for coding agents**:
the agent never holds secrets, it holds short-lived, minimum-scope
capabilities. AES-256-GCM vault, fail-closed policy engine, token minters
(`jwt`, `github_app`, `aws_sts`, `huly`, `google_sa`), Ed25519-signed audit,
21 `scopegate_*` MCP tools, native bridges (huly/railway/cloudflare/
google), and an optional multi-tenant Cloud control plane. Published as
`scopegate` on npm (Apache-2.0). Architecture: [ARCHITECTURE.md](ARCHITECTURE.md).

## Conventions

- **Default branch: `master`.** Trunk-based flow: short-lived branch from
  `master` → PR → squash merge → delete the branch.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `chore:`,
  `refactor:`). Releases cut from tags `v*` via `release.yml`; SemVer,
  `0.x` during beta (minor = features, patch = fixes).
- **Tests**: vitest (`tests/*.test.ts`). Tests never touch the real
  `~/.scopegate` — use `useTempHome()` from `tests/helpers.ts` and import
  src modules dynamically after calling it (paths resolve at module load).
- **e2e scripts** (`e2e-*.mjs`, run with `node`, self-contained with a
  throwaway `SCOPEGATE_HOME` + ephemeral ports + bridge `*_MOCK=1` modes).
  Three of them **require production** and do not run in CI:
  `e2e-prod.mjs`, `e2e-ecosystem-prod.mjs` (real operations on
  Huly/Railway/GitHub/Cloudflare/Google), `e2e-landing-prod.mjs`.
- **Signed registry is fail-closed**: manifests in `registry/` are
  sha256-pinned in `index.json` and Ed25519-signed in `index.sig`; the
  public key is embedded in `src/registry/verify.ts`. Adding/changing a
  manifest means re-hashing and re-signing — that is a maintainer
  operation, not a drive-by edit.
- **No new runtime dependencies** without opening an issue first.
- Language: code, docs and commit messages in English (public OSS).

## Key commands

```bash
npm install
npm run build              # tsc → dist/ (type-check + emit)
npm test                   # vitest run
node e2e-client.mjs        # e2e: proxy + injection + policy + audit
node redteam/run.mjs       # red-team harness

scopegate init             # idempotent setup (vault, policies, harness migration)
scopegate start            # MCP gateway on stdio (--http for Streamable HTTP)
scopegate audit verify     # seq + hash chain + Ed25519 signatures (exit 1 on tamper)
scopegate status           # config, vault ref names, upstream health
```

CI (`.github/workflows/ci.yml`) runs build + tests + e2e smokes + redteam
and **builds the production Dockerfile as a merge gate** — a Dockerfile
break once shipped broken across three `master` pushes.

## Do NOT touch

- `registry/index.sig` / `index.json` hashes — never edit without rotating
  the signing keys (private key is dev-only, by design).
- **Fail-closed policy semantics** (`deny` globs, `max_ttl`, rate limits in
  `src/policy/`) — no change without human review; they are the product's
  security contract. Same for the frozen `AUDIT_KINDS` taxonomy and the
  frozen 21-tool list in `src/gateway/tools.ts`.
- `LICENSE` (Apache-2.0) — a deliberate choice; the moat is the cloud
  plane, not the proxy.
- Never commit secret values, and never make config/argv/logs/tool
  responses carry them — config only ever holds `secretRef` names.

## Learnings

Operational lessons accumulated while working on this repo live in
[LEARNINGS.md](LEARNINGS.md) — read it before non-trivial work and append
new entries (symptom → root cause → rule) when you learn something the hard
way.
