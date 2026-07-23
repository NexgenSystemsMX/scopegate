# Contributing to ScopeGate

Thanks for helping make credentials safe for coding agents. This is a security
product: correctness and the "agent never sees secrets" invariant come before
convenience.

## Dev setup

Requirements: **Node.js ≥ 20** (developed on 22), npm 10. No native modules,
no global services.

```bash
git clone https://github.com/nexgen/scopegate.git
cd scopegate/scopegate
npm install
npm run build        # tsc → dist/
```

## Running the checks

All must be green before a PR:

```bash
npm run build        # type-check + emit
npm test             # vitest unit tests (tests/*.test.ts)

# end-to-end (each is self-contained, uses a throwaway SCOPEGATE_HOME):
node e2e-client.mjs  # gateway proxy + injection + policy + audit
node e2e-init.mjs    # harness detection & migration
node e2e-oauth.mjs   # oauth2 refresh daemon + device-code re-auth
node e2e-vaultd.mjs  # vault as isolated process over IPC

# red team harness (EPIC-11, when present):
node redteam/run.mjs
```

Test conventions:

- **Never touch the real `~/.scopegate`.** Tests get a throwaway home via
  `useTempHome()` from `tests/helpers.ts` (sets `SCOPEGATE_HOME` to a
  mkdtemp dir + `vi.resetModules()`), and import src modules **dynamically
  after** calling it — `src/config/config.ts` resolves paths at module load.
- No fixed ports: e2e scripts bind ephemeral ports and use mkdtemp dirs.
- No new runtime dependencies. Node stdlib + the existing deps
  (`@modelcontextprotocol/sdk`, `commander`, `picomatch`, `yaml`,
  `@aws-sdk/client-sts`) are enough. If you think you need one, open an
  issue first.

## Project layout

```
src/
├── cli.ts                  # entry: init | start | secret | status | audit | auth | vaultd | vault | rollback
├── commands/               # init, secret, oauth-login, vaultd, vault-rotate
├── config/config.ts        # paths + scopegate.yaml loader (NEVER holds secrets)
├── gateway/                # server.ts (MCP + policy enforcement), proxy.ts
│                           # (upstream connections + injection + self-heal), tools.ts
├── harness/                # adapters: claude-code, kimi-code, cursor, opencode, mcp-json
├── vault/                  # AES-256-GCM store, master key backends, vaultd daemon + IPC
├── policy/                 # engine, grants, limits, rate limit, redact, approvals
├── minter/                 # token minter + providers/ (jwt, github-app, aws-sts)
├── oauth/                  # refresh daemon, device-code, scheduler
├── audit/                  # hash-chained JSONL log, Ed25519 signing, verify, index
└── telemetry/              # opt-in anonymous telemetry (fail-silent)
```

## Adding an upstream auth type

1. Extend the `UpstreamAuth` union in `src/config/config.ts` (document the
   vault convention — config only ever holds `secretRef` names).
2. If it mints short-lived tokens, add a provider in
   `src/minter/providers/` and register it in `src/minter/minter.ts`;
   otherwise add the injection path in `src/gateway/proxy.ts`.
3. Add a commented example to `scopegate.example.yaml`.
4. Add tests (`tests/minter.test.ts` style) and, if it changes the outbound
   hop, cover it in `e2e-client.mjs`.

Invariants you may not break: no secret values in config, argv, logs or tool
responses; agent-proposed policy never takes effect without human review;
hard limits (`deny` globs, `max_ttl`) stay fail-closed; every privileged
action is audited.

## Pull requests

- Branch from `main`, keep diffs focused, describe the *why*.
- Conventional-ish commit subjects are appreciated (`fix:`, `feat:`, `docs:`).
- CI runs build + tests + e2e; releases cut from tags `v*` (see
  `.github/workflows/release.yml`). Semver: `0.x` during the beta — minor =
  features, patch = fixes.

## Reporting security issues

**Do not open a public issue for vulnerabilities.** Email
security@scopegate.dev with details and a repro; you will get a triage
response within 72 hours. (A dedicated SECURITY.md with the full policy is
tracked in the roadmap.)

## Code of conduct (short version)

Be respectful and constructive. No harassment, no personal attacks, no
publishing others' private information — doubly so here, where private
information is literally the threat model. Maintainers may remove content and
ban repeat offenders. Report conduct issues to the maintainers via a private
channel, not in public threads.
