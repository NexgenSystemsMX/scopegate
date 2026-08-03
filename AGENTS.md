# AGENTS.md — ScopeGate repo guide for coding agents

ScopeGate is an **ephemeral-credentials gateway** for coding agents
(Claude Code, Kimi Code, Cursor, OpenCode, or any MCP harness). The agent
never holds secrets — it holds short-lived, minimum-scope **capabilities**
minted by a policy engine. Secrets live in an AES-256-GCM encrypted vault
and are injected only at the outbound hop.

## If you want to USE ScopeGate

Do not read the source. The complete, agent-executable usage documentation
lives in **[docs/agents/README.md](docs/agents/README.md)** — eight guides
covering self-install, the operating protocol, the MCP tools reference,
connectors, policies, self-repair, security rules, and long tasks. Start at
guide 01 and follow it literally.

A drop-in protocol summary also ships as [SKILL.md](SKILL.md) (usable as a
skills-dir entry or a `CLAUDE.md` / `AGENTS.md` fragment).

## If you are DEVELOPING ScopeGate

Requirements: Node.js ≥ 20, npm 10. No native modules, no global services.

Repository: `NexgenSystemsMX/scopegate`, default branch `master`.

Surface facts (verified 2026-08): the agent-facing MCP server exposes 21
`scopegate_*` tools (frozen list in `src/gateway/tools.ts`); the bundled
bridges expose huly 16 / railway 7 / cloudflare 8 / google 7 tools.

### Deployment (Railway)

The public product deploys from the image `ghcr.io/luisrosasx/scopegate`
(built by `docker-ghcr.yml` on push to `master`) into the Railway project
`scopegate`: service `scopegate` (gateway with `SCOPEGATE_SEED_DEMO=1` —
100% fake demo data) and `scopegate-cloud` (ScopeGate Cloud: landing, panel
and `/v1` API) at [scopegate.io](https://scopegate.io). The Nexgen
ecosystem's production gateways do **not** deploy from this repo — they run
as services of the Railway project `kimi-tag`. Full map:
[docs/ecosistema.md](docs/ecosistema.md).

### Layout (`src/`)

```
cli.ts          # entry: init | start | secret | status | audit | auth | vaultd | vault |
                #        rollback | approve | deny | policies | cloud | git-credential |
                #        inject | honeytoken
api.ts          # M7: embeddable library API (createGatewayServer) — dist/api.js + types
testkit/        # M7: scopegate/testkit — fake upstream + bootFakeGateway (consumer tests)
commands/       # init, secret, oauth-login, vaultd, vault-rotate, approvals/policies CLI,
                # git-credential, inject
config/         # paths + scopegate.yaml loader (NEVER holds secrets)
gateway/        # MCP server, policy enforcement, upstream proxy + injection + self-heal,
                # scopegate_* tools (transports: stdio, http, openapi)
harness/        # adapters: claude-code, kimi-code, cursor, opencode, mcp-json
vault/          # AES-256-GCM store, master-key backends, vaultd daemon + IPC
policy/         # engine (when: arg guards, vault:inject default escalation), grants,
                # limits, rate limit, redact, approvals
inject/         # M10: governed secret materialization into files (atomic 0600 + sidecar)
minter/         # token minter + providers/ (jwt, github-app, aws-sts, huly, google-sa)
oauth/          # refresh daemon, device-code
audit/          # hash-chained JSONL, Ed25519 signing, verify, index
upstreams/      # native connectors: huly, railway, cloudflare, google + openapi importer
cloud/          # optional multi-tenant control plane (metadata-only; FileStore|PostgresStore)
attestation/ honeytoken/ notify/ registry/ telemetry/
```

### Commands

```bash
npm install
npm run build       # tsc → dist/ (type-check + emit)
npm test            # vitest unit tests (tests/*.test.ts)

# e2e — each is self-contained: throwaway SCOPEGATE_HOME, ephemeral ports
node e2e-client.mjs   # proxy + injection + policy + audit
node e2e-init.mjs     # harness detection & migration
node e2e-oauth.mjs    # oauth2 refresh daemon + device-code re-auth
node e2e-vaultd.mjs   # vault as isolated process over IPC
node e2e-http.mjs     # Streamable HTTP transport
node e2e-cloud.mjs    # control plane end-to-end
node redteam/run.mjs  # red-team harness
```

All must be green before a PR. CI (`.github/workflows/ci.yml`) additionally
builds the production Dockerfile and smoke-runs the image as a merge gate —
a Dockerfile break once stayed broken across three `master` pushes (see the
comments in `ci.yml`). The three production e2e scripts (`e2e-prod.mjs`,
`e2e-ecosystem-prod.mjs`, `e2e-landing-prod.mjs`) do NOT run in CI: they
require the live Railway services.

### Contribution rules (short)

- **No new runtime dependencies** without opening an issue first. Node
  stdlib plus the existing deps are enough.
- **Tests never touch the real `~/.scopegate`** — use `useTempHome()` from
  `tests/helpers.ts` (mkdtemp `SCOPEGATE_HOME` + `vi.resetModules()`) and
  import src modules dynamically after calling it.
- **No secrets in the repo** — no secret values in config, argv, logs,
  tests, fixtures, or tool responses. Config only ever holds `secretRef`
  names.
- Invariants you may not break: agent-proposed policy never takes effect
  without human review; hard limits (`deny` globs, `max_ttl`) stay
  fail-closed; every privileged action is audited.
- Branch from `master`, keep diffs focused; `fix:` / `feat:` / `docs:`
  subjects appreciated.
- Security issues: email security@scopegate.dev — never a public issue.

Full details: [CONTRIBUTING.md](CONTRIBUTING.md).

<!-- ECOSISTEMA-SYNC:2026-08-03 — English rendering of the common block synced across all 5 ecosystem repos (nexum, kimi-tag, scopegate, nexum-cli, org). The canonical Spanish version carries the same marker; edit both together. Source: Railway inventory + analysis of the 5 repos (2026-08-03). -->

## Nexgen Ecosystem

This repo is part of an ecosystem of **4 systems + 1 configuration repo** under the `NexgenSystemsMX` org:

| Repo | System | What it is | Deployment |
|---|---|---|---|
| [NexgenSystemsMX/nexum](https://github.com/NexgenSystemsMX/nexum) | **Platform** | Fork of the Huly Platform (Rush monorepo, EPL-2.0) — the codebase of [nexum.work](https://nexum.work) | Railway project `nexum.work`: 19 services in production (front, transactor, account, workspace, collaborator, stats, elastic, fulltext, cockroach, MongoDB, minio, redpanda, mail, aibot, love, rekoni, nginx + 2 backups). Single nginx edge: `nexum.work`, `www.nexum.work`, `huly2.nexgen.systems` (dev: `dev.nexum.work`). Branches: `develop`→dev, `main` (protected)→prod |
| [NexgenSystemsMX/kimi-tag](https://github.com/NexgenSystemsMX/kimi-tag) | **Agents** | Multi-role worker: `@Kimi` agent (Kimi Code engine, per-thread session), **Nexo** router, auditor and ScopeGate gateway — one Docker image; role set by `RUN_MODE`/`SERVICE_ROLE`/`AGENT_PROFILE` | Railway project `kimi-tag` — prod: `worker`, `worker-nexo-prod`, `scopegate-gateway`, Redis, Postgres; staging: `worker`, `worker-nexo`, `worker-auditor`, `worker-docs-updater`, `scopegate-gateway1/-auditor/-docs-updater` |
| [NexgenSystemsMX/scopegate](https://github.com/NexgenSystemsMX/scopegate) | **Credentials** | Ephemeral-credentials MCP gateway: AES-256-GCM vault, TTL capabilities, policy engine, Ed25519-signed audit + **ScopeGate Cloud** (multi-tenant control plane) | Railway project `scopegate`: `scopegate` (demo seed, image `ghcr.io/luisrosasx/scopegate`) and `scopegate-cloud` ([scopegate.io](https://scopegate.io)). **The ecosystem's production gateways** run as services of the kimi-tag project (same worker image; scopegate as npm dependency) |
| [NexgenSystemsMX/nexum-cli](https://github.com/NexgenSystemsMX/nexum-cli) | **CLI** | Agent-first CLI v1.1.0: 129 commands in 20 groups, stable JSON envelope, exit codes 0-8, idempotency, MCP server (`mcp-serve`) | No deploy (npm/local). ScopeGate spawns it as a stdio upstream in minted-env mode |
| [NexgenSystemsMX/org](https://github.com/NexgenSystemsMX/org) | **Org config** | Org chart as code: `people/`, `agents/`, `areas/`, `skills.yaml`, `productos.yaml` — source of truth for Nexo routing | No deploy. Synced by `worker-nexo` (`/gh-webhook` webhook + ≤5 min poll); its CI dry-runs PRs against the worker's `/org/sync?dry-run=true` |

### How they relate

- **nexum front → kimi-tag workers**: `KIMI_TAG_URL` and `AGENT_WORKER_URLS` are published in `config.json`; the front consumes `/api/sessions`, the `/api/run/*` widget, Nexo cards `/api/action/*` and the Agents console `/api/admin/*`.
- **kimi-tag workers → platform**: `HULY_URL` (WebSocket to the transactor + REST) with their own bot identities; staging may point at `dev.nexum.work`.
- **@Kimi worker → ScopeGate gateway**: `MCP_MODE=scopegate`, `SCOPEGATE_URL/mcp` (bearer + `X-ScopeGate-Agent`); human approvals via `/sg-events` webhook and the `git-credential` shim; 1:1 worker↔gateway pairs (`SG_WORKER_DOMAIN`).
- **Agents console (nexum) → gateway** via worker: `/api/admin/sg/{policies,secrets,approvals,capabilities}`; the same approvals are operated from nexum-cli (`nexum agent approvals`).
- **worker-nexo → org**: `ORG_REPO=NexgenSystemsMX/org`, routing in `propose` mode; org's CI dry-runs the snapshot against the worker on every PR.
- **nexum-cli → platform and workers**: workspace-scoped token login, discovery via `config.json` (`KIMI_TAG_URL`/`AGENT_WORKER_URLS`), real health probe (stop on a nonexistent run ⇒ 404 = healthy); the `kimi`/`nexo-duda` toolsets are a contract with kimi-tag's agent briefs.
- **scopegate (repo)**: library/CLI consumed by the agents; the repo has no code references to Nexo, nexum-cli or org — that coupling lives in configuration in the other repos.

_Last ecosystem sync: 2026-08-03. Full detail: `docs/ecosistema.md` in this repo._
