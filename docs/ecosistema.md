# ScopeGate in the Nexgen Ecosystem

> Cross-repo view, synced 2026-08-03 from the live Railway inventory and a
> static analysis of the five ecosystem repos. Only variable and secret-ref
> **names** are ever mentioned — never values.

## 1. Role: the credentials plane

ScopeGate is the **credential boundary of the ecosystem**. The agents that
run on the kimi-tag workers (`@Kimi`, Nexo, auditor, docs-updater) never
possess a secret: they hold short-lived, minimum-scope capabilities minted
by the gateway's policy engine, and secrets are injected only at the
outbound hop toward Huly, Railway, GitHub, Cloudflare and Google.

The production secret flow, end to end:

1. Long-lived secrets live as environment variables of the `worker` service
   in the Railway project `kimi-tag`.
2. `scripts/stage-ecosystem-secrets.mjs` reads them (`railway variable
   list`) and maps them to vault refs — `HULY_BOT_EMAIL/HULY_BOT_PASSWORD/
   HULY_WORKSPACE` (+`HULY_URL`) → blob `huly_nexgen`, `RAILWAY_TOKEN` →
   `railway_token`, `MOONSHOT_API_KEY` → `moonshot_api_key`,
   `GH_WEBHOOK_SECRET` → `gh_webhook_secret`, `GH_APP_PRIVATE_KEY` →
   `github_app_key`, `GH_APP_ID`/`GH_APP_INSTALLATION_ID` → `githubApp`
   config (`stage-ecosystem-secrets.mjs:21,41-72`) — and publishes the
   bundle as `SCOPEGATE_BOOTSTRAP_SECRETS` on the gateway service.
3. `docker/bootstrap-prod.mjs` deposits the bundle into the vault at boot
   (keep-first), wires the five ecosystem upstreams and fixes the
   production identity `agentId: "nexgen-kimi"`
   (`docker/bootstrap-prod.mjs:76,80-137`).
4. From there the minter turns vault secrets into short-lived credentials
   (GitHub App installation tokens, Huly workspace tokens, Google SA access
   tokens) or injects scoped tokens at the outbound hop.

The same bootstrap script also defines the **controlled-risk surface**
(`docker/bootstrap-prod.mjs:152-168`):

| Capability | Rule |
|---|---|
| `railway:call:{deploy,redeploy}` | `require: human_approval` |
| `cloudflare:call:dns_delete` | `require: human_approval` |
| `github:call:{merge_pull_request,create_or_update_file,delete_file}` | `require: human_approval` |
| everything else | `auto_approve`, 15 min TTL (google: 10 min) |

## 2. Relationship matrix

| Repo | Relationship | Evidence (in this repo) |
|---|---|---|
| [NexgenSystemsMX/kimi-tag](https://github.com/NexgenSystemsMX/kimi-tag) | Source of the production secret bundle and of the `nexgen-kimi` agent identity; Kimi Code harness adapter (`scopegate init` migrates `.kimi-code/mcp.json`); governed `inject` of the Moonshot key into `~/.kimi/config.toml`; the ecosystem's production gateways deploy from **that** repo, not this one (§3.2) | `scripts/stage-ecosystem-secrets.mjs:21`; `docker/bootstrap-prod.mjs:76,137`; `src/harness/kimi-code.ts:1-22`; `src/commands/inject.ts:4-6` |
| [NexgenSystemsMX/nexum](https://github.com/NexgenSystemsMX/nexum) | The Huly minter targets the Nexgen instance (`DEFAULT_ACCOUNTS_URL = https://huly2.nexgen.systems`, `login → selectWorkspace`); the huly-bridge (16 tools, `@hcengineering/*` stack) is the agents' surface on the platform; approval alerts post to a chunter channel | `src/minter/providers/huly.ts:35,127-131`; `package.json:71-75`; `src/notify/channels.ts:87-105` |
| [NexgenSystemsMX/nexum-cli](https://github.com/NexgenSystemsMX/nexum-cli) | **No code reference in this repo** (grep-verified, 2026-08-03). The coupling — CLI as a governed stdio upstream, `nexum agent approvals` against the same gateway — lives in nexum-cli's own configuration | repo-wide grep |
| [NexgenSystemsMX/org](https://github.com/NexgenSystemsMX/org) | **No code reference in this repo** (grep-verified, 2026-08-03). `org` is consumed by `worker-nexo`, not by the gateway | repo-wide grep |

Cross-cutting: a single GitHub App (org `NexgenSystemsMX`, one installation
per repo) covers the ecosystem repos — see the commented upstreams
`github-huly-platform`, `github-kimi-tag`, `github-scopegate` in
`scopegate.example.yaml:139-165`; `e2e-ecosystem-prod.mjs:133-137` verifies
the read path against `NexgenSystemsMX/huly-platform` in production.

## 3. Railway deployment map

### 3.1 Project `scopegate` (`a5ba3b9f-9a02-408e-af63-063c451fd964`) — the public product

Two services, both from the image `ghcr.io/luisrosasx/scopegate:latest`
(built by `docker-ghcr.yml` on push to `master`; deploys carry no commit):

| Service | Service ID | Domain(s) | Notes |
|---|---|---|---|
| `scopegate` | `981bc921-fd2d-44e7-8a74-efdf2ee7a45e` | `scopegate-production.up.railway.app` | Gateway instance with `SCOPEGATE_VAULT_MODE=local`, `SCOPEGATE_SEED_DEMO=1` (100% fake demo data), `SCOPEGATE_AGENT_ID=nexgen-kimi`; volume `scopegate-volume` on `/data` |
| `scopegate-cloud` | `b36e582c-1104-4a5b-b46d-19d89519d5e3` | **`scopegate.io`** + `scopegate-cloud-production.up.railway.app` | ScopeGate Cloud (landing `/`, panel `/panel`, API `/v1`); start `node dist/cli.js cloud serve --home /data` (dashboard override — `railway.toml` only describes the gateway); health `/health`; volume `scopegate-cloud-volume` |

### 3.2 Project `kimi-tag` (`f2c3a796-074e-4451-aff1-b80313abc0af`) — the ecosystem's production gateways

**The gateways the workers actually use do not deploy from this repo** —
they run as services of the kimi-tag project (same worker image, scopegate
as a dependency), paired 1:1 with their workers via `SCOPEGATE_URL`
(worker side, `…/mcp`) and `SG_WORKER_DOMAIN` (gateway side):

| Gateway | Domain | Paired worker | Environment |
|---|---|---|---|
| `scopegate-gateway` | `scopegate-gateway-production.up.railway.app` | `worker` (`worker-production-17e8.up.railway.app`) **and** `worker-nexo-prod` (shared) | production |
| `scopegate-gateway1` | `scopegate-gateway1-staging.up.railway.app` | `worker` (`worker-staging-babf.up.railway.app`) | staging |
| `scopegate-gateway-auditor` | `scopegate-gateway-auditor-staging.up.railway.app` | `worker-auditor` (`worker-auditor-staging-c52f.up.railway.app`) | staging |
| `scopegate-gateway-docs-updater` | `scopegate-gw-docs-updater-staging.up.railway.app` | `worker-docs-updater` (`worker-docs-updater-staging.up.railway.app`) | staging |

Agent identities per gateway (`SCOPEGATE_AGENT_ID`): `nexgen-kimi`,
`nexgen-nexo`, `auditor`, `docs-updater`. The production gateway also holds
`SG_RAILWAY_TOKEN`, which is what lets `@Kimi` operate Railway itself
through the railway-bridge.

### 3.3 Domains

- **`scopegate.io` is the only canonical domain** — landing, docs, panel
  and the `curl | sh` installer (`https://scopegate.io/install.sh`).
- `get.scopegate.dev` is **unowned and forbidden**: the production e2e
  fails if the landing links it (`e2e-landing-prod.mjs:61-62`).
- `scopegate.dev` is only the default telemetry endpoint
  (`telemetry.scopegate.dev`) and the security contact mailbox — nothing
  else is served there.

## 4. End-to-end flows

### 4.1 Capability grant

`scopegate_request_capability { capability, reason }` → policy engine
(hard limits fail-closed first: `deny` globs, `max_ttl`, `rate_limit`) →
TTL grant → the upstream call is proxied with the credential injected at
the outbound hop → the action lands in the hash-chained, Ed25519-signed
audit log (inputs hashed, never stored). A denial tells the agent not to
retry with broader scope; `scopegate_propose_policy` is the only way out,
and it never touches live policy.

### 4.2 Human approval — three surfaces

When a rule says `require: human_approval` the tool returns
`pending_human_approval` with an `approval_id`. A human unblocks it from
any of:

1. **CLI** — `scopegate approve <id>` / `deny <id>` on the gateway host
   (TTY, or non-interactive with `SCOPEGATE_APPROVAL_TOKEN`).
2. **Cloud panel** — the Approvals tab at `scopegate.io/panel`; the
   gateway's approval-sync loop (15 s) applies the decision to the local
   queue (`decidedBy: human:cloud:panel`).
3. **Nexum Agents console** — the nexum front calls the worker's
   `/api/admin/sg/approvals`, which proxies the gateway; the same queue is
   operable from nexum-cli (`nexum agent approvals`).

### 4.3 Cloud enroll + the four loops

`scopegate cloud enroll --cloud <url> --token <enrollToken>` writes
`cloud.json` (0600). From then on four background loops run against the
cloud — all fail-soft, so a dead cloud never blocks a tool call
(**local-first**):

| Loop | Interval | What it does |
|---|---|---|
| policy-sync | 60 s | Pulls the signed (Ed25519) team policy, applies it as a restrictive intersection with local policy; last-good cache in `team-policy.json` |
| audit-export | batch | Ships signed audit batches with a checkpointed cursor; at-least-once with server-side dedup; the server re-verifies hash chain + per-event signature and runs the `looksLikeSecret` guard |
| revocation-sync | 15 s | Revokes live grants and persists `cloud-revoked.json`, whose mere presence denies everything (restart-proof); target < 30 s end-to-end |
| approval-sync | 15 s | Applies panel decisions to the local approval queue |

### 4.4 Production e2e proofs

Three scripts exercise the live deployment (they require the production
services and do **not** run in CI):

- `e2e-prod.mjs` — 8 assertions against the gateway (health, auth 401s,
  initialize, listTools, grant, authenticated proxied call, diagnose, deny
  path).
- `e2e-ecosystem-prod.mjs` — real operations on all five ecosystem
  surfaces: Huly (issue create + comment + search), Railway (service and
  domain status of `scopegate` itself), GitHub (read
  `NexgenSystemsMX/huly-platform` with an installation token), Cloudflare
  (zone list) and Google (Drive list).
- `e2e-landing-prod.mjs` — the public contract: landing copy and GitHub
  links (`NexgenSystemsMX/scopegate`, `master` branch), `/panel` reachable,
  admin API auth-gated, `GET /install.sh` on the gateway, npm package
  resolution, and the `get.scopegate.dev` prohibition.

## 5. Ecosystem roadmap

- **QM + A2A native** (design approved 2026-08-03, not started): the kimi-tag worker will speak native A2A v1.0 (JSON-RPC server, signed Agent Card, M2M auth via ScopeGate, push notifications) and adopt QM's governance semantics (scopes, postures, grants, screening, skills). Full set: [`kimi-tag/docs/implementacion/a2a-qm/`](https://github.com/NexgenSystemsMX/kimi-tag/tree/main/docs/implementacion/a2a-qm) — CONTRASTE-PLAN1, PLAN-V2, ROADMAP F0-F5, EPIC-00..11 (PR [#75](https://github.com/NexgenSystemsMX/kimi-tag/pull/75)). This repo owns EPIC-02 (M2M auth), EPIC-04 (card signing) and EPIC-06 (QM keychain grants over capabilities).

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
