# ScopeGate

**Ephemeral credentials & persistent MCP connections for coding agents — Claude Code, Kimi Code, Cursor, OpenCode.**

[![npm](https://img.shields.io/npm/v/scopegate)](https://www.npmjs.com/package/scopegate)
[![CI](https://github.com/NexgenSystemsMX/scopegate/actions/workflows/release.yml/badge.svg)](https://github.com/NexgenSystemsMX/scopegate/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## 🧩 Nexum.Work Ecosystem

This repo is one of the 4 pillars of Nexum.Work (canonical map: [org/ECOSYSTEM.md](https://github.com/NexgenSystemsMX/org/blob/main/ECOSYSTEM.md)).

| Pillar | Repo | What it is |
|---|---|---|
| 🏢 Product | [NexgenSystemsMX/nexum](https://github.com/NexgenSystemsMX/nexum) | The platform — production fork of Huly, 19 services behind the `nexum.work` edge |
| 🤖 Agent | [NexgenSystemsMX/kimi-tag](https://github.com/NexgenSystemsMX/kimi-tag) | The agent workers (@Kimi, Nexo, auditor) — the production ScopeGate gateways are embedded here |
| 🔐 Credentials | [NexgenSystemsMX/scopegate](https://github.com/NexgenSystemsMX/scopegate) | **This repo** — ephemeral-credentials MCP gateway + ScopeGate Cloud |
| ⌨️ CLI | [NexgenSystemsMX/nexum-cli](https://github.com/NexgenSystemsMX/nexum-cli) | Agent-first CLI (129 commands) — spawned by ScopeGate as a minted-env stdio upstream |

📖 Source of truth: [org/ECOSYSTEM.md](https://github.com/NexgenSystemsMX/org/blob/main/ECOSYSTEM.md)

The agent never holds credentials — it holds short-lived, minimum-scope
**capabilities**. Secrets live in an AES-256-GCM encrypted local vault and are
injected only at the outbound hop. A leaked context leaks nothing of durable
value.

```
Agent/CLI ──(MCP, zero secrets)──► ScopeGate ──(creds injected)──► GitHub / AWS / your MCPs
                                      │
                    vault + policy engine + token minter + signed audit
```

**Capability ≠ credential.** What the agent gets expires in minutes and is
scoped to one task; what the vault keeps never enters the model's context.

## Quickstart (agent-executable, non-interactive)

```bash
npm i -g scopegate
scopegate init
```

or via the installer:

```bash
curl -sSL https://scopegate.io/install.sh | sh
```

`init` is idempotent and does everything:

- creates `~/.scopegate/` (encrypted vault, master key, default policies)
- detects harness configs (Claude Code, Kimi Code, Cursor, OpenCode, `.mcp.json`)
- **migrates existing MCPs behind the gateway, moving plaintext secrets
  (env vars, auth headers) into the encrypted vault** and leaving only refs
- rewrites the harness config so `scopegate` is the single MCP entry point
  (backup kept as `*.pre-scopegate.bak`; `scopegate rollback` restores it)

Deposit secrets — human-only path, never through chat, never via argv:

```bash
scopegate secret add github_pat                      # hidden prompt
echo "$TOKEN" | scopegate secret add notion_token    # or piped
```

Then restart the agent session (once — the harness launches the gateway on
startup). From there, the agent operates ScopeGate by itself through the
`scopegate_*` MCP tools (see [SKILL.md](SKILL.md)). **Later** `secret add`
deposits hot-reload: the running gateway drops its connections and re-injects
fresh credentials on the next call — no restart, no context loss.

## CLI

| Command | What it does |
|---|---|
| `scopegate init [--dry-run] [--harness <id>]` | Idempotent setup: vault, policies, harness detection & secret migration |
| `scopegate start` | Run the gateway MCP server on stdio (launched by the harness) |
| `scopegate secret add <ref>` / `ls` / `rm <ref>` | Vault secrets. Value via hidden prompt or piped stdin — never argv |
| `scopegate status` | Config, vault ref names and upstream health |
| `scopegate audit verify` | Verify seq continuity, hash chain and Ed25519 signatures (exit 1 on tamper) |
| `scopegate audit query [--agent --kind --since --until --limit]` | What did an agent/token touch in a window (JSONL) |
| `scopegate audit reindex` | Rebuild the derived `audit-index.json` snapshot |
| `scopegate auth login <upstream>` | OAuth device-code re-authorization (human, out-of-band) |
| `scopegate vaultd [--socket <path>]` | Run the vault as an isolated process (unix socket / Windows named pipe) |
| `scopegate vault rotate-key [--backend file\|dpapi\|keychain\|secret-service]` | Re-encrypt the vault with a fresh master key |
| `scopegate rollback [--harness <id>]` | Restore harness configs from `*.pre-scopegate.bak` |
| `scopegate approve <id> [--ttl <t>]` / `deny <id> --reason <r>` | Human-side approval of escalated capability requests (TTY or `SCOPEGATE_APPROVAL_TOKEN`) |
| `scopegate policies review` / `accept <n>` / `reject <n>` | Human review of agent-proposed policy rules (`policies.pending.yaml`) |
| `scopegate cloud serve [--port <n>] [--home <dir>]` | Run the ScopeGate Cloud control plane (landing at `/`, panel at `/panel`, multi-tenant API at `/v1`) |
| `scopegate cloud enroll --cloud <url> --token <t>` | Enroll this gateway into a control plane (writes `cloud.json`) |
| `scopegate git-credential` | Git credential-helper: `git credential fill` gets a fresh GitHub App installation token, governed by `git:credential:<path>` policies |
| `scopegate inject --ref <r> --out <f> [--template …]` · `--refresh <f>` | Materialize a vault secret into a legacy config file (approval by default, atomic 0600, sha256-only audit) |
| `scopegate honeytoken plant <name>` | Plant a decoy credential (`canary:<name>`) whose use triggers surgical revocation |

## Agent tools (MCP)

Exposed by `scopegate start`; the agent self-manages through them (21 tools).

| Tool | Use when |
|---|---|
| `scopegate_request_capability` | Before privileged actions — returns a TTL grant, or `pending_human_approval` with an `approval_id`; `wait: true` long-polls the decision inline; `execute_on_approval` queues the intended call |
| `scopegate_request_capabilities` | Batch: up to 20 capability requests in one call, per-item outcomes |
| `scopegate_list_capabilities` | Active grants and remaining TTL |
| `scopegate_register_upstream` | Connect a new service (never accepts secret values, only `secretRef` names; also `from_registry` 1-click) |
| `scopegate_diagnose` | Any auth/connection error — self-repair with `action_required` hints |
| `scopegate_propose_policy` | A needed capability was denied — lands in `policies.pending.yaml` for human review |
| `scopegate_vault_status` | Which secretRef **names** exist (never values) |
| `scopegate_collect` / `scopegate_wait` | Collect / long-poll an approval-continuation outcome |
| `scopegate_upstream_health` | Per-upstream liveness, oauth state and circuit-breaker state |
| `scopegate_can_i` / `scopegate_policy_summary` | Read-only policy preflight and session-start digest — plan before acting |
| `scopegate_recall` / `scopegate_events` | Session memory from the signed audit; metadata-only event tail for host UIs |
| `scopegate_open_task_lease` / `scopegate_renew_capability` | Long-task leases (double budget) and agent-driven grant renewal |
| `scopegate_request_plan` | Submit a whole task plan — ONE aggregated approval with the full blast radius |
| `scopegate_result_get` / `scopegate_result_grep` | Page/search oversized results via handles (context window never flooded) |
| `scopegate_delegate` | Attenuated sub-grants for subagents (scope ⊆ parent, dies with the parent) |
| `scopegate_inject_file` | Materialize a vault secret into a file (governed exception; approval by default) |

## Library API (embed the gateway in-process)

```ts
import { createGatewayServer } from "scopegate";

const gw = await createGatewayServer({ agentId: "my-worker" });
// gw.server is the full agent-facing MCP server — connect any transport.
await gw.close();
```

No subprocess, no daemons (opt-in), throws instead of `process.exit`. For
consumer integration tests, `scopegate/testkit` ships a fake upstream and
`bootFakeGateway()` wired to an MCP client over in-memory transport — no real
credentials needed. Experimental in v0.x; strict semver from v1.

## Configuration

Two files in `~/.scopegate/` (both secret-free; secrets live only in the vault):

- `scopegate.yaml` — upstream registry ([example](scopegate.example.yaml)),
  transports `stdio` / `http` / `openapi` (OpenAPI 3 spec → one governed tool
  per operation, no bridge needed)
- `policies.yaml` — policy engine rules ([example](policies.example.yaml)):
  `limits` (`max_ttl`, `deny` globs, `rate_limit`, `approval_ttl`),
  `auto_approve`, `require: human_approval`, `redact: [pii]`,
  `when:` (argument guards — e.g. auto-approve only on `kimi/*` branches)

Auth types per upstream:

```yaml
upstreams:
  - name: notion
    transport: { kind: http, url: "https://mcp.notion.com/mcp" }
    auth: { type: bearer, secretRef: notion_token }

  - name: github
    transport: { kind: stdio, command: npx, args: ["-y", "@modelcontextprotocol/server-github"] }
    auth:
      type: env
      env: { GITHUB_PERSONAL_ACCESS_TOKEN: github_pat }
```

All auth types: `bearer` (header injection), `env` (env vars into spawned
stdio servers), `composite` (several sources fused into one stdio upstream:
static refs + provider mints — multi-service MCPs 100% minted), `oauth2`
(refresh daemon + device-code re-auth), `jwt` (gateway-minted HS256),
`github_app` (installation tokens minted from the App key), `aws_sts` (session
credentials via AssumeRole/GetSessionToken), `huly` (workspace token minted
via login + selectWorkspace against a Huly account service — URL discovery
through `/config.json`), `google_sa` (Google service account JWT → access
token), `none`. Minted credentials on stdio respawn proactively at 80% of
their TTL, and spawned children only inherit a secret-scrubbed env
(`SCOPEGATE_ENV_PASSTHROUGH=1` restores legacy full-inherit).
See [scopegate.example.yaml](scopegate.example.yaml) for commented examples of each.

## Native connectors (bridges in `src/upstreams/`)

Ready-to-run MCP bridges; each runs as a stdio upstream and is also available
in the signed registry (`scopegate_register_upstream {from_registry}`):

| Upstream | Tools | Auth |
|---|---|---|
| `huly` | 16 tools: tracker (create/read/update/comment/search issues incl. comments, milestone/dueDate, assignee filter; projects), documents, chunter (post/edit messages, threads, thinking flag), contacts | `huly` (vault blob `{email,password,workspace}` → minted workspace token) |
| `railway` | 7 tools: list/status/deploy/redeploy/logs/variables(names only)/domains | `env` (`RAILWAY_TOKEN` account-scoped) |
| `cloudflare` | 8 tools: zones, DNS list/create/update/delete, workers, pages, R2 | `env` (scoped API token) |
| `google` | 7 tools: Drive list/search/read, Gmail send/list, Calendar list/create | `google_sa` (SA JWT → access token) |

Plus: `github-official` in the registry (GitHub's own remote MCP with
`github_app` auth — ~1h installation tokens, no PAT), and the `openapi`
transport that turns any OpenAPI 3 spec into a governed upstream.

Their manifests ship signed in [`registry/`](registry/README.md).

Environment variables:

| Variable | Purpose |
|---|---|
| `SCOPEGATE_HOME` | Base dir instead of `~/.scopegate` (tests, portable installs) |
| `SCOPEGATE_LOG_LEVEL` | `debug` for stack traces and gateway debug logs |
| `SCOPEGATE_CONNECT_TIMEOUT_MS` | Upstream connect timeout (default 10000) |
| `SCOPEGATE_VAULT_MODE` | `auto` (default) \| `local` \| `daemon` |
| `SCOPEGATE_VAULT_SOCKET` | Override the vaultd IPC socket/pipe path |
| `SCOPEGATE_MASTER_KEY_BACKEND` | `auto` \| `file` \| `dpapi` \| `keychain` \| `secret-service` |
| `SCOPEGATE_AGENT_ID` | Agent identity for policy/audit (set per harness entry) |
| `SCOPEGATE_APPROVAL_TOKEN` | Lets `approve`/`deny`/`policies accept|reject` run non-interactively (keep it out of the agent's reach) |
| `SCOPEGATE_HONEYTOKEN_MODE` | `enforce` (default) \| `alert` — canary response mode |
| `SCOPEGATE_TELEMETRY` | `1` opts in to anonymous telemetry (default **off**) |
| `SCOPEGATE_TELEMETRY_ENDPOINT` | Override the telemetry collector URL |
| `SCOPEGATE_HTTP_TOKEN` | Bearer token — **required** in `--http` mode |

## Production deployment (Railway)

The gateway also speaks Streamable HTTP: `scopegate start --http --port <n>
--host <h>` (bearer `SCOPEGATE_HTTP_TOKEN` on every request except a public
`GET /health`). This repo deploys as-is to Railway:

- `railway.toml` pins the build (Nixpacks: `npm run build`) and the start
  command (`seed-demo` idempotente + `start --http`), with `/health` as the
  healthcheck. A root `Dockerfile` (multi-stage, non-root) is kept for plain
  Docker builds outside Railway.
- Persistent state lives on a volume mounted at `/data`
  (`SCOPEGATE_HOME=/data`): vault, identity, policies, config.
- With `SCOPEGATE_SEED_DEMO=1` and an empty home, a clearly-marked **demo**
  seed provisions a fake upstream + fake secret so the deployment is
  self-contained (zero real credentials).
- Live proof: `SCOPEGATE_PROD_URL=<url> SCOPEGATE_HTTP_TOKEN=<token> node
  e2e-prod.mjs` runs the production e2e (8 assertions: health, auth 401s,
  initialize, listTools, grant, authenticated proxied call, diagnose, deny
  path).

## ScopeGate Cloud (management plane)

`scopegate cloud serve` runs the optional multi-tenant control plane —
metadata-only by design (no secret values ever cross it), and the gateway
keeps enforcing its local policy + last signed team policy when the cloud is
down (**local-first**). One process serves three things:

- `GET /` — the public **landing page** (`site/`)
- `GET /panel` — the **product panel** (vanilla SPA, no build step): Overview
  (fleet health, security events), Fleet (revocation with explicit
  blast-radius confirmation, including team-wide), Approvals (the human queue:
  approve/deny from the browser and the gateway applies it in seconds via the
  approval-sync loop — no terminal needed), Capabilities (live grants with
  TTLs), Audit (query + signed JSONL export), Policy (signed, versioned, with
  line diff), Billing (active-agent metering), Settings (enroll snippets,
  Slack alerts).
- `/v1/*` — the management API: enroll, signed policy distribution, audit
  ingest (hash-chain + per-event Ed25519 verified, `looksLikeSecret` guard),
  revocation feed, approval decisions feed, billing usage, admin
  overview/queue/export endpoints. `GET /health` is a public probe.

Gateway side: `scopegate cloud enroll --cloud <url> --token <enrollToken>`
links a gateway to a team; from there four background loops run — policy-sync
(signed, restrictive intersection), audit-export, revocation-sync and
approval-sync (all fail-soft: a dead cloud never blocks a tool call).

Access today: the panel authenticates with the control plane's admin token
(env `ADMIN_TOKEN`) — dev-grade by design; SSO with per-team roles
(owner/approver/viewer) plugs into the same API via the `SsoAdapter`
interface (`src/cloud/server/sso.ts`). Persistence: the `FileStore` (default)
or `PostgresStore` when `SCOPEGATE_CLOUD_DATABASE_URL` is set — both behind
the `Store` interface, with configurable audit retention
(`SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS`).
Verify the whole plane: `node e2e-cloud.mjs` (enroll → sync → central audit →
panel approval loop → fleet revocation → local-first) and `node
e2e-landing.mjs` (static routing contract).

## Security model (summary)

1. Secrets never enter the model's context (CLI/stdin only, encrypted at rest).
2. Capability ≠ credential: grants expire in minutes, scoped per task.
3. Write asymmetry: agents propose policy, humans approve
   (`policies.pending.yaml` → human review).
4. `looksLikeSecret()` guard rejects raw secrets smuggled as refs by agents.
5. Hard limits are fail-closed: `deny` globs and `max_ttl` beat any rule.
6. Every action lands in `audit.jsonl` — append-only, hash-chained, signed
   Ed25519; inputs are hashed, never stored. Verify with `scopegate audit verify`.

Full detail: [docs-site/security-model.md](docs-site/security-model.md).

## Telemetry (opt-in, anonymous)

ScopeGate collects **nothing** by default. If you explicitly opt in
(`SCOPEGATE_TELEMETRY=1` or `{"enabled": true}` in `~/.scopegate/telemetry.json`),
it sends a minimal anonymous event on install, init completion and first tool
call: version, OS/arch, Node version, detected harness ids, a random anonymous
install id. **Never** agentId, paths, upstream names, tool args, inputs, or
anything derived from your config. Fail-silent by design — telemetry can never
break a run. Endpoint: `https://telemetry.scopegate.dev/v1/event`
(override with `SCOPEGATE_TELEMETRY_ENDPOINT` for self-hosting). The full
payload contract lives in [src/telemetry/telemetry.ts](src/telemetry/telemetry.ts).

## Documentation

- [docs-site/quickstart.md](docs-site/quickstart.md) — agent-executable quickstart
- [docs-site/security-model.md](docs-site/security-model.md) — enforcement model
- [docs-site/agent-protocol.md](docs-site/agent-protocol.md) — the SKILL protocol
- [docs-site/cli-reference.md](docs-site/cli-reference.md) — every command
- [docs-site/configuration.md](docs-site/configuration.md) — config reference
- [docs/ecosistema.md](docs/ecosistema.md) — ScopeGate in the Nexgen ecosystem (Railway map, e2e flows)
- [SKILL.md](SKILL.md) — drop-in agent protocol (skills dir or `CLAUDE.md`/`AGENTS.md`)

## Contributing & license

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, tests and e2e.

Licensed under **Apache-2.0** ([LICENSE](LICENSE)). Deliberate choice: the
gateway core is open and permissive because adoption by agents and enterprises
demands zero legal friction — the future commercial moat is the cloud
management plane, not the proxy. Dependency licenses (`@modelcontextprotocol/sdk`,
commander, picomatch, yaml, `@aws-sdk/client-sts`) are all permissive
(MIT/Apache-2.0) and compatible.
