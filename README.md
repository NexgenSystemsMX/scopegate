# ScopeGate

**Ephemeral credentials & persistent MCP connections for coding agents — Claude Code, Kimi Code, Cursor, OpenCode.**

[![npm](https://img.shields.io/npm/v/scopegate)](https://www.npmjs.com/package/scopegate)
[![CI](https://github.com/nexgen/scopegate/actions/workflows/release.yml/badge.svg)](https://github.com/nexgen/scopegate/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

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
curl -sSL https://get.scopegate.dev | sh
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

## Agent tools (MCP)

Exposed by `scopegate start`; the agent self-manages through them.

| Tool | Use when |
|---|---|
| `scopegate_request_capability` | Before privileged actions — returns a TTL grant, or `pending_human_approval` with an `approval_id` when a human must approve |
| `scopegate_list_capabilities` | Active grants and remaining TTL |
| `scopegate_register_upstream` | Connect a new service (never accepts secret values, only `secretRef` names) |
| `scopegate_diagnose` | Any auth/connection error — self-repair with `action_required` hints |
| `scopegate_propose_policy` | A needed capability was denied — lands in `policies.pending.yaml` for human review |
| `scopegate_vault_status` | Which secretRef **names** exist (never values) |

## Configuration

Two files in `~/.scopegate/` (both secret-free; secrets live only in the vault):

- `scopegate.yaml` — upstream registry ([example](scopegate.example.yaml))
- `policies.yaml` — policy engine rules ([example](policies.example.yaml)):
  `limits` (`max_ttl`, `deny` globs, `rate_limit`, `approval_ttl`),
  `auto_approve`, `require: human_approval`, `redact: [pii]`

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
stdio servers), `oauth2` (refresh daemon + device-code re-auth), `jwt`
(gateway-minted HS256), `github_app` (installation tokens minted from the App
key), `aws_sts` (session credentials via AssumeRole/GetSessionToken), `huly`
(workspace token minted via login + selectWorkspace against a Huly account
service — URL discovery through `/config.json`), `google_sa` (Google service
account JWT → access token), `none`.
See [scopegate.example.yaml](scopegate.example.yaml) for commented examples of each.

## Native connectors (bridges in `src/upstreams/`)

Ready-to-run MCP bridges; each runs as a stdio upstream and is also available
in the signed registry (`scopegate_register_upstream {from_registry}`):

| Upstream | Tools | Auth |
|---|---|---|
| `huly` | 13 tools: tracker (create/update/comment/search issues, projects), documents, chunter (channels/messages/threads), contacts | `huly` (vault blob `{email,password,workspace}` → minted workspace token) |
| `railway` | 7 tools: list/status/deploy/redeploy/logs/variables(names only)/domains | `env` (`RAILWAY_TOKEN` account-scoped) |
| `cloudflare` | 8 tools: zones, DNS list/create/update/delete, workers, pages, R2 | `env` (scoped API token) |
| `google` | 7 tools: Drive list/search/read, Gmail send/list, Calendar list/create | `google_sa` (SA JWT → access token) |

Their manifests ship signed in [`registry/`](registry/README.md);
`docs/Implementacion/EPIC-13..18` has the design docs.

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
interface (`src/cloud/server/sso.ts`). Persistence is the dev-grade
`FileStore` behind the `Store` interface — the swap point for Postgres.
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
- [SKILL.md](SKILL.md) — drop-in agent protocol (skills dir or `CLAUDE.md`/`AGENTS.md`)

## Contributing & license

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, tests and e2e.

Licensed under **Apache-2.0** ([LICENSE](LICENSE)). Deliberate choice: the
gateway core is open and permissive because adoption by agents and enterprises
demands zero legal friction — the future commercial moat is the cloud
management plane, not the proxy. Dependency licenses (`@modelcontextprotocol/sdk`,
commander, picomatch, yaml, `@aws-sdk/client-sts`) are all permissive
(MIT/Apache-2.0) and compatible.
