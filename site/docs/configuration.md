# Configuration Reference

Everything lives under `~/.scopegate/` (override with `SCOPEGATE_HOME`).
**No config file ever contains a secret value** — only `secretRef` names that
point into the encrypted vault.

## `scopegate.yaml` — upstream registry

```yaml
version: 1
agentId: agent-luis-nexgen        # default identity for policy + audit
upstreams:
  - name: notion                  # tools exposed as notion__*
    transport: { kind: http, url: "https://mcp.notion.com/mcp" }
    auth: { type: bearer, secretRef: notion_token }
```

Full annotated file: [`scopegate.example.yaml`](../scopegate.example.yaml).

### `transport`

- `{ kind: http, url }` — remote MCP over HTTP
- `{ kind: stdio, command, args?, env? }` — local MCP spawned per session

### `auth` types

| type | shape | what reaches the upstream |
|---|---|---|
| `none` | `{type:"none"}` | nothing |
| `bearer` | `{type:"bearer", secretRef, header?, scheme?}` | header (default `Authorization: Bearer <secret>`) |
| `env` | `{type:"env", env:{ENV_VAR: secretRef}}` | env vars into the spawned stdio server |
| `oauth2` | `{type:"oauth2", secretRef, header?, scheme?, authErrorPattern?}` | access token; refresh handled by the daemon |
| `jwt` | `{type:"jwt", secretRef, ttl?, claims?}` | gateway-minted HS256 token (vault holds the HMAC key) |
| `github_app` | `{type:"github_app", appId, installationId, secretRef, apiUrl?, permissions?, repositories?}` | installation token (~1h), minted from the App PEM |
| `aws_sts` | `{type:"aws_sts", secretRef, roleArn?, region?, durationSeconds?}` | session credentials; `secretRef` is a base name for `<ref>_ACCESS_KEY_ID` / `<ref>_SECRET_ACCESS_KEY` |

Optional per-upstream: `exposeTools: [...]` (allowlist) and `enabled: false`.

## `policies.yaml` — policy engine

Only humans edit this file. Agents propose changes via
`scopegate_propose_policy` → `policies.pending.yaml`.

```yaml
version: 1
limits:                    # global hard ceilings — fail-closed, beat any rule
  max_ttl: 1h              #   no grant ever exceeds this
  deny: ["aws:*:production", "\\*:*"]   # checked before auto_approve
  rate_limit: 30/m         #   capability requests per agent
  approval_ttl: 10m        #   human-approval request expiry
agents:
  agent-luis-nexgen:
    default_ttl: 15m
    limits: { max_ttl: 30m, deny: ["stripe:write:*"] }   # per-agent, wins over global
    capabilities:
      - match: "github:call:{get_*,list_*,search_*}"
        auto_approve: true
      - match: "github:call:*"
        auto_approve: true
        ttl: 5m
      - match: "support:call:get_customer"
        auto_approve: true
        redact: [pii]      # mask PII in upstream responses (best-effort)
      - match: "aws:*:production"
        require: human_approval   # → pending_human_approval + approvals.pending.jsonl
  "*":                     # fallback for unknown agents
    default_ttl: 5m
    capabilities:
      - match: "*:call:{get_*,list_*,search_*,read_*}"
        auto_approve: true
```

Annotated copy: [`policies.example.yaml`](../policies.example.yaml).

## Environment variables

| Variable | Values | Purpose |
|---|---|---|
| `SCOPEGATE_HOME` | path | Base dir instead of `~/.scopegate` |
| `SCOPEGATE_LOG_LEVEL` | `debug` | Stack traces + gateway debug logs |
| `SCOPEGATE_CONNECT_TIMEOUT_MS` | ms (default 10000) | Upstream connect timeout |
| `SCOPEGATE_VAULT_MODE` | `auto` (default) · `local` · `daemon` | Vault access: in-process vs via `vaultd` IPC |
| `SCOPEGATE_VAULT_SOCKET` | path | Override the vaultd socket/pipe path |
| `SCOPEGATE_MASTER_KEY_BACKEND` | `auto` · `file` · `dpapi` · `keychain` · `secret-service` | Master-key storage |
| `SCOPEGATE_AGENT_ID` | string | Agent identity for policy/audit (the harness sets this per entry) |
| `SCOPEGATE_APPROVAL_TOKEN` | string | Non-interactive `approve`/`deny`/`policies accept\|reject` (human-held, out of the agent's reach) |
| `SCOPEGATE_HONEYTOKEN_MODE` | `enforce` (default) · `alert` | Canary response: revoke vs alert-only |
| `SCOPEGATE_TELEMETRY` | `1` | Opt in to anonymous telemetry (default off) |
| `SCOPEGATE_TELEMETRY_ENDPOINT` | URL | Override the telemetry collector |

## Files in `~/.scopegate/`

`scopegate.yaml` · `policies.yaml` · `policies.pending.yaml` (agent proposals)
· `approvals.pending.jsonl` (human-approval queue) · `vault.enc` (AES-256-GCM)
· `master.key` (mode 0600, unless an OS backend is used) · `audit.jsonl` +
`audit-index.json` (derived) · `reauth-required.json` (oauth2 re-auth signal)
· `telemetry.json` (opt-in state).
