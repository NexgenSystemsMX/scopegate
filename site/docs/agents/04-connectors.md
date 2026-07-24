# 04 — Connectors: native upstreams and how to add new ones

A **connector** (upstream) is an MCP server or API behind the gateway. You never touch its credentials — the gateway injects or mints them at the outbound hop. Every upstream tool is exposed to you as `<upstream>__<tool>`, and every call requires the capability `<upstream>:call:<tool>` granted by policy (see `./03-tools-reference.md`).

ScopeGate ships 5 native connectors, installable in one call each from the signed registry (`registry/*.yaml` — verified fail-closed: signed index + per-manifest sha256 + stdio command allowlist):

| Connector | Tools | Auth type | Credential mode |
|---|---|---|---|
| `huly` | 16 | `huly` (vault blob → workspace token) | `minted:huly` |
| `github` | upstream pkg | `env` (PAT) or `github_app` (~1h installation token) | `fallback:injection` / `minted:github_app` |
| `railway` | 7 | `env` (API token) | `fallback:injection` |
| `cloudflare` | 8 | `env` (scoped API token) | `fallback:injection` |
| `google` | 7 | `google_sa` (SA key → ~1h access token) | `minted:google_sa` |

**Golden rule.** You register and operate connectors. The human does exactly two things, in THEIR terminal, never in chat: deposit secrets (`scopegate secret add <ref>`) and approve escalations (`scopegate approve <id>` / `scopegate policies accept <n>`). NEVER ask the user to paste a secret value into the conversation.

## 1. huly — tracker, documents, chunter, contacts

Bundled bridge (stdio) covering the four Huly surfaces: tracker (issues/projects), documents, chunter (channels/messages), contact (persons). Markdown in and out.

**Tools (16, exposed as `huly__<name>`).** Status names: `backlog|todo|in_progress|done|canceled`; priority: `urgent|high|medium|low|none` or `0-4`. `project` accepts the identifier (`DEMO`) or an id; `issueId` accepts `DEMO-1` or an id.

- tracker: `tracker_create_issue {project, title, description?, priority?, assignee?, status?}`, `tracker_read_issue {issueId}` (with the full description), `tracker_read_comments {issueId, limit?}`, `tracker_update_issue {issueId, fields}` (fields now include `milestone` and `dueDate`; `""` clears them), `tracker_comment_issue {issueId, message}`, `tracker_search_issues {query?, project?, status?, assignee?, limit?}`, `tracker_list_projects {}`
- documents: `documents_create {teamspace, title, content}`, `documents_read {documentId}`, `documents_update {documentId, content}`, `documents_list {teamspace?, limit?}`
- chunter: `chunter_post_message {channel, message, thread?, thinking?}` (`thinking: true` renders the message as 💭 thinking), `chunter_edit_message {channel, messageId, content}` (update the bot's own checklist), `chunter_list_channels {}`, `chunter_list_messages {channel, limit?, thread?}`
- contact: `contact_list_persons {limit?}`

**Auth.** Type `huly`, `secretRef: huly_nexgen`. The human deposits a JSON blob (never echoed):

```sh
scopegate secret add huly_nexgen   # value: {"email":"you@nexgen","password":"…","workspace":"your-workspace","accountsUrl":"https://huly2.nexgen.systems"}
```

The gateway runs `login → selectWorkspace` and mints a short-lived workspace token (TTL = the token's `exp`, else 12h; renewed at 80%). Only `HULY_TOKEN` / `HULY_ENDPOINT` / `HULY_WORKSPACE` reach the bridge — the account password never leaves the vault.

**Register** — 1-click, or the exact manual JSON the registry applies verbatim:

```json
scopegate_register_upstream { "from_registry": "huly" }
scopegate_register_upstream { "name": "huly", "transport": { "kind": "stdio", "command": "node", "args": ["dist/upstreams/huly-bridge/server.js"] }, "auth": { "type": "huly", "secretRef": "huly_nexgen" } }
```

**Recommended policy** (from `policies.example.yaml`): `- match: "huly:call:*"` with `auto_approve: true`.

**Ops.** Read-after-write is handled inside the bridge (issue resolution retries briefly), so create → comment/update flows are deterministic. Errors are actionable `isError` results naming the listing tool to use.

## 2. github — repos, issues, PRs, code search

The ecosystem MCP server `@modelcontextprotocol/server-github`, spawned over stdio via `npx` (repos, issues, PRs, code search).

**Tools.** The closed list belongs to that upstream package, not to ScopeGate: the gateway proxies whatever the server lists as `github__*`. After registering, run `scopegate_diagnose` and check your tool list for the exact set of the installed version. Names pinned by this repo's policies and e2e: `get_file_contents`, `get_issue`, `list_issues`, `create_pull_request`, `merge_pull_request`, `create_or_update_file`, `delete_file`.

**Auth — two modes.**

- Default (registry): type `env`, `GITHUB_PERSONAL_ACCESS_TOKEN` ← vault ref `github_pat`. The human creates a fine-grained PAT scoped to only the repos needed (`https://github.com/settings/personal-access-tokens`) and runs `scopegate secret add github_pat`.
- Stricter: type `github_app` — the gateway signs an App JWT (RS256) with the App private key from the vault and exchanges it for a ~1h **installation token**, optionally narrowed by `permissions` / `repositories`. Only the installation token reaches the upstream (as `Authorization: Bearer`; for stdio MCPs also as the `GITHUB_PERSONAL_ACCESS_TOKEN` env). The human deposits the App private key PEM: `scopegate secret add github_app_key`.

**Register** — 1-click, manual PAT mode, or per-repo App mode (from `scopegate.example.yaml`; one upstream per repo — a leaked token is worth ≤1h and only its repo):

```json
scopegate_register_upstream { "from_registry": "github" }
scopegate_register_upstream { "name": "github", "transport": { "kind": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }, "auth": { "type": "env", "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "github_pat" } } }
scopegate_register_upstream { "name": "github-huly-platform", "transport": { "kind": "http", "url": "https://api.githubcopilot.com/mcp" }, "auth": { "type": "github_app", "appId": "123456", "installationId": "11111111", "secretRef": "github_app_key", "repositories": ["huly-platform"], "permissions": { "contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read" } } }
```

**Official remote server (1-click).** `from_registry: "github-official"` points at GitHub's
own remote MCP (`https://api.githubcopilot.com/mcp`) with `github_app` auth — ~1h
installation tokens, no PAT, nothing to spawn. The manifest ships `REPLACE_WITH_*`
placeholders: after registering, edit `appId` / `installationId` (and optionally
`repositories` / `permissions`) in `~/.scopegate/scopegate.yaml` and deposit the App
private key (`scopegate secret add github_app_key`).

**Recommended policies** — reads and PRs auto, destructive writes escalate:

```yaml
- match: "github:call:{merge_pull_request,create_or_update_file,delete_file}"
  require: human_approval
- match: "github:call:*"
  auto_approve: true
  ttl: 15m
```

## 3. railway — services, deploys, logs, domains

Bundled bridge over the Railway public GraphQL API (backboard v2). The token travels only as `Authorization: Bearer` from the bridge.

**Tools (7, exposed as `railway__<name>`).** `service` accepts a name (case-insensitive) or an id. When `projectId` is omitted the service is resolved across every accessible project: zero matches → "service not found"; more than one → "ambiguous, pass projectId".

- `list_services {projectId?}` — without `projectId`, every accessible project with its services
- `service_status {service, projectId?}` — latest deployment: `status`, `createdAt`, `url`
- `deploy {service, projectId?}` — triggers a NEW deployment; `redeploy {service, projectId?}` — redeploys the latest
- `get_logs {service, lines?=100, projectId?}` — deploy (runtime) logs, most recent last
- `variables_list {service, projectId?}` — variable NAMES only (see redaction below)
- `domain_status {service, projectId?}` — service + custom domains with DNS status

**Auth.** Type `env`, `RAILWAY_TOKEN` ← vault ref `railway_token` (long-lived, account-scoped; declared `fallback:injection`). The human creates a token in the Railway dashboard → Tokens, scoped to the workspace/projects needed, then runs `scopegate secret add railway_token`.

**Register** — 1-click or manual:

```json
scopegate_register_upstream { "from_registry": "railway" }
scopegate_register_upstream { "name": "railway", "transport": { "kind": "stdio", "command": "node", "args": ["dist/upstreams/railway-bridge/server.js"] }, "auth": { "type": "env", "env": { "RAILWAY_TOKEN": "railway_token" } } }
```

**Recommended policies** — reads auto, deploys always with a human:

```yaml
- match: "railway:call:{deploy,redeploy}"
  require: human_approval
- match: "railway:call:{service_status,list_services,get_logs,domain_status}"
  auto_approve: true
```

**Ops.** Redaction is a hard contract: `variables_list` never returns values — anything the API returns is replaced by `"[redacted]"` inside the bridge, before it leaves the process. The bridge NEVER writes variables or secrets; rotating one means asking the human for `scopegate secret add`.

## 4. cloudflare — zones, DNS, Workers, Pages, R2

Bundled bridge over the Cloudflare API v4. The token is verified once at startup (`GET /user/tokens/verify`) and sent only as `Authorization: Bearer`.

**Tools (8, exposed as `cloudflare__<name>`).**

- `list_zones {}`
- `dns_list {zone, type?, name?}` — `zone` by name (`example.com`) or id; `type`/`name` are exact-match filters
- `dns_create {zone, type, name, content, ttl?, proxied?}`
- `dns_update {zone, recordId, type?, name?, content?, ttl?, proxied?}` — at least one field required
- `dns_delete {zone, recordId}` — the bridge imposes NO extra check; the gateway POLICY gates it
- `workers_list {accountId?}`, `pages_projects {accountId?}`, `r2_buckets {accountId?}`

**Auth.** Type `env`, `CLOUDFLARE_API_TOKEN` ← vault ref `cloudflare_api_token` (`fallback:injection`). The human creates a SCOPED token at `https://dash.cloudflare.com/profile/api-tokens` (Zone.DNS edit on the zones needed + Workers/Pages/R2 read — NEVER a Global API Key), then runs `scopegate secret add cloudflare_api_token`.

**Register** — 1-click or manual:

```json
scopegate_register_upstream { "from_registry": "cloudflare" }
scopegate_register_upstream { "name": "cloudflare", "transport": { "kind": "stdio", "command": "node", "args": ["dist/upstreams/cloudflare-bridge/server.js"] }, "auth": { "type": "env", "env": { "CLOUDFLARE_API_TOKEN": "cloudflare_api_token" } } }
```

**Recommended policies:** `- match: "cloudflare:call:dns_delete"` with `require: human_approval`, then `- match: "cloudflare:call:*"` with `auto_approve: true`.

**Ops.** When `accountId` is omitted, the bridge resolves it via `GET /accounts` and uses the FIRST account the token can access (cached per process; the response always carries the `accountId` used) — pass `accountId` explicitly for multi-account tokens. `401/403` means "token rejected or under-scoped": the fix is a better-scoped deposit, not a retry.

## 5. google — Drive, Gmail, Calendar

Bundled bridge over the Google REST APIs. The gateway signs a service-account JWT (RS256) with the key from the vault and exchanges it at `oauth2.googleapis.com/token` for a ~1h access token — only that token (`GOOGLE_ACCESS_TOKEN`) reaches the bridge.

**Tools (7, exposed as `google__<name>`).**

- drive: `drive_list {query?, limit?}` (name substring), `drive_search {query, limit?}` (full-text), `drive_read {fileId}` — Docs/Sheets/Slides exported to text; content capped at 1 MiB (`truncated: true`)
- gmail: `gmail_send {to, subject, body, cc?}` (RFC 822, header-injection safe), `gmail_list {query?, limit?}`
- calendar: `calendar_list {calendarId?=primary, limit?, timeMin?=now}`, `calendar_create {summary, start, end, attendees?, calendarId?=primary, description?}` — ISO 8601 datetimes, or `YYYY-MM-DD` for all-day events

**Auth.** Type `google_sa`, `secretRef: google_sa`. The human creates a service account with the minimum scopes, generates its JSON key, and runs `scopegate secret add google_sa`. The vault blob is `{client_email, private_key, subject?}` — `subject` enables domain-wide delegation (impersonating a Workspace user).

**Scopes.** Frozen default set: `drive.readonly`, `gmail.send`, `calendar.readonly`. Widen with `auth.scopes` on the upstream config (and grant the same to the SA, or to its client id under domain-wide delegation): `calendar_create` needs `…/auth/calendar.events`; other common additions are `gmail.readonly` and `drive` (write). A 401 means "retry to force a re-mint / re-check the vault blob"; a 403 means "insufficient scope — widen `auth.scopes`".

**Register** — 1-click or manual (add `"scopes": [...]` to `auth` to widen). User-OAuth alternative (device-code daemon): the human runs `scopegate auth login google`, then register with `"auth": { "type": "oauth2", "secretRef": "google_user" }`.

```json
scopegate_register_upstream { "from_registry": "google" }
scopegate_register_upstream { "name": "google", "transport": { "kind": "stdio", "command": "node", "args": ["dist/upstreams/google-bridge/server.js"] }, "auth": { "type": "google_sa", "secretRef": "google_sa" } }
```

**Recommended policy:** `- match: "google:call:*"` with `auto_approve: true` and `ttl: 10m`.

## 6. Any REST API: the `openapi` transport (no bridge needed)

Any REST API with an OpenAPI 3 spec becomes a governed upstream in minutes — the
gateway generates ONE tool per operation and executes the HTTP calls itself (no MCP
server in between). Declared in `~/.scopegate/scopegate.yaml`:

```yaml
upstreams:
  - name: petstore
    transport: { kind: openapi, spec: "https://api.example.com/openapi.json" }  # or a local path
    auth: { type: bearer, secretRef: petstore_key }   # bearer | none in v1
```

- Each operation becomes `petstore__<operationId>` (operations without one get
  `<method>_<path>`), with input schemas built from path/query/header parameters and
  the JSON request body — `required` included.
- Capabilities are the usual `petstore:call:<operationId>` — auto-approve, `when:`,
  `require: human_approval`, hard limits, circuit breaker and signed audit all apply.
- The spec is cached 24h under `~/.scopegate/openapi-cache/` (a failed refetch falls
  back to the cache); https only outside localhost; 30s per-call timeout.
- `baseUrl` in the transport overrides the spec's `servers[0].url`.

**Registering one from chat:** `scopegate_register_upstream` accepts the same envelope
(`transport: {"kind":"openapi","spec":"…"}`) — or write the YAML and restart the gateway.

## 7. Adding a new upstream (generic)

Register any MCP server with the exact envelope:

```json
scopegate_register_upstream { "name": "my-api", "transport": { "kind": "http", "url": "https://api.example.com/mcp" }, "auth": { "type": "bearer", "secretRef": "my_api_key" } }
```

`name`: lowercase `[a-z0-9_-]`, unique (re-registering the same name replaces it); tools appear as `<name>__<tool>` after reconnect. `transport`: `{"kind":"http","url":…}` or `{"kind":"stdio","command":…,"args":[…]}`. Optional `"exposeTools": ["tool_a"]` allowlists upstream tools.

**Auth types** — only REF NAMES, never values (a raw-looking value is rejected as `raw_secret_rejected`):

- `none` — `{ "type": "none" }`
- `bearer` — `{ "type": "bearer", "secretRef": "ref", "header"?: "X-Api-Key", "scheme"?: "Bearer" }` (defaults: header `Authorization`, scheme `Bearer`; `scheme: ""` sends raw)
- `env` — `{ "type": "env", "env": { "ENV_VAR": "ref" } }` — vault refs injected as spawn env of a stdio upstream
- `oauth2` — `{ "type": "oauth2", "secretRef": "ref", "header"?, "scheme"?, "authErrorPattern"? }` — the token blob is written ONLY by `scopegate auth login <upstream>` / the refresh daemon
- `jwt` — `{ "type": "jwt", "secretRef": "hmac_ref", "ttl"?: "5m", "claims"?: {…} }` — gateway-signed HS256 tokens for internal APIs
- `github_app` — `{ "type": "github_app", "appId", "installationId", "secretRef": "pem_ref", "apiUrl"?, "permissions"?, "repositories"? }`
- `aws_sts` — `{ "type": "aws_sts", "secretRef": "base", "roleArn"?, "region"?, "durationSeconds"? }` — the vault must hold `<base>_ACCESS_KEY_ID` + `<base>_SECRET_ACCESS_KEY`; only session credentials are injected

**The `waiting_for_secrets` flow.** For `bearer` / `oauth2` / `env` the gateway checks the vault BEFORE saving; missing refs come back as:

```json
{ "registered": "my-api", "status": "waiting_for_secrets",
  "setup_hints": { "my_api_key": "…where to obtain it… (registry registrations only)" },
  "action_required": "Ask the human to run in their terminal: scopegate secret add my_api_key — then call scopegate_diagnose." }
```

Relay `action_required` verbatim. Do NOT retry the registration, do NOT ask for the value in chat. Check which refs already exist yourself with `scopegate_vault_status`.

**Always verify afterwards.** Once the human confirms the deposit (and after ANY registration), call `scopegate_diagnose` → `{ "upstreams": { "my-api": { "ok": true, "tools": 12, "mode": "fallback:injection" } } }`. `mode` is `minted:<provider>` (jwt/github_app/aws_sts/huly/google_sa), `fallback:injection` (bearer/env/oauth2) or `none`. For minted auth types a missing/invalid secret surfaces HERE (`ok: false` with an actionable `error`), not at registration. A failing upstream is reconnected automatically on the next call.

**Then get policy.** Registration grants nothing: call `scopegate_request_capability`, and if denied, `scopegate_propose_policy { "match": "my-api:call:*", "ttl": "10m", "justification": "…" }`. Proposals land in `policies.pending.yaml` and have NO effect until a human runs `scopegate policies review` / `scopegate policies accept <n>`.

Registry names available beyond the five natives: `aws`, `notion`, `supabase`, `stripe` (`fakegit` is a test fixture, not a real service).
