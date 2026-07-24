# 03 — MCP Tools Reference

Exact reference of the nine `scopegate_*` management tools, plus how proxied
upstream tools (`<upstream>__<tool>`) work. Every shape here is traceable to
`src/gateway/tools.ts`, `src/gateway/server.ts` and `src/policy/engine.ts`.
Read [02 — Agent Protocol](./02-protocol.md) first; use this as its lookup table.

## Response conventions

Every management tool returns its payload as pretty-printed JSON in `content[0].text`
— parse it as JSON. Three fail-closed gates can deny ANY call: **agent suspended**
(honeytoken) and **agent revoked by ScopeGate Cloud** deny everything until a human
intervenes; **audit unavailable** denies the action.

Failures come in two shapes:

- **Argument/misuse errors** — text `"ERROR: <actionable message>"`, `isError: true`
  (fix the call and retry).
- **Machine-readable error envelopes** (execution/policy failures) — JSON with
  `isError: true`. Always act on `kind` + `next_action`, never on the prose:

```json
{
  "error": true,
  "kind": "expired_grant | missing_scope | policy_denied | rate_limited | upstream_down | auth_broken",
  "message": "one actionable line",
  "retry_after_s": 5,
  "next_action": "renew | request_capability | wait | diagnose | human",
  "next_step": "literal instruction for you"
}
```

| `kind` | you should |
|---|---|
| `expired_grant` | `scopegate_renew_capability` (or request a fresh grant) |
| `missing_scope` | `scopegate_request_capability` with the SAME capability |
| `policy_denied` | stop — human path only (`scopegate_propose_policy` or ask) |
| `rate_limited` | wait `retry_after_s`, never loop |
| `upstream_down` | wait briefly, retry once, then `scopegate_diagnose` |
| `auth_broken` | `scopegate_diagnose` for the self-repair path |

Upstream availability is additionally guarded by a per-upstream **circuit breaker**:
after 5 consecutive failures the circuit opens for 30 s (calls fail fast with an
`upstream_down` envelope), then a half-open probe decides. See
`scopegate_upstream_health` for the live states.


## scopegate_request_capability

Request an ephemeral grant before privileged work. Capability format:
`<upstream>:<action>:<resource>`. Request the MINIMUM scope and SHORTEST TTL.

| field | type | required | notes |
|---|---|---|---|
| `capability` | string | yes | e.g. `github:write:easyorder/*` |
| `ttl` | string | no | `'<n>s'`, `'<n>m'` or `'<n>h'`; the policy ceiling always wins |
| `reason` | string | yes | one line; recorded in the audit log |
| `execute_on_approval` | object | no | `{tool, args}` continuation — see below |

**Approval continuation (`execute_on_approval`).** When a request escalates, you
may attach the exact call you intend to make: `{tool: '<upstream>__<tool>', args: {...}}`.
Constraints, all fail-closed: the tool's derived capability (`<upstream>:call:<tool>`)
must EQUAL the requested capability (a human approves exactly what they see — no
smuggling a different action), and the intent expires with the approval window.
The response then carries a `continuation` block and the flow changes to fire-and-collect:

```json
{
  "granted": false,
  "status": "pending_human_approval",
  "approval_id": "3f6b8c2e-…",
  "continuation": {
    "queued": true,
    "intent_id": "d41d8cd9-…",
    "collect_with": "scopegate_collect {approval_id: \"3f6b8c2e-…\"}",
    "wait_with": "scopegate_wait {approval_id: \"3f6b8c2e-…\", timeout_s: 60}"
  }
}
```

When the human approves (CLI or cloud panel), the gateway executes the intent with the
fresh grant and persists the outcome — you collect it; you do NOT re-issue the call.

**Response — granted**

```json
{ "granted": true, "capability": "github:write:easyorder/*", "expires_in_seconds": 900, "matched_rule": "github:write:easyorder/*" }
```

`expires_in_seconds` = `min(requested, rule/default ceiling, limits.max_ttl)` (default
15m). Re-requesting a held capability is idempotent (`matched_rule` may be `"existing_grant"`).

**Response — pending_human_approval**

```json
{
  "granted": false,
  "status": "pending_human_approval",
  "approval_id": "3f6b8c2e-1a2d-4e5f-9a0b-7c8d9e0f1a2b",
  "approval_expires_at": "2026-07-23T18:20:11.492Z",
  "reason": "Capability 'aws:deploy:prod' matches 'aws:deploy:*' which requires human approval.",
  "instructions": "A human must approve this request. Ask them to run in their terminal: scopegate approve 3f6b8c2e-… (or: scopegate deny 3f6b8c2e-…). Once approved, call scopegate_request_capability again with the SAME capability — do NOT retry with broader scope.",
  "next_step": "Ask the human to approve this action, or wait for approval."
}
```

STOP and relay the exact `scopegate approve <approval_id>` command. The request expires
after `approval_ttl` (default 10m; `approval_expires_at` omitted when unset). Once approved,
re-call with the SAME capability — never broader or reworded.

**Response — denied**

```json
{ "granted": false, "code": "no_rule", "reason": "No auto_approve rule matches 'stripe:write:*' for agent 'kimi-code'.", "next_step": "Call scopegate_propose_policy with a justification; a human will review it." }
```

| `code` | meaning |
|---|---|
| `no_policy` | no policy section covers your agent id at all |
| `no_rule` | no `auto_approve` rule matches the capability |
| `ceiling_blocked` | hit a hard-limit `deny` glob — non-negotiable; `next_step` tells you not to retry |
| `invalid_ttl` | your `ttl` was not `'<n>s'/'<n>m'/'<n>h'` |
| `config_error` | broken human-written policy value (fail-closed) |
| `capability_rate_limited` | exceeded the request rate limit (default `30/m`); back off — do NOT loop |

Tool errors: `Missing required argument 'capability' …` / `'reason' …` (fix the
call); `… references honeytoken '<ref>' …` (canary mentioned; incident recorded).

**Example call**

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "scopegate_request_capability",
              "arguments": { "capability": "github:write:easyorder/*", "ttl": "15m", "reason": "Push the fix branch and open a PR" } } }
```

## scopegate_collect

Read the outcome of an approval continuation. Triggers the approval materialization
on access (an approved request executes its intent at that moment).

| field | type | required | notes |
|---|---|---|---|
| `approval_id` | string | yes | from the pending response |

**Response — executed**

```json
{ "status": "executed", "approval_id": "3f6b8c2e-…", "tool": "fakegit__danger2",
  "executed_at": "2026-07-23T18:21:40.102Z", "duration_ms": 312,
  "result": { "content": [{ "type": "text", "text": "danger2 executed" }] } }
```

**Response — failed / pending / none**

```json
{ "status": "failed", "approval_id": "…", "error": "upstream said no" }
{ "status": "pending", "approval_id": "…", "expires_at": "…" }
{ "status": "none", "approval_id": "…", "note": "No continuation intent exists for this approval_id …" }
```

## scopegate_wait

Long-poll for the outcome — prefer this over polling loops that burn turns.

| field | type | required | notes |
|---|---|---|---|
| `approval_id` | string | yes | from the pending response |
| `timeout_s` | number | no | default 60, max 120 |

Returns the executed/failed shape as soon as it exists, `{status: "expired"}` when the
approval window closed, or `{status: "timeout"}` — in which case the approval is still
pending: collect later with `scopegate_collect`, never abandon the task silently.

## scopegate_upstream_health

Per-upstream health as a machine-readable report (this is `scopegate_diagnose` plus
circuit-breaker state — use it before deciding to retry).

```json
{
  "agentId": "kimi-code",
  "upstreams": {
    "fakegit": { "ok": true, "tools": 5, "mode": "fallback:injection", "circuit": { "state": "closed", "failures": 0 } },
    "notion": { "ok": false, "error": "HTTP 401", "mode": "minted:oauth2", "action_required": "…", "circuit": { "state": "open", "failures": 5 } }
  }
}
```

`circuit.state` is `closed` (healthy), `open` (fail-fast after 5 consecutive failures,
30 s) or `half_open` (a single probe is deciding).

## scopegate_list_capabilities

List your active (non-expired) grants with remaining TTL. No arguments.

```json
{ "agentId": "kimi-code",
  "active_grants": [ { "id": "9d1e0b3a-…", "capability": "github:call:create_pull_request", "remaining_seconds": 812 } ] }
```

`id` is the grant's UUID; `remaining_seconds` is clamped at 0. Example call: `{ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "scopegate_list_capabilities", "arguments": {} } }`

## scopegate_register_upstream

Register a new upstream behind the gateway. Two envelopes — pass EITHER `from_registry`
alone (1-click; name/transport/auth come from the signed, verified manifest) OR `name` +
`transport` + `auth` manually. NEVER pass a secret value — only secretRef NAMES.

| field | type | notes |
|---|---|---|
| `from_registry` | string | envelope A; e.g. `github`, `aws`, `notion`, `supabase`, `stripe`; fail-closed on tampered/unknown entries |
| `name` | string | envelope B; lowercase, digits, `_`, `-`; tools exposed as `<name>__<tool>` |
| `transport` | object | envelope B; `{kind:"http", url}` or `{kind:"stdio", command, args?}` |
| `auth` | object | envelope B; `{type:"bearer", secretRef, header?, scheme?}` · `{type:"oauth2", secretRef}` · `{type:"env", env:{ENV_VAR: secretRef}}` · `{type:"none"}` |

**Response — registered**

```json
{ "registered": "grafana", "connection": { "ok": true, "tools": 14 } }
```

`connection` is a live probe (`{ok:true, tools:n}` or `{ok:false, error:"…"}`); the
upstream is saved either way and the proxy (re)connects lazily on first call.

**Response — waiting_for_secrets**

```json
{
  "registered": "github",
  "status": "waiting_for_secrets",
  "from_registry": "github",
  "setup_hints": { "github_token": "<hint text from the registry manifest>" },
  "action_required": "Ask the human to run in their terminal: scopegate secret add github_token  — then call scopegate_diagnose."
}
```

Relay `action_required` verbatim: the human runs `scopegate secret add <ref>` in
THEIR terminal — never in chat. `from_registry`/`setup_hints` appear only for
registry registrations.

Tool errors: `Registry entry '<x>' could not be verified — nothing was registered
(fail-closed): …` · `Invalid or missing 'name' …` · `Invalid or missing 'transport.kind' …`
· `Missing 'transport.url' …` · `Missing 'transport.command' …` · `auth.secretRef is
required` · `secretRef looks like a raw secret value. …` / `env value '…' looks like a raw
secret. …` (heuristic: length > 40, an `sk-`/`ghp_`/`gho_`/`xox[bap]-`/`AKIA`/`AIza`/`eyJ`
prefix, or ≥32-char base64 run — pass a NAME) · `Registration denied: '<ref>' is a honeytoken. …`

**Example call**

```json
{ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "scopegate_register_upstream",
              "arguments": { "name": "grafana", "transport": { "kind": "http", "url": "https://g.example.com/mcp" }, "auth": { "type": "bearer", "secretRef": "grafana_token" } } } }
```

## scopegate_diagnose

Health-check every enabled upstream (bounded liveness probe + tool count). Call it FIRST
on any connection/auth error: a failed connection is dropped and re-established with
fresh credentials on the next call. No arguments; never rejects. See [06 — Self-Repair](./06-self-repair.md).

**Response**

```json
{ "upstreams": {
    "github": { "ok": true, "tools": 42, "mode": "minted:github_app" },
    "notion": { "ok": true, "tools": 12, "mode": "fallback:injection",
                "oauth": { "state": "needs_reauth", "token_expires_in_s": null, "consecutive_failures": 3 },
                "action_required": "run in your terminal: scopegate auth login notion" },
    "railway": { "ok": false, "error": "health probe of upstream 'railway' timed out after 10000 ms", "mode": "fallback:injection" } } }
```

Per-upstream fields: `ok` + `tools` (count) or `ok:false` + `error`; `mode` is `none` ·
`minted:<provider>` (`jwt`, `github_app`, `aws_sts`, `huly`, `google_sa`) · `fallback:injection`.
`oauth` (oauth2 upstreams only): `state` ∈ `ok`, `backoff`, `circuit_open`, `needs_reauth`,
`unknown_expiry`; plus `token_expires_in_s` (null when unknown), `consecutive_failures`, optional
`last_refresh_at`/`next_refresh_in_s`. `action_required` appears when `state` is `needs_reauth`
— relay verbatim (human-only device-code login). `pool`: `{size, inUse, hits}` when pooled.
Example call: `{ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "scopegate_diagnose", "arguments": {} } }`

## scopegate_propose_policy

Propose a policy rule when a needed capability is denied. Validated, deduplicated,
linted against hard limits and appended to `policies.pending.yaml` (under
`~/.scopegate` by default) for HUMAN review — it NEVER changes live policy.
Only `{match, ttl}` are agent-settable.

| field | type | required | notes |
|---|---|---|---|
| `match` | string | yes | capability glob, e.g. `stripe:read:*` (must compile) |
| `ttl` | string | no | suggested ceiling, `'<n>s'/'<n>m'/'<n>h'` |
| `justification` | string | yes | a human reads this — explain why it is needed |

**Response**

```json
{ "queued": true, "deduped": false, "pending_file": "/home/user/.scopegate/policies.pending.yaml",
  "note": "A human must review and merge this into policies.yaml. It has NO effect until then." }
```

An identical pending proposal (same agent, `match`, `ttl`) returns `"queued": false,
"deduped": true`. A proposal colliding with hard limits is queued but flagged
`"lint": "conflicts_with_limits"` (+ `lint_note`). Tell the human: `scopegate policies
review`, then `scopegate policies accept <n>` (or `reject <n>`). See [05 — Policies](./05-policies.md).

Tool errors: `Missing required argument 'match' …` / `'justification' …` · `Proposal
rejected: field '<x>' is not agent-settable. …` · `Proposal rejected: match: invalid
glob …` / `Proposal rejected: Invalid ttl '1d' — expected '<n>s', '<n>m' or '<n>h' …`

**Example call**

```json
{ "jsonrpc": "2.0", "id": 5, "method": "tools/call",
  "params": { "name": "scopegate_propose_policy",
              "arguments": { "match": "stripe:read:*", "ttl": "10m", "justification": "Read invoices to reconcile payout report #4821" } } }
```

## scopegate_vault_status

List the secret REF NAMES in the vault — never values. Check it before registering an
upstream so you pick an existing secretRef. No arguments. A missing ref means asking
the human to run `scopegate secret add <ref>` in their terminal.

```json
{ "secret_refs": ["github_token", "grafana_token", "railway_api_token"] }
```

Example call: `{ "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": { "name": "scopegate_vault_status", "arguments": {} } }`

## Proxied tools: `<upstream>__<tool>`

`tools/list` returns the nine management tools PLUS every tool of every connected upstream,
renamed `<upstream>__<toolName>` (double underscore; description/inputSchema pass through
unchanged; an upstream config may restrict exposure with an `exposeTools` allowlist).

Every proxied call maps to the capability `<upstream>:call:<toolName>`. The gateway checks
a live covering grant first; with none, it attempts an IMPLICIT request that succeeds only
via an `auto_approve` rule. A denied call is a tool error:

```text
ERROR: Capability 'grafana:call:query' not granted. Call scopegate_request_capability first (or scopegate_propose_policy if denied). Reason: No auto_approve rule matches 'grafana:call:query' for agent 'kimi-code'.
```

If the denial escalated, it appends ` Approval request <id> is pending — ask the human to
run: scopegate approve <id>`. Unknown names yield `ERROR: Unknown tool '<name>'`. Correct
flow — request explicitly FIRST (the reason lands in the audit log), then call:

```json
{ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
  "params": { "name": "scopegate_request_capability",
              "arguments": { "capability": "github:call:create_pull_request", "reason": "Open the fix PR" } } }
{ "jsonrpc": "2.0", "id": 8, "method": "tools/call",
  "params": { "name": "github__create_pull_request",
              "arguments": { "owner": "easyorder", "repo": "api", "title": "fix", "head": "fix/x", "base": "main" } } }
```

Under the hood: credentials are minted/injected per call with `token_ttl = min(provider
ceiling, remaining grant TTL)`, failed calls reconnect/retry transparently (bounded), and
the issuing rule's `redact: [...]` categories are applied to the response first.

Related: [02 — Agent Protocol](./02-protocol.md) · [05 — Policies](./05-policies.md) · [06 — Self-Repair](./06-self-repair.md) · [07 — Security Rules](./07-security-rules.md) · [Index](./README.md)
