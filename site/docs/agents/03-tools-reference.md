# 03 — MCP Tools Reference

Exact reference of the eighteen `scopegate_*` management tools, plus how proxied
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

**Oversized results (result handles).** A proxied payload larger than
`limits.max_inline_bytes` (default 16 KiB) never floods your context: the gateway
persists it (AFTER policy redaction) and returns a preview + handle instead:

```json
{
  "truncated": true,
  "result_ref": "r-d215da552957e6f1",
  "preview": "{ \"items\": [ …first 2 KiB…",
  "stats": { "bytes": 14230, "shape": "object", "top_keys": ["items", "generated_at"], "items": 120 },
  "hint": "Full payload stored (14230 bytes). Page it with scopegate_result_get {ref: …, path: …} or search it with scopegate_result_grep {ref: …, pattern: …} — do NOT re-call the tool for the rest."
}
```

Refs live 2h and are per-agent (you can only read your own). Page with
`scopegate_result_get` / search with `scopegate_result_grep`.


## scopegate_request_capability

Request an ephemeral grant before privileged work. Capability format:
`<upstream>:<action>:<resource>`. Request the MINIMUM scope and SHORTEST TTL.

| field | type | required | notes |
|---|---|---|---|
| `capability` | string | yes | e.g. `github:write:easyorder/*` |
| `ttl` | string | no | `'<n>s'`, `'<n>m'` or `'<n>h'`; the policy ceiling always wins |
| `reason` | string | yes | one line; recorded in the audit log |
| `lease_id` | string | no | bind the grant to a task lease (validated: live + upstream scope) |
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

## scopegate_open_task_lease

Open a task lease for long-running work (see [08 — Long tasks](./08-long-tasks.md)).
Double budget: total time (clamped by `limits.max_lease_total`, default 4h — hard
ceiling, never extends) and writes (default 200).

| field | type | required | notes |
|---|---|---|---|
| `goal` | string | yes | one line naming the task (audited) |
| `upstreams` | string[] | yes | scope; `[]` means all |
| `max_total` | string | no | e.g. `2h` — clamped by the ceiling |
| `max_writes` | number | no | default 200 |

```json
{ "lease_id": "f47ac10b-…", "goal": "…", "upstreams": ["github"],
  "total_ms": 7200000, "deadline_at": "…", "max_writes": 60,
  "next_step": "Request capabilities with lease_id to bind them to this lease; renew them with scopegate_renew_capability before they die." }
```

## scopegate_renew_capability

Renew a lease-covered grant (sliding TTL, auto-approved while the lease lives).

| field | type | required | notes |
|---|---|---|---|
| `grant_id` | string | yes | from `scopegate_list_capabilities` |

```json
{ "renewed": true, "grant_id": "…", "lease_id": "f47ac10b-…",
  "expires_at": "2026-07-23T20:10:00.000Z", "expires_in_seconds": 594 }
```

New expiry = `min(now + original ttl, lease deadline, rule ceilings)` — never
past the deadline. Tool errors when the grant is unknown, not lease-covered, or
the lease is dead (open a new lease).

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

## scopegate_can_i

Read-only policy preflight — plan a task without learning from denials. **Zero
side effects**: nothing is issued, queued or audited, so it never dirties your
trail or the human's queue.

| field | type | required | notes |
|---|---|---|---|
| `capability` | string | yes | e.g. `github:write:easyorder/*` |
| `ttl` | string | no | evaluates the effective clamp too |

**Responses**

```json
{ "capability": "fakegit:call:whoami", "decision": "allow", "ttl_ms": 600000,
  "rule": "fakegit:call:whoami", "reason": "Auto-approved by rule 'fakegit:call:whoami'.",
  "recommended_next": "Proceed — call scopegate_request_capability (or the tool directly)." }
```

```json
{ "capability": "fakegit:call:danger3", "decision": "needs_approval", "via": "local_policy",
  "rule": "fakegit:call:danger3", "recommended_next": "Plan for a human approval — request with execute_on_approval so the work completes on approval." }
```

```json
{ "capability": "aws:write:production", "decision": "deny", "code": "ceiling_blocked",
  "hard": true, "recommended_next": "Hard limit — do NOT attempt this in any form; only a human policy change would allow it." }
```

`decision: "allow"` may also carry `covered_by_existing_grant: true` (you already
hold it — call the tool directly). Denials reuse the `request_capability` codes
(`no_policy | no_rule | ceiling_blocked | invalid_ttl | config_error`).

## scopegate_policy_summary

Your policy digest for session-start planning (read-only).

```json
{
  "agentId": "kimi-code",
  "agent_found": true,
  "default_ttl": "15m",
  "auto_approve": ["fakegit:call:whoami", "db:read:*"],
  "requires_approval": ["fakegit:call:danger"],
  "deny_globs": ["aws:*:production"],
  "max_ttl": "30m",
  "approval_ttl": "10m",
  "rate_limit": "30/m",
  "team": { "version": 3, "fetchedAt": "2026-07-23T18:00:00Z" }
}
```

Cache it at handshake time and plan the whole task with `scopegate_can_i` for the
specifics. `team` is null when no team policy is installed (local-first default).

## scopegate_recall

Your own signed audit as session memory — **scoped to your agentId only** (you
can never read another agent's trail). Use it after a restart or context
compaction: reconstruct state instead of re-reading the repo or repeating work.

| field | type | required | notes |
|---|---|---|---|
| `since` | string | no | ISO 8601 lower bound; default: last 2 hours |
| `kinds` | string[] | no | audit-kind filter, e.g. `["tool_call","grant_issued"]` |
| `limit` | number | no | max actions returned (default 50, max 200) |

**Response**

```json
{
  "agentId": "kimi-code",
  "since": "2026-07-23T16:00:00.000Z",
  "counts": { "actions": 42, "writes": 3, "active_grants": 2, "pending_approvals": 1 },
  "recent_actions": [ { "ts": "…", "kind": "tool_call", "tool": "huly__create_issue" } ],
  "writes": [ { "ts": "…", "tool": "huly__create_issue" } ],
  "active_grants": [ { "id": "g-…", "capability": "fakegit:call:whoami", "remaining_seconds": 512 } ],
  "pending_approvals": [ { "approval_id": "…", "capability": "aws:deploy:production", "expires_at": "…" } ]
}
```

`writes` are classified with the side-effects table (curated bridge writes,
prefix heuristic, manifest `side_effects` overrides) — answer "did I already do
this write?" before repeating it (see also `_sg_idempotency_key`).

## scopegate_request_plan

One task plan, ONE aggregated human decision (see [08 — Long tasks](./08-long-tasks.md)).
Auto-approvable capabilities are issued immediately, denials are reported, and every
needs_approval capability is bundled into a single approval with the whole blast
radius visible as one item.

| field | type | required | notes |
|---|---|---|---|
| `goal` | string | yes | one line naming the task (audited) |
| `capabilities` | array | yes | `[{capability, ttl?}]` — max 20 |
| `open_lease` | boolean | no | also open a task lease and bind every grant of the plan |
| `max_total` | string | no | lease total (with open_lease) |
| `max_writes` | number | no | lease write budget (with open_lease) |

**Response**

```json
{
  "goal": "read repo X, write branch Y, deploy staging",
  "lease_id": "f47ac10b-…",
  "auto": [
    { "capability": "github:read:easyorder", "granted": true, "ttlMs": 600000 },
    { "capability": "aws:write:production", "granted": false, "code": "ceiling_blocked", "reason": "…" }
  ],
  "pending": {
    "approvalId": "3f6b8c2e-…",
    "items": [ { "capability": "github:write:fix-x" }, { "capability": "railway:call:deploy", "ttl": "5m" } ],
    "approvalExpiresAt": 1823400000000
  },
  "instructions": "The auto-approvable part is already granted. The rest is ONE aggregated approval: ask the human to run scopegate approve 3f6b8c2e-… — on approval every bundled capability is issued at once (your next request materializes them)."
}
```

On approval, every bundled capability is issued at once (each clamped per its own
rule ceilings; bound to the plan's lease when `open_lease` was set).

## scopegate_result_get

Slice a stored oversized result by dot-path.

| field | type | required | notes |
|---|---|---|---|
| `ref` | string | yes | the `result_ref` (r-…) |
| `path` | string | yes | e.g. `items.3.title` or `content.0.text` |

```json
{ "found": true, "ref": "r-…", "path": "items.0.title", "value": "item-0 — …" }
```

`{found: false}` means a bad path (adjust it — `top_keys` comes in the response),
not an error. Unknown/expired refs are a tool error (refs live 2h, per-agent).

## scopegate_result_grep

Search a stored oversized result by substring or `/regex/` (optional flags).

```json
{ "ref": "r-…", "pattern": "item-42", "count": 2,
  "hits": [ { "path": "items", "line": "\"title\": \"item-42 — …\"" } ] }
```

Capped at 50 hits — context-sized by design.

## scopegate_delegate

Delegate one of YOUR live grants to a child agent (subagent) with strict
attenuation — orchestrating parallel subagents without sharing your identity.

| field | type | required | notes |
|---|---|---|---|
| `grant_id` | string | yes | your live grant (see `scopegate_list_capabilities`) |
| `child_agent_id` | string | yes | the child's agent id — must differ from yours |
| `scope_subset` | string | yes | capability covered by the parent grant (never broader) |
| `ttl` | string | no | must not exceed the parent's remaining TTL |

```json
{ "delegated": true, "child_grant_id": "…", "child_agent_id": "subagent-explorer",
  "capability": "github:write:easyorder/api", "expires_at": "…",
  "note": "The child grant is attenuated (subset + shorter ttl) and dies with the parent. The child sees it in its own scopegate_list_capabilities." }
```

Fail-closed refusals: a scope NOT covered by the parent glob (`Attenuation
violation`), a ttl longer than the parent's remaining, self-delegation, or a
dead parent grant. The child grant carries `parentGrantId` — revoking the
parent (directly or via fleet revocation) kills every child, and the audit
chain (`grant_delegated` with `parent_grant`) attributes every action.

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

`tools/list` returns the eighteen management tools PLUS every tool of every connected upstream,
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
