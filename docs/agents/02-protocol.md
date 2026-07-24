# 02 — The Agent Protocol: Operating Behind the Gateway

This guide defines how you (an autonomous coding agent) work with ScopeGate's
ephemeral capabilities. It is the operational contract: follow it exactly and
privileged work flows; deviate and the gateway fails closed against you.

Prerequisites: ScopeGate is installed and you can call its MCP tools
(`scopegate_request_capability`, `scopegate_list_capabilities`, …). If not,
see the setup guide first. Tool argument schemas live in
[03 — Tools Reference](./03-tools-reference.md); this document covers the
*protocol*, not every field.

## 1. Mental model

**A capability is not a credential.** You never see, hold, or transmit a
secret value. Secrets live in the encrypted vault; the gateway injects them
into upstream requests inside the proxy, outside your context. What you hold
is a *capability*: a permission string of the form
`<upstream>:<action>:<resource>`, e.g. `github:write:myorg/myrepo`,
`aws:deploy:staging`, `huly:read:*`. Proxied tool calls map to
`<upstream>:call:<toolName>` when no finer scope applies.

**A grant is a time-boxed, audited materialization of a capability.** When
policy allows your request, the engine issues a persistent grant (UUID,
`expiresAt`, issuing rule). Every grant has a TTL and dies on its own — the
default ceiling is 15 minutes unless the matched rule says otherwise.

**Why a leaked token is worth ~zero.** Any token a minter produces for a call
is clamped to the *remaining TTL of the covering grant*
(`token_ttl = min(provider ceiling, grant TTL)`). It is scoped to one
capability, expires with the grant, and every use is attributed in the
Ed25519-chained audit log. Meanwhile the long-lived secret never left the
vault, and honeytoken decoys (`canary:*` refs) turn any exfiltration attempt
into a high-precision alarm (see §5). Stealing what you can touch buys an
attacker minutes of narrow, fully-logged access.

## 2. Lifecycle of a privileged action

1. **Ask before you act.** Call `scopegate_request_capability` with the
   minimum capability and a one-line `reason` (required — it goes to the
   audit log). Optionally pass `ttl` (strict format: `30s`, `5m`, `1h`).
2. **The engine evaluates, in this order:** rate limit → honeytoken mention →
   existing covering grant (idempotent re-request: returned as-is, never
   duplicated) → hard-limit `deny` globs (fail-closed, beat every rule) →
   policy rules in order (`require: human_approval` → escalation;
   `auto_approve` → grant). TTL is always
   `min(requested, rule/default ceiling, limits.max_ttl)` — you can shorten,
   never extend.
3. **Read the verdict.** Three shapes come back:

**Granted** — proceed with the work:

```json
{
  "granted": true,
  "capability": "github:write:myorg/myrepo",
  "expires_in_seconds": 900,
  "matched_rule": "github:write:myorg/*"
}
```

**Denied** — do not retry; follow `next_step`:

```json
{
  "granted": false,
  "code": "no_rule",
  "reason": "No auto_approve rule matches 'aws:deploy:prod' for agent 'kimi-code'.",
  "next_step": "Call scopegate_propose_policy with a justification; a human will review it."
}
```

Deny `code` values: `no_policy` (no policy section covers you),
`no_rule` (no auto-approve rule matches), `ceiling_blocked` (hard-limit deny
glob — absolutely non-negotiable), `invalid_ttl` (your `ttl` was malformed),
`config_error` (broken human config — report it), `capability_rate_limited`.

**Pending human approval** — a wall, not a delay (see §4):

```json
{
  "granted": false,
  "status": "pending_human_approval",
  "approval_id": "7c9e2f1a-…",
  "approval_expires_at": "2026-07-23T18:20:11.396Z",
  "reason": "Capability 'github:write:myorg/myrepo' matches 'github:write:*' which requires human approval.",
  "instructions": "A human must approve this request. Ask them to run in their terminal: scopegate approve 7c9e2f1a-… (or: scopegate deny 7c9e2f1a-…). Once approved, call scopegate_request_capability again with the SAME capability — do NOT retry with broader scope.",
  "next_step": "Ask the human to approve this action, or wait for approval."
}
```

4. **Do the work through the gateway.** With a live grant, call the proxied
   tools (`<upstream>__<tool>`). Each call re-checks the grant, is audited
   fail-closed (input hashed, never stored), gets credentials injected, and
   may return PII-redacted output if the issuing rule carries `redact`.
   Calling a proxied tool *without* a grant triggers an implicit
   auto-approve attempt — on failure you get
   `Capability '<upstream>:call:<tool>' not granted. Call scopegate_request_capability first…`.
   Prefer the explicit request: it records your `reason` in the audit trail.
5. **Renew by re-requesting the SAME capability.** A live covering grant is
   returned idempotently; after expiry, the same request re-evaluates policy
   and issues a fresh grant if the rule still allows it.

## 3. Hard rules (non-negotiable)

- **Minimum scope, shortest TTL.** Ask for `github:write:myorg/myrepo`, not
  `github:*`. Pass a `ttl` that fits the task; the ceiling always wins anyway.
- **Never retry with broader scope after a deny.** The deny messages say so
  verbatim. The correct move is `scopegate_propose_policy` with a
  justification, then inform the human.
- **Never ask the human to paste a secret in chat.** If a secret is missing,
  the answer is always: "Run in your terminal: `scopegate secret add <ref>`".
- **Never escalate yourself.** You can propose rules (`{match, ttl}` only) —
  they land in `policies.pending.yaml` and have NO effect until a human
  accepts them (`scopegate policies accept <n>`). Never edit `policies.yaml`,
  never touch approval queue files, never try to approve your own request.
- **Human approval is a wall.** See §4 — stop, hand over the command, wait.
- **No request loops.** `scopegate_request_capability` is throttled by a
  sliding window (default `30/m`, tunable via `limits.rate_limit`). Hammering
  earns you `capability_rate_limited` and wastes the window.

## 4. When you get `pending_human_approval`

A rule with `require: human_approval` matched your capability. A request now
sits in the human's queue (it expires after `approval_expires_at` — default
10 minutes, set by `limits.approval_ttl`). Do exactly this:

1. **STOP that line of work.** Do not retry, do not rephrase the capability,
   do not poll in a loop. Re-requesting the same capability just returns the
   same pending `approval_id` (requests are deduplicated) — it does not
   speed anything up.
2. **Inform the human with the exact command** from the response:
   `scopegate approve <approval_id>` (or `scopegate deny <approval_id>`).
   Relay it verbatim; approval is a human-only action by design.
3. **Continue unrelated work or wait.**
4. **After the human approves, call `scopegate_request_capability` again with
   the SAME capability string.** The engine materializes a one-shot grant
   from the decision and returns it (`granted: true`). A different string
   starts a brand-new approval cycle — you just reset your own clock.
5. **If the request expired** (no decision before `approval_expires_at`),
   re-request the same capability to open a fresh one and tell the human the
   previous approval lapsed. **If the human denied it**, do not re-ask — drop
   that path or use `scopegate_propose_policy` with a stronger justification.

### 4b. The better path: approval continuation (`execute_on_approval`)

Polling for an approval burns turns and tokens, and an approval that lands
after you abandoned the task is wasted. Attach the exact call to the request
and the approval becomes a continuation — queued, then executed by the
gateway the moment the human approves (from the CLI or the cloud panel):

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "scopegate_request_capability",
              "arguments": {
                "capability": "github:call:create_pull_request",
                "reason": "Open the fix PR",
                "execute_on_approval": {
                  "tool": "github__create_pull_request",
                  "args": { "owner": "easyorder", "repo": "api", "title": "fix", "head": "fix/x", "base": "main" }
                } } } }
```

Rules, all fail-closed: the intent's derived capability must EQUAL the
requested one (the human approves exactly what they see — no smuggling), and
the intent dies with the approval window (`approval_ttl`). The response
carries `continuation.queued: true`. Then:

- `scopegate_wait {approval_id, timeout_s}` for short waits (long-poll, max
  120 s — never a polling loop), or
- `scopegate_collect {approval_id}` any time later, including after a restart:
  the outcome is persisted in the gateway home.

On approval the intent executes with the fresh grant and the upstream result
(or the failure) is stored for collection. The audit records the intent hash
and the outcome hash — never the payloads.


## 5. `suspended`: the gateway has contained you

If any response tells you the agent is `SUSPENDED`, a security tripwire
fired — almost always a honeytoken: a decoy `canary:<name>` ref was used as a
credential (`register_upstream`), named in a capability
(`request_capability`), or seen outside the gateway. In enforce mode (the
default) every one of your live grants was revoked and the gateway now denies
EVERY request from you, fail-closed:

```
Agent 'kimi-code' is SUSPENDED: honeytoken 'deploy' (canary:deploy) used via
request_capability at 2026-07-23T18:12:00Z. Every request is denied
(fail-closed) until a human reviews the incident (see audit.jsonl:
honeytoken_triggered / agent_revoked) and removes the agent's entry under
'suspended' in ~/.scopegate/honeytoken-state.json.
```

What you do: **stop all gateway interaction immediately and escalate to the
human.** Do not retry a single call — everything is denied and each attempt
is audited. Do not try to clear the state file, rotate anything, or
"explain" your way past it: re-enabling is a human-only incident-review
process with no CLI by design. The same behavior applies if you were revoked
from a ScopeGate Cloud fleet. Prevention: never reference `canary:*` refs,
never pass vault ref names as if they were values.

## 6. Self-managing TTLs with `scopegate_list_capabilities`

Before a long task, inventory yourself:

```json
{
  "agentId": "kimi-code",
  "active_grants": [
    { "id": "3f6b…", "capability": "github:write:myorg/myrepo", "remaining_seconds": 412 }
  ]
}
```

- If the capability you need is listed with comfortable `remaining_seconds`,
  skip the request — you are already covered.
- If it is about to expire mid-task, re-request the SAME capability (with a
  `reason`) *before* the tool call that would fail; an expired grant makes the
  next proxied call re-evaluate policy from scratch.
- If it is missing, request it. Never assume yesterday's grant survives.

## 7. Common agent mistakes (and the fix)

- **Asking for `*:*` or `github:*` "to be safe".** No sane rule matches it;
  you get `no_rule` or `ceiling_blocked`, and broad proposals get rejected by
  the human. Fix: name the exact resource; use globs only at the tail
  (`github:write:myorg/*`).
- **Ignoring `next_step` / `instructions`.** These fields are the protocol
  telling you the one correct move (`propose_policy`, back off, hand an
  `approve` command to the human). Read them before acting.
- **Retry loops.** Denied is denied; looping only trips
  `capability_rate_limited` ("Back off and retry… — do NOT loop requests")
  and burns your window for legitimate requests.
- **Re-asking with a different/broader capability after a deny or while
  pending.** Forbidden — it creates noise in the human's queue and resets
  your approval. Same string, always.
- **Malformed `ttl`.** `600`, `1h30m`, `10 minutes` → `invalid_ttl`. Strict
  format: `<n>s`, `<n>m`, `<n>h` (`30s`, `10m`, `1h`).
- **Omitting `reason`.** It is a required argument; the call errors out
  before evaluation.
- **Asking the human for a token in chat.** Never. `scopegate secret add
  <ref>` in THEIR terminal is the only path for secrets.
- **Editing `policies.yaml` or the approval files yourself.** Out of bounds —
  your only write path is `scopegate_propose_policy`.
