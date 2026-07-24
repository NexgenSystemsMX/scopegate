# 05 — Policies: how to request well and propose new rules

`policies.yaml` is the contract between you (the agent) and the human who owns
the machine. It decides which capabilities you get, with what TTL, and which
ones escalate to a human. **You never edit this file.** You read it to know
what is already allowed, you request capabilities against it, and when nothing
matches you *propose* a new rule that a human reviews.

Write asymmetry, non-negotiable:

- **Humans** edit `~/.scopegate/policies.yaml`, run `scopegate secret add`,
  `scopegate approve <id>`, and `scopegate policies accept|reject`.
- **You** call `scopegate_request_capability` and `scopegate_propose_policy`.
  Nothing you do can widen your own access.

## 1. Anatomy of `policies.yaml`

Annotated from the shipped `policies.example.yaml`:

```yaml
version: 1                    # REQUIRED, must be exactly 1 — anything else fails load (fail-closed).

limits:                       # OPTIONAL global hard ceilings (see §4).
  max_ttl: 1h                 #   No grant ever exceeds this, whatever anyone asks for.
  deny:                       #   Globs blocked BEFORE any auto_approve rule is evaluated.
    - "aws:*:production"      #   Fail-closed; audit records `ceiling_blocked`.
  rate_limit: 30/m            #   Sliding window on scopegate_request_capability, per agent.
  approval_ttl: 10m           #   How long a pending human-approval request lives (default 10m).

agents:
  agent-luis-nexgen:          # Your agent id (config.agentId). Exact name match wins…
    default_ttl: 15m          # TTL ceiling for rules that don't set their own `ttl`.
    limits:                   # OPTIONAL per-agent ceilings — WIN over the global ones.
      max_ttl: 30m
      deny: ["stripe:write:*"]
    capabilities:             # Rule list, evaluated top to bottom — FIRST MATCH WINS.
      - match: "github:call:{get_*,list_*,search_*}"   # picomatch braces: read-only tools.
        auto_approve: true                             #   granted silently, ceiling 15m (default_ttl).
      - match: "github:call:*"                         # everything else on github…
        auto_approve: true
        ttl: 5m                                        #   …but with a shorter 5m ceiling.
      - match: "support:call:get_customer"
        auto_approve: true
        ttl: 5m
        redact: [pii]                                  # proxied RESPONSES are masked (see §5).
      - match: "aws:*:production"                      # placed BEFORE any broader auto rule —
        require: human_approval                        #   matching stops here and escalates.
  "*":                        # …otherwise the "*" fallback applies to any agent without an entry.
    default_ttl: 5m
    capabilities:
      - match: "*:call:{get_*,list_*,search_*,read_*}"
        auto_approve: true
```

Rule fields (anything else is rejected at load time — unknown keys fail
closed, so a typo in the human's file breaks load loudly, never silently):

| Field | Meaning |
|---|---|
| `match` | Required. picomatch glob over the capability string. |
| `auto_approve` | `true` → grant without human involvement. |
| `ttl` | Per-rule TTL ceiling (`<n>s`, `<n>m`, `<n>h`). Beats `default_ttl`. |
| `require` | Only `human_approval` is supported. Escalates instead of granting. |
| `redact` | List of categories to mask in proxied responses (`pii`, `email`, `phone`, `card`, `aws_access_key`). |

The file is hot-reloaded (debounced ~250 ms): a human edit is live in under a
second. An invalid edit keeps the **last-good** policy set and is audited as
`policy_reload_error`; a missing file means deny-all. You cannot break it and
you cannot exploit a broken one.

## 2. How matching works

- A capability is a string `<upstream>:<action>:<resource>`. MCP tool calls
  map to `<upstream>:call:<toolName>` — e.g. calling `merge_pull_request` on
  the `github` upstream is `github:call:merge_pull_request`.
- Your agent entry is your exact agent id; if absent, the `"*"` fallback
  applies; if neither exists you get `no_policy` — ask a human to add you, or
  propose rules (§6) so the human has something to accept.
- Globs are picomatch: `*` within a segment, `**` across segments, and brace
  expansion `{get_*,list_*}`. Quote patterns in YAML.
- Rules are evaluated in order, **first match wins** — a `require` rule placed
  after a broad `auto_approve` rule is dead. This is why examples put
  `require: human_approval` rules *before* the wildcard ones.
- `limits.deny` globs are checked **before** any rule. They always win.

Practical consequence: before requesting, compute the exact capability string
and request that — not a broader one "just in case". A denied broad request
teaches you nothing a narrow one wouldn't, and `deny` hits are audited.

## 2b. `when:` — guards over the call's arguments

A rule may carry a `when` clause that constrains the *arguments of the tool
call*, not just the capability string:

```yaml
capabilities:
  - match: "github:call:create_or_update_file"
    auto_approve: true
    ttl: 5m
    when: { branch: "kimi/*" }        # auto-approve ONLY on kimi/* branches
  - match: "github:call:create_or_update_file"
    require: human_approval           # everything else (main, release/*) escalates
```

- String values are picomatch globs; numbers and booleans match by strict
  equality. Every entry must match.
- A call **without** the guarded argument (or with no args at all) never
  satisfies a `when` — the rule is skipped (fail-closed) and evaluation
  continues with the next rule.
- The guard sticks to the issued grant: a grant minted for `branch: kimi/x`
  does **not** cover a later call with `branch: main` — that call re-evaluates
  and escalates.
- `when` also applies to approvals: a human approves a guarded request for the
  exact arguments shown, and the materialized grant keeps the guard.

Use it for branch/environment/severity-shaped decisions. What you cannot
express with args still belongs in separate capabilities or `require` rules.

## 3. TTLs: you can shorten, never extend

Resolution for an auto-approved request:

```
ceiling  = rule.ttl ?? agent.default_ttl ?? 15m      # built-in default is 15 minutes
grantTTL = min(requested_ttl, ceiling, limits.max_ttl)
```

- Omit `ttl` in your request → you get the full ceiling (internally your
  request is `MAX_SAFE_INTEGER`, clamped down).
- Ask for less than the ceiling → you get exactly what you asked. Ask for
  more → silently clamped to the ceiling. **Shorten yes, extend never.**
- `ttl` must be `<n>s`, `<n>m` or `<n>h`. Garbage like `"1 day"` is denied
  with `invalid_ttl` — fix the string, don't retry it.
- Grants persist on disk and expire on their own. Re-requesting the same
  capability while a covering grant is live returns the existing grant's
  remaining TTL — it does **not** stack or renew. Request again only after
  expiry.
- `limits.max_ttl` is the absolute ceiling over everything, including grants
  materialized from a human approval. A human saying "yes" cannot push a
  grant past `max_ttl` either.

Ask for the shortest TTL that covers your task. It is faster for a human to
trust an agent that requests `5m` than one that always takes the ceiling.

## 4. Hard limits and rate limit — why they exist

`limits` exist because of prompt injection. If hostile text in an issue, a web
page, or a log convinces you to request `aws:*:production` or `*:*`, the
policy engine is the layer that says no even when you say yes:

- `deny` globs are evaluated before every `auto_approve` rule (fail-closed).
  A hit returns code `ceiling_blocked` with: *"Hard limits are non-negotiable
  — do NOT retry with broader scope"*. Take that literally: do not
  rephrase, reslice, or retry. Tell the human which `deny` glob you hit.
- `rate_limit` (format `<n>/s`, `<n>/m`, `<n>/h`; default `30/m`) throttles
  `scopegate_request_capability` per agent in a sliding window. Exceeding it
  returns `capability_rate_limited` with a backoff hint. Back off and batch
  your work around the grants you already hold — never loop requests.
- Per-agent `limits` override global ones; otherwise global applies.

These ceilings are not yours to negotiate: only a human editing
`policies.yaml` changes them, and `scopegate_propose_policy` cannot propose
them (§6).

## 5. `redact: [pii]`

A rule may carry `redact` categories. The grant issued from that rule records
them, and every proxied tool **response** under that grant is masked after the
upstream answers: `pii` expands to `email`, `phone`, `card` (Luhn-validated),
and `aws_access_key`, replaced with `[REDACTED:<category>]`.

This is a best-effort heuristic, not a DLP guarantee — conservative matchers
keep false positives low, and the audit log records replacement **counts**
only, never content. For you: if responses under a capability arrive masked,
that is policy working as intended, not a bug to route around. You cannot
propose `redact` yourself; mention it in your justification if you believe a
rule should have it.

## 6. Proposing a new rule: `scopegate_propose_policy`

When a request is denied with `no_rule` or `no_policy`, propose the rule you
need. A human merges it — or not.

```json
{
  "match": "huly:call:create_issue",
  "ttl": "10m",
  "justification": "EPIC-14 requires filing one Huly issue per migrated ticket; 10m covers a batch run."
}
```

Fields: `match` (required, compilable picomatch glob), `ttl` (optional,
strict `<n>s|m|h`), `justification` (required, non-empty). **Nothing else is
agent-settable.** Sending `require: null`, `auto_approve`, `limits`, `redact`,
or any extra key rejects the whole call with *"field '<k>' is not
agent-settable"*. You can only ever propose rules that auto-approve something
narrower than a human would — the accept path hard-codes
`auto_approve: true` on what you send (§7).

What happens next:

1. The proposal is validated, deduplicated (identical pending
   `agentId + match + ttl` returns `deduped: true` without queuing again),
   and linted against hard limits.
2. It is appended to `~/.scopegate/policies.pending.yaml` with status
   `pending_human_review` and audited as `policy_proposed`.
3. The tool result tells you plainly: **"It has NO effect until then."** Do
   not retry the denied capability expecting the proposal to have helped.
4. The human runs `scopegate policies review`, then
   `scopegate policies accept <n>` or
   `scopegate policies reject <n> --reason "..."`. Accept appends
   `{match, ttl?, auto_approve: true}` to your agent's `capabilities` in
   `policies.yaml` (comments preserved, schema re-validated, atomic write) and
   hot-reload makes it live in under a second.
5. If your proposal collided with `limits.deny` or exceeded `max_ttl`, it is
   queued with `lint: "conflicts_with_limits"` — the human sees the flag, and
   accepting it will **not** make it effective. Check limits first; a linted
   proposal is a wasted round-trip.

Writing a justification a human accepts fast:

- State the concrete task ("filing issues for EPIC-14"), not a vague wish.
- Keep `match` minimal — one tool or a tight brace group, one upstream.
- Keep `ttl` short and say why it suffices.
- One capability per proposal. Ten small proposals are reviewable; one
  `*:*:*` proposal is a reject.

## 7. Good and bad proposals, with expected results

Good — narrow, short, explained:

```json
{ "match": "railway:call:list_services", "ttl": "5m",
  "justification": "Read-only inventory needed to map services before the migration run." }
```

→ `{ queued: true, deduped: false, pending_file: ".../policies.pending.yaml", note: "A human must review…" }`.
A human accepts with `scopegate policies accept 1`; you then
`scopegate_request_capability` and proceed.

Bad — too broad:

```json
{ "match": "*:*:*", "justification": "I need full access to do my job." }
```

→ Queued (it validates), but any human reviewing it rejects it:
`scopegate policies reject 2 --reason "scope it to one upstream and tool set"`.
You burned a review cycle. Propose `github:call:{get_*,list_*}` style instead.

Bad — forbidden fields:

```json
{ "match": "aws:*:production", "require": null, "justification": "deploy" }
```

→ Tool error: `Proposal rejected: field 'require' is not agent-settable…`.
You cannot propose away an escalation; `require: human_approval` rules mean
the human decides per request via `scopegate approve <id>`.

Bad — conflicts with hard limits:

```json
{ "match": "aws:*:production", "ttl": "2h", "justification": "weekly deploy window" }
```

→ Queued with `lint: "conflicts_with_limits"` (deny glob overlap and/or
`ttl > max_ttl`). The human is told accepting will not make it effective.
The honest move is to request the capability, take the
`escalation: "human_approval"` response, and ask the human to run
`scopegate approve <approvalId>` — one-shot, bounded by `max_ttl`.

---

See also: `./03-tools-reference.md` for the full MCP tool schemas
(`scopegate_request_capability`, `scopegate_propose_policy`, …).
