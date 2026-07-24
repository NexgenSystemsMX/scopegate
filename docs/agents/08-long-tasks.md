# 08 — Long tasks: leases, renewals, idempotent writes

How to finish multi-hour tasks (refactors, migrations, iterative debugging)
behind ScopeGate without dying mid-way: **task leases** keep your grants alive
under a double budget, and **idempotency keys** make your writes safe to retry.
Read [02 — Protocol](./02-protocol.md) first; the tool shapes live in
[03 — Tools reference](./03-tools-reference.md).

## 1. The problem this solves

Grants expire in minutes; your tasks last hours. The naive failure mode is the
TTL dying at 70% of the task — and if the re-request needs a human, they may
not be there. Retrying writes after a timeout is the other classic: duplicate
issues, double deploys. Both are solved in the gateway, not by you being careful.

## 2. Task leases

A lease groups every grant of one task under **two budgets**:

- **Time** — `max_total` you ask for, clamped by `limits.max_lease_total`
  (default **4h**). This is a hard, non-negotiable ceiling exactly like
  `max_ttl`: the ceiling always wins, it never extends.
- **Writes** — `max_writes` (default **200**). Every lease-covered write
  consumes one unit; exhausted budget denies the call with an actionable error.

Open one at task start:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "scopegate_open_task_lease",
              "arguments": { "goal": "Migrate the billing module",
                             "upstreams": ["github", "railway"],
                             "max_total": "3h", "max_writes": 60 } } }
```

```json
{ "lease_id": "f47ac10b-…", "goal": "Migrate the billing module",
  "upstreams": ["github", "railway"], "total_ms": 10800000,
  "deadline_at": "2026-07-23T21:00:00.000Z", "max_writes": 60,
  "next_step": "Request capabilities with lease_id to bind them to this lease; renew them with scopegate_renew_capability before they die." }
```

Then bind your requests with `lease_id` (lease binding applies to NEW grants;
an already-held grant is returned as-is):

```json
{ "capability": "github:write:easyorder/*", "reason": "push the migration", "lease_id": "f47ac10b-…" }
```

Grants bound to the lease come back with `renewable: true`. Two rules,
fail-closed both: the lease must be **live** (open, before `deadline_at`) and
the capability's upstream must be **in scope** (`upstreams: []` means all;
anything else refuses with `lease_error`).

## 3. Renew, don't die

While the lease lives you renew by yourself — sliding TTL, auto-approved:

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
  "params": { "name": "scopegate_renew_capability",
              "arguments": { "grant_id": "<id from scopegate_list_capabilities>" } } }
```

New expiry = `min(now + original ttl, lease deadline, rule ceilings)` — you can
never renew past the lease deadline. Proxied responses warn you when a grant
drops below 20% TTL with a structured `scopegate_notice` (grant_id, expires_in_s,
renewable) — renew on the notice, not on the failure.

`scopegate_list_capabilities` shows the lease itself (goal, status, deadline,
writes used/max) next to your grants. Revoking a lease
(`scopegate cloud` panel, or the operator's policy) drops **every** bound grant
at once — one kill switch per task.

## 4. Idempotent writes

Any proxied call accepts `_sg_idempotency_key`. Generate **one key per
intention** (never per attempt), e.g. `create-issue-billing-migration-2026-07-23`:

```json
{ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
  "params": { "name": "huly__create_issue",
              "arguments": { "title": "Billing migration", "project": "BILL",
                             "_sg_idempotency_key": "huly-create-billing-migration-v1" } } }
```

- First call: executes upstream; the result is cached 24h (the key never
  reaches the upstream).
- Retry with the same key + same args: the cached result is **replayed** — the
  upstream is never called twice (audit records `idempotency_replayed`).
- Same key + different args: explicit `idempotency_key_conflict` error — you
  are reusing a key for a different intention. Mint a fresh one.

Combine with [recall](./03-tools-reference.md#scopegate_recall): "did I already
do this write?" is answered from your own audit before you repeat it.

## 5. The pattern, end to end

1. `scopegate_policy_summary` — what auto-approves, what needs a human.
2. `scopegate_can_i` on anything uncertain — zero side effects.
3. `scopegate_request_plan` for the whole task at once: auto parts are issued
   immediately, guarded parts become ONE aggregated human decision (optionally
   `open_lease` to bind everything to a lease in the same call).
4. Work through lease-bound grants; renew on the 20% notice.
5. Every write carries an idempotency key; every escalation carries
   `execute_on_approval` so a human decision completes the work (see
   [02 §4b](./02-protocol.md)).
6. Oversized results are never a context problem: the gateway truncates them
   to a `result_ref` — page with `scopegate_result_get`, search with
   `scopegate_result_grep`, never re-call for "the rest".
7. After a restart or compaction: `scopegate_recall` to rebuild state — grants,
   writes done, pending approvals, the lease's remaining budget.

Related: [02 — Agent Protocol](./02-protocol.md) · [03 — Tools reference](./03-tools-reference.md) · [05 — Policies](./05-policies.md) · [06 — Self-repair](./06-self-repair.md) · [07 — Security rules](./07-security-rules.md) · [Index](./README.md)
