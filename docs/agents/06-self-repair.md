# 06 — Self-Repair Playbook

How to recover from any ScopeGate failure on your own. The loop is always the
same: **symptom → `scopegate_diagnose` → action**. Escalate to the human ONLY
in the cases documented below — everything else heals by itself or by you.

The only two things a human ever does in this system:

1. Deposit secrets: `scopegate secret add <ref>` (in THEIR terminal).
2. Decide escalations: `scopegate approve <id>` / `scopegate deny <id>` /
   `scopegate policies accept <n>`.

OAuth re-authorization (`scopegate auth login <upstream>`) is also human-only:
it is a device-code flow that needs their browser.

## 1. The rule: diagnose FIRST

On ANY tool or upstream error — a failed call, an auth error, a timeout, an
empty tool list — call `scopegate_diagnose` before doing anything else. It
takes no arguments.

What it does for you (all automatic, it never rejects):

- Probes every enabled upstream with a bounded liveness check (`listTools`,
  10 s timeout).
- **Drops broken connections**, so your next call reconnects with
  freshly-injected credentials (self-heal).
- For `oauth2` upstreams, reports the refresh daemon's health and, when the
  grant is dead, the literal human instruction in `action_required`.

Response shape (per upstream):

```json
{
  "upstreams": {
    "github": { "ok": true, "tools": 42, "mode": "minted:github_app" },
    "huly": {
      "ok": true,
      "tools": 8,
      "mode": "fallback:injection",
      "oauth": {
        "state": "needs_reauth",
        "token_expires_in_s": 0,
        "consecutive_failures": 0
      },
      "action_required": "run in your terminal: scopegate auth login huly"
    }
  }
}
```

Fields: `ok` / `error` (liveness), `tools` (count), `mode`
(`none` | `minted:<provider>` | `fallback:injection`), `oauth.state`
(`ok` | `backoff` | `circuit_open` | `needs_reauth` | `unknown_expiry`),
`action_required` (present ONLY when a human must act — relay it verbatim).

## 2. What already heals without you

Do not reinvent these — they are built into the gateway:

- **Transparent retry.** Every tool call gets up to 3 total attempts with
  linear backoff (250 ms, 500 ms). On failure the connection is dropped and
  re-established with fresh credentials. In-band upstream errors (MCP
  `isError` results) are returned, NOT retried.
- **Tolerant startup.** One dead upstream never blocks the gateway; the rest
  come up normally.
- **Bounded connect.** A hung upstream times out after 10 s
  (`SCOPEGATE_CONNECT_TIMEOUT_MS`), it cannot stall anything.
- **OAuth renewal.** The daemon renews tokens proactively (at ~80% of TTL)
  and does ONE synchronous refresh on a 401 mid-call. Retryable failures back
  off exponentially (5 s → 15 min); 5 consecutive failures open a circuit.

## 3. Decision tree by symptom

### 3.1 A call failed once, then worked — transient upstream failure

Diagnose shows `"ok": true`. **Action: nothing.** The proxy already reconnected
and retried for you. Continue your work.

### 3.2 OAuth 401 / expired token

Diagnose shows the upstream's `oauth.state`:

- `ok`, `backoff`, `circuit_open`, `unknown_expiry` → the daemon owns it.
  **Retry your call once** with the same arguments.
- `needs_reauth` (with `action_required`) → the grant is dead; only a human
  can re-authorize. Calls fail fast with:
  `upstream '<name>' requires human re-authorization — run in your terminal: scopegate auth login <name> (then call scopegate_diagnose)`

Tell the human exactly:

> The OAuth session for `<upstream>` expired and needs re-authorization.
> Run in your terminal: `scopegate auth login <upstream>` (a device-code flow
> opens in your browser). Tell me when done.

After they confirm: `scopegate_diagnose` (state should be back to `ok`), then
retry the SAME call. If you see
`... — OAuth call still failing after a token refresh + single retry. Call scopegate_diagnose.`
the gateway already refreshed and retried once — diagnose, and if it persists,
report it (§5).

### 3.3 `waiting_for_secrets` (from `scopegate_register_upstream`)

The upstream is registered but its secretRef is not in the vault yet. The
response carries the exact instruction:

```json
{
  "registered": "grafana",
  "status": "waiting_for_secrets",
  "action_required": "Ask the human to run in their terminal: scopegate secret add grafana_token  — then call scopegate_diagnose."
}
```

Tell the human: **"Run in your terminal: `scopegate secret add <ref>`"** — one
line per missing ref. NEVER ask them to paste the value in chat: the command
stores it in the encrypted vault, outside your context. After they confirm,
`scopegate_diagnose` → the `<name>__*` tools are live.

### 3.4 Capability denied

- Error `Capability '<upstream>:call:<tool>' not granted. Call scopegate_request_capability first ...`
  → call `scopegate_request_capability` with that SAME capability and a
  one-line `reason`.
- `{ "granted": false, "code": ..., "next_step": "Call scopegate_propose_policy ..." }`
  → no rule covers it. Call `scopegate_propose_policy` with `match` +
  `justification`, and tell the human a proposal awaits
  `scopegate policies review` / `scopegate policies accept <n>`.
- `code: "ceiling_blocked"` → hard limit. Do NOT retry with broader scope.
  Ask a human to review `policies.yaml`.
- `{ "status": "pending_human_approval", "approval_id": "..." }` → **STOP that
  line of work** (approval is a wall, not a delay). Tell the human:
  `scopegate approve <approval_id>` (or `scopegate deny <approval_id>`).
  Do NOT poll, do NOT retry with a different capability or broader scope.
  Once approved, call `scopegate_request_capability` again with the SAME
  capability.

### 3.5 Rate limited

```json
{ "granted": false, "code": "capability_rate_limited",
  "reason": "... Back off and retry in ~42s — do NOT loop requests." }
```

The sliding window (default `30/m` for `scopegate_request_capability`,
tunable via `limits.rate_limit`) is full. **Wait the `~Ns` from `reason`,
then retry once.** This is not an error — plan fewer capability requests.

### 3.6 Suspended or revoked — security containment

Every request denied with `Agent '<id>' is SUSPENDED: ...` or
`Agent '<id>' was REVOKED from ScopeGate Cloud ...`. This is fail-closed
containment (honeytoken trip or fleet revocation), not a malfunction.

**STOP. Do not retry a single call. Do not work around it.** Report to the
human immediately (§5): they investigate `audit.jsonl`
(`honeytoken_triggered` / `agent_revoked`), rotate the exposed credential if
any, and only then clear the state — remove the agent's entry under
`suspended` in `~/.scopegate/honeytoken-state.json`, or remove
`~/.scopegate/cloud-revoked.json`. No restart is needed; the next request
picks it up.

### 3.7 Connection timeout

`connect to upstream '<name>' timed out after 10000 ms` — the upstream is slow
or down. `scopegate_diagnose`: if it now shows `"ok": true`, retry your call
once. If it still shows `"ok": false` with a connect error, the problem is on
the upstream's side — nothing local to fix. Report it (§5) and move on to
work that does not need that upstream.

### 3.8 The gateway itself does not respond

Your ScopeGate tool calls fail at the transport level (server unreachable).

- Run `scopegate status` in the shell: it prints the config, vault refs, and
  a fresh per-upstream health probe (`✓ name (N tools)` / `✗ name — error`).
  This validates config and credentials end-to-end from a new process.
- **stdio mode** (default): the harness owns the gateway as a child process.
  You cannot restart it yourself — tell the human: "The ScopeGate gateway
  process is down. Please restart this agent session (it relaunches the
  gateway), after checking `scopegate status`."
- **http mode** (`scopegate start --http`): probe it directly —
  `curl -s http://<host>:<port>/health` is unauthenticated and returns
  `{ "status": "ok", "uptime_s": ..., "upstreams": <connected count> }`.
  A `401` on `/mcp` means you are missing
  `Authorization: Bearer <SCOPEGATE_HTTP_TOKEN>`. If nothing listens, ask the
  human to restart: `scopegate start --http --port <port> --host <host>`
  (with `SCOPEGATE_HTTP_TOKEN` set in the environment).
- Stack traces never reach you — they go to the gateway's **stderr**, for the
  human operator. Mention that when escalating.

## 4. What you must NEVER do

- **No retry loops.** Calls are already bounded (3 attempts); the rate
  limiter explicitly forbids looping. One diagnose + one retry, then act or
  report.
- **No scope escalation.** A denied or pending capability is never a reason
  to ask for a broader one or a differently-worded one.
- **No secrets in chat.** Never ask for, accept, or forward a secret value.
  The only path is the human running `scopegate secret add <ref>`.
- **No hand-edits.** Never edit `policies.yaml`, `config.json`, or any file
  under `~/.scopegate/` yourself. Proposals go through
  `scopegate_propose_policy`; only `scopegate policies accept <n>` writes
  `policies.yaml`. You cannot approve your own escalations, by design.
- **No retries while suspended/revoked.** Containment is deliberate.
- **No killing/restarting the gateway on your own** in stdio mode — that
  process belongs to the harness.

## 5. Reporting to the human when all else fails

Escalate only after: `scopegate_diagnose` ran, one bounded retry happened, and
no `action_required` path remains. Use this format:

```text
SCOPEGATE FAILURE REPORT
- Goal blocked:      <what you were trying to do, one line>
- Failing tool:      <upstream>__<tool>
- Error (verbatim):  <exact error message>
- Diagnose output:   <paste the FULL scopegate_diagnose JSON>
- Self-repair done:  <e.g. "diagnose ×2, retried once after reconnect">
- Needs from you:    <e.g. "run scopegate auth login huly" /
                     "run scopegate secret add <ref>" /
                     "upstream X appears down — check the service" /
                     "restart the agent session / scopegate start">
```

Attach, never summarize away, the diagnose JSON — it is the operator's ground
truth (they can cross-check with `scopegate status` and
`scopegate audit query --kind tool_call`).

## See also

- `./03-tools-reference.md` — full argument/response reference for
  `scopegate_diagnose` and the other management tools.
