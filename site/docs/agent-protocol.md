# Agent Protocol

ScopeGate is operated by the agent itself through MCP tools. The canonical
protocol ships as [`SKILL.md`](../SKILL.md) in the npm package — install it as
a skill or reference it from `CLAUDE.md` / `AGENTS.md`:

```markdown
See ./SKILL.md — you operate behind ScopeGate. Never handle secret values;
request capabilities via scopegate_* tools.
```

## The rules (non-negotiable)

1. **Never ask the user to paste a secret in chat.** Secrets go in via
   `scopegate secret add <ref>` from the human's terminal.
2. **Minimum scope, shortest TTL.** Call `scopegate_request_capability` with a
   one-line reason before privileged work.
3. **Human approval is a wall, not a delay.** A
   `status: "pending_human_approval"` response carries an `approval_id` and
   `instructions`: inform the human, hand them the exact command
   (`scopegate approve <approval_id>` / `scopegate deny <approval_id>`), and
   do **not** retry with broader scope — once approved, re-request the SAME
   capability.
4. **Self-repair first.** On any upstream error call `scopegate_diagnose`
   before reporting failure, and follow any `action_required` field (missing
   secret, `scopegate auth login <upstream>` re-auth — both human steps).
5. **Agents propose, humans approve.** Policy proposals land in
   `policies.pending.yaml`; the agent never edits `policies.yaml`.

## Tools

| Tool | Purpose |
|---|---|
| `scopegate_request_capability` | Request `{capability, ttl?, reason}` → grant with TTL, or `pending_human_approval` |
| `scopegate_list_capabilities` | Active grants + remaining TTL |
| `scopegate_register_upstream` | Register an MCP/API upstream (`http` or `stdio`); secret values are rejected — only `secretRef` names |
| `scopegate_diagnose` | Liveness + tool count per upstream; reconnects are automatic |
| `scopegate_propose_policy` | Queue a `{match, ttl?, justification}` rule for human review |
| `scopegate_vault_status` | List secretRef **names** in the vault (never values) |

Capability format: `"<upstream>:<action>:<resource>"`, e.g.
`github:write:easyorder/*`. Proxied tools appear as `<upstream>__<tool>`.

## Onboarding a new service (worked example)

Human: "connect our Grafana MCP" →

1. `scopegate_vault_status` — is `grafana_token` already deposited?
2. `scopegate_register_upstream`:
   `{ name: "grafana", transport: { kind: "http", url: "https://g.example.com/mcp" }, auth: { type: "bearer", secretRef: "grafana_token" } }`
3. Response `waiting_for_secrets` → tell the human:
   "Run in your terminal: `scopegate secret add grafana_token`"
4. `scopegate_diagnose` → `grafana__*` tools live.

## Session lifecycle notes

- OAuth2 upstreams refresh automatically (daemon renews at ~80% of TTL). If a
  refresh token dies, the gateway flags re-auth; the human runs
  `scopegate auth login <upstream>` (device-code) — the agent cannot do this.
- Setup itself is agent-executable: `npm i -g scopegate && scopegate init`
  migrates existing MCPs and their plaintext secrets behind the gateway.
