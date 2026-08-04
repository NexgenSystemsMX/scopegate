---
name: scopegate
description: >
  Use this skill whenever you (the agent) need credentials, API keys, tokens,
  or access to an MCP/API — or when a connection fails with auth errors.
  ScopeGate is the credentials gateway: you never handle secret values;
  you request ephemeral capabilities instead. Also use it to onboard new
  services ("connect X", "add the Y MCP") and to self-repair broken
  connections mid-session.
---

# ScopeGate — Agent Protocol

You operate behind ScopeGate, a gateway that owns all credentials. You never
see, ask for, or handle secret values. You request **capabilities** instead.

## Rules (non-negotiable)

1. **NEVER ask the user to paste an API key, token, or password in chat.**
   If a secret is needed, tell them to run in THEIR terminal:
   `scopegate secret add <ref_name>` — the value goes straight to the
   encrypted vault, outside your context.
2. **Request minimum scope, shortest TTL.** Before privileged work, call
   `scopegate_request_capability` with a one-line reason. If denied, do NOT
   retry with broader scope — call `scopegate_propose_policy` and inform the
   human.
3. **Human approval is a wall, not a delay.** If `request_capability` returns
   `status: "pending_human_approval"` (with an `approval_id`), STOP that line
   of work: inform the human that approval is needed and give them the exact
   command from the response (`scopegate approve <approval_id>` /
   `scopegate deny <approval_id>`). Do NOT retry with broader scope, a
   different capability string, or repeated polling — once approved, call
   `request_capability` again with the SAME capability.
4. **Self-repair before reporting failure.** On any upstream/tool error, call
   `scopegate_diagnose` first; connections re-establish automatically. Follow
   any `action_required` field in the response (e.g. a missing secretRef, or
   `scopegate auth login <upstream>` — an OAuth device-code step that ONLY the
   human can complete in their terminal/browser). Only escalate to the human
   if diagnose still fails.
5. **You cannot approve your own escalations.** Policy proposals go to
   `policies.pending.yaml` for human review. Never edit `policies.yaml`
   directly.

## Setup (you can do this yourself)

If ScopeGate is not installed in the environment:

```bash
npm install -g scopegate   # or: npx scopegate init
scopegate init             # idempotent, non-interactive
```

`init` migrates every existing MCP (and its plaintext secrets) behind the
gateway automatically and rewrites `.mcp.json`. Ask the human to restart the
session afterwards.

## Onboarding a new service (example)

Human: "connect our Grafana MCP"

1. `scopegate_vault_status` → check if a usable secretRef already exists.
2. `scopegate_register_upstream` with:
   `{ name: "grafana", transport: { kind: "http", url: "https://g.example.com/mcp" }, auth: { type: "bearer", secretRef: "grafana_token" } }`
3. If the response says `waiting_for_secrets`, tell the human exactly:
   "Run in your terminal: `scopegate secret add grafana_token`"
4. After they confirm, `scopegate_diagnose` → tools `grafana__*` are live.

## When a human must act

Some steps are human-only by design. Never try to work around them; hand them
to the human with the exact command:

| Situation | What you tell the human |
|---|---|
| `pending_human_approval` from `request_capability` | "This action needs your approval: `scopegate approve <approval_id>`" |
| OAuth session expired / re-auth flagged | "Run: `scopegate auth login <upstream>` (device-code flow in your browser)" |
| `waiting_for_secrets` from `register_upstream` | "Run: `scopegate secret add <ref>`" |
| `action_required` in a `diagnose` response | Relay it verbatim |

## Tool reference

| Tool | Use when |
|---|---|
| `scopegate_request_capability` | Before privileged actions (may return `pending_human_approval`; supports `mode: "once"`, `audience`, `purpose`) |
| `scopegate_list_capabilities` | To check what you can do now / remaining TTL (mode, audience, purpose, status) |
| `scopegate_revoke_capability` | To give up one of YOUR grants early (attenuation; cascade kills delegations/promotions) |
| `scopegate_register_upstream` | Human asks to connect a new service |
| `scopegate_diagnose` | Any auth/connection error (self-repair; check `action_required`) |
| `scopegate_propose_policy` | A needed capability was denied |
| `scopegate_vault_status` | To see which secretRef NAMES exist (never values) |

Keychain notes: a `once` grant authorizes EXACTLY ONE call (claim = use — no
refunds); a grant for another `audience` always needs human approval; `purpose`
is a declarative instruction, never enforced by the engine.

## Full documentation

Deep guides for every topic live in [`docs/agents/`](docs/agents/README.md):
quickstart self-install, the operating protocol, exact tool schemas, the
native connectors (huly, github, railway, cloudflare, google), policies,
self-repair playbooks, and the security rules. Read them when this file is
not enough — start at `docs/agents/README.md`.
