# ScopeGate — Agent Documentation

ScopeGate is an **ephemeral-credentials gateway** for coding agents. It sits
between your agent runtime and every external service (MCP servers, cloud
APIs, SaaS tools). Real secrets live in an AES-256-GCM encrypted local vault
and are injected only at the outbound hop — they never enter your context.

**You never hold secrets; you hold capabilities.** A capability is a
short-lived, minimum-scope grant minted by the gateway's policy engine —
scoped to one task, expiring in minutes. Capability ≠ credential: what leaks
from a model context is nearly worthless; what the vault keeps never touches
the context at all.

Everything you need is exposed as twenty-one MCP tools
(`scopegate_request_capability`, `scopegate_list_capabilities`,
`scopegate_register_upstream`, `scopegate_diagnose`,
`scopegate_propose_policy`, `scopegate_vault_status`) plus the `scopegate`
CLI. You install, configure and operate all of it yourself.

## Who this documentation is for

Any autonomous coding agent on any MCP-capable harness: **Claude Code, Kimi
Code, Cursor, OpenCode**, or any other client that speaks MCP (`.mcp.json`).
No prior knowledge of ScopeGate is assumed. If you have never seen ScopeGate
before, read guide 01 first and follow it literally; treat the rest as
reference material you pull in on demand.

## How to consume these docs

| Document | Read it when |
|---|---|
| [01 — Quickstart: self-install](./01-quickstart-self-install.md) | First contact. ScopeGate is not installed, or you are not sure it is. |
| [02 — Protocol](./02-protocol.md) | Before your first privileged action. The operating rules of the capability model. |
| [03 — Tools reference](./03-tools-reference.md) | Before calling any `scopegate_*` tool — exact parameters and response shapes. |
| [04 — Connectors](./04-connectors.md) | When connecting a service: huly, github, railway, cloudflare, google, or any custom MCP upstream. |
| [05 — Policies](./05-policies.md) | When a capability is denied, or before proposing a policy change. |
| [06 — Self-repair](./06-self-repair.md) | On any auth or connection error — before telling the human it failed. |
| [07 — Security rules](./07-security-rules.md) | Always. The non-negotiables. Re-read whenever unsure. |
| [08 — Long tasks](./08-long-tasks.md) | Multi-hour work: task leases, grant renewals, idempotent writes, the end-to-end pattern. |

## The eight guides

- **01 — Quickstart: self-install** — detect, install and initialize
  ScopeGate non-interactively (`npm i -g scopegate`, `scopegate init`),
  verify with `scopegate status`, and hand off the single human step.
- **02 — Protocol** — the capability lifecycle: request → grant → use →
  expire; how to think in capabilities instead of credentials; what
  `pending_human_approval` means.
- **03 — Tools reference** — all twenty-one `scopegate_*` MCP tools: parameters,
  return shapes, error cases, copy-paste JSON payloads.
- **04 — Connectors** — the five native connectors (huly, github, railway,
  cloudflare, google), the signed registry, and how to register any custom
  upstream MCP with `scopegate_register_upstream`.
- **05 — Policies** — how the policy engine decides grants (TTL limits,
  scopes, `auto_approve` vs `require: human_approval`, hard `deny` globs)
  and how to propose changes with `scopegate_propose_policy`.
- **06 — Self-repair** — `scopegate_diagnose` playbooks: expired OAuth,
  missing secretRef, unreachable upstream; when and how to escalate to the
  human with the exact command.
- **07 — Security rules** — the invariants you must never break: no secrets
  in chat, no self-approval, minimum scope, full audit trail.
- **08 — Long tasks** — multi-hour work behind the gateway: task leases
  (`scopegate_open_task_lease`), grant renewals, idempotent writes and the
  end-to-end pattern.

## The self-configuration manifesto

You — the agent — can install, configure and operate ScopeGate **100% on
your own**. Installation, harness migration, upstream registration,
capability requests, policy proposals, diagnosis and self-repair are all
agent-executable, non-interactive and idempotent.

The **only two human actions** in the entire system are:

1. **Depositing secrets.** The human runs `scopegate secret add <ref>` in
   THEIR terminal. The value goes straight into the encrypted vault via a
   hidden prompt or piped stdin. It never passes through chat, argv, logs,
   or your context. **NEVER ask a human to paste a secret in the chat** —
   ask them to run that command instead.
2. **Approving escalations.** The human runs `scopegate approve <id>` (for
   capability requests that return `pending_human_approval`) or
   `scopegate policies accept <n>` (for policy rules you proposed). You
   cannot approve your own escalations — that write asymmetry *is* the
   security model.

Everything else is yours to do.

## Golden rules (TL;DR)

- Never ask for, receive, store, or repeat a secret value.
- Request minimum scope and shortest TTL, always with a one-line reason.
- `pending_human_approval` means STOP, not retry — hand the human the exact
  command from the response.
- Diagnose before reporting failure: call `scopegate_diagnose` first.
- Never edit `policies.yaml` yourself. Propose, don't modify.
