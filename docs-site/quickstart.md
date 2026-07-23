# Quickstart

Agent-executable: every step is a command an agent (or you) can run.
Target: first proxied tool call in < 90 seconds. Requirements: Node.js ≥ 20.

## 1. Install

```bash
npm install -g scopegate
# or: curl -sSL https://get.scopegate.dev | sh -s -- --yes
```

## 2. Init (idempotent, non-interactive)

```bash
scopegate init
```

`init` creates `~/.scopegate/` (encrypted vault, master key, default
policies), detects your harness configs, **migrates existing MCP servers
behind the gateway** (plaintext env vars and auth headers move into the
vault; configs keep only refs), and rewrites the harness config so
`scopegate` is the single MCP entry point. Originals are backed up as
`*.pre-scopegate.bak`.

Preview without writing anything:

```bash
scopegate init --dry-run
```

## 3. Deposit a secret (human, out-of-band)

Secrets never pass through chat or argv:

```bash
scopegate secret add github_pat        # hidden prompt
echo "$TOKEN" | scopegate secret add notion_token   # or piped
```

## 4. Restart the agent session

The harness now launches `scopegate start` as its only MCP server. The agent
sees upstream tools as `<upstream>__<tool>` plus the `scopegate_*`
management tools.

## 5. First capability + tool call (agent side)

The agent does this by itself (see [Agent Protocol](agent-protocol.md)):

```
scopegate_request_capability  { capability: "github:call:list_issues", reason: "triage issues" }
→ { granted: true, expires_in_seconds: 900 }
github__list_issues { ... }   # token injected at the outbound hop, never exposed
```

When a rule says `require: human_approval`, the response is
`status: "pending_human_approval"` with an `approval_id`; the human runs
`scopegate approve <approval_id>` and the agent retries the SAME capability.

## 6. Check health anytime

```bash
scopegate status            # config + vault refs + upstream liveness
scopegate audit verify      # hash chain + Ed25519 signatures intact
```

## Undo

```bash
scopegate rollback          # restores *.pre-scopegate.bak harness configs
```

The vault, policies and audit log under `~/.scopegate/` are left untouched;
delete the directory manually if you want a full removal.
