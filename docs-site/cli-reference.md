# CLI Reference

Binary: `scopegate` (Node ≥ 20). Global flags: `--version`, `--help`.
Errors print one actionable line to stderr and exit non-zero; stack traces
only at `SCOPEGATE_LOG_LEVEL=debug`.

## `scopegate init [--dry-run] [--harness <id>]`

Idempotent setup, safe to re-run:

- creates `~/.scopegate/` (vault, master key, default `policies.yaml`)
- detects harnesses: `claude-code`, `kimi-code`, `cursor`, `opencode`,
  `mcp-json`
- migrates each detected MCP behind the gateway, moving plaintext secrets
  (env vars, auth headers) into the vault and rewriting the harness config to
  a single `scopegate start` entry (backup: `*.pre-scopegate.bak`)
- `--dry-run`: print the plan without writing harness configs
- `--harness <id>`: restrict detection/migration to one harness

## `scopegate start`

Run the gateway MCP server on stdio. Launched by the harness, not by hand.

## `scopegate secret add <ref>` · `ls` · `rm <ref>`

Vault management — the human-only path. `add` reads the value from a hidden
prompt or piped stdin, never argv. `ls` prints ref names only.

## `scopegate status`

Prints agentId, upstreams, vault ref names and per-upstream health
(`✓ name (N tools)` / `✗ name — error`).

## `scopegate audit verify`

Verifies sequence continuity, the hash chain and the Ed25519 signature of
every event in `audit.jsonl`. Exit 1 names the first invalid event's seq.

## `scopegate audit query [--agent <id>] [--kind <k>] [--since <iso>] [--until <iso>] [--limit <n>]`

Answers "what did this agent/token touch in this window"; matching events as
JSONL on stdout (e.g. `--kind tool_call`, `--kind secret_ref_used`).

## `scopegate audit reindex`

Rebuilds the derived `audit-index.json` snapshot from `audit.jsonl`
(verifies the trail first).

## `scopegate auth login <upstream>`

OAuth device-code re-authorization for an `oauth2` upstream — human,
out-of-band. The daemon refreshes tokens automatically afterwards.

## `scopegate vaultd [--socket <path>]`

Run the vault as an isolated process (unix socket / Windows named pipe). Use
with `SCOPEGATE_VAULT_MODE=daemon` (or `auto`, which prefers the daemon when
reachable).

## `scopegate vault rotate-key [--backend <name>]`

Re-encrypt the vault with a fresh master key. `--backend`:
`file | dpapi | keychain | secret-service` — migrates the master-key storage
backend when given.

## `scopegate rollback [--harness <id>]`

Restore harness configs from their `*.pre-scopegate.bak` backups.

## `scopegate cloud serve [--port <n>] [--home <dir>]`

Run the ScopeGate Cloud control plane (EPIC-10): multi-tenant API under `/v1`
(team enroll, signed team policies, central audit ingest with per-event
signature verification, fleet revocation feed, billing usage) plus a minimal
web dashboard at `/`. State lives under `--home` (default
`~/.scopegate-cloud`); admin endpoints take `Authorization: Bearer
$ADMIN_TOKEN` (default `dev-admin-token` — set it in any real deployment).
Prints `SCOPEGATE_CLOUD_LISTENING port=<n>` when ready.

## `scopegate cloud enroll --cloud <url> --token <enrollToken> [--agent <id>]`

Enroll this gateway into a ScopeGate Cloud control plane (M13): exchanges the
one-time enroll token for the gateway's credentials and writes `cloud.json`
(0600) — from then on the gateway syncs team policies, central audit and
revocation with the cloud. The printed JSON never includes the agent secret.
Backend: `SCOPEGATE_CLOUD_DATABASE_URL` (Postgres) or the JSON file store by
default; audit retention via `SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS`.

## Approvals: `scopegate approve <id>` · `deny <id>` · `policies`

Human-side commands for the approval flow: when `request_capability` returns
`pending_human_approval`, the response text points the human at
`scopegate approve <approval_id>` (or `deny`). Pending human-approval
requests live in `approvals.pending.jsonl`, agent policy proposals in
`policies.pending.yaml`. (These subcommands ship with the approval-channel
work — see [EPIC-08](../../docs/Implementacion/EPIC-08-human-approval-channels.md);
the gateway-side `pending_human_approval` contract is already live.)

## `scopegate git-credential`

Native git credential-helper — configure once with
`git config --global credential.helper "!scopegate git-credential"` and every
`git clone/fetch/push` over HTTPS gets a freshly minted GitHub App installation
token straight from the gateway (the token goes to git, never through the
agent's context, never into `.git/config`). The capability
`git:credential:<repo/path>` is evaluated by the same policy engine
(auto-approve per repo glob, `require: human_approval` for the rest); a denial
exits 1 with an actionable stderr message that git surfaces. Non-GitHub hosts
and store/erase are silent no-ops. Every mint is audited
(`git_credential_minted`). Requires a `github_app` upstream in `scopegate.yaml`.

## `scopegate inject --ref <r> --out <f> [--template|--template-file]` · `--refresh <f>`

Materialize a vault secret into a legacy CLI config file (governed exception):
`vault:inject:<ref>` requires human approval BY DEFAULT (a policy rule must
explicitly auto_approve it). Atomic 0600 write with the previous file backed up
to `<out>.bak`; the audit stores only the rendered content's sha256. A sidecar
manifest (`<out>.scopegate.json`) powers `--refresh` — re-materialize after the
secret rotates (the vault is the source; the file is a view). Output is one
JSON line; exit 0 materialized, 1 denied/error, 2 pending approval.

## `scopegate honeytoken plant <name> [--agent <id>] [--upstream <n>]`

Plant a decoy credential in the vault as `canary:<name>` (the value prints
once — spread it wherever a leak would prove exfiltration). Any use of the
decoy as a credential triggers a honeytoken alert and surgical revocation.

## Exit codes

`0` success · `1` error (e.g. audit tamper, vaultd unreachable) · e2e scripts
use `2` for timeouts.
