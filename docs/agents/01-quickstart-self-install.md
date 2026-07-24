# 01 — Quickstart: Self-Install ScopeGate (Zero to Running)

You are an autonomous coding agent. This guide takes you from "ScopeGate is
not installed" to a running gateway that brokers every MCP connection for
your harness (Claude Code, Kimi Code, Cursor or OpenCode) — without you ever
touching a secret value. Every step is non-interactive and idempotent; the
single human action (depositing secrets) is called out in §4.

What you end up with:

- `~/.scopegate/` — AES-256-GCM vault (`vault.enc` + `master.key`), Ed25519
  audit identity (`identity.json`), `scopegate.yaml` (upstream registry),
  `policies.yaml` (grant rules). No plaintext secrets on disk.
- Your harness's MCP config rewritten so `scopegate` is the ONLY MCP entry
  point; pre-existing MCP servers migrated behind the gateway, their
  plaintext secrets vaulted and replaced by `secretRef` names.
- Keep-first backups of every original config as `<config>.pre-scopegate.bak`
  (restorable with `scopegate rollback`, §6).

## 1. Prerequisites

- **Node.js >= 20** with `npm` on PATH:

  ```bash
  node -v   # must print v20.x or newer
  npm -v
  ```

  Too old or missing? `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | sh && nvm install 22` (or volta / brew).
- Write access to your home directory (portable/test install: export
  `SCOPEGATE_HOME` BEFORE any scopegate command):

  ```bash
  export SCOPEGATE_HOME=/path/to/scopegate-home
  ```

- **Never use sudo.** If the global npm prefix is not writable, use a
  user-level prefix instead (decision tree in §2).

## 2. Install

Pick ONE method. All are idempotent.

### A. Global npm install (preferred)

```bash
npm install -g scopegate
scopegate --version
```

### B. npx (no global install)

```bash
npx --yes scopegate@latest init   # downloads transiently and runs init
```

### C. Installer script (curl | sh), built for agents

```bash
curl -sSL https://scopegate.io/install.sh | sh -s -- --yes
```

- `--yes` = fully non-interactive. Other flags: `--version X.Y.Z`, `--no-init`.
- Checks node >= 20, installs via `npm install -g` (fallbacks: user prefix
  `~/.npm-global`, then `npx`), and runs `init` for you.
- **Checksum verification (out-of-band):** it prints the published tarball
  URL and its SHA-1 from the npm registry. Verify independently:

  ```bash
  npm view scopegate dist.tarball dist.shasum   # tarball URL + expected SHA-1
  curl -sSL <tarball-url> | shasum -a 1         # output must equal dist.shasum
  ```

### Decision tree — install

```text
IF `npm install -g scopegate` exits 0          → verify `scopegate --version`; go to §3
ELSE IF it fails on permissions (EACCES)       → npm install -g --prefix "$HOME/.npm-global" scopegate
                                                 export PATH="$HOME/.npm-global/bin:$PATH"
ELSE (npm install fails for any other reason)  → npx --yes scopegate@latest init  (no global install)
```

## 3. `scopegate init` — what it does, exactly

Run it from the project root (project-scope configs resolve against your
cwd). Non-interactive, exit 0 on success. `--dry-run` is pure inspection and
creates NOTHING — no `~/.scopegate`, no master key, no vault, no backups:

```bash
scopegate init --dry-run   # report what WOULD change; zero side effects
scopegate init             # do it (idempotent)
```

Step by step:

1. **Provisions `~/.scopegate/`**: master key + empty encrypted vault; the
   Ed25519 `identity.json` that signs the audit log (keep-first: an existing
   identity is NEVER regenerated); default `policies.yaml` (mode 0600) with
   a safe rule — `*:call:*` auto-approved at 15-minute TTL; `scopegate.yaml`
   with a generated `agentId` (`agent-<username>-<6 hex>`).
2. **Detects your harness** via four adapters:

   | Harness | Project config | User config | CLI probe |
   |---|---|---|---|
   | `claude-code` | `.mcp.json` | `~/.claude.json` | `claude` |
   | `kimi-code` | `.kimi-code/mcp.json` | `~/.kimi-code/mcp.json` (or `$KIMI_CODE_HOME/mcp.json`) | `kimi` |
   | `cursor` | `.cursor/mcp.json` | `~/.cursor/mcp.json` | `cursor-agent` / `cursor` |
   | `opencode` | `opencode.json` | `~/.config/opencode/opencode.json` | `opencode` |

   Every config file that EXISTS is migrated (a leftover config still holds
   secrets). If none exists but the harness CLI is on PATH, init creates the
   user-level config fresh; if nothing is found at all, it writes a project
   `.mcp.json` with only scopegate. (`~` = `%USERPROFILE%` on Windows.)
3. **Migrates every MCP server behind the gateway**, vaulting secrets and
   leaving only `secretRef` names in `scopegate.yaml`:
   - env vars matching `KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AUTH`
     (case-insensitive) → vaulted as `<server>_<var lowercase>`;
   - headers matching `authorization|api-key|token|secret` → vaulted
     (`Bearer ` prefix stripped; with several secret headers, the first —
     Authorization preferred — is wired as the auth header, the rest stay
     vaulted with a WARN);
   - Kimi `bearerTokenEnvVar` is resolved at init time; when unset — or an
     OpenCode `oauth` entry — the upstream migrates as **oauth2-PENDING**
     (never silently degraded to `none`) with a WARN naming the exact
     `scopegate secret add <ref>` command — relay it to the human (§4);
   - SSE endpoints migrate with `enabled: false` + WARN (not proxied yet).
4. **Backs up each original config** to `<config>.pre-scopegate.bak` —
   KEEP-FIRST: written once, never overwritten, always the rollback target.
5. **Rewrites the harness config** so `scopegate` is its ONLY MCP server,
   carrying `SCOPEGATE_AGENT_ID` equal to `scopegate.yaml`'s `agentId`:

   ```json
   { "mcpServers": { "scopegate": {
       "command": "scopegate", "args": ["start"],
       "env": { "SCOPEGATE_AGENT_ID": "agent-…" } } } }
   ```

   (OpenCode: one `mcp.scopegate` entry of `type: "local"`, `command:
   ["scopegate", "start"]`.) The rewrite is re-parsed and validated; on
   failure the backup is restored (or the incomplete file removed) and init
   aborts with an actionable error.
6. **Prints the outcome**: `DONE. Upstreams behind the gateway: [...]`, any
   WARNs needing a human, and `Next: restart your agent session.`

Flags: `--dry-run` (report only); `--harness <id>` (restrict to
`claude-code | kimi-code | cursor | opencode`). A pre-existing entry NAMED
`scopegate` not written by init is a hard error — rename/remove, re-run.

## 4. When a secret is needed — the ONE human action

Migration may end with `PENDING auth (oauth2)` warnings, or a service may
need credentials later. The ONLY thing a human ever does is deposit the
secret in THEIR OWN TERMINAL. Never ask for a secret in chat, never accept
one, never route one through argv or env vars you control.

Tell the human EXACTLY this (copy-paste, substituting the ref):

> Run in your terminal — the value never enters this chat:
> `scopegate secret add <ref>`

- Interactive: hidden prompt (`Value for '<ref>' (input hidden):`). Piped:
  `echo "$TOKEN" | scopegate secret add <ref>`.
- Ref names: letters, digits, `_`, `-`, `.`, `:` (e.g. `github_token`,
  `oauth2:notion`).
- Verify afterwards (names only, never values): `scopegate secret ls`, or
  the `scopegate_vault_status` MCP tool once the gateway is live.
- **No restart needed for deposits after the first session**: a running
  gateway watches the vault version — on the next call it drops connections
  and re-injects fresh credentials. A restart is only needed ONCE, right
  after `init`, so the harness launches the gateway.

### Decision tree — secrets

```text
IF init warned "PENDING auth (oauth2) … scopegate secret add <ref>"
    → hand the human that exact command; wait for confirmation; re-verify
IF a call later fails over a missing secretRef
    → call scopegate_diagnose and relay its action_required verbatim
IF the human offers to paste the key in chat
    → REFUSE. `scopegate secret add <ref>` in their terminal. No exceptions
```

## 5. Post-install verification

1. **Config + vault + upstream health** (works before any restart):

   ```bash
   scopegate status
   ```

   Expect your `agentId`, upstream names, vault ref names, and one line per
   upstream: `✓ <name> (N tools)` / `✗ <name> — <error>` (`✗` = unreachable
   UPSTREAM, not a failed install — §7).
2. **Restart the agent session.** The harness only re-reads its MCP config
   on startup — tell the human: "restart this session so the gateway
   connects." (You never run `scopegate start`; the harness launches it.)
3. **First tool call** (after restart, via the `scopegate_*` MCP tools):

   ```json
   scopegate_request_capability({
     "capability": "<upstream>:call:<tool>",
     "ttl": "15m",
     "reason": "first post-install check"
   })
   → { "granted": true, … }
   ```

   Then call the proxied tool `<upstream>__<tool>`;
   `scopegate_list_capabilities` shows active grants and TTL. If the
   response is `status: "pending_human_approval"` with an `approval_id`:
   STOP and hand the human `scopegate approve <approval_id>` — the second
   and last human-only action; see
   [03 — Tools reference](./03-tools-reference.md).

## 6. Rollback and re-running init

- **Re-running `scopegate init` is a verifiable no-op**: SHA-256 migration
  fingerprints (persisted in `scopegate.yaml`) detect unchanged servers;
  rewritten configs are byte-compared (`already up to date — no changes`);
  backups, identity and config are keep-first. Re-run freely — e.g. after a
  new MCP server appears in a harness config.
- **Undo the harness side:**

  ```bash
  scopegate rollback                   # all harnesses
  scopegate rollback --harness cursor  # just one
  ```

  Restores each config from its `.pre-scopegate.bak`, byte-verified by hash.
  Conservative: `scopegate.yaml` upstreams and vault secrets stay untouched
  (remove manually if permanent). No backups → `No backups found — nothing
  to restore.`

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `node not found` / `too old` | Node < 20 | Install Node >= 20 (nvm/volta/brew), re-run |
| `npm install -g` fails (EACCES) | Global prefix not writable | User prefix + PATH export (§2) — never sudo |
| init: `no harness config found` | No config file, no harness CLI on PATH | init wrote a project `.mcp.json`; or pass `--harness <id>` |
| init error: `already defines an MCP server named 'scopegate'` | Name clash not created by init | Rename/remove that entry, re-run init |
| init WARN: `could not parse <path> … skipping` | Invalid JSON in that config | Fix or remove the file, re-run init |
| init WARN: `PENDING auth (oauth2)` | Secret unavailable at init time | Human: `scopegate secret add <ref>` (§4), restart |
| `status` shows `✗ <upstream>` (timeout) | Upstream unreachable (default 10 s; tune `SCOPEGATE_CONNECT_TIMEOUT_MS`) | Fix the endpoint; after restart call `scopegate_diagnose` |
| Need stack traces | Errors print one actionable line | Re-run with `SCOPEGATE_LOG_LEVEL=debug` |
| Wrong/empty home dir | `SCOPEGATE_HOME` unset/different | Export it BEFORE every scopegate command |

## Next

- Day-to-day operation (request_capability, diagnose, propose_policy,
  register_upstream): [03 — Tools reference](./03-tools-reference.md)
- The non-negotiable agent protocol: [SKILL.md](../../SKILL.md)
- Config and policy formats: [scopegate.example.yaml](../../scopegate.example.yaml),
  [policies.example.yaml](../../policies.example.yaml)
