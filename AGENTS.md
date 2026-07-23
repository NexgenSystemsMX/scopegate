# AGENTS.md — ScopeGate repo guide for coding agents

ScopeGate is an **ephemeral-credentials gateway** for coding agents
(Claude Code, Kimi Code, Cursor, OpenCode, or any MCP harness). The agent
never holds secrets — it holds short-lived, minimum-scope **capabilities**
minted by a policy engine. Secrets live in an AES-256-GCM encrypted vault
and are injected only at the outbound hop.

## If you want to USE ScopeGate

Do not read the source. The complete, agent-executable usage documentation
lives in **[docs/agents/README.md](docs/agents/README.md)** — seven guides
covering self-install, the operating protocol, the MCP tools reference,
connectors, policies, self-repair, and security rules. Start at guide 01
and follow it literally.

A drop-in protocol summary also ships as [SKILL.md](SKILL.md) (usable as a
skills-dir entry or a `CLAUDE.md` / `AGENTS.md` fragment).

## If you are DEVELOPING ScopeGate

Requirements: Node.js ≥ 20, npm 10. No native modules, no global services.

### Layout (`src/`)

```
cli.ts          # entry: init | start | secret | status | audit | auth | vaultd | vault |
                #        rollback | approve | deny | policies | cloud
commands/       # init, secret, oauth-login, vaultd, vault-rotate, approvals/policies CLI
config/         # paths + scopegate.yaml loader (NEVER holds secrets)
gateway/        # MCP server, policy enforcement, upstream proxy + injection + self-heal,
                # scopegate_* tools
harness/        # adapters: claude-code, kimi-code, cursor, opencode, mcp-json
vault/          # AES-256-GCM store, master-key backends, vaultd daemon + IPC
policy/         # engine, grants, limits, rate limit, redact, approvals
minter/         # token minter + providers/ (jwt, github-app, aws-sts, huly, google-sa)
oauth/          # refresh daemon, device-code
audit/          # hash-chained JSONL, Ed25519 signing, verify, index
upstreams/      # native connectors: huly, railway, cloudflare, google
cloud/          # optional multi-tenant control plane (metadata-only)
attestation/ honeytoken/ notify/ registry/ telemetry/
```

### Commands

```bash
npm install
npm run build       # tsc → dist/ (type-check + emit)
npm test            # vitest unit tests (tests/*.test.ts)

# e2e — each is self-contained: throwaway SCOPEGATE_HOME, ephemeral ports
node e2e-client.mjs   # proxy + injection + policy + audit
node e2e-init.mjs     # harness detection & migration
node e2e-oauth.mjs    # oauth2 refresh daemon + device-code re-auth
node e2e-vaultd.mjs   # vault as isolated process over IPC
node e2e-http.mjs     # Streamable HTTP transport
node e2e-cloud.mjs    # control plane end-to-end
node redteam/run.mjs  # red-team harness
```

All must be green before a PR.

### Contribution rules (short)

- **No new runtime dependencies** without opening an issue first. Node
  stdlib plus the existing deps are enough.
- **Tests never touch the real `~/.scopegate`** — use `useTempHome()` from
  `tests/helpers.ts` (mkdtemp `SCOPEGATE_HOME` + `vi.resetModules()`) and
  import src modules dynamically after calling it.
- **No secrets in the repo** — no secret values in config, argv, logs,
  tests, fixtures, or tool responses. Config only ever holds `secretRef`
  names.
- Invariants you may not break: agent-proposed policy never takes effect
  without human review; hard limits (`deny` globs, `max_ttl`) stay
  fail-closed; every privileged action is audited.
- Branch from `main`, keep diffs focused; `fix:` / `feat:` / `docs:`
  subjects appreciated.
- Security issues: email security@scopegate.dev — never a public issue.

Full details: [CONTRIBUTING.md](CONTRIBUTING.md).
