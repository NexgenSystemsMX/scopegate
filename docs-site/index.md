# ScopeGate Documentation

ScopeGate is an **ephemeral credentials gateway for coding agents** (Claude
Code, Kimi Code, Cursor, OpenCode). The agent never holds secrets — it holds
short-lived, minimum-scope **capabilities**. Secrets live in an encrypted
local vault and are injected only at the outbound hop, just before the
request leaves your machine.

```
Agent/CLI ──(MCP, zero secrets)──► ScopeGate ──(creds injected)──► GitHub / AWS / your MCPs
                                      │
                    vault + policy engine + token minter + signed audit
```

## Pages

- [Quickstart](quickstart.md) — zero to first proxied tool call, agent-executable
- [Security Model](security-model.md) — the enforcement rules and why they hold
- [Agent Protocol](agent-protocol.md) — the SKILL protocol agents follow
- [CLI Reference](cli-reference.md) — every command and flag
- [Configuration](configuration.md) — `scopegate.yaml`, `policies.yaml`, env vars

## The contract in one minute

1. **Capability ≠ credential.** Agents request `github:call:create_pull_request`
   for 5 minutes; they never see the token that ultimately authorizes the call.
2. **Secrets enter out-of-band.** `scopegate secret add <ref>` from a human
   terminal — hidden prompt or piped stdin, never chat, never argv.
3. **Write asymmetry.** Agents propose policy changes
   (`policies.pending.yaml`); only humans edit `policies.yaml`.
4. **Everything is audited.** Append-only, hash-chained, Ed25519-signed JSONL;
   inputs are hashed, never stored. `scopegate audit verify` detects tampering.

## Status & roadmap

Implemented today: proxy + injection (`bearer`, `env`), OAuth2 refresh daemon
with device-code re-auth, token minter (JWT / GitHub App / AWS STS), policy
engine with TTL grants, hard limits, rate limiting, PII redaction and human
approvals, vault with AES-256-GCM (+ optional `vaultd` process isolation and
OS keychain master keys), multi-harness init (Claude Code, Kimi Code, Cursor,
OpenCode, `.mcp.json`), signed audit trail with verify/query/reindex.

Not in this repo (future, see the roadmap EPICs under
[`../../docs/Implementacion/`](../../docs/Implementacion/)):

- **ScopeGate Cloud** — multi-tenant management plane, SSO, fleet revocation
  (EPIC-10). The paid tier; the OSS gateway stays Apache-2.0.
- **Upstream registry & attestation** — 1-click onboarding (EPIC-12).
