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
with device-code re-auth, token minter (JWT / GitHub App / AWS STS / Google SA
/ Huly), policy engine with TTL grants, hard limits, rate limiting, PII
redaction and human approvals, vault with AES-256-GCM (+ optional `vaultd`
process isolation and OS keychain master keys), multi-harness init (Claude
Code, Kimi Code, Cursor, OpenCode, `.mcp.json`), signed audit trail with
verify/query/reindex, upstream registry with signed manifests, EdDSA
attestation, honeytokens, and native bridges (Huly, Railway, Cloudflare,
Google).

Also in this repo: **ScopeGate Cloud** — the optional multi-tenant management
plane (`scopegate cloud serve`): landing page at `/`, product panel at
`/panel` (fleet, approvals, capabilities, audit, versioned signed policies,
billing), and the `/v1` API with enroll, signed policy distribution, verified
audit ingest, fleet revocation and the panel-driven approval loop. Local-first
holds: gateways keep working with their local policy when the cloud is down.

Still future (see the roadmap EPICs under
[`../../docs/Implementacion/`](../../docs/Implementacion/)):

- **Cloud hardening** — Postgres store, SSO/SAML with per-team roles, Stripe
  metering, on-prem packaging, SIEM export (EPIC-10 enterprise stories).
- **Ecosystem growth** — more registry upstreams and warm-pool fleets
  (EPIC-12 follow-ups).
