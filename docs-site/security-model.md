# Security Model

ScopeGate's design goal: **a leaked agent context leaks nothing of durable
value.** Six rules enforce it; each maps to code.

## 1. Secrets never enter the model's context

Secrets are deposited only via `scopegate secret add <ref>` (hidden prompt or
piped stdin — never argv, never chat). They are stored in
`~/.scopegate/vault.enc` (AES-256-GCM; master key in `master.key` with mode
0600, or an OS backend: DPAPI / macOS Keychain / libsecret). Config files hold
only `secretRef` **names**. The gateway injects values at the outbound hop
only, inside the proxy process.

## 2. Capability ≠ credential

Agents request capabilities — `"<upstream>:<action>:<resource>"` — and receive
TTL grants (minutes, clamped by policy ceilings). Grants are evaluated per
call; there is no standing credential in the agent's environment. The token
minter can go further: for `jwt`, `github_app` and `aws_sts` upstreams the
value that leaves the machine is itself short-lived, minted per connection
and clamped to the grant TTL.

## 3. Write asymmetry: agents propose, humans approve

`scopegate_propose_policy` writes to `policies.pending.yaml` — validated,
deduplicated, linted against hard limits — and never touches live policy.
Capabilities matching `require: human_approval` return
`pending_human_approval` with an `approval_id`; only a human running
`scopegate approve <id>` / `scopegate deny <id>` unblocks them. Approval
requests expire (`limits.approval_ttl`).

## 4. Hard limits are fail-closed

`policies.yaml` → `limits` are ceilings no rule can beat: `max_ttl`, `deny`
globs (evaluated before any `auto_approve`, including a literal `*:*`
injection guard) and `rate_limit` on capability requests. A ceiling hit is
audited as `ceiling_blocked` and the tool response tells the agent not to
retry with broader scope. A `looksLikeSecret()` guard rejects raw secrets
smuggled in place of ref names.

## 5. Data minimization on the way out

Rules can set `redact: [pii]` to mask emails, phones, card numbers (Luhn) and
AWS key ids in upstream **responses** before they reach the agent —
best-effort; the audit log records only redaction counts, never matches.

## 6. Tamper-evident audit

Every privileged action is appended to `~/.scopegate/audit.jsonl`: each event
carries a sequence number, the previous event's hash (hash chain) and an
Ed25519 signature (key pair generated at init, private key mode 0600).
Tool-call inputs are hashed, never stored. `scopegate audit verify` checks
continuity, chain and signatures; `query`/`reindex` answer "what did this
agent touch in this window" from a derived index.

## Process isolation (optional hardening)

`scopegate vaultd` runs the vault as a separate process behind a unix socket
/ Windows named pipe (`SCOPEGATE_VAULT_MODE=daemon`), so the gateway process
never holds decrypted secrets at rest. `scopegate vault rotate-key`
re-encrypts with a fresh master key, optionally migrating backends.

## Threat-model boundaries (honest list)

- A malicious process running **as your user** can call the gateway like the
  agent does — policy and approvals are the control, not process boundaries
  (unless you isolate `vaultd` further at the OS level).
- PII redaction is best-effort pattern matching, not a DLP product.
- The audit chain proves tampering after the fact; it does not prevent a
  privileged attacker from deleting the file outright.

Roadmap hardening (EPIC-10 enterprise stories): SSO/SAML with per-team roles
in the cloud plane. Honeytoken tripwires (`scopegate honeytoken plant`) and
fleet revocation (cloud panel, Fleet tab) already shipped — see the
[CLI Reference](cli-reference.md).

## Telemetry (opt-in)

Off by default. When enabled (`SCOPEGATE_TELEMETRY=1` or
`{"enabled": true}` in `~/.scopegate/telemetry.json`) the only events are
`install`, `init_completed` and `first_tool_call`, with an allowlisted
payload: version, OS/arch, Node version, detected harness ids, latency in ms,
and a random anonymous install id. Never agentId, paths, upstream names,
args, inputs or config content. The collector defaults to
`https://telemetry.scopegate.dev/v1/event` and is overridable via
`SCOPEGATE_TELEMETRY_ENDPOINT`. Implementation:
[`src/telemetry/telemetry.ts`](../src/telemetry/telemetry.ts) — fail-silent,
allowlist-enforced.
