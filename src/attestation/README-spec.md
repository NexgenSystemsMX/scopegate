# ScopeGate Agent Attestation — public wire spec (v1)

ScopeGate signs every outbound HTTP hop with a short-lived EdDSA JWT so a
third-party MCP server can tell **which verified agent** is calling, not just
that the call carries a valid credential. The attestation is **additive**: it
travels *next to* the upstream credential (Authorization header, minted token,
…), never instead of it. The same Ed25519 keypair that signs the ScopeGate
audit log signs the attestation — one agent identity, two verifiable artifacts.

## 1. Token format

Compact JWS (`header.payload.signature`, all base64url):

```json
// header
{ "alg": "EdDSA", "typ": "JWT", "kid": "sha256:<hex>" }
// claims
{
  "iss": "<agentId>",                 // e.g. "agent-luis-nexgen"
  "sub": "sha256:<hex>",              // == kid: fingerprint of the agent pubkey
  "iat": 1750000000,
  "exp": 1750000060,                  // contract: exp ≤ iat + 60
  "jti": "<random uuid>"              // unique per token (anti-replay handle)
}
```

- `kid` / `sub` are the **agent identity fingerprint**: `sha256:` + hex of the
  SHA-256 over the SPKI DER of the agent's Ed25519 public key. They are always
  equal; a token where they differ is invalid.
- Signature: Ed25519 (EdDSA) over `base64url(header) + "." + base64url(payload)`.
- Lifetime: ≤ 60 s. Issuers cache a token for ~45 s, so what arrives on the
  wire always has ≥ ~15 s of validity.

## 2. Transport

```
X-ScopeGate-Attestation: <compact JWT>
```

Injected on **every outbound HTTP request** to upstreams with attestation
enabled (default: enabled when the gateway holds an agent identity; opt out
per upstream or globally with `attestation: false` in `scopegate.yaml`).

**stdio upstreams: not attested by design.** A local stdio MCP has no remote
counterpart that could verify a signature, so the gateway does not inject the
token there (neither as env var nor as `_meta`). If a future stdio-side
verifier appears, the spec can be extended without changing the HTTP wire
format.

The header never replaces the credential and carries **no secrets** — it only
proves possession of the agent identity private key at request-signing time.

## 3. Key discovery (JWKS)

The gateway publishes its current public key as a JSON Web Key Set at:

```
~/.scopegate/jwks.json          (mode 0644 — public material only)
```

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "<base64url raw pubkey>",
      "kid": "sha256:<hex>", "use": "sig", "alg": "EdDSA" }
  ]
}
```

The file is rewritten atomically on every token (re)issue, so it always
reflects the current signing key. Deployments that cannot read the agent's
filesystem may distribute the JWKS (or just the expected `kid` + `x`)
**out-of-band and pin it** — the verification algorithm is identical.

## 4. Verification (fail-closed)

Reference implementation: `verify.ts` in this directory — self-contained,
`node:crypto` only, copy-paste friendly. `verifyAttestation(token, jwks)`
returns `{ agentId, fingerprint }` or `null`. Verification steps:

1. Split into 3 parts; base64url-decode header and payload.
2. Require `alg == "EdDSA"` and a string `kid`.
3. Look up a JWKS key with `kid`, `kty == "OKP"`, `crv == "Ed25519"`.
   **Unknown kid → reject** (never fall back to another key).
4. Require string `iss`/`sub`/`jti`, numeric `iat`/`exp`; require `sub == kid`.
5. Require `exp ≤ iat + 60` and `exp > now` (no clock-skew leeway).
6. Verify the Ed25519 signature over `header.payload` with the JWK public key.

Any failure → `null`. A verifier that requires attestation (e.g.
`fake-upstream.mjs` with `FAKE_REQUIRE_ATTESTATION=1`) answers **HTTP 401**
with a JSONRPC-shaped error body when the header is missing or invalid.

## 5. Rotation

`scopegate` rotates the identity by replacing the Ed25519 keypair; the new
fingerprint becomes the new `kid`. Because verifiers look keys up by `kid` and
the JWKS is republished on every issue, rotation needs **no coordination**:
old-kid tokens expire within 60 s and new tokens verify against the new JWKS
entry. A verifier holding a stale JWKS rejects unknown kids fail-closed — it
never trusts the wrong key.

## 6. Anti-replay notes

- `exp ≤ 60 s` bounds the replay window; combined with per-request TLS or a
  local trust boundary it is sufficient for the intended use (agent
  attribution, per-agent policy at the MCP).
- `jti` is unique per token: a verifier that needs stronger guarantees may
  cache seen `jti`s for 60 s and reject duplicates.
- The attestation proves *which agent*, at *issue time*. It is not an
  authorization grant: the upstream credential still governs access.

## 7. Failure modes

- **Gateway (fail-open):** if the identity cannot be loaded, the hop proceeds
  *without* the header and logs a warning — attestation must never break a
  working upstream. (A verifying upstream will then reject, which is the
  correct signal.)
- **Verifier (fail-closed):** missing, malformed, expired, unknown-kid or
  bad-signature tokens yield `null`; requiring verifiers answer 401.
