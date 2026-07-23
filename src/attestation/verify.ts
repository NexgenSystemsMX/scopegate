/**
 * STANDALONE attestation verifier (EPIC-12) — reference implementation for
 * third-party MCP servers. It imports NOTHING from ScopeGate (only
 * node:crypto) on purpose: any MCP can copy this single file and verify the
 * `X-ScopeGate-Attestation` header against the agent's published JWKS.
 *
 * Fail-closed by contract: every malformed, expired, unknown-kid or
 * bad-signature token yields `null` — never an exception, never a
 * "best-effort" identity. Callers treat `null` as "unverified agent" and
 * apply their own policy (the frozen e2e rejects with HTTP 401).
 *
 * Wire format (README-spec.md):
 *   header : { alg: "EdDSA", typ: "JWT", kid: <agent fingerprint "sha256:…"> }
 *   claims : { iss: <agentId>, sub: <agent fingerprint>, iat, exp ≤ iat+60s, jti }
 */
import crypto from "node:crypto";

export interface AttestationJwksDoc {
  keys: Array<{
    kty: string;
    crv: string;
    x: string;
    kid: string;
    use?: string;
    alg?: string;
  }>;
}

export interface VerifiedAttestation {
  /** JWT `iss` — the agentId the gateway claims. */
  agentId: string;
  /** JWT `sub` — sha256 fingerprint of the agent identity public key. */
  fingerprint: string;
}

function decodeJson(part: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Verify an attestation JWT against a JWKS document.
 * Returns { agentId, fingerprint } on success, `null` on ANY failure.
 * `nowMs` is injectable for tests; no clock-skew leeway is applied.
 */
export function verifyAttestation(
  token: string,
  jwks: AttestationJwksDoc,
  nowMs: number = Date.now(),
): VerifiedAttestation | null {
  if (typeof token !== "string" || !jwks || !Array.isArray(jwks.keys)) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  const header = decodeJson(h);
  const payload = decodeJson(p);
  if (!header || !payload) return null;
  if (header.alg !== "EdDSA" || typeof header.kid !== "string") return null;

  // Key discovery by kid — unknown kid is a hard reject (rotation-safe: a
  // verifier with a stale JWKS rejects rather than trusting the wrong key).
  const key = jwks.keys.find(
    (k) => k && k.kid === header.kid && k.kty === "OKP" && k.crv === "Ed25519",
  );
  if (!key || typeof key.x !== "string") return null;

  const { iss, sub, iat, exp, jti } = payload;
  if (
    typeof iss !== "string" ||
    typeof sub !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    typeof jti !== "string"
  ) {
    return null;
  }
  // sub and kid commit to the SAME key fingerprint (spec invariant).
  if (sub !== header.kid) return null;
  // Lifetime: expired tokens are rejected; the contract caps exp ≤ iat + 60 s,
  // and a token claiming a longer life is not from a conforming issuer.
  if (exp > iat + 60) return null;
  if (exp * 1000 <= nowMs) return null;

  let ok = false;
  try {
    const publicKey = crypto.createPublicKey({
      key: { kty: key.kty, crv: key.crv, x: key.x },
      format: "jwk",
    } as crypto.JsonWebKeyInput);
    ok = crypto.verify(
      null,
      Buffer.from(`${h}.${p}`, "utf8"),
      publicKey,
      Buffer.from(s, "base64url"),
    );
  } catch {
    return null;
  }
  if (!ok) return null;
  return { agentId: iss, fingerprint: sub };
}
