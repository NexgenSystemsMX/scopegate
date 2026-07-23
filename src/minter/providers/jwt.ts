/**
 * JWT provider (EPIC-02 H2): the gateway signs short-lived HS256 tokens with
 * an HMAC key from the vault, for internal APIs/MCPs that accept tokens
 * signed by us. Pure node:crypto — no dependencies.
 *
 * Claims: iss (gateway), aud (upstream), iat/exp (clamped to the grant TTL),
 * jti (random, for audit correlation), plus any extra `claims` from config.
 * The minted token is injected as `Authorization: Bearer <jwt>` and never
 * reaches the agent.
 */
import crypto from "node:crypto";
import type { UpstreamAuth } from "../../config/config.js";
import { parseTtl } from "../../policy/engine.js";
import type { Vault } from "../../vault/vault.js";
import type { CredentialProvider, MintedCredential, MintOpts } from "../minter.js";

/** Default provider ceiling, aligned with the policy default_ttl. */
const DEFAULT_TTL_MS = 15 * 60 * 1000;

export function base64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

/** Sign an HS256 JWT. `payload` must already contain iat/exp. */
export function signHs256(payload: Record<string, unknown>, key: string): string {
  const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", key).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

/** Verify an HS256 JWT signature (used by tests and internal consumers). */
export function verifyHs256(token: string, key: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const expected = crypto.createHmac("sha256", key).update(`${parts[0]}.${parts[1]}`).digest();
  const actual = Buffer.from(parts[2], "base64url");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

export class JwtProvider implements CredentialProvider {
  readonly type = "jwt";

  supports(auth: UpstreamAuth): boolean {
    return auth.type === "jwt";
  }

  maxTtlMs(auth: UpstreamAuth): number {
    return auth.type === "jwt" ? parseTtl(auth.ttl, DEFAULT_TTL_MS) : 0;
  }

  mint(auth: UpstreamAuth, vault: Vault, opts: MintOpts): Promise<MintedCredential> {
    if (auth.type !== "jwt") {
      return Promise.reject(new Error(`JwtProvider cannot mint for auth type '${auth.type}'`));
    }
    const key = vault.get(auth.secretRef);
    const nowMs = opts.nowMs ?? Date.now();
    const iat = Math.floor(nowMs / 1000);
    const exp = Math.floor((nowMs + opts.ttlMs) / 1000);
    const payload: Record<string, unknown> = {
      ...(auth.claims ?? {}),
      // Enforced after user claims: integrity fields can never be overridden.
      iss: "scopegate",
      aud: opts.upstream,
      iat,
      exp,
      jti: crypto.randomUUID(),
    };
    const token = signHs256(payload, key);
    return Promise.resolve({
      value: token,
      headers: { Authorization: `Bearer ${token}` },
      expiresAt: exp * 1000,
    });
  }
}
