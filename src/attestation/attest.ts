/**
 * Attestation issuer (EPIC-12): a short-lived EdDSA JWT that the gateway
 * injects as the `X-ScopeGate-Attestation` header on outbound HTTP hops, so a
 * third-party MCP can tell WHICH verified agent is calling — the credential
 * says "may enter", the attestation says "who you are". It is ALWAYS additive:
 * it never replaces the upstream credential.
 *
 * Unified identity: the token is signed with the SAME Ed25519 keypair that
 * signs the audit log (src/audit/identity.ts, PEM-in-JSON at
 * ~/.scopegate/identity.json). One agent identity, two wire formats.
 *
 * Frozen wire contract (see README-spec.md):
 *   header : { alg: "EdDSA", typ: "JWT", kid: <agent fingerprint "sha256:…"> }
 *   claims : { iss: <agentId>, sub: <agent fingerprint>, iat, exp ≤ iat+60s, jti }
 *
 * Signing is cached for ~45 s: a token lives 60 s, so the cached copy is
 * reused only while ≥15 s of validity remain — a cached token can never
 * arrive expired at the upstream. Rotation is natural by kid: the cache is
 * keyed on the identity fingerprint, so an identity rotation invalidates it.
 */
import crypto from "node:crypto";
import { loadOrCreateIdentity } from "../audit/identity.js";
import { publishJwks } from "./jwks.js";

/** Header injected on outbound HTTP hops (contract, do not rename). */
export const ATTESTATION_HEADER = "X-ScopeGate-Attestation";

/** Token lifetime (contract: exp ≤ iat + 60 s). */
export const ATTESTATION_TTL_S = 60;
/** How long a signed token is reused before re-signing (< TTL, with margin). */
export const ATTESTATION_CACHE_MS = 45_000;

export interface Attestation {
  /** Compact JWT: base64url(header).base64url(payload).base64url(signature). */
  token: string;
  /** kid = agent identity fingerprint ("sha256:<hex>"). */
  kid: string;
  /** Epoch ms when the token stops being valid. */
  expiresAtMs: number;
}

const b64u = (s: string): string => Buffer.from(s, "utf8").toString("base64url");

/**
 * Sign a fresh attestation for `agentId`. Also (re)publishes the local JWKS
 * (~/.scopegate/jwks.json) so verifiers always find the current kid.
 * `nowMs` is injectable for tests.
 */
export function issueAttestation(
  agentId: string,
  nowMs: number = Date.now(),
): Attestation {
  const id = loadOrCreateIdentity();
  const iat = Math.floor(nowMs / 1000);
  const header = b64u(
    JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: id.fingerprint }),
  );
  const payload = b64u(
    JSON.stringify({
      iss: agentId,
      sub: id.fingerprint,
      iat,
      exp: iat + ATTESTATION_TTL_S,
      jti: crypto.randomUUID(),
    }),
  );
  const sig = crypto
    .sign(null, Buffer.from(`${header}.${payload}`, "utf8"), id.privateKey)
    .toString("base64url");
  // Keep the published JWKS in sync with the signing key (rotation by kid).
  publishJwks();
  return {
    token: `${header}.${payload}.${sig}`,
    kid: id.fingerprint,
    expiresAtMs: (iat + ATTESTATION_TTL_S) * 1000,
  };
}

let cache: {
  agentId: string;
  kid: string;
  token: string;
  reuseUntilMs: number;
  expiresAtMs: number;
} | null = null;

/**
 * Attestation for the injection hot path: returns the cached token while it
 * still has ≥15 s of life and the identity has not rotated; otherwise signs a
 * fresh one. `nowMs` is injectable for tests.
 */
export function getAttestation(
  agentId: string,
  nowMs: number = Date.now(),
): Attestation {
  const kid = loadOrCreateIdentity().fingerprint;
  if (
    cache &&
    cache.agentId === agentId &&
    cache.kid === kid &&
    nowMs < cache.reuseUntilMs
  ) {
    return { token: cache.token, kid: cache.kid, expiresAtMs: cache.expiresAtMs };
  }
  const att = issueAttestation(agentId, nowMs);
  cache = {
    agentId,
    kid: att.kid,
    token: att.token,
    reuseUntilMs: nowMs + ATTESTATION_CACHE_MS,
    expiresAtMs: att.expiresAtMs,
  };
  return att;
}
