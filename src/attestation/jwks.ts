/**
 * JWKS publisher (EPIC-12): exposes the agent identity public key as a
 * JSON Web Key Set at ~/.scopegate/jwks.json so third-party MCPs can verify
 * `X-ScopeGate-Attestation` tokens. Contains PUBLIC material only (mode 0644).
 *
 * Rotation by kid: the file is re-derived from the current identity on every
 * publish; verifiers look keys up by the JWT header `kid`, so an identity
 * rotation simply adds a new kid — consumers never need out-of-band notice.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { loadOrCreateIdentity, type AgentIdentity } from "../audit/identity.js";

export const JWKS_PATH = path.join(SCOPEGATE_DIR, "jwks.json");

export interface AttestationJwk {
  kty: "OKP";
  crv: "Ed25519";
  /** base64url of the raw 32-byte Ed25519 public key. */
  x: string;
  /** Agent identity fingerprint ("sha256:<hex>") — matches the JWT header kid. */
  kid: string;
  use: "sig";
  alg: "EdDSA";
}

export interface AttestationJwks {
  keys: AttestationJwk[];
}

/** Derive the JWKS for an identity (pure — no I/O). */
export function jwksFromIdentity(id: AgentIdentity): AttestationJwks {
  const jwk = crypto.createPublicKey(id.publicKey).export({ format: "jwk" }) as {
    kty?: string;
    crv?: string;
    x?: string;
  };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("agent identity public key is not an Ed25519 key");
  }
  return {
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        x: jwk.x,
        kid: id.fingerprint,
        use: "sig",
        alg: "EdDSA",
      },
    ],
  };
}

/**
 * Publish the JWKS of the current identity to ~/.scopegate/jwks.json.
 * Atomic write (tmp + rename). Returns the published document.
 */
export function publishJwks(): AttestationJwks {
  const jwks = jwksFromIdentity(loadOrCreateIdentity());
  ensureDir();
  const tmp = JWKS_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(jwks, null, 2) + "\n", { mode: 0o644 });
  fs.renameSync(tmp, JWKS_PATH);
  return jwks;
}
