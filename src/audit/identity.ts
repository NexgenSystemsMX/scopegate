/**
 * Agent identity: a local Ed25519 keypair that signs every audit event
 * (EPIC-07 H7.2). It is what makes the audit trail ATTRIBUTABLE: an attacker
 * with disk access can recompute the hash chain, but cannot re-sign events
 * without the private key.
 *
 * Storage format (documented decision — PEM-in-JSON, not JWK):
 *   ~/.scopegate/identity.json, mode 0600:
 *   {
 *     "v": 1,
 *     "algo": "ed25519",
 *     "publicKey":  "<PEM SPKI>",   // -----BEGIN PUBLIC KEY-----
 *     "privateKey": "<PEM PKCS8>",  // -----BEGIN PRIVATE KEY-----
 *     "fingerprint": "sha256:<hex>",// sha256 of the SPKI DER bytes
 *     "createdAt": "<ISO 8601>"
 *   }
 * PEM (SPKI/PKCS8) is chosen over JWK because node:crypto consumes it
 * directly for sign/verify AND it is the interchange format every external
 * verifier (openssl, SIEM-side checkers) understands. The fingerprint —
 * sha256 over the raw SPKI DER, algorithm-prefixed for versioning — is the
 * STABLE identifier of the agent-identity; it never changes across config
 * edits or agentId renames.
 *
 * Lifecycle:
 *   - `scopegate init` provisions it (keep-first: never regenerated, so past
 *     signatures stay verifiable — rotating the key invalidates verification
 *     of the existing log and is a deliberate human operation).
 *   - audit() creates it LAZILY as a defensive fallback (gateway started
 *     without init), with a WARN to stderr.
 *   - Read paths (audit verify) NEVER create it: verification against a
 *     freshly-minted key would be meaningless.
 *
 * No passphrase in Phase 0 (documented in EPIC-07); OS keychain custody
 * arrives with EPIC-05.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";

export const IDENTITY_PATH = path.join(SCOPEGATE_DIR, "identity.json");

const SIG_PREFIX = "ed25519:";
const FP_PREFIX = "sha256:";

export interface AgentIdentity {
  v: 1;
  algo: "ed25519";
  /** PEM SPKI (public). */
  publicKey: string;
  /** PEM PKCS8 (private). */
  privateKey: string;
  /** "sha256:<hex>" over the SPKI DER — stable agent-identity identifier. */
  fingerprint: string;
  createdAt: string;
}

export function identityExists(): boolean {
  return fs.existsSync(IDENTITY_PATH);
}

/** Fingerprint of a PEM public key: sha256 over its SPKI DER encoding. */
export function fingerprintOf(publicKeyPem: string): string {
  const der = crypto
    .createPublicKey(publicKeyPem)
    .export({ type: "spki", format: "der" });
  return FP_PREFIX + crypto.createHash("sha256").update(der).digest("hex");
}

/** Load and validate the identity. Throws an actionable Error if missing or corrupt. */
export function loadIdentity(): AgentIdentity {
  if (!identityExists()) {
    throw new Error(
      `No agent identity at ${IDENTITY_PATH}. Run \`scopegate init\` to provision it.`,
    );
  }
  let id: AgentIdentity;
  try {
    id = JSON.parse(fs.readFileSync(IDENTITY_PATH, "utf8")) as AgentIdentity;
  } catch (e) {
    throw new Error(
      `Agent identity at ${IDENTITY_PATH} is corrupt (${e instanceof Error ? e.message : String(e)}). ` +
        `Refusing to regenerate it automatically (that would invalidate every past signature); rotate it manually.`,
    );
  }
  if (
    id?.v !== 1 ||
    id.algo !== "ed25519" ||
    typeof id.publicKey !== "string" ||
    typeof id.privateKey !== "string" ||
    typeof id.fingerprint !== "string"
  ) {
    throw new Error(
      `Agent identity at ${IDENTITY_PATH} has an unsupported or incomplete shape; rotate it manually.`,
    );
  }
  // Detect mixed/tampered files: the stored fingerprint must commit to the pubkey.
  if (fingerprintOf(id.publicKey) !== id.fingerprint) {
    throw new Error(
      `Agent identity at ${IDENTITY_PATH} is inconsistent (fingerprint does not match the public key); rotate it manually.`,
    );
  }
  return id;
}

/**
 * Generate and persist a new identity — KEEP-FIRST: if one already exists it
 * is returned unchanged. Write is atomic (tmp + rename), mode 0600.
 */
export function createIdentity(): AgentIdentity {
  if (identityExists()) return loadIdentity();
  ensureDir();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const id: AgentIdentity = {
    v: 1,
    algo: "ed25519",
    publicKey: pubPem,
    privateKey: privPem,
    fingerprint: fingerprintOf(pubPem),
    createdAt: new Date().toISOString(),
  };
  const tmp = IDENTITY_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(id, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, IDENTITY_PATH);
  return id;
}

let cached: AgentIdentity | null = null;

/**
 * Identity for the signing hot path: load once per process; create lazily
 * (with a stderr WARN) when the gateway runs without a prior `init`.
 */
export function loadOrCreateIdentity(): AgentIdentity {
  if (cached) return cached;
  if (identityExists()) {
    cached = loadIdentity();
    return cached;
  }
  console.error(
    `[scopegate audit] WARN: no agent identity found — generating one on the fly at ${IDENTITY_PATH}. ` +
      `Run \`scopegate init\` to provision it explicitly.`,
  );
  cached = createIdentity();
  return cached;
}

/** Sign a canonical event serialization; returns "ed25519:<base64>". */
export function signCanonical(identity: AgentIdentity, canonical: string): string {
  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), identity.privateKey);
  return SIG_PREFIX + sig.toString("base64");
}

/** Verify an "ed25519:<base64>" signature over a canonical serialization. */
export function verifyCanonical(
  publicKeyPem: string,
  canonical: string,
  sig: string,
): boolean {
  if (typeof sig !== "string" || !sig.startsWith(SIG_PREFIX)) return false;
  try {
    return crypto.verify(
      null,
      Buffer.from(canonical, "utf8"),
      publicKeyPem,
      Buffer.from(sig.slice(SIG_PREFIX.length), "base64"),
    );
  } catch {
    return false;
  }
}
