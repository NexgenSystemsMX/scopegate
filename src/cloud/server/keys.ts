/**
 * Cloud identity: the control plane's own Ed25519 keypair, used to sign team
 * policies so gateways can verify them end-to-end (a tampered policy served
 * by a compromised or MITM'd control plane is rejected gateway-side).
 *
 * Same PEM-in-JSON storage format as the agent identity (src/audit/identity.ts)
 * for operational symmetry — one format, verifiable everywhere with openssl:
 *   <home>/cloud-identity.json, mode 0600:
 *   { "v": 1, "algo": "ed25519", "publicKey": "<PEM SPKI>",
 *     "privateKey": "<PEM PKCS8>", "fingerprint": "sha256:<hex>",
 *     "createdAt": "<ISO 8601>" }
 *
 * KEEP-FIRST: an existing identity is never regenerated (rotating it would
 * invalidate every policy signature gateways may have cached). Rotation is a
 * deliberate human operation: stop the server, move the file away, restart.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fingerprintOf } from "../../audit/identity.js";

export interface CloudIdentity {
  v: 1;
  algo: "ed25519";
  publicKey: string; // PEM SPKI
  privateKey: string; // PEM PKCS8
  fingerprint: string; // "sha256:<hex>"
  createdAt: string;
}

export function cloudIdentityPath(home: string): string {
  return path.join(home, "cloud-identity.json");
}

/**
 * Load the cloud identity, creating it on first boot (keep-first). Write is
 * atomic (tmp + rename), mode 0600. Throws an actionable Error if the file
 * exists but is corrupt or inconsistent (never silently regenerates).
 */
export function loadOrCreateCloudIdentity(home: string): CloudIdentity {
  const file = cloudIdentityPath(home);
  if (fs.existsSync(file)) {
    let id: CloudIdentity;
    try {
      id = JSON.parse(fs.readFileSync(file, "utf8")) as CloudIdentity;
    } catch (e) {
      throw new Error(
        `Cloud identity at ${file} is corrupt (${e instanceof Error ? e.message : String(e)}). ` +
          `Refusing to regenerate it automatically (that would invalidate every signed policy); rotate it manually.`,
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
        `Cloud identity at ${file} has an unsupported or incomplete shape; rotate it manually.`,
      );
    }
    if (fingerprintOf(id.publicKey) !== id.fingerprint) {
      throw new Error(
        `Cloud identity at ${file} is inconsistent (fingerprint does not match the public key); rotate it manually.`,
      );
    }
    return id;
  }

  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const id: CloudIdentity = {
    v: 1,
    algo: "ed25519",
    publicKey: pubPem,
    privateKey: privPem,
    fingerprint: fingerprintOf(pubPem),
    createdAt: new Date().toISOString(),
  };
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(id, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
  return id;
}

/** Sign `canonical` with the cloud key; returns "ed25519:<base64>". */
export function signWithCloudKey(identity: CloudIdentity, canonical: string): string {
  const sig = crypto.sign(null, Buffer.from(canonical, "utf8"), identity.privateKey);
  return "ed25519:" + sig.toString("base64");
}
