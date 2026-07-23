#!/usr/bin/env node
/**
 * Regenerates registry/index.json + registry/index.sig.
 *
 *   node registry/sign-index.mjs [registryDir]
 *
 * What it does:
 *   1. Ensures a DEV Ed25519 keypair exists at <registryDir>/keys/
 *      (dev-private.pem / dev-public.pem) — KEEP-FIRST: an existing key is
 *      never overwritten.
 *   2. Hashes every *.yaml manifest in <registryDir> (sha256, exact bytes).
 *   3. Writes index.json ({version, updatedAt, manifests:{name:{file,sha256}}})
 *      with sorted keys and a trailing newline, then signs the EXACT bytes
 *      with Ed25519 → index.sig ("ed25519:<base64>").
 *
 * The public key printed at the end must be embedded in
 * src/registry/verify.ts (REGISTRY_PUBLIC_KEY_PEM) whenever the keypair is
 * (re)generated. The private key in this directory is a DEV key: it signs the
 * in-repo development registry only and MUST be replaced by the release key
 * (EPIC-09) for any production distribution. It is NOT a secret that protects
 * user data — it only anchors manifest integrity for the dev workflow.
 *
 * Portable: no dependencies, relative paths only. Used by maintainers, and by
 * tests/registry.test.ts to re-sign intentionally-tampered fixture copies.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const registryDir = path.resolve(
  process.argv[2] ?? path.dirname(fileURLToPath(import.meta.url)),
);
const keysDir = path.join(registryDir, "keys");
const privPath = path.join(keysDir, "dev-private.pem");
const pubPath = path.join(keysDir, "dev-public.pem");

// 1. Keypair (keep-first).
if (!fs.existsSync(privPath)) {
  fs.mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(privPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  fs.writeFileSync(pubPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
  console.log(`generated DEV keypair in ${keysDir}`);
}
const privateKeyPem = fs.readFileSync(privPath, "utf8");
const publicKeyPem = fs.readFileSync(pubPath, "utf8");

// 2. Manifest hashes. The manifest name is the basename minus .yaml; the
// loader cross-checks it against the `name` field inside the manifest.
const files = fs
  .readdirSync(registryDir)
  .filter((f) => f.endsWith(".yaml"))
  .sort();
if (files.length === 0) {
  console.error(`no *.yaml manifests found in ${registryDir}`);
  process.exit(1);
}
const manifests = {};
for (const file of files) {
  const bytes = fs.readFileSync(path.join(registryDir, file));
  manifests[file.replace(/\.yaml$/, "")] = {
    file,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
  };
}

// 3. Index + signature over the exact bytes.
const index = {
  version: 1,
  updatedAt: new Date().toISOString(),
  manifests: Object.fromEntries(
    Object.entries(manifests).sort(([a], [b]) => a.localeCompare(b)),
  ),
};
const indexBytes = Buffer.from(JSON.stringify(index, null, 2) + "\n", "utf8");
const sig = crypto.sign(null, indexBytes, privateKeyPem).toString("base64");

const tmpIndex = path.join(registryDir, "index.json.tmp");
fs.writeFileSync(tmpIndex, indexBytes);
fs.renameSync(tmpIndex, path.join(registryDir, "index.json"));
fs.writeFileSync(path.join(registryDir, "index.sig"), `ed25519:${sig}\n`);

const fingerprint = crypto
  .createHash("sha256")
  .update(crypto.createPublicKey(publicKeyPem).export({ type: "spki", format: "der" }))
  .digest("hex");
console.log(`signed ${files.length} manifests → ${path.join(registryDir, "index.json")}`);
console.log(`key fingerprint: sha256:${fingerprint}`);
console.log(`\npublic key (must match REGISTRY_PUBLIC_KEY_PEM in src/registry/verify.ts):\n${publicKeyPem}`);
