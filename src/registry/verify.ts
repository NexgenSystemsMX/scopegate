/**
 * Registry verification (EPIC-12) — FAIL-CLOSED, always:
 *   - The index is accepted only with a valid Ed25519 signature over its
 *     exact bytes, made by the registry key embedded below.
 *   - A manifest is accepted only when its sha256 matches the signed index
 *     entry AND (for stdio transports) its command is a bare name on the
 *     embedded allowlist (supply-chain mitigation).
 * Every check throws on failure — a tampered registry is an ERROR, never a
 * warning, and nothing from it is ever applied.
 *
 * The key below is the DEV registry key (registry/keys/, documented as DEV).
 * Production distribution must re-sign with the release key (EPIC-09) and
 * update this constant. Regenerate index+signature: node registry/sign-index.mjs
 */
import crypto from "node:crypto";

/**
 * Trust anchor. fingerprint: sha256:e9f6e849a524cbd308c6f8cc14932c8709eeaa8d24d58024212d5250ef26ce3e
 * (mirrors registry/keys/dev-public.pem — keep both in sync).
 */
export const REGISTRY_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAncA8UGBmtH/VwFxwx7CPVn8B+8zWDkofhrhaX1ac9XA=
-----END PUBLIC KEY-----
`;

export const INDEX_SIG_PREFIX = "ed25519:";

/**
 * Supply-chain allowlist for stdio manifests: the ONLY executable names a
 * registry manifest may spawn. Commands must additionally be BARE names —
 * anything containing a path separator is rejected even if its basename is
 * listed (otherwise "/tmp/evil/npx" would pass).
 */
export const STDIO_COMMAND_ALLOWLIST: readonly string[] = [
  "npx",
  "node",
  "uvx",
  "uv",
  "docker",
  "python",
  "python3",
  "deno",
  "bun",
];

/** Hex sha256 of the given bytes. */
export function sha256Hex(bytes: Buffer | string): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * Verify the Ed25519 signature over the exact index bytes. Throws
 * (fail-closed) when the signature is malformed or invalid.
 */
export function verifyIndexSignature(indexBytes: Buffer, sigRaw: string): void {
  const sig = sigRaw.trim();
  if (!sig.startsWith(INDEX_SIG_PREFIX)) {
    throw new Error(
      `registry index signature has an unsupported format (expected '${INDEX_SIG_PREFIX}<base64>')`,
    );
  }
  let ok = false;
  try {
    ok = crypto.verify(
      null,
      indexBytes,
      REGISTRY_PUBLIC_KEY_PEM,
      Buffer.from(sig.slice(INDEX_SIG_PREFIX.length), "base64"),
    );
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new Error(
      "registry index signature verification FAILED — the index was tampered with or signed by an unknown key (fail-closed)",
    );
  }
}

/**
 * Verify a manifest against its signed index entry. Throws on mismatch.
 */
export function verifyManifestSha256(manifestBytes: Buffer, expectedSha256: string, file: string): void {
  const actual = sha256Hex(manifestBytes);
  if (actual !== expectedSha256.toLowerCase()) {
    throw new Error(
      `manifest '${file}' sha256 mismatch (expected ${expectedSha256}, got ${actual}) — tampered manifest (fail-closed)`,
    );
  }
}

/**
 * Enforce the stdio command allowlist. Throws (fail-closed) when the command
 * contains path separators or is not on the allowlist.
 */
export function assertStdioCommandAllowed(command: string): void {
  if (/[/\\]/.test(command)) {
    throw new Error(
      `stdio command '${command}' is rejected: registry manifests must use a bare executable name, not a path (fail-closed)`,
    );
  }
  const normalized = command.toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, "");
  if (!STDIO_COMMAND_ALLOWLIST.includes(normalized)) {
    throw new Error(
      `stdio command '${command}' is not on the registry allowlist (${STDIO_COMMAND_ALLOWLIST.join(", ")}) — rejected (fail-closed)`,
    );
  }
}
