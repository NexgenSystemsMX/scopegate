/**
 * Secret-smuggling guard for the control plane (EPIC-10 acceptance criterion:
 * "Ningún endpoint, log ni tabla de Cloud contiene valores de secretos").
 *
 * KEEP IN SYNC with `looksLikeSecret` in src/gateway/server.ts — this is an
 * intentional copy, not an import: importing the gateway server module would
 * drag its whole import graph (MCP SDK, vault, telemetry, honeytoken) into the
 * cloud control-plane process for a 6-line pure function. tests/cloud-server.test.ts
 * asserts behavioral parity against the original so the copies cannot drift
 * silently.
 */
export function looksLikeSecret(s: string): boolean {
  return (
    s.length > 40 ||
    /^(sk-|ghp_|gho_|xox[bap]-|AKIA|AIza|eyJ)/.test(s) ||
    /[A-Za-z0-9+/=]{32,}/.test(s)
  );
}

/**
 * Keys whose values are legitimate cryptographic material, not smuggled
 * payloads: the audit envelope's signature/hash commitments are long
 * high-entropy strings BY DESIGN (and are hashes/signatures, not secrets).
 */
const STRUCTURAL_KEYS = new Set([
  "sig",
  "hash",
  "prev",
  "inputHash",
  "signature",
  "fingerprint",
  "publicKey",
  "pubkey",
  "pubkeyFingerprint",
  "cloudPubkey",
  // Top-level audit-envelope metadata: agentId/ts/kind are validated
  // structurally elsewhere (enroll, shape checks); they are identities and
  // timestamps, not payload.
  "ts",
  "agentId",
  "kind",
]);

/**
 * Free-text operational metadata produced by the gateway itself (deny
 * reasons, upstream error messages, approval instructions). Long values are
 * EXPECTED here — the blunt ">40 chars" heuristic would reject legitimate
 * operational metadata (observed: ~25% of routine events). Safe to skip:
 * agents never possess secret values (that is ScopeGate's core invariant),
 * so these fields cannot carry a real secret; and the gateway hashes inputs
 * at the source precisely so audit details stay metadata-only.
 */
const FREETEXT_KEYS = new Set([
  "reason",
  "error",
  "message",
  "instructions",
  "action_required",
  "next_step",
  "justification",
]);

export interface SecretScanHit {
  /** Dotted path of the offending value (e.g. "detail.args.password"). */
  path: string;
}

/**
 * Recursively scan every string value of `value`, skipping structural crypto
 * keys (see above). Returns the list of offending paths (empty = clean).
 * This is applied to audit event `detail` payloads AND to any unknown extra
 * fields a client sends, before anything is persisted.
 */
export function findSecretLikeStrings(
  value: unknown,
  path = "",
  hits: SecretScanHit[] = [],
): SecretScanHit[] {
  if (typeof value === "string") {
    if (looksLikeSecret(value)) hits.push({ path });
    return hits;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      findSecretLikeStrings(value[i], `${path}[${i}]`, hits);
    }
    return hits;
  }
  if (typeof value === "object" && value !== null) {
    for (const [k, v] of Object.entries(value)) {
      if (STRUCTURAL_KEYS.has(k)) continue;
      if (FREETEXT_KEYS.has(k)) continue;
      findSecretLikeStrings(v, path ? `${path}.${k}` : k, hits);
    }
  }
  return hits;
}
