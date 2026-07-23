/**
 * ScopeGate Cloud — data model (EPIC-10, H10.1).
 *
 * LOCAL-FIRST / metadata-only rules that shape every type below:
 *   - The control plane NEVER stores secret values. Agents enroll with a
 *     pubkey fingerprint (+ the pubkey PEM, which is PUBLIC by definition);
 *     audit events travel with inputs already hashed by the gateway; any
 *     string that still looks like a secret is rejected at ingest (guard.ts).
 *   - `agentSecret` (the agent bearer credential) is stored as a sha256 hash
 *     only — the plaintext is returned exactly once, at enroll time.
 *   - `enrollToken` is stored in cleartext: it is the human-distributed
 *     bootstrap credential that the dashboard must be able to display
 *     (admin-only). The cloud home dir is the trust boundary (files 0600).
 *
 * Persistence is dev-grade file JSON (store.ts) behind the `Store` interface
 * so a Postgres implementation can replace it without touching callers.
 */

/** A customer team (the tenant of this dev-grade control plane). */
export interface Team {
  teamId: string;
  name: string;
  /** Bootstrap token the human pastes into `scopegate cloud enroll` (cleartext, see header). */
  enrollToken: string;
  /** Slack-compatible incoming webhook for approval alerts (alerts.ts). */
  slackWebhookUrl?: string;
  createdAt: string; // ISO 8601
}

/** An enrolled gateway/agent identity. */
export interface Agent {
  agentId: string;
  teamId: string;
  /** "sha256:<hex>" of the agent's Ed25519 SPKI DER (see src/audit/identity.ts). */
  fingerprint: string;
  /** PEM SPKI public key — PUBLIC material, required to verify event signatures. */
  publicKey?: string;
  /** sha256 hex of the agentSecret bearer. Plaintext is never stored. */
  secretHash: string;
  enrolledAt: string; // ISO 8601
  /** Last successful audit ingest (any accepted event). */
  lastSeen: string | null;
  revoked: boolean;
  revokedAt?: string;
  /** Chain tail of the last RECEIVED event (accepted or not) — gap detection. */
  lastChainHash?: string;
}

/** One versioned, cloud-signed team policy. */
export interface PolicyVersion {
  teamId: string;
  version: number; // 1-based, strictly increasing per team
  yaml: string;
  /** "ed25519:<base64>" over policyCanonical() — signed with the cloud key. */
  signature: string;
  signedAt: string; // ISO 8601
}

/** Fleet-revocation record (feed consumed by gateways). */
export interface Revocation {
  teamId: string;
  agentId: string;
  reason: string; // mandatory — it lands in audit
  ts: string; // ISO 8601
}

/**
 * A human approval decision issued FROM THE PANEL (EPIC-10 H10.6, cloud
 * resolution channel). Gateways poll these (mirroring the revocations feed)
 * and apply them to their local pending queue via `resolveApproval` — the
 * policy engine then materializes the one-shot grant and audits exactly once.
 * Idempotent per `approvalId`: a re-resolve returns the existing decision.
 */
export interface ApprovalDecision {
  approvalId: string;
  teamId: string;
  agentId: string;
  decision: "approved" | "denied";
  /** Mandatory for denials; optional note on approvals. */
  reason?: string;
  /** Optional TTL SHORTEN (approved only) — same rule as the CLI: never extends. */
  ttl?: string;
  /** Origin marker, e.g. "human:cloud:panel" — lands in the gateway's audit. */
  decidedBy: string;
  ts: string; // ISO 8601
}

/**
 * Audit event as stored by the cloud: the gateway's signed event verbatim
 * (schema from src/audit/log.ts) plus cloud-side ingest metadata.
 */
export interface StoredAuditEvent {
  ts: string;
  agentId: string;
  kind: string;
  detail: Record<string, unknown>;
  inputHash?: string;
  prev: string;
  seq: number;
  sig: string;
  hash: string;
  /** Cloud metadata — when it was ingested and whether the per-event
   *  Ed25519 signature verified against the enrolled agent pubkey. */
  _cloud: {
    ingestedAt: string;
    sigVerified: boolean;
  };
}

export interface AuditQuery {
  agentId?: string;
  kind?: string;
  since?: string; // inclusive ISO 8601
  limit?: number;
}

/* ------------------------------------------------------------------ */
/* Small runtime validators (the API boundary is untrusted JSON).      */
/* ------------------------------------------------------------------ */

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function asNonEmptyString(v: unknown): string | null {
  return typeof v === "string" && v.trim().length > 0 ? v : null;
}

/** HTTP error with a status code — router turns it into a JSON response. */
export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export function badRequest(message: string, code?: string): HttpError {
  return new HttpError(400, message, code);
}

export function unauthorized(message = "missing or invalid credentials"): HttpError {
  return new HttpError(401, message, "unauthorized");
}

export function forbidden(message = "insufficient scope"): HttpError {
  return new HttpError(403, message, "forbidden");
}

export function notFound(message: string, code?: string): HttpError {
  return new HttpError(404, message, code);
}
