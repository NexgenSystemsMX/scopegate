/**
 * Audit log: append-only JSONL with a hash chain (each entry commits to the
 * previous entry's hash) AND an Ed25519 signature per event (EPIC-07). The
 * chain gives tamper-evidence; the signature gives tamper-RESISTANCE and
 * attribution — re-chaining rewritten events requires the identity private
 * key (see identity.ts). Inputs are hashed, not stored, so the audit log
 * itself can never leak payload secrets or PII.
 *
 * Event schema (v1, signed):
 *   { ts, agentId, kind, detail, inputHash?, prev, seq, sig, hash }
 *   - seq:  integer, strictly +1 per event, first event is 1. Survives
 *     restarts by reading the current file tail (legacy unsigned events —
 *     pre-EPIC-07 lines without seq — implicitly occupy positions 1..N, so
 *     the first signed event after an upgrade gets seq N+1).
 *   - sig:  "ed25519:<base64>" signature over the CANONICAL UNSIGNED
 *     serialization (below), which includes prev and seq — so a signature
 *     binds the event to its exact chain position.
 *   - hash: sha256 hex of `prev + canonicalSigned(event)` — the same
 *     `prev + JSON.stringify(...)` formula the chain has always used, now
 *     committing to seq and sig as well. Kept as bare hex (not "sha256:"-prefixed)
 *     for chain continuity with pre-signing logs; only sig is algorithm-prefixed.
 *   - prev: hash of the previous entry ("genesis" for the first).
 *
 * Canonicalization (documented, stable — DO NOT change without a schema bump):
 *   canonicalUnsigned(e) = JSON.stringify of the object with keys in this
 *   exact fixed order, compact separators, UTF-8:
 *     ts, agentId, kind, detail, inputHash (only if defined), prev, seq
 *   canonicalSigned(e)   = same object plus a final "sig" key.
 *   Key order inside `detail` is preserved exactly as provided by the caller
 *   (JSON round-trips it); verifiers re-serialize through these two functions,
 *   which normalizes top-level key order regardless of how the line was written.
 *
 * FROZEN event taxonomy (Sprint-1 contract with EPIC-02 and future sprints):
 * the kind union below is append-only BY AGREEMENT — new kinds require
 * coordination; none may be removed or renamed.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import { AUDIT_LOG_PATH, ensureDir } from "../config/config.js";
import { loadOrCreateIdentity, signCanonical } from "./identity.js";

/** FROZEN taxonomy — see header. Single runtime source of truth for `AuditKind`. */
export const AUDIT_KINDS = [
  // Sprint 0 (pre-existing)
  "tool_call",
  "capability_request",
  "capability_denied",
  "secret_ref_used",
  "upstream_registered",
  "policy_proposed",
  "gateway_start",
  // EPIC-07 frozen additions (emitted by this and future sprints)
  "token_minted",
  "token_mint_failed",
  "token_refreshed",
  "token_refresh_failed",
  "oauth_reauth_required",
  "oauth_reauth_completed",
  "ceiling_blocked",
  "approval_requested",
  "approval_approved",
  "approval_denied",
  "approval_expired",
  "approval_waited",
  "secret_materialized",
  "policy_accepted",
  "policy_rejected",
  "grant_issued",
  "grant_expired",
  "grants_revoked",
  "redaction_applied",
  "policy_reload_error",
  "honeytoken_triggered",
  "agent_revoked",
  // Mejoras del agente (append-only, wave A): approval continuation.
  "intent_queued",
  "intent_executed",
  // Mejoras del agente (append-only, wave C): task leases + idempotency.
  "lease_opened",
  "lease_renewed",
  "lease_revoked",
  "idempotency_replayed",
  // Mejoras del agente (append-only, wave D): plans + result handles.
  "plan_requested",
  "result_stored",
  // Mejoras del agente (append-only, wave E): delegation + taint.
  "grant_delegated",
  "taint_detected",
  // M3: git credential-helper mints.
  "git_credential_minted",
  // Consola de administración (/admin/*): mutaciones del vault hechas por una
  // persona identificada. Las capacidades y políticas reutilizan
  // grants_revoked / policy_accepted.
  "secret_added",
  "secret_rotated",
  "secret_deleted",
] as const;

export type AuditKind = (typeof AUDIT_KINDS)[number];

export interface AuditEvent {
  ts: string;
  agentId: string;
  kind: AuditKind;
  detail: Record<string, unknown>;
  inputHash?: string;
  prev: string; // hash of previous entry ("genesis" for the first)
  seq: number; // 1-based, strictly monotonic
  sig: string; // "ed25519:<base64>" over canonicalUnsigned
  hash: string; // sha256 hex of prev + canonicalSigned
}

/** Event before signing; event before hashing. Structural views of AuditEvent. */
export type UnsignedEvent = Omit<AuditEvent, "sig" | "hash">;
export type SignedEvent = Omit<AuditEvent, "hash">;

/** Canonical serialization the signature commits to (see header). */
export function canonicalUnsigned(e: UnsignedEvent): string {
  const o: Record<string, unknown> = {
    ts: e.ts,
    agentId: e.agentId,
    kind: e.kind,
    detail: e.detail,
  };
  if (e.inputHash !== undefined) o.inputHash = e.inputHash;
  o.prev = e.prev;
  o.seq = e.seq;
  return JSON.stringify(o);
}

/** Canonical serialization the chain hash commits to (unsigned + sig). */
export function canonicalSigned(e: SignedEvent): string {
  const o: Record<string, unknown> = {
    ts: e.ts,
    agentId: e.agentId,
    kind: e.kind,
    detail: e.detail,
  };
  if (e.inputHash !== undefined) o.inputHash = e.inputHash;
  o.prev = e.prev;
  o.seq = e.seq;
  o.sig = e.sig;
  return JSON.stringify(o);
}

interface Tail {
  hash: string;
  seq: number;
}

let lastTail: Tail | null = null;

function readTailFromDisk(): Tail {
  if (!fs.existsSync(AUDIT_LOG_PATH)) return { hash: "genesis", seq: 0 };
  const lines = fs
    .readFileSync(AUDIT_LOG_PATH, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0);
  const last = lines[lines.length - 1];
  if (!last) return { hash: "genesis", seq: 0 };
  try {
    const e = JSON.parse(last) as Partial<AuditEvent>;
    const hash = typeof e.hash === "string" ? e.hash : "genesis";
    // Legacy unsigned events have no seq: they implicitly occupy positions
    // 1..N, so the chain continues at N+1 (see header).
    const seq =
      typeof e.seq === "number" && Number.isInteger(e.seq) ? e.seq : lines.length;
    return { hash, seq };
  } catch {
    return { hash: "genesis", seq: 0 };
  }
}

function tailState(): Tail {
  if (lastTail) return lastTail;
  return readTailFromDisk();
}

/** seq of the current on-disk tail (0 when no log). Always fresh — used by the index freshness check. */
export function auditTailSeq(): number {
  return readTailFromDisk().seq;
}

export function audit(
  agentId: string,
  kind: AuditEvent["kind"],
  detail: Record<string, unknown>,
  input?: unknown,
): void {
  ensureDir();
  const identity = loadOrCreateIdentity();
  const { hash: prev, seq: prevSeq } = tailState();
  // Property insertion order here defines the on-disk key order and must match
  // the canonical serializers above: ts, agentId, kind, detail, inputHash?,
  // prev, seq, sig, hash.
  const unsigned: UnsignedEvent = {
    ts: new Date().toISOString(),
    agentId,
    kind,
    detail,
    ...(input === undefined
      ? {}
      : {
          inputHash: crypto
            .createHash("sha256")
            .update(JSON.stringify(input))
            .digest("hex"),
        }),
    prev,
    seq: prevSeq + 1,
  };
  const signed: SignedEvent = {
    ...unsigned,
    sig: signCanonical(identity, canonicalUnsigned(unsigned)),
  };
  const event: AuditEvent = {
    ...signed,
    hash: crypto
      .createHash("sha256")
      .update(prev + canonicalSigned(signed))
      .digest("hex"),
  };
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(event) + "\n", {
    mode: 0o600,
  });
  lastTail = { hash: event.hash, seq: event.seq };
}
