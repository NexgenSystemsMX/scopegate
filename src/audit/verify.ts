/**
 * Audit trail verification (EPIC-07 H7.2): replays audit.jsonl checking, for
 * every event and in this order:
 *   1. seq continuity — event i must carry seq i (1-based); a gap means the
 *      log was truncated, reordered or rewritten.
 *   2. hash-chain continuity — prev must equal the previous event's hash
 *      ("genesis" for the first).
 *   3. hash integrity — recomputing sha256(prev + canonicalSigned) must match
 *      the stored hash (detects any content edit, including to sig).
 *   4. Ed25519 signature — verified against the local identity public key;
 *      an attacker who recomputes hashes after editing still cannot re-sign.
 * The FIRST failing event is reported with its exact seq (and file line).
 *
 * Notes:
 *   - Legacy unsigned events (pre-EPIC-07 lines without seq/sig) FAIL
 *     verification at their position — unsigned events are not attributable.
 *   - Verification NEVER creates an identity: a missing/corrupt identity.json
 *     with a non-empty log is a verification failure, not a key generation.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import { isPruned, readAuditLines } from "./segments.js";
import {
  canonicalSigned,
  canonicalUnsigned,
  type AuditEvent,
} from "./log.js";
import { loadIdentity, verifyCanonical, type AgentIdentity } from "./identity.js";

export interface VerifyOk {
  ok: true;
  events: AuditEvent[];
  count: number;
  /** Fingerprint of the identity the events verified against (null when the log is empty). */
  fingerprint: string | null;
  /**
   * Set when retention pruned the oldest segments: the chain no longer reaches
   * genesis and was verified from this seq onward. Absent means "from genesis".
   */
  verifiedFromSeq?: number;
}

export interface VerifyFail {
  ok: false;
  /** 1-based line in audit.jsonl of the first invalid event. */
  line: number;
  /** seq of the first invalid event (null when the event carries none). */
  seq: number | null;
  reason: string;
}

export type VerifyResult = VerifyOk | VerifyFail;

/**
 * Parse the whole log. Throws an Error naming the 1-based line on the first
 * unparseable entry. Used by the index/query paths; verifyAuditLog converts
 * that throw into a VerifyFail.
 */
export function readAuditEvents(): AuditEvent[] {
  // All rotated segments plus the live one, oldest first: the chain is one
  // logical log even when it lives in several files.
  const lines = readAuditLines();
  return lines.map((l, i) => {
    try {
      return JSON.parse(l) as AuditEvent;
    } catch {
      throw new Error(`audit.jsonl line ${i + 1}: unparseable JSON (log truncated mid-write?)`);
    }
  });
}

export function verifyAuditLog(): VerifyResult {
  let events: AuditEvent[];
  try {
    events = readAuditEvents();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const m = /line (\d+)/.exec(msg);
    return { ok: false, line: m ? Number(m[1]) : 0, seq: null, reason: msg };
  }
  if (events.length === 0) {
    return { ok: true, events, count: 0, fingerprint: null };
  }

  let identity: AgentIdentity;
  try {
    identity = loadIdentity();
  } catch (e) {
    const first = events[0];
    return {
      ok: false,
      line: 1,
      seq: Number.isInteger(first?.seq) ? (first.seq as number) : null,
      reason: `cannot verify signatures: ${e instanceof Error ? e.message : String(e)}`,
    };
  }

  // A pruned log (retention dropped the oldest segments) no longer starts at
  // genesis. Its first retained event is trusted as the starting point and the
  // result says where verification begins — pretending the chain still reached
  // genesis would be a lie, and reporting a break would read like tampering.
  const firstSeq = Number.isInteger(events[0]?.seq) ? (events[0].seq as number) : 1;
  const pruned = isPruned() && firstSeq > 1;
  if (firstSeq > 1 && !pruned) {
    return {
      ok: false,
      line: 1,
      seq: firstSeq,
      reason: `log does not start at seq 1 (starts at ${firstSeq}) and no retention marker explains it — truncated or rewritten`,
    };
  }
  const baseSeq = pruned ? firstSeq : 1;
  let prev = pruned ? events[0].prev : "genesis";
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const line = i + 1;
    const expectedSeq = baseSeq + i;
    if (!Number.isInteger(e.seq)) {
      return {
        ok: false,
        line,
        seq: null,
        reason:
          "missing or non-integer seq (unsigned legacy event — not attributable, cannot be verified)",
      };
    }
    if (e.seq !== expectedSeq) {
      return {
        ok: false,
        line,
        seq: e.seq,
        reason: `seq discontinuity: expected ${expectedSeq} — log truncated, reordered or rewritten`,
      };
    }
    if (e.prev !== prev) {
      return {
        ok: false,
        line,
        seq: e.seq,
        reason: "hash-chain break: prev does not match the previous event's hash",
      };
    }
    const hash = crypto
      .createHash("sha256")
      .update(e.prev + canonicalSigned(e))
      .digest("hex");
    if (hash !== e.hash) {
      return {
        ok: false,
        line,
        seq: e.seq,
        reason: "hash mismatch: event content was modified after signing",
      };
    }
    if (!verifyCanonical(identity.publicKey, canonicalUnsigned(e), e.sig)) {
      return {
        ok: false,
        line,
        seq: e.seq,
        reason:
          "invalid Ed25519 signature (event forged or re-chained without the identity private key)",
      };
    }
    prev = e.hash;
  }
  return {
    ok: true,
    events,
    count: events.length,
    fingerprint: identity.fingerprint,
    ...(pruned ? { verifiedFromSeq: baseSeq } : {}),
  };
}

/**
 * CLI body of `scopegate audit verify`. Prints the outcome and returns the
 * process exit code: 0 when the trail is intact, 1 naming the first invalid
 * event's seq otherwise.
 */
export function runVerifyCli(): number {
  const r = verifyAuditLog();
  if (r.ok) {
    console.log(
      `audit log OK: ${r.count} event(s) verified (seq + hash chain + Ed25519 signatures` +
        `${r.fingerprint ? `, identity ${r.fingerprint}` : ""})` +
        // Say it out loud: "OK" over a pruned window is a weaker claim than
        // "OK" over the whole history, and the reader must know which one this is.
        `${r.verifiedFromSeq ? ` — from seq ${r.verifiedFromSeq}; earlier segments pruned by retention` : ""}.`,
    );
    return 0;
  }
  console.error(
    `audit log INVALID: first invalid event seq=${r.seq ?? "unknown"} (line ${r.line}): ${r.reason}`,
  );
  return 1;
}
