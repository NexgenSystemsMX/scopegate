/**
 * ScopeGate Cloud — audit exporter (EPIC-10, consumes the EPIC-07 contract).
 *
 * Ships audit.jsonl events to the cloud in SIGNED BATCHES with at-least-once
 * semantics:
 *   - Cursor checkpointed on disk (~/.scopegate/audit-export-cursor.json):
 *     the last exported seq. A gateway restart resumes exactly there; the
 *     server dedups by agentId+seq, so a re-sent batch is harmless.
 *   - The batch is signed with the SAME agent identity that signs each event
 *     (src/audit/identity.ts), so the control plane verifies provenance
 *     without trusting the transport.
 *   - Metadata-only: events carry hashes (inputHash), never inputs — no
 *     secret or PII crosses the control plane by design.
 *   - Never blocks the request path: the exporter runs in a background loop
 *     (unref'd timers, see sync.ts) and every failure just backs off.
 *
 * Frozen wire contract:
 *   POST /v1/audit/batch {agentId, events, signature} → 200 {accepted, rejected}
 *
 * BATCH SIGNATURE CANONICALIZATION (contract point with AGENTE CLOUD-CORE):
 *   canonical = JSON.stringify({agentId, events})
 *   — keys in that exact order, each event the JSON-round-tripped AuditEvent
 *   object; signature "ed25519:<base64>" over those bytes (identity.ts
 *   format). The body also carries `pubkey` + `pubkeyFingerprint`
 *   (additive metadata): enroll only ships the fingerprint, so the pubkey
 *   rides along to let the server verify without a prior key exchange; the
 *   server must check fingerprintOf(pubkey) === enrolled fingerprint.
 *
 * Server ACK semantics (reconciled with CLOUD-CORE's ingest.ts): every
 * event is accounted for as `accepted` (newly stored), `duplicates`
 * (already known — at-least-once resends) or `rejected` (permanently
 * invalid: bad hash/signature/chain or secret-like payload). The cursor
 * advances past the whole batch on any 200 — rejected events are skipped
 * loudly instead of poison-looping (they stay in the local audit.jsonl,
 * which remains the source of truth).
 */
import fs from "node:fs";
import { readAuditLines } from "../../audit/segments.js";
import {
  loadOrCreateIdentity,
  signCanonical,
  type AgentIdentity,
} from "../../audit/identity.js";
import type { AuditEvent } from "../../audit/log.js";
import { AUDIT_EXPORT_CURSOR_PATH } from "./cloud-config.js";
import { atomicWriteFileSync } from "../../policy/fsutil.js";

export const DEFAULT_AUDIT_EXPORT_INTERVAL_MS = 10_000;
export const DEFAULT_AUDIT_BATCH_SIZE = 200;

export interface ExportCursor {
  /** Last seq successfully exported (or skipped as rejected). */
  lastSeq: number;
  updatedAt: string;
}

export interface SignedAuditBatch {
  agentId: string;
  events: AuditEvent[];
  signature: string; // "ed25519:<base64>" over canonicalAuditBatch
  /** Additive: lets the server verify without a prior pubkey exchange. */
  pubkey: string;
  pubkeyFingerprint: string;
}

/** The exact serialization the batch signature commits to (see header). */
export function canonicalAuditBatch(p: {
  agentId: string;
  events: AuditEvent[];
}): string {
  return JSON.stringify({ agentId: p.agentId, events: p.events });
}

export function loadExportCursor(): ExportCursor {
  try {
    const c = JSON.parse(
      fs.readFileSync(AUDIT_EXPORT_CURSOR_PATH, "utf8"),
    ) as Partial<ExportCursor>;
    if (typeof c.lastSeq === "number" && Number.isInteger(c.lastSeq) && c.lastSeq >= 0) {
      return { lastSeq: c.lastSeq, updatedAt: String(c.updatedAt ?? "") };
    }
  } catch {
    /* absent/corrupt cursor → export from the beginning */
  }
  return { lastSeq: 0, updatedAt: "" };
}

function saveExportCursor(lastSeq: number): void {
  atomicWriteFileSync(
    AUDIT_EXPORT_CURSOR_PATH,
    JSON.stringify({ lastSeq, updatedAt: new Date().toISOString() } satisfies ExportCursor) + "\n",
  );
}

/**
 * Read up to `limit` events with seq > afterSeq from audit.jsonl. Legacy
 * unsigned lines (no seq) implicitly occupy positions 1..N — the same rule
 * audit/log.ts uses to continue the chain. Unparseable lines are skipped
 * (they still occupy their implicit position, keeping seqs aligned).
 */
export function readEventsAfter(afterSeq: number, limit: number): AuditEvent[] {
  // All segments, oldest first: after a rotation the pending events live in
  // audit.jsonl.1, and reading only the live file would skip them for good —
  // the cursor only moves forward, so nothing would ever go back for them.
  const lines = readAuditLines();
  const out: AuditEvent[] = [];
  for (let i = 0; i < lines.length && out.length < limit; i++) {
    let e: Partial<AuditEvent>;
    try {
      e = JSON.parse(lines[i]) as Partial<AuditEvent>;
    } catch {
      continue;
    }
    const seq =
      typeof e.seq === "number" && Number.isInteger(e.seq) ? e.seq : i + 1;
    if (seq <= afterSeq) continue;
    out.push({ ...(e as AuditEvent), seq });
  }
  return out;
}

export interface AuditExportDeps {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  batchSize?: number;
  /** Injectable for tests; defaults to the real identity on disk. */
  identity?: AgentIdentity;
}

export interface AuditExportResult {
  sent: number;
  accepted: number;
  rejected: number;
  /** false when nothing was pending (cheap no-op tick). */
  hadPending: boolean;
}

/**
 * One export tick. Sends at most one batch; the cursor advances ONLY on a
 * server ACK (at-least-once). Throws on transport/HTTP error — the loop
 * backs off and the batch is re-sent on the next tick.
 */
export async function exportAuditOnce(
  cfg: { url: string; agentId: string; agentSecret: string },
  deps: AuditExportDeps = {},
): Promise<AuditExportResult> {
  const cursor = loadExportCursor();
  const events = readEventsAfter(cursor.lastSeq, deps.batchSize ?? DEFAULT_AUDIT_BATCH_SIZE);
  if (events.length === 0) {
    return { sent: 0, accepted: 0, rejected: 0, hadPending: false };
  }
  const identity = deps.identity ?? loadOrCreateIdentity();
  const batch: SignedAuditBatch = {
    agentId: cfg.agentId,
    events,
    signature: signCanonical(identity, canonicalAuditBatch({ agentId: cfg.agentId, events })),
    pubkey: identity.publicKey,
    pubkeyFingerprint: identity.fingerprint,
  };
  const fetchImpl = deps.fetchImpl ?? fetch;
  const res = await fetchImpl(`${cfg.url}/v1/audit/batch`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${cfg.agentSecret}`,
    },
    body: JSON.stringify(batch),
    signal: AbortSignal.timeout(deps.timeoutMs ?? 10_000),
  });
  if (!res.ok) {
    throw new Error(`audit export failed (HTTP ${res.status})`);
  }
  const ack = (await res.json()) as {
    accepted?: number;
    rejected?: number;
    duplicates?: number;
  };
  const accepted = typeof ack.accepted === "number" ? ack.accepted : events.length;
  const rejected = typeof ack.rejected === "number" ? ack.rejected : 0;
  const duplicates = typeof ack.duplicates === "number" ? ack.duplicates : 0;
  const lastBatchSeq = events[events.length - 1].seq;
  if (rejected > 0) {
    // Poison events can never become valid — skip them loudly instead of
    // blocking every subsequent event behind a retry loop.
    console.error(
      `[scopegate cloud] warn: cloud rejected ${rejected}/${events.length} audit event(s) ` +
        `(signature/chain invalid or secret-like payload) — skipping up to seq ${lastBatchSeq} for export; ` +
        `they remain in the local audit.jsonl`,
    );
    saveExportCursor(lastBatchSeq);
  } else if (accepted + duplicates >= events.length) {
    // Every event accounted for: stored now, or already known server-side
    // (an at-least-once resend after a crash is acked as duplicates).
    saveExportCursor(lastBatchSeq);
  } else {
    // Defensive: the server did not account for the whole batch — resume
    // right after the accepted prefix on the next tick.
    saveExportCursor(events[accepted - 1]?.seq ?? cursor.lastSeq);
  }
  return { sent: events.length, accepted, rejected, hadPending: true };
}
