/**
 * Centralized audit ingestion (EPIC-10, H10.3).
 *
 *   POST /v1/audit/batch { agentId, events: [...], signature }
 *     → { accepted, rejected, duplicates, rejections: [{index, seq, reason}] }
 *
 * Trust model — the control plane trusts NOTHING the transport says:
 *   1. BATCH signature: `signature` must be an Ed25519 signature by the
 *      ENROLLED agent pubkey over the batch. Accepted canonicalizations
 *      (either verifies → batch is authentic; both commit to the full,
 *      ordered event list):
 *        a) JSON.stringify(events)
 *        b) JSON.stringify({ agentId, events })
 *      (key order as shown, compact separators, UTF-8 — FROZEN, shared with
 *      the CLOUD-SYNC client). A batch whose signature is missing or invalid
 *      is rejected WHOLESALE: provenance failure is not a per-event matter.
 *   2. PER-EVENT verification (this is what `rejected` counts granularity):
 *      shape → duplicate (agentId+seq, at-least-once dedup per EPIC-07) →
 *      hash recompute sha256(prev + canonicalSigned) → Ed25519 sig via
 *      verifyCanonical against the enrolled pubkey → intra-batch chain link
 *      (events[i].prev === events[i-1].hash) → secret scan.
 *   3. SECRET SCAN: every received string value passes the looksLikeSecret
 *      guard (guard.ts) before ANY byte is persisted — a hit rejects the
 *      event with reason "secret_like_payload" and it is never stored
 *      (EPIC-10 acceptance: "Secretos recibidos en el control plane: 0").
 *
 * An agent enrolled WITHOUT a pubkey PEM gets every event rejected with
 * reason "agent_pubkey_not_enrolled" — fail-closed: unverifiable provenance
 * is not ingestible.
 *
 * Cross-batch continuity: the store tracks the agent's last received chain
 * hash. A batch whose first event does not continue it (and is not a fresh
 * "genesis" chain) is ACCEPTED but flagged `chainGap: true` and reported to
 * the alerts hook — gaps mean loss or tampering; forgery is already caught
 * fail-closed by the hash/signature checks above, so gaps stay fail-open.
 */
import crypto from "node:crypto";
import { verifyCanonical } from "../../audit/identity.js";
import {
  canonicalSigned,
  canonicalUnsigned,
  type SignedEvent,
  type UnsignedEvent,
} from "../../audit/log.js";
import { findSecretLikeStrings } from "./guard.js";
import {
  asNonEmptyString,
  badRequest,
  forbidden,
  isRecord,
  type Agent,
  type StoredAuditEvent,
  type Team,
} from "./model.js";
import type { Store } from "./store.js";

export interface IngestRejection {
  index: number;
  seq: number | null;
  reason: string;
}

export interface IngestResult {
  accepted: number;
  rejected: number;
  /** Already-stored agentId+seq pairs (at-least-once resends). */
  duplicates: number;
  rejections: IngestRejection[];
  /** First event did not continue the agent's known chain tail. */
  chainGap?: true;
}

export interface IngestHooks {
  /** Called with ACCEPTED events (already persisted) — e.g. approval alerts. */
  onAcceptedEvents?: (team: Team, events: StoredAuditEvent[]) => void;
  /** Called when a cross-batch chain gap is detected (loss/tamper signal). */
  onChainGap?: (team: Team, agentId: string, detail: Record<string, unknown>) => void;
}

const MAX_EVENTS_PER_BATCH = 5000;

function recomputeHash(e: {
  ts: string;
  agentId: string;
  kind: string;
  detail: Record<string, unknown>;
  inputHash?: string;
  prev: string;
  seq: number;
  sig: string;
}): string {
  // The cloud accepts any `kind` string (forward-compat with newer gateways);
  // canonicalization only re-serializes the fields, so the cast is safe.
  return crypto
    .createHash("sha256")
    .update(e.prev + canonicalSigned(e as SignedEvent))
    .digest("hex");
}

function eventShapeError(e: unknown, batchAgentId: string): string | null {
  if (!isRecord(e)) return "event is not an object";
  if (typeof e.ts !== "string") return "ts missing";
  if (e.agentId !== batchAgentId) return "agentId mismatch with batch";
  if (typeof e.kind !== "string") return "kind missing";
  if (!isRecord(e.detail)) return "detail missing";
  if (typeof e.prev !== "string") return "prev missing";
  if (!Number.isInteger(e.seq) || (e.seq as number) < 1) return "seq invalid";
  if (typeof e.sig !== "string") return "sig missing";
  if (typeof e.hash !== "string") return "hash missing";
  return null;
}

export function ingestBatch(
  store: Store,
  team: Team,
  body: unknown,
  hooks: IngestHooks = {},
): IngestResult {
  if (!isRecord(body)) throw badRequest("body must be a JSON object");
  const agentId = asNonEmptyString(body.agentId);
  if (!agentId) throw badRequest("agentId is required");
  if (!Array.isArray(body.events)) throw badRequest("events must be an array");
  if (body.events.length > MAX_EVENTS_PER_BATCH) {
    throw badRequest(`events exceeds max batch size (${MAX_EVENTS_PER_BATCH})`);
  }
  const events = body.events as unknown[];

  const agent = store.getAgent(team.teamId, agentId);
  if (!agent) {
    throw forbidden(`agent ${agentId} is not enrolled in team ${team.teamId}`);
  }

  const rejections: IngestRejection[] = [];
  const rejectAll = (reason: string): IngestResult => ({
    accepted: 0,
    rejected: events.length,
    duplicates: 0,
    rejections: events.map((e, index) => ({
      index,
      seq: isRecord(e) && Number.isInteger(e.seq) ? (e.seq as number) : null,
      reason,
    })),
  });

  // Fail-closed: without the enrolled pubkey nothing is verifiable.
  if (!agent.publicKey) return rejectAll("agent_pubkey_not_enrolled");
  const pubkey = agent.publicKey;

  // 1) Batch signature — wholesale provenance check.
  const signature = asNonEmptyString(body.signature);
  if (!signature) return rejectAll("batch_signature_missing");
  const batchCanonicalCandidates = [
    JSON.stringify(events),
    JSON.stringify({ agentId, events }),
  ];
  const batchOk = batchCanonicalCandidates.some((c) =>
    verifyCanonical(pubkey, c, signature),
  );
  if (!batchOk) return rejectAll("batch_signature_invalid");

  // 2) Per-event pipeline.
  const known = store.knownAuditSeqs(team.teamId, agentId);
  const acceptedEvents: StoredAuditEvent[] = [];
  let duplicates = 0;
  let chainGap = false;
  let lastValidChainHash: string | undefined;

  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const seq = isRecord(e) && Number.isInteger(e.seq) ? (e.seq as number) : null;
    const reject = (reason: string): void => {
      rejections.push({ index: i, seq, reason });
    };

    const shapeError = eventShapeError(e, agentId);
    if (shapeError !== null) {
      reject(`shape_invalid: ${shapeError}`);
      continue;
    }
    const ev = e as {
      ts: string;
      agentId: string;
      kind: string;
      detail: Record<string, unknown>;
      inputHash?: string;
      prev: string;
      seq: number;
      sig: string;
      hash: string;
    };

    // At-least-once dedup (EPIC-07 H7.9: receptor deduplica por agentId+seq).
    if (known.has(ev.seq)) {
      duplicates++;
      lastValidChainHash = ev.hash; // already stored: still the chain tail
      continue;
    }

    if (recomputeHash(ev) !== ev.hash) {
      reject("hash_mismatch");
      continue;
    }
    if (!verifyCanonical(pubkey, canonicalUnsigned(ev as UnsignedEvent), ev.sig)) {
      reject("signature_invalid");
      continue;
    }

    // Chain links across the RECEIVED sequence (what the gateway sent).
    if (i > 0) {
      const prevEvent = events[i - 1];
      const prevHash =
        isRecord(prevEvent) && typeof prevEvent.hash === "string"
          ? prevEvent.hash
          : null;
      if (ev.prev !== prevHash) {
        reject("chain_link_invalid");
        continue;
      }
    } else if (
      agent.lastChainHash &&
      ev.prev !== agent.lastChainHash &&
      ev.prev !== "genesis"
    ) {
      chainGap = true; // loss or tamper signal — flagged, not rejected (see header)
    }

    const secretHits = findSecretLikeStrings(ev);
    if (secretHits.length > 0) {
      reject(`secret_like_payload at ${secretHits[0].path}`);
      continue;
    }

    acceptedEvents.push({
      ...ev,
      _cloud: { ingestedAt: new Date().toISOString(), sigVerified: true },
    });
    known.add(ev.seq);
    lastValidChainHash = ev.hash;
  }

  store.appendAuditEvents(team.teamId, acceptedEvents);

  const patch: Partial<Agent> = {};
  if (acceptedEvents.length > 0) patch.lastSeen = new Date().toISOString();
  if (lastValidChainHash !== undefined) patch.lastChainHash = lastValidChainHash;
  if (Object.keys(patch).length > 0) {
    store.updateAgent(team.teamId, agentId, patch);
  }

  if (acceptedEvents.length > 0) hooks.onAcceptedEvents?.(team, acceptedEvents);
  if (chainGap) {
    hooks.onChainGap?.(team, agentId, {
      expectedPrev: agent.lastChainHash ?? null,
      batchFirstSeq: seq0(events),
    });
  }

  return {
    accepted: acceptedEvents.length,
    rejected: rejections.length,
    duplicates,
    rejections,
    ...(chainGap ? { chainGap: true as const } : {}),
  };
}

function seq0(events: unknown[]): number | null {
  const e0 = events[0];
  return isRecord(e0) && Number.isInteger(e0.seq) ? (e0.seq as number) : null;
}
