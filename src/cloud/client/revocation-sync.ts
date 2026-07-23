/**
 * ScopeGate Cloud — fleet revocation sync (EPIC-10 H10.4).
 *
 * Poll GET /v1/revocations?teamId=&since= every
 * SCOPEGATE_CLOUD_REVOCATION_INTERVAL_MS (default 15 s — the end-to-end
 * target is an effective revocation in < 30 s on online gateways).
 *
 * When a revocation names THIS gateway's agentId (or "*" — a team-wide
 * revocation), the gateway:
 *   1. revokes every live grant of the agent (PolicyEngine.revokeAgent),
 *   2. persists ~/.scopegate/cloud-revoked.json — its PRESENCE denies every
 *      subsequent request in the request path (cloudRevocationCheckpoint,
 *      wired in gateway/server.ts next to the honeytoken gate), fail-closed
 *      and restart-proof (a revocation received while online still bites
 *      after a restart; no cloud round-trip is needed to enforce it),
 *   3. audits `agent_revoked` (best-effort — containment never waits on the
 *      audit trail).
 *
 * Application is idempotent: the revoked file is written once per revocation
 * episode; a human re-enables the agent by deleting the file (mirrors the
 * honeytoken suspended-state re-enable process — see honeytoken.ts header).
 *
 * Frozen wire contract:
 *   GET /v1/revocations?teamId=<id>&since=<ISO> → 200 {revocations: [...]}
 *   revocation: {teamId, agentId, reason, ts} — the server (CLOUD-CORE
 *   revocations.ts) timestamps with `ts`; `revokedAt` is also tolerated.
 */
import fs from "node:fs";
import { audit } from "../../audit/log.js";
import type { PolicyEngine } from "../../policy/engine.js";
import { CLOUD_REVOKED_PATH } from "./cloud-config.js";
import { atomicWriteFileSync } from "../../policy/fsutil.js";

export const DEFAULT_REVOCATION_SYNC_INTERVAL_MS = 15_000;

export interface CloudRevocation {
  agentId: string;
  reason?: string;
  /** Server-issued timestamp (CLOUD-CORE's field name). */
  ts?: string;
  /** Tolerated alias some implementations emit. */
  revokedAt?: string;
  scope?: string;
}

export interface CloudRevokedRecord {
  agentId: string;
  reason: string;
  revokedAt: string;
  appliedAt: string;
  source: "cloud";
}

/* ------------------------------------------------------------------------ */
/* Revoked-state file (mtime-cached reads — one stat syscall per request)    */
/* ------------------------------------------------------------------------ */

let cache: { mtimeMs: number | null; size: number; record: CloudRevokedRecord | null } | null =
  null;
let warnedCorrupt = false;

function readRevokedFromDisk(): CloudRevokedRecord | null {
  let raw: string;
  try {
    raw = fs.readFileSync(CLOUD_REVOKED_PATH, "utf8");
  } catch {
    return null;
  }
  try {
    const r = JSON.parse(raw) as Partial<CloudRevokedRecord>;
    if (typeof r?.agentId !== "string" || !r.agentId) return null;
    return {
      agentId: r.agentId,
      reason: String(r.reason ?? "revoked from ScopeGate Cloud"),
      revokedAt: String(r.revokedAt ?? ""),
      appliedAt: String(r.appliedAt ?? ""),
      source: "cloud",
    };
  } catch {
    // Mirror honeytoken.ts: a corrupt state file must not DoS the gateway —
    // treat as not-revoked and warn once (the sync loop re-applies a live
    // revocation on its next tick anyway).
    if (!warnedCorrupt) {
      warnedCorrupt = true;
      console.error(
        `[scopegate cloud] warn: ${CLOUD_REVOKED_PATH} is unreadable — treating cloud revocation state as empty`,
      );
    }
    return null;
  }
}

/** The persisted revocation record, or null when the agent is clear. */
export function loadRevokedRecord(): CloudRevokedRecord | null {
  let st: fs.Stats | null = null;
  try {
    st = fs.statSync(CLOUD_REVOKED_PATH);
  } catch {
    st = null;
  }
  const mtimeMs = st ? st.mtimeMs : null;
  const size = st ? st.size : 0;
  if (cache && cache.mtimeMs === mtimeMs && cache.size === size) {
    return cache.record;
  }
  const record = readRevokedFromDisk();
  cache = { mtimeMs, size, record };
  return record;
}

function saveRevokedRecord(record: CloudRevokedRecord): void {
  atomicWriteFileSync(CLOUD_REVOKED_PATH, JSON.stringify(record, null, 2) + "\n");
  cache = null; // force a fresh read next time
}

/**
 * Fail-closed gate evaluated at the start of EVERY tool call (wired in
 * server.ts right after the honeytoken checkpoint): an agent revoked from
 * the cloud gets EVERY request denied until a human reviews the incident
 * and removes cloud-revoked.json.
 */
export function cloudRevocationCheckpoint(agentId: string): {
  revoked: boolean;
  message?: string;
} {
  const rec = loadRevokedRecord();
  if (!rec || (rec.agentId !== agentId && rec.agentId !== "*")) {
    return { revoked: false };
  }
  return {
    revoked: true,
    message:
      `Agent '${agentId}' was REVOKED from ScopeGate Cloud (${rec.reason}) at ${rec.revokedAt}. ` +
      `Every request is denied (fail-closed) until a human reviews the incident ` +
      `(see audit.jsonl: agent_revoked) and removes ${CLOUD_REVOKED_PATH}.`,
  };
}

/* ------------------------------------------------------------------------ */
/* Sync                                                                      */
/* ------------------------------------------------------------------------ */

function safeAudit(agentId: string, detail: Record<string, unknown>): void {
  try {
    // The event's agentId must match the batch agentId at cloud ingest
    // (per-event mismatch is rejected there) — use the revoked agent's id,
    // falling back to the same env convention as the policy engine.
    audit(process.env.SCOPEGATE_AGENT_ID ?? agentId, "agent_revoked", detail);
  } catch (e) {
    console.error(`[scopegate cloud] warn: audit(agent_revoked) failed: ${(e as Error).message}`);
  }
}

/**
 * Apply a revocation for this agent: purge grants, persist the revoked
 * record (the request-path gate reads it), audit. Idempotent — when a
 * revoked record already exists this is a no-op (returns false).
 */
export function applyCloudRevocation(
  policy: PolicyEngine,
  agentId: string,
  revocation: CloudRevocation,
): boolean {
  if (loadRevokedRecord()) return false; // already revoked; human must clear
  const removed = policy.revokeAgent(agentId);
  const record: CloudRevokedRecord = {
    agentId,
    reason: revocation.reason ?? "fleet revocation from ScopeGate Cloud",
    revokedAt: revocation.ts ?? revocation.revokedAt ?? new Date().toISOString(),
    appliedAt: new Date().toISOString(),
    source: "cloud",
  };
  saveRevokedRecord(record);
  safeAudit(agentId, {
    revokedAgentId: agentId,
    via: "cloud",
    reason: record.reason,
    revokedAt: record.revokedAt,
    revokedGrants: removed,
    suspended: true,
  });
  console.error(
    `[scopegate cloud] info: agent '${agentId}' REVOKED by the cloud (${record.reason}) — ` +
      `${removed} grant(s) purged, every request denied until human review`,
  );
  return true;
}

export interface RevocationSyncDeps {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Injectable clock for tests. */
  now?: () => number;
}

/**
 * One revocation poll tick. `lastSeen` is an in-memory cursor (revokedAt of
 * the newest revocation already processed); correctness never depends on it
 * (application is idempotent), it only trims the payload. Throws on
 * transport/HTTP errors — the loop backs off.
 */
export async function syncRevocationsOnce(
  cfg: { url: string; teamId: string; agentSecret: string },
  policy: PolicyEngine,
  agentId: string,
  lastSeen: string | null,
  deps: RevocationSyncDeps = {},
): Promise<{ applied: boolean; lastSeen: string | null }> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const qs = new URLSearchParams({ teamId: cfg.teamId });
  if (lastSeen) qs.set("since", lastSeen);
  const res = await fetchImpl(`${cfg.url}/v1/revocations?${qs}`, {
    headers: { authorization: `Bearer ${cfg.agentSecret}` },
    signal: AbortSignal.timeout(deps.timeoutMs ?? 10_000),
  });
  if (!res.ok) {
    throw new Error(`revocation sync failed (HTTP ${res.status})`);
  }
  const body = (await res.json()) as { revocations?: CloudRevocation[] };
  const revocations = Array.isArray(body.revocations) ? body.revocations : [];
  let applied = false;
  let newest = lastSeen;
  for (const r of revocations) {
    if (typeof r?.agentId !== "string") continue;
    const ts = r.ts ?? r.revokedAt;
    if (ts && (!newest || ts > newest)) newest = ts;
    if (r.agentId !== agentId && r.agentId !== "*") continue;
    if (applyCloudRevocation(policy, agentId, r)) applied = true;
  }
  return { applied, lastSeen: newest };
}
