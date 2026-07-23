/**
 * Queryable audit index (EPIC-07 H7.4) — PURE TYPESCRIPT fallback, documented
 * ADR deviation: the EPIC asks for a better-sqlite3 derived index, but
 * better-sqlite3 cannot build on this Windows toolchain (node-gyp without a
 * C++ toolchain), and the sprint plan adopts the documented fallback: an
 * in-memory derived index rebuilt from the canonical JSONL, plus an optional
 * JSON snapshot (audit-index.json) to skip re-parsing on repeat queries.
 *
 * Invariants:
 *   - audit.jsonl is the ONLY source of truth; the index is disposable and
 *     rebuildable at any time (`scopegate audit reindex`).
 *   - reindex VERIFIES the chain + signatures before indexing: a broken log
 *     is never silently indexed.
 *   - The snapshot is used only when provably fresh (its lastSeq matches the
 *     current log tail); anything else triggers an in-memory rebuild.
 *   - Query hot path: seq/ts are already ordered (append-only), filters run
 *     in a single linear pass over the materialized events. If this ever
 *     becomes the bottleneck, the SQLite index can land as a drop-in
 *     replacement behind buildIndex/queryIndex.
 */
import fs from "node:fs";
import path from "node:path";
import { SCOPEGATE_DIR } from "../config/config.js";
import { auditTailSeq, type AuditEvent } from "./log.js";
import { readAuditEvents, verifyAuditLog } from "./verify.js";

export const AUDIT_INDEX_PATH = path.join(SCOPEGATE_DIR, "audit-index.json");

export interface AuditIndex {
  v: 1;
  builtAt: string;
  /** seq of the newest event the index covers (0 = empty log). */
  lastSeq: number;
  events: AuditEvent[];
}

export function buildIndex(events: AuditEvent[]): AuditIndex {
  return {
    v: 1,
    builtAt: new Date().toISOString(),
    lastSeq: events.length > 0 ? events[events.length - 1].seq : 0,
    events,
  };
}

/**
 * Index for querying: the snapshot when it exists and is fresh (lastSeq
 * matches the current log tail), otherwise an in-memory rebuild from the
 * canonical JSONL (no disk write — snapshots are written only by reindex).
 */
export function loadOrBuildIndex(): AuditIndex {
  const tailSeq = auditTailSeq();
  if (fs.existsSync(AUDIT_INDEX_PATH)) {
    try {
      const snap = JSON.parse(
        fs.readFileSync(AUDIT_INDEX_PATH, "utf8"),
      ) as AuditIndex;
      if (snap?.v === 1 && Array.isArray(snap.events) && snap.lastSeq === tailSeq) {
        return snap;
      }
    } catch {
      // Corrupt snapshot: fall through to a rebuild from the source of truth.
    }
  }
  return buildIndex(readAuditEvents());
}

/**
 * Full rebuild of the snapshot from the canonical JSONL. Refuses to index a
 * log that fails verification — the index must never launder a broken trail.
 */
export function reindex(): AuditIndex {
  const r = verifyAuditLog();
  if (!r.ok) {
    throw new Error(
      `refusing to index a broken audit log: first invalid event seq=${r.seq ?? "unknown"} ` +
        `(line ${r.line}): ${r.reason}`,
    );
  }
  const idx = buildIndex(r.events);
  const tmp = AUDIT_INDEX_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(idx), { mode: 0o600 });
  fs.renameSync(tmp, AUDIT_INDEX_PATH);
  return idx;
}

export interface AuditQuery {
  agent?: string;
  kind?: string;
  /** ISO 8601, inclusive lower bound on ts. */
  since?: string;
  /** ISO 8601, inclusive upper bound on ts. */
  until?: string;
  limit?: number;
}

/**
 * Answer "what did this agent/token touch in this window". ts values are
 * ISO 8601 UTC (new Date().toISOString()), so lexicographic comparison is
 * chronological; since/until are validated and normalized to the same shape.
 */
export function queryIndex(idx: AuditIndex, q: AuditQuery): AuditEvent[] {
  const since = q.since !== undefined ? normalizeIso(q.since, "--since") : undefined;
  const until = q.until !== undefined ? normalizeIso(q.until, "--until") : undefined;
  const out: AuditEvent[] = [];
  for (const e of idx.events) {
    if (q.agent !== undefined && e.agentId !== q.agent) continue;
    if (q.kind !== undefined && e.kind !== q.kind) continue;
    if (since !== undefined && e.ts < since) continue;
    if (until !== undefined && e.ts > until) continue;
    out.push(e);
    if (q.limit !== undefined && out.length >= q.limit) break;
  }
  return out;
}

function normalizeIso(s: string, flag: string): string {
  const t = Date.parse(s);
  if (Number.isNaN(t)) {
    throw new Error(
      `Invalid ${flag} timestamp '${s}' — use ISO 8601 (e.g. 2026-07-22T14:00:00Z).`,
    );
  }
  return new Date(t).toISOString();
}
