/**
 * Rotation of audit.jsonl — and the single place that knows the layout.
 *
 * Why this file exists: the audit log grew without bound. On a container
 * filesystem that ends one way — the disk fills, the gateway can no longer
 * append, and because the audit path is fail-closed it aborts startup. The
 * safety property (nothing happens without a record) turns into an outage.
 *
 * Why rotation is not a one-liner here: the log is a HASH CHAIN. Every event
 * carries `prev` (the previous event's hash) and a monotonic `seq`. Rotating
 * the live file to `audit.jsonl.1` and starting an empty one would restart the
 * chain at genesis and make the whole thing unverifiable. So:
 *
 *   - Segments are read as ONE logical log, oldest first:
 *     `audit.jsonl.N` … `audit.jsonl.1`, `audit.jsonl`.
 *   - The chain continues across the boundary: the first event of a fresh
 *     segment carries the `prev`/`seq` of the last event of the previous one.
 *   - Everything that reads the log (verifier, tail, cloud exporter) goes
 *     through here, so no reader can silently see only part of the chain.
 *
 * Retention drops the OLDEST segments. That does break the link back to
 * genesis, and the verifier says so out loud instead of pretending: a pruned
 * chain is verified from its first retained event, and the result reports
 * where it starts. Silent partial verification would be worse than none.
 */
import fs from "node:fs";
import { AUDIT_LOG_PATH } from "../config/config.js";

/** Rotate once the live segment reaches this size. */
export function maxSegmentBytes(env = process.env): number {
  const mb = Number(env.SCOPEGATE_AUDIT_MAX_MB);
  return (Number.isFinite(mb) && mb > 0 ? mb : 100) * 1024 * 1024;
}

/**
 * Rotated segments to keep (the live one is extra). Default 5 → roughly
 * 600 MB at the default size. `0` keeps every segment: unbounded on disk, but
 * the chain stays verifiable to genesis. That is a real trade-off, so it is a
 * setting and not a hardcoded choice.
 */
export function keepSegments(env = process.env): number {
  const n = Number(env.SCOPEGATE_AUDIT_KEEP);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 5;
}

const segmentPath = (n: number): string => `${AUDIT_LOG_PATH}.${n}`;

/** Existing rotated segment numbers, newest (1) first. */
function rotatedNumbers(): number[] {
  const out: number[] = [];
  for (let n = 1; ; n++) {
    if (!fs.existsSync(segmentPath(n))) break;
    out.push(n);
  }
  return out;
}

/** Every segment path in chronological order; the live log is last. */
export function auditSegmentPaths(): string[] {
  const rotated = rotatedNumbers()
    .sort((a, b) => b - a) // .3, .2, .1 — oldest first
    .map(segmentPath);
  return fs.existsSync(AUDIT_LOG_PATH) ? [...rotated, AUDIT_LOG_PATH] : rotated;
}

/** Non-empty lines of the whole logical log, oldest first. */
export function readAuditLines(): string[] {
  const out: string[] = [];
  for (const p of auditSegmentPaths()) {
    let raw: string;
    try {
      raw = fs.readFileSync(p, "utf8");
    } catch {
      continue;
    }
    for (const l of raw.split("\n")) {
      if (l.trim().length > 0) out.push(l);
    }
  }
  return out;
}

/** Bytes on disk across all segments — what `/health` reports. */
export function auditSizeBytes(): number {
  let total = 0;
  for (const p of auditSegmentPaths()) {
    try {
      total += fs.statSync(p).size;
    } catch {
      // A segment pruned between listing and stat is not an error.
    }
  }
  return total;
}

/** True when the chain no longer reaches genesis (oldest segments pruned). */
export function isPruned(): boolean {
  return pruneMarkerExists();
}

const PRUNE_MARKER = `${AUDIT_LOG_PATH}.pruned`;

function pruneMarkerExists(): boolean {
  return fs.existsSync(PRUNE_MARKER);
}

/**
 * Rotate the live segment if appending `nextBytes` would cross the limit.
 *
 * Called before every append. The check is a `statSync` on one file, which is
 * cheap next to the signing and hashing the append already does.
 */
export function rotateIfNeeded(nextBytes: number, env = process.env): void {
  let size: number;
  try {
    size = fs.statSync(AUDIT_LOG_PATH).size;
  } catch {
    return; // no live log yet: nothing to rotate
  }
  const max = maxSegmentBytes(env);
  if (size === 0 || size + nextBytes <= max) return;

  // Shift from the far end so nothing is overwritten: .2 → .3, .1 → .2, live → .1
  const keep = keepSegments(env);
  const existing = rotatedNumbers().sort((a, b) => b - a);
  for (const n of existing) {
    const from = segmentPath(n);
    const to = segmentPath(n + 1);
    if (keep > 0 && n + 1 > keep) {
      // Beyond retention: this is where the link to genesis is lost. Leave a
      // marker so the verifier can say "verified from seq N" instead of
      // reporting a broken chain, which would read like tampering.
      try {
        fs.rmSync(from, { force: true });
        fs.writeFileSync(PRUNE_MARKER, new Date().toISOString() + "\n", {
          mode: 0o600,
        });
      } catch {
        // Failing to prune is not worth aborting an audit write over.
      }
      continue;
    }
    try {
      fs.renameSync(from, to);
    } catch {
      // Same: a rotation hiccup must never block the append below.
    }
  }
  try {
    fs.renameSync(AUDIT_LOG_PATH, segmentPath(1));
  } catch {
    // If the rename fails the log keeps growing — bad, but still recorded.
  }
}
