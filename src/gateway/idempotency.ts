/**
 * Proxy-level idempotency for writes (mejora #6).
 *
 * Agents retry on timeouts and lost responses — with writes that means
 * duplicate issues, double deploys, double comments. The gateway sees every
 * call, so it is the exact right place to dedupe.
 *
 * Contract (agent-driven, opt-in):
 *   - Any proxied call may carry `_sg_idempotency_key: "<string>"` in args
 *     (stripped before the upstream call — it never leaks upstream).
 *   - First call with a key: executes; the result is cached for 24 h with a
 *     hash of the (stripped) args.
 *   - Same key + same args hash: the CACHED result is replayed, the upstream
 *     is never called (audit: idempotency_replayed).
 *   - Same key + different args hash: an explicit conflict error — the agent
 *     must pick a new key for a new intention (keys name INTENTIONS, not
 *     attempts).
 *
 * FILE CONTRACT: `~/.scopegate/idempotency.json`, mode 0600, atomic writes.
 * Entries expire after 24 h (lazily pruned on read/write).
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { atomicWriteFileSync } from "../policy/fsutil.js";

export const IDEMPOTENCY_PATH = path.join(SCOPEGATE_DIR, "idempotency.json");
export const IDEMPOTENCY_TTL_MS = 24 * 3600 * 1000;
export const MAX_IDEMPOTENCY_ENTRIES = 1000;
export const IDEMPOTENCY_ARG = "_sg_idempotency_key";

interface IdempotencyEntry {
  upstream: string;
  tool: string;
  argsHash: string;
  result: unknown;
  ts: number;
}

type IdempotencyFile = Record<string, IdempotencyEntry>;

let cache: { mtimeMs: number | null; size: number; data: IdempotencyFile } | null = null;

function readStore(): IdempotencyFile {
  let stat: fs.Stats | null = null;
  try {
    stat = fs.statSync(IDEMPOTENCY_PATH);
  } catch {
    cache = { mtimeMs: null, size: 0, data: {} };
    return cache.data;
  }
  if (cache && cache.mtimeMs === stat.mtimeMs && cache.size === stat.size) {
    return cache.data;
  }
  let data: IdempotencyFile = {};
  try {
    const raw = JSON.parse(fs.readFileSync(IDEMPOTENCY_PATH, "utf8"));
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      data = raw as IdempotencyFile;
    }
  } catch {
    console.error(
      `[scopegate] warn: idempotency store unreadable — treating as empty (fail-open for calls, fail-closed for replays)`,
    );
  }
  const now = Date.now();
  let pruned = 0;
  for (const [k, e] of Object.entries(data)) {
    if (typeof e?.ts !== "number" || now - e.ts > IDEMPOTENCY_TTL_MS) {
      delete data[k];
      pruned++;
    }
  }
  if (pruned > 0) writeStore(data);
  cache = { mtimeMs: stat.mtimeMs, size: stat.size, data };
  return data;
}

function writeStore(data: IdempotencyFile): void {
  ensureDir();
  atomicWriteFileSync(IDEMPOTENCY_PATH, JSON.stringify(data, null, 2) + "\n");
  cache = null;
}

/** sha256 over the canonical JSON of the args (the key's identity check). */
export function hashCallArgs(args: Record<string, unknown>): string {
  return crypto.createHash("sha256").update(JSON.stringify(args)).digest("hex");
}

export type IdempotencyLookup =
  | { outcome: "replay"; result: unknown }
  | { outcome: "conflict" }
  | { outcome: "miss" };

/** Look up a key: replay (same hash), conflict (different hash), or miss. */
export function lookupIdempotent(key: string, argsHash: string): IdempotencyLookup {
  const store = readStore();
  const entry = store[key];
  if (!entry) return { outcome: "miss" };
  return entry.argsHash === argsHash
    ? { outcome: "replay", result: entry.result }
    : { outcome: "conflict" };
}

/** Store a successful result under the key (24 h TTL, bounded size). */
export function storeIdempotent(
  key: string,
  upstream: string,
  tool: string,
  argsHash: string,
  result: unknown,
): void {
  const store = readStore();
  if (!(key in store) && Object.keys(store).length >= MAX_IDEMPOTENCY_ENTRIES) {
    // Bounded file: drop the oldest entry when full.
    const oldest = Object.entries(store).sort((a, b) => a[1].ts - b[1].ts)[0]?.[0];
    if (oldest) delete store[oldest];
  }
  store[key] = { upstream, tool, argsHash, result, ts: Date.now() };
  writeStore(store);
}

/** Test helper: wipe the memoized view (fresh HOME per test). */
export function _resetIdempotencyCacheForTests(): void {
  cache = null;
}
