/**
 * Result handles (mejora #7): the gateway as a shock absorber for payloads.
 *
 * An upstream tool answering 80 KB of JSON burns the agent's most scarce
 * resource — the context window. When a proxied result exceeds
 * `limits.max_inline_bytes` (default 16 KiB), the gateway persists the FULL
 * payload (after policy redaction, never before) and returns a small
 * preview + a `result_ref` + stats. The agent then pages through it with
 * scopegate_result_get / scopegate_result_grep instead of swallowing it whole.
 *
 * FILE CONTRACT: `~/.scopegate/results/<ref>.json` (mode 0600), ref =
 * "r-<sha256[:16]>" of (tool + ts + payload). Refs expire after 2 h
 * (session lifetime) and are pruned lazily.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";

export const RESULTS_DIR = path.join(SCOPEGATE_DIR, "results");
export const RESULT_REF_TTL_MS = 2 * 3600 * 1000;
export const DEFAULT_MAX_INLINE_BYTES = 16 * 1024;
const PREVIEW_CHARS = 2048;

export interface StoredResult {
  ref: string;
  agentId: string;
  upstream: string;
  tool: string;
  ts: number;
  bytes: number;
  payload: unknown;
}

function refFile(ref: string): string {
  // Refs are gateway-generated ([A-Za-z0-9-]) — safe as a filename component.
  return path.join(RESULTS_DIR, `${ref}.json`);
}

/** Persist a payload and mint its ref. */
export function storeResult(input: {
  agentId: string;
  upstream: string;
  tool: string;
  payload: unknown;
}): StoredResult {
  const bytes = Buffer.byteLength(JSON.stringify(input.payload) ?? "null", "utf8");
  const ref =
    "r-" +
    crypto
      .createHash("sha256")
      .update(input.tool + ":" + Date.now() + ":" + bytes)
      .digest("hex")
      .slice(0, 16);
  const stored: StoredResult = {
    ref,
    agentId: input.agentId,
    upstream: input.upstream,
    tool: input.tool,
    ts: Date.now(),
    bytes,
    payload: input.payload,
  };
  fs.mkdirSync(RESULTS_DIR, { recursive: true, mode: 0o700 });
  ensureDir();
  const tmp = refFile(ref) + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(stored, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, refFile(ref));
  return stored;
}

/** Load a stored result, or undefined when absent/expired/foreign. */
export function loadResult(ref: string, agentId: string): StoredResult | undefined {
  if (!/^r-[a-z0-9]{16}$/.test(ref)) return undefined;
  pruneExpired();
  try {
    const raw = JSON.parse(fs.readFileSync(refFile(ref), "utf8")) as StoredResult;
    if (raw.agentId !== agentId) return undefined; // refs are per-agent, never shared
    if (Date.now() - raw.ts > RESULT_REF_TTL_MS) return undefined;
    return raw;
  } catch {
    return undefined;
  }
}

/** Drop expired ref files (lazy, best-effort). */
function pruneExpired(): void {
  let names: string[];
  try {
    names = fs.readdirSync(RESULTS_DIR);
  } catch {
    return;
  }
  const cutoff = Date.now() - RESULT_REF_TTL_MS;
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    try {
      const stat = fs.statSync(path.join(RESULTS_DIR, name));
      if (stat.mtimeMs < cutoff) fs.rmSync(path.join(RESULTS_DIR, name), { force: true });
    } catch {
      /* best effort */
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Preview + stats (what the agent gets instead of the full payload)         */
/* ------------------------------------------------------------------------ */

export interface ResultPreview {
  truncated: true;
  result_ref: string;
  preview: string;
  stats: { bytes: number; shape: string; top_keys?: string[]; items?: number };
  hint: string;
}

function shapeOf(payload: unknown): { shape: string; top_keys?: string[]; items?: number } {
  if (Array.isArray(payload)) return { shape: "array", items: payload.length };
  if (payload !== null && typeof payload === "object") {
    return { shape: "object", top_keys: Object.keys(payload as Record<string, unknown>).slice(0, 10) };
  }
  return { shape: typeof payload };
}

/** Build the truncated response for an oversized stored result. */
export function buildPreview(stored: StoredResult): ResultPreview {
  const serialized = JSON.stringify(stored.payload, null, 2) ?? "null";
  return {
    truncated: true,
    result_ref: stored.ref,
    preview: serialized.slice(0, PREVIEW_CHARS),
    stats: { bytes: stored.bytes, ...shapeOf(stored.payload) },
    hint: `Full payload stored (${stored.bytes} bytes). Page it with scopegate_result_get {ref: "${stored.ref}", path: "..."} or search it with scopegate_result_grep {ref: "${stored.ref}", pattern: "..."} — do NOT re-call the tool for the rest.`,
  };
}

/** Bytes a serialized payload occupies (the truncation threshold input). */
export function payloadBytes(payload: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(payload) ?? "null", "utf8");
  } catch {
    return 0;
  }
}

/**
 * Unwrap the MCP result envelope for handle purposes: a single-part text
 * result whose text parses as JSON is stored as the PARSED value (natural
 * dot-paths like "items.0.title" just work); everything else passes through.
 */
export function unwrapMcpResult(payload: unknown): unknown {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return payload;
  const content = (payload as { content?: unknown }).content;
  if (!Array.isArray(content) || content.length !== 1) return payload;
  const part = content[0];
  if (part === null || typeof part !== "object") return payload;
  const text = (part as { type?: unknown; text?: unknown }).text;
  if ((part as { type?: unknown }).type !== "text" || typeof text !== "string") return payload;
  try {
    return JSON.parse(text);
  } catch {
    return text; // plain text result — store the string itself
  }
}

/* ------------------------------------------------------------------------ */
/* Accessors: get by dot-path, grep by substring/regex                       */
/* ------------------------------------------------------------------------ */

/**
 * Dot-path accessor: "content.0.text" or "items.3.title". Segments are object
 * keys or array indices. Returns {found: false} (not an error) for bad paths —
 * the agent adjusts the path, no need to re-fetch the payload.
 */
export function getByPath(payload: unknown, dotPath: string): { found: boolean; value?: unknown } {
  if (!dotPath || typeof dotPath !== "string") return { found: false };
  let current: unknown = payload;
  for (const seg of dotPath.split(".")) {
    if (current === null || current === undefined) return { found: false };
    if (Array.isArray(current)) {
      const idx = Number(seg);
      if (!Number.isInteger(idx) || idx < 0 || idx >= current.length) return { found: false };
      current = current[idx];
    } else if (typeof current === "object") {
      const rec = current as Record<string, unknown>;
      if (!(seg in rec)) return { found: false };
      current = rec[seg];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: current };
}

export interface GrepHit {
  path: string;
  line: string;
}

/**
 * Substring or /regex/ search over the serialized payload. Returns matching
 * LINES with their dot-path parent, capped at 50 — context-sized by design.
 */
export function grepPayload(payload: unknown, pattern: string, maxHits = 50): GrepHit[] {
  const serialized = JSON.stringify(payload, null, 2) ?? "";
  let regex: RegExp;
  const asRegex = /^\/(.+)\/([a-z]*)$/.exec(pattern);
  try {
    regex = asRegex
      ? new RegExp(asRegex[1], asRegex[2] || "i")
      : new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  } catch {
    regex = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  }
  const hits: GrepHit[] = [];
  const lines = serialized.split("\n");
  const pathStack: string[] = [];
  for (const line of lines) {
    // Track a best-effort path from key lines ("key": value / "key": {).
    const keyMatch = /^\s*"([^"]+)":\s*[{\[]?/.exec(line);
    if (keyMatch) pathStack.push(keyMatch[1]);
    if (regex.test(line)) {
      hits.push({ path: pathStack[pathStack.length - 1] ?? "", line: line.trim().slice(0, 200) });
      if (hits.length >= maxHits) break;
    }
  }
  return hits;
}
