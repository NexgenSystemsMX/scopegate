/**
 * Honeytokens (EPIC-11): credential canaries with surgical revocation.
 *
 * A canary is a high-entropy decoy value deposited in the vault under a
 * `canary:<name>` secretRef and registered in a local state file
 * (`~/.scopegate/honeytoken-state.json`, NEVER in the config). Canaries are
 * never functional credentials: they exist so that ANY use of them is, by
 * construction, a high-precision exfiltration signal (~0 false positives —
 * a legitimate agent never generates nor references a canary ref).
 *
 * Detection vectors (all funneled into respondCanaryTrigger):
 *   1. register_upstream — the agent passes a canary ref as `secretRef`
 *      (or as an env mapping value), i.e. tries to turn the decoy into a
 *      live credential. Wired in gateway/server.ts.
 *   2. request_capability — the capability string mentions a canary ref.
 *      Wired in gateway/server.ts.
 *   3. External use — the canary VALUE shows up outside the gateway. The
 *      test fixture fake-upstream.mjs exposes `/canary-hit`, which appends
 *      presented values to `~/.scopegate/canary-hits.jsonl`; the gateway
 *      sweeps that file on every request (honeytokenCheckpoint) and matches
 *      values against the registered canary hashes.
 *
 * Response (mode-dependent):
 *   - audit `honeytoken_triggered` (always, both modes);
 *   - enforce (default): PolicyEngine.revokeAgent(agentId) — every live
 *     grant of the agent dies — the agent is marked `suspended` in the state
 *     file, and audit `agent_revoked` records the containment. From that
 *     point on the gateway denies EVERY request from that agent
 *     (fail-closed, see honeytokenCheckpoint wired in server.ts).
 *   - alert (SCOPEGATE_HONEYTOKEN_MODE=alert): detection is audited but the
 *     agent keeps operating — for canary roll-out periods where the
 *     no-false-positive property is being validated before enforcement.
 *
 * Blast radius (§6.5): revocation touches ONLY the triggering agent. Other
 * agents, upstreams and the vault are unaffected.
 *
 * HUMAN RE-ENABLE PROCESS (no CLI by design — incident review is human):
 *   1. Investigate audit.jsonl: `honeytoken_triggered` + `agent_revoked`
 *      carry canary name, ref, vector and revocation counts.
 *   2. Rotate the real credential the canary was standing next to, if any.
 *   3. Remove the agent's entry under `suspended` in
 *      `~/.scopegate/honeytoken-state.json` (or delete the file to reset all
 *      honeytoken state). The gateway picks the change up on the next
 *      request (state is re-read when the file changes) — no restart needed.
 *
 * Canary values are stored in the vault (same as any secret); the state file
 * records only their SHA-256, so the state file itself is not sensitive.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { atomicWriteFileSync } from "../policy/fsutil.js";
import { audit } from "../audit/log.js";
import type { PolicyEngine } from "../policy/engine.js";

export const HONEYTOKEN_STATE_PATH = path.join(
  SCOPEGATE_DIR,
  "honeytoken-state.json",
);
/** Appended by fake-upstream.mjs `/canary-hit`; swept by the gateway. */
export const CANARY_HITS_PATH = path.join(SCOPEGATE_DIR, "canary-hits.jsonl");

export const CANARY_REF_PREFIX = "canary:";

export type CanaryVector =
  | "register_upstream"
  | "request_capability"
  | "external_hit";

export type HoneytokenMode = "alert" | "enforce";

export interface RegisteredCanary {
  /** Short name; the vault ref is `canary:<name>`. */
  name: string;
  ref: string;
  /** SHA-256 hex of the canary value (the value itself lives in the vault). */
  valueSha256: string;
  /** Agent the canary was planted for — the blast-radius target on trigger. */
  agentId?: string;
  /** Upstream the canary was planted next to (informational). */
  upstream?: string;
  plantedAt: string; // ISO
}

export interface Suspension {
  suspendedAt: string; // ISO
  canary: string;
  ref: string;
  vector: CanaryVector;
  reason: string;
}

interface HoneytokenState {
  version: 1;
  canaries: RegisteredCanary[];
  /** agentId → suspension record. Presence == agent is suspended. */
  suspended: Record<string, Suspension>;
  /** Byte offset already processed in CANARY_HITS_PATH. */
  externalHitsOffset: number;
}

function emptyState(): HoneytokenState {
  return { version: 1, canaries: [], suspended: {}, externalHitsOffset: 0 };
}

/* ------------------------------------------------------------------------ */
/* Mode                                                                       */
/* ------------------------------------------------------------------------ */

/**
 * SCOPEGATE_HONEYTOKEN_MODE=alert|enforce. Default: ENFORCE (a canary has
 * ~0 false positives by design, so automated containment is safe); `alert`
 * audits detections without revoking — used while validating a deployment.
 */
export function honeytokenMode(): HoneytokenMode {
  const raw = (process.env.SCOPEGATE_HONEYTOKEN_MODE ?? "enforce").toLowerCase();
  return raw === "alert" ? "alert" : "enforce";
}

/* ------------------------------------------------------------------------ */
/* State file (mtime-cached reads, atomic writes)                             */
/* ------------------------------------------------------------------------ */

let cache: { mtimeMs: number | null; size: number; state: HoneytokenState } | null =
  null;
let warnedCorrupt = false;

function readStateFromDisk(): HoneytokenState {
  let raw: string;
  try {
    raw = fs.readFileSync(HONEYTOKEN_STATE_PATH, "utf8");
  } catch {
    return emptyState();
  }
  try {
    const parsed = JSON.parse(raw) as Partial<HoneytokenState>;
    return {
      version: 1,
      canaries: Array.isArray(parsed.canaries) ? parsed.canaries : [],
      suspended:
        parsed.suspended && typeof parsed.suspended === "object"
          ? parsed.suspended
          : {},
      externalHitsOffset:
        typeof parsed.externalHitsOffset === "number"
          ? parsed.externalHitsOffset
          : 0,
    };
  } catch {
    // The state file is a security control, but it only exists once the
    // honeytoken feature is used: a corrupt file must not DoS the whole
    // gateway. Treat as empty and warn the operator on stderr.
    if (!warnedCorrupt) {
      warnedCorrupt = true;
      console.error(
        `[scopegate] warn: ${HONEYTOKEN_STATE_PATH} is unreadable — treating honeytoken state as empty`,
      );
    }
    return emptyState();
  }
}

/** mtime/size-cached read: one stat syscall per call in the hot path. */
export function loadState(): HoneytokenState {
  let st: fs.Stats | null = null;
  try {
    st = fs.statSync(HONEYTOKEN_STATE_PATH);
  } catch {
    st = null;
  }
  const mtimeMs = st ? st.mtimeMs : null;
  const size = st ? st.size : 0;
  if (cache && cache.mtimeMs === mtimeMs && cache.size === size) {
    return cache.state;
  }
  const state = readStateFromDisk();
  cache = { mtimeMs, size, state };
  return state;
}

function saveState(state: HoneytokenState): void {
  ensureDir();
  atomicWriteFileSync(HONEYTOKEN_STATE_PATH, JSON.stringify(state, null, 2));
  cache = null; // force a fresh read next time
}

/* ------------------------------------------------------------------------ */
/* Generation                                                                 */
/* ------------------------------------------------------------------------ */

function sha256(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/**
 * Plant a canary: generate a high-entropy decoy value, deposit it in the
 * vault under `canary:<name>` (a human-equivalent operation — the value
 * never transits an agent context) and register its hash in the state file.
 * Re-planting the same name ROTATES the value.
 */
export function plantCanary(
  vault: { set(ref: string, value: string): void },
  opts: { name: string; agentId?: string; upstream?: string },
): { name: string; ref: string; value: string } {
  if (!/^[a-z0-9][a-z0-9_.-]*$/i.test(opts.name)) {
    throw new Error(
      `Invalid canary name '${opts.name}' — use letters, digits, '_', '-', '.'.`,
    );
  }
  const ref = CANARY_REF_PREFIX + opts.name;
  const value = "sg_canary_" + crypto.randomBytes(24).toString("base64url");
  vault.set(ref, value);
  const state = loadState();
  const entry: RegisteredCanary = {
    name: opts.name,
    ref,
    valueSha256: sha256(value),
    ...(opts.agentId ? { agentId: opts.agentId } : {}),
    ...(opts.upstream ? { upstream: opts.upstream } : {}),
    plantedAt: new Date().toISOString(),
  };
  state.canaries = [...state.canaries.filter((c) => c.ref !== ref), entry];
  saveState(state);
  return { name: opts.name, ref, value };
}

/* ------------------------------------------------------------------------ */
/* Detection                                                                  */
/* ------------------------------------------------------------------------ */

/** The registered canary for an exact ref (`canary:<name>`), else null. */
export function findCanaryRef(ref: string): RegisteredCanary | null {
  if (typeof ref !== "string" || !ref.startsWith(CANARY_REF_PREFIX)) return null;
  return loadState().canaries.find((c) => c.ref === ref) ?? null;
}

/**
 * First registered canary ref mentioned inside an arbitrary text (e.g. a
 * capability string). Longest refs first so the most specific match wins.
 */
export function findCanaryRefsInText(text: string): RegisteredCanary | null {
  if (typeof text !== "string" || !text.includes(CANARY_REF_PREFIX)) return null;
  const canaries = [...loadState().canaries].sort(
    (a, b) => b.ref.length - a.ref.length,
  );
  return canaries.find((c) => text.includes(c.ref)) ?? null;
}

/** The registered canary whose VALUE matches `value`, else null. */
export function findCanaryByValue(value: string): RegisteredCanary | null {
  if (typeof value !== "string" || value.length === 0) return null;
  const hash = sha256(value);
  return loadState().canaries.find((c) => c.valueSha256 === hash) ?? null;
}

/** Suspension record for an agent, or null when the agent is clear. */
export function getSuspension(agentId: string): Suspension | null {
  return loadState().suspended[agentId] ?? null;
}

/* ------------------------------------------------------------------------ */
/* Response                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Trigger events are security telemetry: audit them best-effort (mirroring
 * engine.ts bestEffortAudit) so a broken audit trail never blocks the
 * containment itself — the suspension gate stays fail-closed regardless.
 */
function safeAudit(
  agentId: string,
  kind: "honeytoken_triggered" | "agent_revoked",
  detail: Record<string, unknown>,
): void {
  try {
    audit(agentId, kind, detail);
  } catch (e) {
    console.error(
      `[scopegate] warn: audit(${kind}) failed: ${(e as Error).message}`,
    );
  }
}

/**
 * The single funnel for every detection vector. Audits `honeytoken_triggered`
 * always; in enforce mode additionally revokes the agent's grants, suspends
 * the agent and audits `agent_revoked`. Returns what happened.
 */
export function respondCanaryTrigger(opts: {
  policy: PolicyEngine;
  agentId: string;
  canary: RegisteredCanary;
  vector: CanaryVector;
  evidence?: Record<string, unknown>;
}): { mode: HoneytokenMode; revokedGrants: number } {
  const mode = honeytokenMode();
  safeAudit(opts.agentId, "honeytoken_triggered", {
    canary: opts.canary.name,
    ref: opts.canary.ref,
    vector: opts.vector,
    mode,
    ...(opts.evidence ?? {}),
  });
  let revokedGrants = 0;
  if (mode === "enforce") {
    revokedGrants = opts.policy.revokeAgent(opts.agentId);
    const reason = `honeytoken '${opts.canary.name}' (${opts.canary.ref}) used via ${opts.vector}`;
    const state = loadState();
    state.suspended[opts.agentId] = {
      suspendedAt: new Date().toISOString(),
      canary: opts.canary.name,
      ref: opts.canary.ref,
      vector: opts.vector,
      reason,
    };
    saveState(state);
    safeAudit(opts.agentId, "agent_revoked", {
      canary: opts.canary.name,
      ref: opts.canary.ref,
      vector: opts.vector,
      revokedGrants,
      suspended: true,
    });
  }
  return { mode, revokedGrants };
}

/* ------------------------------------------------------------------------ */
/* External-use sweep + per-request checkpoint                              */
/* ------------------------------------------------------------------------ */

let lastHitsStat: { mtimeMs: number; size: number } | null = null;

interface CanaryHit {
  ts?: string;
  value?: string;
  source?: string;
}

/**
 * Sweep CANARY_HITS_PATH for new external uses of canary values (appended by
 * fake-upstream `/canary-hit`). Idempotent: a byte offset in the state file
 * tracks what was already processed. New hits matching a registered canary
 * go through respondCanaryTrigger with vector `external_hit`.
 */
export function processExternalHits(policy: PolicyEngine): void {
  let st: fs.Stats;
  try {
    st = fs.statSync(CANARY_HITS_PATH);
  } catch {
    return; // no hits file: nothing to sweep
  }
  if (
    lastHitsStat &&
    lastHitsStat.mtimeMs === st.mtimeMs &&
    lastHitsStat.size === st.size
  ) {
    return;
  }
  lastHitsStat = { mtimeMs: st.mtimeMs, size: st.size };

  let offset = loadState().externalHitsOffset;
  if (st.size <= offset) {
    if (st.size < offset) {
      // File was truncated/rotated: restart from the beginning.
      const state = loadState();
      state.externalHitsOffset = 0;
      saveState(state);
      offset = 0;
    } else {
      return;
    }
  }
  const fd = fs.openSync(CANARY_HITS_PATH, "r");
  let chunk: string;
  try {
    const buf = Buffer.alloc(st.size - offset);
    fs.readSync(fd, buf, 0, buf.length, offset);
    chunk = buf.toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
  for (const line of chunk.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let hit: CanaryHit;
    try {
      hit = JSON.parse(trimmed) as CanaryHit;
    } catch {
      continue;
    }
    const canary = hit.value ? findCanaryByValue(hit.value) : null;
    if (!canary) continue;
    respondCanaryTrigger({
      policy,
      agentId: canary.agentId ?? "external",
      canary,
      vector: "external_hit",
      evidence: {
        source: hit.source ?? CANARY_HITS_PATH,
        ...(hit.ts ? { hitAt: hit.ts } : {}),
      },
    });
  }
  const done = loadState();
  done.externalHitsOffset = st.size;
  saveState(done);
}

/**
 * Fail-closed gate evaluated at the start of EVERY tool call (wired in
 * server.ts): first sweep external canary hits (a hit may suspend this
 * agent), then deny everything while the agent is suspended.
 */
export function honeytokenCheckpoint(
  policy: PolicyEngine,
  agentId: string,
): { suspended: boolean; message?: string } {
  processExternalHits(policy);
  const s = getSuspension(agentId);
  if (!s) return { suspended: false };
  return {
    suspended: true,
    message:
      `Agent '${agentId}' is SUSPENDED: ${s.reason} at ${s.suspendedAt}. ` +
      `Every request is denied (fail-closed) until a human reviews the incident ` +
      `(see audit.jsonl: honeytoken_triggered / agent_revoked) and removes the ` +
      `agent's entry under 'suspended' in ${HONEYTOKEN_STATE_PATH}.`,
  };
}
