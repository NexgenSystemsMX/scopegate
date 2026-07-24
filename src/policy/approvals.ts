/**
 * Local human-approval queue (EPIC-04 H-04.3) — the bridge between a policy
 * rule `require: human_approval` and the human who approves or denies it.
 *
 * FILE CONTRACT (frozen for EPIC-08, which builds `scopegate approve|deny`
 * on top of it — the CLI must treat these files exactly as described here):
 *
 *   ~/.scopegate/approvals.pending.jsonl   — one JSON object per line, 0600.
 *     {
 *       id:          string (uuid),
 *       agentId:     string,
 *       capability:  string,           // exact capability string requested
 *       ttl:         string | null,    // TTL the agent asked for (null = none)
 *       reason:      string,           // one-line justification from the agent
 *       requestedAt: number (epoch ms),
 *       expiresAt:   number (epoch ms),// request expiry (default +10 min,
 *                                      //   configurable via limits.approval_ttl)
 *       status?:     "pending" | "approved" | "denied" | "expired",
 *       resolvedAt?: number (epoch ms) // set when status leaves "pending"
 *     }
 *     Lines are APPENDED by agents' gateways (createApprovalRequest). A line
 *     without `status` (or "pending") is awaiting a human. The gateway that
 *     owns the agent marks lines resolved IN PLACE (atomic rewrite, see
 *     updatePendingStatuses) when it consumes a decision or observes expiry,
 *     so a decision is never materialized twice — not even across restarts.
 *     The CLI may prune resolved lines; it must preserve lines it does not
 *     understand.
 *
 *   ~/.scopegate/approvals.decisions.jsonl — one JSON object per line, 0600.
 *     {
 *       id:        string,             // id of a pending request
 *       decision:  "approved" | "denied",
 *       decidedAt: number (epoch ms),
 *       decidedBy: string              // e.g. "human:cli"; free-form
 *     }
 *     APPEND-ONLY. Written by the human side (CLI now, remote channels in
 *     EPIC-08), read by gateways. Latest decision for an id wins.
 *
 * Cross-process protocol (no watchers): readers re-read a file only when its
 * (mtimeMs, size) changed — cheap stat per check, fresh data after any write.
 * Writers: pending creates and decision resolves are single-line appends;
 * status marking is read-merge-write with an atomic rename (a concurrent
 * single-line append racing the rename survives: lines are merged by id).
 *
 * PUBLIC API consumed by EPIC-08:
 *   - createApprovalRequest(input)  → queue a request (dedups open ones)
 *   - resolveApproval(id, decision) → append a decision (idempotent)
 *   - checkDecision(id)             → latest decision or null (fresh read)
 *   - listApprovals()               → every request with its effective state
 *   - readPendingRequests()/readDecisions() → raw fresh reads
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { atomicWriteFileSync } from "./fsutil.js";
import { notifyApprovalRequested } from "../notify/notifier.js";

export const APPROVALS_PENDING_PATH = path.join(
  SCOPEGATE_DIR,
  "approvals.pending.jsonl",
);
export const APPROVALS_DECISIONS_PATH = path.join(
  SCOPEGATE_DIR,
  "approvals.decisions.jsonl",
);

/** Default lifetime of a pending request: 10 minutes (limits.approval_ttl). */
export const DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000;

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalRequest {
  id: string;
  agentId: string;
  capability: string;
  ttl: string | null;
  reason: string;
  requestedAt: number;
  expiresAt: number;
  status?: ApprovalStatus;
  resolvedAt?: number;
  /** Capability-plan bundle (mejora #4): the items a single decision covers. */
  plan?: { capability: string; ttl?: string }[];
  /** Lease every plan grant binds to on approval (mejora #1 + #4). */
  leaseId?: string;
}

export interface ApprovalDecision {
  id: string;
  decision: "approved" | "denied";
  decidedAt: number;
  decidedBy: string;
}

/* ------------------------------------------------------------------------ */
/* Fresh-by-mtime JSONL readers (no file watchers between processes).        */
/* ------------------------------------------------------------------------ */

interface FileCache<T> {
  mtimeMs: number;
  size: number;
  data: T[];
}

const caches = new Map<string, FileCache<unknown>>();

function readJsonlFresh<T>(filePath: string, validate: (v: unknown) => T | null): T[] {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    caches.delete(filePath);
    return [];
  }
  const cached = caches.get(filePath) as FileCache<T> | undefined;
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached.data;
  }
  const data: T[] = [];
  const raw = fs.readFileSync(filePath, "utf8");
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const v = validate(JSON.parse(trimmed));
      if (v) data.push(v);
    } catch {
      // A half-written or foreign line must never break the queue: skip it.
    }
  }
  caches.set(filePath, { mtimeMs: stat.mtimeMs, size: stat.size, data });
  return data;
}

function asApprovalRequest(v: unknown): ApprovalRequest | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (
    typeof r.id !== "string" ||
    typeof r.agentId !== "string" ||
    typeof r.capability !== "string" ||
    typeof r.requestedAt !== "number" ||
    typeof r.expiresAt !== "number"
  ) {
    return null;
  }
  return r as unknown as ApprovalRequest;
}

function asApprovalDecision(v: unknown): ApprovalDecision | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (
    typeof r.id !== "string" ||
    (r.decision !== "approved" && r.decision !== "denied") ||
    typeof r.decidedAt !== "number"
  ) {
    return null;
  }
  return r as unknown as ApprovalDecision;
}

/* ------------------------------------------------------------------------ */
/* Raw reads (fresh by mtime+size).                                          */
/* ------------------------------------------------------------------------ */

export function readPendingRequests(): ApprovalRequest[] {
  return readJsonlFresh(APPROVALS_PENDING_PATH, asApprovalRequest);
}

/** Latest decision per id. */
export function readDecisions(): Map<string, ApprovalDecision> {
  const list = readJsonlFresh(APPROVALS_DECISIONS_PATH, asApprovalDecision);
  const map = new Map<string, ApprovalDecision>();
  for (const d of list) map.set(d.id, d); // append-only: latest wins
  return map;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Queue a new approval request. Idempotent per (agentId, capability): when an
 * open request (pending, unexpired, undecided) already exists, it is returned
 * with `created: false` instead of flooding the human's queue.
 */
export function createApprovalRequest(input: {
  agentId: string;
  capability: string;
  ttl?: string | null;
  reason?: string;
  approvalTtlMs?: number;
  /** Capability-plan bundle (mejora #4): one decision covers every item. */
  plan?: { capability: string; ttl?: string }[];
  leaseId?: string;
}): { request: ApprovalRequest; created: boolean } {
  const now = Date.now();
  const decisions = readDecisions();
  const existing = readPendingRequests().find(
    (r) =>
      r.agentId === input.agentId &&
      r.capability === input.capability &&
      (!r.status || r.status === "pending") &&
      r.expiresAt > now &&
      !decisions.has(r.id),
  );
  if (existing) return { request: existing, created: false };

  const request: ApprovalRequest = {
    id: crypto.randomUUID(),
    agentId: input.agentId,
    capability: input.capability,
    ttl: input.ttl ?? null,
    reason: input.reason ?? "",
    requestedAt: now,
    expiresAt: now + (input.approvalTtlMs ?? DEFAULT_APPROVAL_TTL_MS),
    ...(input.plan?.length ? { plan: input.plan } : {}),
    ...(input.leaseId ? { leaseId: input.leaseId } : {}),
  };
  ensureDir();
  fs.appendFileSync(APPROVALS_PENDING_PATH, JSON.stringify(request) + "\n", {
    mode: 0o600,
  });
  // EPIC-08 hook (additive): tell the human a request is waiting. Fires ONLY
  // on a genuinely new line (deduped re-requests stay silent) and is fully
  // fire-and-forget — a notifier failure never blocks, breaks, or grants.
  void notifyApprovalRequested(request).catch((e: unknown) => {
    console.error(
      `[scopegate] warn: approval notifier failed: ${(e as Error).message}`,
    );
  });
  return { request, created: true };
}

/**
 * Record a human decision for a pending request (this is what
 * `scopegate approve|deny <id>` will call). Idempotent: an existing decision
 * for the id is returned unchanged. Throws when the id is unknown — the CLI
 * should list requests first (listApprovals).
 */
export function resolveApproval(
  id: string,
  decision: "approved" | "denied",
  decidedBy: string = "human:cli",
): ApprovalDecision {
  const existing = readDecisions().get(id);
  if (existing) return existing;
  const known = readPendingRequests().some((r) => r.id === id);
  if (!known) {
    throw new Error(
      `Unknown approval id '${id}' — run \`scopegate approvals list\` to see pending requests.`,
    );
  }
  const entry: ApprovalDecision = {
    id,
    decision,
    decidedAt: Date.now(),
    decidedBy,
  };
  ensureDir();
  fs.appendFileSync(APPROVALS_DECISIONS_PATH, JSON.stringify(entry) + "\n", {
    mode: 0o600,
  });
  return entry;
}

/** Latest decision for a request id (fresh read), or null when undecided. */
export function checkDecision(id: string): ApprovalDecision | null {
  return readDecisions().get(id) ?? null;
}

export interface ListedApproval extends ApprovalRequest {
  /** Computed state: stored status, else derived from decisions/expiry. */
  effectiveStatus: ApprovalStatus;
  decision?: ApprovalDecision;
}

/** Everything a human reviewer needs: requests plus their effective state. */
export function listApprovals(): ListedApproval[] {
  const decisions = readDecisions();
  const now = Date.now();
  return readPendingRequests().map((r) => {
    const decision = decisions.get(r.id);
    const stored =
      r.status && r.status !== "pending" ? r.status : undefined;
    const effectiveStatus: ApprovalStatus =
      stored ?? decision?.decision ?? (r.expiresAt <= now ? "expired" : "pending");
    return { ...r, effectiveStatus, ...(decision ? { decision } : {}) };
  });
}

/**
 * Mark pending lines resolved IN PLACE (atomic read-merge-write). Used by the
 * gateway when it consumes a decision or observes expiry — this is what makes
 * approvals one-shot across process restarts. Lines appended by other
 * processes between read and write are preserved (merged by id).
 */
export function updatePendingStatuses(
  updates: Map<string, { status: ApprovalStatus; resolvedAt: number }>,
): void {
  if (updates.size === 0) return;
  // Bypass the cache for the merge base: correctness beats speed here.
  caches.delete(APPROVALS_PENDING_PATH);
  const lines = readPendingRequests().map((r) => {
    const u = updates.get(r.id);
    return u ? { ...r, status: u.status, resolvedAt: u.resolvedAt } : r;
  });
  ensureDir();
  atomicWriteFileSync(
    APPROVALS_PENDING_PATH,
    lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
  );
  caches.delete(APPROVALS_PENDING_PATH);
}

/**
 * Shorten the TTL of a pending request IN PLACE (atomic, line-level merge:
 * foreign/corrupt lines preserved byte-for-byte). Callers must enforce the
 * shorten-only rule themselves (the CLI and the cloud approval-sync both
 * validate before calling). The engine's ceilings clamp on top when the
 * grant materializes.
 */
export function shortenApprovalRequestTtl(id: string, newTtl: string): void {
  let raw: string;
  try {
    raw = fs.readFileSync(APPROVALS_PENDING_PATH, "utf8");
  } catch {
    throw new Error(`approval '${id}' not found — no pending requests file`);
  }
  let found = false;
  const out = raw
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return line;
      try {
        const obj = JSON.parse(trimmed) as Record<string, unknown>;
        if (obj && obj.id === id) {
          found = true;
          return JSON.stringify({ ...obj, ttl: newTtl });
        }
        return line;
      } catch {
        return line; // half-written/foreign line: preserved byte-for-byte
      }
    })
    .join("\n");
  if (!found) {
    throw new Error(`approval '${id}' vanished from the pending file — nothing to shorten`);
  }
  ensureDir();
  atomicWriteFileSync(APPROVALS_PENDING_PATH, out);
  caches.delete(APPROVALS_PENDING_PATH);
}

/* ------------------------------------------------------------------------ */
/* Approval continuation (mejora #2): intents + results                      */
/*                                                                          */
/* An agent may attach `execute_on_approval: {tool, args}` to a capability   */
/* request that escalates to human approval. The gateway queues the INTENT   */
/* here; when the approval is decided "approved" (CLI or cloud panel), the   */
/* engine's materialization step executes the intent with the fresh grant    */
/* and persists the outcome. The agent learns the result via                 */
/* scopegate_collect / scopegate_wait instead of polling-burning turns.      */
/*                                                                          */
/* FILE CONTRACT (append-only JSONL, 0600, same trust level as the rest of   */
/* ~/.scopegate):                                                            */
/*   approvals.intents.jsonl  — one ApprovalIntent per line. args are stored */
/*     verbatim (needed to execute) — local disk only, NEVER audited.        */
/*   approval-results.jsonl   — one IntentResult per line. Results are       */
/*     stored verbatim for collection; the AUDIT only records their hash.    */
/* ------------------------------------------------------------------------ */

export const APPROVALS_INTENTS_PATH = path.join(
  SCOPEGATE_DIR,
  "approvals.intents.jsonl",
);
export const APPROVALS_RESULTS_PATH = path.join(
  SCOPEGATE_DIR,
  "approval-results.jsonl",
);

export interface ApprovalIntent {
  id: string;
  approvalId: string;
  agentId: string;
  tool: string;
  args: Record<string, unknown>;
  /** sha256 of canonical args — what the audit records (never the values). */
  argsHash: string;
  status: "queued" | "executed" | "failed" | "expired";
  createdAt: number;
  expiresAt: number;
}

export interface IntentResult {
  intentId: string;
  approvalId: string;
  agentId: string;
  tool: string;
  status: "executed" | "failed";
  result?: unknown;
  error?: string;
  executedAt: number;
  durationMs: number;
}

function asApprovalIntent(v: unknown): ApprovalIntent | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (
    typeof r.id !== "string" ||
    typeof r.approvalId !== "string" ||
    typeof r.agentId !== "string" ||
    typeof r.tool !== "string" ||
    typeof r.args !== "object" ||
    r.args === null ||
    typeof r.status !== "string" ||
    typeof r.createdAt !== "number" ||
    typeof r.expiresAt !== "number"
  ) {
    return null;
  }
  return r as unknown as ApprovalIntent;
}

function asIntentResult(v: unknown): IntentResult | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (
    typeof r.intentId !== "string" ||
    typeof r.approvalId !== "string" ||
    (r.status !== "executed" && r.status !== "failed") ||
    typeof r.executedAt !== "number"
  ) {
    return null;
  }
  return r as unknown as IntentResult;
}

export function readIntents(): ApprovalIntent[] {
  return readJsonlFresh(APPROVALS_INTENTS_PATH, asApprovalIntent);
}

export function readIntentResults(): IntentResult[] {
  return readJsonlFresh(APPROVALS_RESULTS_PATH, asIntentResult);
}

/** sha256 over the canonical JSON of the args (audit-safe reference). */
export function hashArgs(args: Record<string, unknown>): string {
  return crypto.createHash("sha256").update(JSON.stringify(args)).digest("hex");
}

/**
 * Queue an intent for execution-on-approval. Idempotent per approvalId — a
 * re-request with the same open approval returns the existing intent.
 */
export function queueIntent(input: {
  approvalId: string;
  agentId: string;
  tool: string;
  args: Record<string, unknown>;
  expiresAt: number;
}): ApprovalIntent {
  const existing = readIntents().find(
    (i) => i.approvalId === input.approvalId && i.status === "queued",
  );
  if (existing) return existing;
  const intent: ApprovalIntent = {
    id: crypto.randomUUID(),
    approvalId: input.approvalId,
    agentId: input.agentId,
    tool: input.tool,
    args: input.args,
    argsHash: hashArgs(input.args),
    status: "queued",
    createdAt: Date.now(),
    expiresAt: input.expiresAt,
  };
  ensureDir();
  fs.appendFileSync(APPROVALS_INTENTS_PATH, JSON.stringify(intent) + "\n", {
    mode: 0o600,
  });
  return intent;
}

/** The queued intent for an approval, if any (fresh mtime-checked read). */
export function pendingIntentFor(approvalId: string): ApprovalIntent | undefined {
  return readIntents().find((i) => i.approvalId === approvalId && i.status === "queued");
}

/** The latest intent for an approval regardless of status. */
export function latestIntentFor(approvalId: string): ApprovalIntent | undefined {
  const all = readIntents().filter((i) => i.approvalId === approvalId);
  return all.length > 0 ? all[all.length - 1] : undefined;
}

/** The stored result for an approval (or intent id), if executed. */
export function resultFor(id: string): IntentResult | undefined {
  const all = readIntentResults();
  return (
    all.find((r) => r.approvalId === id) ??
    all.filter((r) => r.intentId === id).pop()
  );
}

/**
 * Persist the outcome of an executed intent and flip the intent's status
 * (atomic read-merge-write, foreign lines preserved byte-for-byte).
 */
export function storeIntentResult(result: IntentResult): void {
  ensureDir();
  fs.appendFileSync(APPROVALS_RESULTS_PATH, JSON.stringify(result) + "\n", {
    mode: 0o600,
  });
  caches.delete(APPROVALS_INTENTS_PATH);
  const lines = readIntents().map((i) =>
    i.approvalId === result.approvalId && i.status === "queued"
      ? { ...i, status: result.status as ApprovalIntent["status"] }
      : i,
  );
  ensureDir();
  atomicWriteFileSync(
    APPROVALS_INTENTS_PATH,
    lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
  );
  caches.delete(APPROVALS_INTENTS_PATH);
}

/** Mark queued intents whose window closed (called by the engine's refresh). */
export function expireStaleIntents(now: number): string[] {
  const stale = readIntents().filter(
    (i) => i.status === "queued" && i.expiresAt <= now,
  );
  if (stale.length === 0) return [];
  const updates = new Map(stale.map((i) => [i.id, i]));
  caches.delete(APPROVALS_INTENTS_PATH);
  const lines = readIntents().map((i) =>
    updates.has(i.id) ? { ...i, status: "expired" as const } : i,
  );
  ensureDir();
  atomicWriteFileSync(
    APPROVALS_INTENTS_PATH,
    lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
  );
  caches.delete(APPROVALS_INTENTS_PATH);
  return stale.map((i) => i.approvalId);
}
