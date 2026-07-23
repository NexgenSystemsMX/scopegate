/**
 * `scopegate approvals list` / `scopegate approve` / `scopegate deny` (EPIC-08
 * H8.3) — the HUMAN side of the local approval queue.
 *
 * ANTI-SELF-APPROVAL GUARD: deciding requires an interactive TTY or the
 * SCOPEGATE_APPROVAL_TOKEN env var, which the human sets in their own shell —
 * outside the agent's context. Honest limit (EPIC-08 risks): on a local
 * machine this is a DETECTION barrier, not a hard one — an agent with full
 * shell access could write the decisions file directly. The hard,
 * out-of-band barrier arrives with the cloud-signed grant channel (Fase 2).
 * Every decision carries its origin ("human:cli:tty" | "human:cli:token") so
 * the tamper-evident audit trail records how it was made.
 *
 * Audit discipline: this module does NOT emit approval_approved/denied
 * events itself. The gateway's policy engine consumes the decision (fresh
 * mtime-checked read), materializes the one-shot grant, and audits exactly
 * once — with `decidedBy` carrying the CLI origin. Auditing here too would
 * double-count every decision.
 *
 * `--ttl` on approve can only SHORTEN the TTL the agent asked for; the rule
 * ceiling and limits.max_ttl still clamp the materialized grant in the
 * engine. It is applied by rewriting the pending line's `ttl` field in place
 * (atomic read-merge-write, foreign/corrupt lines preserved byte-for-byte) —
 * the frozen decisions.jsonl contract has no TTL field.
 */
import fs from "node:fs";
import {
  APPROVALS_PENDING_PATH,
  listApprovals,
  resolveApproval,
  type ApprovalDecision,
  type ListedApproval,
} from "../policy/approvals.js";
import { parseTtlStrict } from "../policy/engine.js";
import { ensureDir } from "../config/config.js";

export type ApprovalOrigin = "tty" | "token";

export function decidedByFor(origin: ApprovalOrigin): string {
  return `human:cli:${origin}`;
}

/**
 * The human guard: an approval/denial is only accepted from an interactive
 * terminal or with SCOPEGATE_APPROVAL_TOKEN present in the environment.
 * Throws an actionable error otherwise.
 */
export function assertHumanOrigin(): ApprovalOrigin {
  if (process.stdin.isTTY === true) return "tty";
  if ((process.env.SCOPEGATE_APPROVAL_TOKEN ?? "").length > 0) return "token";
  throw new Error(
    "Refusing to decide: approvals are human-only and this is not an interactive terminal. " +
      "A HUMAN must run this command in their own terminal, or set " +
      "SCOPEGATE_APPROVAL_TOKEN in their shell (outside the agent's context) and retry.",
  );
}

/* ------------------------------------------------------------------------ */
/* Decision logic (pure w.r.t. process state — origin is passed in)          */
/* ------------------------------------------------------------------------ */

export interface ApproveResult {
  request: ListedApproval;
  decision: ApprovalDecision;
  /** True when the decision already existed (idempotent re-run). */
  alreadyDecided: boolean;
  /** Effective TTL string recorded on the request after any --ttl shorten. */
  effectiveTtl: string | null;
}

function findRequest(id: string): ListedApproval {
  const req = listApprovals().find((r) => r.id === id);
  if (!req) {
    throw new Error(
      `Unknown approval id '${id}' — run \`scopegate approvals list\` to see pending requests.`,
    );
  }
  return req;
}

export function approveRequest(opts: {
  id: string;
  ttl?: string;
  origin: ApprovalOrigin;
}): ApproveResult {
  const req = findRequest(opts.id);

  const prior = req.decision;
  if (prior) {
    return {
      request: req,
      decision: prior,
      alreadyDecided: true,
      effectiveTtl: req.ttl,
    };
  }
  if (req.effectiveStatus === "expired") {
    throw new Error(
      `Approval '${opts.id}' expired at ${new Date(req.expiresAt).toISOString()} — ` +
        `it can no longer be approved. The agent must request the capability again.`,
    );
  }

  // --ttl can only SHORTEN what the agent asked for. When the request carries
  // no TTL, any valid value shortens "unbounded ask" — the rule/max_ttl
  // ceilings still clamp the grant in the engine.
  if (opts.ttl !== undefined) {
    const newMs = parseTtlStrict(opts.ttl, "--ttl");
    if (req.ttl !== null) {
      const askedMs = parseTtlStrict(req.ttl, "requested ttl");
      if (newMs > askedMs) {
        throw new Error(
          `--ttl can only SHORTEN the requested TTL: the agent asked for '${req.ttl}', ` +
            `you passed '${opts.ttl}'. Pick a value <= '${req.ttl}' (the rule ceiling and ` +
            `limits.max_ttl still apply on top).`,
        );
      }
    }
    shortenRequestTtl(opts.id, opts.ttl);
  }

  const decision = resolveApproval(opts.id, "approved", decidedByFor(opts.origin));
  return {
    request: req,
    decision,
    alreadyDecided: false,
    effectiveTtl: opts.ttl ?? req.ttl,
  };
}

export function denyRequest(opts: {
  id: string;
  reason: string;
  origin: ApprovalOrigin;
}): { request: ListedApproval; decision: ApprovalDecision; alreadyDecided: boolean } {
  const reason = (opts.reason ?? "").trim();
  if (!reason) {
    throw new Error(`--reason is required for deny — the agent deserves to know why.`);
  }
  const req = findRequest(opts.id);
  const prior = req.decision;
  if (prior) return { request: req, decision: prior, alreadyDecided: true };
  const decision = resolveApproval(opts.id, "denied", decidedByFor(opts.origin));
  return { request: req, decision, alreadyDecided: false };
}

/** Approvals for review: pending first, oldest first. */
export function approvalsForReview(includeResolved = false): ListedApproval[] {
  const all = listApprovals();
  const filtered = includeResolved
    ? all
    : all.filter((r) => r.effectiveStatus === "pending");
  return [...filtered].sort((a, b) => a.requestedAt - b.requestedAt);
}

/* ------------------------------------------------------------------------ */
/* Pending-file TTL shorten (line-level merge: preserves foreign lines)      */
/* ------------------------------------------------------------------------ */

/** Atomic write: sibling tmp file + rename, mode 0600 (config.ts pattern). */
function atomicWrite(filePath: string, data: string): void {
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

function shortenRequestTtl(id: string, newTtl: string): void {
  const raw = fs.readFileSync(APPROVALS_PENDING_PATH, "utf8");
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
  atomicWrite(APPROVALS_PENDING_PATH, out);
}

/* ------------------------------------------------------------------------ */
/* CLI entry points (guard + print)                                          */
/* ------------------------------------------------------------------------ */

function fmtAge(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m${s % 60}s`;
}

export function runApprovalsList(opts: { all?: boolean }): void {
  const rows = approvalsForReview(!!opts.all);
  if (rows.length === 0) {
    console.log(opts.all ? "(no approval requests on file)" : "(no pending approval requests)");
    return;
  }
  const now = Date.now();
  console.log(
    opts.all
      ? `APPROVAL REQUESTS (${rows.length})`
      : `PENDING APPROVAL REQUESTS (${rows.length})`,
  );
  for (const r of rows) {
    const state = r.effectiveStatus.toUpperCase();
    console.log(`  ${r.id}  [${state}]`);
    console.log(`    agent:      ${r.agentId}`);
    console.log(`    capability: ${r.capability}`);
    console.log(`    ttl asked:  ${r.ttl ?? "(none)"}`);
    if (r.reason) console.log(`    reason:     ${r.reason}`);
    console.log(`    requested:  ${fmtAge(now - r.requestedAt)} ago`);
    if (r.effectiveStatus === "pending") {
      console.log(`    expires in: ${fmtAge(r.expiresAt - now)}`);
      console.log(`    decide:     scopegate approve ${r.id}  |  scopegate deny ${r.id} --reason "..."`);
    } else if (r.decision) {
      console.log(`    decided by: ${r.decision.decidedBy} at ${new Date(r.decision.decidedAt).toISOString()}`);
    }
  }
}

export function runApprove(id: string, opts: { ttl?: string }): void {
  const origin = assertHumanOrigin();
  const res = approveRequest({ id, ttl: opts.ttl, origin });
  if (res.alreadyDecided) {
    console.log(
      `[scopegate] approval ${id} was already ${res.decision.decision} by ${res.decision.decidedBy} — no change.`,
    );
    return;
  }
  console.log(
    `[scopegate] approval ${id} APPROVED (origin: ${origin})` +
      (res.effectiveTtl ? ` — ttl: ${res.effectiveTtl}` : "") +
      `.`,
  );
  console.log(
    `[scopegate] capability: ${res.request.capability} — the agent's next request for it ` +
      `materializes a one-shot grant (still clamped by the rule ceiling and limits.max_ttl).`,
  );
}

export function runDeny(id: string, opts: { reason?: string }): void {
  const origin = assertHumanOrigin();
  const res = denyRequest({ id, reason: opts.reason ?? "", origin });
  if (res.alreadyDecided) {
    console.log(
      `[scopegate] approval ${id} was already ${res.decision.decision} by ${res.decision.decidedBy} — no change.`,
    );
    return;
  }
  console.log(
    `[scopegate] approval ${id} DENIED (origin: ${origin}). Reason: ${(opts.reason ?? "").trim()}`,
  );
}
