/**
 * ScopeGate Cloud — approval decisions sync (PLAN-LANDING-PANEL F3, gateway
 * side of EPIC-10 H10.6).
 *
 * Poll GET /v1/approvals/decisions?teamId=&since= every
 * SCOPEGATE_CLOUD_APPROVAL_INTERVAL_MS (default 15 s — the same cadence as
 * the revocations feed).
 *
 * For each decision naming THIS gateway's agentId the sync applies it to the
 * LOCAL pending queue via resolveApproval() (src/policy/approvals.ts) — the
 * human-side write of the frozen approvals contract. The policy engine then
 * consumes the decision on its next refresh (fresh mtime-checked read),
 * materializes the one-shot grant and audits exactly once, with `decidedBy`
 * carrying "human:cloud:panel" — indistinguishable in kind from a CLI
 * decision, distinguishable in origin.
 *
 * This module NEVER mints grants and NEVER audits: the engine is the only
 * place where a decision becomes a capability (same discipline as
 * approvals-cli.ts, which documents why double-auditing would double-count).
 *
 * Failure modes, all fail-soft and idempotent:
 *   - cloud unreachable        → the loop backs off; the local CLI channel
 *                                keeps working (local-first, §3).
 *   - decision for an unknown  → skipped (the request is not pending on THIS
 *     id                         gateway: already resolved, pruned, or made
 *                                by another gateway of the same team).
 *   - already decided locally  → skipped (resolveApproval is idempotent;
 *                                latest decision wins, first one recorded).
 *   - ttl on the decision      → applied as a SHORTEN of the pending line
 *                                before resolving (the server validated the
 *                                shorten-only rule; the engine clamps anyway).
 *
 * Frozen wire contract:
 *   GET /v1/approvals/decisions?teamId=<id>&since=<ISO> → 200 {decisions: [...]}
 *   decision: {approvalId, teamId, agentId, decision: "approved"|"denied",
 *              reason?, ttl?, decidedBy, ts}
 */
import {
  checkDecision,
  readPendingRequests,
  resolveApproval,
  shortenApprovalRequestTtl,
} from "../../policy/approvals.js";

export const DEFAULT_APPROVAL_SYNC_INTERVAL_MS = 15_000;

/** Origin marker used when the server omitted decidedBy (it never does). */
export const DEFAULT_PANEL_DECIDED_BY = "human:cloud:panel";

export interface CloudApprovalDecision {
  approvalId: string;
  agentId: string;
  decision: "approved" | "denied";
  reason?: string;
  ttl?: string;
  decidedBy?: string;
  ts?: string;
}

/**
 * Apply one cloud decision to the local queue. Returns true when a decision
 * was newly recorded. Never throws on data problems — a malformed or
 * inapplicable decision is skipped, never fatal to the loop.
 */
export function applyCloudApproval(
  agentId: string,
  decision: CloudApprovalDecision,
): boolean {
  if (typeof decision?.approvalId !== "string" || !decision.approvalId) return false;
  if (decision.agentId !== agentId) return false;
  if (decision.decision !== "approved" && decision.decision !== "denied") return false;

  // Already decided locally (CLI, or an earlier sync tick) — idempotent.
  if (checkDecision(decision.approvalId)) return false;

  // The request must be pending on THIS gateway.
  const pending = readPendingRequests().find((r) => r.id === decision.approvalId);
  if (!pending) return false;

  // TTL shorten BEFORE resolving: the engine materializes from the line.
  if (decision.decision === "approved" && decision.ttl) {
    try {
      shortenApprovalRequestTtl(decision.approvalId, decision.ttl);
    } catch (e) {
      console.error(
        `[scopegate cloud] warn: could not shorten ttl of approval ${decision.approvalId}: ` +
          `${(e as Error).message} — applying the decision with the original ask`,
      );
    }
  }

  const decidedBy = decision.decidedBy ?? DEFAULT_PANEL_DECIDED_BY;
  try {
    resolveApproval(decision.approvalId, decision.decision, decidedBy);
  } catch (e) {
    console.error(
      `[scopegate cloud] warn: could not apply approval ${decision.approvalId}: ${(e as Error).message}`,
    );
    return false;
  }
  console.error(
    `[scopegate cloud] info: approval ${decision.approvalId} ${decision.decision} from the panel ` +
      `(${decidedBy}) — the engine materializes it on the agent's next request`,
  );
  return true;
}

export interface ApprovalSyncDeps {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * One approval-sync poll tick. `lastSeen` is an in-memory cursor (ts of the
 * newest decision already processed); correctness never depends on it —
 * application is idempotent — it only trims the payload. Throws on
 * transport/HTTP errors so the loop backs off.
 */
export async function syncApprovalsOnce(
  cfg: { url: string; teamId: string; agentSecret: string },
  agentId: string,
  lastSeen: string | null,
  deps: ApprovalSyncDeps = {},
): Promise<{ applied: number; lastSeen: string | null }> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const qs = new URLSearchParams({ teamId: cfg.teamId });
  if (lastSeen) qs.set("since", lastSeen);
  const res = await fetchImpl(`${cfg.url}/v1/approvals/decisions?${qs}`, {
    headers: { authorization: `Bearer ${cfg.agentSecret}` },
    signal: AbortSignal.timeout(deps.timeoutMs ?? 10_000),
  });
  if (!res.ok) {
    throw new Error(`approval sync failed (HTTP ${res.status})`);
  }
  const body = (await res.json()) as { decisions?: CloudApprovalDecision[] };
  const decisions = Array.isArray(body.decisions) ? body.decisions : [];
  let applied = 0;
  let newest = lastSeen;
  for (const d of decisions) {
    if (typeof d?.ts === "string" && (!newest || d.ts > newest)) newest = d.ts;
    if (applyCloudApproval(agentId, d)) applied++;
  }
  return { applied, lastSeen: newest };
}
