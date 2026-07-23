/**
 * Panel-side human approvals (EPIC-10 H10.6, PLAN-LANDING-PANEL F2).
 *
 * The approval QUEUE is derived from two sources of truth:
 *   1. the team's central audit — `approval_requested` events (reported by the
 *      gateways) plus the resolution echoes the gateway emits when it APPLIES
 *      a decision (`approval_approved` / `approval_denied` / `approval_expired`);
 *   2. the panel's own decision records (approvals.json) — decisions issued
 *      here, which the gateway's approval-sync polls and applies.
 *
 * Status precedence: gateway echo (proof of application) > panel decision
 * (issued, maybe not yet applied) > expiry (expiresAt in the past) > pending.
 *
 * The gateway remains the ONLY place where grants materialize: a panel
 * decision never mints anything itself — it is a signed intent the gateway
 * consumes fail-closed (unknown/expired ids are ignored there), and the
 * engine audits the outcome exactly once.
 */
import { parseTtlStrict } from "../../policy/engine.js";
import {
  asNonEmptyString,
  badRequest,
  isRecord,
  notFound,
  type ApprovalDecision,
  type StoredAuditEvent,
} from "./model.js";
import type { Store } from "./store.js";

/** Origin marker recorded on every panel decision (lands in gateway audit). */
export const PANEL_DECIDED_BY = "human:cloud:panel";

export type PanelApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface PanelApproval {
  approvalId: string;
  agentId: string;
  capability: string;
  /** TTL the agent asked for (null = unbounded ask). */
  ttl: string | null;
  reason: string | null;
  requestedAt: string;
  expiresAt: string | null;
  status: PanelApprovalStatus;
  decidedBy?: string;
  decidedAt?: string;
  /** Where the resolution came from: the panel or the gateway itself (CLI). */
  resolution: "cloud" | "gateway" | null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

interface EchoResolution {
  status: PanelApprovalStatus;
  decidedBy?: string;
  ts: string;
}

/** approval_approved / _denied / _expired events, keyed by request id. */
function echoResolutions(events: StoredAuditEvent[]): Map<string, EchoResolution> {
  const map = new Map<string, EchoResolution>();
  for (const e of events) {
    const id = str(e.detail.id);
    if (!id) continue;
    if (e.kind === "approval_approved" || e.kind === "approval_denied") {
      map.set(id, {
        status: e.kind === "approval_approved" ? "approved" : "denied",
        decidedBy: str(e.detail.decidedBy) ?? undefined,
        ts: e.ts,
      });
    } else if (e.kind === "approval_expired") {
      map.set(id, { status: "expired", ts: e.ts });
    }
  }
  return map;
}

/**
 * The approvals queue for a team. `filter`: "pending" (default), "resolved"
 * or "all". Pending first (oldest first — the human triage order), resolved
 * after (newest first).
 */
export function listApprovals(
  store: Store,
  teamId: string,
  filter: "pending" | "resolved" | "all" = "all",
  now: Date = new Date(),
): PanelApproval[] {
  const events = store.allAuditEvents(teamId);
  const echoes = echoResolutions(events);
  const out: PanelApproval[] = [];

  for (const e of events) {
    if (e.kind !== "approval_requested") continue;
    const approvalId = str(e.detail.id);
    if (!approvalId) continue;

    const expiresAt = str(e.detail.expiresAt);
    const echo = echoes.get(approvalId);
    const panelDecision = store.approvalDecision(teamId, approvalId);

    let status: PanelApprovalStatus;
    let decidedBy: string | undefined;
    let decidedAt: string | undefined;
    let resolution: PanelApproval["resolution"] = null;

    if (echo) {
      status = echo.status;
      decidedBy = echo.decidedBy;
      decidedAt = echo.ts;
      resolution = panelDecision ? "cloud" : "gateway";
    } else if (panelDecision) {
      status = panelDecision.decision;
      decidedBy = panelDecision.decidedBy;
      decidedAt = panelDecision.ts;
      resolution = "cloud";
    } else if (expiresAt && Date.parse(expiresAt) <= now.getTime()) {
      status = "expired";
      decidedAt = expiresAt;
      resolution = "gateway";
    } else {
      status = "pending";
    }

    out.push({
      approvalId,
      agentId: e.agentId,
      capability: str(e.detail.capability) ?? "(unknown)",
      ttl: str(e.detail.ttl),
      reason: str(e.detail.reason),
      requestedAt: e.ts,
      expiresAt,
      status,
      ...(decidedBy ? { decidedBy } : {}),
      ...(decidedAt ? { decidedAt } : {}),
      resolution,
    });
  }

  const filtered = out.filter((a) =>
    filter === "all" ? true : filter === "pending" ? a.status === "pending" : a.status !== "pending",
  );
  const weight = (a: PanelApproval) => (a.status === "pending" ? 0 : 1);
  return filtered.sort((a, b) => {
    const w = weight(a) - weight(b);
    if (w !== 0) return w;
    // Pending: oldest first (triage). Resolved: newest first (recency).
    return a.status === "pending"
      ? a.requestedAt.localeCompare(b.requestedAt)
      : b.requestedAt.localeCompare(a.requestedAt);
  });
}

export interface ResolveResult {
  decision: ApprovalDecision;
  alreadyDecided: boolean;
}

/**
 * Issue a panel decision for a pending approval request.
 *
 * Validation mirrors the CLI contract (approvals-cli.ts): denials REQUIRE a
 * reason; an optional TTL can only SHORTEN what the agent asked for; an
 * already-decided or expired request cannot be (re-)decided.
 */
export function resolveApproval(
  store: Store,
  body: unknown,
  now: Date = new Date(),
): ResolveResult {
  if (!isRecord(body)) throw badRequest("body must be a JSON object");
  const teamId = asNonEmptyString(body.teamId);
  const approvalId = asNonEmptyString(body.approvalId);
  const decisionRaw = asNonEmptyString(body.decision);
  const reason = asNonEmptyString(body.reason) ?? undefined;
  const ttl = asNonEmptyString(body.ttl) ?? undefined;

  if (!teamId) throw badRequest("teamId is required");
  if (!approvalId) throw badRequest("approvalId is required");
  if (decisionRaw !== "approve" && decisionRaw !== "deny") {
    throw badRequest("decision must be 'approve' or 'deny'");
  }
  if (decisionRaw === "deny" && !reason) {
    throw badRequest("reason is required for deny — the agent deserves to know why");
  }
  if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);

  // The request must exist in the team's central audit (gateway-reported).
  const events = store.allAuditEvents(teamId);
  const requestEvent = events.find(
    (e) => e.kind === "approval_requested" && str(e.detail.id) === approvalId,
  );
  if (!requestEvent) {
    throw notFound(
      `unknown approval id '${approvalId}' — the gateway has not reported it to this team`,
    );
  }

  // Already decided? Panel record first, then the gateway echo (CLI decision).
  const existing = store.approvalDecision(teamId, approvalId);
  if (existing) return { decision: existing, alreadyDecided: true };
  const echo = echoResolutions(events).get(approvalId);
  if (echo && echo.status !== "expired") {
    throw badRequest(
      `approval '${approvalId}' was already ${echo.status} at the gateway` +
        (echo.decidedBy ? ` by ${echo.decidedBy}` : "") +
        " — decisions are one-shot",
      "already_decided",
    );
  }

  // Expired requests can no longer be approved (the agent must re-request).
  const expiresAt = str(requestEvent.detail.expiresAt);
  if (expiresAt && Date.parse(expiresAt) <= now.getTime()) {
    throw badRequest(
      `approval '${approvalId}' expired at ${expiresAt} — the agent must request the capability again`,
      "approval_expired",
    );
  }

  // TTL can only SHORTEN the ask (same rule as the CLI; ceilings clamp later
  // in the engine when the grant materializes).
  if (ttl !== undefined) {
    if (decisionRaw === "deny") throw badRequest("ttl only applies to approve");
    const newMs = parseTtlStrict(ttl, "ttl");
    const askedTtl = str(requestEvent.detail.ttl);
    if (askedTtl !== null) {
      const askedMs = parseTtlStrict(askedTtl, "requested ttl");
      if (newMs > askedMs) {
        throw badRequest(
          `ttl can only SHORTEN the requested TTL: the agent asked for '${askedTtl}', you passed '${ttl}'`,
        );
      }
    }
  }

  const decision: ApprovalDecision = {
    approvalId,
    teamId,
    agentId: requestEvent.agentId,
    decision: decisionRaw === "approve" ? "approved" : "denied",
    ...(reason ? { reason } : {}),
    ...(ttl ? { ttl } : {}),
    decidedBy: PANEL_DECIDED_BY,
    ts: now.toISOString(),
  };
  store.addApprovalDecision(decision);
  return { decision, alreadyDecided: false };
}

/** The gateway-facing feed: panel decisions for a team (optionally one agent). */
export function listDecisions(
  store: Store,
  teamId: string,
  since?: string,
  forAgentId?: string,
): ApprovalDecision[] {
  return store
    .approvalDecisions(teamId, since)
    .filter((d) => (forAgentId === undefined ? true : d.agentId === forAgentId));
}
