/**
 * Active capabilities view (PLAN-LANDING-PANEL F2, B5).
 *
 * Derived from the team's central audit: a `grant_issued` event is ACTIVE when
 * its `expiresAt` is still in the future and no revocation of that agent
 * postdates the issue time (a revocation purges every live grant of the agent
 * — see revocation-sync.ts). This is a faithful projection: grants are
 * one-shot/TTL-bound by construction, so "active" never overstates reach.
 */
import type { StoredAuditEvent } from "./model.js";
import type { Store } from "./store.js";

export interface ActiveCapability {
  agentId: string;
  grantId: string;
  capability: string;
  issuedAt: string;
  expiresAt: string;
  remainingMs: number;
  rule: string | null;
  /** "human_approval" when the grant materialized from an approved request. */
  via: string | null;
  approvalId: string | null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** Latest revocation timestamp per agent (a later grant survives it). */
function latestRevocations(store: Store, teamId: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const r of store.listRevocations(teamId)) {
    const prev = map.get(r.agentId);
    if (!prev || r.ts > prev) map.set(r.agentId, r.ts);
  }
  return map;
}

function grantStillActive(
  e: StoredAuditEvent,
  expiresAtMs: number,
  revocations: Map<string, string>,
  nowMs: number,
): boolean {
  if (expiresAtMs <= nowMs) return false;
  const revokedAt = revocations.get(e.agentId);
  // A revocation purges every grant issued BEFORE it; the team-wide "*"
  // revocation purges the whole fleet's grants.
  const revokedAll = revocations.get("*");
  if (revokedAt && e.ts < revokedAt) return false;
  if (revokedAll && e.ts < revokedAll) return false;
  return true;
}

export function listActiveCapabilities(
  store: Store,
  teamId: string,
  agentIdFilter?: string,
  now: Date = new Date(),
): ActiveCapability[] {
  const nowMs = now.getTime();
  const revocations = latestRevocations(store, teamId);
  const out: ActiveCapability[] = [];

  for (const e of store.allAuditEvents(teamId)) {
    if (e.kind !== "grant_issued") continue;
    if (agentIdFilter && e.agentId !== agentIdFilter) continue;
    const grantId = str(e.detail.id);
    const capability = str(e.detail.capability);
    const expiresAt = str(e.detail.expiresAt);
    if (!grantId || !capability || !expiresAt) continue;
    const expiresAtMs = Date.parse(expiresAt);
    if (Number.isNaN(expiresAtMs)) continue;
    if (!grantStillActive(e, expiresAtMs, revocations, nowMs)) continue;
    out.push({
      agentId: e.agentId,
      grantId,
      capability,
      issuedAt: e.ts,
      expiresAt,
      remainingMs: expiresAtMs - nowMs,
      rule: str(e.detail.rule),
      via: str(e.detail.via),
      approvalId: str(e.detail.approvalId),
    });
  }

  // Soonest to expire first — the operationally relevant order.
  return out.sort((a, b) => a.expiresAt.localeCompare(b.expiresAt));
}
