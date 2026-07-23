/**
 * Fleet overview for the panel home (PLAN-LANDING-PANEL F2, B1).
 *
 * Everything here is derived from data the control plane already holds —
 * enrolled agents, the central audit, the policy store and the panel's
 * approval queue. No new trust surface: it is a read-only aggregation.
 */
import type { StoredAuditEvent } from "./model.js";
import { listApprovals } from "./approvals.js";
import type { Store } from "./store.js";

/** An agent is "online" when its last accepted ingest is fresher than this. */
export const ONLINE_THRESHOLD_MS = 90_000;

const SECURITY_KINDS = [
  "capability_denied",
  "ceiling_blocked",
  "honeytoken_triggered",
  "agent_revoked",
  "approval_expired",
] as const;

export interface AgentHealth {
  agentId: string;
  lastSeen: string | null;
  online: boolean;
  revoked: boolean;
}

export interface TeamOverview {
  teamId: string;
  generatedAt: string;
  agents: {
    total: number;
    active: number; // enrolled, not revoked
    revoked: number;
    online: number; // lastSeen within ONLINE_THRESHOLD_MS
    health: AgentHealth[];
  };
  audit: {
    total: number;
    last24h: number;
    lastEventAt: string | null;
  };
  approvals: {
    pending: number;
  };
  policy: {
    version: number;
    signedAt: string;
  } | null;
  /** Security-relevant audit events in the last 24 h, by kind. */
  security24h: Record<string, number>;
  /** Most recent security-relevant events (newest first, max 10). */
  recentSecurityEvents: StoredAuditEvent[];
}

export function getOverview(
  store: Store,
  teamId: string,
  now: Date = new Date(),
): TeamOverview {
  const nowMs = now.getTime();
  const since24h = new Date(nowMs - 24 * 3600 * 1000).toISOString();

  const agents = store.listAgents(teamId);
  const health: AgentHealth[] = agents.map((a) => ({
    agentId: a.agentId,
    lastSeen: a.lastSeen,
    online:
      !a.revoked && a.lastSeen !== null && nowMs - Date.parse(a.lastSeen) < ONLINE_THRESHOLD_MS,
    revoked: a.revoked,
  }));

  const events = store.allAuditEvents(teamId);
  const last24hEvents = events.filter((e) => e.ts >= since24h);

  const security24h: Record<string, number> = {};
  for (const kind of SECURITY_KINDS) security24h[kind] = 0;
  for (const e of last24hEvents) {
    if (e.kind in security24h) security24h[e.kind]++;
  }

  const recentSecurityEvents = events
    .filter((e) => (SECURITY_KINDS as readonly string[]).includes(e.kind))
    .slice(-10)
    .reverse();

  const latestPolicy = store.latestPolicy(teamId);
  const pending = listApprovals(store, teamId, "pending", now).length;

  return {
    teamId,
    generatedAt: now.toISOString(),
    agents: {
      total: agents.length,
      active: agents.filter((a) => !a.revoked).length,
      revoked: agents.filter((a) => a.revoked).length,
      online: health.filter((h) => h.online).length,
      health,
    },
    audit: {
      total: events.length,
      last24h: last24hEvents.length,
      lastEventAt: events.length > 0 ? events[events.length - 1].ts : null,
    },
    approvals: { pending },
    policy: latestPolicy
      ? { version: latestPolicy.version, signedAt: latestPolicy.signedAt }
      : null,
    security24h,
    recentSecurityEvents,
  };
}
