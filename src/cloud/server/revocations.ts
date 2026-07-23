/**
 * Fleet revocation (EPIC-10, H10.4).
 *
 *   POST /v1/admin/revocations { teamId, agentId, reason }  → Revocation
 *   GET  /v1/revocations?teamId=&since=                     → { revocations }
 *
 * The admin endpoint records the revocation (reason is MANDATORY — it lands
 * in the audit trail, per blast-radius discipline of §6.5) and marks the
 * agent revoked. Gateways pull the feed on their sync loop and apply
 * `PolicyEngine.revokeAgent(agentId)` locally; a gateway that is offline
 * revokes on reconnect (its minted tokens have already expired by TTL).
 *
 * Note: a REVOKED agent's audit batches are still ingested — revocation cuts
 * capabilities, not forensics. Re-enrolling with a valid enrollToken lifts
 * the revocation (enroll.ts), which is the deliberate human recovery path.
 */
import {
  asNonEmptyString,
  badRequest,
  isRecord,
  notFound,
  type Revocation,
} from "./model.js";
import type { Store } from "./store.js";

export function addRevocation(store: Store, body: unknown): Revocation {
  if (!isRecord(body)) throw badRequest("body must be a JSON object");
  const teamId = asNonEmptyString(body.teamId);
  const agentId = asNonEmptyString(body.agentId);
  const reason = asNonEmptyString(body.reason);
  if (!teamId) throw badRequest("teamId is required");
  if (!agentId) throw badRequest("agentId is required");
  if (!reason) {
    throw badRequest(
      "reason is required — fleet revocation without a motive is not auditable",
    );
  }
  if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);
  const agent = store.getAgent(teamId, agentId);
  if (!agent) throw notFound(`agent ${agentId} is not enrolled in team ${teamId}`);

  const revocation: Revocation = {
    teamId,
    agentId,
    reason,
    ts: new Date().toISOString(),
  };
  store.addRevocation(revocation);
  store.updateAgent(teamId, agentId, {
    revoked: true,
    revokedAt: revocation.ts,
  });
  return revocation;
}

export function listRevocations(
  store: Store,
  teamId: string,
  since?: string,
): Revocation[] {
  return store.listRevocations(teamId, since);
}
