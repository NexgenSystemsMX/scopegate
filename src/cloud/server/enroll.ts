/**
 * Agent enrollment (EPIC-10, H10.2).
 *
 *   POST /v1/enroll { agentId, enrollToken, pubkeyFingerprint, pubkey? }
 *     → { agentSecret, teamId, cloudPubkey }
 *
 * The enrollToken (created with the team, shown in the dashboard) is the
 * bootstrap credential — it is presented in the request BODY, so the endpoint
 * itself needs no Bearer. Whoever holds it may (re-)enroll an agent.
 *
 * Re-enrollment of the same agentId with a valid token ROTATES the
 * agentSecret (a fresh one is minted and returned; the old one stops working)
 * and updates the enrolled pubkey/fingerprint. This is the recovery path for
 * a gateway whose home dir was wiped; it is also why the enrollToken must be
 * treated as a team-root secret.
 *
 * Pubkey handling (contract note): the frozen API contract names the field
 * `pubkeyFingerprint`. Signature verification at ingest needs the actual
 * PUBLIC KEY, so enroll additionally accepts it under `pubkey` / `publicKey`
 * / `publicKeyPem` (or a PEM passed inside `pubkeyFingerprint` itself).
 * When both PEM and fingerprint are present they must match. An agent
 * enrolled without a PEM can authenticate but its audit batches will be
 * REJECTED (fail-closed: unverifiable provenance is not ingestible).
 */
import crypto from "node:crypto";
import { fingerprintOf } from "../../audit/identity.js";
import {
  asNonEmptyString,
  badRequest,
  isRecord,
  unauthorized,
  type Agent,
} from "./model.js";
import type { Store } from "./store.js";
import type { CloudIdentity } from "./keys.js";

export interface EnrollResult {
  agentSecret: string;
  teamId: string;
  cloudPubkey: string;
}

export function hashAgentSecret(secret: string): string {
  return crypto.createHash("sha256").update(secret, "utf8").digest("hex");
}

/** Extract the agent pubkey PEM from the tolerant set of accepted fields. */
function extractPubkey(body: Record<string, unknown>): string | undefined {
  for (const key of ["pubkey", "publicKey", "publicKeyPem"] as const) {
    const v = body[key];
    if (typeof v === "string" && v.includes("BEGIN PUBLIC KEY")) return v;
  }
  const fp = body.pubkeyFingerprint;
  if (typeof fp === "string" && fp.includes("BEGIN PUBLIC KEY")) return fp;
  return undefined;
}

export function enrollAgent(
  store: Store,
  cloudIdentity: CloudIdentity,
  body: unknown,
): EnrollResult {
  if (!isRecord(body)) throw badRequest("body must be a JSON object");
  const agentId = asNonEmptyString(body.agentId);
  const enrollToken = asNonEmptyString(body.enrollToken);
  if (!agentId) throw badRequest("agentId is required");
  if (agentId.length > 128) throw badRequest("agentId too long (max 128)");
  if (!enrollToken) throw badRequest("enrollToken is required");

  const team = store.findTeamByEnrollToken(enrollToken);
  if (!team) throw unauthorized("invalid enrollToken");

  const publicKey = extractPubkey(body);
  let fingerprint: string | undefined;
  if (publicKey !== undefined) {
    try {
      fingerprint = fingerprintOf(publicKey);
    } catch {
      throw badRequest("pubkey is not a valid PEM public key");
    }
    const declared = asNonEmptyString(body.pubkeyFingerprint);
    if (
      declared &&
      !declared.includes("BEGIN PUBLIC KEY") &&
      declared !== fingerprint
    ) {
      throw badRequest("pubkeyFingerprint does not match the provided pubkey");
    }
  } else {
    fingerprint = asNonEmptyString(body.pubkeyFingerprint) ?? undefined;
    if (!fingerprint) {
      throw badRequest(
        "pubkeyFingerprint is required (and a pubkey PEM is strongly recommended: " +
          "without it audit ingest is rejected fail-closed)",
      );
    }
  }

  const agentSecret = crypto.randomBytes(32).toString("base64url");
  const existing = store.getAgent(team.teamId, agentId);
  const agent: Agent = {
    agentId,
    teamId: team.teamId,
    fingerprint,
    ...(publicKey !== undefined ? { publicKey } : {}),
    secretHash: hashAgentSecret(agentSecret),
    enrolledAt: existing?.enrolledAt ?? new Date().toISOString(),
    lastSeen: existing?.lastSeen ?? null,
    revoked: false, // re-enroll lifts a previous revocation (explicit human act)
  };
  store.upsertAgent(agent);

  return {
    agentSecret,
    teamId: team.teamId,
    cloudPubkey: cloudIdentity.publicKey,
  };
}
