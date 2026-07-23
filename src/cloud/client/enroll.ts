/**
 * ScopeGate Cloud — gateway enroll (EPIC-10).
 *
 * enrollGateway() binds this gateway to a team: it sends the agent identity
 * FINGERPRINT (never the private key, never any vault secret) plus the
 * one-shot enroll token the human generated in the dashboard, and persists
 * the returned {agentSecret, teamId, cloudPubkey} into cloud.json.
 *
 * Frozen wire contract (AGENTE CLOUD-CORE implements the server):
 *   POST /v1/enroll {agentId, enrollToken, pubkeyFingerprint}
 *     → 200 {agentSecret, teamId, cloudPubkey}
 *
 * Additive field (contract note reconciled with the server, enroll.ts):
 * the client ALSO sends `pubkey` (the identity public key PEM). The server
 * needs the actual PEM to verify audit batch signatures at ingest — an
 * agent enrolled without it gets its batches rejected fail-closed
 * ("agent_pubkey_not_enrolled"). The fingerprint stays the stable identifier
 * and the server cross-checks both when present.
 *
 * The CLI command `scopegate cloud enroll` belongs to AGENTE CLOUD-CORE.
 * Until it lands, tests/e2e enroll by calling this function directly (or via
 * the raw API + writing cloud.json) — same code path, no CLI required.
 *
 * Metadata-only guarantee: the request body carries {agentId, enrollToken,
 * pubkeyFingerprint, pubkey} — public key material only, so enrolling can
 * never leak signing material or secrets.
 */
import crypto from "node:crypto";
import { loadConfig } from "../../config/config.js";
import { fingerprintOf, loadOrCreateIdentity } from "../../audit/identity.js";
import {
  saveCloudConfig,
  normalizeCloudUrl,
  type CloudConfig,
} from "./cloud-config.js";

export const ENROLL_TIMEOUT_MS = 10_000;

export interface EnrollOptions {
  /** Base URL of the cloud API (e.g. http://127.0.0.1:8080). */
  url: string;
  /** One-shot enroll token generated in the dashboard / admin API. */
  enrollToken: string;
  /** Override the agent identity to enroll (default: env/config agentId). */
  agentId?: string;
  /** Injectable for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
}

export interface EnrollResponse {
  agentSecret: string;
  teamId: string;
  cloudPubkey: string;
}

function defaultAgentId(): string {
  if (process.env.SCOPEGATE_AGENT_ID) return process.env.SCOPEGATE_AGENT_ID;
  try {
    return loadConfig().agentId;
  } catch {
    return "gateway";
  }
}

/**
 * Enroll this gateway against a cloud. On success cloud.json is (re)written
 * and the config returned. Throws an actionable Error on any failure — no
 * partial state is persisted.
 */
export async function enrollGateway(opts: EnrollOptions): Promise<CloudConfig> {
  const url = normalizeCloudUrl(opts.url);
  if (!url) throw new Error("enroll: 'url' is required");
  if (!opts.enrollToken?.trim()) {
    throw new Error("enroll: 'enrollToken' is required (one-shot code from the dashboard)");
  }
  const fetchImpl = opts.fetchImpl ?? fetch;
  // The identity is provisioned lazily (same keep-first semantics as init):
  // the fingerprint we publish commits to the key that signs audit batches.
  const identity = loadOrCreateIdentity();
  const agentId = opts.agentId ?? defaultAgentId();

  let res: Response;
  try {
    res = await fetchImpl(`${url}/v1/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId,
        enrollToken: opts.enrollToken,
        pubkeyFingerprint: identity.fingerprint,
        // Additive (see header): the server stores the PEM to verify audit
        // batch signatures; without it ingest is rejected fail-closed.
        pubkey: identity.publicKey,
      }),
      signal: AbortSignal.timeout(ENROLL_TIMEOUT_MS),
    });
  } catch (e) {
    throw new Error(
      `enroll: cannot reach ${url} (${(e as Error).message}) — check the URL and network. ` +
        `The gateway keeps working local-first without enroll.`,
    );
  }
  if (!res.ok) {
    const detail = (await res.text().catch(() => "")).slice(0, 200);
    throw new Error(
      `enroll: the cloud rejected the enrollment (HTTP ${res.status})${detail ? `: ${detail}` : ""}. ` +
        `The enroll token is one-shot — generate a fresh one and retry.`,
    );
  }
  const body = (await res.json()) as Partial<EnrollResponse>;
  if (
    typeof body.agentSecret !== "string" ||
    !body.agentSecret ||
    typeof body.teamId !== "string" ||
    !body.teamId ||
    typeof body.cloudPubkey !== "string"
  ) {
    throw new Error(
      `enroll: malformed response from ${url} (expected {agentSecret, teamId, cloudPubkey}).`,
    );
  }
  // Fail fast on a bogus cloud pubkey: every team policy verification depends
  // on it being a loadable Ed25519 SPKI key.
  try {
    crypto.createPublicKey(body.cloudPubkey);
    fingerprintOf(body.cloudPubkey);
  } catch {
    throw new Error(`enroll: the cloud returned an unusable cloudPubkey (not a PEM public key).`);
  }

  const cfg: CloudConfig = {
    url,
    agentId,
    teamId: body.teamId,
    agentSecret: body.agentSecret,
    cloudPubkey: body.cloudPubkey,
    enrolledAt: new Date().toISOString(),
  };
  saveCloudConfig(cfg);
  return cfg;
}
