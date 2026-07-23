/**
 * ScopeGate Cloud — team policy sync (EPIC-10).
 *
 * Loop: poll GET /v1/policy?teamId= every SCOPEGATE_CLOUD_SYNC_INTERVAL_MS
 * (default 60 s), verify the Ed25519 signature with the enrolled cloud
 * pubkey, schema-validate the YAML with the SAME validator as local
 * policies.yaml, cache it signed in ~/.scopegate/team-policy.json and apply
 * it to the PolicyEngine as a restrictive-intersection layer.
 *
 * LOCAL-FIRST guarantees:
 *   - Cloud down / network error → the last verified cache stays applied.
 *   - No cache (never synced) or invalid cache (tampered/corrupt) → the
 *     gateway runs LOCAL-ONLY, exactly like the OSS build, with a warn.
 *   - A bad payload (bad signature, invalid YAML, lower version) is rejected
 *     and the last-good policy stays in force — the sync path can never
 *     loosen policy.
 *
 * SIGNATURE CANONICALIZATION (FROZEN with AGENTE CLOUD-CORE — the server
 * signs exactly this serialization, see src/cloud/server/policies.ts
 * `policyCanonical`; the two sides must change only together):
 *   canonical = JSON.stringify({teamId, version, yaml, signedAt})
 *   — keys in that exact order, compact separators, UTF-8; signature is the
 *   identity.ts "ed25519:<base64>" format over those bytes.
 *
 * Frozen wire contract:
 *   GET /v1/policy?teamId=<id>  → 200 {teamId, version, yaml, signature, signedAt}
 */
import fs from "node:fs";
import YAML from "yaml";
import { verifyCanonical } from "../../audit/identity.js";
import {
  validatePoliciesFile,
  type PoliciesFile,
  type PolicyEngine,
  type TeamPolicyMeta,
} from "../../policy/engine.js";
import { TEAM_POLICY_CACHE_PATH } from "./cloud-config.js";
import { atomicWriteFileSync } from "../../policy/fsutil.js";

export const DEFAULT_POLICY_SYNC_INTERVAL_MS = 60_000;

/** What the cloud returns on GET /v1/policy. */
export interface TeamPolicyPayload {
  teamId: string;
  version: number;
  yaml: string;
  signature: string; // "ed25519:<base64>" over canonicalTeamPolicyPayload
  signedAt: string; // ISO
}

/** On-disk cache shape (team-policy.json). signedAt/teamId are needed to re-verify. */
export interface TeamPolicyCache {
  teamId: string;
  version: number;
  yaml: string;
  signature: string;
  signedAt: string;
  fetchedAt: string;
}

/**
 * The exact byte serialization the cloud signs (FROZEN with the server's
 * policyCanonical — do not change the key order without a coordinated
 * contract bump; verification would silently break).
 */
export function canonicalTeamPolicyPayload(p: {
  teamId: string;
  version: number;
  yaml: string;
  signedAt: string;
}): string {
  return JSON.stringify({
    teamId: p.teamId,
    version: p.version,
    yaml: p.yaml,
    signedAt: p.signedAt,
  });
}

/** Verify the payload's Ed25519 signature against the enrolled cloud pubkey. */
export function verifyTeamPolicySignature(
  cloudPubkey: string,
  p: TeamPolicyPayload,
): boolean {
  return verifyCanonical(cloudPubkey, canonicalTeamPolicyPayload(p), p.signature);
}

function parseAndValidate(p: TeamPolicyCache): PoliciesFile | null {
  try {
    return validatePoliciesFile(YAML.parse(p.yaml));
  } catch {
    return null;
  }
}

/**
 * Load the signed cache at gateway boot. Returns the validated policy + meta,
 * or null (local-only fallback) when the cache is missing, corrupt, fails
 * signature verification or fails schema validation. Never throws.
 */
export function loadVerifiedTeamPolicyCache(
  cloudPubkey: string,
): { policies: PoliciesFile; meta: TeamPolicyMeta } | null {
  let cache: TeamPolicyCache;
  try {
    cache = JSON.parse(fs.readFileSync(TEAM_POLICY_CACHE_PATH, "utf8")) as TeamPolicyCache;
  } catch {
    return null; // no cache (never synced) — local-first default
  }
  if (
    typeof cache?.teamId !== "string" ||
    typeof cache?.version !== "number" ||
    typeof cache?.yaml !== "string" ||
    typeof cache?.signature !== "string" ||
    typeof cache?.signedAt !== "string" ||
    typeof cache?.fetchedAt !== "string"
  ) {
    console.error(
      `[scopegate cloud] warn: ${TEAM_POLICY_CACHE_PATH} is malformed — ignoring it (local-only policy)`,
    );
    return null;
  }
  if (!verifyTeamPolicySignature(cloudPubkey, cache)) {
    console.error(
      `[scopegate cloud] warn: ${TEAM_POLICY_CACHE_PATH} failed signature verification — ` +
        `ignoring it (local-only policy). The cache may have been tampered with.`,
    );
    return null;
  }
  const policies = parseAndValidate(cache);
  if (!policies) {
    console.error(
      `[scopegate cloud] warn: cached team policy fails schema validation — ignoring it (local-only policy)`,
    );
    return null;
  }
  return { policies, meta: { version: cache.version, fetchedAt: cache.fetchedAt } };
}

export interface PolicySyncDeps {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface PolicySyncResult {
  /** true when a NEW version was applied to the engine. */
  applied: boolean;
  version?: number;
}

/**
 * One sync tick: fetch → verify → validate → (version check) → cache + apply.
 * Throws on transport/HTTP errors (the loop turns that into backoff); any
 * payload-level problem is a clean rejection, never a crash and never a
 * policy change.
 */
export async function syncTeamPolicyOnce(
  cfg: { url: string; teamId: string; agentSecret: string; cloudPubkey: string },
  engine: PolicyEngine,
  deps: PolicySyncDeps = {},
): Promise<PolicySyncResult> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const res = await fetchImpl(
    `${cfg.url}/v1/policy?teamId=${encodeURIComponent(cfg.teamId)}`,
    {
      headers: { authorization: `Bearer ${cfg.agentSecret}` },
      signal: AbortSignal.timeout(deps.timeoutMs ?? 10_000),
    },
  );
  if (!res.ok) {
    throw new Error(`policy sync failed (HTTP ${res.status})`);
  }
  const payload = (await res.json()) as Partial<TeamPolicyPayload>;
  if (
    typeof payload.version !== "number" ||
    typeof payload.yaml !== "string" ||
    typeof payload.signature !== "string" ||
    typeof payload.signedAt !== "string"
  ) {
    console.error("[scopegate cloud] warn: malformed policy payload — keeping last-good policy");
    return { applied: false };
  }
  // The signed canonical commits to teamId: a payload naming a DIFFERENT
  // team than the enrolled one is a mix-up/attack — reject before verifying.
  if (typeof payload.teamId === "string" && payload.teamId !== cfg.teamId) {
    console.error(
      `[scopegate cloud] warn: policy payload names team '${payload.teamId}' but this gateway is enrolled in '${cfg.teamId}' — rejected`,
    );
    return { applied: false };
  }
  const p: TeamPolicyPayload = { ...(payload as TeamPolicyPayload), teamId: cfg.teamId };
  if (!verifyTeamPolicySignature(cfg.cloudPubkey, p)) {
    console.error(
      "[scopegate cloud] warn: team policy signature INVALID — rejected, keeping last-good policy",
    );
    return { applied: false };
  }
  let policies: PoliciesFile;
  try {
    policies = validatePoliciesFile(YAML.parse(p.yaml));
  } catch (e) {
    console.error(
      `[scopegate cloud] warn: team policy fails schema validation (${(e as Error).message}) — rejected, keeping last-good policy`,
    );
    return { applied: false };
  }
  // Anti-rollback: the server issues monotonically increasing versions (an
  // admin revert is a NEW version with old content), so an older/equal
  // version than the one in force is never applied.
  const current = engine.teamPolicyInfo();
  if (current && p.version <= current.version) {
    return { applied: false, version: current.version };
  }
  const cache: TeamPolicyCache = {
    teamId: cfg.teamId,
    version: p.version,
    yaml: p.yaml,
    signature: p.signature,
    signedAt: p.signedAt,
    fetchedAt: new Date().toISOString(),
  };
  atomicWriteFileSync(TEAM_POLICY_CACHE_PATH, JSON.stringify(cache, null, 2) + "\n");
  engine.applyTeamPolicy(policies, { version: p.version, fetchedAt: cache.fetchedAt });
  console.error(`[scopegate cloud] info: team policy v${p.version} applied (restrictive intersection)`);
  return { applied: true, version: p.version };
}
