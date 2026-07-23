/**
 * Team policy distribution (EPIC-10, H10.2/H10.5).
 *
 * The human admin publishes a team policy (PUT /v1/admin/policy); the cloud
 * SIGNS it with the cloud identity key and versions it (append-only history);
 * gateways pull the latest version (GET /v1/policy) and verify the signature
 * against the cloudPubkey they received at enroll. A control plane (or the
 * network in front of it) therefore cannot inject a policy the team did not
 * publish — the gateway-side cache only ever holds cloud-signed documents.
 *
 * Canonicalization the signature commits to (FROZEN — the CLOUD-SYNC client
 * verifies against this exact serialization; do not change without a schema
 * bump):
 *   policyCanonical(p) = JSON.stringify({ teamId, version, yaml, signedAt })
 *   — compact separators, that exact key order, UTF-8.
 * `verifyPolicySignature` is exported so the gateway client (and tests) can
 * verify a pulled policy with zero guesswork.
 */
import { verifyCanonical } from "../../audit/identity.js";
import { signWithCloudKey, type CloudIdentity } from "./keys.js";
import {
  asNonEmptyString,
  badRequest,
  isRecord,
  notFound,
  type PolicyVersion,
} from "./model.js";
import type { Store } from "./store.js";

export function policyCanonical(
  p: Pick<PolicyVersion, "teamId" | "version" | "yaml" | "signedAt">,
): string {
  return JSON.stringify({
    teamId: p.teamId,
    version: p.version,
    yaml: p.yaml,
    signedAt: p.signedAt,
  });
}

/** Verify a pulled policy against the cloud pubkey (gateway-side check). */
export function verifyPolicySignature(
  cloudPubkeyPem: string,
  policy: Pick<PolicyVersion, "teamId" | "version" | "yaml" | "signedAt" | "signature">,
): boolean {
  return verifyCanonical(cloudPubkeyPem, policyCanonical(policy), policy.signature);
}

/**
 * Refuse to sign a policy document that appears to embed a raw secret.
 *
 * HIGH-PRECISION guard, deliberately narrower than the audit-ingest one:
 * a policy yaml legitimately contains long glob patterns and path-like
 * strings, so the blunt `looksLikeSecret` heuristics (length > 40, 32+ char
 * base64 blob) would false-positive here. Instead only unambiguous secret
 * shapes are rejected: well-known token prefixes, JWTs (eyJ…) and PEM
 * private-key blocks. Trade-off documented: a random high-entropy blob
 * pasted into a policy is NOT caught here — the strict guard is the audit
 * ingest one, which rejects anything payload-like before it is stored.
 */
export function assertPolicyHasNoSecrets(yaml: string): void {
  const SECRET_LINE = /(sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[bap]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|BEGIN [A-Z ]*PRIVATE KEY)/;
  const lines = yaml.split("\n");
  for (let i = 0; i < lines.length; i++) {
    // Comments are NOT stripped: a secret pasted into a YAML comment is
    // stored and distributed to gateways all the same.
    if (SECRET_LINE.test(lines[i])) {
      throw badRequest(
        `policy yaml line ${i + 1} looks like it contains a raw secret — ` +
          `policies reference secrets by vault ref, never by value`,
        "secret_like_policy_content",
      );
    }
  }
}

export function putPolicy(
  store: Store,
  cloudIdentity: CloudIdentity,
  body: unknown,
): PolicyVersion {
  if (!isRecord(body)) throw badRequest("body must be a JSON object");
  const teamId = asNonEmptyString(body.teamId);
  const yaml = typeof body.yaml === "string" ? body.yaml : null;
  if (!teamId) throw badRequest("teamId is required");
  if (yaml === null || yaml.trim().length === 0) throw badRequest("yaml is required");
  if (yaml.length > 256 * 1024) throw badRequest("policy yaml too large (max 256 KiB)");
  if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);
  assertPolicyHasNoSecrets(yaml);

  const latest = store.latestPolicy(teamId);
  const policy: PolicyVersion = {
    teamId,
    version: (latest?.version ?? 0) + 1,
    yaml,
    signature: "", // filled below — the signature commits to all other fields
    signedAt: new Date().toISOString(),
  };
  policy.signature = signWithCloudKey(cloudIdentity, policyCanonical(policy));
  store.addPolicyVersion(policy);
  return policy;
}

export function getPolicy(store: Store, teamId: string): PolicyVersion {
  const policy = store.latestPolicy(teamId);
  if (!policy) {
    throw notFound(
      `no policy published for team ${teamId} — the gateway keeps operating ` +
        `with its local policies.yaml (local-first)`,
      "no_team_policy",
    );
  }
  return policy;
}
