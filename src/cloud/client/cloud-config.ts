/**
 * ScopeGate Cloud — gateway-side config (EPIC-10, management plane).
 *
 * `~/.scopegate/cloud.json` is written by a successful enroll (see enroll.ts)
 * and is the SINGLE switch that turns cloud sync on: if the file does not
 * exist the gateway behaves exactly like the OSS build (local-first, §3 of
 * the product plan). The file holds METADATA ONLY — the enroll token and
 * agent secret authenticate the gateway against the control plane; no vault
 * secret is ever stored here or sent to the cloud.
 *
 * Shape (v1):
 *   { url, agentId, teamId, agentSecret, cloudPubkey, enrolledAt }
 *   - url:         base URL of the cloud API (no trailing slash).
 *   - agentId:     this gateway's agent identity, as enrolled.
 *   - teamId:      team the gateway is bound to.
 *   - agentSecret: bearer token issued at enroll (gateway → cloud auth).
 *   - cloudPubkey: PEM SPKI Ed25519 public key of the cloud signer; every
 *                  team policy pulled from the cloud is verified against it.
 *   - enrolledAt:  ISO timestamp of the enroll.
 */
import fs from "node:fs";
import path from "node:path";
import { SCOPEGATE_DIR, ensureDir } from "../../config/config.js";
import { atomicWriteFileSync } from "../../policy/fsutil.js";

export const CLOUD_CONFIG_PATH = path.join(SCOPEGATE_DIR, "cloud.json");
/** Signed team policy cache (survives cloud outages — local-first). */
export const TEAM_POLICY_CACHE_PATH = path.join(SCOPEGATE_DIR, "team-policy.json");
/** Audit exporter checkpoint (last exported seq). */
export const AUDIT_EXPORT_CURSOR_PATH = path.join(
  SCOPEGATE_DIR,
  "audit-export-cursor.json",
);
/** Fleet-revocation state: presence of this file denies the agent (fail-closed). */
export const CLOUD_REVOKED_PATH = path.join(SCOPEGATE_DIR, "cloud-revoked.json");

export interface CloudConfig {
  url: string;
  agentId: string;
  teamId: string;
  agentSecret: string;
  cloudPubkey: string;
  enrolledAt: string;
}

/** Strip trailing slashes so endpoint joins are unambiguous. */
export function normalizeCloudUrl(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

/** True when this gateway is enrolled (cloud.json exists and parses). */
export function cloudConfigured(): boolean {
  return loadCloudConfig() !== null;
}

/**
 * Load cloud.json. A MISSING file is the normal local-first case → null.
 * A CORRUPT file also yields null (cloud sync stays off, the gateway keeps
 * working locally) plus a one-line operator warning on stderr.
 */
export function loadCloudConfig(): CloudConfig | null {
  let raw: string;
  try {
    raw = fs.readFileSync(CLOUD_CONFIG_PATH, "utf8");
  } catch {
    return null; // not enrolled — the common case
  }
  try {
    const c = JSON.parse(raw) as Partial<CloudConfig>;
    if (
      typeof c.url !== "string" ||
      !c.url.trim() ||
      typeof c.agentId !== "string" ||
      !c.agentId ||
      typeof c.teamId !== "string" ||
      !c.teamId ||
      typeof c.agentSecret !== "string" ||
      !c.agentSecret ||
      typeof c.cloudPubkey !== "string" ||
      !c.cloudPubkey.includes("BEGIN PUBLIC KEY") ||
      typeof c.enrolledAt !== "string"
    ) {
      throw new Error("missing or invalid fields");
    }
    return {
      url: normalizeCloudUrl(c.url),
      agentId: c.agentId,
      teamId: c.teamId,
      agentSecret: c.agentSecret,
      cloudPubkey: c.cloudPubkey,
      enrolledAt: c.enrolledAt,
    };
  } catch (e) {
    console.error(
      `[scopegate cloud] warn: ${CLOUD_CONFIG_PATH} is corrupt (${(e as Error).message}) — ` +
        `cloud sync disabled; the gateway keeps running local-first. Re-enroll to fix.`,
    );
    return null;
  }
}

/** Persist cloud.json atomically (tmp + rename, mode 0600). */
export function saveCloudConfig(cfg: CloudConfig): void {
  ensureDir();
  atomicWriteFileSync(
    CLOUD_CONFIG_PATH,
    JSON.stringify({ ...cfg, url: normalizeCloudUrl(cfg.url) }, null, 2) + "\n",
  );
}
