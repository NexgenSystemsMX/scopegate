/**
 * Local-first re-authorization signal (EPIC-03 H3.5). When an upstream's
 * refresh grant dies, the daemon records it in
 * `~/.scopegate/reauth-required.json` (mode 0600, single entry — the EPIC's
 * frozen shape) so that:
 *
 *   - the human sees it out-of-band (file + gateway stderr),
 *   - `scopegate_diagnose` can return the literal instruction
 *     `run in your terminal: scopegate auth login <upstream>`,
 *   - a restarted gateway remembers the upstream still needs re-auth,
 *   - `scopegate auth login` (a SEPARATE process) signals completion simply by
 *     deleting the file — the daemon notices on its next touch and resumes.
 */
import fs from "node:fs";
import { REAUTH_REQUIRED_PATH, ensureDir } from "../config/config.js";

export interface ReauthRequired {
  upstream: string;
  reason: string;
  since: string; // ISO 8601
}

export function readReauthRequired(): ReauthRequired | null {
  try {
    const raw = fs.readFileSync(REAUTH_REQUIRED_PATH, "utf8");
    const p = JSON.parse(raw) as Record<string, unknown>;
    if (typeof p.upstream !== "string" || p.upstream.length === 0) return null;
    return {
      upstream: p.upstream,
      reason: typeof p.reason === "string" ? p.reason : "unknown",
      since: typeof p.since === "string" ? p.since : new Date(0).toISOString(),
    };
  } catch {
    return null; // absent or corrupt — nothing required
  }
}

export function writeReauthRequired(entry: ReauthRequired): void {
  ensureDir();
  const tmp = REAUTH_REQUIRED_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(entry, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, REAUTH_REQUIRED_PATH);
}

/** Delete the signal only when it names this upstream (login completes it). */
export function clearReauthRequired(upstream: string): void {
  const current = readReauthRequired();
  if (!current || current.upstream !== upstream) return;
  try {
    fs.unlinkSync(REAUTH_REQUIRED_PATH);
  } catch {
    /* already gone */
  }
}
