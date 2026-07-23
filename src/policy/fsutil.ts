/**
 * Small fs helpers shared by the policy subsystem (grants store, approval
 * queue). Kept private to src/policy — mirrors the atomic-write pattern of
 * config.saveConfig (tmp file + rename, mode 0600).
 */
import fs from "node:fs";

/**
 * Write `data` to `filePath` atomically: a sibling tmp file is written with
 * mode 0600 and then renamed over the target, so a crash mid-write never
 * leaves a truncated state file behind.
 */
export function atomicWriteFileSync(filePath: string, data: string): void {
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}
