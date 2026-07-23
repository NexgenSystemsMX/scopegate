/**
 * Shared helpers for harness adapters: candidate detection, PATH probing,
 * config reading and the secret-recognition regexes.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { HarnessConfig, HarnessId, HarnessInstall, HarnessScope } from "./types.js";

/** Suffix of the immutable pre-migration backup (keep-first, never overwritten). */
export const BACKUP_SUFFIX = ".pre-scopegate.bak";

/** Env var names that look like secrets (stdio upstreams). */
export const SECRETY_ENV = /(KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AUTH)/i;

/** Header names that look like they carry credentials (http upstreams). */
export const AUTHY_HEADER = /authorization|api-?key|token|secret/i;

/** User home — read at call time so tests/e2e can override HOME/USERPROFILE. */
export function homeDir(): string {
  return os.homedir();
}

/**
 * Project-level dir for project-scoped configs. SCOPEGATE_PROJECT_DIR is an
 * explicit override seam for tests/e2e (they cannot chdir safely); otherwise
 * the current working directory, exactly as the harness sees it.
 */
export function projectDir(): string {
  return process.env.SCOPEGATE_PROJECT_DIR ?? process.cwd();
}

/** Read + parse a JSON harness config; {} when missing; throws on invalid JSON. */
export function readJsonConfig(configPath: string): HarnessConfig {
  if (!fs.existsSync(configPath)) return {};
  const parsed: unknown = JSON.parse(fs.readFileSync(configPath, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`expected a JSON object at ${configPath}`);
  }
  return parsed as HarnessConfig;
}

/** True when an executable (or its Windows variants) is found on PATH. */
export function executableOnPath(name: string): boolean {
  const dirs = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const exts =
    process.platform === "win32"
      ? ["", ...(process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.PS1").split(";")]
      : [""];
  for (const dir of dirs) {
    for (const ext of exts) {
      try {
        fs.accessSync(path.join(dir, name + ext), fs.constants.X_OK);
        return true;
      } catch {
        /* keep looking */
      }
    }
  }
  return false;
}

/**
 * Shared detection rule (see the matrix in types.ts): every candidate that
 * exists on disk is migrated; when none exists but the harness CLI is on
 * PATH, offer the LAST candidate (user-level by convention) as the file to
 * create. Otherwise the harness is considered absent.
 */
export function detectFromCandidates(
  adapterId: HarnessId,
  candidates: Array<{ scope: HarnessScope; path: string }>,
  executables: string | string[],
): HarnessInstall[] {
  const found = candidates
    .map((c) => ({ adapterId, scope: c.scope, path: c.path, exists: fs.existsSync(c.path) }))
    .filter((i) => i.exists);
  if (found.length > 0) return found;
  const names = Array.isArray(executables) ? executables : [executables];
  if (names.some(executableOnPath)) {
    const primary = candidates[candidates.length - 1];
    return [{ adapterId, scope: primary.scope, path: primary.path, exists: false }];
  }
  return [];
}
