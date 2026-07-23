/**
 * Registry of the supported harness adapters (EPIC-06) and lookup by id
 * (used by `init --harness <id>`).
 */
import type { HarnessAdapter, HarnessId } from "./types.js";
import { claudeCodeAdapter } from "./claude-code.js";
import { kimiCodeAdapter } from "./kimi-code.js";
import { cursorAdapter } from "./cursor.js";
import { opencodeAdapter } from "./opencode.js";

export const ALL_ADAPTERS: HarnessAdapter[] = [
  claudeCodeAdapter,
  kimiCodeAdapter,
  cursorAdapter,
  opencodeAdapter,
];

export const HARNESS_IDS: HarnessId[] = ALL_ADAPTERS.map((a) => a.id);

/** Look up an adapter by id; throws an actionable error on an unknown id. */
export function getAdapter(id: string): HarnessAdapter {
  const found = ALL_ADAPTERS.find((a) => a.id === id);
  if (!found) {
    throw new Error(
      `Unknown harness '${id}'. Valid values: ${HARNESS_IDS.join(", ")}.`,
    );
  }
  return found;
}

export type {
  HarnessAdapter,
  HarnessConfig,
  HarnessId,
  HarnessInstall,
  HarnessScope,
  McpServerSpec,
  MigrateHooks,
  MigratedUpstream,
  OpencodeMcpSpec,
  ScopegateEntry,
  VaultLike,
} from "./types.js";
