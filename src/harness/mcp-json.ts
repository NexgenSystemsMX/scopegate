/**
 * Factory for adapters of harnesses that use the de-facto `mcpServers`
 * format (Claude Code, Kimi Code, Cursor). Only candidate paths and the CLI
 * executable name differ between them; parsing, migration and rewrite are
 * shared here.
 */
import type {
  HarnessAdapter,
  HarnessConfig,
  HarnessId,
  HarnessScope,
  McpServerSpec,
  MigrateHooks,
  MigratedUpstream,
  ScopegateEntry,
} from "./types.js";
import { BACKUP_SUFFIX, detectFromCandidates, readJsonConfig } from "./util.js";
import {
  fingerprintOf,
  normalizeMcpServersSpec,
  toUpstreamFromNormalized,
} from "./migrate.js";

export function makeMcpJsonAdapter(
  id: HarnessId,
  candidates: () => Array<{ scope: HarnessScope; path: string }>,
  executables: string | string[],
): HarnessAdapter {
  return {
    id,
    candidatePaths: candidates,
    detect() {
      return Promise.resolve(detectFromCandidates(id, candidates(), executables));
    },
    readConfig: readJsonConfig,
    listServers(config: HarnessConfig) {
      return Object.entries((config.mcpServers ?? {}) as Record<string, unknown>);
    },
    isGatewayEntry(entry: unknown) {
      return (entry as McpServerSpec | undefined)?.command === "scopegate";
    },
    toUpstreams(
      name: string,
      entry: unknown,
      hooks: MigrateHooks,
    ): MigratedUpstream[] {
      const normalized = normalizeMcpServersSpec(entry);
      if (!normalized) {
        hooks.warn(`'${name}': unrecognized MCP entry (no command/url) — skipped.`);
        return [];
      }
      const upstream = toUpstreamFromNormalized(name, normalized, hooks);
      return upstream
        ? [{ upstream, fingerprint: fingerprintOf(name, normalized) }]
        : [];
    },
    writeGatewayEntry(config: HarnessConfig, entry: ScopegateEntry): HarnessConfig {
      return {
        ...config,
        mcpServers: {
          scopegate: {
            command: entry.command,
            args: entry.args,
            env: { SCOPEGATE_AGENT_ID: entry.agentId },
          },
        },
      };
    },
    backupPath(configPath: string) {
      return configPath + BACKUP_SUFFIX;
    },
  };
}
