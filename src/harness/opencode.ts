/**
 * OpenCode adapter: project `opencode.json` and user
 * `~/.config/opencode/opencode.json`. OpenCode does NOT use `mcpServers` —
 * its MCP servers live under the `mcp` key with a format that needs real
 * translation (not just a different path):
 *
 *   { "mcp": {
 *       "local-svc":  { "type": "local",  "command": ["bun", "x", "svc"],
 *                       "environment": {"KEY": "..."}, "enabled": true },
 *       "remote-svc": { "type": "remote", "url": "https://…",
 *                       "headers": {"Authorization": "Bearer …"}, "oauth": {...} }
 *   } }
 *
 * Mapping: `type: local` → stdio (command[0] + command.slice(1) as args,
 * `environment` → env); `type: remote` → http (url, headers, `oauth` →
 * oauth2-pending). The gateway entry is written back in OpenCode's own
 * format: a single `mcp.scopegate` entry of `type: local`. Detection falls
 * back to the `opencode` CLI on PATH.
 */
import path from "node:path";
import type {
  HarnessAdapter,
  HarnessConfig,
  MigrateHooks,
  MigratedUpstream,
  OpencodeMcpSpec,
  ScopegateEntry,
} from "./types.js";
import {
  BACKUP_SUFFIX,
  detectFromCandidates,
  homeDir,
  projectDir,
  readJsonConfig,
} from "./util.js";
import {
  fingerprintOf,
  normalizeOpencodeSpec,
  toUpstreamFromNormalized,
} from "./migrate.js";

function candidates(): Array<{ scope: "user" | "project"; path: string }> {
  return [
    { scope: "project", path: path.join(projectDir(), "opencode.json") },
    {
      scope: "user",
      path: path.join(homeDir(), ".config", "opencode", "opencode.json"),
    },
  ];
}

export const opencodeAdapter: HarnessAdapter = {
  id: "opencode",
  candidatePaths: candidates,
  detect() {
    return Promise.resolve(detectFromCandidates("opencode", candidates(), "opencode"));
  },
  readConfig: readJsonConfig,
  listServers(config: HarnessConfig) {
    return Object.entries((config.mcp ?? {}) as Record<string, unknown>);
  },
  isGatewayEntry(entry: unknown) {
    const spec = entry as OpencodeMcpSpec | undefined;
    return (
      spec?.type === "local" &&
      Array.isArray(spec.command) &&
      spec.command[0] === "scopegate"
    );
  },
  toUpstreams(
    name: string,
    entry: unknown,
    hooks: MigrateHooks,
  ): MigratedUpstream[] {
    const normalized = normalizeOpencodeSpec(entry);
    if (!normalized) {
      hooks.warn(
        `'${name}': unrecognized OpenCode MCP entry (expected type: local with ` +
          `command[] or type: remote with url) — skipped.`,
      );
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
      mcp: {
        scopegate: {
          type: "local",
          command: [entry.command, ...entry.args],
          environment: { SCOPEGATE_AGENT_ID: entry.agentId },
          enabled: true,
        },
      },
    };
  },
  backupPath(configPath: string) {
    return configPath + BACKUP_SUFFIX;
  },
};
