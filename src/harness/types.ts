/**
 * Harness adapter model (EPIC-06): one adapter per supported coding-agent
 * harness. `scopegate init` detects installs, migrates their MCP servers
 * behind the gateway and rewrites each config so ScopeGate is the ONLY MCP
 * entry point.
 *
 * Detection matrix (config paths × format) — keep in sync with README:
 *
 * | Harness     | Config paths                                                   | MCP format |
 * |-------------|----------------------------------------------------------------|------------|
 * | claude-code | project: .mcp.json · user: ~/.claude.json                      | mcpServers |
 * | kimi-code   | project: .kimi-code/mcp.json · user: ~/.kimi-code/mcp.json     | mcpServers |
 * |             |   (or $KIMI_CODE_HOME/mcp.json)                                | +transport:"sse", bearerTokenEnvVar, enabledTools |
 * | cursor      | project: .cursor/mcp.json · user: ~/.cursor/mcp.json           | mcpServers |
 * | opencode    | project: opencode.json · user: ~/.config/opencode/opencode.json | mcp (type: local/remote) |
 *
 * Detection rule: existing config files are ALWAYS migrated (a leftover
 * config still holds secrets). When no config file exists but the harness
 * CLI is found on PATH, the user-level candidate is returned with
 * `exists: false` so init can create a fresh config there.
 */
import type { UpstreamConfig } from "../config/config.js";
import type { Vault } from "../vault/vault.js";

/** Harnesses supported by `scopegate init`. */
export type HarnessId = "claude-code" | "kimi-code" | "cursor" | "opencode";

/** Project-level config (cwd of the agent) vs user-level config ($HOME). */
export type HarnessScope = "user" | "project";

/** A located harness config file (existing on disk or a candidate to create). */
export interface HarnessInstall {
  adapterId: HarnessId;
  scope: HarnessScope;
  /** Absolute path of the harness config file. */
  path: string;
  /** Whether the file exists on disk right now. */
  exists: boolean;
}

/** Raw parsed harness config file (a JSON object). */
export type HarnessConfig = Record<string, unknown>;

/**
 * Shape of an MCP server entry in the `mcpServers` format shared by
 * Claude Code, Kimi Code and Cursor.
 */
export interface McpServerSpec {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  /** Claude Code uses `type: "stdio"|"sse"|"http"`; Kimi Code uses `transport: "sse"`. */
  type?: string;
  transport?: string;
  headers?: Record<string, string>;
  /** Kimi Code: NAME of an env var holding the bearer token (resolved at init time). */
  bearerTokenEnvVar?: string;
  enabled?: boolean;
  /** Kimi Code tool allowlist → UpstreamConfig.exposeTools. */
  enabledTools?: string[];
  disabledTools?: string[];
}

/** Shape of an OpenCode `mcp` entry: `type: "local"` or `type: "remote"`. */
export interface OpencodeMcpSpec {
  type?: string;
  /** local: full argv (command[0] + args). */
  command?: string[];
  /** local: env vars. */
  environment?: Record<string, string>;
  /** remote: endpoint URL. */
  url?: string;
  /** remote: static headers. */
  headers?: Record<string, string>;
  /** remote: OAuth flow config (object) or explicitly disabled (false). */
  oauth?: unknown;
  enabled?: boolean;
  timeout?: number;
}

/** The surface of Vault that migration actually needs (real or dry-run). */
export type VaultLike = Pick<Vault, "set" | "has" | "listRefs">;

/**
 * Gateway entry written into harness configs as their only MCP server.
 * `agentId` MUST match scopegate.yaml's agentId — it travels to the gateway
 * process as SCOPEGATE_AGENT_ID so audit/policy identity is coherent.
 */
export interface ScopegateEntry {
  command: string; // "scopegate"
  args: string[]; // ["start"]
  agentId: string;
}

/** Side channels the migration core needs from the caller. */
export interface MigrateHooks {
  vault: VaultLike;
  /** Non-fatal, user-visible warning (printed and collected). */
  warn(msg: string): void;
}

/** One migrated server: the gateway upstream plus its migration fingerprint. */
export interface MigratedUpstream {
  upstream: UpstreamConfig;
  /**
   * SHA-256 over the NORMALIZED harness entry (see fingerprintOf in
   * migrate.ts). Persisted in scopegate.yaml; a changed fingerprint on
   * re-run means the harness entry changed and the upstream is re-migrated.
   */
  fingerprint: string;
}

export interface HarnessAdapter {
  readonly id: HarnessId;
  /**
   * All config paths this harness may use, in migration order
   * (project first, then user — project wins upstream name collisions,
   * mirroring harness precedence).
   */
  candidatePaths(): Array<{ scope: HarnessScope; path: string }>;
  /**
   * Locate installs: every existing candidate path, or — when none exists
   * but the harness CLI is on PATH — the user-level candidate with
   * `exists: false`.
   */
  detect(): Promise<HarnessInstall[]>;
  /** Parse a config file; returns {} when the file does not exist; throws on invalid JSON. */
  readConfig(path: string): HarnessConfig;
  /** [name, rawEntry] pairs of the harness's MCP server map. */
  listServers(config: HarnessConfig): Array<[string, unknown]>;
  /** True when the entry is the gateway entry written by a previous init. */
  isGatewayEntry(entry: unknown): boolean;
  /**
   * Convert one harness entry into gateway upstream(s) — extracting every
   * secret into the vault. Empty array when the entry is not migratable.
   */
  toUpstreams(name: string, entry: unknown, hooks: MigrateHooks): MigratedUpstream[];
  /** Return a copy of `config` whose ONLY MCP entry is the gateway. */
  writeGatewayEntry(config: HarnessConfig, entry: ScopegateEntry): HarnessConfig;
  /** Immutable backup path for a config file (keep-first, never overwritten). */
  backupPath(configPath: string): string;
}
