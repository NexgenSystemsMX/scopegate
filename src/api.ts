/**
 * M7: embeddable library API — the gateway as a library, not a subprocess.
 *
 *   import { createGatewayServer } from "scopegate";
 *
 * Boots the SAME pieces as the CLI gateway (config, vault, policy engine,
 * upstream proxy, agent-facing MCP server) as in-process objects:
 * no process.exit on invalid policies (throws instead) and no background
 * daemons (policy watcher, cloud sync) unless explicitly opted in.
 *
 * The CLI stays the recommended path for general use; this API targets
 * harnesses that already run in-process and want one gateway per worker.
 * Marked experimental in v0.x — strict semver from v1.
 *
 * HOME: config paths resolve from process.env.SCOPEGATE_HOME at module load.
 * Set it BEFORE importing "scopegate", or pass `home` — a mismatch with the
 * already-resolved home is a loud error, never a silent wrong-home boot.
 */
import path from "node:path";
import {
  SCOPEGATE_DIR,
  loadConfig,
  type ScopeGateConfig,
} from "./config/config.js";
import { Vault } from "./vault/vault.js";
import { Minter } from "./minter/minter.js";
import { PolicyEngine, type PoliciesFile } from "./policy/engine.js";
import { UpstreamProxy } from "./gateway/proxy.js";
import { createAgentServer } from "./gateway/server.js";
import { audit } from "./audit/log.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

export interface EmbeddedGatewayOptions {
  /**
   * ScopeGate home (vault, grants, audit). Must equal the SCOPEGATE_HOME the
   * process resolved at import time — set the env var before importing, or
   * pass it here before any other scopegate import took effect.
   */
  home?: string;
  /** Logical agent identity (grants, audit, approvals). Default: env / config. */
  agentId?: string;
  /** Parsed config — bypasses scopegate.yaml on disk. */
  config?: ScopeGateConfig;
  /** Parsed policies — bypasses policies.yaml on disk. */
  policies?: PoliciesFile;
  /** Connect upstreams now (default true). */
  connect?: boolean;
  /** Hot-reload policies.yaml (default false — no daemons in embedded mode). */
  watchPolicies?: boolean;
  /** Write the gateway_start audit line (default true). */
  auditBoot?: boolean;
}

export interface EmbeddedGateway {
  /** Agent-facing MCP server (management tools + proxied tools). Connect any transport. */
  server: Server;
  proxy: UpstreamProxy;
  policy: PolicyEngine;
  vault: Vault;
  minter: Minter;
  agentId: string;
  /** Stop the policy watcher and close every upstream connection. */
  close(): Promise<void>;
}

export async function createGatewayServer(
  opts: EmbeddedGatewayOptions = {},
): Promise<EmbeddedGateway> {
  if (opts.home) {
    const resolved = path.resolve(opts.home);
    if (SCOPEGATE_DIR !== resolved) {
      throw new Error(
        `createGatewayServer({home: '${resolved}'}) but the scopegate paths already resolved to '${SCOPEGATE_DIR}' — ` +
          `set process.env.SCOPEGATE_HOME='${resolved}' BEFORE importing 'scopegate'.`,
      );
    }
  }
  const cfg = opts.config ?? loadConfig();
  const vault = Vault.open();
  // Fail-closed, but throwing (never process.exit in a library).
  const policy = opts.policies
    ? new PolicyEngine(opts.policies)
    : PolicyEngine.load();
  if (opts.watchPolicies) policy.startWatching();
  const agentId = opts.agentId ?? process.env.SCOPEGATE_AGENT_ID ?? cfg.agentId;
  const minter = new Minter(vault);
  const proxy = new UpstreamProxy(cfg.upstreams, vault, {
    agentId,
    minter,
    attestationDefault: cfg.attestation,
  });
  const status = opts.connect === false ? {} : await proxy.connectAll();
  if (opts.auditBoot !== false) {
    audit(agentId, "gateway_start", { upstreams: status, embedded: true });
  }
  const server = createAgentServer({ cfg, proxy, policy, vault, agentId });
  return {
    server,
    proxy,
    policy,
    vault,
    minter,
    agentId,
    close: async () => {
      policy.stopWatching();
      await proxy.closeAll();
    },
  };
}

export type {
  ScopeGateConfig,
  PoliciesFile,
  UpstreamProxy,
  PolicyEngine,
  Vault,
  Minter,
  Server,
};
