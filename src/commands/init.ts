/**
 * `scopegate init` — designed to be executed BY THE AGENT, unattended:
 *   idempotent, non-interactive, exit code 0 on success.
 *
 * What it does:
 *   1. Creates ~/.scopegate, master key, empty vault, default policies.yaml
 *      and the Ed25519 agent identity that signs the audit log (keep-first)
 *   2. Detects harness installs via the adapters in src/harness/
 *      (Claude Code, Kimi Code, Cursor, OpenCode — see the matrix in
 *      src/harness/types.ts)
 *   3. MIGRATES existing MCP servers behind the gateway:
 *        - env vars and auth headers that look like secrets → moved into the
 *          vault, replaced by secretRefs (plaintext leaves the configs)
 *        - bearerTokenEnvVar / OAuth entries → oauth2-PENDING auth with an
 *          explicit WARN (never silently degraded to auth none)
 *   4. Rewrites each harness config so its ONLY MCP server is scopegate,
 *      carrying SCOPEGATE_AGENT_ID = scopegate.yaml's agentId so the
 *      gateway's audit/policy identity is coherent (a backup of the
 *      original is kept next to it)
 *
 * Options (wired by cli.ts):
 *   --dry-run          pure inspection: creates and writes nothing
 *   --harness <id>     restrict detection/migration to one harness
 *                      (claude-code | kimi-code | cursor | opencode)
 *
 * Hardening (EPIC-01 H5, EPIC-06 H-06.5/H-06.6):
 *   - `--dry-run` is PURE INSPECTION: it creates nothing — no ~/.scopegate,
 *     no master key, no vault file, no config, no backups — and writes
 *     nothing. The real Vault is never opened because `Vault.open()` creates
 *     the directory and master key as a side effect; an in-memory stand-in
 *     (DryRunVault) records which secret refs WOULD be deposited instead.
 *   - Backup is KEEP-FIRST: `<config>.pre-scopegate.bak` is written once and
 *     never overwritten, so the ORIGINAL pre-migration config always remains
 *     the rollback target even across repeated `init` runs.
 *   - Rollback: `restoreFromBackup` (re-exported from src/harness/migrate.ts)
 *     restores every harness config from its backup, byte-verified by hash.
 *   - Idempotency is fingerprint-driven: each migrated server's spec hash is
 *     persisted in scopegate.yaml (`migrations` key), so re-running init is
 *     a verifiable no-op — the rewrite is byte-compared and skipped when
 *     nothing changed.
 *   - Post-rewrite validation: the rewritten harness config is re-parsed and
 *     must expose the scopegate gateway entry; on failure the backup is
 *     restored automatically (or the incomplete new file removed) and init
 *     aborts with an actionable error.
 *   - A pre-existing MCP entry named `scopegate` that was not written by a
 *     previous init is an actionable error, not a silent overwrite.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import YAML from "yaml";
import {
  CONFIG_PATH,
  POLICIES_PATH,
  ensureDir,
  saveConfig,
  configExists,
  loadConfig,
  type ScopeGateConfig,
} from "../config/config.js";
import { Vault } from "../vault/vault.js";
import {
  IDENTITY_PATH,
  createIdentity,
  identityExists,
  loadIdentity,
} from "../audit/identity.js";
import { ALL_ADAPTERS, getAdapter } from "../harness/index.js";
import type { HarnessInstall, VaultLike } from "../harness/types.js";
import { migrateInstall } from "../harness/migrate.js";
import { projectDir } from "../harness/util.js";

// Re-exports kept for backwards compatibility (and for the future rollback
// CLI command, which the orchestrator wires in cli.ts).
export type { McpServerSpec, VaultLike } from "../harness/types.js";
export { toUpstream, restoreFromBackup } from "../harness/migrate.js";

/**
 * In-memory vault stand-in for `--dry-run`: records which refs WOULD be
 * deposited without any disk I/O. The real `Vault.open()` must not run in
 * dry-run because it creates ~/.scopegate and master.key as side effects.
 */
class DryRunVault implements VaultLike {
  private refs = new Set<string>();
  set(ref: string, _value: string): void {
    this.refs.add(ref);
  }
  has(ref: string): boolean {
    return this.refs.has(ref);
  }
  listRefs(): string[] {
    return [...this.refs].sort();
  }
}

export interface InitOptions {
  dryRun?: boolean;
  /** Restrict migration to one harness id (see HARNESS_IDS). */
  harness?: string;
}

export async function runInit(opts: InitOptions = {}): Promise<void> {
  const dryRun = opts.dryRun ?? false;
  if (dryRun) {
    log("[dry-run] inspection only — nothing will be created, modified or deleted.");
  } else {
    ensureDir();
  }
  // In dry-run the real vault is never opened (see DryRunVault above).
  const vault: VaultLike = dryRun ? new DryRunVault() : Vault.open();

  // 1. Agent identity (Ed25519 keypair signing every audit event). Idempotent
  //    and KEEP-FIRST: an existing identity is never regenerated, so past
  //    signatures stay verifiable. Pure inspection under --dry-run.
  ensureAgentIdentity(dryRun);

  // 2. Base config (idempotent). Reading is always side-effect free.
  let cfg: ScopeGateConfig;
  if (configExists()) {
    cfg = loadConfig();
    log(`config exists at ${CONFIG_PATH} — keeping it (idempotent).`);
  } else {
    cfg = {
      version: 1,
      agentId: `agent-${os.userInfo().username}-${crypto.randomBytes(3).toString("hex")}`,
      upstreams: [],
    };
    if (dryRun) {
      log(`[dry-run] would create config at ${CONFIG_PATH} (agentId '${cfg.agentId}')`);
    }
  }

  // 3. Default policies (safe: only scopegate self-management is open)
  if (!fs.existsSync(POLICIES_PATH)) {
    if (dryRun) {
      log(`[dry-run] would write default policies → ${POLICIES_PATH}`);
    } else {
      fs.writeFileSync(POLICIES_PATH, DEFAULT_POLICIES(cfg.agentId), {
        mode: 0o600,
      });
      log(`wrote default policies → ${POLICIES_PATH}`);
    }
  }

  // 4. Detect harness installs via adapters (--harness restricts the set;
  //    an unknown id is an actionable error from getAdapter).
  const adapters = opts.harness ? [getAdapter(opts.harness)] : ALL_ADAPTERS;
  let installs: HarnessInstall[] = [];
  for (const adapter of adapters) {
    installs.push(...(await adapter.detect()));
  }
  if (installs.length > 0) {
    log(
      `detected ${installs.length} harness config(s): ${installs
        .map((i) => `${i.adapterId} (${i.scope}: ${i.path}${i.exists ? "" : ", new"})`)
        .join("; ")}`,
    );
  }
  if (installs.length === 0) {
    log("no harness config found; writing a project .mcp.json with scopegate.");
    installs = [
      {
        adapterId: "claude-code",
        scope: "project",
        path: path.join(projectDir(), ".mcp.json"),
        exists: false,
      },
    ];
  }

  // 5. Migrate + rewrite each harness config
  const warnings: string[] = [];
  const warn = (msg: string): void => {
    warnings.push(msg);
    log(`WARN: ${msg}`);
  };
  for (const install of installs) {
    migrateInstall(getAdapter(install.adapterId), install, cfg, vault, {
      dryRun,
      log,
      warn,
    });
  }

  if (dryRun) {
    const refs = vault.listRefs();
    log(`[dry-run] would save config → ${CONFIG_PATH}`);
    if (refs.length > 0) {
      log(`[dry-run] would deposit ${refs.length} secret(s) into the vault: [${refs.join(", ")}]`);
    }
    log(
      `[dry-run] upstreams that would sit behind the gateway: [${cfg.upstreams
        .map((u) => u.name)
        .join(", ")}]`,
    );
    log("[dry-run] done — no changes were made.");
    return;
  }

  saveConfig(cfg);
  log(`config saved → ${CONFIG_PATH}`);
  log(
    `DONE. Upstreams behind the gateway: [${cfg.upstreams
      .map((u) => u.name)
      .join(", ")}]`,
  );
  if (warnings.length > 0) {
    log(`${warnings.length} warning(s) above need human attention (auth pending or partial migration).`);
  }
  log(
    "Next: restart your agent session. All tools now flow through scopegate; secrets live only in the vault.",
  );
}

/**
 * Step 1 of init: provision the Ed25519 identity that signs the audit log.
 * Keep-first, mirroring the backup policy: an existing identity.json is NEVER
 * regenerated — rotating it would invalidate the signature of every past
 * audit event, so it is a deliberate human operation, not an init side effect.
 */
function ensureAgentIdentity(dryRun: boolean): void {
  if (identityExists()) {
    try {
      log(`agent identity exists (fingerprint ${loadIdentity().fingerprint}) — keeping it (keep-first).`);
    } catch (e) {
      log(
        `WARN: agent identity at ${IDENTITY_PATH} is unreadable (${e instanceof Error ? e.message : String(e)}); ` +
          `keeping it untouched — audit verification will fail until a human rotates it.`,
      );
    }
    return;
  }
  if (dryRun) {
    log(`[dry-run] would generate Ed25519 agent identity → ${IDENTITY_PATH}`);
    return;
  }
  const id = createIdentity();
  log(`agent identity generated (fingerprint ${id.fingerprint}) → ${IDENTITY_PATH}`);
}

function DEFAULT_POLICIES(agentId: string): string {
  return YAML.stringify({
    version: 1,
    agents: {
      [agentId]: {
        default_ttl: "15m",
        capabilities: [
          // Safe default: every migrated upstream is callable with short TTL.
          // Humans tighten/expand this file; agents can only PROPOSE changes.
          { match: "*:call:*", auto_approve: true, ttl: "15m" },
        ],
      },
    },
  });
}

function log(msg: string): void {
  console.log(`[scopegate init] ${msg}`);
}
