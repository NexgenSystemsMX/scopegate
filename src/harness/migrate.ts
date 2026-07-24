/**
 * Migration core (EPIC-06): normalized harness entry → UpstreamConfig with
 * every secret extracted into the vault, migration fingerprints for
 * idempotent re-runs, immutable backups, rewrite + post-validation, and
 * byte-verified rollback.
 *
 * Key decisions (documented per EPIC-06 H-06.5/H-06.6):
 *
 * - FINGERPRINT: SHA-256 over the NORMALIZED harness entry (stable JSON,
 *   secret values included — a hash, never plaintext). Persisted in
 *   scopegate.yaml under the additive `migrations` key, mapped as
 *   `"<harnessId>:<configPath>" → { <serverName>: <fingerprint> }`.
 *   Storing the hash next to the vault is safe: scopegate.yaml lives in the
 *   vault's own security domain (same dir, mode 0600), and hashing the
 *   values lets a rotated secret be detected and re-vaulted. Re-run with an
 *   unchanged fingerprint → no-op (upstream and vault untouched).
 *
 * - NEVER DEGRADE AUTH SILENTLY: `bearerTokenEnvVar` whose env var is unset
 *   and OAuth-flow entries migrate as `auth.type: "oauth2"` with a secretRef
 *   that is NOT yet in the vault ("oauth2-pending") plus an explicit WARN
 *   naming the exact `scopegate secret add` command. They never become
 *   `auth: none`.
 *
 * - MULTI-HEADER: every credential-looking header is vaulted (the old code
 *   returned inside the loop and only captured the first). The gateway
 *   injects ONE auth header today, so the first (Authorization preferred)
 *   is wired as `auth: bearer` and the rest are vaulted + WARNed about.
 *
 * - BACKUP is KEEP-FIRST: `<config>.pre-scopegate.bak` is written once and
 *   never overwritten; the original pre-migration config always remains the
 *   rollback target.
 *
 * - REWRITE is BYTE-COMPARED: when the rewritten content equals the current
 *   file bytes, nothing is written and no backup logic runs — re-executing
 *   init is a verifiable no-op (empty diff).
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  upsertUpstream,
  type ScopeGateConfig,
  type UpstreamAuth,
  type UpstreamConfig,
} from "../config/config.js";
import type {
  HarnessAdapter,
  HarnessConfig,
  HarnessInstall,
  McpServerSpec,
  MigrateHooks,
  MigratedUpstream,
  OpencodeMcpSpec,
  ScopegateEntry,
  VaultLike,
} from "./types.js";
import { AUTHY_HEADER, BACKUP_SUFFIX, SECRETY_ENV } from "./util.js";

/** Harness entry translated to a format-independent shape. */
export interface NormalizedSpec {
  kind: "stdio" | "http";
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  /** Entry speaks SSE — the gateway proxy today only handles streamable HTTP. */
  sse?: boolean;
  /** Kimi Code: NAME of an env var holding the bearer token. */
  bearerTokenEnvVar?: string;
  /** Entry declares an OAuth flow (opencode `oauth`) instead of a static secret. */
  oauth?: boolean;
  enabledTools?: string[];
  enabled?: boolean;
}

/** Sanitize an upstream name to [a-z0-9_-] (same rule as pre-EPIC-06 init). */
export function safeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9_-]/g, "-");
}

/** Normalize a `mcpServers`-format entry (Claude Code, Kimi Code, Cursor). */
export function normalizeMcpServersSpec(entry: unknown): NormalizedSpec | null {
  const spec = (entry ?? {}) as McpServerSpec;
  if (typeof spec.command === "string" && spec.command) {
    return {
      kind: "stdio",
      command: spec.command,
      args: spec.args ?? [],
      env: spec.env ?? {},
      ...(spec.enabledTools ? { enabledTools: spec.enabledTools } : {}),
      ...(spec.enabled !== undefined ? { enabled: spec.enabled } : {}),
    };
  }
  if (typeof spec.url === "string" && spec.url) {
    return {
      kind: "http",
      url: spec.url,
      headers: spec.headers ?? {},
      ...(spec.type === "sse" || spec.transport === "sse" ? { sse: true } : {}),
      ...(spec.bearerTokenEnvVar
        ? { bearerTokenEnvVar: spec.bearerTokenEnvVar }
        : {}),
      ...(spec.enabledTools ? { enabledTools: spec.enabledTools } : {}),
      ...(spec.enabled !== undefined ? { enabled: spec.enabled } : {}),
    };
  }
  return null;
}

/** Normalize an OpenCode `mcp` entry: `type: local` → stdio, `type: remote` → http. */
export function normalizeOpencodeSpec(entry: unknown): NormalizedSpec | null {
  const spec = (entry ?? {}) as OpencodeMcpSpec;
  if (spec.type === "local" && Array.isArray(spec.command) && spec.command.length > 0) {
    return {
      kind: "stdio",
      command: spec.command[0],
      args: spec.command.slice(1),
      env: spec.environment ?? {},
      ...(spec.enabled !== undefined ? { enabled: spec.enabled } : {}),
    };
  }
  if (spec.type === "remote" && typeof spec.url === "string" && spec.url) {
    return {
      kind: "http",
      url: spec.url,
      headers: spec.headers ?? {},
      ...(spec.oauth !== undefined && spec.oauth !== false ? { oauth: true } : {}),
      ...(spec.enabled !== undefined ? { enabled: spec.enabled } : {}),
    };
  }
  return null;
}

/** Deterministic JSON with sorted keys (fingerprint input must be stable). */
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/**
 * Migration fingerprint: SHA-256 over the normalized entry, secret VALUES
 * included (a rotated secret must re-vault on the next init). The hash is
 * persisted in scopegate.yaml — never the plaintext.
 */
export function fingerprintOf(name: string, spec: NormalizedSpec): string {
  const digest = crypto
    .createHash("sha256")
    .update(stableStringify({ name, ...spec }))
    .digest("hex");
  return `sha256:${digest}`;
}

/**
 * Convert a normalized harness entry into an UpstreamConfig, moving EVERY
 * secret into the vault (only secretRefs remain in configs). Returns null
 * for entries that carry no command/url at all.
 */
export function toUpstreamFromNormalized(
  name: string,
  spec: NormalizedSpec,
  hooks: MigrateHooks,
): UpstreamConfig | null {
  const n = safeName(name);
  const exposeTools =
    spec.enabledTools && spec.enabledTools.length > 0
      ? [...spec.enabledTools].sort()
      : undefined;
  let enabled = spec.enabled ?? true;
  if (spec.sse) {
    // M14.6: EXPLICIT reject — legacy SSE-only MCP servers are not proxied
    // (the gateway speaks streamable HTTP). Migrated disabled + loud warning
    // instead of a silently broken upstream.
    enabled = false;
    hooks.warn(
      `'${name}': legacy SSE transport is not proxied by the gateway (streamable HTTP only) — migrated with ` +
        `enabled: false so nothing breaks silently. Upgrade the server to streamable HTTP and re-enable it.`,
    );
  }

  if (spec.kind === "stdio") {
    if (!spec.command) return null;
    const cleanEnv: Record<string, string> = {};
    const secretEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(spec.env ?? {})) {
      if (SECRETY_ENV.test(k) && v) {
        const ref = `${n}_${k.toLowerCase()}`;
        hooks.vault.set(ref, v); // plaintext moves into the vault…
        secretEnv[k] = ref; // …config keeps only the ref
      } else {
        cleanEnv[k] = v;
      }
    }
    return {
      name: n,
      transport: {
        kind: "stdio",
        command: spec.command,
        args: spec.args ?? [],
        env: cleanEnv,
      },
      auth:
        Object.keys(secretEnv).length > 0
          ? { type: "env", env: secretEnv }
          : { type: "none" },
      ...(exposeTools ? { exposeTools } : {}),
      enabled,
    };
  }

  // --- http upstream ---
  if (!spec.url) return null;
  const headers = spec.headers ?? {};
  // ALL credential-looking headers are vaulted (multi-header fix: the old
  // code returned inside the loop and only captured the first). Deterministic
  // order: Authorization first, then alphabetical.
  const secretHeaders = Object.entries(headers)
    .filter(([h, v]) => AUTHY_HEADER.test(h) && v)
    .sort(([a], [b]) =>
      a.toLowerCase() === "authorization"
        ? -1
        : b.toLowerCase() === "authorization"
          ? 1
          : a.localeCompare(b),
    );
  const vaulted = secretHeaders.map(([h, v]) => ({
    header: h,
    raw: v,
    ref: `${n}_${h.toLowerCase().replace(/[^a-z0-9]/g, "_")}`,
    value: v.replace(/^Bearer\s+/i, ""),
  }));
  for (const s of vaulted) hooks.vault.set(s.ref, s.value);

  let auth: UpstreamAuth;
  if (vaulted.length > 0) {
    const [first, ...rest] = vaulted;
    auth = {
      type: "bearer",
      secretRef: first.ref,
      header: first.header,
      scheme: /^Bearer\s+/i.test(first.raw) ? "Bearer" : "",
    };
    if (rest.length > 0) {
      hooks.warn(
        `'${name}': ${rest.length} extra secret header(s) vaulted (${rest
          .map((r) => `'${r.header}' → ref '${r.ref}'`)
          .join(", ")}). The gateway injects ONE auth header today, so only ` +
          `'${first.header}' is wired — the other refs are preserved in the vault.`,
      );
    }
    if (spec.bearerTokenEnvVar) {
      hooks.warn(
        `'${name}': bearerTokenEnvVar '${spec.bearerTokenEnvVar}' ignored — ` +
          `static secret header(s) take precedence.`,
      );
    }
  } else if (spec.bearerTokenEnvVar) {
    const ref = `${n}_bearer_token`;
    const value = process.env[spec.bearerTokenEnvVar];
    if (value) {
      hooks.vault.set(ref, value);
      auth = { type: "bearer", secretRef: ref, header: "Authorization", scheme: "Bearer" };
    } else {
      // oauth2-pending: NEVER degrade to auth none. The ref is deliberately
      // absent from the vault until the human deposits it.
      auth = { type: "oauth2", secretRef: ref };
      hooks.warn(
        `'${name}': bearerTokenEnvVar '${spec.bearerTokenEnvVar}' is NOT set in this ` +
          `environment — migrated with PENDING auth (oauth2). Deposit it with: ` +
          `scopegate secret add ${ref}  (then restart the agent session).`,
      );
    }
  } else if (spec.oauth) {
    const ref = `${n}_oauth`;
    auth = { type: "oauth2", secretRef: ref };
    hooks.warn(
      `'${name}': declares an OAuth flow — migrated with PENDING auth (oauth2). ` +
        `Deposit the token blob with: scopegate secret add ${ref}  ` +
        `(automatic refresh belongs to the EPIC-03 refresh daemon).`,
    );
  } else {
    auth = { type: "none" };
  }
  return {
    name: n,
    transport: { kind: "http", url: spec.url },
    auth,
    ...(exposeTools ? { exposeTools } : {}),
    enabled,
  };
}

/**
 * Backwards-compatible wrapper over the pre-EPIC-06 `toUpstream` export of
 * init.ts (mcpServers-format entry in, UpstreamConfig out, warnings muted).
 */
export function toUpstream(
  name: string,
  spec: McpServerSpec,
  vault: VaultLike,
): UpstreamConfig | null {
  const normalized = normalizeMcpServersSpec(spec);
  if (!normalized) return null;
  return toUpstreamFromNormalized(name, normalized, { vault, warn: () => {} });
}

// ---------------------------------------------------------------------------
// Migration fingerprints, persisted in scopegate.yaml (additive key — the
// config schema in config.ts is untouched; YAML round-trips the extra key).
// ---------------------------------------------------------------------------

type ConfigWithMigrations = ScopeGateConfig & {
  migrations?: Record<string, Record<string, string>>;
};

/** Key under `migrations` for one harness config file. */
export function migrationKey(adapterId: string, configPath: string): string {
  return `${adapterId}:${configPath}`;
}

export interface MigrateOptions {
  dryRun: boolean;
  log: (msg: string) => void;
  warn: (msg: string) => void;
}

/**
 * Migrate one harness config: vault its servers' secrets, upsert the
 * upstreams (fingerprint-driven idempotency), keep-first backup, rewrite so
 * the gateway is the only MCP entry, and validate the result (restoring the
 * backup on failure).
 */
export function migrateInstall(
  adapter: HarnessAdapter,
  install: HarnessInstall,
  cfg: ScopeGateConfig,
  vault: VaultLike,
  opts: MigrateOptions,
): void {
  const { dryRun, log, warn } = opts;
  let json: HarnessConfig = {};
  if (fs.existsSync(install.path)) {
    try {
      json = adapter.readConfig(install.path);
    } catch (e) {
      warn(
        `could not parse ${install.path} (${e instanceof Error ? e.message : String(e)}); ` +
          `skipping migration for it.`,
      );
      return;
    }
  }
  const servers = adapter.listServers(json);

  // A "scopegate" entry written by a previous init is fine and idempotent —
  // anything else with that name is a conflict the human must resolve.
  const clashing = servers.find(([n]) => n === "scopegate");
  if (clashing && !adapter.isGatewayEntry(clashing[1])) {
    throw new Error(
      `${install.path} already defines an MCP server named 'scopegate' ` +
        `that was not created by ScopeGate. Rename or remove it, then re-run \`scopegate init\`.`,
    );
  }

  const withMigrations = cfg as ConfigWithMigrations;
  const fingerprints = ((withMigrations.migrations ??= {})[
    migrationKey(adapter.id, install.path)
  ] ??= {});

  for (const [name, entry] of servers) {
    if (name === "scopegate") continue;
    const migrated: MigratedUpstream[] = adapter.toUpstreams(name, entry, { vault, warn });
    for (const m of migrated) {
      const existing = cfg.upstreams.find((u) => u.name === m.upstream.name);
      if (existing && fingerprints[name] === m.fingerprint) {
        // Unchanged since the last migration: no-op. Still surface pending
        // oauth2 auth so the human sees what is left to deposit.
        if (existing.auth.type === "oauth2" && !vault.has(existing.auth.secretRef)) {
          warn(
            `'${name}': auth still PENDING — deposit it with: ` +
              `scopegate secret add ${existing.auth.secretRef}`,
          );
        }
        continue;
      }
      upsertUpstream(cfg, m.upstream);
      fingerprints[name] = m.fingerprint;
      log(
        dryRun
          ? `[dry-run] would migrate MCP '${name}' (${adapter.id}) behind the gateway`
          : `migrated MCP '${name}' (${adapter.id}) behind the gateway`,
      );
    }
  }

  const gatewayEntry: ScopegateEntry = {
    command: "scopegate",
    args: ["start"],
    agentId: cfg.agentId,
  };
  const rewritten = adapter.writeGatewayEntry(json, gatewayEntry);
  const next = JSON.stringify(rewritten, null, 2);

  if (dryRun) {
    log(
      `[dry-run] would rewrite ${install.path} (backup: ${path.basename(install.path)}${BACKUP_SUFFIX}, scopegate as the only MCP entry)`,
    );
    return;
  }

  // Byte-compared no-op: re-running init changes nothing on disk.
  if (fs.existsSync(install.path) && fs.readFileSync(install.path, "utf8") === next) {
    log(`${install.path} already up to date — no changes (idempotent).`);
    return;
  }

  // Backup, then rewrite: scopegate becomes the single MCP entry point.
  const backup = adapter.backupPath(install.path);
  if (fs.existsSync(install.path)) {
    if (fs.existsSync(backup)) {
      // KEEP-FIRST policy: the first backup holds the original pre-migration
      // config and is the rollback target. Re-running init must never
      // overwrite it with an already-migrated config.
      log(`backup exists (${path.basename(backup)}) — keeping the original.`);
    } else {
      fs.copyFileSync(install.path, backup);
      log(`backup written → ${path.basename(backup)}`);
    }
  }
  fs.writeFileSync(install.path, next);

  // Post-rewrite validation: the file must re-parse and expose scopegate as
  // the gateway entry. On failure, restore the backup (or remove the
  // incomplete new file) and abort with an actionable error.
  try {
    const check = adapter.readConfig(install.path);
    const gateway = adapter.listServers(check).find(([n]) => n === "scopegate");
    if (!gateway || !adapter.isGatewayEntry(gateway[1])) {
      throw new Error("scopegate gateway entry missing after rewrite");
    }
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    if (fs.existsSync(backup)) {
      fs.copyFileSync(backup, install.path);
      throw new Error(
        `Failed to rewrite ${install.path} (${reason}). Original config restored from ${path.basename(backup)}.`,
      );
    }
    fs.rmSync(install.path, { force: true });
    throw new Error(
      `Failed to write ${install.path} (${reason}). The incomplete file was removed.`,
    );
  }
  log(`rewrote ${install.path} (backup: ${path.basename(backup)})`);
}

// ---------------------------------------------------------------------------
// Rollback (EPIC-06 H-06.5)
// ---------------------------------------------------------------------------

export interface RollbackResult {
  adapterId: string;
  path: string;
  backup: string;
  /** True when the restored file is byte-identical to the backup (hash-verified). */
  restored: boolean;
  reason?: string;
}

function sha256File(p: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

/**
 * Restore every harness config that has a `.pre-scopegate.bak` backup,
 * verifying byte-identical restoration by hash. The backup itself is NEVER
 * modified or deleted (immutable audit trail of the pre-migration state).
 *
 * Conservative by design: scopegate.yaml upstreams and vault secrets are
 * left untouched — undoing the harness side never deletes deposited secrets.
 * The caller reports that explicitly.
 *
 * Exported for the future CLI command (wired by the orchestrator) and used
 * by tests today.
 */
export function restoreFromBackup(
  adapters: HarnessAdapter[],
  log: (msg: string) => void = (m) => console.log(`[scopegate rollback] ${m}`),
): RollbackResult[] {
  const results: RollbackResult[] = [];
  for (const adapter of adapters) {
    for (const candidate of adapter.candidatePaths()) {
      const backup = adapter.backupPath(candidate.path);
      if (!fs.existsSync(backup)) continue;
      fs.copyFileSync(backup, candidate.path);
      const ok = sha256File(candidate.path) === sha256File(backup);
      results.push({
        adapterId: adapter.id,
        path: candidate.path,
        backup,
        restored: ok,
        ...(ok ? {} : { reason: "hash mismatch after restore" }),
      });
      log(
        ok
          ? `restored ${candidate.path} ← ${path.basename(backup)} (byte-identical, hash-verified)`
          : `ERROR: ${candidate.path} does not match ${path.basename(backup)} after restore`,
      );
    }
  }
  if (results.length === 0) {
    log("no .pre-scopegate.bak backups found — nothing to roll back.");
  } else {
    log(
      "scopegate.yaml upstreams and vault secrets were left untouched (conservative); " +
        "remove them manually if the rollback is permanent.",
    );
  }
  return results;
}
