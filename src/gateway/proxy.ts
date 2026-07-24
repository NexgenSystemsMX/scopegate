/**
 * Upstream proxy: owns the MCP client connections to upstream servers and is
 * the ONLY place where secrets leave the vault — injected at the outbound hop:
 *
 *   - http upstreams  → Authorization / custom header on the transport
 *   - stdio upstreams → env vars at child-process spawn
 *
 * The agent-facing side (server.ts) only ever sees tool names and results.
 *
 * Hardening invariants (EPIC-01 H2):
 *   - LOGS GO TO STDERR ONLY. stdout belongs to the MCP protocol; a single
 *     stray console.log corrupts the framing and kills the agent session.
 *   - Connect timeout: a hung upstream must not block gateway startup or a
 *     lazy reconnect. `connect()` races against SCOPEGATE_CONNECT_TIMEOUT_MS
 *     (default 10_000 ms) and cleans up the half-open client on failure.
 *   - `connectAll()` NEVER rejects: it resolves with per-upstream status
 *     ({ ok, tools } | { ok: false, error }), so one dead upstream still
 *     yields a working gateway for the rest.
 *   - Self-healing calls (pre-existing transparent retry, now bounded): on
 *     failure the connection is dropped, re-established with freshly-injected
 *     credentials, and the call retried with linear backoff — at most
 *     MAX_CALL_ATTEMPTS total attempts, so a dead upstream fails fast
 *     instead of retrying forever.
 *   - EPIC-12 attestation: outbound HTTP hops carry an EdDSA JWT in
 *     `X-ScopeGate-Attestation`, ADDITIVE to the credential (never instead),
 *     signed with the audit identity keypair and cached ~45 s by attest.ts.
 *     Fail-open: if signing is unavailable the hop proceeds without it.
 *   - EPIC-12 warm pool: upstreams with `pool.min > 0` keep pre-authenticated
 *     connections (checkout/checkin per call), kept alive by the diagnose()
 *     probe, rebuilt after an OAuth refresh. Upstreams without `pool` behave
 *     exactly as before (single lazy connection).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import crypto from "node:crypto";
import fs from "node:fs";
import type { PoolConfig, UpstreamConfig } from "../config/config.js";
import { VAULT_VERSION_PATH } from "../config/config.js";
import { Vault } from "../vault/vault.js";
import { Minter, secretRefsOf, type CredentialMode } from "../minter/minter.js";
import { audit } from "../audit/log.js";
import { isRateLimitMessage, parseRetryAfterS } from "./errors.js";
import { markTainted, scoreTaint, taintMode } from "./taint.js";
import {
  IDEMPOTENCY_ARG,
  hashCallArgs,
  lookupIdempotent,
  storeIdempotent,
} from "./idempotency.js";
import {
  OAuthRefreshDaemon,
  reauthInstruction,
  type OAuthHealth,
} from "../oauth/daemon.js";
import { ATTESTATION_HEADER, getAttestation } from "../attestation/attest.js";

/** Correlation fingerprint for a minted token: first 12 hex of its SHA-256. */
function tokenFingerprint(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 12);
}

/**
 * Default auth-failure detector for oauth2 upstreams: an upstream error whose
 * message carries HTTP 401 / unauthorized / invalid_token. Overridable per
 * upstream via `auth.authErrorPattern` (EPIC-03 H3.4).
 */
const DEFAULT_AUTH_ERROR_RE = /(\b401\b|unauthorized|invalid_token)/i;

function isAuthError(e: unknown, pattern?: string): boolean {
  const msg = errorMessage(e);
  if (pattern) {
    try {
      return new RegExp(pattern, "i").test(msg);
    } catch {
      /* invalid user regex — fall back to the default */
    }
  }
  return DEFAULT_AUTH_ERROR_RE.test(msg);
}

/* ------------------------------------------------------------------------ */
/* Minimal structured stderr logger + error helpers                          */
/* (shared with server.ts and cli.ts — stdout is the MCP channel).           */
/* ------------------------------------------------------------------------ */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function threshold(): number {
  const raw = (process.env.SCOPEGATE_LOG_LEVEL ?? "info").toLowerCase();
  return LEVEL_ORDER[raw as LogLevel] ?? LEVEL_ORDER.info;
}

/**
 * Structured log line to stderr. NEVER write logs to stdout in gateway code:
 * stdout is reserved for the MCP protocol.
 */
export function log(
  level: LogLevel,
  msg: string,
  ctx?: Record<string, unknown>,
): void {
  if (LEVEL_ORDER[level] < threshold()) return;
  const line = `[scopegate] ${level} ${msg}`;
  console.error(ctx ? `${line} ${JSON.stringify(ctx)}` : line);
}

/** Human-readable message for any thrown value (never a stack trace). */
export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/* ------------------------------------------------------------------------ */

export interface ProxiedTool {
  upstream: string;
  /** Name exposed to the agent: `<upstream>__<tool>` */
  exposedName: string;
  upstreamName: string;
  description?: string;
  inputSchema: unknown;
}

interface Connection {
  client: Client;
  tools: ProxiedTool[];
  connectedAt: number;
}

/* ------------------------------------------------------------------------ */
/* EPIC-12: warm pool of pre-authenticated connections                       */
/* ------------------------------------------------------------------------ */

interface PoolEntry {
  conn: Connection;
  inUse: boolean;
  lastUsed: number;
}

interface Pool {
  entries: PoolEntry[];
  /** Checkouts served by an already-warm connection. */
  hits: number;
  /** Checkouts that had to establish a new connection. */
  misses: number;
  /** Keep-alive timer (unref'd — never holds the process open). */
  timer?: NodeJS.Timeout;
  /** Guards against overlapping refill loops. */
  filling: boolean;
  /** Last refill failure, surfaced by connectAll/diagnose. */
  lastError?: string;
}

/** Result of a pool checkout: the connection plus how to release it. */
interface PoolHandle {
  conn: Connection;
  /** Set when the connection belongs to the pool (vs. a throwaway overflow). */
  entry?: PoolEntry;
  /** Overflow connection beyond pool.max — closed after the call. */
  throwaway?: boolean;
}

/** Effective pool settings; null when pooling is disabled for the upstream. */
type EffectivePoolConfig = Required<PoolConfig>;

/** Per-upstream diagnose entry; oauth2 upstreams also report token health. */
export interface DiagnoseEntry {
  ok: boolean;
  tools?: number;
  error?: string;
  mode: CredentialMode;
  /** EPIC-03: daemon snapshot for oauth2 upstreams. */
  oauth?: OAuthHealth;
  /** Literal human instruction when the upstream needs re-authorization. */
  action_required?: string;
  /** EPIC-12: warm pool metrics (present only when pooling is enabled). */
  pool?: { size: number; inUse: number; hits: number };
}

/** Per-upstream connect timeout; a dead/hung upstream must not hang startup. */
const CONNECT_TIMEOUT_MS = parseTimeout(
  process.env.SCOPEGATE_CONNECT_TIMEOUT_MS,
  10_000,
);

function parseTimeout(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Total attempts for a proxied call (initial try + transparent retries). */
const MAX_CALL_ATTEMPTS = 3;
/** Linear backoff between call attempts: 250 ms, 500 ms, … */
const CALL_BACKOFF_BASE_MS = 250;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Race `p` against a timeout. `p` keeps running after a timeout, but its
 * handlers are attached here so it can never surface as an unhandled
 * rejection; callers are responsible for cleaning up the abandoned work.
 */
function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${what} timed out after ${ms} ms`)),
      ms,
    );
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/** Per-call context threaded from server.ts down to the injection points. */
export interface CallContext {
  /** Remaining TTL (ms) of the policy grant covering this call. */
  grantTtlMs?: number;
  /** Exposed tool name, for audit attribution when the call drives a connect. */
  tool?: string;
}

export class UpstreamProxy {
  private connections = new Map<string, Connection>();
  /**
   * Last-known tool list per upstream, kept independently of the live
   * connection: a dropped connection (self-heal / 401) must not make the
   * agent's tools vanish — resolve() consults this registry and call()
   * rebuilds the connection on demand. Updated on every (re)connect.
   */
  private toolRegistry = new Map<string, ProxiedTool[]>();
  private minter: Minter;
  private agentId: string;
  /**
   * OAuth refresh daemon (EPIC-03): present whenever at least one enabled
   * upstream is oauth2. It owns ALL blob writes (single-writer rule) and runs
   * the proactive renewal scheduler; the proxy only delegates 401-driven
   * synchronous refreshes to it.
   */
  private oauthDaemon?: OAuthRefreshDaemon;
  /** EPIC-12: warm pools, only for upstreams with `pool.min > 0`. */
  private pools = new Map<string, Pool>();
  /** EPIC-12: global attestation default (per-upstream `attestation` wins). */
  private attestationDefault: boolean;
  /**
   * Mejora #8: per-upstream circuit breaker. After CIRCUIT_OPEN_AFTER
   * consecutive failed calls the circuit OPENS for CIRCUIT_RESET_MS (calls
   * fail fast with an upstream_down envelope instead of hammering a dead
   * service), then a single half-open probe decides: success closes it.
   */
  private circuits = new Map<
    string,
    { state: "closed" | "open" | "half_open"; failures: number; openedAt: number }
  >();

  private static readonly CIRCUIT_OPEN_AFTER = 5;
  private static readonly CIRCUIT_RESET_MS = 30_000;

  constructor(
    private upstreams: UpstreamConfig[],
    private vault: Vault,
    deps: { agentId?: string; minter?: Minter; attestationDefault?: boolean } = {},
  ) {
    this.agentId = deps.agentId ?? process.env.SCOPEGATE_AGENT_ID ?? "gateway";
    this.minter = deps.minter ?? new Minter(vault);
    this.attestationDefault = deps.attestationDefault ?? true;
    if (upstreams.some((u) => u.enabled !== false && u.auth.type === "oauth2")) {
      this.oauthDaemon = new OAuthRefreshDaemon({
        vault,
        upstreams,
        agentId: this.agentId,
      });
      // Non-blocking: arms timers only (unref'd); no network I/O happens here.
      this.oauthDaemon.start();
    }
  }

  /** The OAuth refresh daemon, when any upstream needs it (tests, diagnose). */
  oauth(): OAuthRefreshDaemon | undefined {
    return this.oauthDaemon;
  }

  /** Declared credential mode of an upstream (minted vs fallback injection). */
  credentialMode(up: UpstreamConfig): CredentialMode {
    return this.minter.modeFor(up.auth);
  }

  /**
   * THE single point where a secret leaves the vault for an HTTP upstream.
   * Provider-backed auth types mint a short-lived token (clamped to the
   * grant TTL); static bearer/oauth2 use pure fallback injection. Every
   * injection — minted or fallback — is audited as `secret_ref_used`.
   *
   * EPIC-12: the attestation JWT is appended here (ADDITIVE — the credential
   * headers are computed first and never altered), so it rides on EVERY
   * outbound HTTP request of the connection, initialize included.
   */
  private async buildAuthHeaders(
    up: UpstreamConfig,
    ctx: CallContext,
  ): Promise<Record<string, string>> {
    const a = up.auth;
    let headers: Record<string, string> = {};
    if (this.minter.providerFor(a)) {
      const res = await this.mintOrThrow(up, ctx);
      this.auditSecretRefsUsed(up, ctx);
      headers = res.cred.headers ?? {};
    } else if (a.type === "bearer" || a.type === "oauth2") {
      const secret =
        a.type === "bearer"
          ? this.vault.get(a.secretRef)
          : accessTokenFromOAuthBlob(this.vault.get(a.secretRef));
      this.auditSecretRefsUsed(up, ctx);
      const header = a.header ?? "Authorization";
      const scheme = a.scheme ?? (header === "Authorization" ? "Bearer" : "");
      headers = { [header]: scheme ? `${scheme} ${secret}` : secret };
    }
    return this.withAttestation(up, headers);
  }

  /**
   * EPIC-12: whether to sign outbound hops to this upstream. Per-upstream
   * `attestation` wins over the global default; default is ON (the gateway
   * always holds an identity — audit creates it lazily otherwise). stdio
   * upstreams are never attested (no verifying counterpart, by design).
   */
  attestationEnabledFor(up: UpstreamConfig): boolean {
    if (up.transport.kind !== "http") return false;
    return up.attestation ?? this.attestationDefault;
  }

  /**
   * Append the attestation header. Fail-open: if the identity cannot be
   * loaded, the hop proceeds without it (a WARN is logged) — attestation must
   * never break an otherwise-working upstream. The token is cached ~45 s by
   * attest.ts, so this does NOT re-sign per connection.
   */
  private withAttestation(
    up: UpstreamConfig,
    headers: Record<string, string>,
  ): Record<string, string> {
    if (!this.attestationEnabledFor(up)) return headers;
    try {
      const att = getAttestation(this.agentId);
      return { ...headers, [ATTESTATION_HEADER]: att.token };
    } catch (e) {
      log("warn", `attestation unavailable for '${up.name}' — sending without it`, {
        error: errorMessage(e),
      });
      return headers;
    }
  }

  /**
   * Mint via the minter and emit the mint lifecycle events. Fail-closed: a
   * mint that fails (or cannot be audited) aborts the connect — no
   * unattributed credential ever reaches an upstream.
   */
  private async mintOrThrow(up: UpstreamConfig, ctx: CallContext) {
    let provider: string;
    try {
      const res = await this.minter.resolve(up, {
        grantTtlMs: ctx.grantTtlMs,
        scope: ctx.tool,
        agentId: this.agentId,
      });
      if (!res) throw new Error(`no credential provider for auth '${up.auth.type}'`);
      provider = res.provider;
      if (res.minted) {
        audit(this.agentId, "token_minted", {
          upstream: up.name,
          provider,
          ttlMs: res.ttlMs,
          expiresAt: new Date(res.cred.expiresAt).toISOString(),
          fingerprint: tokenFingerprint(res.cred.value),
        });
      }
      return res;
    } catch (e) {
      audit(this.agentId, "token_mint_failed", {
        upstream: up.name,
        provider: up.auth.type,
        error: errorMessage(e),
      });
      throw e;
    }
  }

  /** One `secret_ref_used` event per vault ref read at an injection point. */
  private auditSecretRefsUsed(up: UpstreamConfig, ctx: CallContext): void {
    for (const secretRef of secretRefsOf(up.auth)) {
      audit(this.agentId, "secret_ref_used", {
        upstream: up.name,
        secretRef,
        ...(ctx.tool ? { tool: ctx.tool } : {}),
      });
    }
  }

  private async connect(up: UpstreamConfig, ctx: CallContext = {}): Promise<Connection> {
    const conn = await this.connectRaw(up, ctx);
    this.connections.set(up.name, conn);
    return conn;
  }

  /**
   * Establish a connection and register its tools, WITHOUT taking the
   * upstream's primary slot in `connections` — used by connect() (lazy path)
   * and by the warm pool (pool entries live in `pools`, not `connections`).
   */
  private async connectRaw(up: UpstreamConfig, ctx: CallContext = {}): Promise<Connection> {
    const client = new Client(
      { name: "scopegate", version: "0.1.0" },
      { capabilities: {} },
    );

    try {
      const tools = await withTimeout(
        this.connectAndListTools(client, up, ctx),
        CONNECT_TIMEOUT_MS,
        `connect to upstream '${up.name}'`,
      );
      const conn: Connection = { client, tools, connectedAt: Date.now() };
      this.toolRegistry.set(up.name, tools);
      log("debug", `upstream '${up.name}' connected`, {
        tools: tools.length,
      });
      return conn;
    } catch (e) {
      // Don't leak a half-open transport / spawned child process. The close
      // is fire-and-forget: awaiting it could hang on the same dead upstream.
      void client.close().catch(() => {});
      throw e;
    }
  }

  /* ---------------------------------------------------------------------- */
  /* EPIC-12: warm pool — pre-established, keep-alive, checkout/checkin      */
  /* ---------------------------------------------------------------------- */

  /**
   * Effective pool settings for an upstream, or null when pooling is off.
   * `pool.min: 0` (or no `pool` at all) keeps the pre-EPIC-12 lazy behavior.
   */
  private poolCfgFor(up: UpstreamConfig): EffectivePoolConfig | null {
    const p = up.pool;
    if (!p) return null;
    const min = Math.max(0, Math.floor(p.min ?? 0));
    if (min === 0) return null;
    return {
      min,
      max: Math.max(min, Math.floor(p.max ?? 2)),
      idleTimeoutMs: p.idleTimeoutMs ?? 300_000,
    };
  }

  /**
   * Create the pool (if needed), fill it to `min` and arm the keep-alive
   * timer. NEVER rejects — like connectAll, a dead upstream yields
   * `{ ok: false, error }` and the timer keeps retrying in the background.
   */
  private async initPool(
    up: UpstreamConfig,
    ctx: CallContext = {},
  ): Promise<{ ok: boolean; tools?: number; error?: string }> {
    const cfg = this.poolCfgFor(up);
    if (!cfg) return { ok: false, error: `pooling disabled for '${up.name}'` };
    let pool = this.pools.get(up.name);
    if (!pool) {
      pool = { entries: [], hits: 0, misses: 0, filling: false };
      this.pools.set(up.name, pool);
      // Keep-alive cadence: half the idle timeout, clamped to [50 ms, 60 s].
      // Attested upstreams are re-probed at least every 45 s so a connection
      // whose attestation JWT expired (60 s TTL) is dropped and replaced
      // before a call can ride on a stale header for long.
      let interval = Math.min(60_000, Math.max(50, Math.floor(cfg.idleTimeoutMs / 2)));
      if (this.attestationEnabledFor(up)) interval = Math.min(interval, 45_000);
      pool.timer = setInterval(() => {
        void this.maintainPool(up, pool!).catch(() => {});
      }, interval);
      pool.timer.unref();
    }
    await this.fillPool(up, pool, ctx);
    const first = pool.entries[0];
    if (!first) {
      return {
        ok: false,
        error:
          pool.lastError ??
          `pool '${up.name}': unable to establish ${cfg.min} connection(s)`,
      };
    }
    return { ok: true, tools: first.conn.tools.length };
  }

  /** Top the pool up to `min`. Stops (and records) at the first failure. */
  private async fillPool(up: UpstreamConfig, pool: Pool, ctx: CallContext): Promise<void> {
    if (pool.filling) return;
    const cfg = this.poolCfgFor(up);
    if (!cfg) return;
    pool.filling = true;
    try {
      while (pool.entries.length < cfg.min) {
        try {
          const conn = await this.connectRaw(up, ctx);
          pool.entries.push({ conn, inUse: false, lastUsed: Date.now() });
          pool.lastError = undefined;
        } catch (e) {
          pool.lastError = errorMessage(e);
          log("warn", `pool '${up.name}': refill connect failed`, {
            error: pool.lastError,
          });
          break;
        }
      }
    } finally {
      pool.filling = false;
    }
  }

  /**
   * Checkout: reuse an idle warm connection (hit), establish a new pooled one
   * below `max` (miss), or hand out a throwaway overflow connection when the
   * pool is fully busy (also a miss; closed on release).
   */
  private async checkoutPool(
    up: UpstreamConfig,
    pool: Pool,
    ctx: CallContext,
    countMetrics = true,
  ): Promise<PoolHandle> {
    const cfg = this.poolCfgFor(up);
    const idle = pool.entries.find((e) => !e.inUse);
    if (idle) {
      idle.inUse = true;
      if (countMetrics) pool.hits++;
      return { conn: idle.conn, entry: idle };
    }
    if (countMetrics) pool.misses++;
    const conn = await this.connectRaw(up, ctx);
    if (cfg && pool.entries.length < cfg.max) {
      const entry: PoolEntry = { conn, inUse: true, lastUsed: Date.now() };
      pool.entries.push(entry);
      return { conn, entry };
    }
    return { conn, throwaway: true };
  }

  /** Checkin: a healthy connection goes back to idle; a failed one is dropped. */
  private releasePoolEntry(
    up: UpstreamConfig,
    pool: Pool,
    handle: PoolHandle,
    ok: boolean,
  ): void {
    if (handle.throwaway || !handle.entry) {
      void handle.conn.client.close().catch(() => {});
      return;
    }
    const entry = handle.entry;
    if (ok) {
      entry.inUse = false;
      entry.lastUsed = Date.now();
      return;
    }
    // Invalid connection → drop + refill (the self-heal pattern of call()).
    this.dropPoolEntry(pool, entry);
    void this.fillPool(up, pool, {}).catch(() => {});
  }

  private dropPoolEntry(pool: Pool, entry: PoolEntry): void {
    const i = pool.entries.indexOf(entry);
    if (i >= 0) pool.entries.splice(i, 1);
    void entry.conn.client.close().catch(() => {});
  }

  /**
   * Keep-alive, reusing the diagnose() probe: reap idle connections past
   * `idleTimeoutMs` (down to `min`), probe the survivors with `listTools`,
   * drop the dead ones, then refill to `min`. Never rejects.
   */
  private async maintainPool(up: UpstreamConfig, pool: Pool): Promise<void> {
    const cfg = this.poolCfgFor(up);
    if (!cfg) return;
    const now = Date.now();
    let removable = pool.entries.length - cfg.min;
    for (const e of [...pool.entries]) {
      if (removable <= 0) break;
      if (!e.inUse && now - e.lastUsed > cfg.idleTimeoutMs) {
        this.dropPoolEntry(pool, e);
        removable--;
      }
    }
    for (const e of [...pool.entries]) {
      if (e.inUse) continue; // in-use connections are exercised by their call
      try {
        await withTimeout(
          e.conn.client.listTools(),
          CONNECT_TIMEOUT_MS,
          `pool keep-alive probe of upstream '${up.name}'`,
        );
      } catch (err) {
        log("warn", `pool '${up.name}': dropping a dead connection`, {
          error: errorMessage(err),
        });
        this.dropPoolEntry(pool, e);
      }
    }
    await this.fillPool(up, pool, {});
  }

  /** Run one keep-alive pass over every pool (timer entry point; tests use it). */
  async maintainPools(): Promise<void> {
    for (const [name, pool] of this.pools) {
      const up = this.upstreams.find((u) => u.name === name);
      if (up) await this.maintainPool(up, pool).catch(() => {});
    }
  }

  /** Drop ALL pooled connections (e.g. after an OAuth token refresh) and refill. */
  private async rebuildPool(up: UpstreamConfig, pool: Pool, ctx: CallContext): Promise<void> {
    for (const e of [...pool.entries]) this.dropPoolEntry(pool, e);
    await this.fillPool(up, pool, ctx);
  }

  private poolMetrics(pool: Pool): { size: number; inUse: number; hits: number } {
    return {
      size: pool.entries.length,
      inUse: pool.entries.filter((e) => e.inUse).length,
      hits: pool.hits,
    };
  }

  /** Transport setup + initial tool listing — the parts that can hang. */
  private async connectAndListTools(
    client: Client,
    up: UpstreamConfig,
    ctx: CallContext,
  ): Promise<ProxiedTool[]> {
    if (up.transport.kind === "http") {
      const headers = await this.buildAuthHeaders(up, ctx);
      const transport = new StreamableHTTPClientTransport(
        new URL(up.transport.url),
        { requestInit: { headers } },
      );
      await client.connect(transport);
    } else {
      // stdio: inject secret env vars at spawn — invisible to the agent.
      const env = this.buildSpawnEnv(up);
      if (up.auth.type === "composite") {
        // M1 (composite): static refs + every mint, fused in order.
        for (const [envName, secretRef] of Object.entries(up.auth.env ?? {})) {
          env[envName] = this.vault.get(secretRef);
        }
        for (const mintAuth of up.auth.mint ?? []) {
          const subUp = { ...up, auth: mintAuth };
          const res = await this.mintOrThrow(subUp, ctx);
          Object.assign(env, res.cred.env ?? {});
          // M14.2: header-only mints (jwt) also reach the child as
          // <NAME>_ACCESS_TOKEN in composite mode.
          if (!res.cred.env && res.cred.headers?.Authorization) {
            env[this.accessTokenEnvName(up.name)] = res.cred.headers.Authorization.replace(
              /^Bearer\s+/i,
              "",
            );
          }
          this.scheduleMintRefresh(up.name, res.cred.expiresAt);
        }
        this.auditSecretRefsUsed(up, ctx);
      } else if (this.minter.providerFor(up.auth)) {
        // Provider-backed (e.g. aws_sts): inject minted session credentials.
        const res = await this.mintOrThrow(up, ctx);
        this.auditSecretRefsUsed(up, ctx);
        Object.assign(env, res.cred.env ?? {});
        // M14.2: a header-only minted credential (jwt) also reaches stdio
        // bridges as <NAME>_ACCESS_TOKEN.
        if (!res.cred.env && res.cred.headers?.Authorization) {
          env[this.accessTokenEnvName(up.name)] = res.cred.headers.Authorization.replace(
            /^Bearer\s+/i,
            "",
          );
        }
        this.scheduleMintRefresh(up.name, res.cred.expiresAt);
      } else if (up.auth.type === "env") {
        for (const [envName, secretRef] of Object.entries(up.auth.env)) {
          env[envName] = this.vault.get(secretRef);
        }
        this.auditSecretRefsUsed(up, ctx);
      } else if (up.auth.type === "oauth2") {
        // M14.2: the daemon keeps the blob fresh — inject the CURRENT access
        // token as <NAME>_ACCESS_TOKEN for stdio bridges that read it from env.
        env[this.accessTokenEnvName(up.name)] = accessTokenFromOAuthBlob(
          this.vault.get(up.auth.secretRef),
        );
        this.auditSecretRefsUsed(up, ctx);
      } else if (up.auth.type === "bearer") {
        // M14.2: static bearer also injects as <NAME>_ACCESS_TOKEN on stdio.
        env[this.accessTokenEnvName(up.name)] = this.vault.get(up.auth.secretRef);
        this.auditSecretRefsUsed(up, ctx);
      }
      const transport = new StdioClientTransport({
        command: up.transport.command,
        args: up.transport.args ?? [],
        env,
      });
      await client.connect(transport);
    }

    const listed = await client.listTools();
    const allow = new Set(up.exposeTools ?? []);
    return listed.tools
      .filter((t) => allow.size === 0 || allow.has(t.name))
      .map((t) => ({
        upstream: up.name,
        exposedName: `${up.name}__${t.name}`,
        upstreamName: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      }));
  }

  private async getConnection(name: string, ctx: CallContext = {}): Promise<Connection> {
    const existing = this.connections.get(name);
    if (existing) return existing;
    const up = this.upstreams.find((u) => u.name === name && u.enabled !== false);
    if (!up) throw new Error(`Unknown or disabled upstream '${name}'`);
    return this.connect(up, ctx);
  }

  /**
   * Connect all enabled upstreams (in parallel, each with its own connect
   * timeout) and resolve with per-upstream status. NEVER rejects: a failed
   * upstream yields `{ ok: false, error }` and is logged to stderr, while
   * the rest of the gateway comes up normally.
   */
  async connectAll(): Promise<Record<string, { ok: boolean; error?: string; tools?: number }>> {
    const status: Record<string, { ok: boolean; error?: string; tools?: number }> = {};
    await Promise.all(
      this.upstreams
        .filter((u) => u.enabled !== false)
        .map(async (up) => {
          try {
            // EPIC-12: a pooled upstream pre-establishes `pool.min` warm
            // connections instead of the single lazy one.
            if (this.poolCfgFor(up)) {
              const res = await this.initPool(up);
              status[up.name] = res.ok
                ? { ok: true, tools: res.tools }
                : { ok: false, error: res.error };
              if (!res.ok) {
                log("error", `upstream '${up.name}' failed to connect`, {
                  error: res.error,
                });
              }
              return;
            }
            const conn = await this.getConnection(up.name);
            status[up.name] = { ok: true, tools: conn.tools.length };
          } catch (e) {
            log("error", `upstream '${up.name}' failed to connect`, {
              error: errorMessage(e),
            });
            status[up.name] = { ok: false, error: errorMessage(e) };
          }
        }),
    );
    return status;
  }

  listProxiedTools(): ProxiedTool[] {
    return [...this.toolRegistry.values()].flat();
  }

  resolve(exposedName: string): ProxiedTool | undefined {
    return this.listProxiedTools().find((t) => t.exposedName === exposedName);
  }

  /**
   * Call an upstream tool with transparent self-healing (pre-existing
   * behavior, now bounded and documented): if the call fails, the connection
   * is dropped — the token may have expired or the server died — and
   * re-established with freshly-injected credentials before retrying.
   *
   * OAuth (EPIC-03 H3.4): on an oauth2 upstream, an auth-failure error
   * (HTTP 401 / `auth.authErrorPattern`) delegates ONE synchronous refresh to
   * the daemon (mutex'd, single-writer) and the usual self-heal reconnects
   * with the fresh token — the agent never sees the expiry. A known-dead
   * grant (needs_reauth) fails fast with an actionable message instead of
   * hammering the upstream.
   *
   * Bounds: at most MAX_CALL_ATTEMPTS total attempts with linear backoff
   * (250 ms, 500 ms) between them; the last error is rethrown so a dead
   * upstream fails fast instead of looping. Tool-level failures reported
   * in-band by the upstream (MCP `isError` results) are returned, not
   * retried — retries only cover transport/protocol exceptions.
   *
   * `opts.grantTtlMs` (remaining TTL of the covering policy grant, passed by
   * server.ts) clamps any token minted during a (re)connect driven by this
   * call: token_ttl = min(provider ceiling, grant TTL).
   */
  async call(
    exposedName: string,
    args: Record<string, unknown>,
    opts: { grantTtlMs?: number } = {},
  ): Promise<unknown> {
    const ctx: CallContext = { grantTtlMs: opts.grantTtlMs, tool: exposedName };
    // Quick win (hot-reload): a vault mutation since our last check drops
    // every connection — the next call re-injects fresh credentials instead
    // of requiring an agent-session restart.
    this.refreshVaultVersion();
    let tool = this.resolve(exposedName);
    if (!tool) {
      // An oauth2 upstream whose connection was dropped (401 self-heal) loses
      // its tool list until it reconnects. If its grant is dead, the
      // actionable re-auth error must win over a bare "unknown tool";
      // otherwise rebuild the connection on demand and re-resolve.
      const up = this.upstreams.find(
        (u) =>
          u.enabled !== false &&
          u.auth.type === "oauth2" &&
          exposedName.startsWith(`${u.name}__`),
      );
      if (up && this.oauthDaemon) {
        const block = this.oauthDaemon.reauthBlockReason(up.name);
        if (block) throw new Error(block);
        await this.getConnection(up.name, ctx).catch(() => {});
        tool = this.resolve(exposedName);
      }
      if (!tool) throw new Error(`Tool '${exposedName}' not found`);
    }
    const up = this.upstreams.find((u) => u.name === tool.upstream);
    const oauthAuth = up && up.auth.type === "oauth2" ? up.auth : undefined;
    const daemon = oauthAuth ? this.oauthDaemon : undefined;

    // Mejora #6 (idempotent writes): `_sg_idempotency_key` in args is the
    // agent's dedupe handle — stripped before the upstream call. Same key +
    // same args → cached replay (upstream untouched); same key + different
    // args → explicit conflict (keys name intentions, not attempts).
    let idemKey: string | undefined;
    let idemArgsHash: string | undefined;
    let callArgs = args;
    const rawIdem = args[IDEMPOTENCY_ARG];
    if (typeof rawIdem === "string" && rawIdem.length > 0) {
      idemKey = rawIdem;
      callArgs = { ...args };
      delete (callArgs as Record<string, unknown>)[IDEMPOTENCY_ARG];
      idemArgsHash = hashCallArgs(callArgs);
      const lookup = lookupIdempotent(idemKey, idemArgsHash);
      if (lookup.outcome === "replay") {
        audit(this.agentId, "idempotency_replayed", {
          upstream: tool.upstream,
          tool: exposedName,
          key: idemKey,
        });
        return lookup.result;
      }
      if (lookup.outcome === "conflict") {
        throw new Error(
          `idempotency_key_conflict: key '${idemKey}' was already used with DIFFERENT args — ` +
            `pick a new key for a new intention (keys name intentions, not attempts).`,
        );
      }
    }
    // A grant already known to be dead fails fast (no retry loop, no dead
    // token on the wire); reauthBlockReason also recovers the daemon when the
    // human already completed `scopegate auth login`.
    if (daemon) {
      const block = daemon.reauthBlockReason(tool.upstream);
      if (block) throw new Error(block);
    }
    let lastError: unknown;
    let refreshedAfter401 = false;
    let refreshSucceeded = false;
    let absorbed429 = false;

    // Mejora #8: circuit breaker — a dead upstream fails FAST while its
    // circuit is open (the error classifies as upstream_down for the agent);
    // after the reset window a single half-open probe decides.
    const circuit = this.circuitGate(tool.upstream);
    if (circuit !== null) throw new Error(circuit);

    const poolUp = up && this.poolCfgFor(up) ? up : undefined;
    // The pool is normally created by connectAll(); a call landing first
    // initializes it on demand so pooling never silently degrades to lazy.
    if (poolUp && !this.pools.has(poolUp.name)) {
      await this.initPool(poolUp, ctx);
    }
    const pool = poolUp ? this.pools.get(poolUp.name) : undefined;
    for (let attempt = 1; attempt <= MAX_CALL_ATTEMPTS; attempt++) {
      let handle: PoolHandle | null = null;
      try {
        const conn = pool
          ? (handle = await this.checkoutPool(poolUp!, pool, ctx)).conn
          : await this.getConnection(tool.upstream, ctx);
        const result = await conn.client.callTool({
          name: tool.upstreamName,
          arguments: callArgs,
        });
        if (handle && poolUp && pool) this.releasePoolEntry(poolUp, pool, handle, true);
        // M2.2: an in-band auth failure (isError) on a minted/oauth2 upstream
        // invalidates the mint cache and heals with a fresh credential — never
        // stored as idempotent, never counted as a circuit success.
        if (this.isAuthErrorResult(result, up) && !refreshedAfter401) {
          refreshedAfter401 = true;
          if (daemon && oauthAuth) {
            const res = await daemon.refreshNow(tool.upstream);
            if (!res.ok) throw new Error(res.error);
          }
          this.minter.invalidate(tool.upstream);
          throw new Error(
            `upstream auth error (in-band isError) from '${tool.upstream}' — mint cache invalidated, reconnecting with fresh credentials`,
          );
        }
        this.circuitSuccess(tool.upstream);
        if (idemKey && idemArgsHash) {
          // Persist ONLY after a genuine upstream success — a replay never
          // stands in for a result the upstream never produced.
          storeIdempotent(idemKey, tool.upstream, tool.upstreamName, idemArgsHash, result);
        }
        // Mejora #10 (taint): score the RETURN path for prompt injection. A
        // tainted payload marks the agent's session (30 min); in enforce mode
        // cross-upstream writes degrade to human approval while the mark lives.
        const mode = taintMode();
        if (mode !== "off") {
          try {
            const serialized = JSON.stringify(result)?.slice(0, 65_536) ?? "";
            const score = scoreTaint(serialized);
            if (score.score > 0) {
              markTainted(this.agentId, tool.upstream, score);
              audit(this.agentId, "taint_detected", {
                upstream: tool.upstream,
                tool: exposedName,
                score: score.score,
                hits: score.hits.slice(0, 5),
                mode,
              });
            }
          } catch {
            /* taint scoring never breaks a call */
          }
        }
        return result;
      } catch (e) {
        lastError = e;
        if (handle && poolUp && pool) {
          this.releasePoolEntry(poolUp, pool, handle, false);
          handle = null;
        }
        // Mejora #8: absorb ONE upstream 429 server-side — wait the hinted
        // window (≤5 s) instead of propagating the rate-limit to the agent.
        if (!absorbed429 && isRateLimitMessage(errorMessage(e))) {
          absorbed429 = true;
          const waitS = Math.min(parseRetryAfterS(errorMessage(e)) ?? 3, 5);
          log("warn", `upstream rate limit on '${exposedName}' — absorbing a ${waitS}s wait server-side`, {});
          await sleep(waitS * 1000);
        }
        // Auth failure on an oauth2 upstream → ONE synchronous refresh via
        // the daemon; the self-heal below then reconnects with the fresh
        // token (the reconnect rebuilds auth headers from the vault blob the
        // daemon just wrote).
        if (
          daemon &&
          oauthAuth &&
          !refreshedAfter401 &&
          isAuthError(e, oauthAuth.authErrorPattern)
        ) {
          refreshedAfter401 = true;
          const res = await daemon.refreshNow(tool.upstream);
          if (res.ok) {
            refreshSucceeded = true;
            log(
              "info",
              `oauth token refreshed for '${tool.upstream}' after an auth error — retrying once`,
              { recovered: res.recovered === true },
            );
            // EPIC-12: every pooled connection still holds the STALE token —
            // rebuild the pool where the proxy already reconnects.
            if (poolUp && pool) await this.rebuildPool(poolUp, pool, ctx);
          } else if (res.state === "needs_reauth") {
            throw new Error(res.error);
          } else {
            log(
              "warn",
              `oauth refresh for '${tool.upstream}' failed (${res.state}); bounded retry continues`,
              { error: res.error },
            );
          }
        }
        // Self-heal: drop the connection so the next attempt reconnects
        // with freshly-injected credentials.
        void this.connections.get(tool.upstream)?.client.close().catch(() => {});
        this.connections.delete(tool.upstream);
        if (attempt < MAX_CALL_ATTEMPTS) {
          log(
            "warn",
            `call '${exposedName}' failed; reconnecting (attempt ${attempt + 1}/${MAX_CALL_ATTEMPTS})`,
            { error: errorMessage(e) },
          );
          await sleep(CALL_BACKOFF_BASE_MS * attempt);
        }
      }
    }
    log("error", `call '${exposedName}' failed after ${MAX_CALL_ATTEMPTS} attempts`, {
      error: errorMessage(lastError),
    });
    this.circuitFailure(tool.upstream);
    // Still an auth error after a successful refresh + retry: escalate with
    // an actionable pointer instead of a bare 401.
    if (daemon && refreshSucceeded && isAuthError(lastError)) {
      throw new Error(
        `${errorMessage(lastError)} — OAuth call still failing after a token refresh + single retry. Call scopegate_diagnose.`,
      );
    }
    throw lastError;
  }

  /* ------------------------------------------------------------------ */
  /* Mejora #8: circuit breaker                                          */
  /* ------------------------------------------------------------------ */

  /**
   * Gate evaluated before a call. Returns an error message to throw when the
   * circuit is open (fail fast), or null to proceed (closed / half-open probe).
   */
  private circuitGate(upstream: string): string | null {
    const c = this.circuits.get(upstream);
    if (!c || c.state === "closed") return null;
    if (c.state === "open") {
      const elapsed = Date.now() - c.openedAt;
      if (elapsed < UpstreamProxy.CIRCUIT_RESET_MS) {
        return (
          `upstream '${upstream}' circuit OPEN after ${c.failures} consecutive failures — ` +
          `retry in ~${Math.ceil((UpstreamProxy.CIRCUIT_RESET_MS - elapsed) / 1000)}s ` +
          `(upstream_down; a half-open probe decides then)`
        );
      }
      c.state = "half_open"; // one probe decides
      return null;
    }
    return null; // half_open: the probe is already being allowed
  }

  private circuitSuccess(upstream: string): void {
    this.circuits.set(upstream, { state: "closed", failures: 0, openedAt: 0 });
  }

  private circuitFailure(upstream: string): void {
    const c = this.circuits.get(upstream) ?? { state: "closed" as const, failures: 0, openedAt: 0 };
    c.failures += 1;
    if (c.state === "half_open" || c.failures >= UpstreamProxy.CIRCUIT_OPEN_AFTER) {
      c.state = "open";
      c.openedAt = Date.now();
      log("warn", `circuit OPEN on upstream '${upstream}' (${c.failures} consecutive failures)`, {});
    }
    this.circuits.set(upstream, c);
  }

  /** Circuit state per upstream, for scopegate_upstream_health. */
  public circuitReport(): Record<
    string,
    { state: "closed" | "open" | "half_open"; failures: number }
  > {
    const out: Record<string, { state: "closed" | "open" | "half_open"; failures: number }> = {};
    for (const up of this.upstreams.filter((u) => u.enabled !== false)) {
      const c = this.circuits.get(up.name);
      out[up.name] = { state: c?.state ?? "closed", failures: c?.failures ?? 0 };
    }
    return out;
  }

  /* ------------------------------------------------------------------ */
  /* Mejora #8: circuit breaker — end                                    */
  /* ------------------------------------------------------------------ */

  /* ------------------------------------------------------------------ */
  /* Quick win: vault hot-reload                                          */
  /* ------------------------------------------------------------------ */

  private lastVaultVersionCheck: { mtimeMs: number | null } = { mtimeMs: null };

  /**
   * One stat per call: when vault.version changed since the last check,
   * close and drop every connection — they rebuild with fresh credentials
   * (secrets deposited while the gateway runs take effect without restart).
   */
  private refreshVaultVersion(): void {
    let mtimeMs: number | null = null;
    try {
      mtimeMs = fs.statSync(VAULT_VERSION_PATH).mtimeMs;
    } catch {
      mtimeMs = null; // no version file yet — nothing to reload
    }
    if (this.lastVaultVersionCheck.mtimeMs === null && mtimeMs === null) return;
    if (this.lastVaultVersionCheck.mtimeMs === mtimeMs) return;
    const had = this.lastVaultVersionCheck.mtimeMs !== null;
    this.lastVaultVersionCheck.mtimeMs = mtimeMs;
    if (!had) return; // first sight of the file — not a change
    for (const c of this.connections.values()) {
      void c.client.close().catch(() => {});
    }
    this.connections.clear();
    log("info", "vault changed — connections dropped; next calls re-inject fresh credentials (hot-reload)", {});
  }

  /* ------------------------------------------------------------------ */
  /* Quick win: vault hot-reload — end                                   */
  /* ------------------------------------------------------------------ */

  /* ------------------------------------------------------------------ */
  /* M8: env hygiene for spawned children                                 */
  /* ------------------------------------------------------------------ */

  private static readonly SPAWN_ENV_ALLOW = [
    "PATH",
    "HOME",
    "LANG",
    "TMPDIR",
    "TMP",
    "TEMP",
    "SystemRoot",
    "WINDIR",
    "NODE_OPTIONS",
  ];
  private static readonly SPAWN_ENV_SECRET_RE =
    /(SECRET|TOKEN|PASSWORD|PRIVATE_KEY|CREDENTIAL|AUTH)/i;

  /**
   * Minimal, secret-scrubbed env for spawned upstream children (M8): the
   * gateway's whole environment is NO LONGER inherited by default — only the
   * safe base set, LC_* vars, `transport.envPassthrough`, `transport.env`
   * and the auth injections (added by the caller). Anything matching a
   * secret shape is dropped unless explicitly declared. Legacy full-inherit
   * behavior stays available via SCOPEGATE_ENV_PASSTHROUGH=1.
   */
  private buildSpawnEnv(up: UpstreamConfig): Record<string, string> {
    const env: Record<string, string> = {};
    const legacy = process.env.SCOPEGATE_ENV_PASSTHROUGH === "1";
    if (legacy) {
      Object.assign(env, process.env as Record<string, string>);
    } else {
      for (const key of UpstreamProxy.SPAWN_ENV_ALLOW) {
        if (process.env[key] !== undefined) env[key] = process.env[key] as string;
      }
      for (const [key, value] of Object.entries(process.env)) {
        if (key.startsWith("LC_")) env[key] = value as string;
      }
      const passthrough =
        up.transport.kind === "stdio" ? (up.transport.envPassthrough ?? []) : [];
      for (const name of passthrough) {
        if (process.env[name] !== undefined) env[name] = process.env[name] as string;
      }
      const declared = new Set([
        ...Object.keys(up.transport.kind === "stdio" ? (up.transport.env ?? {}) : {}),
        ...passthrough,
      ]);
      for (const key of Object.keys(env)) {
        if (UpstreamProxy.SPAWN_ENV_SECRET_RE.test(key) && !declared.has(key)) {
          delete env[key];
        }
      }
    }
    Object.assign(env, up.transport.kind === "stdio" ? (up.transport.env ?? {}) : {});
    return env;
  }

  /** M14.2: env var a stdio bridge reads its access token from. */
  private accessTokenEnvName(upstreamName: string): string {
    return upstreamName.toUpperCase().replace(/[^A-Z0-9]/g, "_") + "_ACCESS_TOKEN";
  }

  /* ------------------------------------------------------------------ */
  /* M2: proactive mint refresh for stdio connections                     */
  /* ------------------------------------------------------------------ */

  private mintRespawnTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /**
   * After minting for a stdio spawn, schedule the proactive respawn at 80%
   * of the credential's TTL — the connection is rebuilt with a fresh mint
   * BEFORE the old token dies, so long sessions never stall (C2).
   */
  private scheduleMintRefresh(name: string, expiresAt: number): void {
    const existing = this.mintRespawnTimers.get(name);
    if (existing) clearTimeout(existing);
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) return;
    const delay = Math.max(1000, Math.floor(remaining * 0.8));
    const timer = setTimeout(() => {
      void this.respawnMintedConnection(name).catch((e) => {
        log("warn", `proactive mint respawn of '${name}' failed: ${errorMessage(e)} — bounded retry continues`, {});
      });
    }, delay);
    timer.unref?.();
    this.mintRespawnTimers.set(name, timer);
  }

  /**
   * Connect fresh FIRST, swap the connection map, then close the old
   * transport after a grace period (in-flight calls finish on the old one).
   */
  private async respawnMintedConnection(name: string): Promise<void> {
    const up = this.upstreams.find((u) => u.name === name && u.enabled !== false);
    if (!up) return;
    const fresh = await this.connect(up, {});
    const old = this.connections.get(name);
    this.connections.set(name, fresh);
    if (old && old !== fresh) {
      setTimeout(() => {
        void old.client.close().catch(() => {});
      }, 15_000).unref?.();
    }
    log("info", `stdio connection to '${name}' respawned proactively (mint refresh)`, {});
  }

  /**
   * M2.2: true when an MCP RESULT is an in-band auth failure (isError with
   * an auth-shaped message) on a minted/oauth2 upstream — the caller
   * invalidates the mint cache and retries with a fresh credential.
   */
  private isAuthErrorResult(result: unknown, up: UpstreamConfig | undefined): boolean {
    if (result === null || typeof result !== "object") return false;
    if ((result as { isError?: unknown }).isError !== true) return false;
    if (!up) return false;
    const mintedOrOauth = up.auth.type === "oauth2" || this.minter.providerFor(up.auth) !== undefined;
    if (!mintedOrOauth) return false;
    const custom = up.auth.type === "oauth2" ? up.auth.authErrorPattern : undefined;
    const pattern = custom
      ? new RegExp(custom, "i")
      : /401|unauthorized|invalid[_ ]?token|token[_ ]?expired|expired[_ ]?token|forbidden/i;
    let message = "";
    try {
      message = JSON.stringify(result).slice(0, 2048);
    } catch {
      message = String(result);
    }
    return pattern.test(message);
  }

  /* ------------------------------------------------------------------ */
  /* M2: proactive mint refresh — end                                     */
  /* ------------------------------------------------------------------ */

  /**
   * Health check used by scopegate_diagnose. Never rejects. For oauth2
   * upstreams the entry additionally carries the daemon's health snapshot
   * (`oauth`) and — when the grant is dead — the literal human instruction
   * in `action_required` (EPIC-03 H3.6).
   */
  async diagnose(): Promise<Record<string, DiagnoseEntry>> {
    const out: Record<string, DiagnoseEntry> = {};
    for (const up of this.upstreams.filter((u) => u.enabled !== false)) {
      const mode = this.credentialMode(up);
      const poolCfg = this.poolCfgFor(up);
      if (poolCfg) {
        // EPIC-12: probe a checked-out warm connection and expose pool metrics.
        let pool = this.pools.get(up.name);
        if (!pool) {
          await this.initPool(up);
          pool = this.pools.get(up.name)!;
        }
        let handle: PoolHandle | null = null;
        try {
          // The diagnose probe is maintenance, not an agent call: don't count it.
          handle = await this.checkoutPool(up, pool, {}, false);
          const t = await withTimeout(
            handle.conn.client.listTools(),
            CONNECT_TIMEOUT_MS,
            `health probe of upstream '${up.name}'`,
          );
          this.releasePoolEntry(up, pool, handle, true);
          handle = null;
          out[up.name] = {
            ok: true,
            tools: t.tools.length,
            mode,
            pool: this.poolMetrics(pool),
          };
        } catch (e) {
          if (handle) this.releasePoolEntry(up, pool, handle, false);
          out[up.name] = {
            ok: false,
            error: errorMessage(e),
            mode,
            pool: this.poolMetrics(pool),
          };
        }
      } else {
        try {
          const conn = await this.getConnection(up.name);
          // Liveness probe, bounded so a hung server can't stall diagnosis.
          const t = await withTimeout(
            conn.client.listTools(),
            CONNECT_TIMEOUT_MS,
            `health probe of upstream '${up.name}'`,
          );
          out[up.name] = { ok: true, tools: t.tools.length, mode };
        } catch (e) {
          // Drop (and close) the broken connection; the next call to this
          // upstream reconnects with fresh credentials (self-heal).
          void this.connections.get(up.name)?.client.close().catch(() => {});
          this.connections.delete(up.name);
          out[up.name] = { ok: false, error: errorMessage(e), mode };
        }
      }
      if (up.auth.type === "oauth2" && this.oauthDaemon) {
        const health = this.oauthDaemon.statusFor(up.name);
        if (health) {
          out[up.name].oauth = health;
          if (health.state === "needs_reauth") {
            out[up.name].action_required = reauthInstruction(up.name);
          }
        }
      }
    }
    return out;
  }

  async closeAll(): Promise<void> {
    this.oauthDaemon?.stop();
    for (const t of this.mintRespawnTimers.values()) clearTimeout(t);
    this.mintRespawnTimers.clear();
    for (const c of this.connections.values()) {
      await c.client.close().catch(() => {});
    }
    this.connections.clear();
    for (const pool of this.pools.values()) {
      if (pool.timer) clearInterval(pool.timer);
      for (const e of pool.entries) {
        await e.conn.client.close().catch(() => {});
      }
    }
    this.pools.clear();
    this.toolRegistry.clear();
  }
}

/** OAuth blob stored in the vault is JSON: {access_token, refresh_token?, ...} */
function accessTokenFromOAuthBlob(blob: string): string {
  try {
    const parsed = JSON.parse(blob);
    if (parsed.access_token) return parsed.access_token as string;
  } catch {
    /* fall through: treat blob as a raw token */
  }
  return blob;
}
