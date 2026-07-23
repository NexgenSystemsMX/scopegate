/**
 * OAuth Refresh Daemon (EPIC-03): keeps every `oauth2` upstream's access
 * token alive so an agent session never sees an expiry (the "Notion 4 h"
 * case). Runs in-process inside the gateway; the proxy owns its lifecycle.
 *
 * Invariants:
 *   - SINGLE-WRITER: this daemon is the ONLY writer of OAuth blobs in the
 *     vault (the proxy never writes; `scopegate auth login` writes from its
 *     own process and signals completion by deleting reauth-required.json).
 *   - MUTEX PER UPSTREAM: at most one refresh in flight per upstream —
 *     refresh tokens ROTATE, so a second use of a stale one can invalidate
 *     the whole grant family (Auth0-style). The scheduler's tick and the
 *     proxy's 401-driven refresh share the same queue.
 *   - PROACTIVE: each upstream is scheduled to renew at 80% of its remaining
 *     TTL (±10% jitter); retryable failures back off exponentially (5 s →
 *     15 min) and trip a circuit breaker after 5 consecutive failures.
 *   - NO RETRY LOOPS on invalid_grant: the grant is dead — mark
 *     needs_reauth, signal the human (reauth-required.json + stderr + audit)
 *     and fail subsequent calls with an actionable message until the human
 *     re-authorizes out-of-band.
 *   - Timers are unref'd: the daemon never keeps a process alive, and
 *     start() never touches the network (gateway startup stays non-blocking).
 */
import type { UpstreamConfig } from "../config/config.js";
import { Vault } from "../vault/vault.js";
import { audit, type AuditKind } from "../audit/log.js";
import { log, errorMessage } from "../gateway/proxy.js";
import {
  parseOAuthBlob,
  serializeOAuthBlob,
  type OAuthTokenBlob,
} from "./types.js";
import { postRefreshGrant, RefreshError } from "./refresh.js";
import {
  refreshDelayMs,
  backoffDelayMs,
  CIRCUIT_BREAKER_THRESHOLD,
} from "./scheduler.js";
import {
  readReauthRequired,
  writeReauthRequired,
  type ReauthRequired,
} from "./reauth.js";

export type OAuthDaemonState =
  | "ok"
  | "backoff"
  | "circuit_open"
  | "needs_reauth"
  | "unknown_expiry";

export interface OAuthHealth {
  state: OAuthDaemonState;
  /** Seconds of access-token life left (null when unknown). */
  token_expires_in_s: number | null;
  consecutive_failures: number;
  last_refresh_at?: string;
  next_refresh_in_s?: number;
}

export interface RefreshResult {
  ok: boolean;
  state: OAuthDaemonState;
  /** Actionable message when !ok. */
  error?: string;
  /** True when the upstream recovered from needs_reauth out-of-band. */
  recovered?: boolean;
}

/** Literal instruction the human needs; also surfaced verbatim by diagnose. */
export function reauthInstruction(upstream: string): string {
  return `run in your terminal: scopegate auth login ${upstream}`;
}

function reauthMessage(upstream: string): string {
  return (
    `upstream '${upstream}' requires human re-authorization — ` +
    `${reauthInstruction(upstream)} (then call scopegate_diagnose)`
  );
}

interface UpstreamState {
  state: OAuthDaemonState;
  consecutiveFailures: number;
  lastRefreshAt?: number;
  nextRefreshAt?: number;
  timer?: NodeJS.Timeout;
  /** Single in-flight refresh; concurrent callers join this promise. */
  inflight?: Promise<RefreshResult>;
  /** stderr announcement happens once per needs_reauth episode. */
  reauthAnnounced?: boolean;
}

export interface OAuthRefreshDaemonDeps {
  vault: Vault;
  upstreams: UpstreamConfig[];
  agentId?: string;
  /** Injectable for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Injectable jitter source for deterministic tests. */
  random?: () => number;
}

export class OAuthRefreshDaemon {
  private vault: Vault;
  private upstreams: UpstreamConfig[];
  private agentId: string;
  private fetchImpl: typeof fetch;
  private random: () => number;
  private states = new Map<string, UpstreamState>();
  private started = false;

  constructor(deps: OAuthRefreshDaemonDeps) {
    this.vault = deps.vault;
    // Same array reference the proxy holds: upstreams registered at runtime
    // (scopegate_register_upstream mutates cfg.upstreams) become visible here.
    this.upstreams = deps.upstreams;
    this.agentId = deps.agentId ?? "gateway";
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.random = deps.random ?? Math.random;
  }

  /**
   * Non-blocking: reads local state (vault + reauth file) and arms timers.
   * Never awaits the network — a dead authorization server cannot stall
   * gateway startup.
   */
  start(): void {
    if (this.started) return;
    this.started = true;
    const reauth = readReauthRequired();
    for (const up of this.oauthUpstreams()) {
      const st = this.stateFor(up.name);
      if (reauth && reauth.upstream === up.name) {
        st.state = "needs_reauth";
        this.announceReauth(up.name, reauth);
        continue;
      }
      const blob = this.readBlob(up);
      if (!this.isRefreshable(blob)) {
        st.state = "unknown_expiry";
        continue;
      }
      this.schedule(up.name, st);
    }
  }

  /** Cancel every timer (gateway shutdown / SIGTERM path via closeAll). */
  stop(): void {
    this.started = false;
    for (const st of this.states.values()) this.clearTimer(st);
  }

  /**
   * Synchronous refresh used by the proxy's 401 hook and by the scheduler.
   * Mutex'd per upstream: concurrent callers share one endpoint call, and the
   * blob is re-read INSIDE the critical section (rotation safety).
   */
  refreshNow(upstream: string): Promise<RefreshResult> {
    const st = this.stateFor(upstream);
    if (st.inflight) return st.inflight;
    const p = this.doRefresh(upstream, st).finally(() => {
      st.inflight = undefined;
    });
    st.inflight = p;
    return p;
  }

  /**
   * Actionable block reason when the upstream awaits human re-auth, else
   * null. Syncs with the on-disk signal first: if the human completed
   * `scopegate auth login` (file deleted), the daemon recovers here.
   */
  reauthBlockReason(upstream: string): string | null {
    const st = this.stateFor(upstream);
    if (st.state !== "needs_reauth") return null;
    this.syncReauth(upstream, st);
    return st.state === "needs_reauth" ? reauthMessage(upstream) : null;
  }

  needsReauth(upstream: string): boolean {
    return this.reauthBlockReason(upstream) !== null;
  }

  /** Health snapshot for scopegate_diagnose. Never rejects, never throws. */
  statusFor(upstream: string): OAuthHealth | undefined {
    const up = this.upstreams.find(
      (u) => u.name === upstream && u.auth.type === "oauth2",
    );
    if (!up) return undefined;
    const st = this.stateFor(upstream);
    try {
      this.syncReauth(upstream, st);
    } catch {
      /* best effort — diagnose must not fail */
    }
    const blob = this.readBlob(up);
    return {
      state: st.state,
      token_expires_in_s:
        blob?.expires_at !== undefined
          ? Math.max(0, Math.round((blob.expires_at - Date.now()) / 1000))
          : null,
      consecutive_failures: st.consecutiveFailures,
      ...(st.lastRefreshAt !== undefined
        ? { last_refresh_at: new Date(st.lastRefreshAt).toISOString() }
        : {}),
      ...(st.nextRefreshAt !== undefined
        ? {
            next_refresh_in_s: Math.max(
              0,
              Math.round((st.nextRefreshAt - Date.now()) / 1000),
            ),
          }
        : {}),
    };
  }

  status(): Record<string, OAuthHealth> {
    const out: Record<string, OAuthHealth> = {};
    for (const up of this.oauthUpstreams()) {
      const h = this.statusFor(up.name);
      if (h) out[up.name] = h;
    }
    return out;
  }

  /* ------------------------------------------------------------------ */

  private oauthUpstreams(): UpstreamConfig[] {
    return this.upstreams.filter(
      (u) => u.enabled !== false && u.auth.type === "oauth2",
    );
  }

  private stateFor(name: string): UpstreamState {
    let st = this.states.get(name);
    if (!st) {
      st = { state: "ok", consecutiveFailures: 0 };
      this.states.set(name, st);
    }
    return st;
  }

  private findUpstream(name: string): UpstreamConfig | undefined {
    return this.upstreams.find((u) => u.name === name && u.auth.type === "oauth2");
  }

  private readBlob(up: UpstreamConfig): OAuthTokenBlob | null {
    if (up.auth.type !== "oauth2") return null;
    try {
      return parseOAuthBlob(this.vault.get(up.auth.secretRef));
    } catch {
      return null;
    }
  }

  /** A blob the daemon can actually renew: parseable + expiry + grant. */
  private isRefreshable(
    blob: OAuthTokenBlob | null,
  ): blob is OAuthTokenBlob & { expires_at: number; refresh_token: string } {
    return (
      blob !== null &&
      blob.expires_at !== undefined &&
      typeof blob.refresh_token === "string" &&
      blob.refresh_token.length > 0
    );
  }

  private clearTimer(st: UpstreamState): void {
    if (st.timer) {
      clearTimeout(st.timer);
      st.timer = undefined;
    }
    st.nextRefreshAt = undefined;
  }

  private schedule(name: string, st: UpstreamState, delayOverride?: number): void {
    this.clearTimer(st);
    if (!this.started) return;
    let delay = delayOverride;
    if (delay === undefined) {
      const up = this.findUpstream(name);
      const blob = up ? this.readBlob(up) : null;
      if (!up || !this.isRefreshable(blob)) {
        if (st.state === "ok") st.state = "unknown_expiry";
        return;
      }
      delay = refreshDelayMs(blob.expires_at - Date.now(), this.random);
    }
    st.nextRefreshAt = Date.now() + delay;
    st.timer = setTimeout(() => {
      st.timer = undefined;
      st.nextRefreshAt = undefined;
      void this.refreshNow(name).catch(() => {});
    }, delay);
    // A daemon timer must never keep the host process alive.
    st.timer.unref?.();
  }

  private async doRefresh(
    name: string,
    st: UpstreamState,
  ): Promise<RefreshResult> {
    const up = this.findUpstream(name);
    if (!up || up.auth.type !== "oauth2") {
      return {
        ok: false,
        state: st.state,
        error: `upstream '${name}' is not an oauth2 upstream`,
      };
    }

    if (st.state === "needs_reauth") {
      this.syncReauth(name, st);
      if (st.state === "needs_reauth") {
        return { ok: false, state: st.state, error: reauthMessage(name) };
      }
      // Human re-authorized out-of-band; the fresh blob is already in the
      // vault — no endpoint call needed.
      return { ok: true, state: st.state, recovered: true };
    }

    if (st.state === "circuit_open") {
      // External poke (401-driven refresh): allow one manual attempt.
      st.state = "ok";
      st.consecutiveFailures = 0;
    }

    const blob = this.readBlob(up);
    if (!this.isRefreshable(blob)) {
      st.state = "unknown_expiry";
      return {
        ok: false,
        state: st.state,
        error: `OAuth blob '${up.auth.secretRef}' is missing or has no refresh_token/expires_at — nothing to refresh`,
      };
    }

    try {
      const tokens = await postRefreshGrant(blob, this.fetchImpl);
      const rotated =
        typeof tokens.refresh_token === "string" &&
        tokens.refresh_token !== blob.refresh_token;
      const expiresAt = Date.now() + tokens.expires_in * 1000;
      const next: OAuthTokenBlob = {
        ...blob,
        v: 1,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token ?? blob.refresh_token,
        expires_at: expiresAt,
        obtained_at: Date.now(),
        scope: tokens.scope ?? blob.scope,
      };
      // Atomic persist (vault.set writes tmp + rename): the rotated refresh
      // token replaces the old one on disk in a single write.
      this.vault.set(up.auth.secretRef, serializeOAuthBlob(next));
      st.consecutiveFailures = 0;
      st.state = "ok";
      st.lastRefreshAt = Date.now();
      // Audit metadata only — NEVER token values.
      this.safeAudit("token_refreshed", {
        upstream: name,
        expires_at: new Date(expiresAt).toISOString(),
        rotated,
      });
      this.schedule(name, st);
      return { ok: true, state: "ok" };
    } catch (e) {
      if (e instanceof RefreshError && e.kind === "invalid_grant") {
        this.markNeedsReauth(name, st, e.message);
        return { ok: false, state: "needs_reauth", error: reauthMessage(name) };
      }
      st.consecutiveFailures += 1;
      this.safeAudit("token_refresh_failed", {
        upstream: name,
        error: errorMessage(e),
        consecutive_failures: st.consecutiveFailures,
      });
      const fatal = e instanceof RefreshError && e.kind === "fatal";
      if (fatal || st.consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD) {
        st.state = "circuit_open";
        this.clearTimer(st);
        log(
          "error",
          `oauth refresh circuit open for '${name}' after ${st.consecutiveFailures} consecutive failure(s) — no more retries until a call or diagnose pokes it`,
        );
      } else {
        st.state = "backoff";
        const delay = backoffDelayMs(st.consecutiveFailures, this.random);
        log("warn", `oauth refresh for '${name}' failed; backing off`, {
          error: errorMessage(e),
          consecutive_failures: st.consecutiveFailures,
          retry_in_ms: delay,
        });
        this.schedule(name, st, delay);
      }
      return { ok: false, state: st.state, error: errorMessage(e) };
    }
  }

  private markNeedsReauth(name: string, st: UpstreamState, reason: string): void {
    st.state = "needs_reauth";
    st.consecutiveFailures = 0;
    this.clearTimer(st);
    const entry: ReauthRequired = {
      upstream: name,
      reason,
      since: new Date().toISOString(),
    };
    try {
      writeReauthRequired(entry);
    } catch (e) {
      log("error", `cannot write reauth-required.json`, { error: errorMessage(e) });
    }
    this.safeAudit("oauth_reauth_required", { upstream: name, reason });
    this.announceReauth(name, entry);
  }

  private announceReauth(name: string, entry: ReauthRequired): void {
    const st = this.stateFor(name);
    if (st.reauthAnnounced) return;
    st.reauthAnnounced = true;
    log("error", `upstream '${name}' needs human re-authorization`, {
      reason: entry.reason,
      since: entry.since,
      action: reauthInstruction(name),
    });
  }

  /**
   * Recovery path: the needs_reauth signal lives on disk so that
   * `scopegate auth login` — a SEPARATE process — can clear it. When the file
   * no longer names this upstream, pull the freshly-written blob from disk
   * into the live vault (the login process wrote vault.enc; this process's
   * vault cache is stale) and resume the scheduler.
   */
  private syncReauth(name: string, st: UpstreamState): void {
    if (st.state !== "needs_reauth") return;
    const file = readReauthRequired();
    if (file && file.upstream === name) return;
    const up = this.findUpstream(name);
    if (up && up.auth.type === "oauth2") {
      try {
        const fresh = Vault.open().get(up.auth.secretRef);
        this.vault.set(up.auth.secretRef, fresh);
      } catch (e) {
        log("warn", `re-auth signal cleared for '${name}' but the vault blob could not be reloaded`, {
          error: errorMessage(e),
        });
      }
    }
    st.state = "ok";
    st.consecutiveFailures = 0;
    st.reauthAnnounced = false;
    this.schedule(name, st);
    log("info", `oauth re-auth completed for '${name}' — scheduler resumed`);
  }

  /** Best-effort audit: a broken audit log must not wedge the daemon loop. */
  private safeAudit(kind: AuditKind, detail: Record<string, unknown>): void {
    try {
      audit(this.agentId, kind, detail);
    } catch (e) {
      log("error", `oauth daemon could not write audit event '${kind}'`, {
        error: errorMessage(e),
      });
    }
  }
}
