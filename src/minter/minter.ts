/**
 * Token Minter (EPIC-02): turns long-lived vault secrets into short-lived,
 * scope-minimal credentials. What travels to the upstream is NEVER the
 * long-lived secret deposited in the vault:
 *
 *   - jwt        -> HS256 token signed by the gateway (internal APIs)
 *   - github_app -> App JWT (RS256) exchanged for an installation token
 *   - aws_sts    -> STS session credentials (AssumeRole / GetSessionToken)
 *   - google_sa  -> service-account JWT (RS256) exchanged for an access token
 *
 * Upstreams whose auth is not handled by any provider (bearer / env / oauth2)
 * fall back to pure proxy-injection (plan, risk 8): the long secret leaves
 * the vault only at the outbound hop. That fallback is a declared
 * per-upstream mode (see `modeFor`), never an error.
 *
 * Invariants:
 *   - token_ttl = min(provider ceiling, remaining grant TTL) — a leaked token
 *     expires in minutes and is worth ~zero.
 *   - In-memory cache ONLY (never persisted), keyed by
 *     (upstream, secretRef, scope), renewed at 80% of the token TTL.
 *   - Single-flight: concurrent resolves for the same key share one mint.
 */
import type { UpstreamAuth, UpstreamConfig } from "../config/config.js";
import { Vault } from "../vault/vault.js";
import { JwtProvider } from "./providers/jwt.js";
import { GitHubAppProvider } from "./providers/github-app.js";
import { AwsStsProvider } from "./providers/aws-sts.js";
import { HulyProvider } from "./providers/huly.js";
import { GoogleSaProvider } from "./providers/google-sa.js";

/** Raw minted material. `value` is NEVER logged (fingerprint only). */
export interface MintedCredential {
  /** Raw credential material — used for the audit fingerprint, never logged. */
  value: string;
  /** HTTP headers to set on the outbound hop (http upstreams). */
  headers?: Record<string, string>;
  /** Env vars to inject at child-process spawn (stdio upstreams). */
  env?: Record<string, string>;
  /** Epoch ms after which the gateway treats the credential as dead. */
  expiresAt: number;
}

export interface MintOpts {
  /** Upstream name — used as the token audience/cache key component. */
  upstream: string;
  /** TTL (ms) the token must not exceed — already clamped by the Minter. */
  ttlMs: number;
  /** Agent identity (embedded in tokens where the provider supports it). */
  agentId?: string;
  nowMs?: number; // testability; defaults to Date.now()
}

export interface CredentialProvider {
  /** Provider name, equal to the auth.type it handles. */
  readonly type: string;
  supports(auth: UpstreamAuth): boolean;
  /** Provider-side TTL ceiling in ms, before clamping to the grant TTL. */
  maxTtlMs(auth: UpstreamAuth): number;
  mint(auth: UpstreamAuth, vault: Vault, opts: MintOpts): Promise<MintedCredential>;
}

export interface ResolvedCredential {
  cred: MintedCredential;
  provider: string;
  /** false on cache hit (no provider call happened). */
  minted: boolean;
  /** Effective TTL (ms) granted to this token after clamping. */
  ttlMs: number;
}

/** Vault refs whose values a credential derives from (one audit event each). */
export function secretRefsOf(auth: UpstreamAuth): string[] {
  switch (auth.type) {
    case "bearer":
    case "oauth2":
    case "jwt":
    case "github_app":
    case "aws_sts":
    case "huly":
    case "google_sa":
      return [auth.secretRef];
    case "env":
      return Object.values(auth.env);
    case "composite":
      return [
        ...Object.values(auth.env ?? {}),
        ...(auth.mint ?? []).flatMap((m) => secretRefsOf(m)),
      ];
    case "none":
      return [];
  }
}

interface CacheEntry {
  cred: MintedCredential;
  mintedAt: number;
  expiresAt: number;
}

/** Renewal threshold: a cached token is a hit only while >20% of its life remains. */
const RENEW_AT_FRACTION = 0.8;

function cacheKey(up: UpstreamConfig, scope?: string): string {
  return [up.name, secretRefsOf(up.auth).join(","), scope ?? ""].join(" ");
}

export function defaultProviders(): CredentialProvider[] {
  return [
    new JwtProvider(),
    new GitHubAppProvider(),
    new AwsStsProvider(),
    new HulyProvider(),
    new GoogleSaProvider(),
  ];
}

/** Credential mode of an upstream: minted by a provider, or fallback injection. */
export type CredentialMode = "none" | `minted:${string}` | "fallback:injection";

export class Minter {
  private cache = new Map<string, CacheEntry>();
  private inflight = new Map<string, Promise<MintedCredential>>();

  constructor(
    private vault: Vault,
    private providers: CredentialProvider[] = defaultProviders(),
    private now: () => number = Date.now,
  ) {}

  providerFor(auth: UpstreamAuth): CredentialProvider | undefined {
    return this.providers.find((p) => p.supports(auth));
  }

  /** Declared credential mode for an upstream (surfaced in diagnose). */
  modeFor(auth: UpstreamAuth): CredentialMode {
    if (auth.type === "none") return "none";
    const provider = this.providerFor(auth);
    return provider ? `minted:${provider.type}` : "fallback:injection";
  }

  /**
   * M2.3: drop every cached credential of an upstream (after an auth error).
   * The next resolve mints fresh — a revoked token is never retried as-is.
   */
  invalidate(upstreamName: string): number {
    let removed = 0;
    for (const key of this.cache.keys()) {
      if (key === upstreamName || key.startsWith(upstreamName + " ")) {
        this.cache.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Resolve a credential for an upstream, minting (or reusing from cache) as
   * needed. Returns null when no provider handles the auth type — the caller
   * then applies the static fallback injection itself.
   */
  async resolve(
    up: UpstreamConfig,
    opts: { grantTtlMs?: number; scope?: string; agentId?: string } = {},
  ): Promise<ResolvedCredential | null> {
    const provider = this.providerFor(up.auth);
    if (!provider) return null;

    // Clamp: token_ttl = min(provider ceiling, remaining grant TTL).
    const capMs = provider.maxTtlMs(up.auth);
    const ttlMs =
      opts.grantTtlMs !== undefined ? Math.min(capMs, opts.grantTtlMs) : capMs;

    const key = cacheKey(up, opts.scope);
    const nowMs = this.now();
    const hit = this.cache.get(key);
    if (hit) {
      const total = hit.expiresAt - hit.mintedAt;
      const remaining = hit.expiresAt - nowMs;
      // Renew at 80% of the TTL; also re-mint when the cached token would
      // outlive the current clamp (a narrower grant must narrow the token).
      if (remaining > (1 - RENEW_AT_FRACTION) * total && hit.expiresAt <= nowMs + ttlMs) {
        return { cred: hit.cred, provider: provider.type, minted: false, ttlMs };
      }
    }

    // Single-flight: concurrent resolves for the same key share one mint.
    let flight = this.inflight.get(key);
    if (!flight) {
      flight = provider
        .mint(up.auth, this.vault, {
          upstream: up.name,
          ttlMs,
          agentId: opts.agentId,
          nowMs,
        })
        .then((cred) => {
          this.cache.set(key, { cred, mintedAt: this.now(), expiresAt: cred.expiresAt });
          return cred;
        })
        .finally(() => this.inflight.delete(key));
      this.inflight.set(key, flight);
    }
    const cred = await flight;
    return { cred, provider: provider.type, minted: true, ttlMs };
  }
}
