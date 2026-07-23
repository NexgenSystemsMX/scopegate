/**
 * Sliding-window rate limiter for `scopegate_request_capability` (EPIC-04
 * H-04.7). Anti-flood/anti-loop protection: an injected or buggy agent can
 * no longer hammer the policy engine with unlimited requests.
 *
 * Counters live in memory only — the risk being mitigated is a flood within
 * a session, not a historical allowance. The window spec comes from
 * `limits.rate_limit` (per-agent wins over global); default "30/m".
 */

export interface RateWindow {
  count: number;
  windowMs: number;
}

/** Parse "<n>/<s|m|h>" strictly — invalid specs throw (fail-closed config). */
export function parseRateWindow(spec: string): RateWindow {
  const m = /^(\d+)\/(s|m|h)$/.exec(spec.trim());
  if (!m) {
    throw new Error(
      `Invalid rate_limit '${spec}' — expected '<n>/s', '<n>/m' or '<n>/h' (e.g. '30/m').`,
    );
  }
  const n = parseInt(m[1], 10);
  if (n <= 0) throw new Error(`Invalid rate_limit '${spec}' — count must be > 0.`);
  return {
    count: n,
    windowMs: m[2] === "s" ? 1_000 : m[2] === "m" ? 60_000 : 3_600_000,
  };
}

export const DEFAULT_RATE_LIMIT = "30/m";

export class RateLimiter {
  private hits: number[] = [];

  constructor(private window: RateWindow) {}

  /**
   * Record an attempt and tell whether it is within the window. Attempts are
   * counted whether or not the underlying request ends up allowed: the point
   * is to bound request FREQUENCY.
   */
  check(now: number = Date.now()): { allowed: boolean; retryAfterMs?: number } {
    const floor = now - this.window.windowMs;
    this.hits = this.hits.filter((t) => t > floor);
    if (this.hits.length >= this.window.count) {
      return {
        allowed: false,
        retryAfterMs: this.hits[0] + this.window.windowMs - now,
      };
    }
    this.hits.push(now);
    return { allowed: true };
  }
}
