/**
 * Scheduling math for the OAuth refresh daemon (EPIC-03). Pure functions,
 * exported for unit tests; the daemon wires them to real timers.
 *
 *   - Proactive renewal fires at 80% of the REMAINING TTL, with ±10% jitter
 *     (thundering-herd protection when many upstreams expire together).
 *   - Retryable refresh failures (network/5xx/429) back off exponentially
 *     from 5 s up to a 15 min ceiling, also jittered, and trip a circuit
 *     breaker after 5 consecutive failures.
 */

/** Fraction of the remaining TTL after which a token is renewed. */
export const REFRESH_AT_FRACTION = 0.8;
/** Symmetric jitter applied to every scheduled delay (±10%). */
export const JITTER_FRACTION = 0.1;
/** Never schedule a tick tighter than this (avoids busy loops at startup). */
export const MIN_SCHEDULE_MS = 250;
/** Exponential backoff base for retryable refresh failures. */
export const BACKOFF_BASE_MS = 5_000;
/** Backoff ceiling. */
export const BACKOFF_MAX_MS = 15 * 60_000;
/** Consecutive retryable failures before the circuit breaker opens. */
export const CIRCUIT_BREAKER_THRESHOLD = 5;

function jitter(random: () => number): number {
  return 1 + (random() * 2 - 1) * JITTER_FRACTION;
}

/**
 * Delay until the next proactive refresh for a token with `remainingMs` of
 * life left: 80% of the remaining TTL, jittered, floored at MIN_SCHEDULE_MS
 * (an already-expired token is renewed almost immediately, never blocking
 * gateway startup).
 */
export function refreshDelayMs(
  remainingMs: number,
  random: () => number = Math.random,
): number {
  return Math.max(
    MIN_SCHEDULE_MS,
    Math.floor(remainingMs * REFRESH_AT_FRACTION * jitter(random)),
  );
}

/**
 * Backoff delay after `consecutiveFailures` (1-based) retryable refresh
 * failures: 5 s, 10 s, 20 s, … capped at 15 min, jittered.
 */
export function backoffDelayMs(
  consecutiveFailures: number,
  random: () => number = Math.random,
): number {
  const exp = BACKOFF_BASE_MS * 2 ** Math.max(0, consecutiveFailures - 1);
  return Math.floor(Math.min(BACKOFF_MAX_MS, exp) * jitter(random));
}
