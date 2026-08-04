/**
 * Machine-readable error taxonomy for agents (mejora #8).
 *
 * Every failure the gateway surfaces to the agent is classified into a small,
 * closed set of kinds with a recommended next action — the decision an agent
 * otherwise burns 2-3 turns guessing: retry? renew? request a capability?
 * escalate to a human? give up?
 *
 * The envelope is JSON (parsed by the agent), not prose:
 *   {
 *     error: true,
 *     kind: expired_grant | missing_scope | policy_denied | rate_limited
 *         | upstream_down | auth_broken,
 *     message: string,            // actionable, one line
 *     retry_after_s?: number,     // rate_limited / upstream_down only
 *     next_action: renew | request_capability | wait | diagnose | human,
 *     next_step: string           // literal instruction for the agent
 *   }
 *
 * Classification is deliberately heuristic and fail-safe: an unclassifiable
 * failure degrades to `upstream_down` + `diagnose` (the agent runs
 * scopegate_diagnose and gets the full picture) — never to a wrong confident
 * answer.
 */

export type AgentErrorKind =
  | "expired_grant"
  | "missing_scope"
  | "policy_denied"
  | "rate_limited"
  | "upstream_down"
  | "auth_broken";

export type AgentNextAction =
  | "renew"
  | "request_capability"
  | "wait"
  | "diagnose"
  | "human";

export interface AgentErrorEnvelope {
  error: true;
  kind: AgentErrorKind;
  message: string;
  /** The authoritative policy/denial code when one exists (EPIC-06 grant
   *  lifecycle codes included) — machine-readable beyond the coarse `kind`. */
  code?: string;
  retry_after_s?: number;
  next_action: AgentNextAction;
  next_step: string;
}

const NETWORK_PATTERNS = [
  /econnrefused/i,
  /econnreset/i,
  /enotfound/i,
  /eai_again/i,
  /socket hang up/i,
  /fetch failed/i,
  /network/i,
  /timed?\s?out/i,
  /timeout/i,
  /connect.*fail/i,
  /upstream.*(down|unreachable|unavailable)/i,
  /503/,
  /502/,
  /504/,
];

const AUTH_PATTERNS = [
  /\b401\b/,
  /\b403\b/,
  /unauthorized/i,
  /forbidden/i,
  /invalid[_ ]?(token|credential|api.?key)/i,
  /expired[_ ]?token/i,
  /reauth/i,
  /auth.*(fail|broken|error)/i,
  /access token/i,
];

/** Pull "retry after N seconds" out of an error message when present. */
export function parseRetryAfterS(message: string): number | undefined {
  const m = message.match(/retry[- ]after[:\s]+(\d{1,5})\s?s?/i)
    ?? message.match(/(\d{1,5})\s*(s|sec|seconds)\b.*(?:retry|wait|back\s?off)/i)
    ?? message.match(/retry\s+in\s+(\d{1,5})/i);
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

/** True when the error looks like an upstream HTTP 429 / rate limit. */
export function isRateLimitMessage(message: string): boolean {
  return /\b429\b|rate.?limit|too many requests|throttl/i.test(message);
}

/** True when the error looks like an upstream auth failure (401/403 class). */
export function isAuthMessage(message: string): boolean {
  return AUTH_PATTERNS.some((p) => p.test(message));
}

/** True when the error looks like a network/upstream availability problem. */
export function isNetworkMessage(message: string): boolean {
  return NETWORK_PATTERNS.some((p) => p.test(message));
}

function envelope(
  kind: AgentErrorKind,
  message: string,
  next_action: AgentNextAction,
  next_step: string,
  retry_after_s?: number,
  code?: string,
): AgentErrorEnvelope {
  return {
    error: true,
    kind,
    message,
    ...(code !== undefined && code !== "" ? { code } : {}),
    ...(retry_after_s !== undefined ? { retry_after_s } : {}),
    next_action,
    next_step,
  };
}

/**
 * Classify a thrown error (or a denial message) into the agent envelope.
 * `hint.code`, when present (policy decision codes like ceiling_blocked),
 * wins over message heuristics.
 */
export function classifyError(input: {
  message: string;
  code?: string;
}): AgentErrorEnvelope {
  const { message } = input;
  const code = input.code ?? "";

  // Policy decision codes first (they are authoritative, not heuristic).
  if (code === "ceiling_blocked" || code === "no_rule" || code === "policy_denied") {
    return envelope(
      "policy_denied",
      message,
      "human",
      "Hard policy denial — do NOT retry or broaden scope. Call scopegate_propose_policy with a justification, or ask a human to review policies.yaml.",
      undefined,
      code,
    );
  }
  // EPIC-06 grant lifecycle codes: the grant is gone (consumed, revoked,
  // raced out of existence) or its audience excludes the caller — the way
  // back is always an explicit, attributed re-request.
  if (
    code === "grant_used" ||
    code === "grant_revoked" ||
    code === "grant_expired" ||
    code === "grant_audience"
  ) {
    return envelope(
      "missing_scope",
      message,
      "request_capability",
      "Call scopegate_request_capability with the SAME capability (never broader) — the previous grant is gone for good.",
      undefined,
      code,
    );
  }
  if (code === "capability_rate_limited" || isRateLimitMessage(message)) {
    return envelope(
      "rate_limited",
      message,
      "wait",
      "Back off and retry after the indicated window. Do NOT loop requests.",
      parseRetryAfterS(message),
    );
  }
  if (code === "missing_scope" || /not granted/i.test(message)) {
    return envelope(
      "missing_scope",
      message,
      "request_capability",
      "Call scopegate_request_capability with the SAME capability (never broader). If it escalates, a human must approve.",
    );
  }
  if (code === "expired_grant" || /grant.*expired|expired.*grant/i.test(message)) {
    return envelope(
      "expired_grant",
      message,
      "renew",
      "The grant expired. Call scopegate_renew_capability with the grant_id (or scopegate_request_capability for a fresh one).",
    );
  }
  if (code === "auth_broken" || isAuthMessage(message)) {
    return envelope(
      "auth_broken",
      message,
      "diagnose",
      "Upstream authentication is broken. Call scopegate_diagnose for the self-repair path (or re-auth instruction for the human).",
    );
  }
  if (isNetworkMessage(message)) {
    return envelope(
      "upstream_down",
      message,
      "wait",
      "Upstream is unreachable/failing. Wait briefly and retry once; if it persists, call scopegate_diagnose.",
      parseRetryAfterS(message) ?? 5,
    );
  }
  // Fail-safe default: never a confident wrong answer.
  return envelope(
    "upstream_down",
    message,
    "diagnose",
    "Unclassified failure — call scopegate_diagnose for the full health picture before deciding.",
  );
}
