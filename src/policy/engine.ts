/**
 * Policy Engine: decides whether an agent gets a capability, with what TTL.
 *
 * Capability string format:  <upstream>:<action>:<resource>
 *   e.g.  github:write:easyorder/*   aws:deploy:staging   notion:read:*
 * Tool calls map to  <upstream>:call:<toolName>  when no finer scope applies.
 *
 * Security asymmetry (core of the model):
 *   - Agents can REQUEST capabilities and PROPOSE new policy rules.
 *   - Agents can NEVER auto-approve anything not already matched by an
 *     auto_approve rule. Escalations require a human (approval queue in
 *     approvals.ts, or editing policies.yaml / accepting a pending proposal).
 *
 * Sprint 2 (EPIC-04) additions:
 *   - HARD LIMITS (`limits`, global and per-agent — per-agent wins):
 *     `deny` globs are evaluated BEFORE any auto_approve rule (fail-closed),
 *     `max_ttl` clamps every grant, `rate_limit` throttles
 *     scopegate_request_capability, `approval_ttl` sets approval expiry.
 *   - Persistent grants with UUIDs (grants.ts) — they survive restarts.
 *   - Local human-approval flow for `require: human_approval` (approvals.ts):
 *     pending request → human decision → one-shot grant materialized here.
 *   - Hot-reload of policies.yaml with last-good semantics (startWatching).
 *   - propose_policy 2.0: glob/TTL validation, field allowlist, dedup, and a
 *     `conflicts_with_limits` lint. policies.yaml stays byte-identical.
 *   - Strict TTL parsing: broken HUMAN config fails closed (load-time schema
 *     validation + config_error decisions), never silently falls back.
 *
 * Sprint 4 (EPIC-10) additions:
 *   - Optional TEAM POLICY layer (applyTeamPolicy): a signature-verified team
 *     policy pulled from ScopeGate Cloud, applied as a RESTRICTIVE
 *     INTERSECTION over the local policy and evaluated live at request time.
 *     A capability is granted only when BOTH policies allow it; the team
 *     layer can never make the local policy more permissive (deny globs:
 *     union; max_ttl/rule TTLs: min; a team `require: human_approval` rule
 *     overrides local auto-approve; team silence on a capability is a deny).
 *     With no team layer installed the engine behaves exactly as before
 *     (local-first: the gateway works 100% without cloud).
 */
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import picomatch from "picomatch";
import {
  POLICIES_PATH,
  PENDING_POLICIES_PATH,
  ensureDir,
} from "../config/config.js";
import { audit, type AuditKind } from "../audit/log.js";
import { GrantStore, type Grant } from "./grants.js";
import { matchesWhen } from "./when.js";
import {
  LeaseStore,
  DEFAULT_LEASE_TOTAL_MS,
  DEFAULT_LEASE_MAX_WRITES,
  type Lease,
} from "./leases.js";
import {
  createApprovalRequest,
  readPendingRequests,
  readDecisions,
  updatePendingStatuses,
  expireStaleIntents,
  pendingIntentFor,
  storeIntentResult,
  DEFAULT_APPROVAL_TTL_MS,
  type ApprovalRequest,
  type ApprovalStatus,
  type ApprovalIntent,
} from "./approvals.js";
import {
  RateLimiter,
  parseRateWindow,
  DEFAULT_RATE_LIMIT,
} from "./ratelimit.js";
import { REDACT_CATEGORIES } from "./redact.js";

export type { Grant } from "./grants.js";

export interface PolicyRule {
  match: string; // glob over capability string
  auto_approve?: boolean;
  ttl?: string; // "15m", "1h"
  require?: "human_approval";
  /** Redaction categories applied to proxied responses under this rule. */
  redact?: string[];
  /**
   * M6: optional arg guard — the rule matches ONLY when the tool call's args
   * satisfy every entry (string values as picomatch globs, non-strings by
   * strict equality). Absent = matches always. A non-matching `when` means
   * the RULE doesn't match (evaluation continues first-match-wins) — `when`
   * only ever RESTRICTS, it can never widen what plain `match` would allow.
   */
  when?: Record<string, string | number | boolean>;
}

/** Hard, non-negotiable limits. Global and per-agent; the per-agent wins. */
export interface PolicyLimits {
  /** Absolute ceiling for every grant TTL (e.g. "1h"). */
  max_ttl?: string;
  /** Capability globs denied BEFORE any auto_approve rule is evaluated. */
  deny?: string[];
  /** Sliding-window limit for scopegate_request_capability (e.g. "30/m"). */
  rate_limit?: string;
  /** Absolute ceiling for a task-lease total duration (mejora #1; e.g. "4h"). */
  max_lease_total?: string;
  /** Max bytes of a proxied payload returned inline (mejora #7; default 16384). */
  max_inline_bytes?: number;
  /** Lifetime of a pending human-approval request (default 10m). */
  approval_ttl?: string;
}

export interface AgentPolicy {
  default_ttl?: string;
  limits?: PolicyLimits;
  capabilities: PolicyRule[];
}

export interface PoliciesFile {
  version: 1;
  limits?: PolicyLimits;
  agents: Record<string, AgentPolicy>;
}

/**
 * M10 (inverted default): capabilities under these prefixes escalate to human
 * approval BY DEFAULT — a matching auto_approve rule must be written
 * explicitly to lift it. Materializing a vault secret into a file
 * (`vault:inject:<ref>`) widens the egress surface, so silence is an
 * escalation, never a plain no_rule denial.
 */
export const DEFAULT_APPROVAL_PREFIXES = ["vault:inject:"];

/** Provenance of an installed team policy layer (EPIC-10). */
export interface TeamPolicyMeta {
  /** Server-issued, monotonically increasing policy version. */
  version: number;
  /** ISO timestamp of when the gateway fetched/verified this version. */
  fetchedAt: string;
}

export type DenyCode =
  | "no_policy"
  | "no_rule"
  | "ceiling_blocked"
  | "invalid_ttl"
  | "config_error"
  /** Lease unusable for the request (dead, unknown, or out of scope). */
  | "lease_error"
  /** EPIC-06: the requested audience is not allowed (org is admin-only, or an
   *  undeclared identity). */
  | "audience_denied";

export type Decision =
  | { allow: true; ttlMs: number; rule: string }
  | {
      allow: false;
      reason: string;
      code?: DenyCode;
      escalation?: "human_approval";
      /** Present when escalation created/found a pending approval request. */
      approvalId?: string;
      approvalExpiresAt?: number;
    };

/**
 * Mejora #3: result of the read-only policy preflight (`evaluate`). Mirrors
 * the Decision semantics without issuing anything.
 */
export interface Evaluation {
  decision: "allow" | "needs_approval" | "deny";
  /** "allow": effective TTL after every clamp (rule/default, max_ttl, team). */
  ttl_ms?: number;
  /** The matched rule glob, when one exists. */
  rule?: string;
  /** Denial classification (same codes as Decision). */
  code?: DenyCode;
  /** "needs_approval": which layer demands the human. */
  via?: "local_policy" | "team_policy";
  /** True for hard-limit denials (deny globs — non-negotiable). */
  hard?: boolean;
  /** True when a live grant already covers the capability. */
  covered_by_existing_grant?: boolean;
  reason: string;
}

/** Mejora #3: the agent-facing digest from `policySummary()`. */
export interface PolicySummary {
  agentId: string;
  agent_found: boolean;
  default_ttl?: string;
  /** Rule globs with auto_approve for this agent. */
  auto_approve: string[];
  /** Rule globs that escalate to a human. */
  requires_approval: string[];
  /** Hard-limit deny globs (non-negotiable). */
  deny_globs: string[];
  max_ttl?: string;
  approval_ttl?: string;
  rate_limit?: string;
  /** Installed team policy layer (EPIC-10), when present. */
  team: { version: number; fetchedAt: string } | null;
}

const DEFAULT_TTL_MS = 15 * 60 * 1000;

/**
 * Lenient TTL parse kept for backward compatibility (the minter relies on
 * the silent-fallback contract for its own config). Policy code paths use
 * parseTtlStrict instead.
 */
export function parseTtl(ttl: string | undefined, fallback = DEFAULT_TTL_MS): number {
  if (!ttl) return fallback;
  const m = /^(\d+)(s|m|h)$/.exec(ttl.trim());
  if (!m) return fallback;
  const n = parseInt(m[1], 10);
  return n * (m[2] === "s" ? 1_000 : m[2] === "m" ? 60_000 : 3_600_000);
}

/**
 * Strict TTL parse: throws on anything but '<n>s' | '<n>m' | '<n>h'. Used for
 * every value that comes from a HUMAN-written policy file (fail-closed on
 * broken config) and from agent requests (clear deny instead of fallback).
 */
export function parseTtlStrict(ttl: string, what = "ttl"): number {
  const m = /^(\d+)(s|m|h)$/.exec(String(ttl).trim());
  if (!m) {
    throw new Error(
      `Invalid ${what} '${ttl}' — expected '<n>s', '<n>m' or '<n>h' (e.g. '30s', '15m', '1h').`,
    );
  }
  const n = parseInt(m[1], 10);
  return n * (m[2] === "s" ? 1_000 : m[2] === "m" ? 60_000 : 3_600_000);
}

/** Error thrown when a policies.yaml document fails schema validation. */
export class PolicyConfigError extends Error {}

/* ------------------------------------------------------------------------ */
/* Schema validation (schema v1 + Sprint-2 extensions, backward compatible)  */
/* ------------------------------------------------------------------------ */

const RULE_KEYS = new Set(["match", "auto_approve", "ttl", "require", "redact", "when"]);
const LIMIT_KEYS = new Set(["max_ttl", "deny", "rate_limit", "approval_ttl", "max_lease_total", "max_inline_bytes"]);

function assertCompilableGlob(glob: unknown, where: string): asserts glob is string {
  if (typeof glob !== "string" || !glob.trim()) {
    throw new PolicyConfigError(`${where}: glob must be a non-empty string`);
  }
  if (/[\r\n]/.test(glob)) {
    throw new PolicyConfigError(`${where}: glob must not contain newlines`);
  }
  try {
    picomatch(glob);
  } catch (e) {
    throw new PolicyConfigError(
      `${where}: invalid glob '${glob}': ${(e as Error).message}`,
    );
  }
}

function strictTtlAt(value: unknown, where: string): void {
  if (typeof value !== "string") {
    throw new PolicyConfigError(`${where}: must be a string like '15m'`);
  }
  try {
    parseTtlStrict(value, where);
  } catch (e) {
    throw new PolicyConfigError((e as Error).message);
  }
}

function validateLimits(raw: unknown, where: string): void {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PolicyConfigError(`${where}: must be an object`);
  }
  for (const k of Object.keys(raw)) {
    if (!LIMIT_KEYS.has(k)) {
      throw new PolicyConfigError(
        `${where}: unknown key '${k}' (allowed: ${[...LIMIT_KEYS].join(", ")})`,
      );
    }
  }
  const lim = raw as PolicyLimits;
  if (lim.max_ttl !== undefined) strictTtlAt(lim.max_ttl, `${where}.max_ttl`);
  if (lim.max_lease_total !== undefined) strictTtlAt(lim.max_lease_total, `${where}.max_lease_total`);
  if (lim.approval_ttl !== undefined) strictTtlAt(lim.approval_ttl, `${where}.approval_ttl`);
  if (lim.max_inline_bytes !== undefined) {
    if (!Number.isInteger(lim.max_inline_bytes) || (lim.max_inline_bytes as number) < 256) {
      throw new PolicyConfigError(`${where}.max_inline_bytes: must be an integer >= 256`);
    }
  }
  if (lim.deny !== undefined) {
    if (!Array.isArray(lim.deny)) {
      throw new PolicyConfigError(`${where}.deny: must be an array of globs`);
    }
    lim.deny.forEach((g, i) => assertCompilableGlob(g, `${where}.deny[${i}]`));
  }
  if (lim.rate_limit !== undefined) {
    if (typeof lim.rate_limit !== "string") {
      throw new PolicyConfigError(`${where}.rate_limit: must be a string like '30/m'`);
    }
    try {
      parseRateWindow(lim.rate_limit);
    } catch (e) {
      throw new PolicyConfigError((e as Error).message);
    }
  }
}

function validateRule(raw: unknown, where: string): void {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PolicyConfigError(`${where}: must be an object`);
  }
  for (const k of Object.keys(raw)) {
    if (!RULE_KEYS.has(k)) {
      throw new PolicyConfigError(
        `${where}: unknown key '${k}' (allowed: ${[...RULE_KEYS].join(", ")})`,
      );
    }
  }
  const rule = raw as PolicyRule;
  assertCompilableGlob(rule.match, `${where}.match`);
  if (rule.when !== undefined) {
    if (!rule.when || typeof rule.when !== "object" || Array.isArray(rule.when)) {
      throw new PolicyConfigError(`${where}.when: must be an object of arg globs (fail-closed)`);
    }
    for (const [argName, v] of Object.entries(rule.when)) {
      if (!argName) throw new PolicyConfigError(`${where}.when: empty arg name`);
      if (typeof v === "string") assertCompilableGlob(v, `${where}.when.${argName}`);
      else if (typeof v !== "number" && typeof v !== "boolean") {
        throw new PolicyConfigError(
          `${where}.when.${argName}: must be a string glob, number or boolean`,
        );
      }
    }
  }
  if (rule.auto_approve !== undefined && typeof rule.auto_approve !== "boolean") {
    throw new PolicyConfigError(`${where}.auto_approve: must be a boolean`);
  }
  if (rule.ttl !== undefined) strictTtlAt(rule.ttl, `${where}.ttl`);
  if (rule.require !== undefined && rule.require !== "human_approval") {
    throw new PolicyConfigError(
      `${where}.require: only 'human_approval' is supported`,
    );
  }
  if (rule.redact !== undefined) {
    if (!Array.isArray(rule.redact)) {
      throw new PolicyConfigError(`${where}.redact: must be an array of categories`);
    }
    for (const c of rule.redact) {
      if (!(REDACT_CATEGORIES as readonly string[]).includes(String(c))) {
        throw new PolicyConfigError(
          `${where}.redact: unknown category '${c}' (known: ${REDACT_CATEGORIES.join(", ")})`,
        );
      }
    }
  }
}

/**
 * Validate a parsed policies.yaml document. Throws PolicyConfigError on any
 * violation — used both by the fail-closed first load at startup and by the
 * hot-reload path (which keeps the last-good set on error).
 */
export function validatePoliciesFile(raw: unknown): PoliciesFile {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PolicyConfigError("policies.yaml: top level must be an object");
  }
  const p = raw as PoliciesFile;
  if (p.version !== 1) {
    throw new PolicyConfigError("policies.yaml: 'version' must be 1");
  }
  if (p.limits !== undefined) validateLimits(p.limits, "limits");
  if (!p.agents || typeof p.agents !== "object" || Array.isArray(p.agents)) {
    throw new PolicyConfigError("policies.yaml: 'agents' must be an object");
  }
  for (const [name, ap] of Object.entries(p.agents)) {
    const where = `agents.${name === "*" ? '"*"' : name}`;
    // Agent keys may be globs (`nexgen-kimi-*`): a worker that mints one
    // logical identity per work unit cannot enumerate them in advance.
    //
    // Caveat worth knowing before trusting this line: picomatch is permissive
    // — it only rejects the empty string, so `nexgen-kimi-[` compiles fine and
    // simply matches nothing. This validates what IS detectable (empty,
    // newlines, whitespace) and cannot catch a glob typo. The defense against
    // a section that matches nothing is operational, not static: the 403
    // message names every declared section, and `GET /admin/agents` lists
    // them, so an identity falling through is visible immediately.
    assertCompilableGlob(name, where);
    if (/\s/.test(name)) {
      throw new PolicyConfigError(
        `${where}: agent key must not contain whitespace — ids arrive trimmed ` +
          `from the X-ScopeGate-Agent header, so a key with a space can never match`,
      );
    }
    if (!ap || typeof ap !== "object" || Array.isArray(ap)) {
      throw new PolicyConfigError(`${where}: must be an object`);
    }
    if (ap.default_ttl !== undefined) strictTtlAt(ap.default_ttl, `${where}.default_ttl`);
    if (ap.limits !== undefined) validateLimits(ap.limits, `${where}.limits`);
    if (ap.capabilities !== undefined && !Array.isArray(ap.capabilities)) {
      throw new PolicyConfigError(`${where}.capabilities: must be an array`);
    }
    (ap.capabilities ?? []).forEach((r, i) =>
      validateRule(r, `${where}.capabilities[${i}]`),
    );
  }
  return p;
}

/* ------------------------------------------------------------------------ */
/* Limits resolution                                                          */
/* ------------------------------------------------------------------------ */

/**
 * Resolves the `agents:` section that governs one logical identity.
 *
 * Keys may be globs, so a worker can mint an identity per work unit
 * (`nexgen-kimi-<channelId>`) and still be governed by one declared rule set.
 * Precedence is deterministic and most-specific-first, because a widening
 * glob must never silently outrank a narrower one:
 *
 *   1. exact key            (`nexgen-kimi-6a68fe4b…`)
 *   2. globs, longest key first, `*` never counted here
 *   3. the catch-all `*`
 *
 * Ties at equal length are broken by key order in the file (stable), which
 * only happens between two globs of identical length — a config smell the
 * caller can see in `agentIds()`.
 */
function agentKeyFor(policies: PoliciesFile, agentId: string): string | null {
  if (policies.agents[agentId]) return agentId;
  const globs = Object.keys(policies.agents)
    .filter((k) => k !== "*" && k !== agentId && /[*?[\]{}!]/.test(k))
    .sort((a, b) => b.length - a.length);
  for (const g of globs) {
    if (picomatch.isMatch(agentId, g)) return g;
  }
  if (policies.agents["*"]) return "*";
  return null;
}

/**
 * Whether a logical identity is accepted by this gateway (M4 allowlist).
 *
 * Exported because `http.ts` gates `X-ScopeGate-Agent` on it: with glob keys
 * the old `allowedAgents().includes(id)` no longer answers the question. An
 * identity is accepted when it resolves to a section — `*` included, since a
 * catch-all is an explicit decision to accept anything.
 */
export function agentIdAccepted(policies: PoliciesFile, agentId: string): boolean {
  return agentKeyFor(policies, agentId) !== null;
}

/** Effective limits for an agent: global merged with per-agent (agent wins). */
export function effectiveLimitsFor(
  policies: PoliciesFile,
  agentId: string,
): PolicyLimits {
  const key = agentKeyFor(policies, agentId);
  return {
    ...(policies.limits ?? {}),
    ...(key ? (policies.agents[key]?.limits ?? {}) : {}),
  };
}

/* ------------------------------------------------------------------------ */
/* Best-effort lifecycle auditing                                             */
/* ------------------------------------------------------------------------ */

/**
 * Lifecycle events (grant_issued, approval_*, policy_reload_error, …) are
 * audited best-effort from inside the engine: the FAIL-CLOSED guarantee for
 * the action itself lives in server.ts (auditOrThrow on the primary event);
 * a secondary lifecycle event must never crash a purge/reload path.
 */
function bestEffortAudit(
  agentId: string,
  kind: AuditKind,
  detail: Record<string, unknown>,
): void {
  try {
    audit(agentId, kind, detail);
  } catch (e) {
    console.error(
      `[scopegate] warn: audit(${kind}) failed: ${(e as Error).message}`,
    );
  }
}

function reloadAuditAgent(): string {
  return process.env.SCOPEGATE_AGENT_ID ?? "gateway";
}

/* ------------------------------------------------------------------------ */
/* Engine                                                                     */
/* ------------------------------------------------------------------------ */

export class PolicyEngine {
  private policies: PoliciesFile;
  private grants: GrantStore;
  private limiters = new Map<string, { spec: string; limiter: RateLimiter }>();
  /** EPIC-10 team layer: null unless a verified team policy is installed. */
  private teamPolicies: PoliciesFile | null = null;
  private teamPolicyMeta: TeamPolicyMeta | null = null;
  private teamLimiters = new Map<string, { spec: string; limiter: RateLimiter }>();
  private watcher: fs.FSWatcher | null = null;
  private reloadTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * Mejora #2 (approval continuation): injected by the gateway server (which
   * owns the proxy) to execute queued intents when their approval is granted.
   * Kept as a hook so the policy layer never imports the gateway layer.
   */
  public intentExecutor:
    | ((intent: ApprovalIntent) => Promise<{ ok: boolean; result?: unknown; error?: string }>)
    | null = null;

  /** Mejora #1: task-lease store (grants grouped per task with a double budget). */
  private leases = new LeaseStore();

  constructor(policies: PoliciesFile, deps: { grants?: GrantStore } = {}) {
    this.policies = policies;
    this.grants = deps.grants ?? new GrantStore();
    // EPIC-06: `audience: "org"` matching needs the DECLARED identities, and
    // those live in the (hot-reloadable) policy set — a closure over the
    // engine keeps the check current across reloads.
    this.grants.agentAccepted = (id: string) => this.acceptsAgentId(id);
  }

  /**
   * First load at startup — FAIL-CLOSED: a missing file yields the deny-all
   * default; an INVALID file throws (the gateway must not boot with a policy
   * set it cannot parse).
   */
  static load(): PolicyEngine {
    if (!fs.existsSync(POLICIES_PATH)) {
      // Safe default: nothing auto-approved until a human writes policy.
      return new PolicyEngine({ version: 1, agents: {} });
    }
    const raw = YAML.parse(fs.readFileSync(POLICIES_PATH, "utf8"));
    return new PolicyEngine(validatePoliciesFile(raw));
  }

  /** Evaluate a capability request. Grants persist on disk and expire by TTL.
   *
   * EPIC-06 (QM keychain): `opts.audience` asks for a grant usable by ANOTHER
   * declared identity. Audience ≠ self NEVER auto-approves — it always
   * escalates to the human queue (the owner of last resort), and the literal
   * "org" cannot be requested by an agent at all (admin-only, see
   * adminIssueGrant/promoteGrant). `opts.mode: "once"` asks for a single-use
   * grant (consumed atomically at authorization time); `opts.purpose` is a
   * declarative instruction recorded on the grant — NOT enforceable.
   */
  request(
    agentId: string,
    capability: string,
    ttl?: string,
    reason = "",
    opts?: {
      leaseId?: string;
      args?: Record<string, unknown>;
      audience?: string;
      mode?: "once" | "standing";
      purpose?: string;
    },
  ): Decision {
    // Pick up human decisions first: an approved request materializes its
    // one-shot grant here (fresh read by mtime — no cross-process watchers).
    this.refreshApprovals(agentId);

    // EPIC-10 team layer (restrictive intersection, evaluated LIVE at request
    // time): when a team policy is installed it is a ceiling over every path
    // below — including live grants. Team silence on a capability is a deny.
    // No-op when no team policy is installed (local-first default).
    const teamGateDeny = this.teamGate(agentId, capability);
    if (teamGateDeny) return teamGateDeny;

    // Mejora #1: a lease-bound request is validated UP FRONT (live + upstream
    // scope) — an existing grant must never bypass the lease's scope check.
    if (opts?.leaseId) {
      try {
        this.assertLeaseUsable(agentId, opts.leaseId, capability);
      } catch (e) {
        return { allow: false, code: "lease_error", reason: (e as Error).message };
      }
    }

    // EPIC-06: audience validation. "org" is admin-born only; any other
    // audience must be a declared identity (fail-closed with a clear reason).
    const audience = opts?.audience;
    const audienceRequested = audience !== undefined && audience !== agentId;
    if (audience === "org") {
      return {
        allow: false,
        code: "audience_denied",
        reason:
          `Audience 'org' cannot be requested by an agent — org-wide grants are born only ` +
          `via the admin surface (direct issue or promote). Ask a human with admin access.`,
      };
    }
    if (audienceRequested && !this.acceptsAgentId(audience)) {
      return {
        allow: false,
        code: "audience_denied",
        reason:
          `Audience '${audience}' is not a declared agent identity on this gateway ` +
          `(policies.yaml agents: sections). Declared: ${this.agentIds().join(", ") || "(none)"}.`,
      };
    }

    // Idempotent re-request: a live covering grant (including one just
    // materialized from an approval) is returned, not duplicated. For M6
    // `when`-guarded grants the call's args must satisfy the guard too.
    // EPIC-06: for an audience≠self request the idempotency key is OWNERSHIP
    // (the audience grant does not cover the requester, by design).
    const now = Date.now();
    const existing = audienceRequested
      ? this.grants
          .active(agentId, now)
          .find(
            (g) =>
              g.audience === audience &&
              (g.capability === capability || picomatch.isMatch(capability, g.capability)) &&
              (g.mode ?? "standing") === (opts?.mode ?? "standing") &&
              (!g.when || matchesWhen(g.when, opts?.args)),
          )
      : this.grants.coveringGrant(agentId, capability, now, opts?.args);
    if (existing) {
      let ttlMs = Math.max(0, existing.expiresAt - now);
      // A tightened team policy re-clamps (never extends) live grants.
      const teamCeiling = this.teamTtlCeilingMs(agentId, capability);
      if (teamCeiling !== null) ttlMs = Math.min(ttlMs, teamCeiling);
      return {
        allow: true,
        ttlMs,
        rule: existing.rule ?? "existing_grant",
      };
    }

    const agentKey = agentKeyFor(this.policies, agentId);
    const agent = agentKey ? this.policies.agents[agentKey] : null;
    if (!agent) {
      return {
        allow: false,
        code: "no_policy",
        reason: `No policy defined for agent '${agentId}'. A human must add one to policies.yaml (or the agent may call scopegate_propose_policy).`,
      };
    }

    const limits = effectiveLimitsFor(this.policies, agentId);

    // HARD LIMITS FIRST (fail-closed): deny globs beat every auto_approve rule.
    for (const glob of limits.deny ?? []) {
      if (picomatch.isMatch(capability, glob)) {
        return {
          allow: false,
          code: "ceiling_blocked",
          reason:
            `Capability '${capability}' is blocked by a hard limit (deny '${glob}'). ` +
            `Hard limits are non-negotiable — do NOT retry with broader scope; a human must change policies.yaml.`,
        };
      }
    }

    // EPIC-06: audience ≠ self NEVER auto-approves — hard limits already
    // evaluated above; from here the request always escalates to the human
    // queue (the keychain's owner-of-last-resort), whatever the rules say.
    if (audienceRequested) {
      let approvalTtlMs = DEFAULT_APPROVAL_TTL_MS;
      try {
        approvalTtlMs = limits.approval_ttl
          ? parseTtlStrict(limits.approval_ttl, "limits.approval_ttl")
          : DEFAULT_APPROVAL_TTL_MS;
      } catch {
        /* validated at load; keep the safe default defensively */
      }
      const purpose = opts?.purpose ?? reason;
      const { request: ap, created } = createApprovalRequest({
        agentId,
        capability,
        ttl: ttl ?? null,
        reason,
        approvalTtlMs,
        audience,
        ...(opts?.mode ? { mode: opts.mode } : {}),
        ...(purpose ? { purpose } : {}),
      });
      if (created) {
        bestEffortAudit(agentId, "approval_requested", {
          id: ap.id,
          capability,
          ttl: ap.ttl,
          reason,
          audience,
          ...(opts?.mode ? { mode: opts.mode } : {}),
          ...(purpose ? { purpose } : {}),
          expiresAt: new Date(ap.expiresAt).toISOString(),
        });
      }
      return {
        allow: false,
        reason:
          `Audience '${audience}' differs from the requester — a grant for another identity ` +
          `always requires human approval (QM keychain: only the owner may grant).`,
        escalation: "human_approval",
        approvalId: ap.id,
        approvalExpiresAt: ap.expiresAt,
      };
    }

    // Agent-supplied TTL: strict parse, clear deny on garbage.
    let requested: number;
    try {
      requested = ttl === undefined ? Number.MAX_SAFE_INTEGER : parseTtlStrict(ttl);
    } catch (e) {
      return { allow: false, code: "invalid_ttl", reason: (e as Error).message };
    }

    for (const rule of agent.capabilities ?? []) {
      if (!picomatch.isMatch(capability, rule.match)) continue;
      // M6: arg guard — a `when` that the call's args don't satisfy makes the
      // RULE not match (evaluation continues first-match-wins; never widens).
      if (rule.when && !matchesWhen(rule.when, opts?.args)) continue;

      if (rule.require === "human_approval") {
        let approvalTtlMs = DEFAULT_APPROVAL_TTL_MS;
        try {
          approvalTtlMs = limits.approval_ttl
            ? parseTtlStrict(limits.approval_ttl, "limits.approval_ttl")
            : DEFAULT_APPROVAL_TTL_MS;
        } catch {
          /* validated at load; keep the safe default defensively */
        }
        const { request: ap, created } = createApprovalRequest({
          agentId,
          capability,
          ttl: ttl ?? null,
          reason,
          approvalTtlMs,
        });
        if (created) {
          bestEffortAudit(agentId, "approval_requested", {
            id: ap.id,
            capability,
            ttl: ap.ttl,
            reason,
            expiresAt: new Date(ap.expiresAt).toISOString(),
          });
        }
        return {
          allow: false,
          reason: `Capability '${capability}' matches '${rule.match}' which requires human approval.`,
          escalation: "human_approval",
          approvalId: ap.id,
          approvalExpiresAt: ap.expiresAt,
        };
      }

      if (rule.auto_approve) {
        // EPIC-10: a team rule demanding human approval overrides local
        // auto-approve (the intersection is restrictive): escalate instead
        // of granting. The team pre-gate already guaranteed a rule exists.
        const teamRule = this.teamRuleFor(agentId, capability);
        if (teamRule && teamRule.require === "human_approval") {
          const approvalTtlMs = this.teamApprovalTtlMs(agentId, limits);
          const { request: ap, created } = createApprovalRequest({
            agentId,
            capability,
            ttl: ttl ?? null,
            reason,
            approvalTtlMs,
          });
          if (created) {
            bestEffortAudit(agentId, "approval_requested", {
              id: ap.id,
              capability,
              ttl: ap.ttl,
              reason,
              via: "team_policy",
              expiresAt: new Date(ap.expiresAt).toISOString(),
            });
          }
          return {
            allow: false,
            reason: `[team policy] Capability '${capability}' matches team rule '${teamRule.match}' which requires human approval.`,
            escalation: "human_approval",
            approvalId: ap.id,
            approvalExpiresAt: ap.expiresAt,
          };
        }
        let ttlMs: number;
        try {
          ttlMs = this.clampTtl(requested, rule, agent, limits);
          // EPIC-10: the team layer's TTL ceiling clamps further (min).
          const teamCeiling = this.teamTtlCeilingMs(agentId, capability);
          if (teamCeiling !== null) ttlMs = Math.min(ttlMs, teamCeiling);
        } catch (e) {
          return { allow: false, code: "config_error", reason: (e as Error).message };
        }
        const purpose = opts?.purpose ?? (reason || undefined);
        const grant = this.grants.issue({
          agentId,
          capability,
          ttlMs,
          redact: rule.redact,
          rule: rule.match,
          ...(rule.when ? { when: rule.when } : {}),
          ...(opts?.leaseId ? { leaseId: opts.leaseId } : {}),
          ...(opts?.mode ? { mode: opts.mode } : {}),
          ...(purpose ? { purpose } : {}),
        });
        bestEffortAudit(agentId, "grant_issued", {
          id: grant.id,
          capability,
          ttlMs,
          expiresAt: new Date(grant.expiresAt).toISOString(),
          rule: rule.match,
          ...(teamRule ? { teamRule: teamRule.match } : {}),
          ...(opts?.mode ? { mode: opts.mode } : {}),
          ...(purpose ? { purpose } : {}),
        });
        // agent can shorten, never extend
        return { allow: true, ttlMs, rule: rule.match };
      }
    }
    // M10: inverted default — vault:inject:* escalates instead of no_rule.
    if (DEFAULT_APPROVAL_PREFIXES.some((p) => capability.startsWith(p))) {
      let approvalTtlMs = DEFAULT_APPROVAL_TTL_MS;
      try {
        approvalTtlMs = limits.approval_ttl
          ? parseTtlStrict(limits.approval_ttl, "limits.approval_ttl")
          : DEFAULT_APPROVAL_TTL_MS;
      } catch {
        /* validated at load; keep the safe default defensively */
      }
      const { request: ap, created } = createApprovalRequest({
        agentId,
        capability,
        ttl: ttl ?? null,
        reason,
        approvalTtlMs,
      });
      if (created) {
        bestEffortAudit(agentId, "approval_requested", {
          id: ap.id,
          capability,
          ttl: ap.ttl,
          reason,
          via: "default_escalation",
          expiresAt: new Date(ap.expiresAt).toISOString(),
        });
      }
      return {
        allow: false,
        reason:
          `Capability '${capability}' requires human approval BY DEFAULT — materializing a secret into a file ` +
          `is a governed exception; a policy rule must explicitly auto_approve it.`,
        escalation: "human_approval",
        approvalId: ap.id,
        approvalExpiresAt: ap.expiresAt,
      };
    }
    return {
      allow: false,
      code: "no_rule",
      reason: `No auto_approve rule matches '${capability}' for agent '${agentId}'.`,
    };
  }

  /**
   * Mejora #3: read-only policy preflight — `request()`'s decision logic
   * WITHOUT any side effect (no grant issued, no approval queued, no audit,
   * no refresh). What the agent uses to plan instead of learning by denials.
   */
  evaluate(agentId: string, capability: string, ttl?: string, args?: Record<string, unknown>): Evaluation {
    // Team pre-gate is pure (deny globs / coverage / silence) — reuse it.
    const teamGateDeny = this.teamGate(agentId, capability);
    if (teamGateDeny && !teamGateDeny.allow) {
      return {
        decision: "deny",
        code: teamGateDeny.code,
        hard: teamGateDeny.code === "ceiling_blocked" ? true : undefined,
        reason: teamGateDeny.reason,
      };
    }

    // A live covering grant makes the answer trivially "allow".
    const now = Date.now();
    const existing = this.grants.coveringGrant(agentId, capability, now, args);
    if (existing) {
      let ttlMs = Math.max(0, existing.expiresAt - now);
      const teamCeiling = this.teamTtlCeilingMs(agentId, capability);
      if (teamCeiling !== null) ttlMs = Math.min(ttlMs, teamCeiling);
      return {
        decision: "allow",
        covered_by_existing_grant: true,
        ttl_ms: ttlMs,
        rule: existing.rule ?? "existing_grant",
        reason: "A live grant already covers this capability.",
      };
    }

    const agentKey = agentKeyFor(this.policies, agentId);
    const agent = agentKey ? this.policies.agents[agentKey] : null;
    if (!agent) {
      return {
        decision: "deny",
        code: "no_policy",
        reason: `No policy defined for agent '${agentId}'.`,
      };
    }

    const limits = effectiveLimitsFor(this.policies, agentId);

    // Hard limits first (fail-closed), same as request().
    for (const glob of limits.deny ?? []) {
      if (picomatch.isMatch(capability, glob)) {
        return {
          decision: "deny",
          code: "ceiling_blocked",
          hard: true,
          reason: `Capability '${capability}' is blocked by a hard limit (deny '${glob}').`,
        };
      }
    }

    let requested: number;
    try {
      requested = ttl === undefined ? Number.MAX_SAFE_INTEGER : parseTtlStrict(ttl);
    } catch (e) {
      return { decision: "deny", code: "invalid_ttl", reason: (e as Error).message };
    }

    for (const rule of agent.capabilities ?? []) {
      if (!picomatch.isMatch(capability, rule.match)) continue;
      if (rule.when && !matchesWhen(rule.when, args)) continue;

      if (rule.require === "human_approval") {
        return {
          decision: "needs_approval",
          via: "local_policy",
          rule: rule.match,
          reason: `Capability '${capability}' matches '${rule.match}' which requires human approval.`,
        };
      }

      if (rule.auto_approve) {
        // Team require:human_approval overrides local auto-approve (restrictive).
        const teamRule = this.teamRuleFor(agentId, capability);
        if (teamRule && teamRule.require === "human_approval") {
          return {
            decision: "needs_approval",
            via: "team_policy",
            rule: teamRule.match,
            reason: `[team policy] Capability '${capability}' matches team rule '${teamRule.match}' which requires human approval.`,
          };
        }
        try {
          let ttlMs = this.clampTtl(requested, rule, agent, limits);
          const teamCeiling = this.teamTtlCeilingMs(agentId, capability);
          if (teamCeiling !== null) ttlMs = Math.min(ttlMs, teamCeiling);
          return {
            decision: "allow",
            ttl_ms: ttlMs,
            rule: rule.match,
            reason: `Auto-approved by rule '${rule.match}'.`,
          };
        } catch (e) {
          return { decision: "deny", code: "config_error", reason: (e as Error).message };
        }
      }
    }

    // M10: inverted default — mirror of request()'s default escalation.
    if (DEFAULT_APPROVAL_PREFIXES.some((p) => capability.startsWith(p))) {
      return {
        decision: "needs_approval",
        reason:
          `Capability '${capability}' requires human approval BY DEFAULT (governed exception — ` +
          `a policy rule must explicitly auto_approve it).`,
      };
    }
    return {
      decision: "deny",
      code: "no_rule",
      reason: `No auto_approve rule matches '${capability}' for agent '${agentId}'.`,
    };
  }

  /**
   * Mejora #3: the agent-facing policy digest for session-start planning —
   * which capabilities auto-approve, which need a human, and the hard
   * ceilings. Read-only, cheap to compute at handshake time.
   */
  policySummary(agentId: string): PolicySummary {
    const agentKey = agentKeyFor(this.policies, agentId);
    const agent = agentKey ? this.policies.agents[agentKey] : null;
    const limits = effectiveLimitsFor(this.policies, agentId);
    const rules = agent?.capabilities ?? [];
    return {
      agentId,
      agent_found: agent !== null,
      ...(agent?.default_ttl ? { default_ttl: agent.default_ttl } : {}),
      auto_approve: rules.filter((r) => r.auto_approve).map((r) => r.match),
      requires_approval: rules
        .filter((r) => r.require === "human_approval")
        .map((r) => r.match),
      deny_globs: [...(limits.deny ?? [])],
      ...(limits.max_ttl ? { max_ttl: limits.max_ttl } : {}),
      ...(limits.approval_ttl ? { approval_ttl: limits.approval_ttl } : {}),
      ...(limits.rate_limit ? { rate_limit: limits.rate_limit } : {}),
      team: this.teamPolicyMeta
        ? { version: this.teamPolicyMeta.version, fetchedAt: this.teamPolicyMeta.fetchedAt }
        : null,
    };
  }

  /** Final TTL clamp: min(requested, rule/default ceiling, limits.max_ttl). */
  private clampTtl(
    requestedMs: number,
    rule: PolicyRule,
    agent: AgentPolicy,
    limits: PolicyLimits,
  ): number {
    let ceiling = DEFAULT_TTL_MS;
    if (rule.ttl !== undefined) {
      ceiling = parseTtlStrict(rule.ttl, `ttl of rule '${rule.match}'`);
    } else if (agent.default_ttl !== undefined) {
      ceiling = parseTtlStrict(agent.default_ttl, "default_ttl");
    }
    let ttlMs = Math.min(requestedMs, ceiling);
    if (limits.max_ttl !== undefined) {
      ttlMs = Math.min(ttlMs, parseTtlStrict(limits.max_ttl, "limits.max_ttl"));
    }
    return ttlMs;
  }

  /** Check an existing (non-expired) grant covering the capability. */
  isGranted(agentId: string, capability: string, args?: Record<string, unknown>): boolean {
    this.refreshApprovals(agentId);
    this.purgeAndAudit();
    return this.grants.isGranted(agentId, capability, Date.now(), args);
  }

  /**
   * The latest live grant covering the capability (historical "latest
   * covering grant wins" rule), carrying redact categories and remaining TTL.
   * Used by server.ts for the token-TTL clamp and response redaction.
   */
  coveringGrant(agentId: string, capability: string, args?: Record<string, unknown>) {
    this.refreshApprovals(agentId);
    this.purgeAndAudit();
    return this.grants.coveringGrant(agentId, capability, Date.now(), args);
  }

  /**
   * EPIC-06 (QM keychain): authorize ONE tool call — the single check+claim
   * operation that replaces the old isGranted/coveringGrant pair in the
   * dispatcher. With `mode: "once"` grants, checking and claiming must be one
   * atomic step: otherwise the gate itself would consume the grant, or two
   * concurrent calls would both pass.
   *
   * Returns the covering grant (claimed, when `once`) or WHY the call is not
   * covered:
   *   - "none"       — nothing related to this caller matches (the dispatcher
   *                    falls back to the implicit auto-approve request, the
   *                    historical behaviour);
   *   - "used"       — the matching once grant was already consumed;
   *   - "revoked"    — the matching grant was revoked;
   *   - "expired"    — the grant died between check and claim (race);
   *   - "audience"   — a live related grant exists but its audience excludes
   *                    this caller;
   *   - "hard_limit" — cross-agent consumption (audience/org grant) that hits
   *                    the CALLER's deny globs: those are non-negotiable even
   *                    for a valid grant.
   *
   * Note on purpose: it rides along on the grant (audit + model instruction)
   * and is deliberately NEVER evaluated here — purpose is not enforceable.
   */
  authorizeCall(
    agentId: string,
    capability: string,
    args?: Record<string, unknown>,
  ):
    | { grant: Grant }
    | { denied: "used" | "revoked" | "expired" | "audience" | "hard_limit" | "none" } {
    this.refreshApprovals(agentId);
    this.purgeAndAudit();
    const now = Date.now();
    const grant = this.grants.coveringGrant(agentId, capability, now, args);
    if (grant) {
      if (grant.agentId !== agentId) {
        // Cross-agent consumption: the caller's OWN hard limits still gate —
        // an org/audience grant never overrides a deny glob (fail-closed).
        const limits = effectiveLimitsFor(this.policies, agentId);
        for (const glob of limits.deny ?? []) {
          if (picomatch.isMatch(capability, glob)) return { denied: "hard_limit" };
        }
      }
      if (grant.mode === "once") {
        const claimed = this.grants.claimOnce(grant.id, agentId);
        if (claimed !== "ok") return { denied: claimed };
        bestEffortAudit(agentId, "grant_claimed", {
          id: grant.id,
          capability,
          holder: grant.agentId,
          ...(grant.audience ? { audience: grant.audience } : {}),
          ...(grant.purpose ? { purpose: grant.purpose } : {}),
        });
      }
      return { grant };
    }
    const last = this.grants.latestForCapability(agentId, capability, now, args);
    if (!last) return { denied: "none" };
    if (last.status === "used") return { denied: "used" };
    if (last.status === "revoked") return { denied: "revoked" };
    // Live and related, but the audience excludes this caller.
    return { denied: "audience" };
  }

  activeGrants(agentId: string) {
    this.purgeAndAudit();
    return this.grants.active(agentId);
  }

  /**
   * EPIC-06: grants the agent can USE (own + named audience + org) plus its
   * own lifecycle tombstones — the engine behind scopegate_list_capabilities'
   * extended view.
   */
  usableGrants(agentId: string) {
    this.purgeAndAudit();
    return this.grants.usableBy(agentId, Date.now(), { includeTombstones: true });
  }

  /**
   * EPIC-06: revoke a grant and its WHOLE descendant chain (delegated
   * children, promoted org grants, their children in turn — recursive).
   * Revocation is a tombstone (status "revoked" + revokedAt) and the audit
   * carries the full chain: who revoked (via/author), how many fell by
   * cascade and the grant ids involved.
   */
  revokeCascade(
    grantId: string,
    opts: { via: string; author?: string; revokedAgentId?: string },
  ): { count: number; chain: { id: string; agentId: string; capability: string; audience?: string }[] } {
    const revoked = this.grants.revokeById(grantId);
    const chain = revoked.map((g) => ({
      id: g.id,
      agentId: g.agentId,
      capability: g.capability,
      ...(g.audience ? { audience: g.audience } : {}),
    }));
    if (revoked.length > 0) {
      bestEffortAudit(opts.author ?? reloadAuditAgent(), "grants_revoked", {
        ...(opts.revokedAgentId ? { revokedAgentId: opts.revokedAgentId } : {}),
        grantId,
        via: opts.via,
        count: revoked.length,
        cascade: revoked.length - 1,
        chain: chain.map((c) => c.id),
      });
    }
    return { count: revoked.length, chain };
  }

  /** Revoke a single grant by id (cascade incluida); audita grants_revoked. */
  revokeGrantById(agentId: string, grantId: string): number {
    return this.revokeCascade(grantId, { via: "engine", revokedAgentId: agentId }).count;
  }

  /**
   * EPIC-06: agent self-service revocation (the scopegate_revoke_capability
   * tool) — an agent may only give up a grant IT HOLDS. Self-revocation is
   * privilege attenuation, so it needs no approval; the cascade still kills
   * every descendant (delegations, promotions).
   */
  revokeOwnGrant(
    agentId: string,
    grantId: string,
  ): { count: number; chain: { id: string; agentId: string; capability: string; audience?: string }[] } {
    const grant = this.grants.byId(agentId, grantId);
    if (!grant) {
      throw new Error(
        `No live grant '${grantId}' held by agent '${agentId}' — an agent can only revoke its own grants (everything else is admin).`,
      );
    }
    return this.revokeCascade(grantId, { via: "agent", author: agentId, revokedAgentId: agentId });
  }

  /** Revoke every grant of an agent; audits grants_revoked with the count. */
  revokeAgent(agentId: string): number {
    const revoked = this.grants.revokeAgent(agentId);
    if (revoked.length > 0) {
      bestEffortAudit(reloadAuditAgent(), "grants_revoked", {
        revokedAgentId: agentId,
        count: revoked.length,
        cascade: revoked.filter((g) => g.agentId !== agentId).length,
        chain: revoked.map((g) => g.id),
      });
    }
    return revoked.length;
  }

  /* ---------------------------------------------------------------------- */
  /* EPIC-06 (QM keychain): admin surface — cross-agent list, direct issue,  */
  /* promote-to-org. Every path re-evaluates hard limits: an admin can never */
  /* jump the deny globs or the TTL ceilings either (fail-closed).           */
  /* ---------------------------------------------------------------------- */

  /**
   * Cross-agent grant listing for the admin console (any holder, tombstones
   * included so the lifecycle is visible), filtered by holder / audience /
   * mode. `audience` matches the EFFECTIVE audience (absent = holder).
   */
  listGrants(filter?: { agent?: string; audience?: string; mode?: string }): Grant[] {
    this.purgeAndAudit();
    let all = this.grants.all();
    if (filter?.agent) all = all.filter((g) => g.agentId === filter.agent);
    if (filter?.audience) {
      all = all.filter((g) => (g.audience ?? g.agentId) === filter.audience);
    }
    if (filter?.mode) all = all.filter((g) => (g.mode ?? "standing") === filter.mode);
    return all;
  }

  /**
   * Admin direct issue (POST /admin/grants): `{agentId | audience: "org"}` —
   * the only way an org-wide grant is born besides promote. `purpose` is
   * MANDATORY (mirror of QM's mint, which demands it verbatim). Hard limits
   * are re-evaluated exactly as for an agent request: deny globs and max_ttl
   * (of the holder, or the GLOBAL limits for an org grant) are non-negotiable.
   * Throws an Error with an actionable message on any refusal.
   */
  adminIssueGrant(
    actor: string,
    input: {
      agentId?: string;
      audience?: string;
      capability: string;
      ttl?: string;
      mode?: "once" | "standing";
      purpose: string;
      when?: Record<string, string | number | boolean>;
    },
  ): Grant {
    const capability = String(input.capability ?? "").trim();
    if (!capability) throw new Error("capability is required.");
    const purpose = String(input.purpose ?? "").trim();
    if (!purpose) {
      throw new Error("purpose is required for admin grants — it is the declarative instruction recorded in the audit trail.");
    }
    if (input.mode !== undefined && input.mode !== "once" && input.mode !== "standing") {
      throw new Error(`Invalid mode '${String(input.mode)}' — expected 'once' or 'standing'.`);
    }
    const audience = input.audience?.trim() || undefined;
    if (audience !== undefined && audience !== "org" && !this.acceptsAgentId(audience)) {
      throw new Error(
        `Audience '${audience}' is not a declared agent identity on this gateway. Declared: ${this.agentIds().join(", ") || "(none)"}.`,
      );
    }
    const holder = input.agentId?.trim() || (audience === "org" ? "org" : (audience ?? ""));
    if (!holder) {
      throw new Error("Provide agentId (holder) or audience: \"org\" — one of the two is required.");
    }
    if (holder !== "org" && !this.acceptsAgentId(holder)) {
      throw new Error(
        `Agent '${holder}' is not a declared identity on this gateway. Declared: ${this.agentIds().join(", ") || "(none)"}.`,
      );
    }
    // Hard limits: holder's effective limits, or the GLOBAL set for org grants.
    const limits =
      holder === "org"
        ? (this.policies.limits ?? {})
        : effectiveLimitsFor(this.policies, holder);
    for (const glob of limits.deny ?? []) {
      if (picomatch.isMatch(capability, glob)) {
        throw new Error(
          `Capability '${capability}' is blocked by a hard limit (deny '${glob}'). Hard limits are non-negotiable — not even for an admin.`,
        );
      }
    }
    let ttlMs: number;
    try {
      ttlMs = input.ttl === undefined ? DEFAULT_TTL_MS : parseTtlStrict(input.ttl);
    } catch (e) {
      throw new Error((e as Error).message);
    }
    if (limits.max_ttl !== undefined) {
      ttlMs = Math.min(ttlMs, parseTtlStrict(limits.max_ttl, "limits.max_ttl"));
    }
    const grant = this.grants.issue({
      agentId: holder,
      capability,
      ttlMs,
      rule: "admin",
      // "org" always lands on the grant (even though the holder is "org" too —
      // without it the self-rule would cover nobody); a specific audience only
      // when it differs from the holder.
      ...(audience && (audience === "org" || audience !== holder) ? { audience } : {}),
      ...(input.mode ? { mode: input.mode } : {}),
      purpose,
      requestedBy: actor,
      ...(input.when ? { when: input.when } : {}),
    });
    // The event is authored by the holder so fleet projections attribute the
    // capability correctly; the human actor rides in the detail.
    bestEffortAudit(holder === "org" ? actor : holder, "grant_issued", {
      id: grant.id,
      capability,
      ttlMs,
      expiresAt: new Date(grant.expiresAt).toISOString(),
      via: "admin",
      actor,
      ...(grant.audience ? { audience: grant.audience } : {}),
      ...(grant.mode ? { mode: grant.mode } : {}),
      purpose,
    });
    return grant;
  }

  /**
   * Admin-gated promotion to audience "org" (POST /admin/grants/:id/promote):
   * the QM `promote` equivalent. The org grant is a CHILD of the original —
   * revoking the original takes the promotion down with it (same cascade as
   * delegation). Mode is inherited; ttl = min(remaining, global max_ttl);
   * `purpose` is mandatory. Audit: `grant_promoted` with parent/child/actor.
   *
   * Promoting a `once` grant is allowed but documented: the FIRST caller
   * consumes it org-wide and `usedBy` records who — rarely useful.
   */
  promoteGrant(
    actor: string,
    grantId: string,
    purpose: string,
  ): { parent: Grant; child: Grant } {
    const trimmedPurpose = String(purpose ?? "").trim();
    if (!trimmedPurpose) {
      throw new Error("purpose is required to promote a grant — it is the declarative instruction recorded in the audit trail.");
    }
    const parent = this.grants.byIdAny(grantId);
    if (!parent) {
      throw new Error(`No live grant '${grantId}' — it may be expired, used or revoked.`);
    }
    const now = Date.now();
    let ttlMs = Math.max(1, parent.expiresAt - now);
    const globalMaxTtl = this.policies.limits?.max_ttl;
    if (globalMaxTtl !== undefined) {
      ttlMs = Math.min(ttlMs, parseTtlStrict(globalMaxTtl, "limits.max_ttl"));
    }
    const child = this.grants.issue({
      agentId: parent.agentId, // attribution stays with the original holder
      capability: parent.capability,
      ttlMs,
      audience: "org",
      ...(parent.mode ? { mode: parent.mode } : {}),
      purpose: trimmedPurpose,
      parentGrantId: parent.id,
      rule: "promoted",
      requestedBy: actor,
      ...(parent.redact?.length ? { redact: parent.redact } : {}),
      ...(parent.when ? { when: parent.when } : {}),
    });
    bestEffortAudit(parent.agentId, "grant_promoted", {
      parent: parent.id,
      child: child.id,
      capability: parent.capability,
      actor,
      purpose: trimmedPurpose,
      mode: child.mode ?? "standing",
      expiresAt: new Date(child.expiresAt).toISOString(),
    });
    return { parent, child };
  }

  /* ---------------------------------------------------------------------- */
  /* Mejora #1: task leases                                                  */
  /* ---------------------------------------------------------------------- */

  /**
   * Open a task lease. `max_total` is CLAMPED by limits.max_lease_total
   * (default 4h — a hard, non-negotiable ceiling exactly like max_ttl:
   * the ceiling always wins, it never extends). `max_writes` defaults to 200.
   */
  openLease(
    agentId: string,
    input: {
      goal: string;
      upstreams: string[];
      max_total?: string;
      max_writes?: number;
    },
  ): { lease: Lease; clamped: boolean } {
    const limits = effectiveLimitsFor(this.policies, agentId);
    const ceilingMs = limits.max_lease_total
      ? parseTtlStrict(limits.max_lease_total, "limits.max_lease_total")
      : DEFAULT_LEASE_TOTAL_MS;
    let totalMs = ceilingMs;
    let clamped = false;
    if (input.max_total !== undefined) {
      const asked = parseTtlStrict(input.max_total, "max_total");
      if (asked < ceilingMs) totalMs = asked;
      else clamped = asked > ceilingMs;
    }
    const maxWrites =
      input.max_writes !== undefined && Number.isInteger(input.max_writes) && input.max_writes > 0
        ? input.max_writes
        : DEFAULT_LEASE_MAX_WRITES;
    const lease = this.leases.open({
      agentId,
      goal: input.goal,
      upstreams: input.upstreams,
      totalMs,
      ceilingMs,
      maxWrites,
    });
    bestEffortAudit(agentId, "lease_opened", {
      leaseId: lease.leaseId,
      goal: lease.goal,
      upstreams: lease.upstreams,
      totalMs: lease.totalMs,
      deadlineAt: new Date(lease.deadlineMs).toISOString(),
      maxWrites: lease.maxWrites,
      clamped,
    });
    return { lease, clamped };
  }

  /** A capability request may bind to a lease: it must be live AND in scope. */
  private assertLeaseUsable(agentId: string, leaseId: string, capability: string): Lease {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.agentId !== agentId) {
      throw new Error(`Unknown lease '${leaseId}' for agent '${agentId}'.`);
    }
    if (!this.leases.isLive(leaseId)) {
      throw new Error(
        `Lease '${leaseId}' is ${lease.status} (deadline ${new Date(lease.deadlineMs).toISOString()}) — open a new one with scopegate_open_task_lease.`,
      );
    }
    const upstream = capability.split(":")[0];
    if (lease.upstreams.length > 0 && !lease.upstreams.includes(upstream)) {
      throw new Error(
        `Lease '${leaseId}' is scoped to upstreams [${lease.upstreams.join(", ")}] — capability '${capability}' is out of scope.`,
      );
    }
    return lease;
  }

  /**
   * Renew a lease-covered grant (sliding TTL): new expiry =
   * min(now + original ttl, lease deadline, rule ceilings) — the lease's
   * live status and scope are re-validated every time. Auto-approved while
   * the lease lives; never past the lease deadline (the hard budget).
   */
  renewGrant(agentId: string, grantId: string): { grantId: string; expiresAt: number; leaseId: string } {
    const grant = this.grants.byId(agentId, grantId);
    if (!grant) {
      throw new Error(
        `No live grant '${grantId}' for agent '${agentId}' — it may have expired; request a fresh capability.`,
      );
    }
    if (!grant.leaseId) {
      throw new Error(
        `Grant '${grantId}' is not covered by any lease — renew by re-requesting the capability (scopegate_request_capability).`,
      );
    }
    const lease = this.assertLeaseUsable(agentId, grant.leaseId, grant.capability);
    const originalTtl = Math.max(1, grant.expiresAt - grant.grantedAt);
    const now = Date.now();
    // Re-apply the same ceilings as a fresh request: rule/max_ttl clamp of
    // the ORIGINAL ttl, then the lease deadline as the outermost bound.
    let newExpiry = now + originalTtl;
    const evald = this.evaluate(agentId, grant.capability);
    if (evald.decision === "allow" && evald.ttl_ms !== undefined) {
      newExpiry = Math.min(newExpiry, now + evald.ttl_ms);
    }
    newExpiry = Math.min(newExpiry, lease.deadlineMs);
    if (newExpiry <= now) {
      throw new Error(
        `Cannot renew: the lease '${lease.leaseId}' deadline has passed — open a new lease with scopegate_open_task_lease.`,
      );
    }
    this.grants.updateExpiry(agentId, grantId, newExpiry);
    bestEffortAudit(agentId, "lease_renewed", {
      leaseId: lease.leaseId,
      grantId,
      capability: grant.capability,
      expiresAt: new Date(newExpiry).toISOString(),
      leaseRemainingMs: lease.deadlineMs - now,
    });
    return { grantId, expiresAt: newExpiry, leaseId: lease.leaseId };
  }

  /** Revoke a lease and every grant bound to it (one kill switch per task). */
  revokeLease(agentId: string, leaseId: string): { revokedGrants: number } {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.agentId !== agentId) {
      throw new Error(`Unknown lease '${leaseId}' for agent '${agentId}'.`);
    }
    this.leases.revoke(leaseId);
    const revokedGrants = this.grants.revokeLease(leaseId);
    bestEffortAudit(agentId, "lease_revoked", {
      leaseId,
      goal: lease.goal,
      revokedGrants,
    });
    return { revokedGrants };
  }

  leasesForAgent(agentId: string): Lease[] {
    return this.leases.listForAgent(agentId);
  }

  /** Write-budget accounting for lease-covered proxied writes. */
  consumeLeaseWrite(leaseId: string): boolean {
    return this.leases.consumeWrite(leaseId);
  }

  leaseWritesRemaining(leaseId: string): number {
    return this.leases.writesRemaining(leaseId);
  }

  /* ---------------------------------------------------------------------- */
  /* Mejora #1: task leases — end                                            */
  /* ---------------------------------------------------------------------- */

  /* ---------------------------------------------------------------------- */
  /* Mejora #4: capability plan (one plan, one human decision)               */
  /* ---------------------------------------------------------------------- */

  /**
   * Evaluate a whole task plan at once: auto-approvable capabilities are
   * issued immediately (with their audit trail), denials are reported, and
   * every needs_approval capability is bundled into ONE aggregated approval
   * request — one informed human decision instead of N popups.
   */
  requestPlan(
    agentId: string,
    input: {
      goal: string;
      capabilities: { capability: string; ttl?: string }[];
      open_lease?: boolean;
      max_total?: string;
      max_writes?: number;
    },
  ): {
    goal: string;
    leaseId?: string;
    auto: { capability: string; granted: boolean; ttlMs?: number; code?: string; reason?: string }[];
    pending?: { approvalId: string; items: { capability: string; ttl?: string }[]; approvalExpiresAt: number };
  } {
    let leaseId: string | undefined;
    if (input.open_lease) {
      leaseId = this.openLease(agentId, {
        goal: input.goal,
        upstreams: [],
        max_total: input.max_total,
        max_writes: input.max_writes,
      }).lease.leaseId;
    }

    const auto: { capability: string; granted: boolean; ttlMs?: number; code?: string; reason?: string }[] = [];
    const bundle: { capability: string; ttl?: string }[] = [];

    for (const item of input.capabilities) {
      const evaluation = this.evaluate(agentId, item.capability, item.ttl);
      if (evaluation.decision === "needs_approval") {
        bundle.push(item);
        continue;
      }
      if (evaluation.decision === "deny") {
        auto.push({ capability: item.capability, granted: false, code: evaluation.code, reason: evaluation.reason });
        continue;
      }
      // Pre-flight says allow → issue through the real path (audited, lease-bound).
      const d = this.request(agentId, item.capability, item.ttl, `plan: ${input.goal}`, {
        leaseId,
      });
      auto.push(
        d.allow
          ? { capability: item.capability, granted: true, ttlMs: d.ttlMs }
          : { capability: item.capability, granted: false, code: d.code, reason: d.reason },
      );
    }

    let pending: { approvalId: string; items: { capability: string; ttl?: string }[]; approvalExpiresAt: number } | undefined;
    if (bundle.length > 0) {
      const limits = effectiveLimitsFor(this.policies, agentId);
      let approvalTtlMs = DEFAULT_APPROVAL_TTL_MS;
      try {
        approvalTtlMs = limits.approval_ttl
          ? parseTtlStrict(limits.approval_ttl, "limits.approval_ttl")
          : DEFAULT_APPROVAL_TTL_MS;
      } catch {
        /* validated at load */
      }
      const { request: ap } = createApprovalRequest({
        agentId,
        capability: `plan:${input.goal.slice(0, 60)}`,
        ttl: null,
        reason: input.goal,
        approvalTtlMs,
        plan: bundle,
        ...(leaseId ? { leaseId } : {}),
      });
      bestEffortAudit(agentId, "plan_requested", {
        id: ap.id,
        goal: input.goal,
        items: bundle,
        autoGranted: auto.filter((a) => a.granted).map((a) => a.capability),
        denied: auto.filter((a) => !a.granted).map((a) => a.capability),
        ...(leaseId ? { leaseId } : {}),
      });
      pending = { approvalId: ap.id, items: bundle, approvalExpiresAt: ap.expiresAt };
    }

    return { goal: input.goal, ...(leaseId ? { leaseId } : {}), auto, ...(pending ? { pending } : {}) };
  }

  /* ---------------------------------------------------------------------- */
  /* Mejora #4: capability plan — end                                        */
  /* ---------------------------------------------------------------------- */

  /* ---------------------------------------------------------------------- */
  /* Mejora #5: attenuated delegation for subagents                          */
  /* ---------------------------------------------------------------------- */

  /**
   * Delegate a grant to a child agent (subagent orchestration) with STRICT
   * attenuation, fail-closed on any widening:
   *   - scope_subset must be covered by the parent grant's capability glob
   *     (a child can never exceed what the parent holds);
   *   - ttl must not exceed the parent's REMAINING ttl;
   *   - the child grant carries parentGrantId — revoking the parent (directly
   *     or via fleet revocation) kills every child with it.
   * The child's identity lives in the audit chain (parent_grant), so a
   * subagent's actions are attributable separately from the orchestrator's.
   */
  delegate(
    agentId: string,
    input: {
      grant_id: string;
      child_agent_id: string;
      scope_subset: string;
      ttl?: string;
    },
  ): { grantId: string; childAgentId: string; capability: string; expiresAt: number } {
    const parent = this.grants.byId(agentId, input.grant_id);
    if (!parent) {
      throw new Error(
        `No live grant '${input.grant_id}' for agent '${agentId}' — delegation requires a live parent grant.`,
      );
    }
    if (!input.child_agent_id || input.child_agent_id === agentId) {
      throw new Error(
        "child_agent_id must be a different agent id — delegating to yourself is just a renew (use scopegate_renew_capability or re-request).",
      );
    }
    // Scope attenuation: the subset must MATCH INTO the parent glob.
    if (!picomatch.isMatch(input.scope_subset, parent.capability)) {
      throw new Error(
        `Attenuation violation: '${input.scope_subset}' is not covered by the parent capability '${parent.capability}' — a child can never exceed its parent (fail-closed).`,
      );
    }
    const now = Date.now();
    const parentRemaining = Math.max(0, parent.expiresAt - now);
    let ttlMs = parentRemaining;
    if (input.ttl !== undefined) {
      const asked = parseTtlStrict(input.ttl, "ttl");
      if (asked > parentRemaining) {
        throw new Error(
          `Attenuation violation: ttl '${input.ttl}' exceeds the parent's remaining ttl (${Math.ceil(parentRemaining / 1000)}s) — a child can never outlive its parent (fail-closed).`,
        );
      }
      ttlMs = asked;
    }
    const child = this.grants.issue({
      agentId: input.child_agent_id,
      capability: input.scope_subset,
      ttlMs,
      parentGrantId: parent.id,
      rule: "delegated",
      ...(parent.leaseId ? { leaseId: parent.leaseId } : {}),
    });
    bestEffortAudit(agentId, "grant_delegated", {
      parent_grant: parent.id,
      parent_capability: parent.capability,
      child_grant: child.id,
      child_agent_id: input.child_agent_id,
      capability: child.capability,
      ttlMs,
      expiresAt: new Date(child.expiresAt).toISOString(),
      ...(parent.leaseId ? { leaseId: parent.leaseId } : {}),
    });
    return {
      grantId: child.id,
      childAgentId: input.child_agent_id,
      capability: child.capability,
      expiresAt: child.expiresAt,
    };
  }

  /* ---------------------------------------------------------------------- */
  /* Mejora #5: delegation — end                                             */
  /* ---------------------------------------------------------------------- */

  /** Mejora #7: inline-payload ceiling for the agent (limits.max_inline_bytes). */
  maxInlineBytesFor(agentId: string): number | undefined {
    return effectiveLimitsFor(this.policies, agentId).max_inline_bytes;
  }

  /** M4: logical agent identities known to this engine (policies sections). */
  agentIds(): string[] {
    return Object.keys(this.policies.agents);
  }

  /**
   * M4 allowlist check. Sections may be globs, so membership is a match, not
   * a lookup — `http.ts` must ask this instead of scanning `agentIds()`.
   */
  acceptsAgentId(agentId: string): boolean {
    return agentIdAccepted(this.policies, agentId);
  }

  /**
   * The section that governs an identity, for audit and diagnostics: an
   * operator seeing `nexgen-kimi-6a68…` in the audit needs to know which
   * declared rule set produced the decision.
   */
  agentKeyOf(agentId: string): string | null {
    return agentKeyFor(this.policies, agentId);
  }

  /**
   * Resumen por identidad para la consola: cuántas reglas tiene y su TTL por
   * defecto. La lista de agentes ES la sección `agents:` de las políticas —
   * no hay un registro paralelo que se pueda desincronizar.
   */
  agentSummaries(): Array<{ agentId: string; defaultTtl?: string; rules: number }> {
    return Object.entries(this.policies.agents).map(([agentId, a]) => ({
      agentId,
      ...(a.default_ttl !== undefined ? { defaultTtl: a.default_ttl } : {}),
      rules: a.capabilities.length,
    }));
  }

  /**
   * Sliding-window rate limit for scopegate_request_capability (H-04.7).
   * Counted here, enforced by server.ts before evaluating the request.
   */
  checkRateLimit(agentId: string): {
    allowed: boolean;
    reason?: string;
    retryAfterMs?: number;
  } {
    const limits = effectiveLimitsFor(this.policies, agentId);
    const spec = limits.rate_limit ?? DEFAULT_RATE_LIMIT;
    let entry = this.limiters.get(agentId);
    if (!entry || entry.spec !== spec) {
      let window;
      try {
        window = parseRateWindow(spec);
      } catch {
        window = parseRateWindow(DEFAULT_RATE_LIMIT); // validated at load; defensive
      }
      entry = { spec, limiter: new RateLimiter(window) };
      this.limiters.set(agentId, entry);
    }
    const res = entry.limiter.check();
    if (!res.allowed) {
      const waitS = Math.max(1, Math.ceil((res.retryAfterMs ?? 0) / 1000));
      return {
        allowed: false,
        retryAfterMs: res.retryAfterMs,
        reason:
          `capability_rate_limited: agent '${agentId}' exceeded ${spec} on scopegate_request_capability. ` +
          `Back off and retry in ~${waitS}s — do NOT loop requests.`,
      };
    }
    // EPIC-10: the team layer's rate limit applies ADDITIONALLY — both the
    // local and the team window must pass (restrictive intersection).
    const teamSpec = this.teamLimitsFor(agentId).rate_limit;
    if (teamSpec) {
      let teamEntry = this.teamLimiters.get(agentId);
      if (!teamEntry || teamEntry.spec !== teamSpec) {
        let window;
        try {
          window = parseRateWindow(teamSpec);
        } catch {
          window = parseRateWindow(DEFAULT_RATE_LIMIT); // validated at apply; defensive
        }
        teamEntry = { spec: teamSpec, limiter: new RateLimiter(window) };
        this.teamLimiters.set(agentId, teamEntry);
      }
      const teamRes = teamEntry.limiter.check();
      if (!teamRes.allowed) {
        const waitS = Math.max(1, Math.ceil((teamRes.retryAfterMs ?? 0) / 1000));
        return {
          allowed: false,
          retryAfterMs: teamRes.retryAfterMs,
          reason:
            `[team policy] capability_rate_limited: agent '${agentId}' exceeded ${teamSpec} on scopegate_request_capability. ` +
            `Back off and retry in ~${waitS}s — do NOT loop requests.`,
        };
      }
    }
    return { allowed: true };
  }

  /* --------------------- team policy layer (EPIC-10) --------------------- */

  /**
   * Install (or replace) the cloud team policy layer. The input must ALREADY
   * be signature-verified and schema-validated by the caller
   * (src/cloud/client/policy-sync.ts); the engine trusts that gate and never
   * fetches anything itself. The layer is a restrictive intersection over
   * the local policy: it can only deny more / clamp TTLs lower, never allow
   * what the local policy denies.
   */
  applyTeamPolicy(policies: PoliciesFile, meta: TeamPolicyMeta): void {
    this.teamPolicies = policies;
    this.teamPolicyMeta = meta;
    this.teamLimiters.clear();
  }

  /** Remove the team layer (local-first fallback / cloud unenrolled). */
  clearTeamPolicy(): void {
    this.teamPolicies = null;
    this.teamPolicyMeta = null;
    this.teamLimiters.clear();
  }

  /** Provenance of the installed team layer, or null when local-only. */
  teamPolicyInfo(): TeamPolicyMeta | null {
    return this.teamPolicyMeta;
  }

  /** Team limits for the agent (global merged with per-agent; agent wins). */
  private teamLimitsFor(agentId: string): PolicyLimits {
    if (!this.teamPolicies) return {};
    return effectiveLimitsFor(this.teamPolicies, agentId);
  }

  /** First team rule matching the capability (any kind), else null. */
  private teamRuleFor(agentId: string, capability: string): PolicyRule | null {
    const tp = this.teamPolicies;
    if (!tp) return null;
    const key = agentKeyFor(tp, agentId);
    if (!key) return null;
    for (const rule of tp.agents[key]?.capabilities ?? []) {
      if (picomatch.isMatch(capability, rule.match)) return rule;
    }
    return null;
  }

  /**
   * Team pre-gate, evaluated on EVERY request while a team layer is
   * installed (before any grant short-circuit): team deny globs are a hard
   * ceiling and the team policy must explicitly cover the capability —
   * team silence is a deny. Returns the deny Decision, or null when the
   * capability survives the team layer.
   */
  private teamGate(agentId: string, capability: string): Decision | null {
    const tp = this.teamPolicies;
    if (!tp) return null;
    for (const glob of this.teamLimitsFor(agentId).deny ?? []) {
      if (picomatch.isMatch(capability, glob)) {
        return {
          allow: false,
          code: "ceiling_blocked",
          reason:
            `[team policy] Capability '${capability}' is blocked by a team hard limit (deny '${glob}'). ` +
            `Team limits are non-negotiable — do NOT retry with broader scope; a team admin must change the team policy.`,
        };
      }
    }
    if (!agentKeyFor(tp, agentId)) {
      return {
        allow: false,
        code: "no_policy",
        reason:
          `[team policy] The team policy does not cover agent '${agentId}'. ` +
          `A team admin must add it to the team policy (until then the team layer denies every capability).`,
      };
    }
    if (!this.teamRuleFor(agentId, capability)) {
      return {
        allow: false,
        code: "no_rule",
        reason:
          `[team policy] No team rule allows '${capability}' for agent '${agentId}'. ` +
          `The team policy is a ceiling over the local policy — a team admin must allow it there first.`,
      };
    }
    return null;
  }

  /**
   * TTL ceiling contributed by the team layer (ms), or null when it imposes
   * none. Only values the team policy SPECIFIES constrain the grant: a team
   * rule without `ttl` and an absent `max_ttl` mean "no extra constraint"
   * (a terse allow-rule must not silently clamp every grant to the default).
   */
  private teamTtlCeilingMs(agentId: string, capability: string): number | null {
    const tp = this.teamPolicies;
    if (!tp) return null;
    let ceiling: number | null = null;
    try {
      const rule = this.teamRuleFor(agentId, capability);
      const key = agentKeyFor(tp, agentId);
      const agentDefault = key ? tp.agents[key]?.default_ttl : undefined;
      if (rule?.ttl !== undefined) {
        ceiling = parseTtlStrict(rule.ttl, `ttl of team rule '${rule.match}'`);
      } else if (agentDefault !== undefined) {
        ceiling = parseTtlStrict(agentDefault, "team default_ttl");
      }
      const maxTtl = this.teamLimitsFor(agentId).max_ttl;
      if (maxTtl !== undefined) {
        const m = parseTtlStrict(maxTtl, "team limits.max_ttl");
        ceiling = ceiling === null ? m : Math.min(ceiling, m);
      }
    } catch {
      /* validated when the layer was applied; defensive */
    }
    return ceiling;
  }

  /** Approval TTL for team-mandated escalations: min(local, team) when both. */
  private teamApprovalTtlMs(agentId: string, localLimits: PolicyLimits): number {
    let localMs: number | null = null;
    let teamMs: number | null = null;
    try {
      if (localLimits.approval_ttl) {
        localMs = parseTtlStrict(localLimits.approval_ttl, "limits.approval_ttl");
      }
      const teamSpec = this.teamLimitsFor(agentId).approval_ttl;
      if (teamSpec) {
        teamMs = parseTtlStrict(teamSpec, "team limits.approval_ttl");
      }
    } catch {
      /* validated at load/apply; keep the safe defaults defensively */
    }
    if (localMs !== null && teamMs !== null) return Math.min(localMs, teamMs);
    return teamMs ?? localMs ?? DEFAULT_APPROVAL_TTL_MS;
  }

  /* ------------------------- hot-reload (H-04.5) ------------------------- */

  /**
   * Watch policies.yaml and hot-reload it (debounced). The DIRECTORY is
   * watched (atomic tmp+rename saves would kill a file-level watch). An
   * invalid document keeps the last-good policy set and is audited as
   * policy_reload_error; the FIRST load at startup stays fail-closed (load).
   */
  startWatching(debounceMs = 250): void {
    if (this.watcher) return;
    const dir = path.dirname(POLICIES_PATH);
    const base = path.basename(POLICIES_PATH);
    try {
      this.watcher = fs.watch(dir, (_event, filename) => {
        if (filename && filename.toString() !== base) return;
        if (this.reloadTimer) clearTimeout(this.reloadTimer);
        this.reloadTimer = setTimeout(() => this.reloadNow(), debounceMs);
        this.reloadTimer.unref?.();
      });
    } catch (e) {
      console.error(
        `[scopegate] warn: cannot watch ${POLICIES_PATH} for hot-reload: ${(e as Error).message}`,
      );
    }
  }

  stopWatching(): void {
    if (this.reloadTimer) {
      clearTimeout(this.reloadTimer);
      this.reloadTimer = null;
    }
    this.watcher?.close();
    this.watcher = null;
  }

  private reloadNow(): void {
    try {
      if (!fs.existsSync(POLICIES_PATH)) {
        // Deleted file: fail-closed to the deny-all default.
        this.policies = { version: 1, agents: {} };
        console.error(
          "[scopegate] warn: policies.yaml deleted — running with an empty (deny-all) policy set",
        );
        return;
      }
      const raw = YAML.parse(fs.readFileSync(POLICIES_PATH, "utf8"));
      this.policies = validatePoliciesFile(raw);
      console.error("[scopegate] info: policies.yaml reloaded");
    } catch (e) {
      // Last-good wins: the previous valid policy set stays in force.
      bestEffortAudit(reloadAuditAgent(), "policy_reload_error", {
        path: POLICIES_PATH,
        error: (e as Error).message,
      });
      console.error(
        `[scopegate] error: policies.yaml reload failed — keeping last-good policy set: ${(e as Error).message}`,
      );
    }
  }

  /* --------------------- human approvals (H-04.3) ------------------------ */

  /**
   * Fresh-read the approval queue (mtime-checked, no watchers) and consume
   * what belongs to this agent: approved decisions materialize ONE-SHOT
   * grants, denied/expired requests are audited. Consumed requests are marked
   * resolved in the pending file so nothing is consumed twice, even across
   * restarts.
   */
  private refreshApprovals(agentId: string): void {
    let pendings: ApprovalRequest[];
    let decisions: ReturnType<typeof readDecisions>;
    try {
      pendings = readPendingRequests();
      decisions = readDecisions();
    } catch {
      return; // unreadable queue: nothing materializes (still fail-closed)
    }
    const now = Date.now();
    expireStaleIntents(now);
    const updates = new Map<string, { status: ApprovalStatus; resolvedAt: number }>();
    for (const req of pendings) {
      if (req.agentId !== agentId) continue;
      if (req.status && req.status !== "pending") continue;
      const dec = decisions.get(req.id);
      if (dec) {
        updates.set(req.id, { status: dec.decision, resolvedAt: now });
        if (dec.decision === "approved" && req.plan && req.plan.length > 0) {
          // Mejora #4: a plan approval issues EVERY bundled capability in one
          // shot (each clamped per its own rule ceilings; bound to the plan's
          // lease when it carries one).
          bestEffortAudit(agentId, "approval_approved", {
            id: req.id,
            capability: req.capability,
            decidedBy: dec.decidedBy,
            planSize: req.plan.length,
          });
          for (const item of req.plan) {
            try {
              const ttlMs = this.materializedTtlFor(agentId, item.capability, item.ttl);
              const grant = this.grants.issue({
                agentId,
                capability: item.capability,
                ttlMs,
                approvalId: req.id,
                rule: "human_approval",
                ...(req.leaseId ? { leaseId: req.leaseId } : {}),
              });
              bestEffortAudit(agentId, "grant_issued", {
                id: grant.id,
                capability: item.capability,
                ttlMs,
                expiresAt: new Date(grant.expiresAt).toISOString(),
                via: "human_approval",
                approvalId: req.id,
                plan: true,
                ...(req.leaseId ? { leaseId: req.leaseId } : {}),
              });
            } catch (e) {
              console.error(
                `[scopegate] error: failed to materialize plan item '${item.capability}' of ${req.id}: ${(e as Error).message}`,
              );
            }
          }
          continue;
        }
        if (dec.decision === "approved") {
          try {
            const ttlMs = this.materializedTtl(agentId, req);
            // EPIC-06: the keychain fields of the request ride into the
            // materialized grant (audience ≠ self is exactly why it
            // escalated; purpose defaults to the request's reason).
            const grant = this.grants.issue({
              agentId,
              capability: req.capability,
              ttlMs,
              approvalId: req.id,
              rule: "human_approval",
              ...(req.audience ? { audience: req.audience } : {}),
              ...(req.mode ? { mode: req.mode } : {}),
              ...(req.purpose ? { purpose: req.purpose } : {}),
            });
            bestEffortAudit(agentId, "approval_approved", {
              id: req.id,
              capability: req.capability,
              decidedBy: dec.decidedBy,
            });
            bestEffortAudit(agentId, "grant_issued", {
              id: grant.id,
              capability: req.capability,
              ttlMs,
              expiresAt: new Date(grant.expiresAt).toISOString(),
              via: "human_approval",
              approvalId: req.id,
              ...(req.audience ? { audience: req.audience } : {}),
              ...(req.mode ? { mode: req.mode } : {}),
              ...(req.purpose ? { purpose: req.purpose } : {}),
            });
            // Mejora #2 (approval continuation): a queued intent attached to
            // this approval is executed NOW, with the fresh grant — the agent
            // collects the outcome via scopegate_collect/_wait instead of
            // re-issuing the call and burning turns. Fire-and-forget: the
            // executor audits `intent_executed` (status + hashes) itself.
            const intent = pendingIntentFor(req.id);
            if (intent && this.intentExecutor) {
              const startedAt = Date.now();
              void Promise.resolve()
                .then(() => this.intentExecutor!(intent))
                .then((outcome) => {
                  storeIntentResult({
                    intentId: intent.id,
                    approvalId: intent.approvalId,
                    agentId: intent.agentId,
                    tool: intent.tool,
                    status: outcome.ok ? "executed" : "failed",
                    ...(outcome.ok
                      ? { result: outcome.result }
                      : { error: outcome.error ?? "intent execution failed" }),
                    executedAt: Date.now(),
                    durationMs: Date.now() - startedAt,
                  });
                })
                .catch((e: unknown) => {
                  storeIntentResult({
                    intentId: intent.id,
                    approvalId: intent.approvalId,
                    agentId: intent.agentId,
                    tool: intent.tool,
                    status: "failed",
                    error: e instanceof Error ? e.message : String(e),
                    executedAt: Date.now(),
                    durationMs: Date.now() - startedAt,
                  });
                });
            }
          } catch (e) {
            console.error(
              `[scopegate] error: failed to materialize approved request ${req.id}: ${(e as Error).message}`,
            );
          }
        } else {
          bestEffortAudit(agentId, "approval_denied", {
            id: req.id,
            capability: req.capability,
            decidedBy: dec.decidedBy,
          });
        }
      } else if (req.expiresAt <= now) {
        updates.set(req.id, { status: "expired", resolvedAt: now });
        bestEffortAudit(agentId, "approval_expired", {
          id: req.id,
          capability: req.capability,
        });
      }
    }
    if (updates.size > 0) {
      try {
        updatePendingStatuses(updates);
      } catch (e) {
        console.error(
          `[scopegate] warn: could not mark approvals resolved: ${(e as Error).message}`,
        );
      }
    }
  }

  /** One-shot grant TTL for an approved request: min(requested, rule, max_ttl). */
  private materializedTtl(agentId: string, req: ApprovalRequest): number {
    const agentKey = agentKeyFor(this.policies, agentId);
    const agent = agentKey ? this.policies.agents[agentKey] : null;
    const limits = effectiveLimitsFor(this.policies, agentId);
    let requested = Number.MAX_SAFE_INTEGER;
    if (req.ttl) {
      try {
        requested = parseTtlStrict(req.ttl);
      } catch {
        /* a request created with a valid ttl; defensive fallback */
      }
    }
    let ceiling = DEFAULT_TTL_MS;
    const rule = agent?.capabilities?.find(
      (r) => r.require === "human_approval" && picomatch.isMatch(req.capability, r.match),
    );
    if (rule?.ttl !== undefined) {
      ceiling = parseTtlStrict(rule.ttl, `ttl of rule '${rule.match}'`);
    } else if (agent?.default_ttl !== undefined) {
      ceiling = parseTtlStrict(agent.default_ttl, "default_ttl");
    }
    let ttlMs = Math.min(requested, ceiling);
    if (limits.max_ttl !== undefined) {
      ttlMs = Math.min(ttlMs, parseTtlStrict(limits.max_ttl, "limits.max_ttl"));
    }
    // EPIC-10: the team layer's ceiling also clamps approval-materialized
    // one-shot grants (min) — a human approval can never widen the team cap.
    const teamCeiling = this.teamTtlCeilingMs(agentId, req.capability);
    if (teamCeiling !== null) ttlMs = Math.min(ttlMs, teamCeiling);
    return ttlMs;
  }

  /**
   * Per-capability materialization TTL for approvals (mejora #4): the same
   * clamp materializedTtl applies to a single approval, generalized for plan
   * items — min(agent's ask, matching-rule ceiling, default_ttl, max_ttl,
   * team ceiling). Falls back to the strict require-rule lookup of the
   * original single-approval path.
   */
  private materializedTtlFor(agentId: string, capability: string, ttl?: string): number {
    const agentKey = agentKeyFor(this.policies, agentId);
    const agent = agentKey ? this.policies.agents[agentKey] : null;
    const limits = effectiveLimitsFor(this.policies, agentId);
    let requested = Number.MAX_SAFE_INTEGER;
    if (ttl) {
      requested = parseTtlStrict(ttl, "plan item ttl");
    }
    let ceiling = DEFAULT_TTL_MS;
    // Prefer a matching require:human_approval rule (the plan's own kind);
    // fall back to any matching rule's ttl for ceiling purposes.
    const rules = agent?.capabilities?.filter((r) => picomatch.isMatch(capability, r.match)) ?? [];
    const requireRule = rules.find((r) => r.require === "human_approval");
    const anyRule = requireRule ?? rules[0];
    if (anyRule?.ttl !== undefined) {
      ceiling = parseTtlStrict(anyRule.ttl, `ttl of rule '${anyRule.match}'`);
    } else if (agent?.default_ttl !== undefined) {
      ceiling = parseTtlStrict(agent.default_ttl, "default_ttl");
    }
    let ttlMs = Math.min(requested, ceiling);
    if (limits.max_ttl !== undefined) {
      ttlMs = Math.min(ttlMs, parseTtlStrict(limits.max_ttl, "limits.max_ttl"));
    }
    const teamCeiling = this.teamTtlCeilingMs(agentId, capability);
    if (teamCeiling !== null) ttlMs = Math.min(ttlMs, teamCeiling);
    return ttlMs;
  }

  /** Purge expired grants and audit grant_expired for each. EPIC-06:
   *  tombstones (used/revoked) expire silently — their lifecycle event
   *  (grant_claimed / grants_revoked) already exists; re-auditing an expiry
   *  for them would be noise. */
  private purgeAndAudit(): void {
    for (const g of this.grants.purgeExpired()) {
      if (g.status === "used" || g.status === "revoked") continue;
      bestEffortAudit(g.agentId, "grant_expired", {
        id: g.id,
        capability: g.capability,
      });
    }
  }

  /* --------------------- propose_policy 2.0 (H-04.4) --------------------- */

  /**
   * Agent-proposed rule → append to a pending file for HUMAN review.
   * Never touches the live policies.yaml.
   *
   * 2.0 hardening:
   *   - Field allowlist: agents propose {match, ttl} ONLY (no require:null,
   *     no auto_approve, no limits, no redact) — anything else throws.
   *   - `match` must be a picomatch-compilable glob; `ttl` strictly parseable.
   *   - Dedup: an identical pending (agentId, match, ttl) is not duplicated.
   *   - Lint: proposals colliding with limits.deny or exceeding max_ttl are
   *     flagged `lint: "conflicts_with_limits"` so the human sees it.
   *
   * `policies` (the live set) is passed for linting; without it lint is skipped.
   */
  static proposeRule(
    agentId: string,
    rule: PolicyRule,
    justification: string,
    policies?: PoliciesFile,
  ): { file: string; deduped: boolean; lint?: string } {
    const ALLOWED = new Set(["match", "ttl"]);
    for (const k of Object.keys(rule ?? {})) {
      if (!ALLOWED.has(k)) {
        throw new Error(
          `Proposal rejected: field '${k}' is not agent-settable. Agents may propose {match, ttl} only; a human edits everything else in policies.yaml.`,
        );
      }
    }
    try {
      assertCompilableGlob(rule?.match, "match");
    } catch (e) {
      throw new Error(`Proposal rejected: ${(e as Error).message}`);
    }
    if (rule.ttl !== undefined) {
      try {
        parseTtlStrict(rule.ttl, "ttl");
      } catch (e) {
        throw new Error(`Proposal rejected: ${(e as Error).message}`);
      }
    }

    const lint = policies ? lintProposal(policies, agentId, rule) : undefined;

    ensureDir();
    // Dedup by (agentId, match, ttl) among pending proposals.
    const dup = readPendingProposals().find(
      (p) =>
        p.agentId === agentId &&
        p.status === "pending_human_review" &&
        p.rule?.match === rule.match &&
        (p.rule?.ttl ?? undefined) === (rule.ttl ?? undefined),
    );
    if (dup) {
      return { file: PENDING_POLICIES_PATH, deduped: true, ...(lint ? { lint } : {}) };
    }

    const entry = {
      proposedAt: new Date().toISOString(),
      agentId,
      rule,
      justification,
      status: "pending_human_review",
      ...(lint ? { lint } : {}),
    };
    fs.appendFileSync(PENDING_POLICIES_PATH, "---\n" + YAML.stringify(entry), {
      mode: 0o600,
    });
    return { file: PENDING_POLICIES_PATH, deduped: false, ...(lint ? { lint } : {}) };
  }

  /** Instance convenience: propose with the LIVE policy set for linting. */
  proposePolicy(
    agentId: string,
    rule: PolicyRule,
    justification: string,
  ): { file: string; deduped: boolean; lint?: string } {
    return PolicyEngine.proposeRule(agentId, rule, justification, this.policies);
  }
}

/* ------------------------------------------------------------------------ */
/* propose_policy helpers                                                     */
/* ------------------------------------------------------------------------ */

interface PendingProposal {
  proposedAt?: string;
  agentId?: string;
  rule?: { match?: string; ttl?: string };
  justification?: string;
  status?: string;
  lint?: string;
}

/** Parse policies.pending.yaml (YAML multi-doc, one proposal per doc). */
function readPendingProposals(): PendingProposal[] {
  if (!fs.existsSync(PENDING_POLICIES_PATH)) return [];
  try {
    const docs = YAML.parseAllDocuments(
      fs.readFileSync(PENDING_POLICIES_PATH, "utf8"),
    );
    const out: PendingProposal[] = [];
    for (const d of docs) {
      try {
        const v = d.toJS() as unknown;
        if (v && typeof v === "object") out.push(v as PendingProposal);
      } catch {
        // skip a broken doc; dedup simply won't see it
      }
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Informational lint: does the proposal collide with hard limits? Two cheap
 * conservative checks (glob-vs-glob intersection is undecidable in general):
 * the deny glob covers the proposal, or vice versa; and ttl > max_ttl.
 */
function lintProposal(
  policies: PoliciesFile,
  agentId: string,
  rule: PolicyRule,
): string | undefined {
  const limits = effectiveLimitsFor(policies, agentId);
  for (const glob of limits.deny ?? []) {
    try {
      if (
        picomatch.isMatch(rule.match, glob) ||
        picomatch.isMatch(glob, rule.match)
      ) {
        return "conflicts_with_limits";
      }
    } catch {
      /* globs validated at load */
    }
  }
  if (limits.max_ttl && rule.ttl) {
    try {
      if (parseTtlStrict(rule.ttl) > parseTtlStrict(limits.max_ttl)) {
        return "conflicts_with_limits";
      }
    } catch {
      /* values validated above / at load */
    }
  }
  return undefined;
}
