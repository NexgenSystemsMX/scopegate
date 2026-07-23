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
import { GrantStore } from "./grants.js";
import {
  createApprovalRequest,
  readPendingRequests,
  readDecisions,
  updatePendingStatuses,
  DEFAULT_APPROVAL_TTL_MS,
  type ApprovalRequest,
  type ApprovalStatus,
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
}

/** Hard, non-negotiable limits. Global and per-agent; the per-agent wins. */
export interface PolicyLimits {
  /** Absolute ceiling for every grant TTL (e.g. "1h"). */
  max_ttl?: string;
  /** Capability globs denied BEFORE any auto_approve rule is evaluated. */
  deny?: string[];
  /** Sliding-window limit for scopegate_request_capability (e.g. "30/m"). */
  rate_limit?: string;
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
  | "config_error";

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

const RULE_KEYS = new Set(["match", "auto_approve", "ttl", "require", "redact"]);
const LIMIT_KEYS = new Set(["max_ttl", "deny", "rate_limit", "approval_ttl"]);

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
  if (lim.approval_ttl !== undefined) strictTtlAt(lim.approval_ttl, `${where}.approval_ttl`);
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

function agentKeyFor(policies: PoliciesFile, agentId: string): string | null {
  if (policies.agents[agentId]) return agentId;
  if (policies.agents["*"]) return "*";
  return null;
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

  constructor(policies: PoliciesFile, deps: { grants?: GrantStore } = {}) {
    this.policies = policies;
    this.grants = deps.grants ?? new GrantStore();
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

  /** Evaluate a capability request. Grants persist on disk and expire by TTL. */
  request(agentId: string, capability: string, ttl?: string, reason = ""): Decision {
    // Pick up human decisions first: an approved request materializes its
    // one-shot grant here (fresh read by mtime — no cross-process watchers).
    this.refreshApprovals(agentId);

    // EPIC-10 team layer (restrictive intersection, evaluated LIVE at request
    // time): when a team policy is installed it is a ceiling over every path
    // below — including live grants. Team silence on a capability is a deny.
    // No-op when no team policy is installed (local-first default).
    const teamGateDeny = this.teamGate(agentId, capability);
    if (teamGateDeny) return teamGateDeny;

    // Idempotent re-request: a live covering grant (including one just
    // materialized from an approval) is returned, not duplicated.
    const now = Date.now();
    const existing = this.grants.coveringGrant(agentId, capability, now);
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

    // Agent-supplied TTL: strict parse, clear deny on garbage.
    let requested: number;
    try {
      requested = ttl === undefined ? Number.MAX_SAFE_INTEGER : parseTtlStrict(ttl);
    } catch (e) {
      return { allow: false, code: "invalid_ttl", reason: (e as Error).message };
    }

    for (const rule of agent.capabilities ?? []) {
      if (!picomatch.isMatch(capability, rule.match)) continue;

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
        const grant = this.grants.issue({
          agentId,
          capability,
          ttlMs,
          redact: rule.redact,
          rule: rule.match,
        });
        bestEffortAudit(agentId, "grant_issued", {
          id: grant.id,
          capability,
          ttlMs,
          expiresAt: new Date(grant.expiresAt).toISOString(),
          rule: rule.match,
          ...(teamRule ? { teamRule: teamRule.match } : {}),
        });
        // agent can shorten, never extend
        return { allow: true, ttlMs, rule: rule.match };
      }
    }
    return {
      allow: false,
      code: "no_rule",
      reason: `No auto_approve rule matches '${capability}' for agent '${agentId}'.`,
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
  isGranted(agentId: string, capability: string): boolean {
    this.refreshApprovals(agentId);
    this.purgeAndAudit();
    return this.grants.isGranted(agentId, capability);
  }

  /**
   * The latest live grant covering the capability (historical "latest
   * covering grant wins" rule), carrying redact categories and remaining TTL.
   * Used by server.ts for the token-TTL clamp and response redaction.
   */
  coveringGrant(agentId: string, capability: string) {
    this.refreshApprovals(agentId);
    this.purgeAndAudit();
    return this.grants.coveringGrant(agentId, capability);
  }

  activeGrants(agentId: string) {
    this.purgeAndAudit();
    return this.grants.active(agentId);
  }

  /** Revoke every grant of an agent; audits grants_revoked with the count. */
  revokeAgent(agentId: string): number {
    const removed = this.grants.revokeAgent(agentId);
    if (removed > 0) {
      bestEffortAudit(reloadAuditAgent(), "grants_revoked", {
        revokedAgentId: agentId,
        count: removed,
      });
    }
    return removed;
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
    const updates = new Map<string, { status: ApprovalStatus; resolvedAt: number }>();
    for (const req of pendings) {
      if (req.agentId !== agentId) continue;
      if (req.status && req.status !== "pending") continue;
      const dec = decisions.get(req.id);
      if (dec) {
        updates.set(req.id, { status: dec.decision, resolvedAt: now });
        if (dec.decision === "approved") {
          try {
            const ttlMs = this.materializedTtl(agentId, req);
            const grant = this.grants.issue({
              agentId,
              capability: req.capability,
              ttlMs,
              approvalId: req.id,
              rule: "human_approval",
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
            });
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

  /** Purge expired grants and audit grant_expired for each. */
  private purgeAndAudit(): void {
    for (const g of this.grants.purgeExpired()) {
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
