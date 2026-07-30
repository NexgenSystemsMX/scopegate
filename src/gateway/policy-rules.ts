/**
 * Structured rule editing for the human console (`/admin/policies/rules`).
 *
 * WHY THIS EXISTS ON TOP OF `/admin/policies`
 *
 * The raw endpoint (GET/PUT the whole `policies.yaml` as text) is the right
 * primitive for an operator who knows YAML, and it already does the hard part:
 * fail-closed validation, a `.prev` backup, 0600, and a hot `reload()`. But a
 * console that renders "capability → effective decision" as a table cannot ask
 * a human to hand-edit YAML to flip one toggle. This layer turns one toggle
 * into a read-modify-write of that same file, reusing the same validation and
 * the same reload — there is no second source of truth.
 *
 * Three properties this layer must have that the raw endpoint does not need:
 *
 *   1. COMMENTS SURVIVE. `policies.yaml` carries operational documentation in
 *      its comments ("this rule exists because…"). `YAML.parse` + `stringify`
 *      destroys all of it, which would make the console's first toggle a
 *      silent act of vandalism. So every edit goes through
 *      `YAML.parseDocument`, which keeps comments and formatting attached to
 *      the nodes it does not touch.
 *
 *   2. NO LOST UPDATES. The console now writes rules while a human may be
 *      editing the raw YAML in the same UI. Both paths write the whole file,
 *      so the last writer would silently win. Every read returns an `etag`
 *      (sha256 of the exact bytes served) and every write requires it back via
 *      `If-Match`; a stale etag is a 409, not an overwrite.
 *
 *   3. WIDENING IS NEVER SILENT. Two guards, both fail-closed:
 *
 *      - A rule that collides with a `limits.deny` glob is refused outright.
 *        `deny` is evaluated before any `auto_approve`, so such a rule would
 *        be dead config that reads as if it granted something. Refusing is
 *        honest; accepting would be a lie in the table.
 *
 *      - A rule whose glob is WIDER than an existing `human_approval` rule and
 *        auto-approves it requires `acknowledge_widening: true`. This is not
 *        hypothetical: production has a specific
 *        `nexgen:call:github_create_pr_draft` → `human_approval` rule sitting
 *        under a wide `nexgen:call:*` → `auto_approve`. Specificity is what
 *        keeps the gate alive. A console toggle that reordered or widened that
 *        pair would remove a human gate with no one noticing, which is exactly
 *        the failure ScopeGate exists to prevent.
 *
 * What this layer deliberately does NOT let the console do: touch
 * `limits.deny`. Hard denials are the floor of the policy; they are changed by
 * a human editing the file, with the diff in front of them.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import picomatch from "picomatch";
import { POLICIES_PATH, ensureDir } from "../config/config.js";
import { validatePoliciesFile, type PolicyRule } from "../policy/engine.js";

/** One rule as the console sees it. `agentId` is the section key (may be a glob). */
export interface RuleView {
  agentId: string;
  match: string;
  auto_approve?: boolean;
  ttl?: string;
  require?: "human_approval";
  /** Position in the agent's `capabilities` list — the only stable identity a
   * rule has, because duplicate `match` values are legal (see `shadowedBy`). */
  index: number;
  /**
   * M6 arg guard. MUST be surfaced: `when` changes what a rule means, and a
   * console (or a human reading this API) that cannot see it will misread the
   * policy.
   *
   * Concretely, the running policy has two rules for
   * `nexgen:call:github_create_pr_draft`: an `auto_approve` guarded by
   * `when: {branch: "kimi/*"}`, then a `require: human_approval`. Without the
   * guard in view, that reads as "auto-approved, and the gate below is dead" —
   * which is the exact wrong conclusion. With it, the design is legible: PRs on
   * the governed branch namespace are auto-approved, anything else escalates.
   * Omitting this field made a reviewer of this very endpoint reach the wrong
   * conclusion about production, so it is not a cosmetic addition.
   */
  when?: Record<string, string | number | boolean>;
  /** True when a `limits.deny` glob already kills this capability. */
  deniedByGlob?: string;
  /**
   * Index of an EARLIER rule that already decides every capability this one
   * would match, making this rule unreachable.
   *
   * This is not a theoretical nicety. Evaluation is first-match-wins over the
   * file order, and the running production/staging policies contain
   * `nexgen:call:github_create_pr_draft` TWICE: an `auto_approve` and, right
   * after it, a `require: human_approval`. In staging the first one has no
   * `when` guard, so the human gate below it is dead code and nothing in the
   * system said so. A console that renders rules as a flat list would show a
   * gate that does not exist.
   *
   * A rule guarded by `when` never shadows: it may decline to match at call
   * time, so what follows it is still reachable.
   */
  shadowedBy?: number;
}

export interface RulesSnapshot {
  agents: Array<{
    agentId: string;
    defaultTtl?: string;
    rules: RuleView[];
  }>;
  /** Read-only in this API on purpose — see the file header. */
  denyGlobs: string[];
  /** sha256 of the exact file bytes served. Required back on writes. */
  etag: string;
}

export type RulesError =
  | { kind: "conflict"; message: string; etag: string }
  | { kind: "invalid"; message: string }
  | { kind: "needs_acknowledge"; message: string; widens: string[] }
  | { kind: "not_found"; message: string };

/** Current policies text, or "" when the file does not exist yet. */
export function readPoliciesRaw(): string {
  return fs.existsSync(POLICIES_PATH) ? fs.readFileSync(POLICIES_PATH, "utf8") : "";
}

export function etagOf(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

/**
 * Effective deny globs for an agent: global `limits.deny` merged with the
 * agent's own. Mirrors `effectiveLimitsFor` (agent wins) so the console shows
 * the same floor the engine enforces.
 */
function denyGlobsFor(parsed: unknown, agentId: string): string[] {
  const p = parsed as {
    limits?: { deny?: string[] };
    agents?: Record<string, { limits?: { deny?: string[] } }>;
  } | null;
  const agentDeny = p?.agents?.[agentId]?.limits?.deny;
  return agentDeny ?? p?.limits?.deny ?? [];
}

/**
 * Index of the first earlier rule that makes `rules[i]` unreachable, or null.
 *
 * "Unreachable" here means: an earlier rule matches everything this one
 * matches, and it always fires. Two conditions make the earlier rule NOT
 * shadow: it carries a `when` guard (it may decline at call time, so later
 * rules stay reachable), or its glob does not cover this rule's match.
 *
 * Coverage is approximated the same way as `globWidens` — by asking whether the
 * earlier glob matches this rule's pattern text. Exact glob containment is
 * undecidable in general; the bias is to report only clear cases, because a
 * false "shadowed" badge on a live gate would teach operators to ignore the
 * badge.
 */
function findShadow(rules: PolicyRule[], i: number): number | null {
  const mine = rules[i]?.match;
  if (typeof mine !== "string") return null;
  for (let j = 0; j < i; j++) {
    const earlier = rules[j];
    if (earlier.when !== undefined) continue; // may decline at call time
    if (earlier.match === mine) return j;
    if (picomatch.isMatch(mine, earlier.match)) return j;
  }
  return null;
}

/** Reads the current rules, with the etag callers must send back. */
export async function readRules(): Promise<RulesSnapshot> {
  const raw = readPoliciesRaw();
  const etag = etagOf(raw);
  if (raw.trim() === "") return { agents: [], denyGlobs: [], etag };

  // Parse for READING only — writes go through parseDocument to keep comments.
  const YAML = await import("yaml");
  const parsed = YAML.parse(raw) as {
    limits?: { deny?: string[] };
    agents?: Record<string, { default_ttl?: string; capabilities?: PolicyRule[] }>;
  };
  const agents = Object.entries(parsed?.agents ?? {}).map(([agentId, a]) => {
    const deny = denyGlobsFor(parsed, agentId);
    const list = a?.capabilities ?? [];
    return {
      agentId,
      ...(a?.default_ttl !== undefined ? { defaultTtl: a.default_ttl } : {}),
      rules: list.map((r, index) => {
        const hit = deny.find((g) => picomatch.isMatch(r.match, g) || r.match === g);
        const shadow = findShadow(list, index);
        return {
          agentId,
          match: r.match,
          index,
          ...(r.auto_approve !== undefined ? { auto_approve: r.auto_approve } : {}),
          ...(r.ttl !== undefined ? { ttl: r.ttl } : {}),
          ...(r.require !== undefined ? { require: r.require } : {}),
          ...(r.when !== undefined ? { when: r.when } : {}),
          ...(hit !== undefined ? { deniedByGlob: hit } : {}),
          ...(shadow !== null ? { shadowedBy: shadow } : {}),
        } satisfies RuleView;
      }),
    };
  });
  return { agents, denyGlobs: parsed?.limits?.deny ?? [], etag };
}

export interface UpsertInput {
  agentId: string;
  match: string;
  auto_approve?: boolean;
  ttl?: string;
  require?: "human_approval";
  /** Required to accept a rule that widens an existing human gate. */
  acknowledge_widening?: boolean;
}

/**
 * True when `candidate` matches strictly more capabilities than `existing`:
 * every capability shape `existing` covers is also covered by `candidate`, and
 * they are not the same glob.
 *
 * There is no exact algorithm over globs, so this is a deliberate
 * approximation in the SAFE direction: it compares the literal prefix before
 * the first wildcard. `nexgen:call:*` is treated as wider than
 * `nexgen:call:github_create_pr_draft` (prefix is a prefix, and the candidate
 * has a wildcard where the other has literal text). False positives cost one
 * explicit acknowledgement; a false negative would silently remove a human
 * gate, so the bias is intentional.
 */
export function globWidens(candidate: string, existing: string): boolean {
  if (candidate === existing) return false;
  if (!candidate.includes("*") && !candidate.includes("?")) return false;
  // A glob that matches the other pattern's literal text is wider.
  const existingLiteral = existing.replace(/[*?].*$/, "");
  return picomatch.isMatch(existingLiteral, candidate, { partial: true }) ||
    picomatch.isMatch(existing, candidate);
}

/**
 * Applies one rule upsert to the YAML document and returns the new text.
 * Pure with respect to disk — the caller writes, validates and reloads.
 */
export async function applyUpsert(
  raw: string,
  input: UpsertInput,
): Promise<{ raw: string } | { error: RulesError }> {
  const YAML = await import("yaml");
  const doc = raw.trim() === "" ? YAML.parseDocument("version: 1\nagents: {}\n") : YAML.parseDocument(raw);

  if (typeof input.agentId !== "string" || input.agentId.trim() === "") {
    return { error: { kind: "invalid", message: "agentId is required" } };
  }
  if (typeof input.match !== "string" || input.match.trim() === "") {
    return { error: { kind: "invalid", message: "match is required" } };
  }
  if (input.auto_approve === true && input.require === "human_approval") {
    return {
      error: {
        kind: "invalid",
        message: "a rule cannot be both auto_approve and require human_approval",
      },
    };
  }

  const parsed = doc.toJS() as {
    limits?: { deny?: string[] };
    agents?: Record<string, { capabilities?: PolicyRule[] }>;
  };

  // Guard 1: a rule under a hard deny is dead config that reads as a grant.
  const deny = denyGlobsFor(parsed, input.agentId);
  const denyHit = deny.find(
    (g) => picomatch.isMatch(input.match, g) || input.match === g,
  );
  if (denyHit !== undefined) {
    return {
      error: {
        kind: "invalid",
        message:
          `'${input.match}' is already denied by the hard deny glob '${denyHit}'. ` +
          `deny is evaluated before auto_approve, so this rule would never grant ` +
          `anything while appearing to. Change limits.deny in the raw policies file ` +
          `if that is really the intent.`,
      },
    };
  }

  // Guard 2: widening an existing human gate needs an explicit acknowledgement.
  if (input.auto_approve === true) {
    const existing = parsed.agents?.[input.agentId]?.capabilities ?? [];
    const widens = existing
      .filter((r) => r.require === "human_approval" && globWidens(input.match, r.match))
      .map((r) => r.match);
    if (widens.length > 0 && input.acknowledge_widening !== true) {
      return {
        error: {
          kind: "needs_acknowledge",
          message:
            `'${input.match}' auto-approves capabilities currently gated by human ` +
            `approval (${widens.join(", ")}). Specificity is what keeps those gates ` +
            `alive. Re-send with acknowledge_widening: true to confirm.`,
          widens,
        },
      };
    }
  }

  // Ensure agents.<id> exists without disturbing sibling comments.
  if (doc.getIn(["agents", input.agentId]) === undefined) {
    doc.setIn(["agents", input.agentId], { capabilities: [] });
  }
  if (doc.getIn(["agents", input.agentId, "capabilities"]) === undefined) {
    doc.setIn(["agents", input.agentId, "capabilities"], []);
  }

  const rules = (doc.getIn(["agents", input.agentId, "capabilities"]) as
    | { items?: unknown[] }
    | undefined) ?? { items: [] };
  const current = (doc.toJS() as { agents: Record<string, { capabilities?: PolicyRule[] }> })
    .agents[input.agentId]?.capabilities ?? [];
  const idx = current.findIndex((r) => r.match === input.match);

  // A rule carrying an M6 `when` guard is NOT editable through this API.
  //
  // This layer has no vocabulary for arg guards, so replacing such a rule in
  // place would drop the guard and turn a conditional auto-approve into an
  // unconditional one — silently widening exactly what the widening guard
  // above exists to protect. The running policy has such a rule
  // (`github_create_pr_draft` guarded by `when: {branch: "kimi/*"}`), so this
  // is a live path, not a defensive hypothetical. Fail closed and send the
  // human to the raw editor, where the guard is visible in the diff.
  if (idx >= 0 && current[idx]?.when !== undefined) {
    return {
      error: {
        kind: "invalid",
        message:
          `rule '${input.match}' for '${input.agentId}' carries a \`when\` arg guard ` +
          `(${JSON.stringify(current[idx].when)}). This API cannot express guards, so ` +
          `editing it here would silently drop the guard and widen the rule. Edit it in ` +
          `the raw policies file instead.`,
      },
    };
  }

  const value: PolicyRule = {
    match: input.match,
    ...(input.auto_approve !== undefined ? { auto_approve: input.auto_approve } : {}),
    ...(input.ttl !== undefined ? { ttl: input.ttl } : {}),
    ...(input.require !== undefined ? { require: input.require } : {}),
  };

  if (idx >= 0) {
    doc.setIn(["agents", input.agentId, "capabilities", idx], value);
  } else {
    // Append. New rules go LAST so they never silently outrank an existing
    // first-match-wins rule the operator wrote earlier.
    const len = Array.isArray(rules.items) ? rules.items.length : current.length;
    doc.setIn(["agents", input.agentId, "capabilities", len], value);
  }
  return { raw: String(doc) };
}

/**
 * Removes one rule, addressed by `match` or by explicit index.
 *
 * Why index addressing exists: duplicate `match` values are legal and the real
 * policies have them (see `shadowedBy`). Deleting "the rule for X" when two
 * rules claim X would silently pick one — and picking wrong could delete a
 * human gate instead of the rule shadowing it. So an ambiguous match is
 * refused, and the caller must say which index it means.
 */
export async function applyDelete(
  raw: string,
  agentId: string,
  target: { match: string } | { index: number },
): Promise<{ raw: string } | { error: RulesError }> {
  if (raw.trim() === "") {
    return { error: { kind: "not_found", message: "no policies file" } };
  }
  const YAML = await import("yaml");
  const doc = YAML.parseDocument(raw);
  const current =
    (doc.toJS() as { agents?: Record<string, { capabilities?: PolicyRule[] }> }).agents?.[agentId]
      ?.capabilities ?? [];

  let idx: number;
  if ("index" in target) {
    idx = target.index;
    if (!Number.isInteger(idx) || idx < 0 || idx >= current.length) {
      return {
        error: {
          kind: "not_found",
          message: `agent '${agentId}' has no rule at index ${idx} (it has ${current.length})`,
        },
      };
    }
  } else {
    const hits = current
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => r.match === target.match);
    if (hits.length === 0) {
      return {
        error: { kind: "not_found", message: `no rule '${target.match}' for agent '${agentId}'` },
      };
    }
    if (hits.length > 1) {
      return {
        error: {
          kind: "invalid",
          message:
            `agent '${agentId}' has ${hits.length} rules matching '${target.match}' ` +
            `(indexes ${hits.map((h) => h.i).join(", ")}). Deleting by match would pick one ` +
            `arbitrarily and could remove a human gate instead of the rule shadowing it. ` +
            `Delete by index instead.`,
        },
      };
    }
    idx = hits[0].i;
  }
  doc.deleteIn(["agents", agentId, "capabilities", idx]);
  return { raw: String(doc) };
}

/**
 * Commits a new policies text: validate → backup → write → reload.
 *
 * Deliberately mirrors `PUT /admin/policies` step for step instead of
 * factoring it out, because the two must stay behaviorally identical and the
 * shared thing is the ORDER, which is easier to verify side by side than
 * hidden in a helper. Validation failing here means the structured edit
 * produced something the engine rejects — a bug in this layer, so the message
 * says so.
 */
export async function commitRules(
  nextRaw: string,
  reload: () => Promise<void>,
): Promise<{ ok: true; etag: string } | { ok: false; error: RulesError }> {
  const YAML = await import("yaml");
  let parsed: unknown;
  try {
    parsed = YAML.parse(nextRaw);
  } catch (e) {
    return {
      ok: false,
      error: {
        kind: "invalid",
        message: `structured edit produced invalid YAML (bug): ${(e as Error).message}`,
      },
    };
  }
  try {
    validatePoliciesFile(parsed);
  } catch (e) {
    return {
      ok: false,
      error: { kind: "invalid", message: `invalid policies: ${(e as Error).message}` },
    };
  }
  if (fs.existsSync(POLICIES_PATH)) {
    fs.copyFileSync(POLICIES_PATH, `${POLICIES_PATH}.prev`);
  }
  ensureDir();
  fs.writeFileSync(POLICIES_PATH, nextRaw, { mode: 0o600 });
  await reload();
  return { ok: true, etag: etagOf(nextRaw) };
}

/** Current on-disk etag, for the caller's If-Match comparison. */
export function currentEtag(): string {
  return etagOf(readPoliciesRaw());
}
