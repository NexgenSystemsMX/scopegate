/**
 * Policy preflight tests (mejora #3).
 *
 *   - evaluate() mirrors request()'s decision logic for every branch (team
 *     deny, existing grant, no_policy, hard deny, invalid ttl, require
 *     approval, team-require override, auto-approve with clamps, no_rule)
 *     with ZERO side effects: no grant issued, no approval queued, no audit.
 *   - policySummary() digests the agent's rules, ceilings and team layer.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts).
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

const LOCAL = {
  version: 1 as const,
  limits: { max_ttl: "30m", deny: ["aws:*:production"] },
  agents: {
    "test-agent": {
      default_ttl: "20m",
      capabilities: [
        { match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" },
        { match: "fakegit:call:danger", require: "human_approval" as const, ttl: "20m" },
        { match: "db:read:*", auto_approve: true },
      ],
    },
  },
};

async function freshEngine(local: unknown = LOCAL) {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(local as never);
}

function noSideEffects(homeDir: string) {
  // evaluate() must not touch grants.json, the approval queue, or audit.jsonl.
  expect(fs.existsSync(path.join(homeDir, "grants.json"))).toBe(false);
  expect(fs.existsSync(path.join(homeDir, "approvals.pending.jsonl"))).toBe(false);
  expect(fs.existsSync(path.join(homeDir, "audit.jsonl"))).toBe(false);
}

describe("evaluate (policy preflight)", () => {
  it("auto-approve → allow with the rule clamp, default and max_ttl ceilings", async () => {
    const engine = await freshEngine();
    // No ttl asked → rule ttl 10m wins.
    expect(engine.evaluate("test-agent", "fakegit:call:whoami")).toMatchObject({
      decision: "allow",
      ttl_ms: 600_000,
      rule: "fakegit:call:whoami",
    });
    // ttl asked ABOVE the rule → clamped to the rule.
    expect(engine.evaluate("test-agent", "fakegit:call:whoami", "25m").ttl_ms).toBe(600_000);
    // db:read:* has no rule ttl → default_ttl 20m.
    expect(engine.evaluate("test-agent", "db:read:analytics").ttl_ms).toBe(1_200_000);
    // Ask 2h → still clamped by the 20m agent default (default wins before max_ttl).
    expect(engine.evaluate("test-agent", "db:read:analytics", "2h").ttl_ms).toBe(1_200_000);
    // With the default ABOVE max_ttl, max_ttl is the binding ceiling.
    const local2 = structuredClone(LOCAL) as typeof LOCAL;
    local2.agents["test-agent"].default_ttl = "45m";
    const engine2 = await freshEngine(local2);
    expect(engine2.evaluate("test-agent", "db:read:analytics", "2h").ttl_ms).toBe(1_800_000);
    noSideEffects(home);
  });

  it("require: human_approval → needs_approval via local_policy", async () => {
    const engine = await freshEngine();
    expect(engine.evaluate("test-agent", "fakegit:call:danger")).toMatchObject({
      decision: "needs_approval",
      via: "local_policy",
      rule: "fakegit:call:danger",
    });
    noSideEffects(home);
  });

  it("hard-limit deny glob → deny with hard=true, no matter the rules", async () => {
    const engine = await freshEngine();
    const e = engine.evaluate("test-agent", "aws:write:production");
    expect(e).toMatchObject({ decision: "deny", code: "ceiling_blocked", hard: true });
    noSideEffects(home);
  });

  it("no matching rule → deny no_rule; unknown agent → no_policy; bad ttl → invalid_ttl", async () => {
    const engine = await freshEngine();
    expect(engine.evaluate("test-agent", "stripe:write:*")).toMatchObject({
      decision: "deny",
      code: "no_rule",
    });
    expect(engine.evaluate("nobody", "db:read:x")).toMatchObject({
      decision: "deny",
      code: "no_policy",
    });
    expect(engine.evaluate("test-agent", "db:read:x", "10x")).toMatchObject({
      decision: "deny",
      code: "invalid_ttl",
    });
    noSideEffects(home);
  });

  it("a live covering grant → allow with covered_by_existing_grant", async () => {
    const engine = await freshEngine();
    engine.request("test-agent", "fakegit:call:whoami", "5m", "x");
    const e = engine.evaluate("test-agent", "fakegit:call:whoami");
    expect(e.decision).toBe("allow");
    expect(e.covered_by_existing_grant).toBe(true);
    expect(e.ttl_ms).toBeLessThanOrEqual(300_000);
  });

  it("team layer: team deny wins, team require overrides local auto-approve", async () => {
    const engine = await freshEngine();
    const { validatePoliciesFile } = await import("../src/policy/engine.js");
    const YAML = (await import("yaml")).default;
    engine.applyTeamPolicy(
      validatePoliciesFile(
        YAML.parse(`
version: 1
limits:
  deny: ["db:read:pii"]
agents:
  test-agent:
    capabilities:
      - match: "fakegit:call:whoami"
        require: human_approval
      - match: "db:read:*"
        auto_approve: true
`),
      ),
      { version: 1, fetchedAt: new Date().toISOString() },
    );
    // Team silence on danger → deny even though local would escalate.
    expect(engine.evaluate("test-agent", "fakegit:call:danger").decision).toBe("deny");
    // Team deny glob blocks db:read:pii despite local auto-approve.
    expect(engine.evaluate("test-agent", "db:read:pii")).toMatchObject({
      decision: "deny",
      code: "ceiling_blocked",
    });
    // Team require overrides local auto-approve for whoami.
    expect(engine.evaluate("test-agent", "fakegit:call:whoami")).toMatchObject({
      decision: "needs_approval",
      via: "team_policy",
    });
    // db:read:analytics: allowed by both.
    expect(engine.evaluate("test-agent", "db:read:analytics").decision).toBe("allow");
    noSideEffects(home);
  });
});

describe("policySummary", () => {
  it("digests rules, ceilings and the team layer", async () => {
    const engine = await freshEngine();
    const s = engine.policySummary("test-agent");
    expect(s.agent_found).toBe(true);
    expect(s.default_ttl).toBe("20m");
    expect(s.auto_approve).toEqual(["fakegit:call:whoami", "db:read:*"]);
    expect(s.requires_approval).toEqual(["fakegit:call:danger"]);
    expect(s.deny_globs).toEqual(["aws:*:production"]);
    expect(s.max_ttl).toBe("30m");
    expect(s.team).toBeNull();

    const nobody = engine.policySummary("ghost");
    expect(nobody.agent_found).toBe(false);
    expect(nobody.auto_approve).toEqual([]);
  });
});
