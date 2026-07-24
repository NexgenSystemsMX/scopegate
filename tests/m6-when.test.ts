/**
 * M6: arg-aware policy guards (`when:` clauses on capability rules).
 *
 *   - matchesWhen: strings are picomatch globs, numbers/booleans strict
 *     equality; undefined args NEVER satisfy a guard (fail-closed).
 *   - engine: a when-rule whose guard fails falls through to the next rule;
 *     evaluate() mirrors request() with zero side effects.
 *   - grants: the guard persists on the issued grant and coverage checks
 *     re-evaluate it (a grant for branch kimi/* does not cover branch main).
 *   - config: malformed `when` clauses are rejected at load (PolicyConfigError).
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
  agents: {
    "test-agent": {
      default_ttl: "10m",
      capabilities: [
        {
          match: "github:write:easyorder/*",
          auto_approve: true,
          ttl: "5m",
          when: { branch: "kimi/*" },
        },
        {
          match: "github:write:easyorder/*",
          require: "human_approval" as const,
          ttl: "10m",
        },
      ],
    },
  },
};

async function freshEngine(local: unknown = LOCAL) {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(local as never);
}

describe("matchesWhen (unit)", () => {
  it("string patterns are globs; numbers/booleans are strict equality", async () => {
    const { matchesWhen } = await import("../src/policy/when.js");
    expect(matchesWhen({ branch: "kimi/*" }, { branch: "kimi/feat-x" })).toBe(true);
    expect(matchesWhen({ branch: "kimi/*" }, { branch: "main" })).toBe(false);
    expect(matchesWhen({ retries: 3 }, { retries: 3 })).toBe(true);
    expect(matchesWhen({ retries: 3 }, { retries: 4 })).toBe(false);
    expect(matchesWhen({ force: true }, { force: true })).toBe(true);
    expect(matchesWhen({ force: true }, { force: false })).toBe(false);
    // Missing arg never satisfies.
    expect(matchesWhen({ branch: "kimi/*" }, {})).toBe(false);
    // Every pattern must match.
    expect(
      matchesWhen({ branch: "kimi/*", force: false }, { branch: "kimi/a", force: true }),
    ).toBe(false);
    // Undefined args (no arg context at all) never satisfy.
    expect(matchesWhen({ branch: "kimi/*" }, undefined)).toBe(false);
  });
});

describe("engine evaluation with when guards", () => {
  it("guard satisfied → the auto_approve rule matches; unsatisfied → falls through to the approval rule", async () => {
    const engine = await freshEngine();
    const allowed = engine.evaluate("test-agent", "github:write:easyorder/api", undefined, {
      branch: "kimi/feat",
    });
    expect(allowed).toMatchObject({ decision: "allow", ttl_ms: 300_000 });

    const guardedOut = engine.evaluate("test-agent", "github:write:easyorder/api", undefined, {
      branch: "main",
    });
    expect(guardedOut.decision).toBe("needs_approval");

    // No args at all: the when-rule is skipped (fail-closed).
    expect(engine.evaluate("test-agent", "github:write:easyorder/api").decision).toBe(
      "needs_approval",
    );
  });

  it("request() issues a guarded grant and persists the when clause", async () => {
    const engine = await freshEngine();
    const d = engine.request("test-agent", "github:write:easyorder/api", undefined, "push", {
      args: { branch: "kimi/feat" },
    });
    expect(d.allow).toBe(true);
    expect(d.ttlMs).toBe(300_000);

    const grants = JSON.parse(
      fs.readFileSync(path.join(home, "grants.json"), "utf8"),
    ) as { grants: { when?: Record<string, unknown> }[] };
    expect(grants.grants).toHaveLength(1);
    expect(grants.grants[0].when).toEqual({ branch: "kimi/*" });
  });

  it("a guarded grant covers only matching args — other args do NOT reuse it", async () => {
    const engine = await freshEngine();
    const first = engine.request("test-agent", "github:write:easyorder/api", undefined, "push", {
      args: { branch: "kimi/feat" },
    });
    expect(first.allow).toBe(true);

    // Same args → idempotent reuse (no duplicate grant).
    const again = engine.request("test-agent", "github:write:easyorder/api", undefined, "push", {
      args: { branch: "kimi/other" },
    });
    expect(again.allow).toBe(true);
    const grants = JSON.parse(
      fs.readFileSync(path.join(home, "grants.json"), "utf8"),
    ) as { grants: unknown[] };
    expect(grants.grants).toHaveLength(1);

    // Different args → the guarded grant does not cover; the approval rule fires.
    const other = engine.request("test-agent", "github:write:easyorder/api", undefined, "push", {
      args: { branch: "main" },
    });
    expect(other.allow).toBe(false);
    expect(other.escalation).toBe("human_approval");

    // No args → also not covered.
    const bare = engine.request("test-agent", "github:write:easyorder/api", undefined, "push");
    expect(bare.allow).toBe(false);
    expect(bare.escalation).toBe("human_approval");
  });

  it("isGranted is arg-aware too (proxy path enforcement)", async () => {
    const engine = await freshEngine();
    engine.request("test-agent", "github:write:easyorder/api", undefined, "push", {
      args: { branch: "kimi/feat" },
    });
    expect(engine.isGranted("test-agent", "github:write:easyorder/api", { branch: "kimi/x" })).toBe(
      true,
    );
    expect(engine.isGranted("test-agent", "github:write:easyorder/api", { branch: "main" })).toBe(
      false,
    );
    expect(engine.isGranted("test-agent", "github:write:easyorder/api")).toBe(false);
  });
});

describe("when clause validation (fail-closed config)", () => {
  it("rejects malformed when clauses at load", async () => {
    const { validatePoliciesFile } = await import("../src/policy/engine.js");

    const bad1 = structuredClone(LOCAL) as any;
    bad1.agents["test-agent"].capabilities[0].when = "kimi/*";
    expect(() => validatePoliciesFile(bad1)).toThrow(/when/);

    const bad2 = structuredClone(LOCAL) as any;
    bad2.agents["test-agent"].capabilities[0].when = { branch: { nested: true } };
    expect(() => validatePoliciesFile(bad2)).toThrow(/when/);

    const bad3 = structuredClone(LOCAL) as any;
    bad3.agents["test-agent"].capabilities[0].when = { "": "x" };
    expect(() => validatePoliciesFile(bad3)).toThrow(/when/);

    // A valid when clause passes validation untouched.
    expect(() => validatePoliciesFile(structuredClone(LOCAL))).not.toThrow();
  });
});
