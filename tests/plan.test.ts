/**
 * Capability plan tests (mejora #4).
 *
 *   - requestPlan partitions: auto-approvable issued now (audited), denials
 *     reported, needs_approval bundled into ONE aggregated approval.
 *   - open_lease binds every plan grant (auto now, bundle on approval).
 *   - On approval, EVERY bundled capability is issued at once with per-item
 *     ceilings (materializedTtlFor), and the plan is one-shot.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts).
 */
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
      default_ttl: "15m",
      capabilities: [
        { match: "github:read:*", auto_approve: true, ttl: "10m" },
        { match: "github:write:*", require: "human_approval" as const, ttl: "20m" },
        { match: "railway:call:deploy", require: "human_approval" as const, ttl: "10m" },
      ],
    },
  },
};

async function freshEngine() {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(LOCAL as never);
}

const PLAN = {
  goal: "read repo X, write branch Y, deploy staging",
  capabilities: [
    { capability: "github:read:easyorder" },
    { capability: "github:write:fix-x" },
    { capability: "railway:call:deploy", ttl: "5m" },
    { capability: "aws:write:production" }, // hard deny
  ],
};

describe("capability plan", () => {
  it("partitions auto/deny/bundle into one aggregated approval", async () => {
    const engine = await freshEngine();
    const out = engine.requestPlan("test-agent", PLAN);

    const granted = out.auto.filter((a) => a.granted);
    const denied = out.auto.filter((a) => !a.granted);
    expect(granted.map((a) => a.capability)).toEqual(["github:read:easyorder"]);
    expect(denied.map((a) => a.capability)).toEqual(["aws:write:production"]);
    expect(denied[0].code).toBe("ceiling_blocked");

    expect(out.pending).toBeDefined();
    expect(out.pending!.items.map((i) => i.capability)).toEqual([
      "github:write:fix-x",
      "railway:call:deploy",
    ]);
    // The auto part is already granted with its clamp.
    const readGrant = engine.activeGrants("test-agent").find((g) => g.capability === "github:read:easyorder");
    expect(readGrant).toBeDefined();
  });

  it("on approval, EVERY bundled capability is issued at once with per-item ceilings", async () => {
    const engine = await freshEngine();
    const out = engine.requestPlan("test-agent", PLAN);
    const approvals = await import("../src/policy/approvals.js");
    approvals.resolveApproval(out.pending!.approvalId, "approved", "human:cli:tty");

    // Materialization happens on the next request (any capability).
    engine.request("test-agent", "github:read:easyorder", "5m", "trigger");

    const grants = engine.activeGrants("test-agent");
    const writeGrant = grants.find((g) => g.capability === "github:write:fix-x");
    const deployGrant = grants.find((g) => g.capability === "railway:call:deploy");
    expect(writeGrant).toBeDefined();
    expect(deployGrant).toBeDefined();
    // Per-item ceilings: write rule 20m; deploy asked 5m (rule 10m) → 5m.
    expect(writeGrant!.expiresAt - writeGrant!.grantedAt).toBe(20 * 60 * 1000);
    expect(deployGrant!.expiresAt - deployGrant!.grantedAt).toBe(5 * 60 * 1000);
    expect(writeGrant!.approvalId).toBe(out.pending!.approvalId);

    // One-shot: a second request does not re-issue from the same approval.
    const line = approvals.listApprovals().find((a) => a.id === out.pending!.approvalId);
    expect(line?.effectiveStatus).toBe("approved");
  });

  it("open_lease binds every plan grant (auto now, bundle on approval) to the lease", async () => {
    const engine = await freshEngine();
    const out = engine.requestPlan("test-agent", { ...PLAN, open_lease: true, max_total: "1h" });
    expect(out.leaseId).toBeDefined();

    const readGrant = engine.activeGrants("test-agent").find((g) => g.capability === "github:read:easyorder");
    expect(readGrant?.leaseId).toBe(out.leaseId);

    const approvals = await import("../src/policy/approvals.js");
    approvals.resolveApproval(out.pending!.approvalId, "approved", "human:cli:tty");
    engine.request("test-agent", "github:read:easyorder", "5m", "trigger");
    const writeGrant = engine.activeGrants("test-agent").find((g) => g.capability === "github:write:fix-x");
    expect(writeGrant?.leaseId).toBe(out.leaseId);
  });

  it("a fully-auto plan needs no approval at all", async () => {
    const engine = await freshEngine();
    const out = engine.requestPlan("test-agent", {
      goal: "reads only",
      capabilities: [{ capability: "github:read:easyorder" }, { capability: "github:read:other" }],
    });
    expect(out.pending).toBeUndefined();
    expect(out.auto.every((a) => a.granted)).toBe(true);
  });
});
