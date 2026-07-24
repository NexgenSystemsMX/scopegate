/**
 * Delegation tests (mejora #5).
 *
 *   - delegate issues a child grant with strict attenuation (scope ⊆ parent,
 *     ttl ≤ parent remaining) and the parent chain recorded.
 *   - Any widening (broader scope, longer ttl, self-delegation, dead parent)
 *     is refused fail-closed.
 *   - revokeAgent cascades: children of the revoked parent die with it.
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
  agents: {
    orchestrator: {
      capabilities: [
        { match: "github:write:easyorder/*", auto_approve: true, ttl: "30m" },
      ],
    },
  },
};

async function freshEngine() {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(LOCAL as never);
}

describe("delegation", () => {
  it("issues an attenuated child grant with the parent chain", async () => {
    const engine = await freshEngine();
    engine.request("orchestrator", "github:write:easyorder/*", "30m", "t");
    const parent = engine.activeGrants("orchestrator")[0];

    const child = engine.delegate("orchestrator", {
      grant_id: parent.id,
      child_agent_id: "subagent-explorer",
      scope_subset: "github:write:easyorder/api",
      ttl: "10m",
    });
    expect(child.childAgentId).toBe("subagent-explorer");
    expect(child.capability).toBe("github:write:easyorder/api");
    expect(child.expiresAt).toBeLessThanOrEqual(parent.expiresAt);

    // The child sees its grant; the parent's chain is recorded.
    const childGrant = engine.activeGrants("subagent-explorer")[0];
    expect(childGrant.parentGrantId).toBe(parent.id);
    expect(childGrant.expiresAt - childGrant.grantedAt).toBe(600_000);

    // No ttl asked → capped at the parent's remaining.
    const child2 = engine.delegate("orchestrator", {
      grant_id: parent.id,
      child_agent_id: "subagent-tester",
      scope_subset: "github:write:easyorder/web",
    });
    expect(child2.expiresAt).toBeLessThanOrEqual(parent.expiresAt);
  });

  it("refuses any widening fail-closed (scope, ttl, self, dead parent)", async () => {
    const engine = await freshEngine();
    engine.request("orchestrator", "github:write:easyorder/*", "30m", "t");
    const parent = engine.activeGrants("orchestrator")[0];

    expect(() =>
      engine.delegate("orchestrator", {
        grant_id: parent.id,
        child_agent_id: "sub",
        scope_subset: "github:write:other/repo",
      }),
    ).toThrow(/Attenuation violation/);
    expect(() =>
      engine.delegate("orchestrator", {
        grant_id: parent.id,
        child_agent_id: "sub",
        scope_subset: "github:write:easyorder/api",
        ttl: "2h",
      }),
    ).toThrow(/exceeds the parent's remaining ttl/);
    expect(() =>
      engine.delegate("orchestrator", {
        grant_id: parent.id,
        child_agent_id: "orchestrator",
        scope_subset: "github:write:easyorder/api",
      }),
    ).toThrow(/different agent id/);
    expect(() =>
      engine.delegate("orchestrator", {
        grant_id: "g-dead",
        child_agent_id: "sub",
        scope_subset: "github:write:easyorder/api",
      }),
    ).toThrow(/No live grant/);
  });

  it("revokeAgent cascades: children of the revoked parent die with it", async () => {
    const engine = await freshEngine();
    engine.request("orchestrator", "github:write:easyorder/*", "30m", "t");
    const parent = engine.activeGrants("orchestrator")[0];
    engine.delegate("orchestrator", {
      grant_id: parent.id,
      child_agent_id: "sub-a",
      scope_subset: "github:write:easyorder/api",
    });
    engine.delegate("orchestrator", {
      grant_id: parent.id,
      child_agent_id: "sub-b",
      scope_subset: "github:write:easyorder/web",
    });
    expect(engine.activeGrants("sub-a").length).toBe(1);
    expect(engine.activeGrants("sub-b").length).toBe(1);

    const removed = engine.revokeAgent("orchestrator");
    expect(removed).toBe(3); // parent + 2 children
    expect(engine.activeGrants("sub-a").length).toBe(0);
    expect(engine.activeGrants("sub-b").length).toBe(0);
  });
});
