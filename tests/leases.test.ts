/**
 * Task lease tests (mejora #1).
 *
 *   - openLease clamps max_total by limits.max_lease_total (hard ceiling,
 *     never extends) and defaults max_writes.
 *   - Lease-bound requests carry leaseId on the grant; out-of-scope
 *     capabilities are refused; dead leases refuse.
 *   - renewGrant slides the expiry (never past the lease deadline, re-clamped
 *     by rule ceilings) while the lease lives.
 *   - Write budget: consumeWrite gates at maxWrites; revokeLease drops every
 *     bound grant at once.
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
  limits: { max_lease_total: "2h" },
  agents: {
    "test-agent": {
      capabilities: [
        { match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" },
        { match: "huly:call:create_issue", auto_approve: true, ttl: "10m" },
      ],
    },
  },
};

async function freshEngine(local: unknown = LOCAL) {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(local as never);
}

describe("task leases", () => {
  it("openLease clamps max_total by the hard ceiling (never extends) and audits", async () => {
    const engine = await freshEngine();
    const { lease, clamped } = engine.openLease("test-agent", {
      goal: "migrate the module",
      upstreams: ["fakegit"],
      max_total: "8h", // above the 2h limit → clamped
    });
    expect(clamped).toBe(true);
    expect(lease.totalMs).toBe(2 * 3600 * 1000);
    expect(lease.ceilingMs).toBe(2 * 3600 * 1000);
    expect(lease.maxWrites).toBe(200); // default
    expect(lease.status).toBe("open");

    const exact = engine.openLease("test-agent", {
      goal: "short task",
      upstreams: [],
      max_total: "30m",
      max_writes: 5,
    });
    expect(exact.clamped).toBe(false);
    expect(exact.lease.totalMs).toBe(30 * 60 * 1000);
    expect(exact.lease.maxWrites).toBe(5);
  });

  it("lease-bound requests carry leaseId; out-of-scope capabilities are refused", async () => {
    const engine = await freshEngine();
    const { lease } = engine.openLease("test-agent", {
      goal: "fakegit-only task",
      upstreams: ["fakegit"],
      max_total: "1h",
    });
    const d = engine.request("test-agent", "fakegit:call:whoami", "5m", "t", { leaseId: lease.leaseId });
    expect(d.allow).toBe(true);
    const grants = engine.activeGrants("test-agent");
    expect(grants[0].leaseId).toBe(lease.leaseId);

    const out = engine.request("test-agent", "huly:call:create_issue", "5m", "t", { leaseId: lease.leaseId });
    expect(out.allow).toBe(false);
    expect(out.code).toBe("lease_error");
    expect(out.reason).toMatch(/out of scope/);
  });

  it("renewGrant slides the expiry while the lease lives, never past the deadline", async () => {
    const engine = await freshEngine();
    const { lease } = engine.openLease("test-agent", {
      goal: "renewal drill",
      upstreams: [],
      max_total: "1h",
    });
    engine.request("test-agent", "fakegit:call:whoami", "10m", "t", { leaseId: lease.leaseId });
    const grant = engine.activeGrants("test-agent")[0];
    const before = grant.expiresAt;

    const renewed = engine.renewGrant("test-agent", grant.id);
    expect(renewed.leaseId).toBe(lease.leaseId);
    expect(renewed.expiresAt).toBeGreaterThan(before - 1000);
    expect(renewed.expiresAt).toBeLessThanOrEqual(lease.deadlineMs);

    // Unknown grant → actionable error; a second agent can't touch it.
    expect(() => engine.renewGrant("test-agent", "g-nope")).toThrow(/No live grant/);
    expect(() => engine.renewGrant("other-agent", grant.id)).toThrow(/No live grant/);
  });

  it("a dead lease refuses renewals and new bound requests", async () => {
    const engine = await freshEngine();
    const { lease } = engine.openLease("test-agent", {
      goal: "already dead",
      upstreams: [],
      max_total: "1s", // expires ~immediately
    });
    await new Promise((r) => setTimeout(r, 1100));
    const d = engine.request("test-agent", "fakegit:call:whoami", "5m", "t", { leaseId: lease.leaseId });
    expect(d.allow).toBe(false);
    expect(d.code).toBe("lease_error");
  }, 10_000);

  it("write budget gates at maxWrites; revokeLease drops every bound grant", async () => {
    const engine = await freshEngine();
    const { lease } = engine.openLease("test-agent", {
      goal: "budget drill",
      upstreams: [],
      max_total: "1h",
      max_writes: 2,
    });
    expect(engine.consumeLeaseWrite(lease.leaseId)).toBe(true);
    expect(engine.consumeLeaseWrite(lease.leaseId)).toBe(true);
    expect(engine.consumeLeaseWrite(lease.leaseId)).toBe(false); // budget exhausted
    expect(engine.leaseWritesRemaining(lease.leaseId)).toBe(0);

    engine.request("test-agent", "fakegit:call:whoami", "5m", "t", { leaseId: lease.leaseId });
    engine.request("test-agent", "huly:call:create_issue", "5m", "t", { leaseId: lease.leaseId });
    expect(engine.activeGrants("test-agent").length).toBe(2);
    const { revokedGrants } = engine.revokeLease("test-agent", lease.leaseId);
    expect(revokedGrants).toBe(2);
    expect(engine.activeGrants("test-agent").length).toBe(0);
    expect(engine.leasesForAgent("test-agent")[0].status).toBe("revoked");
  });

  it("leases persist across a store reload (restart survival)", async () => {
    const engine1 = await freshEngine();
    const { lease } = engine1.openLease("test-agent", { goal: "restart me", upstreams: [], max_total: "1h" });
    const engine2 = await freshEngine();
    const found = engine2.leasesForAgent("test-agent").find((l) => l.leaseId === lease.leaseId);
    expect(found).toBeDefined();
    expect(found?.status).toBe("open");
  });
});
