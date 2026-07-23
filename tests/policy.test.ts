import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

const POLICIES = {
  version: 1 as const,
  agents: {
    "test-agent": {
      default_ttl: "15m",
      capabilities: [
        { match: "github:call:*", auto_approve: true, ttl: "10m" },
        { match: "github:read:*", auto_approve: true }, // inherits agent default_ttl
        { match: "github:write:*", require: "human_approval" as const },
      ],
    },
    "*": {
      capabilities: [{ match: "docs:read:*", auto_approve: true, ttl: "5m" }],
    },
  },
};

async function freshEngine(policies = POLICIES) {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(policies);
}

describe("PolicyEngine TTL clamping", () => {
  it("clamps a request above the rule ceiling down to the ceiling", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "github:call:whoami", "1h");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(10 * 60_000);
  });

  it("honours a request below the ceiling (agent can shorten)", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "github:call:whoami", "2m");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(120_000);
  });

  it("falls back to the agent default_ttl when the rule has none", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "github:read:repo", "1h");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(15 * 60_000);
  });
});

describe("PolicyEngine matching", () => {
  it("matches auto_approve rules with picomatch globs", async () => {
    const e = await freshEngine();
    expect(e.request("test-agent", "github:call:whoami").allow).toBe(true);
    expect(e.request("test-agent", "github:delete:repo").allow).toBe(false);
  });

  it("falls back to the '*' agent policy for unknown agents", async () => {
    const e = await freshEngine();
    const d = e.request("mystery-agent", "docs:read:page1");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(5 * 60_000);
    // ...but '*' rules do not leak capabilities they don't cover.
    expect(e.request("mystery-agent", "github:call:whoami").allow).toBe(false);
  });

  it("denies when no policy exists for the agent and no '*' fallback", async () => {
    const e = await freshEngine({ version: 1, agents: {} });
    const d = e.request("nobody", "docs:read:x");
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.reason).toMatch(/No policy defined for agent 'nobody'/);
  });

  it("require: human_approval denies with escalation", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "github:write:repo");
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.escalation).toBe("human_approval");
  });
});

describe("PolicyEngine grants", () => {
  it("isGranted covers exact and glob-matching grants; revokeAgent drops them", async () => {
    const e = await freshEngine();
    e.request("test-agent", "github:call:*");
    expect(e.isGranted("test-agent", "github:call:whoami")).toBe(true);
    expect(e.isGranted("other-agent", "github:call:whoami")).toBe(false);
    expect(e.activeGrants("test-agent")).toHaveLength(1);
    expect(e.revokeAgent("test-agent")).toBe(1);
    expect(e.isGranted("test-agent", "github:call:whoami")).toBe(false);
  });

  it("expires grants after their TTL", async () => {
    vi.useFakeTimers();
    try {
      const e = await freshEngine();
      e.request("test-agent", "github:call:whoami", "1s");
      expect(e.isGranted("test-agent", "github:call:whoami")).toBe(true);
      vi.setSystemTime(Date.now() + 1_500);
      expect(e.isGranted("test-agent", "github:call:whoami")).toBe(false);
      expect(e.activeGrants("test-agent")).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("PolicyEngine.load / proposeRule", () => {
  it("load() with no policies.yaml denies everything (fail-closed)", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const e = PolicyEngine.load();
    expect(e.request("test-agent", "github:call:whoami").allow).toBe(false);
  });

  it("load() reads policies.yaml from SCOPEGATE_HOME", async () => {
    const { POLICIES_PATH } = await import("../src/config/config.js");
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const YAML = (await import("yaml")).default;
    fs.writeFileSync(POLICIES_PATH, YAML.stringify(POLICIES));
    const e = PolicyEngine.load();
    expect(e.request("test-agent", "github:call:whoami", "5m").allow).toBe(true);
  });

  it("proposeRule appends to policies.pending.yaml and NEVER touches policies.yaml", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const { POLICIES_PATH, PENDING_POLICIES_PATH } = await import(
      "../src/config/config.js"
    );
    fs.writeFileSync(POLICIES_PATH, "version: 1\nagents: {}\n");
    const before = fs.readFileSync(POLICIES_PATH, "utf8");

    const result = PolicyEngine.proposeRule(
      "agent-x",
      { match: "stripe:read:*", ttl: "10m" },
      "need read access to invoices",
    );
    expect(result.file).toBe(PENDING_POLICIES_PATH);
    expect(result.deduped).toBe(false);

    const pending = fs.readFileSync(PENDING_POLICIES_PATH, "utf8");
    expect(pending).toContain("stripe:read:*");
    expect(pending).toContain("need read access to invoices");
    expect(pending).toContain("pending_human_review");
    expect(pending).toContain("agent-x");
    // Live policy file is byte-identical.
    expect(fs.readFileSync(POLICIES_PATH, "utf8")).toBe(before);
  });

  it("proposeRule works when no policies.yaml exists at all", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const { POLICIES_PATH, PENDING_POLICIES_PATH } = await import(
      "../src/config/config.js"
    );
    PolicyEngine.proposeRule("agent-x", { match: "a:b:*" }, "just because");
    expect(fs.existsSync(PENDING_POLICIES_PATH)).toBe(true);
    expect(fs.existsSync(POLICIES_PATH)).toBe(false);
  });
});
