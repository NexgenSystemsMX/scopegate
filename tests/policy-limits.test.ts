/**
 * EPIC-04 unit tests: hard limits (deny/max_ttl/rate_limit), strict TTL
 * parsing, propose_policy 2.0, hot-reload with last-good, grant persistence
 * and PII redaction.
 */
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
let enginesToStop: Array<{ stopWatching(): void }> = [];

beforeEach(() => {
  home = useTempHome();
  enginesToStop = [];
});

afterEach(() => {
  for (const e of enginesToStop) e.stopWatching();
  cleanupTempHome(home);
});

const POLICIES = {
  version: 1 as const,
  limits: {
    max_ttl: "30m",
    deny: ["aws:*:production", "\\*:*"], // glob '\*:*': literal '*' + ':' + wildcard
    rate_limit: "30/m",
  },
  agents: {
    "test-agent": {
      default_ttl: "15m",
      capabilities: [
        { match: "github:call:*", auto_approve: true, ttl: "10m" },
        { match: "aws:call:*", auto_approve: true, ttl: "45m" },
        { match: "github:write:*", require: "human_approval" as const },
      ],
    },
    "capped-agent": {
      limits: { max_ttl: "5m" }, // per-agent wins over the global 30m
      capabilities: [{ match: "aws:call:*", auto_approve: true, ttl: "45m" }],
    },
  },
};

async function freshEngine(policies = POLICIES) {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(policies);
}

async function auditKinds(): Promise<string[]> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  if (!fs.existsSync(AUDIT_LOG_PATH)) return [];
  return fs
    .readFileSync(AUDIT_LOG_PATH, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l).kind as string);
}

describe("hard limits: deny globs (H-04.1)", () => {
  it("deny beats a matching auto_approve rule (fail-closed, ceiling_blocked)", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "aws:deploy:production");
    expect(d.allow).toBe(false);
    if (!d.allow) {
      expect(d.code).toBe("ceiling_blocked");
      expect(d.reason).toMatch(/hard limit/);
    }
  });

  it("deny is evaluated BEFORE any rule even when a rule would auto-approve", async () => {
    const e = await freshEngine();
    // 'aws:call:production' is NOT covered by 'aws:*:production'? it is: aws:call:production matches aws:*:production
    const blocked = e.request("test-agent", "aws:call:production");
    expect(blocked.allow).toBe(false);
    // ...while the same upstream on staging passes the auto_approve rule
    const allowed = e.request("test-agent", "aws:call:staging", "10m");
    expect(allowed.allow).toBe(true);
  });

  it("blocks literal '*:*' injection asks via escaped deny glob, without blocking normal caps", async () => {
    const e = await freshEngine();
    const injection = e.request("test-agent", "*:*");
    expect(injection.allow).toBe(false);
    if (!injection.allow) expect(injection.code).toBe("ceiling_blocked");
    expect(e.request("test-agent", "github:call:whoami", "5m").allow).toBe(true);
  });
});

describe("hard limits: max_ttl clamp (H-04.1)", () => {
  it("clamps below the rule ceiling when max_ttl is lower (global limit)", async () => {
    const e = await freshEngine();
    // rule ttl 45m, max_ttl 30m → 30m wins
    const d = e.request("test-agent", "aws:call:staging", "1h");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(30 * 60_000);
  });

  it("per-agent limits win over global limits", async () => {
    const e = await freshEngine();
    const d = e.request("capped-agent", "aws:call:staging", "1h");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(5 * 60_000); // agent max_ttl 5m, not 30m
  });

  it("agent can still shorten below max_ttl", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "aws:call:staging", "2m");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(120_000);
  });
});

describe("strict TTL parsing (fail-closed config)", () => {
  it("denies with invalid_ttl when the agent asks for a garbage ttl", async () => {
    const e = await freshEngine();
    const d = e.request("test-agent", "github:call:whoami", "whenever");
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.code).toBe("invalid_ttl");
  });

  it("load() throws on a broken rule ttl (first load is fail-closed)", async () => {
    const { POLICIES_PATH } = await import("../src/config/config.js");
    const { PolicyEngine, PolicyConfigError } = await import("../src/policy/engine.js");
    fs.writeFileSync(
      POLICIES_PATH,
      JSON.stringify({
        version: 1,
        agents: { a: { capabilities: [{ match: "x:*", auto_approve: true, ttl: "soon" }] } },
      }),
    );
    expect(() => PolicyEngine.load()).toThrow(PolicyConfigError);
  });

  it("load() throws on unknown limits keys, bad deny globs and unknown redact categories", async () => {
    const { POLICIES_PATH } = await import("../src/config/config.js");
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const bad = [
      { version: 1, limits: { maxttl: "1h" }, agents: {} }, // typo'd key
      { version: 1, limits: { deny: [""] }, agents: {} }, // empty glob
      {
        version: 1,
        agents: { a: { capabilities: [{ match: "x:*", auto_approve: true, redact: ["dna"] }] } },
      },
    ];
    for (const doc of bad) {
      fs.writeFileSync(POLICIES_PATH, JSON.stringify(doc));
      expect(() => PolicyEngine.load()).toThrow(/non-empty|unknown/i);
    }
  });

  it("accepts a Fase-0 policies.yaml unchanged (backward compatible)", async () => {
    const { PolicyEngine, validatePoliciesFile } = await import("../src/policy/engine.js");
    const legacy = {
      version: 1,
      agents: {
        a: {
          default_ttl: "15m",
          capabilities: [
            { match: "github:call:*", auto_approve: true, ttl: "5m" },
            { match: "aws:*:production", require: "human_approval" },
          ],
        },
        "*": { capabilities: [{ match: "*:call:get_*", auto_approve: true }] },
      },
    };
    expect(() => validatePoliciesFile(legacy)).not.toThrow();
    const e = new PolicyEngine(validatePoliciesFile(legacy));
    expect(e.request("a", "github:call:x", "1m").allow).toBe(true);
  });
});

describe("rate limiting (H-04.7)", () => {
  it("denies the (n+1)-th request in the window with capability_rate_limited", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const e = new PolicyEngine({
      version: 1,
      agents: {
        a: {
          limits: { rate_limit: "3/m" },
          capabilities: [{ match: "x:*", auto_approve: true }],
        },
      },
    });
    expect(e.checkRateLimit("a").allowed).toBe(true);
    expect(e.checkRateLimit("a").allowed).toBe(true);
    expect(e.checkRateLimit("a").allowed).toBe(true);
    const fourth = e.checkRateLimit("a");
    expect(fourth.allowed).toBe(false);
    expect(fourth.reason).toMatch(/capability_rate_limited/);
    // ...and the window is per-agent
    expect(e.checkRateLimit("b").allowed).toBe(true);
  });

  it("defaults to 30/m when no rate_limit is configured", async () => {
    const e = await freshEngine({ version: 1, agents: {} });
    for (let i = 0; i < 30; i++) expect(e.checkRateLimit("a").allowed).toBe(true);
    expect(e.checkRateLimit("a").allowed).toBe(false);
  });
});

describe("propose_policy 2.0 (H-04.4)", () => {
  it("rejects agent-settable violations: require, auto_approve, limits, redact", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    for (const rule of [
      { match: "x:*", require: null },
      { match: "x:*", auto_approve: true },
      { match: "x:*", limits: { max_ttl: "1h" } },
      { match: "x:*", redact: ["pii"] },
    ]) {
      expect(() =>
        PolicyEngine.proposeRule("agent-x", rule as never, "trying to escalate"),
      ).toThrow(/not agent-settable/);
    }
  });

  it("rejects empty/invalid globs and unparseable TTLs", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    expect(() => PolicyEngine.proposeRule("a", { match: " " }, "x")).toThrow(/Proposal rejected/);
    expect(() => PolicyEngine.proposeRule("a", { match: "x:*", ttl: "long" }, "x")).toThrow(
      /Proposal rejected/,
    );
  });

  it("flags proposals colliding with limits as lint: conflicts_with_limits", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const byDeny = PolicyEngine.proposeRule(
      "test-agent",
      { match: "aws:read:production" },
      "need prod read",
      POLICIES,
    );
    expect(byDeny.lint).toBe("conflicts_with_limits");
    const byTtl = PolicyEngine.proposeRule(
      "test-agent",
      { match: "github:read:*", ttl: "2h" },
      "long ttl",
      POLICIES,
    );
    expect(byTtl.lint).toBe("conflicts_with_limits");
    const clean = PolicyEngine.proposeRule(
      "test-agent",
      { match: "github:read:*", ttl: "10m" },
      "fine",
      POLICIES,
    );
    expect(clean.lint).toBeUndefined();
  });

  it("dedups by (agentId, match, ttl) and keeps policies.yaml byte-identical", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const { POLICIES_PATH, PENDING_POLICIES_PATH } = await import("../src/config/config.js");
    const YAML = (await import("yaml")).default;
    fs.writeFileSync(POLICIES_PATH, YAML.stringify(POLICIES));
    const before = fs.readFileSync(POLICIES_PATH, "utf8");

    const first = PolicyEngine.proposeRule("agent-x", { match: "stripe:read:*", ttl: "10m" }, "need it");
    const second = PolicyEngine.proposeRule("agent-x", { match: "stripe:read:*", ttl: "10m" }, "need it again");
    const third = PolicyEngine.proposeRule("agent-x", { match: "stripe:read:*", ttl: "5m" }, "different ttl");

    expect(first.deduped).toBe(false);
    expect(second.deduped).toBe(true);
    expect(third.deduped).toBe(false);

    const pending = fs.readFileSync(PENDING_POLICIES_PATH, "utf8");
    expect(pending.match(/stripe:read:\*/g)).toHaveLength(2); // 10m once, 5m once
    // THE invariant: the agent can never touch the live file.
    expect(fs.readFileSync(POLICIES_PATH, "utf8")).toBe(before);
  });
});

describe("hot-reload (H-04.5)", () => {
  it("reloads a valid edit within ~1s and keeps last-good + audits on invalid YAML", async () => {
    const { POLICIES_PATH } = await import("../src/config/config.js");
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const YAML = (await import("yaml")).default;
    fs.writeFileSync(POLICIES_PATH, YAML.stringify(POLICIES));
    const e = PolicyEngine.load();
    enginesToStop.push(e);
    e.startWatching(20); // short debounce for tests

    // 1. valid edit picks up a brand-new rule
    const updated = structuredClone(POLICIES);
    updated.agents["test-agent"].capabilities.push({
      match: "hot:call:*",
      auto_approve: true,
      ttl: "3m",
    });
    fs.writeFileSync(POLICIES_PATH, YAML.stringify(updated));
    let ok = false;
    for (let i = 0; i < 50 && !ok; i++) {
      await new Promise((r) => setTimeout(r, 40));
      ok = e.request("test-agent", "hot:call:x", "1m").allow === true;
    }
    expect(ok).toBe(true);

    // 2. invalid YAML: last-good stays in force and the error is audited
    fs.writeFileSync(POLICIES_PATH, "version: 1\nagents: {broken: [");
    await new Promise((r) => setTimeout(r, 400));
    expect(e.request("test-agent", "hot:call:y", "1m").allow).toBe(true);
    expect(await auditKinds()).toContain("policy_reload_error");
  });
});

describe("grant persistence (H-04.2)", () => {
  it("grants survive an engine restart; expired ones are discarded on load", async () => {
    const { POLICIES_PATH } = await import("../src/config/config.js");
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const YAML = (await import("yaml")).default;
    fs.writeFileSync(POLICIES_PATH, YAML.stringify(POLICIES));

    const e1 = PolicyEngine.load();
    expect(e1.request("test-agent", "github:call:persist", "10m").allow).toBe(true);
    expect(e1.request("test-agent", "github:call:short", "1s").allow).toBe(true);

    // Simulate a restart: a NEW engine over the same SCOPEGATE_HOME.
    const e2 = PolicyEngine.load();
    enginesToStop.push(e2);
    expect(e2.isGranted("test-agent", "github:call:persist")).toBe(true);
    expect(e2.activeGrants("test-agent").map((g) => g.id)).not.toHaveLength(0);

    await new Promise((r) => setTimeout(r, 1100));
    const e3 = PolicyEngine.load();
    enginesToStop.push(e3);
    expect(e3.isGranted("test-agent", "github:call:short")).toBe(false); // expired → dropped
    expect(e3.isGranted("test-agent", "github:call:persist")).toBe(true);
  });

  it("emits grant_issued / grant_expired / grants_revoked lifecycle events", async () => {
    const e = await freshEngine();
    e.request("test-agent", "github:call:lifecycle", "1s");
    e.request("test-agent", "github:call:revoked", "10m");
    await new Promise((r) => setTimeout(r, 1100));
    expect(e.isGranted("test-agent", "github:call:lifecycle")).toBe(false); // purge happens here
    expect(e.revokeAgent("test-agent")).toBe(1);

    const kinds = await auditKinds();
    expect(kinds).toContain("grant_issued");
    expect(kinds).toContain("grant_expired");
    expect(kinds).toContain("grants_revoked");
  });

  it("a corrupt grants.json fails closed (empty store)", async () => {
    const { GRANTS_PATH, GrantStore } = await import("../src/policy/grants.js");
    const { ensureDir } = await import("../src/config/config.js");
    ensureDir();
    fs.writeFileSync(GRANTS_PATH, "{not json");
    const store = new GrantStore();
    expect(store.isGranted("test-agent", "github:call:x")).toBe(false);
  });
});

describe("redact (H-04.6)", () => {
  it("masks email, E.164 phone, Luhn-valid card and AWS key id", async () => {
    const { redactText } = await import("../src/policy/redact.js");
    const input =
      "contact alice@example.com or +34 600 123 456, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE";
    const { text, counts } = redactText(input, ["pii"]);
    expect(text).not.toContain("alice@example.com");
    expect(text).not.toContain("4111 1111 1111 1111");
    expect(text).not.toContain("+34 600 123 456");
    expect(text).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(text).toContain("[REDACTED:email]");
    expect(text).toContain("[REDACTED:card]");
    expect(counts).toMatchObject({ email: 1, card: 1, phone: 1, aws_access_key: 1 });
  });

  it("is conservative: digit strings failing Luhn are NOT masked", async () => {
    const { redactText } = await import("../src/policy/redact.js");
    const { text, counts } = redactText("order 1234567890123456 total", ["pii"]);
    expect(text).toContain("1234567890123456");
    expect(counts.card ?? 0).toBe(0);
  });

  it("redactToolResult masks text content items and reports counts", async () => {
    const { redactToolResult } = await import("../src/policy/redact.js");
    const result = {
      content: [
        { type: "text", text: "mail me at bob@corp.io" },
        { type: "image", data: "binary" },
      ],
    };
    const { result: out, counts } = redactToolResult(result, ["pii"]);
    const items = (out as typeof result).content;
    expect((items[0] as { text: string }).text).toBe("mail me at [REDACTED:email]");
    expect(items[1]).toEqual({ type: "image", data: "binary" });
    expect(counts).toEqual({ email: 1 });
    // original object untouched
    expect(result.content[0].text).toContain("bob@corp.io");
  });
});
