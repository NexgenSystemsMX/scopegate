/**
 * EPIC-11 unit tests: honeytoken generation, detection on every vector
 * (register_upstream / request_capability / external_hit), surgical
 * revocation, alert-only mode, human re-enable and the hard zero-false-
 * positive regression (legitimate refs and values never trigger anything).
 */
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");

let home: string;

beforeEach(() => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local"; // skip the vaultd probe
});

afterEach(() => {
  delete process.env.SCOPEGATE_HONEYTOKEN_MODE;
  delete process.env.SCOPEGATE_VAULT_MODE;
  cleanupTempHome(home);
});

const POLICIES = {
  version: 1 as const,
  agents: {
    "test-agent": {
      capabilities: [
        { match: "fakegit:call:*", auto_approve: true, ttl: "10m" },
      ],
    },
  },
};

async function freshEngine() {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(POLICIES);
}

async function freshVault() {
  const { Vault } = await import("../src/vault/vault.js");
  return Vault.open();
}

async function auditEvents(): Promise<
  Array<{ kind: string; agentId: string; detail: Record<string, unknown> }>
> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  if (!fs.existsSync(AUDIT_LOG_PATH)) return [];
  return fs
    .readFileSync(AUDIT_LOG_PATH, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

/** Spawn fake-upstream --http; resolve with { child, port }. */
function startHttpUpstream(): Promise<{
  child: ReturnType<typeof spawn>;
  port: number;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [FAKE_UPSTREAM, "--http"], {
      stdio: ["ignore", "pipe", "inherit"],
      env: { ...process.env, SCOPEGATE_HOME: home },
    });
    let buf = "";
    child.stdout?.on("data", (d) => {
      buf += d.toString();
      const m = /FAKE_UPSTREAM_PORT=(\d+)/.exec(buf);
      if (m) resolve({ child, port: Number(m[1]) });
    });
    child.on("error", reject);
    child.on("exit", (code) =>
      reject(new Error(`http fake upstream exited early (${code})`)),
    );
    setTimeout(() => reject(new Error("no port reported")), 10_000);
  });
}

describe("honeytoken generation", () => {
  it("plants a high-entropy canary in the vault and registers only its hash", async () => {
    const { plantCanary, loadState, HONEYTOKEN_STATE_PATH } = await import(
      "../src/honeytoken/honeytoken.js"
    );
    const vault = await freshVault();
    const planted = plantCanary(vault, {
      name: "deploy-key",
      agentId: "test-agent",
      upstream: "github",
    });
    expect(planted.ref).toBe("canary:deploy-key");
    // High entropy, credential-looking decoy value, deposited under the ref.
    expect(planted.value).toMatch(/^sg_canary_[A-Za-z0-9_-]{32}$/);
    expect(vault.get("canary:deploy-key")).toBe(planted.value);
    // The state file registers the canary with a HASH, never the value.
    const state = loadState();
    const entry = state.canaries.find((c) => c.ref === "canary:deploy-key");
    expect(entry).toBeDefined();
    expect(entry?.agentId).toBe("test-agent");
    expect(entry?.valueSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(fs.readFileSync(HONEYTOKEN_STATE_PATH, "utf8")).not.toContain(
      planted.value,
    );
    // Re-planting rotates the value (single entry, new hash).
    const rotated = plantCanary(vault, { name: "deploy-key" });
    expect(rotated.value).not.toBe(planted.value);
    expect(
      loadState().canaries.filter((c) => c.ref === "canary:deploy-key"),
    ).toHaveLength(1);
    expect(vault.get("canary:deploy-key")).toBe(rotated.value);
    expect(() => plantCanary(vault, { name: "bad:name" })).toThrow(/Invalid/);
  });
});

describe("honeytoken detection vectors", () => {
  it("register_upstream vector: a canary ref used as a credential triggers", async () => {
    const ht = await import("../src/honeytoken/honeytoken.js");
    const vault = await freshVault();
    const planted = ht.plantCanary(vault, {
      name: "deploy-key",
      agentId: "test-agent",
    });
    // The detection primitive server.ts wires into register_upstream.
    const found = ht.findCanaryRef(planted.ref);
    expect(found?.name).toBe("deploy-key");
    const engine = await freshEngine();
    const res = ht.respondCanaryTrigger({
      policy: engine,
      agentId: "test-agent",
      canary: found!,
      vector: "register_upstream",
      evidence: { upstream: "evil", ref: planted.ref },
    });
    expect(res.mode).toBe("enforce");
    const events = await auditEvents();
    const triggered = events.find((e) => e.kind === "honeytoken_triggered");
    expect(triggered?.agentId).toBe("test-agent");
    expect(triggered?.detail.vector).toBe("register_upstream");
    expect(triggered?.detail.ref).toBe("canary:deploy-key");
    expect(events.some((e) => e.kind === "agent_revoked")).toBe(true);
  });

  it("request_capability vector: a capability string mentioning a canary ref is found", async () => {
    const ht = await import("../src/honeytoken/honeytoken.js");
    const vault = await freshVault();
    ht.plantCanary(vault, { name: "deploy-key", agentId: "test-agent" });
    const found = ht.findCanaryRefsInText("github:call:canary:deploy-key");
    expect(found?.ref).toBe("canary:deploy-key");
    const engine = await freshEngine();
    ht.respondCanaryTrigger({
      policy: engine,
      agentId: "test-agent",
      canary: found!,
      vector: "request_capability",
      evidence: { capability: "github:call:canary:deploy-key" },
    });
    const events = await auditEvents();
    const triggered = events.find((e) => e.kind === "honeytoken_triggered");
    expect(triggered?.detail.vector).toBe("request_capability");
    expect(triggered?.detail.capability).toBe("github:call:canary:deploy-key");
  });

  it(
    "external_hit vector: /canary-hit with the canary VALUE triggers via the sweep (idempotent)",
    async () => {
      const ht = await import("../src/honeytoken/honeytoken.js");
      const vault = await freshVault();
      const planted = ht.plantCanary(vault, {
        name: "deploy-key",
        agentId: "test-agent",
      });
      const upstream = await startHttpUpstream();
      try {
        // The leaked value is used OUTSIDE the gateway (e.g. against the
        // decoy endpoint): the fake upstream records the hit.
        const resp = await fetch(
          `http://127.0.0.1:${upstream.port}/canary-hit?value=${encodeURIComponent(planted.value)}`,
          { method: "POST" },
        );
        expect(resp.status).toBe(200);
        expect(fs.existsSync(ht.CANARY_HITS_PATH)).toBe(true);
        // The gateway's per-request sweep picks it up and responds.
        const engine = await freshEngine();
        ht.processExternalHits(engine);
        expect(ht.getSuspension("test-agent")?.vector).toBe("external_hit");
        const events = await auditEvents();
        const triggered = events.filter(
          (e) => e.kind === "honeytoken_triggered",
        );
        expect(triggered).toHaveLength(1);
        expect(triggered[0].detail.vector).toBe("external_hit");
        // The canary VALUE is evidence — never written to the audit log.
        expect(
          fs.readFileSync(
            (await import("../src/config/config.js")).AUDIT_LOG_PATH,
            "utf8",
          ),
        ).not.toContain(planted.value);
        // Idempotent: sweeping again does not re-trigger (byte offset).
        ht.processExternalHits(engine);
        const after = await auditEvents();
        expect(
          after.filter((e) => e.kind === "honeytoken_triggered"),
        ).toHaveLength(1);
      } finally {
        upstream.child.kill();
      }
    },
    15_000,
  );
});

describe("surgical revocation (enforce mode)", () => {
  it("revokes the agent's grants, suspends it and the checkpoint denies everything", async () => {
    const ht = await import("../src/honeytoken/honeytoken.js");
    const vault = await freshVault();
    const planted = ht.plantCanary(vault, {
      name: "deploy-key",
      agentId: "test-agent",
    });
    const engine = await freshEngine();
    // The agent had a live grant before the incident.
    const d = engine.request("test-agent", "fakegit:call:whoami", "10m", "t");
    expect(d.allow).toBe(true);
    expect(engine.activeGrants("test-agent")).toHaveLength(1);

    const res = ht.respondCanaryTrigger({
      policy: engine,
      agentId: "test-agent",
      canary: ht.findCanaryRef(planted.ref)!,
      vector: "register_upstream",
    });
    expect(res).toEqual({ mode: "enforce", revokedGrants: 1 });
    // Surgical: grants of THIS agent are gone…
    expect(engine.activeGrants("test-agent")).toHaveLength(0);
    expect(engine.isGranted("test-agent", "fakegit:call:whoami")).toBe(false);
    // …the agent is suspended and the fail-closed gate denies everything.
    const gate = ht.honeytokenCheckpoint(engine, "test-agent");
    expect(gate.suspended).toBe(true);
    expect(gate.message).toMatch(/SUSPENDED/);
    expect(gate.message).toMatch(/honeytoken-state\.json/);
    // …with both audit events in order: trigger → revocation.
    const events = await auditEvents();
    const kinds = events.map((e) => e.kind);
    expect(kinds.indexOf("honeytoken_triggered")).toBeGreaterThanOrEqual(0);
    expect(kinds.indexOf("agent_revoked")).toBeGreaterThan(
      kinds.indexOf("honeytoken_triggered"),
    );
    const revoked = events.find((e) => e.kind === "agent_revoked");
    expect(revoked?.detail.revokedGrants).toBe(1);
    expect(revoked?.detail.suspended).toBe(true);
    // Blast radius: a DIFFERENT agent is untouched by the suspension gate.
    expect(ht.honeytokenCheckpoint(engine, "other-agent").suspended).toBe(
      false,
    );
  });

  it("human re-enable: removing the suspension from the state file lifts the gate", async () => {
    const ht = await import("../src/honeytoken/honeytoken.js");
    const vault = await freshVault();
    const planted = ht.plantCanary(vault, { name: "k", agentId: "test-agent" });
    const engine = await freshEngine();
    ht.respondCanaryTrigger({
      policy: engine,
      agentId: "test-agent",
      canary: ht.findCanaryRef(planted.ref)!,
      vector: "register_upstream",
    });
    expect(ht.honeytokenCheckpoint(engine, "test-agent").suspended).toBe(true);
    // The documented human process: delete the state file after the review.
    fs.rmSync(ht.HONEYTOKEN_STATE_PATH);
    expect(ht.honeytokenCheckpoint(engine, "test-agent").suspended).toBe(
      false,
    );
  });
});

describe("alert-only mode (SCOPEGATE_HONEYTOKEN_MODE=alert)", () => {
  it("audits the trigger but does NOT revoke grants or suspend", async () => {
    process.env.SCOPEGATE_HONEYTOKEN_MODE = "alert";
    const ht = await import("../src/honeytoken/honeytoken.js");
    const vault = await freshVault();
    const planted = ht.plantCanary(vault, { name: "k", agentId: "test-agent" });
    const engine = await freshEngine();
    engine.request("test-agent", "fakegit:call:whoami", "10m", "t");
    const res = ht.respondCanaryTrigger({
      policy: engine,
      agentId: "test-agent",
      canary: ht.findCanaryRef(planted.ref)!,
      vector: "register_upstream",
    });
    expect(res).toEqual({ mode: "alert", revokedGrants: 0 });
    // Detection IS audited (with mode: alert)…
    const events = await auditEvents();
    const triggered = events.find((e) => e.kind === "honeytoken_triggered");
    expect(triggered?.detail.mode).toBe("alert");
    // …but containment is not: no agent_revoked, grants live, no suspension.
    expect(events.some((e) => e.kind === "agent_revoked")).toBe(false);
    expect(engine.activeGrants("test-agent")).toHaveLength(1);
    expect(ht.getSuspension("test-agent")).toBeNull();
    expect(ht.honeytokenCheckpoint(engine, "test-agent").suspended).toBe(
      false,
    );
  });
});

describe("zero false positives (hard regression)", () => {
  it("legitimate refs, capabilities and unknown values never trigger anything", async () => {
    const ht = await import("../src/honeytoken/honeytoken.js");
    const vault = await freshVault();
    const planted = ht.plantCanary(vault, {
      name: "deploy-key",
      agentId: "test-agent",
    });
    // Normal vault refs and normal capability strings are not canaries.
    expect(ht.findCanaryRef("github_token")).toBeNull();
    expect(ht.findCanaryRef("canary:not-registered")).toBeNull();
    expect(ht.findCanaryRefsInText("fakegit:call:whoami")).toBeNull();
    expect(ht.findCanaryRefsInText("aws:*:production")).toBeNull();
    // A DIFFERENT (rotated-away or forged) value is not the live canary.
    expect(ht.findCanaryByValue("sg_canary_forged-not-registered")).toBeNull();
    // External hits with unknown values do not trigger.
    const upstream = await startHttpUpstream();
    try {
      await fetch(
        `http://127.0.0.1:${upstream.port}/canary-hit?value=not-a-canary`,
        { method: "POST" },
      );
      await fetch(`http://127.0.0.1:${upstream.port}/canary-hit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ value: "sg_canary_forged-not-registered" }),
      });
      const engine = await freshEngine();
      ht.processExternalHits(engine);
      expect(await auditEvents()).toHaveLength(0);
      expect(ht.getSuspension("test-agent")).toBeNull();
      expect(ht.honeytokenCheckpoint(engine, "test-agent").suspended).toBe(
        false,
      );
      // And a normal proxied-style operation on the engine stays granted.
      const d = engine.request("test-agent", "fakegit:call:whoami", "5m", "t");
      expect(d.allow).toBe(true);
    } finally {
      upstream.child.kill();
    }
    void planted;
  }, 15_000);
});
