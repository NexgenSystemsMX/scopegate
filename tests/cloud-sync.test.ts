/**
 * EPIC-10 unit tests — cloud-sync client (gateway side):
 *   - Restrictive-intersection team policy layer in the PolicyEngine (every
 *     combination: allow/allow, team deny glob, team silence, team require,
 *     local deny, max_ttl/rule TTL min, live-grant re-clamp, rate limit,
 *     approval-materialized clamp, clear).
 *   - policy-sync: signature verification, signed cache, boot fallback
 *     (cloud down / cache absent / cache tampered), anti-rollback.
 *   - audit-exporter: cursor checkpoint, restart resume, at-least-once
 *     resend with server-side dedup, batch signature verifiable by the
 *     (mock) server with the real agent identity.
 *   - revocation-sync: own agentId / "*" applied (grants purged, revoked
 *     file, request-path checkpoint, audit), other agents ignored,
 *     idempotency.
 *   - enroll + cloud-config round-trip, and the startCloudSync orchestrator.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts); the mock cloud
 * implements the frozen wire contract with real Ed25519 keys on an
 * ephemeral port — no network leaves localhost.
 */
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
const servers: http.Server[] = [];

beforeEach(() => {
  home = useTempHome();
});

afterEach(async () => {
  for (const s of servers.splice(0)) {
    await new Promise((r) => s.close(r));
  }
  cleanupTempHome(home);
});

/* ------------------------------------------------------------------------ */
/* Fixtures                                                                  */
/* ------------------------------------------------------------------------ */

const LOCAL = {
  version: 1 as const,
  limits: { max_ttl: "1h", deny: ["aws:*:production"] },
  agents: {
    "test-agent": {
      default_ttl: "30m",
      capabilities: [
        { match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" },
        { match: "fakegit:call:slow", auto_approve: true, ttl: "45m" },
        { match: "fakegit:call:danger", require: "human_approval" as const, ttl: "20m" },
      ],
    },
  },
};

function teamYaml(opts: {
  deny?: string[];
  maxTtl?: string;
  rules?: Array<Record<string, unknown>>;
  coverAgent?: boolean;
  rateLimit?: string;
}) {
  return JSON.stringify({
    version: 1,
    limits: {
      ...(opts.maxTtl ? { max_ttl: opts.maxTtl } : {}),
      ...(opts.deny ? { deny: opts.deny } : {}),
      ...(opts.rateLimit ? { rate_limit: opts.rateLimit } : {}),
    },
    agents:
      opts.coverAgent === false
        ? {}
        : {
            "test-agent": {
              capabilities: opts.rules ?? [
                { match: "fakegit:call:*", auto_approve: true },
              ],
            },
          },
  });
}

async function freshEngine(local: unknown = LOCAL) {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(local as never);
}

async function engineModule() {
  return import("../src/policy/engine.js");
}

async function applyTeam(
  engine: import("../src/policy/engine.js").PolicyEngine,
  yaml: string,
  version = 1,
) {
  const { validatePoliciesFile } = await engineModule();
  const YAML = (await import("yaml")).default;
  engine.applyTeamPolicy(validatePoliciesFile(YAML.parse(yaml)), {
    version,
    fetchedAt: new Date().toISOString(),
  });
}

/* ------------------------------------------------------------------------ */
/* Mock cloud (frozen wire contract, real Ed25519 keys, ephemeral port)      */
/* ------------------------------------------------------------------------ */

interface MockCloud {
  url: string;
  teamId: string;
  enrollToken: string;
  cloudPubkey: string;
  setPolicy(yaml: string): void;
  /** Set an explicit version (signed correctly) — anti-rollback testing. */
  setRawPolicy(version: number, yaml: string): void;
  signWith(wrongPriv: string): void;
  addRevocation(r: Record<string, unknown>): void;
  receivedBatches: Array<Record<string, unknown>>;
  readonly lastBatchVerified: boolean | null;
  storedSeqs: Set<string>; // "agentId:seq" dedup
  failAudit: boolean;
  rejectAudit: boolean;
  close(): Promise<void>;
}

async function startMockCloud(): Promise<MockCloud> {
  const { canonicalTeamPolicyPayload } = await import(
    "../src/cloud/client/policy-sync.js"
  );
  const { canonicalAuditBatch } = await import("../src/cloud/client/audit-exporter.js");
  const { verifyCanonical, fingerprintOf } = await import("../src/audit/identity.js");

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const cloudPubkey = publicKey.export({ type: "spki", format: "pem" }).toString();
  const cloudPriv = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  const state = {
    teamId: "team-1",
    enrollToken: "tok-one-shot",
    policyVersion: 0,
    policyYaml: "",
    policySignedAt: "",
    signingKey: cloudPriv,
    revocations: [] as Array<Record<string, unknown>>,
    receivedBatches: [] as Array<Record<string, unknown>>,
    lastBatchVerified: null as boolean | null,
    storedSeqs: new Set<string>(),
    enrolled: new Map<string, { fingerprint: string; secret: string }>(),
    failAudit: false,
    rejectAudit: false,
  };

  const json = (res: http.ServerResponse, status: number, obj: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };

  const server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body: Record<string, unknown> = {};
      try {
        body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      } catch {
        /* keep {} */
      }

      if (req.method === "POST" && u.pathname === "/v1/enroll") {
        if (body.enrollToken !== state.enrollToken) {
          return json(res, 403, { error: "invalid enroll token" });
        }
        const secret = "sec-" + crypto.randomBytes(8).toString("hex");
        state.enrolled.set(String(body.agentId), {
          fingerprint: String(body.pubkeyFingerprint),
          secret,
        });
        return json(res, 200, {
          agentSecret: secret,
          teamId: state.teamId,
          cloudPubkey,
        });
      }

      if (req.method === "GET" && u.pathname === "/v1/policy") {
        if (u.searchParams.get("teamId") !== state.teamId) {
          return json(res, 404, { error: "unknown team" });
        }
        const signedAt = state.policySignedAt;
        const payload = {
          teamId: state.teamId,
          version: state.policyVersion,
          yaml: state.policyYaml,
          signedAt,
        };
        return json(res, 200, {
          ...payload,
          signature:
            "ed25519:" +
            crypto
              .sign(null, Buffer.from(canonicalTeamPolicyPayload(payload), "utf8"), state.signingKey)
              .toString("base64"),
        });
      }

      if (req.method === "POST" && u.pathname === "/v1/audit/batch") {
        if (state.failAudit) return json(res, 503, { error: "cloud down" });
        const events = (body.events as Array<{ seq: number }>) ?? [];
        state.receivedBatches.push(body);
        // Server-side verification with the REAL agent identity: the batch
        // signature must verify with the transported pubkey, and that
        // pubkey's fingerprint must match the enrolled one.
        const agentId = String(body.agentId);
        const enrolledAgent = state.enrolled.get(agentId);
        state.lastBatchVerified =
          !!enrolledAgent &&
          typeof body.pubkey === "string" &&
          fingerprintOf(String(body.pubkey)) === enrolledAgent.fingerprint &&
          verifyCanonical(
            String(body.pubkey),
            canonicalAuditBatch({ agentId, events: body.events as never }),
            String(body.signature),
          );
        if (state.rejectAudit) {
          return json(res, 200, { accepted: 0, rejected: events.length });
        }
        // Dedup by agentId+seq: dupes are acknowledged (not rejected).
        for (const e of events) state.storedSeqs.add(`${agentId}:${e.seq}`);
        return json(res, 200, { accepted: events.length, rejected: 0 });
      }

      if (req.method === "GET" && u.pathname === "/v1/revocations") {
        const since = u.searchParams.get("since");
        // Same wire shape as the real server (revocations.ts): `ts`.
        const revocations = state.revocations.filter(
          (r) => !since || String(r.ts ?? "") > since,
        );
        return json(res, 200, { revocations });
      }

      return json(res, 404, { error: "not_found" });
    });
  });
  servers.push(server);
  const port = await new Promise<number>((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve((server.address() as { port: number }).port),
    ),
  );

  return {
    url: `http://127.0.0.1:${port}`,
    teamId: state.teamId,
    enrollToken: state.enrollToken,
    cloudPubkey,
    setPolicy(yaml: string) {
      state.policyVersion += 1;
      state.policyYaml = yaml;
      state.policySignedAt = new Date(Date.now() + state.policyVersion).toISOString();
      state.signingKey = cloudPriv; // reset any tampered key
    },
    setRawPolicy(version: number, yaml: string) {
      state.policyVersion = version;
      state.policyYaml = yaml;
      state.policySignedAt = new Date(Date.now() + version).toISOString();
      state.signingKey = cloudPriv;
    },
    signWith(wrongPriv: string) {
      state.signingKey = wrongPriv;
    },
    addRevocation(r: Record<string, unknown>) {
      state.revocations.push({
        ts: new Date(Date.now() + state.revocations.length).toISOString(),
        ...r,
      });
    },
    receivedBatches: state.receivedBatches,
    get lastBatchVerified() {
      return state.lastBatchVerified;
    },
    storedSeqs: state.storedSeqs,
    set failAudit(v: boolean) {
      state.failAudit = v;
    },
    set rejectAudit(v: boolean) {
      state.rejectAudit = v;
    },
    close: () => new Promise((r) => server.close(() => r())),
  };
}

async function writeCloudJson(cloud: MockCloud, agentId = "test-agent") {
  const { saveCloudConfig } = await import("../src/cloud/client/cloud-config.js");
  saveCloudConfig({
    url: cloud.url,
    agentId,
    teamId: cloud.teamId,
    agentSecret: "sec-test",
    cloudPubkey: cloud.cloudPubkey,
    enrolledAt: new Date().toISOString(),
  });
}

/* ------------------------------------------------------------------------ */
/* 1. Restrictive intersection (engine team layer)                           */
/* ------------------------------------------------------------------------ */

describe("team policy restrictive intersection", () => {
  it("local allow + team allow → allow with TTL = min(local, team)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "fakegit:call:*", auto_approve: true, ttl: "5m" }] }),
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", "1h", "t");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(5 * 60_000); // min(local 10m, team 5m)
  });

  it("team rule with a LOOSER ttl never extends the local grant", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "fakegit:call:*", auto_approve: true, ttl: "2h" }] }),
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", "1h", "t");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(10 * 60_000); // local rule ttl wins (min)
  });

  it("team deny glob blocks what local allows (union of deny globs)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({
        deny: ["fakegit:call:whoami"],
        rules: [{ match: "fakegit:call:*", auto_approve: true }],
      }),
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(false);
    if (!d.allow) {
      expect(d.code).toBe("ceiling_blocked");
      expect(d.reason).toContain("[team policy]");
    }
  });

  it("team silence on a capability is a deny (team must explicitly allow)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "github:read:*", auto_approve: true }] }),
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(false);
    if (!d.allow) {
      expect(d.code).toBe("no_rule");
      expect(d.reason).toContain("[team policy]");
    }
  });

  it("team policy not covering the agent denies everything", async () => {
    const engine = await freshEngine();
    await applyTeam(engine, teamYaml({ coverAgent: false }));
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.code).toBe("no_policy");
  });

  it("team require: human_approval overrides local auto-approve (escalation)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({
        rules: [{ match: "fakegit:call:whoami", require: "human_approval", ttl: "3m" }],
      }),
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(false);
    if (!d.allow) {
      expect(d.escalation).toBe("human_approval");
      expect(d.approvalId).toBeTruthy();
      expect(d.reason).toContain("[team policy]");
    }
  });

  it("team can NEVER allow what local denies (no local rule → deny)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "other:call:*", auto_approve: true }] }),
    );
    const d = engine.request("test-agent", "other:call:x", undefined, "t");
    expect(d.allow).toBe(false); // team gate passes, local has no rule
  });

  it("team can NEVER allow what local deny-globs block", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "aws:*", auto_approve: true }] }),
    );
    const d = engine.request("test-agent", "aws:delete:production", undefined, "t");
    expect(d.allow).toBe(false);
    if (!d.allow) {
      expect(d.code).toBe("ceiling_blocked");
      expect(d.reason).not.toContain("[team policy]"); // local ceiling provenance
    }
  });

  it("max_ttl is the min of local and team (team tighter)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({
        maxTtl: "10m",
        rules: [{ match: "fakegit:call:*", auto_approve: true }],
      }),
    );
    const d = engine.request("test-agent", "fakegit:call:slow", "1h", "t");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(10 * 60_000); // 45m rule → local 1h → team 10m
  });

  it("max_ttl is the min of local and team (local tighter)", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({
        maxTtl: "2h",
        rules: [{ match: "fakegit:call:*", auto_approve: true }],
      }),
    );
    const d = engine.request("test-agent", "fakegit:call:slow", "1h", "t");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(45 * 60_000); // rule ttl 45m is the min
  });

  it("a tightened team policy re-clamps (never extends) live grants", async () => {
    const engine = await freshEngine();
    const before = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(before.allow).toBe(true);
    if (before.allow) expect(before.ttlMs).toBe(10 * 60_000);
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "fakegit:call:*", auto_approve: true, ttl: "5m" }] }),
    );
    const after = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(after.allow).toBe(true);
    if (after.allow) {
      expect(after.ttlMs).toBeLessThanOrEqual(5 * 60_000);
      expect(after.rule).toBe("fakegit:call:whoami"); // existing grant, re-clamped
    }
  });

  it("a team policy that stops covering a capability denies its live grant", async () => {
    const engine = await freshEngine();
    engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(engine.isGranted("test-agent", "fakegit:call:whoami")).toBe(true);
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "github:read:*", auto_approve: true }] }),
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(false); // live team gate wins over the stored grant
  });

  it("clearTeamPolicy restores pure local semantics", async () => {
    const engine = await freshEngine();
    await applyTeam(engine, teamYaml({ coverAgent: false }));
    expect(engine.request("test-agent", "fakegit:call:whoami", undefined, "t").allow).toBe(false);
    engine.clearTeamPolicy();
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(true);
    if (d.allow) expect(d.ttlMs).toBe(10 * 60_000);
  });

  it("team rate_limit applies ADDITIONALLY to the local one", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({
        rateLimit: "1/m",
        rules: [{ match: "fakegit:call:*", auto_approve: true }],
      }),
    );
    expect(engine.checkRateLimit("test-agent").allowed).toBe(true);
    const second = engine.checkRateLimit("test-agent");
    expect(second.allowed).toBe(false);
    expect(second.reason).toContain("[team policy]");
  });

  it("local human-approval grant is clamped by the team ceiling on materialize", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({ rules: [{ match: "fakegit:call:*", auto_approve: true, ttl: "5m" }] }),
    );
    // Local rule requires human approval (20m local ttl; team ceiling 5m).
    const esc = engine.request("test-agent", "fakegit:call:danger", undefined, "t");
    expect(esc.allow).toBe(false);
    if (esc.allow || !esc.approvalId) throw new Error("expected escalation");
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({
        id: esc.approvalId,
        decision: "approved",
        decidedAt: Date.now(),
        decidedBy: "human:test",
      }) + "\n",
      { mode: 0o600 },
    );
    const d = engine.request("test-agent", "fakegit:call:danger", undefined, "t");
    expect(d.allow).toBe(true);
    if (d.allow) {
      // min(local 20m, team 5m), reported as remaining ms (a few ms elapsed)
      expect(d.ttlMs).toBeGreaterThan(5 * 60_000 - 5_000);
      expect(d.ttlMs).toBeLessThanOrEqual(5 * 60_000);
    }
  });

  it("team-escalated approval materializes a grant clamped to the team rule ttl", async () => {
    const engine = await freshEngine();
    await applyTeam(
      engine,
      teamYaml({
        rules: [{ match: "fakegit:call:whoami", require: "human_approval", ttl: "3m" }],
      }),
    );
    const esc = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    if (esc.allow || !esc.approvalId) throw new Error("expected team escalation");
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({
        id: esc.approvalId,
        decision: "approved",
        decidedAt: Date.now(),
        decidedBy: "human:test",
      }) + "\n",
      { mode: 0o600 },
    );
    const d = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(d.allow).toBe(true);
    if (d.allow) {
      // team rule ttl 3m, reported as remaining ms (a few ms elapsed)
      expect(d.ttlMs).toBeGreaterThan(3 * 60_000 - 5_000);
      expect(d.ttlMs).toBeLessThanOrEqual(3 * 60_000);
    }
  });
});

/* ------------------------------------------------------------------------ */
/* 2. policy-sync                                                            */
/* ------------------------------------------------------------------------ */

describe("policy-sync", () => {
  it("fetches, verifies, caches and applies the team policy", async () => {
    const cloud = await startMockCloud();
    cloud.setPolicy(teamYaml({ deny: ["fakegit:call:whoami"] }));
    const engine = await freshEngine();
    const { syncTeamPolicyOnce } = await import("../src/cloud/client/policy-sync.js");
    const cfg = {
      url: cloud.url,
      teamId: cloud.teamId,
      agentSecret: "sec-test",
      cloudPubkey: cloud.cloudPubkey,
    };
    const r1 = await syncTeamPolicyOnce(cfg, engine);
    expect(r1).toEqual({ applied: true, version: 1 });
    expect(engine.teamPolicyInfo()?.version).toBe(1);
    // The team layer is live: local-allowed, team-denied → denied.
    expect(engine.request("test-agent", "fakegit:call:whoami", undefined, "t").allow).toBe(false);
    // Cache written and verifiable.
    const { TEAM_POLICY_CACHE_PATH } = await import("../src/cloud/client/cloud-config.js");
    expect(fs.existsSync(TEAM_POLICY_CACHE_PATH)).toBe(true);
    // Same version again → no-op.
    const r2 = await syncTeamPolicyOnce(cfg, engine);
    expect(r2.applied).toBe(false);
  });

  it("rejects a bad signature (engine and cache untouched)", async () => {
    const cloud = await startMockCloud();
    cloud.setPolicy(teamYaml({}));
    const wrong = crypto.generateKeyPairSync("ed25519");
    cloud.signWith(wrong.privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    const engine = await freshEngine();
    const { syncTeamPolicyOnce } = await import("../src/cloud/client/policy-sync.js");
    const r = await syncTeamPolicyOnce(
      { url: cloud.url, teamId: cloud.teamId, agentSecret: "s", cloudPubkey: cloud.cloudPubkey },
      engine,
    );
    expect(r.applied).toBe(false);
    expect(engine.teamPolicyInfo()).toBeNull();
    const { TEAM_POLICY_CACHE_PATH } = await import("../src/cloud/client/cloud-config.js");
    expect(fs.existsSync(TEAM_POLICY_CACHE_PATH)).toBe(false);
  });

  it("rejects a signed but schema-invalid policy", async () => {
    const cloud = await startMockCloud();
    cloud.setPolicy(JSON.stringify({ version: 2, agents: {} })); // wrong schema version
    const engine = await freshEngine();
    const { syncTeamPolicyOnce } = await import("../src/cloud/client/policy-sync.js");
    const r = await syncTeamPolicyOnce(
      { url: cloud.url, teamId: cloud.teamId, agentSecret: "s", cloudPubkey: cloud.cloudPubkey },
      engine,
    );
    expect(r.applied).toBe(false);
    expect(engine.teamPolicyInfo()).toBeNull();
  });

  it("ignores an older version, even with a valid signature (anti-rollback)", async () => {
    const cloud = await startMockCloud();
    cloud.setPolicy(teamYaml({}));
    const engine = await freshEngine();
    const { syncTeamPolicyOnce } = await import("../src/cloud/client/policy-sync.js");
    const cfg = {
      url: cloud.url,
      teamId: cloud.teamId,
      agentSecret: "s",
      cloudPubkey: cloud.cloudPubkey,
    };
    await syncTeamPolicyOnce(cfg, engine); // v1
    cloud.setPolicy(teamYaml({ deny: ["fakegit:call:*"] }));
    await syncTeamPolicyOnce(cfg, engine); // v2 applied
    expect(engine.teamPolicyInfo()?.version).toBe(2);
    // The cloud serves an OLDER (correctly signed) version: never applied.
    cloud.setRawPolicy(1, teamYaml({}));
    const r = await syncTeamPolicyOnce(cfg, engine);
    expect(r.applied).toBe(false);
    expect(engine.teamPolicyInfo()?.version).toBe(2); // v2 stays in force
    expect(engine.request("test-agent", "fakegit:call:whoami", undefined, "t").allow).toBe(false);
  });

  it("boot: applies the verified cache; ignores corrupt or tampered cache (local-first)", async () => {
    const cloud = await startMockCloud();
    cloud.setPolicy(teamYaml({ deny: ["fakegit:call:whoami"] }));
    const engine = await freshEngine();
    const { syncTeamPolicyOnce, loadVerifiedTeamPolicyCache } = await import(
      "../src/cloud/client/policy-sync.js"
    );
    await syncTeamPolicyOnce(
      { url: cloud.url, teamId: cloud.teamId, agentSecret: "s", cloudPubkey: cloud.cloudPubkey },
      engine,
    );
    // Fresh engine at "boot": cache verifies and applies.
    const cached = loadVerifiedTeamPolicyCache(cloud.cloudPubkey);
    expect(cached?.meta.version).toBe(1);
    const bootEngine = await freshEngine();
    bootEngine.applyTeamPolicy(cached!.policies, cached!.meta);
    expect(bootEngine.request("test-agent", "fakegit:call:whoami", undefined, "t").allow).toBe(false);
    // Tampered cache (yaml edited without re-signing) → local-only.
    const { TEAM_POLICY_CACHE_PATH } = await import("../src/cloud/client/cloud-config.js");
    const tampered = JSON.parse(fs.readFileSync(TEAM_POLICY_CACHE_PATH, "utf8"));
    tampered.yaml = teamYaml({}); // signature no longer matches
    fs.writeFileSync(TEAM_POLICY_CACHE_PATH, JSON.stringify(tampered));
    expect(loadVerifiedTeamPolicyCache(cloud.cloudPubkey)).toBeNull();
    // Corrupt cache → local-only.
    fs.writeFileSync(TEAM_POLICY_CACHE_PATH, "{not json");
    expect(loadVerifiedTeamPolicyCache(cloud.cloudPubkey)).toBeNull();
  });

  it("cloud down: sync throws (loop backs off) and the engine keeps last-good", async () => {
    const engine = await freshEngine();
    await applyTeam(engine, teamYaml({}), 7);
    const { syncTeamPolicyOnce } = await import("../src/cloud/client/policy-sync.js");
    const down = async () => {
      throw new Error("fetch failed: ECONNREFUSED");
    };
    await expect(
      syncTeamPolicyOnce(
        { url: "http://127.0.0.1:1", teamId: "t", agentSecret: "s", cloudPubkey: "k" },
        engine,
        { fetchImpl: down as never },
      ),
    ).rejects.toThrow("ECONNREFUSED");
    expect(engine.teamPolicyInfo()?.version).toBe(7); // last-good intact
  });
});

/* ------------------------------------------------------------------------ */
/* 3. audit-exporter                                                         */
/* ------------------------------------------------------------------------ */

describe("audit-exporter", () => {
  async function writeEvents(agentId: string, n: number) {
    const { audit } = await import("../src/audit/log.js");
    for (let i = 0; i < n; i++) {
      audit(agentId, "tool_call", { tool: `tool_${i}`, n: i });
    }
  }

  async function cursorSeq() {
    const { loadExportCursor } = await import("../src/cloud/client/audit-exporter.js");
    return loadExportCursor().lastSeq;
  }

  it("exports new events in a signature-verifiable batch and checkpoints the cursor", async () => {
    const cloud = await startMockCloud();
    await writeCloudJson(cloud);
    // Enroll (registers the identity fingerprint server-side), then write events.
    const { enrollGateway } = await import("../src/cloud/client/enroll.js");
    await enrollGateway({ url: cloud.url, enrollToken: cloud.enrollToken, agentId: "test-agent" });
    await writeEvents("test-agent", 5);
    const { exportAuditOnce } = await import("../src/cloud/client/audit-exporter.js");
    const r = await exportAuditOnce({
      url: cloud.url,
      agentId: "test-agent",
      agentSecret: "sec-test",
    });
    expect(r).toMatchObject({ sent: 5, accepted: 5, rejected: 0 });
    expect(cloud.lastBatchVerified).toBe(true); // server verified the batch signature
    expect(await cursorSeq()).toBe(5);
    // Idle tick: nothing pending.
    const idle = await exportAuditOnce({
      url: cloud.url,
      agentId: "test-agent",
      agentSecret: "sec-test",
    });
    expect(idle.hadPending).toBe(false);
  });

  it("cursor survives a restart; only new events are exported", async () => {
    const cloud = await startMockCloud();
    await writeEvents("test-agent", 3);
    const { exportAuditOnce, loadExportCursor } = await import(
      "../src/cloud/client/audit-exporter.js"
    );
    const cfg = { url: cloud.url, agentId: "test-agent", agentSecret: "sec-test" };
    await exportAuditOnce(cfg);
    expect(loadExportCursor().lastSeq).toBe(3); // fresh read from disk (restart-proof)
    await writeEvents("test-agent", 2);
    const r = await exportAuditOnce(cfg);
    expect(r.sent).toBe(2);
    expect(loadExportCursor().lastSeq).toBe(5);
    expect(cloud.storedSeqs.size).toBe(5);
  });

  it("at-least-once: a failed POST keeps the cursor; the resend is deduped server-side", async () => {
    const cloud = await startMockCloud();
    await writeEvents("test-agent", 4);
    const { exportAuditOnce, loadExportCursor } = await import(
      "../src/cloud/client/audit-exporter.js"
    );
    const cfg = { url: cloud.url, agentId: "test-agent", agentSecret: "sec-test" };
    cloud.failAudit = true;
    await expect(exportAuditOnce(cfg)).rejects.toThrow("HTTP 503");
    expect(loadExportCursor().lastSeq).toBe(0); // nothing acked → nothing checkpointed
    cloud.failAudit = false;
    const r = await exportAuditOnce(cfg);
    expect(r.sent).toBe(4); // same events re-sent
    expect(loadExportCursor().lastSeq).toBe(4);
    expect(cloud.storedSeqs.size).toBe(4); // server deduped by agentId+seq
  });

  it("rejected events are skipped (no poison loop); cursor advances past them", async () => {
    const cloud = await startMockCloud();
    await writeEvents("test-agent", 3);
    const { exportAuditOnce, loadExportCursor } = await import(
      "../src/cloud/client/audit-exporter.js"
    );
    const cfg = { url: cloud.url, agentId: "test-agent", agentSecret: "sec-test" };
    cloud.rejectAudit = true;
    const r = await exportAuditOnce(cfg);
    expect(r.rejected).toBe(3);
    expect(loadExportCursor().lastSeq).toBe(3);
    cloud.rejectAudit = false;
    const idle = await exportAuditOnce(cfg);
    expect(idle.hadPending).toBe(false); // no infinite resend
  });
});

/* ------------------------------------------------------------------------ */
/* 4. revocation-sync                                                        */
/* ------------------------------------------------------------------------ */

describe("revocation-sync", () => {
  async function setup() {
    const cloud = await startMockCloud();
    const engine = await freshEngine();
    const { syncRevocationsOnce, cloudRevocationCheckpoint } = await import(
      "../src/cloud/client/revocation-sync.js"
    );
    const cfg = { url: cloud.url, teamId: cloud.teamId, agentSecret: "sec-test" };
    return { cloud, engine, syncRevocationsOnce, cloudRevocationCheckpoint, cfg };
  }

  it("a revocation for the own agentId purges grants, persists state, denies the request path, audits", async () => {
    const { cloud, engine, syncRevocationsOnce, cloudRevocationCheckpoint, cfg } = await setup();
    // A live grant exists before the revocation lands.
    const g = engine.request("test-agent", "fakegit:call:whoami", undefined, "t");
    expect(g.allow).toBe(true);
    cloud.addRevocation({ agentId: "test-agent", reason: "laptop compromised" });
    const r = await syncRevocationsOnce(cfg, engine, "test-agent", null);
    expect(r.applied).toBe(true);
    expect(r.lastSeen).toBeTruthy();
    expect(engine.activeGrants("test-agent")).toHaveLength(0); // revokeAgent ran
    const gate = cloudRevocationCheckpoint("test-agent");
    expect(gate.revoked).toBe(true);
    expect(gate.message).toContain("laptop compromised");
    const { CLOUD_REVOKED_PATH } = await import("../src/cloud/client/cloud-config.js");
    expect(fs.existsSync(CLOUD_REVOKED_PATH)).toBe(true);
    // audit trail: agent_revoked with cloud provenance.
    const raw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    expect(raw).toContain('"agent_revoked"');
    expect(raw).toContain('"via":"cloud"');
    // Idempotent: a second poll does not re-apply.
    const r2 = await syncRevocationsOnce(cfg, engine, "test-agent", r.lastSeen);
    expect(r2.applied).toBe(false);
  });

  it("a revocation for ANOTHER agent is ignored (blast radius per agent)", async () => {
    const { cloud, engine, syncRevocationsOnce, cloudRevocationCheckpoint, cfg } = await setup();
    cloud.addRevocation({ agentId: "someone-else", reason: "not me" });
    const r = await syncRevocationsOnce(cfg, engine, "test-agent", null);
    expect(r.applied).toBe(false);
    expect(cloudRevocationCheckpoint("test-agent").revoked).toBe(false);
  });

  it("a team-wide '*' revocation applies to this agent", async () => {
    const { cloud, engine, syncRevocationsOnce, cloudRevocationCheckpoint, cfg } = await setup();
    cloud.addRevocation({ agentId: "*", reason: "team incident" });
    const r = await syncRevocationsOnce(cfg, engine, "test-agent", null);
    expect(r.applied).toBe(true);
    expect(cloudRevocationCheckpoint("test-agent").revoked).toBe(true);
  });

  it("checkpoint is clear without a revoked file", async () => {
    const { cloudRevocationCheckpoint } = await import(
      "../src/cloud/client/revocation-sync.js"
    );
    expect(cloudRevocationCheckpoint("test-agent")).toEqual({ revoked: false });
  });
});

/* ------------------------------------------------------------------------ */
/* 5. enroll + cloud-config + orchestrator                                   */
/* ------------------------------------------------------------------------ */

describe("enroll + cloud-config", () => {
  it("enrollGateway persists cloud.json; loadCloudConfig round-trips it", async () => {
    const cloud = await startMockCloud();
    const { enrollGateway } = await import("../src/cloud/client/enroll.js");
    const cfg = await enrollGateway({
      url: cloud.url,
      enrollToken: cloud.enrollToken,
      agentId: "test-agent",
    });
    expect(cfg.teamId).toBe(cloud.teamId);
    expect(cfg.agentSecret).toMatch(/^sec-/);
    const { loadCloudConfig, CLOUD_CONFIG_PATH } = await import(
      "../src/cloud/client/cloud-config.js"
    );
    expect(fs.existsSync(CLOUD_CONFIG_PATH)).toBe(true);
    const loaded = loadCloudConfig();
    expect(loaded).toMatchObject({
      agentId: "test-agent",
      teamId: cloud.teamId,
      cloudPubkey: cloud.cloudPubkey,
    });
    // The fingerprint the cloud received matches the local identity.
    const { loadIdentity } = await import("../src/audit/identity.js");
    expect(loadIdentity().fingerprint).toBeTruthy();
  });

  it("enroll with a bad token throws and writes nothing", async () => {
    const cloud = await startMockCloud();
    const { enrollGateway } = await import("../src/cloud/client/enroll.js");
    await expect(
      enrollGateway({ url: cloud.url, enrollToken: "wrong", agentId: "test-agent" }),
    ).rejects.toThrow("HTTP 403");
    const { CLOUD_CONFIG_PATH } = await import("../src/cloud/client/cloud-config.js");
    expect(fs.existsSync(CLOUD_CONFIG_PATH)).toBe(false);
  });

  it("enroll against a dead URL throws an actionable local-first error", async () => {
    const { enrollGateway } = await import("../src/cloud/client/enroll.js");
    await expect(
      enrollGateway({ url: "http://127.0.0.1:1", enrollToken: "x", agentId: "test-agent" }),
    ).rejects.toThrow(/local-first/);
  });

  it("corrupt cloud.json → loadCloudConfig returns null (sync stays off)", async () => {
    const { loadCloudConfig, CLOUD_CONFIG_PATH } = await import(
      "../src/cloud/client/cloud-config.js"
    );
    fs.writeFileSync(CLOUD_CONFIG_PATH, "{broken");
    expect(loadCloudConfig()).toBeNull();
  });
});

describe("startCloudSync orchestrator", () => {
  it("returns null without cloud.json (OSS default, zero behavior change)", async () => {
    const engine = await freshEngine();
    const { startCloudSync } = await import("../src/cloud/client/sync.js");
    expect(startCloudSync({ policy: engine, agentId: "test-agent" })).toBeNull();
  });

  it("runs the three loops against the mock cloud and stops cleanly", async () => {
    const cloud = await startMockCloud();
    cloud.setPolicy(teamYaml({ deny: ["fakegit:call:slow"] }));
    await writeCloudJson(cloud);
    const engine = await freshEngine();
    const { startCloudSync } = await import("../src/cloud/client/sync.js");
    const handle = startCloudSync({
      policy: engine,
      agentId: "test-agent",
      intervals: { policyMs: 50, auditMs: 50, revocationMs: 50 },
    });
    expect(handle).not.toBeNull();
    try {
      // Policy loop applies the team layer quickly.
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && !engine.teamPolicyInfo()) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(engine.teamPolicyInfo()?.version).toBe(1);
      expect(engine.request("test-agent", "fakegit:call:slow", undefined, "t").allow).toBe(false);
      // Audit loop exports the grant_issued/denied events the engine wrote.
      await writeCloudJson(cloud); // refresh enrolled secret (no-op shape)
      const { audit } = await import("../src/audit/log.js");
      audit("test-agent", "tool_call", { tool: "orchestrator_probe" });
      const auditDeadline = Date.now() + 3000;
      while (Date.now() < auditDeadline && cloud.receivedBatches.length === 0) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(cloud.receivedBatches.length).toBeGreaterThan(0);
      // Revocation loop applies a fleet revocation.
      cloud.addRevocation({ agentId: "test-agent", reason: "orchestrated" });
      const { cloudRevocationCheckpoint } = await import(
        "../src/cloud/client/revocation-sync.js"
      );
      const revDeadline = Date.now() + 3000;
      while (Date.now() < revDeadline && !cloudRevocationCheckpoint("test-agent").revoked) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(cloudRevocationCheckpoint("test-agent").revoked).toBe(true);
    } finally {
      handle!.stop();
    }
  });
});
