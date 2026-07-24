/**
 * M13 — Cloud a producción (additive EPIC tests).
 *
 *   1. FileStore audit-retention purge: purgeAuditEvents drops events older
 *      than the cutoff, keeps the fresh ones, persists the rewrite to disk.
 *   2. Server wiring: SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS triggers a purge
 *      at boot (the hourly timer is the same code path, unref'd).
 *   3. PostgresStore: full Store-interface contract against a MOCK PgPoolLike
 *      (no real Postgres in CI): idempotent schema DDL, mirror semantics
 *      parity with FileStore, 100% parametrized SQL, retention DELETE,
 *      boot-load round trip, close() flush + pool end.
 *   4. CLI `scopegate cloud enroll`: spawns `node dist/cli.js` against a real
 *      cloud server on an ephemeral port and verifies cloud.json lands in a
 *      throwaway SCOPEGATE_HOME. The dist build is refreshed only if stale.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import type {
  Agent,
  StoredAuditEvent,
  Team,
} from "../src/cloud/server/model.js";
import type { PgPoolLike } from "../src/cloud/server/pg-store.js";
import type { startCloudServer as startCloudServerT } from "../src/cloud/server/index.js";

type RunningCloud = Awaited<ReturnType<typeof startCloudServerT>>;

const DAY_MS = 86_400_000;
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const tempDirs: string[] = [];
function mkdtemp(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  delete process.env.SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS;
});

/* ------------------------------------------------------------------ */
/* fixtures                                                            */
/* ------------------------------------------------------------------ */

function ev(agentId: string, seq: number, ts: string, kind = "tool_call"): StoredAuditEvent {
  return {
    ts,
    agentId,
    kind,
    detail: { tool: "fake__call" },
    prev: seq === 1 ? "genesis" : `h-${agentId}-${seq - 1}`,
    seq,
    sig: `sig-${agentId}-${seq}`,
    hash: `h-${agentId}-${seq}`,
    _cloud: { ingestedAt: ts, sigVerified: true },
  };
}

/* ------------------------------------------------------------------ */
/* 1. FileStore retention purge                                        */
/* ------------------------------------------------------------------ */

describe("M13 FileStore audit retention purge", () => {
  it("drops events older than the cutoff, keeps fresh ones, persists", async () => {
    const home = mkdtemp("scopegate-m13-file-");
    const { FileStore } = await import("../src/cloud/server/store.js");
    // auditRetentionDays: 0 disables the legacy append-time prune so the
    // periodic purge is the only mechanism under test.
    const store = new FileStore(home, { auditRetentionDays: 0 });

    const oldTs = new Date(Date.now() - 40 * DAY_MS).toISOString();
    const newTs = new Date().toISOString();
    store.appendAuditEvents("team-a", [ev("agent-1", 1, oldTs), ev("agent-1", 2, newTs)]);
    store.appendAuditEvents("team-b", [ev("agent-9", 1, oldTs)]);

    const cutoff = new Date(Date.now() - 30 * DAY_MS).toISOString();
    const removed = store.purgeAuditEvents(cutoff);
    expect(removed).toBe(2);
    expect(store.allAuditEvents("team-a").map((e) => e.seq)).toEqual([2]);
    expect(store.allAuditEvents("team-b")).toEqual([]);
    // query view agrees (most-recent-first single survivor)
    expect(store.queryAuditEvents("team-a", {}).map((e) => e.seq)).toEqual([2]);

    // The rewrite is on disk, not just in memory.
    const reopened = new FileStore(home);
    expect(reopened.allAuditEvents("team-a").length).toBe(1);
    expect(reopened.allAuditEvents("team-b")).toEqual([]);
    // And a second purge is a no-op (idempotent).
    expect(reopened.purgeAuditEvents(cutoff)).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/* 2. Server wiring: env var → boot purge                              */
/* ------------------------------------------------------------------ */

describe("M13 server audit-retention wiring", () => {
  it("purges at boot when SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS is set", async () => {
    const cloudHome = mkdtemp("scopegate-m13-wire-");
    const { FileStore } = await import("../src/cloud/server/store.js");
    const seed = new FileStore(cloudHome, { auditRetentionDays: 0 });
    const oldTs = new Date(Date.now() - 40 * DAY_MS).toISOString();
    const newTs = new Date().toISOString();
    seed.appendAuditEvents("team-a", [ev("agent-1", 1, oldTs), ev("agent-1", 2, newTs)]);

    process.env.SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS = "30";
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    const cloud = await startCloudServer({
      port: 0,
      home: cloudHome,
      adminToken: "m13-admin",
      announce: false,
      store: seed, // injected → the test keeps ownership
    });
    try {
      // The boot pass of the periodic purge ran before listen returned.
      const kept = seed.allAuditEvents("team-a");
      expect(kept.length).toBe(1);
      expect(kept[0].ts).toBe(newTs);
      // The server is fully functional on the purged store.
      const health = await fetch(`http://127.0.0.1:${cloud.port}/health`);
      expect(health.status).toBe(200);
    } finally {
      await cloud.close();
    }
  });

  it("keeps everything by default (no env var, no periodic purge)", async () => {
    const cloudHome = mkdtemp("scopegate-m13-wire-off-");
    const { FileStore } = await import("../src/cloud/server/store.js");
    const seed = new FileStore(cloudHome, { auditRetentionDays: 0 });
    const oldTs = new Date(Date.now() - 400 * DAY_MS).toISOString();
    seed.appendAuditEvents("team-a", [ev("agent-1", 1, oldTs)]);

    delete process.env.SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS;
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    const cloud = await startCloudServer({
      port: 0,
      home: cloudHome,
      adminToken: "m13-admin",
      announce: false,
      store: seed,
    });
    try {
      expect(seed.allAuditEvents("team-a").length).toBe(1);
    } finally {
      await cloud.close();
    }
  });
});

/* ------------------------------------------------------------------ */
/* 3. PostgresStore over a mock pool (no real Postgres in CI)          */
/* ------------------------------------------------------------------ */

interface RecordedQuery {
  text: string;
  params: unknown[];
}

function makeMockPool(seedRows: Record<string, Record<string, unknown>[]> = {}) {
  const queries: RecordedQuery[] = [];
  let ended = false;
  const pool: PgPoolLike = {
    async query(text, params = []) {
      queries.push({ text, params });
      const m = /^SELECT \* FROM (\w+)/.exec(text);
      if (m) return { rows: seedRows[m[1]] ?? [] };
      return { rows: [] };
    },
    async end() {
      ended = true;
    },
  };
  return { pool, queries, isEnded: () => ended };
}

describe("M13 PostgresStore (mock pool contract)", () => {
  it("creates the schema idempotently before loading the mirror", async () => {
    const mock = makeMockPool();
    const { PostgresStore } = await import("../src/cloud/server/pg-store.js");
    await PostgresStore.create({ pool: mock.pool });

    const ddl = mock.queries.filter((q) => q.text.includes("IF NOT EXISTS"));
    // 6 tables + 2 indexes, all idempotent.
    expect(ddl.length).toBe(8);
    for (const t of [
      "teams",
      "agents",
      "policy_versions",
      "audit_events",
      "revocations",
      "approval_decisions",
    ]) {
      expect(
        mock.queries.some((q) => q.text.includes(`CREATE TABLE IF NOT EXISTS ${t} (`)),
        `DDL for ${t}`,
      ).toBe(true);
    }
    const firstSelect = mock.queries.findIndex((q) => q.text.startsWith("SELECT"));
    expect(firstSelect).toBeGreaterThan(0);
    expect(mock.queries.slice(0, firstSelect).every((q) => q.text.includes("IF NOT EXISTS"))).toBe(
      true,
    );
  });

  it("covers the whole Store interface with FileStore parity semantics", async () => {
    const mock = makeMockPool();
    const { PostgresStore } = await import("../src/cloud/server/pg-store.js");
    const store = await PostgresStore.create({ pool: mock.pool });
    const now = new Date().toISOString();

    // teams (with a SQL-injection-shaped name to prove parametrization)
    const team: Team = {
      teamId: "team-1",
      name: "acme'); DROP TABLE teams;--",
      enrollToken: "tok-1",
      createdAt: now,
    };
    store.createTeam(team);
    expect(store.getTeam("team-1")?.name).toBe(team.name);
    expect(store.findTeamByEnrollToken("tok-1")?.teamId).toBe("team-1");
    expect(store.listTeams().length).toBe(1);
    expect(store.updateTeam("team-1", { slackWebhookUrl: "https://hooks.example/x" })?.slackWebhookUrl).toBe(
      "https://hooks.example/x",
    );
    expect(store.updateTeam("nope", { name: "x" })).toBeUndefined();

    // agents
    const agent: Agent = {
      agentId: "a-1",
      teamId: "team-1",
      fingerprint: "sha256:ff",
      publicKey: "pem",
      secretHash: "hash-1",
      enrolledAt: now,
      lastSeen: null,
      revoked: false,
    };
    store.upsertAgent(agent);
    expect(store.getAgent("team-1", "a-1")?.fingerprint).toBe("sha256:ff");
    expect(store.findAgentBySecretHash("hash-1")?.agentId).toBe("a-1");
    expect(store.listAgents("team-1").length).toBe(1);
    const later = new Date(Date.now() + 1000).toISOString();
    store.updateAgent("team-1", "a-1", { lastSeen: later, revoked: true, revokedAt: later });
    expect(store.getAgent("team-1", "a-1")?.revoked).toBe(true);
    expect(store.getAgent("team-1", "a-1")?.lastSeen).toBe(later);
    // upsert replaces the same key instead of duplicating
    store.upsertAgent({ ...agent, revoked: true });
    expect(store.listAgents("team-1").length).toBe(1);

    // policies (append-only version history)
    store.addPolicyVersion({ teamId: "team-1", version: 2, yaml: "v2", signature: "s2", signedAt: now });
    store.addPolicyVersion({ teamId: "team-1", version: 1, yaml: "v1", signature: "s1", signedAt: now });
    expect(store.latestPolicy("team-1")?.version).toBe(2);
    expect(store.policyVersions("team-1").map((p) => p.version)).toEqual([1, 2]);

    // audit
    const oldTs = new Date(Date.now() - 40 * DAY_MS).toISOString();
    store.appendAuditEvents("team-1", [
      ev("a-1", 1, oldTs),
      ev("a-1", 2, now, "approval_requested"),
      ev("a-2", 1, now),
    ]);
    expect(store.allAuditEvents("team-1").length).toBe(3);
    expect(store.knownAuditSeqs("team-1", "a-1")).toEqual(new Set([1, 2]));
    expect(store.queryAuditEvents("team-1", { kind: "tool_call" }).length).toBe(2);
    // most recent first
    expect(store.queryAuditEvents("team-1", {})[0].agentId).toBe("a-2");
    expect(store.queryAuditEvents("team-1", { agentId: "a-1", limit: 1 }).length).toBe(1);
    expect(
      store.activeAgentsInWindow(
        "team-1",
        new Date(Date.now() - DAY_MS).toISOString(),
        new Date(Date.now() + DAY_MS).toISOString(),
      ),
    ).toEqual(["a-1", "a-2"]);

    // revocations
    store.addRevocation({ teamId: "team-1", agentId: "a-1", reason: "compromised", ts: now });
    expect(store.listRevocations("team-1").length).toBe(1);
    expect(store.listRevocations("team-1", new Date(Date.now() + DAY_MS).toISOString())).toEqual([]);

    // approval decisions (idempotent per approvalId)
    const decision = {
      approvalId: "ap-1",
      teamId: "team-1",
      agentId: "a-1",
      decision: "approved" as const,
      decidedBy: "human:cloud:panel",
      ts: now,
    };
    store.addApprovalDecision(decision);
    store.addApprovalDecision(decision);
    expect(store.approvalDecisions("team-1").length).toBe(1);
    expect(store.approvalDecision("team-1", "ap-1")?.decision).toBe("approved");

    await store.flush();
    // EVERY mutating call reached Postgres as parametrized SQL: the hostile
    // team name never appears inside SQL text, but does appear as a param.
    const writes = mock.queries.filter((q) => !q.text.startsWith("SELECT") && !q.text.includes("IF NOT EXISTS"));
    expect(writes.length).toBeGreaterThan(0);
    expect(mock.queries.every((q) => !q.text.includes("DROP TABLE teams;--"))).toBe(true);
    expect(mock.queries.some((q) => q.params.includes(team.name))).toBe(true);
    expect(mock.queries.some((q) => q.text.includes("ON CONFLICT (team_id, agent_id) DO UPDATE"))).toBe(
      true,
    );
    expect(
      mock.queries.some((q) => q.text.includes("ON CONFLICT (team_id, agent_id, seq) DO NOTHING")),
    ).toBe(true);
  });

  it("purges old audit events and enqueues a parametrized DELETE", async () => {
    const mock = makeMockPool();
    const { PostgresStore } = await import("../src/cloud/server/pg-store.js");
    const store = await PostgresStore.create({ pool: mock.pool });

    const oldTs = new Date(Date.now() - 40 * DAY_MS).toISOString();
    const newTs = new Date().toISOString();
    store.appendAuditEvents("team-1", [ev("a-1", 1, oldTs), ev("a-1", 2, newTs)]);
    store.appendAuditEvents("team-2", [ev("a-9", 1, oldTs)]);

    const cutoff = new Date(Date.now() - 30 * DAY_MS).toISOString();
    expect(store.purgeAuditEvents(cutoff)).toBe(2);
    expect(store.allAuditEvents("team-1").map((e) => e.seq)).toEqual([2]);
    expect(store.allAuditEvents("team-2")).toEqual([]);

    await store.flush();
    const del = mock.queries.find((q) => q.text.startsWith("DELETE FROM audit_events"));
    expect(del).toBeDefined();
    expect(del!.text).not.toContain(cutoff);
    expect(del!.params).toEqual([cutoff]);
    // no events past retention → no-op, no extra DELETE
    expect(store.purgeAuditEvents(cutoff)).toBe(0);
    await store.flush();
    expect(mock.queries.filter((q) => q.text.startsWith("DELETE FROM audit_events")).length).toBe(1);
  });

  it("loads an existing database into the mirror at boot (round trip)", async () => {
    const ts = new Date().toISOString();
    const mock = makeMockPool({
      teams: [
        {
          team_id: "team-9",
          name: "nexgen",
          enroll_token: "tok-9",
          slack_webhook_url: null,
          created_at: ts,
        },
      ],
      agents: [
        {
          team_id: "team-9",
          agent_id: "a-9",
          fingerprint: "sha256:aa",
          public_key: "pem",
          secret_hash: "hash-9",
          enrolled_at: ts,
          last_seen: null,
          revoked: false,
          revoked_at: null,
          last_chain_hash: null,
        },
      ],
      policy_versions: [
        { team_id: "team-9", version: 3, yaml: "v3", signature: "s3", signed_at: ts },
      ],
      audit_events: [
        {
          id: 1,
          team_id: "team-9",
          agent_id: "a-9",
          seq: 7,
          ts,
          kind: "tool_call",
          detail: JSON.stringify({ tool: "fake__call", n: 1 }),
          input_hash: null,
          prev: "p",
          sig: "s",
          hash: "h",
          ingested_at: ts,
          sig_verified: false,
        },
      ],
      revocations: [{ id: 1, team_id: "team-9", agent_id: "a-9", reason: "r", ts }],
      approval_decisions: [
        {
          team_id: "team-9",
          approval_id: "ap-9",
          agent_id: "a-9",
          decision: "denied",
          reason: "no",
          ttl: null,
          decided_by: "human:cloud:panel",
          ts,
        },
      ],
    });
    const { PostgresStore } = await import("../src/cloud/server/pg-store.js");
    const store = await PostgresStore.create({ pool: mock.pool });

    expect(store.getTeam("team-9")?.enrollToken).toBe("tok-9");
    expect(store.getAgent("team-9", "a-9")?.fingerprint).toBe("sha256:aa");
    expect(store.latestPolicy("team-9")?.version).toBe(3);
    expect(store.knownAuditSeqs("team-9", "a-9")).toEqual(new Set([7]));
    const event = store.allAuditEvents("team-9")[0];
    expect(event._cloud.sigVerified).toBe(false);
    expect(event.detail).toEqual({ tool: "fake__call", n: 1 });
    expect(store.listRevocations("team-9").length).toBe(1);
    expect(store.approvalDecision("team-9", "ap-9")?.decision).toBe("denied");
  });

  it("close() flushes the write queue and ends the pool (idempotent)", async () => {
    const mock = makeMockPool();
    const { PostgresStore } = await import("../src/cloud/server/pg-store.js");
    const store = await PostgresStore.create({ pool: mock.pool });
    const now = new Date().toISOString();
    store.createTeam({ teamId: "team-1", name: "n", enrollToken: "t", createdAt: now });
    await store.close();
    expect(mock.isEnded()).toBe(true);
    expect(store.lastWriteError).toBeNull();
    expect(mock.queries.some((q) => q.text.startsWith("INSERT INTO teams"))).toBe(true);
    await store.close(); // second close is a no-op
    expect(mock.isEnded()).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* 4. CLI `scopegate cloud enroll`                                     */
/* ------------------------------------------------------------------ */

/** Build dist/ only when the enroll command is missing from the built CLI. */
function ensureDistBuilt(): void {
  const cliJs = path.join(repoRoot, "dist", "cli.js");
  const enrollJs = path.join(repoRoot, "dist", "cloud", "client", "enroll.js");
  const fresh =
    fs.existsSync(cliJs) &&
    fs.existsSync(enrollJs) &&
    fs.readFileSync(cliJs, "utf8").includes('.command("enroll")');
  if (fresh) return;
  // Local tsc — no npm/shell indirection (Windows-safe).
  execFileSync(process.execPath, [path.join(repoRoot, "node_modules", "typescript", "bin", "tsc")], {
    cwd: repoRoot,
    stdio: "pipe",
    timeout: 180_000,
  });
}

describe("M13 CLI cloud enroll", () => {
  beforeAll(() => ensureDistBuilt(), 240_000);

  async function withCloud(
    fn: (cloud: RunningCloud, base: string) => Promise<void>,
  ): Promise<void> {
    const cloudHome = mkdtemp("scopegate-m13-cli-cloud-");
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    const cloud = await startCloudServer({
      port: 0,
      home: cloudHome,
      adminToken: "m13-admin",
      announce: false,
    });
    try {
      await fn(cloud, `http://127.0.0.1:${cloud.port}`);
    } finally {
      await cloud.close();
    }
  }

  /**
   * Async spawn: spawnSync would block THIS process's event loop and starve
   * the in-process test server, so the child's enroll fetch would time out.
   */
  function runCli(
    gwHome: string,
    args: string[],
  ): Promise<{ status: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [path.join(repoRoot, "dist", "cli.js"), ...args], {
        env: { ...process.env, SCOPEGATE_HOME: gwHome },
      });
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8").on("data", (d) => (stdout += d));
      child.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
      child.on("error", reject);
      child.on("close", (status) => resolve({ status, stdout, stderr }));
    });
  }

  it(
    "enrolls against a real server and writes cloud.json in SCOPEGATE_HOME",
    { timeout: 90_000 },
    async () => {
      const gwHome = mkdtemp("scopegate-m13-cli-gw-");
      await withCloud(async (cloud, base) => {
        const res = await fetch(`${base}/v1/admin/teams`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: "Bearer m13-admin",
          },
          body: JSON.stringify({ name: "m13" }),
        });
        expect(res.status).toBe(201);
        const { enrollToken, teamId } = (await res.json()) as {
          enrollToken: string;
          teamId: string;
        };

        // trailing slash on --cloud exercises URL normalization
        const r = await runCli(gwHome, ["cloud", "enroll", "--cloud", base + "/", "--token", enrollToken]);
        expect(r.status).toBe(0);
        const printed = JSON.parse(r.stdout) as Record<string, unknown>;
        expect(printed.teamId).toBe(teamId);
        expect(printed.url).toBe(base);
        expect(printed.agentId).toBeTypeOf("string");
        expect(printed.cloudPubkey).toBe(cloud.cloudIdentity.publicKey);
        // the agent secret is NEVER printed — it only lands in cloud.json
        expect(printed.agentSecret).toBeUndefined();

        const cloudJson = JSON.parse(
          fs.readFileSync(path.join(gwHome, "cloud.json"), "utf8"),
        ) as Record<string, unknown>;
        expect(cloudJson.teamId).toBe(teamId);
        expect(cloudJson.url).toBe(base);
        expect((cloudJson.agentSecret as string).length).toBeGreaterThan(20);
        expect(cloudJson.cloudPubkey).toBe(cloud.cloudIdentity.publicKey);
        expect(typeof cloudJson.enrolledAt).toBe("string");
      });
    },
  );

  it(
    "fails with a clear error on a bad token and writes nothing",
    { timeout: 90_000 },
    async () => {
      const gwHome = mkdtemp("scopegate-m13-cli-gw-bad-");
      await withCloud(async (_cloud, base) => {
        const r = await runCli(gwHome, ["cloud", "enroll", "--cloud", base, "--token", "wrong-token"]);
        expect(r.status).toBe(1);
        expect(r.stderr).toContain("enroll");
        expect(fs.existsSync(path.join(gwHome, "cloud.json"))).toBe(false);
      });
    },
  );

  it("requires --cloud and --token", { timeout: 60_000 }, async () => {
    const gwHome = mkdtemp("scopegate-m13-cli-gw-opts-");
    const r = await runCli(gwHome, ["cloud", "enroll"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("--cloud");
  });
});
