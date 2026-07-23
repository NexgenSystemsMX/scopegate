/**
 * ScopeGate Cloud control plane — server-side tests (EPIC-10).
 *
 * Covers the frozen contract with CLOUD-SYNC: enroll → signed policy →
 * verified pull, signed audit ingest (accept/reject paths), the
 * looksLikeSecret ingest guard, revocation feed, billing metering, approval
 * alerts and auth scopes.
 *
 * Isolation: every test gets a fresh SCOPEGATE_HOME (helpers.ts) AND a fresh
 * cloud home under it; the server binds an ephemeral port (0). The injected
 * AlertPoster means no network is ever touched.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { startCloudServer as startCloudServerT } from "../src/cloud/server/index.js";

type RunningCloud = Awaited<ReturnType<typeof startCloudServerT>>;
type AlertPoster = import("../src/cloud/server/alerts.js").AlertPoster;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const ADMIN = "test-admin-token";

interface TestAgentIdentity {
  agentId: string;
  publicKey: string;
  privateKey: string;
  fingerprint: string;
}

async function makeAgentIdentity(agentId: string): Promise<TestAgentIdentity> {
  const { fingerprintOf } = await import("../src/audit/identity.js");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    agentId,
    publicKey: pub,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    fingerprint: fingerprintOf(pub),
  };
}

interface TestEvent {
  ts: string;
  agentId: string;
  kind: string;
  detail: Record<string, unknown>;
  prev: string;
  seq: number;
  sig: string;
  hash: string;
}

async function signEvent(
  id: TestAgentIdentity,
  partial: Omit<TestEvent, "sig" | "hash">,
): Promise<TestEvent> {
  const { canonicalSigned, canonicalUnsigned } = await import("../src/audit/log.js");
  const { signCanonical } = await import("../src/audit/identity.js");
  const identity = {
    v: 1 as const,
    algo: "ed25519" as const,
    publicKey: id.publicKey,
    privateKey: id.privateKey,
    fingerprint: id.fingerprint,
    createdAt: new Date().toISOString(),
  };
  const sig = signCanonical(identity, canonicalUnsigned(partial as never));
  const signed = { ...partial, sig };
  const hash = crypto
    .createHash("sha256")
    .update(partial.prev + canonicalSigned(signed as never))
    .digest("hex");
  return { ...signed, hash };
}

/** Build a properly chained+signed batch of `n` events continuing from `prev`. */
async function makeChain(
  id: TestAgentIdentity,
  n: number,
  opts: { startSeq?: number; prev?: string; kind?: string; detail?: Record<string, unknown>; ts?: string } = {},
): Promise<TestEvent[]> {
  const events: TestEvent[] = [];
  let prev = opts.prev ?? "genesis";
  const startSeq = opts.startSeq ?? 1;
  for (let i = 0; i < n; i++) {
    const e = await signEvent(id, {
      ts: opts.ts ?? new Date().toISOString(),
      agentId: id.agentId,
      kind: opts.kind ?? "tool_call",
      detail: opts.detail ?? { tool: "github__get_issue", upstream: "github" },
      prev,
      seq: startSeq + i,
    });
    events.push(e);
    prev = e.hash;
  }
  return events;
}

async function batchSignature(id: TestAgentIdentity, events: TestEvent[]): Promise<string> {
  const { signCanonical } = await import("../src/audit/identity.js");
  return signCanonical(
    {
      v: 1,
      algo: "ed25519",
      publicKey: id.publicKey,
      privateKey: id.privateKey,
      fingerprint: id.fingerprint,
      createdAt: new Date().toISOString(),
    },
    JSON.stringify(events),
  );
}

interface TestCtx {
  home: string;
  cloud: RunningCloud;
  base: string;
  posts: { url: string; text: string }[];
}

async function api(
  ctx: TestCtx,
  path: string,
  opts: { method?: string; token?: string | null; body?: unknown; headers?: Record<string, string> } = {},
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<{ status: number; json: any }> {
  const res = await fetch(ctx.base + path, {
    method: opts.method ?? "GET",
    headers: {
      ...(opts.token !== null ? { authorization: `Bearer ${opts.token ?? ADMIN}` } : {}),
      ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
      ...(opts.headers ?? {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const json = await res.json();
  return { status: res.status, json };
}

/** Create a team and enroll an agent (with pubkey) against a running cloud. */
async function setupTeamAndAgent(
  ctx: TestCtx,
  agentId: string,
): Promise<{ teamId: string; enrollToken: string; identity: TestAgentIdentity; agentSecret: string }> {
  const team = await api(ctx, "/v1/admin/teams", { method: "POST", body: { name: "nexgen" } });
  expect(team.status).toBe(201);
  const identity = await makeAgentIdentity(agentId);
  const enroll = await api(ctx, "/v1/enroll", {
    method: "POST",
    token: null,
    body: {
      agentId,
      enrollToken: (team.json as { enrollToken: string }).enrollToken,
      pubkeyFingerprint: identity.fingerprint,
      pubkey: identity.publicKey,
    },
  });
  expect(enroll.status).toBe(200);
  const e = enroll.json as { agentSecret: string; teamId: string; cloudPubkey: string };
  return {
    teamId: e.teamId,
    enrollToken: (team.json as { enrollToken: string }).enrollToken,
    identity,
    agentSecret: e.agentSecret,
  };
}

/* ------------------------------------------------------------------ */
/* suite                                                               */
/* ------------------------------------------------------------------ */

describe("cloud server (EPIC-10)", () => {
  let home: string;
  let ctx: TestCtx;
  let poster: AlertPoster;

  beforeEach(async () => {
    home = useTempHome();
    const posts: { url: string; text: string }[] = [];
    poster = async (url, text) => {
      posts.push({ url, text });
    };
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    const cloud = await startCloudServer({
      port: 0,
      home: path.join(home, "cloud"),
      adminToken: ADMIN,
      announce: false,
      alertPoster: poster,
    });
    ctx = { home, cloud, base: `http://127.0.0.1:${cloud.port}`, posts };
  });

  afterEach(async () => {
    await ctx.cloud.close();
    cleanupTempHome(home);
  });

  it("announces the frozen stdout lines (contract with CLOUD-SYNC)", async () => {
    await ctx.cloud.close();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const { startCloudServer } = await import("../src/cloud/server/index.js");
      const cloud2 = await startCloudServer({
        port: 0,
        home: path.join(home, "cloud2"),
        adminToken: ADMIN,
        announce: true,
      });
      const lines = logSpy.mock.calls.map((c) => String(c[0]));
      expect(lines).toContain(`SCOPEGATE_CLOUD_LISTENING port=${cloud2.port}`);
      expect(lines.some((l) => l.startsWith("SCOPEGATE_CLOUD_FINGERPRINT sha256:"))).toBe(true);
      await cloud2.close();
    } finally {
      logSpy.mockRestore();
    }
    // restart the per-test server so afterEach cleanup has something to close
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    ctx.cloud = await startCloudServer({
      port: 0,
      home: path.join(home, "cloud"),
      adminToken: ADMIN,
      announce: false,
    });
    ctx.base = `http://127.0.0.1:${ctx.cloud.port}`;
  });

  it("generates the cloud identity keep-first with a printable fingerprint", async () => {
    const idFile = path.join(home, "cloud", "cloud-identity.json");
    expect(fs.existsSync(idFile)).toBe(true);
    const id = JSON.parse(fs.readFileSync(idFile, "utf8"));
    expect(id.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    // keep-first: a second server over the same home loads the same identity
    const { loadOrCreateCloudIdentity } = await import("../src/cloud/server/keys.js");
    const again = loadOrCreateCloudIdentity(path.join(home, "cloud"));
    expect(again.fingerprint).toBe(id.fingerprint);
  });

  it("enrolls an agent and rejects a bad enrollToken", async () => {
    const team = await api(ctx, "/v1/admin/teams", { method: "POST", body: { name: "nexgen" } });
    expect(team.status).toBe(201);
    const { teamId, enrollToken } = team.json as { teamId: string; enrollToken: string };
    expect(teamId).toMatch(/^team-/);
    expect(enrollToken.length).toBeGreaterThan(16);

    const id = await makeAgentIdentity("agent-1");
    const bad = await api(ctx, "/v1/enroll", {
      method: "POST",
      token: null,
      body: { agentId: "agent-1", enrollToken: "wrong", pubkeyFingerprint: id.fingerprint },
    });
    expect(bad.status).toBe(401);

    const ok = await api(ctx, "/v1/enroll", {
      method: "POST",
      token: null,
      body: {
        agentId: "agent-1",
        enrollToken,
        pubkeyFingerprint: id.fingerprint,
        pubkey: id.publicKey,
      },
    });
    expect(ok.status).toBe(200);
    const body = ok.json as { agentSecret: string; teamId: string; cloudPubkey: string };
    expect(body.agentSecret.length).toBeGreaterThan(20);
    expect(body.teamId).toBe(teamId);
    expect(body.cloudPubkey).toContain("BEGIN PUBLIC KEY");

    // fingerprint mismatch with the provided pubkey is rejected
    const other = await makeAgentIdentity("agent-2");
    const mismatch = await api(ctx, "/v1/enroll", {
      method: "POST",
      token: null,
      body: {
        agentId: "agent-2",
        enrollToken,
        pubkeyFingerprint: id.fingerprint, // belongs to another key
        pubkey: other.publicKey,
      },
    });
    expect(mismatch.status).toBe(400);
  });

  it("signs team policies and serves them verifiably versioned", async () => {
    const { teamId, enrollToken, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const yaml = "version: 1\nrules:\n  - match: github:*\n    allow: true\n";

    // policy pull requires auth
    expect((await api(ctx, `/v1/policy?teamId=${teamId}`, { token: null })).status).toBe(401);

    // 404 before the first publish (gateway stays local-first)
    const none = await api(ctx, `/v1/policy?teamId=${teamId}`, { token: enrollToken });
    expect(none.status).toBe(404);

    const put1 = await api(ctx, "/v1/admin/policy", {
      method: "PUT",
      body: { teamId, yaml },
    });
    expect(put1.status).toBe(200);
    const p1 = put1.json as { version: number; signature: string; signedAt: string };
    expect(p1.version).toBe(1);
    expect(p1.signature).toMatch(/^ed25519:/);

    const get = await api(ctx, `/v1/policy?teamId=${teamId}`, { token: enrollToken });
    expect(get.status).toBe(200);
    const policy = get.json as {
      teamId: string; version: number; yaml: string; signature: string; signedAt: string;
    };
    const { verifyPolicySignature } = await import("../src/cloud/server/policies.js");
    expect(verifyPolicySignature(ctx.cloud.cloudIdentity.publicKey, policy)).toBe(true);
    // tampering breaks verification
    expect(
      verifyPolicySignature(ctx.cloud.cloudIdentity.publicKey, { ...policy, yaml: yaml + "# evil" }),
    ).toBe(false);
    // agent-scope pull with the agentSecret also works
    const { agentSecret } = await api(ctx, "/v1/enroll", {
      method: "POST",
      token: null,
      body: {
        agentId: identity.agentId,
        enrollToken,
        pubkeyFingerprint: identity.fingerprint,
        pubkey: identity.publicKey,
      },
    }).then((r) => r.json as { agentSecret: string });
    expect((await api(ctx, `/v1/policy?teamId=${teamId}`, { token: agentSecret })).status).toBe(200);

    // second publish increments the version
    const put2 = await api(ctx, "/v1/admin/policy", {
      method: "PUT",
      body: { teamId, yaml: yaml + "  - match: slack:*\n    allow: false\n" },
    });
    expect((put2.json as { version: number }).version).toBe(2);
  });

  it("refuses to sign a policy that embeds a raw secret", async () => {
    const { teamId } = await setupTeamAndAgent(ctx, "agent-1");
    const evil = await api(ctx, "/v1/admin/policy", {
      method: "PUT",
      body: { teamId, yaml: `rules: []\n# token: ghp_${"a".repeat(36)}` },
    });
    expect(evil.status).toBe(400);
    // a long glob-y policy is NOT a false positive
    const fine = await api(ctx, "/v1/admin/policy", {
      method: "PUT",
      body: {
        teamId,
        yaml: `rules:\n  - match: "github:repo:read:myorg/my-monorepo/packages/backend-services/**"\n    allow: true\n`,
      },
    });
    expect(fine.status).toBe(200);
  });

  it("ingests a properly signed batch and updates lastSeen", async () => {
    const { teamId, agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const events = await makeChain(identity, 3);
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST",
      token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(identity, events) },
    });
    expect(res.status).toBe(200);
    const r = res.json as { accepted: number; rejected: number; duplicates: number };
    expect(r).toMatchObject({ accepted: 3, rejected: 0, duplicates: 0 });

    const agents = await api(ctx, `/v1/admin/agents?teamId=${teamId}`);
    const a = (agents.json as { agents: { agentId: string; lastSeen: string | null }[] }).agents[0];
    expect(a.lastSeen).not.toBeNull();

    const stored = await api(ctx, `/v1/admin/audit?teamId=${teamId}`);
    expect((stored.json as { events: unknown[] }).events.length).toBe(3);
  });

  it("rejects a batch with an invalid batch signature (wholesale)", async () => {
    const { agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const events = await makeChain(identity, 2);
    const stranger = await makeAgentIdentity("stranger");
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST",
      token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(stranger, events) },
    });
    const r = res.json as { accepted: number; rejected: number; rejections: { reason: string }[] };
    expect(r.accepted).toBe(0);
    expect(r.rejected).toBe(2);
    expect(r.rejections[0].reason).toBe("batch_signature_invalid");
  });

  it("rejects a tampered event per-event and keeps the valid ones", async () => {
    const { teamId, agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const events = await makeChain(identity, 3);
    // tamper with the middle event AFTER signing: detail changed, hash stale
    events[1] = { ...events[1], detail: { tool: "evil__exfil" } };
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST",
      token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(identity, events) },
    });
    const r = res.json as {
      accepted: number; rejected: number; rejections: { index: number; reason: string }[];
    };
    // event 1 fails hash_mismatch; event 2's chain link points at the received
    // (tampered) hash so it still verifies — the gateway DID chain it that way.
    expect(r.rejected).toBe(1);
    expect(r.rejections[0]).toMatchObject({ index: 1, reason: "hash_mismatch" });
    expect(r.accepted).toBe(2);

    const stored = await api(ctx, `/v1/admin/audit?teamId=${teamId}`);
    const kinds = (stored.json as { events: { detail: { tool: string } }[] }).events.map(
      (e) => e.detail.tool,
    );
    expect(kinds).not.toContain("evil__exfil");
  });

  it("applies the looksLikeSecret guard: secret payloads rejected, never stored", async () => {
    const { teamId, agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const clean = await makeChain(identity, 1, { detail: { tool: "github__get_issue" } });
    const dirty = await makeChain(identity, 1, {
      startSeq: 2,
      prev: clean[0].hash,
      detail: { tool: "http__post", note: `password=ghp_${"x".repeat(36)}` },
    });
    const events = [...clean, ...dirty];
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST",
      token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(identity, events) },
    });
    const r = res.json as { accepted: number; rejected: number; rejections: { reason: string }[] };
    expect(r.accepted).toBe(1);
    expect(r.rejected).toBe(1);
    expect(r.rejections[0].reason).toMatch(/^secret_like_payload/);

    const stored = await api(ctx, `/v1/admin/audit?teamId=${teamId}`);
    expect((stored.json as { events: unknown[] }).events.length).toBe(1);
  });

  it("deduplicates resends by agentId+seq (at-least-once safe)", async () => {
    const { agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const events = await makeChain(identity, 2);
    const sig = await batchSignature(identity, events);
    const first = await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events, signature: sig },
    });
    expect((first.json as { accepted: number }).accepted).toBe(2);
    const second = await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events, signature: sig },
    });
    expect(second.json as { accepted: number; duplicates: number }).toMatchObject({
      accepted: 0,
      duplicates: 2,
    });
  });

  it("flags a cross-batch chain gap without rejecting the batch", async () => {
    const { agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const first = await makeChain(identity, 2);
    await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events: first, signature: await batchSignature(identity, first) },
    });
    // a batch that does NOT continue the stored tail (as if an export was lost)
    const orphan = await makeChain(identity, 1, { startSeq: 9, prev: "0".repeat(64) });
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events: orphan, signature: await batchSignature(identity, orphan) },
    });
    const r = res.json as { accepted: number; chainGap?: boolean };
    expect(r.accepted).toBe(1);
    expect(r.chainGap).toBe(true);
  });

  it("rejects ingest for an agent enrolled without a pubkey (fail-closed)", async () => {
    const team = await api(ctx, "/v1/admin/teams", { method: "POST", body: { name: "nexgen" } });
    const { enrollToken } = team.json as { enrollToken: string };
    const id = await makeAgentIdentity("agent-1");
    const enroll = await api(ctx, "/v1/enroll", {
      method: "POST", token: null,
      body: { agentId: "agent-1", enrollToken, pubkeyFingerprint: id.fingerprint }, // no pubkey
    });
    expect(enroll.status).toBe(200);
    const { agentSecret } = enroll.json as { agentSecret: string };
    const events = await makeChain(id, 1);
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(id, events) },
    });
    const r = res.json as { accepted: number; rejections: { reason: string }[] };
    expect(r.accepted).toBe(0);
    expect(r.rejections[0].reason).toBe("agent_pubkey_not_enrolled");
  });

  it("revokes an agent with mandatory reason and serves the feed with since filter", async () => {
    const { teamId, enrollToken } = await setupTeamAndAgent(ctx, "agent-1");
    // reason is mandatory
    const noReason = await api(ctx, "/v1/admin/revocations", {
      method: "POST", body: { teamId, agentId: "agent-1" },
    });
    expect(noReason.status).toBe(400);

    const before = new Date(Date.now() - 1000).toISOString();
    const rev = await api(ctx, "/v1/admin/revocations", {
      method: "POST",
      body: { teamId, agentId: "agent-1", reason: "laptop compromised" },
    });
    expect(rev.status).toBe(201);

    const agents = await api(ctx, `/v1/admin/agents?teamId=${teamId}`);
    expect(
      (agents.json as { agents: { revoked: boolean }[] }).agents[0].revoked,
    ).toBe(true);

    const feed = await api(ctx, `/v1/revocations?teamId=${teamId}&since=${encodeURIComponent(before)}`, {
      token: enrollToken,
    });
    const revs = (feed.json as { revocations: { agentId: string; reason: string; ts: string }[] }).revocations;
    expect(revs.length).toBe(1);
    expect(revs[0]).toMatchObject({ agentId: "agent-1", reason: "laptop compromised" });

    const future = await api(
      ctx,
      `/v1/revocations?teamId=${teamId}&since=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`,
      { token: enrollToken },
    );
    expect((future.json as { revocations: unknown[] }).revocations.length).toBe(0);
  });

  it("meters billing by active agent per calendar month", async () => {
    const a1 = await setupTeamAndAgent(ctx, "agent-1");
    // second agent in the same team
    const id2 = await makeAgentIdentity("agent-2");
    const enroll2 = await api(ctx, "/v1/enroll", {
      method: "POST", token: null,
      body: {
        agentId: "agent-2",
        enrollToken: a1.enrollToken,
        pubkeyFingerprint: id2.fingerprint,
        pubkey: id2.publicKey,
      },
    });
    const secret2 = (enroll2.json as { agentSecret: string }).agentSecret;

    // agent-1 active now
    const e1 = await makeChain(a1.identity, 1);
    await api(ctx, "/v1/audit/batch", {
      method: "POST", token: a1.agentSecret,
      body: { agentId: "agent-1", events: e1, signature: await batchSignature(a1.identity, e1) },
    });
    // agent-2 active in a past month only
    const old = await makeChain(id2, 1, { ts: "2024-03-15T10:00:00.000Z" });
    await api(ctx, "/v1/audit/batch", {
      method: "POST", token: secret2,
      body: { agentId: "agent-2", events: old, signature: await batchSignature(id2, old) },
    });

    const now = await api(ctx, `/v1/billing/usage?teamId=${a1.teamId}`, { token: a1.enrollToken });
    const u = now.json as { activeAgents: number; period: string; agents: string[] };
    expect(u.activeAgents).toBe(1);
    expect(u.agents).toEqual(["agent-1"]);

    const march = await api(ctx, `/v1/billing/usage?teamId=${a1.teamId}&month=2024-03`, {
      token: a1.enrollToken,
    });
    const um = march.json as { activeAgents: number; agents: string[]; period: string };
    expect(um).toMatchObject({ activeAgents: 1, period: "2024-03", agents: ["agent-2"] });

    const empty = await api(ctx, `/v1/billing/usage?teamId=${a1.teamId}&month=2020-01`, {
      token: a1.enrollToken,
    });
    expect((empty.json as { activeAgents: number }).activeAgents).toBe(0);
  });

  it("fires a Slack alert for approval_requested with the resolve command (fail-silent)", async () => {
    const { teamId, agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    const hook = await api(ctx, "/v1/admin/alerts", {
      method: "POST",
      body: { teamId, webhookUrl: "https://hooks.slack.example/services/T/B/xxx" },
    });
    expect(hook.status).toBe(200);

    const events = await makeChain(identity, 1, {
      kind: "approval_requested",
      detail: { id: "apr-123", capability: "github:repo:delete", reason: "needs prod access" },
    });
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(identity, events) },
    });
    expect((res.json as { accepted: number }).accepted).toBe(1);

    expect(ctx.posts.length).toBe(1);
    expect(ctx.posts[0].url).toBe("https://hooks.slack.example/services/T/B/xxx");
    expect(ctx.posts[0].text).toContain("scopegate approve apr-123");
    expect(ctx.posts[0].text).toContain("github:repo:delete");
    expect(ctx.posts[0].text).toContain("agent-1");
  });

  it("swallows alert delivery failures (fire-and-forget)", async () => {
    await ctx.cloud.close();
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    const failing: AlertPoster = async () => {
      throw new Error("slack is down");
    };
    ctx.cloud = await startCloudServer({
      port: 0,
      home: path.join(home, "cloud3"),
      adminToken: ADMIN,
      announce: false,
      alertPoster: failing,
    });
    ctx.base = `http://127.0.0.1:${ctx.cloud.port}`;

    const { teamId, agentSecret, identity } = await setupTeamAndAgent(ctx, "agent-1");
    await api(ctx, "/v1/admin/alerts", {
      method: "POST", body: { teamId, webhookUrl: "https://hooks.slack.example/x" },
    });
    const events = await makeChain(identity, 1, {
      kind: "approval_requested",
      detail: { id: "apr-1", capability: "x", reason: "y" },
    });
    const res = await api(ctx, "/v1/audit/batch", {
      method: "POST", token: agentSecret,
      body: { agentId: "agent-1", events, signature: await batchSignature(identity, events) },
    });
    expect(res.status).toBe(200);
    expect((res.json as { accepted: number }).accepted).toBe(1);
    // let the swallowed rejection settle — no unhandled rejection, no crash
    await new Promise((resolve) => setImmediate(resolve));
  });

  it("enforces auth scopes: 401 anonymous, 403 cross-scope, SSO header works", async () => {
    const { teamId, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    // anonymous admin → 401
    expect((await api(ctx, "/v1/admin/agents?teamId=" + teamId, { token: null })).status).toBe(401);
    // agent credential against an admin route → 403
    expect(
      (await api(ctx, "/v1/admin/agents?teamId=" + teamId, { token: agentSecret })).status,
    ).toBe(403);
    // second team: agent from team A cannot read team B
    const teamB = await api(ctx, "/v1/admin/teams", { method: "POST", body: { name: "other" } });
    const teamBId = (teamB.json as { teamId: string }).teamId;
    expect(
      (await api(ctx, `/v1/revocations?teamId=${teamBId}`, { token: agentSecret })).status,
    ).toBe(403);
    // SSO dev adapter: X-Admin-Token header authenticates as admin
    const viaSso = await api(ctx, "/v1/admin/agents?teamId=" + teamId, {
      token: null,
      headers: { "x-admin-token": ADMIN },
    });
    expect(viaSso.status).toBe(200);
  });

  it("serves the dashboard assets (vanilla, same-origin)", async () => {
    const index = await fetch(ctx.base + "/");
    expect(index.status).toBe(200);
    expect(index.headers.get("content-type")).toContain("text/html");
    const html = await index.text();
    expect(html).toContain("ScopeGate Cloud");
    expect(html).toContain("/app.js");

    const js = await fetch(ctx.base + "/app.js");
    expect(js.status).toBe(200);
    const jsText = await js.text();
    expect(jsText).toContain("/v1/admin/teams");
  });

  it("keeps looksLikeSecret in sync with the gateway original", async () => {
    const { looksLikeSecret: cloudGuard } = await import("../src/cloud/server/guard.js");
    const { looksLikeSecret: gatewayGuard } = await import("../src/gateway/server.js");
    const samples = [
      "vault-ref",
      "github-pat",
      "x".repeat(39),
      "x".repeat(41),
      `sk-${"a".repeat(48)}`,
      `ghp_${"b".repeat(36)}`,
      `xoxb-${"1".repeat(10)}-${"2".repeat(10)}`,
      `AKIA${"Z".repeat(16)}`,
      `AIza${"c".repeat(35)}`,
      `eyJ${"d".repeat(20)}.${"e".repeat(20)}`,
      "a]b@c.d/e f g",
      "SG." + "f".repeat(40),
      "",
      "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ];
    for (const s of samples) {
      expect(cloudGuard(s), `parity on ${JSON.stringify(s)}`).toBe(gatewayGuard(s));
    }
  });
});
