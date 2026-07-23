/**
 * Panel backend endpoints — tests (PLAN-LANDING-PANEL F2).
 *
 * Covers the endpoints the product panel consumes:
 *   GET  /v1/admin/overview            (fleet/audit/security aggregation)
 *   GET  /v1/admin/approvals           (queue derived from central audit)
 *   POST /v1/admin/approvals/resolve   (panel decision; CLI-parity validation)
 *   GET  /v1/approvals/decisions       (gateway-facing feed, agent-scoped)
 *   GET  /v1/admin/capabilities        (active grants projection)
 *   GET  /v1/admin/policy/versions     (full signed history)
 *   GET  /v1/admin/audit/export        (NDJSON download)
 *
 * Isolation: fresh SCOPEGATE_HOME + fresh cloud home per test, ephemeral
 * port, injected AlertPoster — no network is ever touched.
 */
import crypto from "node:crypto";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { startCloudServer as startCloudServerT } from "../src/cloud/server/index.js";

type RunningCloud = Awaited<ReturnType<typeof startCloudServerT>>;
type AlertPoster = import("../src/cloud/server/alerts.js").AlertPoster;

const ADMIN = "test-admin-token";

/* ------------------------------------------------------------------ */
/* signed-event helpers (same construction as cloud-server.test.ts)    */
/* ------------------------------------------------------------------ */

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

interface EventSpec {
  kind: string;
  detail: Record<string, unknown>;
  ts?: string;
}

/** Build a properly chained+signed batch with per-event kind/detail. */
async function makeEvents(
  id: TestAgentIdentity,
  specs: EventSpec[],
  opts: { startSeq?: number; prev?: string } = {},
): Promise<TestEvent[]> {
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
  const events: TestEvent[] = [];
  let prev = opts.prev ?? "genesis";
  const startSeq = opts.startSeq ?? 1;
  for (let i = 0; i < specs.length; i++) {
    const partial = {
      ts: specs[i].ts ?? new Date().toISOString(),
      agentId: id.agentId,
      kind: specs[i].kind,
      detail: specs[i].detail,
      prev,
      seq: startSeq + i,
    };
    const sig = signCanonical(identity, canonicalUnsigned(partial as never));
    const signed = { ...partial, sig };
    const hash = crypto
      .createHash("sha256")
      .update(prev + canonicalSigned(signed as never))
      .digest("hex");
    events.push({ ...signed, hash });
    prev = hash;
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

/* ------------------------------------------------------------------ */
/* http helpers                                                        */
/* ------------------------------------------------------------------ */

interface TestCtx {
  home: string;
  cloud: RunningCloud;
  base: string;
}

async function api(
  ctx: TestCtx,
  path: string,
  opts: { method?: string; token?: string | null; body?: unknown } = {},
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<{ status: number; json: any }> {
  const res = await fetch(ctx.base + path, {
    method: opts.method ?? "GET",
    headers: {
      ...(opts.token !== null ? { authorization: `Bearer ${opts.token ?? ADMIN}` } : {}),
      ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const json = await res.json();
  return { status: res.status, json };
}

async function setupTeamAndAgent(
  ctx: TestCtx,
  agentId: string,
): Promise<{ teamId: string; identity: TestAgentIdentity; agentSecret: string }> {
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
  const e = enroll.json as { agentSecret: string; teamId: string };
  return { teamId: e.teamId, identity, agentSecret: e.agentSecret };
}

/** Ingest a batch of events for `id` and assert full acceptance. */
async function ingest(
  ctx: TestCtx,
  id: TestAgentIdentity,
  agentSecret: string,
  specs: EventSpec[],
  opts: { startSeq?: number; prev?: string } = {},
): Promise<TestEvent[]> {
  const events = await makeEvents(id, specs, opts);
  const signature = await batchSignature(id, events);
  const res = await api(ctx, "/v1/audit/batch", {
    method: "POST",
    token: agentSecret,
    body: { agentId: id.agentId, events, signature },
  });
  expect(res.status).toBe(200);
  expect(res.json.rejected).toBe(0);
  return events;
}

/* ------------------------------------------------------------------ */
/* suite                                                               */
/* ------------------------------------------------------------------ */

describe("panel backend endpoints (PLAN-LANDING-PANEL F2)", () => {
  let home: string;
  let ctx: TestCtx;

  beforeEach(async () => {
    home = useTempHome();
    const poster: AlertPoster = async () => {};
    const { startCloudServer } = await import("../src/cloud/server/index.js");
    const cloud = await startCloudServer({
      port: 0,
      home: path.join(home, "cloud"),
      adminToken: ADMIN,
      announce: false,
      alertPoster: poster,
    });
    ctx = { home, cloud, base: `http://127.0.0.1:${cloud.port}` };
  });

  afterEach(async () => {
    await ctx.cloud.close();
    cleanupTempHome(home);
  });

  /* ------------------------------ overview ------------------------- */

  it("overview aggregates fleet, audit, policy, approvals and security", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");

    // Empty team: zeros everywhere.
    const empty = await api(ctx, `/v1/admin/overview?teamId=${teamId}`);
    expect(empty.status).toBe(200);
    expect(empty.json.agents).toMatchObject({ total: 1, active: 1, revoked: 0, online: 0 });
    expect(empty.json.audit).toMatchObject({ total: 0, last24h: 0, lastEventAt: null });
    expect(empty.json.approvals.pending).toBe(0);
    expect(empty.json.policy).toBeNull();

    // Ingest a mixed batch: a grant, a denial, a honeytoken hit and an
    // approval request (pending).
    const in10m = new Date(Date.now() + 600_000).toISOString();
    await ingest(ctx, identity, agentSecret, [
      { kind: "grant_issued", detail: { id: "g1", capability: "github:read:x", ttlMs: 600_000, expiresAt: in10m, rule: "github:read:*" } },
      { kind: "capability_denied", detail: { capability: "aws:*:production", code: "no_rule" } },
      { kind: "honeytoken_triggered", detail: { ref: "canary_aws" } },
      { kind: "approval_requested", detail: { id: "apr-1", capability: "aws:deploy:production", ttl: "10m", reason: "deploy", expiresAt: in10m } },
    ]);

    const pub = await api(ctx, "/v1/admin/policy", {
      method: "PUT",
      body: { teamId, yaml: "agents: {}\n" },
    });
    expect(pub.status).toBe(200);

    const ov = await api(ctx, `/v1/admin/overview?teamId=${teamId}`);
    expect(ov.status).toBe(200);
    expect(ov.json.agents.total).toBe(1);
    expect(ov.json.agents.online).toBe(1); // lastSeen set by the ingest above
    expect(ov.json.audit.total).toBe(4);
    expect(ov.json.audit.last24h).toBe(4);
    expect(ov.json.approvals.pending).toBe(1);
    expect(ov.json.policy).toMatchObject({ version: 1 });
    expect(ov.json.security24h.capability_denied).toBe(1);
    expect(ov.json.security24h.honeytoken_triggered).toBe(1);
    expect(ov.json.recentSecurityEvents.length).toBe(2); // denied + honeytoken
    // Unknown team → 404; anonymous → 401.
    expect((await api(ctx, "/v1/admin/overview?teamId=team-nope")).status).toBe(404);
    expect((await api(ctx, `/v1/admin/overview?teamId=${teamId}`, { token: null })).status).toBe(401);
  });

  /* ------------------------------ approvals ------------------------ */

  it("approvals queue derives status from audit + panel decisions", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    const in10m = new Date(Date.now() + 600_000).toISOString();
    const ago1m = new Date(Date.now() - 60_000).toISOString();

    await ingest(ctx, identity, agentSecret, [
      { kind: "approval_requested", detail: { id: "apr-pend", capability: "aws:deploy:production", ttl: "10m", reason: "ship it", expiresAt: in10m } },
      { kind: "approval_requested", detail: { id: "apr-exp", capability: "db:write:prod", ttl: null, reason: null, expiresAt: ago1m } },
      { kind: "approval_requested", detail: { id: "apr-echo", capability: "github:write:main", ttl: "5m", reason: null, expiresAt: in10m } },
      { kind: "approval_approved", detail: { id: "apr-echo", capability: "github:write:main", decidedBy: "human:cli:tty" } },
    ]);

    const all = await api(ctx, `/v1/admin/approvals?teamId=${teamId}`);
    expect(all.status).toBe(200);
    const byId = Object.fromEntries(
      (all.json.approvals as { approvalId: string }[]).map((a) => [a.approvalId, a]),
    ) as Record<string, { status: string; decidedBy?: string; resolution: string }>;
    expect(byId["apr-pend"].status).toBe("pending");
    expect(byId["apr-exp"].status).toBe("expired");
    expect(byId["apr-echo"].status).toBe("approved");
    expect(byId["apr-echo"].decidedBy).toBe("human:cli:tty");
    expect(byId["apr-echo"].resolution).toBe("gateway");

    // Pending filter only returns the pending one, first in the list.
    const pend = await api(ctx, `/v1/admin/approvals?teamId=${teamId}&status=pending`);
    expect(pend.json.approvals.map((a: { approvalId: string }) => a.approvalId)).toEqual(["apr-pend"]);
    // Bad filter → 400; unknown team → 404.
    expect((await api(ctx, `/v1/admin/approvals?teamId=${teamId}&status=nope`)).status).toBe(400);
    expect((await api(ctx, "/v1/admin/approvals?teamId=team-nope")).status).toBe(404);
  });

  it("resolve issues a panel decision (idempotent, CLI-parity validation)", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    const in10m = new Date(Date.now() + 600_000).toISOString();
    const ago1m = new Date(Date.now() - 60_000).toISOString();
    await ingest(ctx, identity, agentSecret, [
      { kind: "approval_requested", detail: { id: "apr-1", capability: "aws:deploy:production", ttl: "10m", reason: "deploy", expiresAt: in10m } },
      { kind: "approval_requested", detail: { id: "apr-2", capability: "db:write:prod", ttl: "10m", reason: null, expiresAt: in10m } },
      { kind: "approval_requested", detail: { id: "apr-3", capability: "github:write:main", ttl: "5m", reason: null, expiresAt: ago1m } },
    ]);

    // Approve with a TTL shorten.
    const ok = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-1", decision: "approve", ttl: "5m" },
    });
    expect(ok.status).toBe(200);
    expect(ok.json.alreadyDecided).toBe(false);
    expect(ok.json.decision).toMatchObject({
      approvalId: "apr-1",
      agentId: "agent-1",
      decision: "approved",
      ttl: "5m",
      decidedBy: "human:cloud:panel",
    });

    // Idempotent re-resolve.
    const again = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-1", decision: "approve" },
    });
    expect(again.status).toBe(200);
    expect(again.json.alreadyDecided).toBe(true);

    // TTL extension is refused (shorten-only, like the CLI).
    const extend = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-2", decision: "approve", ttl: "30m" },
    });
    expect(extend.status).toBe(400);
    expect(String(extend.json.error)).toContain("SHORTEN");

    // Deny without reason → 400; with reason → 200.
    const noReason = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-2", decision: "deny" },
    });
    expect(noReason.status).toBe(400);
    const denied = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-2", decision: "deny", reason: "not today" },
    });
    expect(denied.status).toBe(200);
    expect(denied.json.decision.decision).toBe("denied");

    // Unknown id → 404; expired → 400; ttl on deny → 400.
    expect(
      (await api(ctx, "/v1/admin/approvals/resolve", {
        method: "POST",
        body: { teamId, approvalId: "apr-nope", decision: "approve" },
      })).status,
    ).toBe(404);
    const expired = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-3", decision: "approve" },
    });
    expect(expired.status).toBe(400);
    expect(expired.json.code).toBe("approval_expired");

    // Queue now reflects the panel decisions with resolution=cloud.
    const q = await api(ctx, `/v1/admin/approvals?teamId=${teamId}`);
    const byId = Object.fromEntries(
      (q.json.approvals as { approvalId: string }[]).map((a) => [a.approvalId, a]),
    ) as Record<string, { status: string; resolution: string }>;
    expect(byId["apr-1"]).toMatchObject({ status: "approved", resolution: "cloud" });
    expect(byId["apr-2"]).toMatchObject({ status: "denied", resolution: "cloud" });
  });

  it("refuses to re-decide a request already resolved at the gateway", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    const in10m = new Date(Date.now() + 600_000).toISOString();
    await ingest(ctx, identity, agentSecret, [
      { kind: "approval_requested", detail: { id: "apr-x", capability: "c", ttl: null, reason: null, expiresAt: in10m } },
      { kind: "approval_denied", detail: { id: "apr-x", capability: "c", decidedBy: "human:cli:tty" } },
    ]);
    const res = await api(ctx, "/v1/admin/approvals/resolve", {
      method: "POST",
      body: { teamId, approvalId: "apr-x", decision: "approve" },
    });
    expect(res.status).toBe(400);
    expect(res.json.code).toBe("already_decided");
  });

  it("decisions feed: agent sees only its own, team token sees all, anon 401", async () => {
    const a = await setupTeamAndAgent(ctx, "agent-1");
    const teamId = a.teamId;
    const b = await (async () => {
      const identity = await makeAgentIdentity("agent-2");
      const enroll = await api(ctx, "/v1/enroll", {
        method: "POST",
        token: null,
        body: {
          agentId: "agent-2",
          enrollToken: (await api(ctx, "/v1/admin/teams")).json.teams[0].enrollToken,
          pubkeyFingerprint: identity.fingerprint,
          pubkey: identity.publicKey,
        },
      });
      expect(enroll.status).toBe(200);
      return { identity, agentSecret: (enroll.json as { agentSecret: string }).agentSecret };
    })();

    const in10m = new Date(Date.now() + 600_000).toISOString();
    await ingest(ctx, a.identity, a.agentSecret, [
      { kind: "approval_requested", detail: { id: "apr-a", capability: "c", ttl: null, reason: null, expiresAt: in10m } },
    ]);
    await ingest(ctx, b.identity, b.agentSecret, [
      { kind: "approval_requested", detail: { id: "apr-b", capability: "c", ttl: null, reason: null, expiresAt: in10m } },
    ]);
    for (const id of ["apr-a", "apr-b"]) {
      const r = await api(ctx, "/v1/admin/approvals/resolve", {
        method: "POST",
        body: { teamId, approvalId: id, decision: "approve" },
      });
      expect(r.status).toBe(200);
    }

    // Agent-1 credential: only its own decision.
    const feedA = await api(ctx, `/v1/approvals/decisions?teamId=${teamId}`, { token: a.agentSecret });
    expect(feedA.status).toBe(200);
    expect(feedA.json.decisions.map((d: { approvalId: string }) => d.approvalId)).toEqual(["apr-a"]);

    // Team enroll token: the whole team's decisions.
    const teams = await api(ctx, "/v1/admin/teams");
    const enrollToken = (teams.json.teams as { enrollToken: string }[])[0].enrollToken;
    const feedTeam = await api(ctx, `/v1/approvals/decisions?teamId=${teamId}`, { token: enrollToken });
    expect(feedTeam.json.decisions.length).toBe(2);

    // since-cursor trims the feed.
    const ts = (feedTeam.json.decisions as { ts: string }[])[0].ts;
    const feedSince = await api(ctx, `/v1/approvals/decisions?teamId=${teamId}&since=${encodeURIComponent(ts)}`, { token: enrollToken });
    expect(feedSince.json.decisions.length).toBe(1);

    // Anonymous → 401; agent of the team against another team → 403.
    expect((await api(ctx, `/v1/approvals/decisions?teamId=${teamId}`, { token: null })).status).toBe(401);
    expect((await api(ctx, "/v1/approvals/decisions?teamId=team-nope", { token: a.agentSecret })).status).toBe(403);
  });

  /* ---------------------------- capabilities ----------------------- */

  it("capabilities lists active grants and purges expired/revoked ones", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    const now = Date.now();
    const in10m = new Date(now + 600_000).toISOString();
    const ago1m = new Date(now - 60_000).toISOString();

    await ingest(ctx, identity, agentSecret, [
      { kind: "grant_issued", detail: { id: "g-active", capability: "github:read:x", ttlMs: 600_000, expiresAt: in10m, rule: "github:read:*" } },
      { kind: "grant_issued", detail: { id: "g-expired", capability: "github:write:x", ttlMs: 1000, expiresAt: ago1m, rule: "github:write:*" } },
      { kind: "grant_issued", detail: { id: "g-approved", capability: "aws:deploy:production", ttlMs: 300_000, expiresAt: in10m, via: "human_approval", approvalId: "apr-1" } },
    ]);

    let caps = await api(ctx, `/v1/admin/capabilities?teamId=${teamId}`);
    expect(caps.status).toBe(200);
    expect(
      (caps.json.capabilities as { grantId: string }[]).map((c) => c.grantId).sort(),
    ).toEqual(["g-active", "g-approved"]);
    const approved = (caps.json.capabilities as { grantId: string; via: string | null; approvalId: string | null }[])
      .find((c) => c.grantId === "g-approved")!;
    expect(approved.via).toBe("human_approval");
    expect(approved.approvalId).toBe("apr-1");

    // Revoke the agent: the earlier grants are purged from the active view.
    const rev = await api(ctx, "/v1/admin/revocations", {
      method: "POST",
      body: { teamId, agentId: "agent-1", reason: "incident" },
    });
    expect(rev.status).toBe(201);
    caps = await api(ctx, `/v1/admin/capabilities?teamId=${teamId}`);
    expect(caps.json.capabilities).toEqual([]);

    // A grant issued AFTER the revocation is visible again (agent re-enabled).
    await ingest(
      ctx,
      identity,
      agentSecret,
      [{ kind: "grant_issued", detail: { id: "g-new", capability: "c", ttlMs: 600_000, expiresAt: new Date(Date.now() + 600_000).toISOString() } }],
      { startSeq: 4 },
    );
    caps = await api(ctx, `/v1/admin/capabilities?teamId=${teamId}`);
    expect((caps.json.capabilities as { grantId: string }[]).map((c) => c.grantId)).toEqual(["g-new"]);
  });

  /* --------------------------- policy versions --------------------- */

  it("policy versions returns the full signed history, ascending", async () => {
    const { teamId } = await setupTeamAndAgent(ctx, "agent-1");
    expect((await api(ctx, `/v1/admin/policy/versions?teamId=${teamId}`)).json.versions).toEqual([]);

    for (const yaml of ["agents: {}\n", "agents:\n  a: {}\n"]) {
      const r = await api(ctx, "/v1/admin/policy", { method: "PUT", body: { teamId, yaml } });
      expect(r.status).toBe(200);
    }
    const res = await api(ctx, `/v1/admin/policy/versions?teamId=${teamId}`);
    expect(res.status).toBe(200);
    expect(res.json.versions.map((v: { version: number }) => v.version)).toEqual([1, 2]);
    expect(res.json.versions[0].signature).toMatch(/^ed25519:/);
    expect(res.json.versions[1].yaml).toBe("agents:\n  a: {}\n");
    expect((await api(ctx, "/v1/admin/policy/versions?teamId=team-nope")).status).toBe(404);
  });

  /* ------------------------- team-wide revocation ------------------ */

  it("team-wide '*' revocation marks every agent and feeds the wildcard", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    // Second agent in the same team.
    const id2 = await makeAgentIdentity("agent-2");
    const enroll2 = await api(ctx, "/v1/enroll", {
      method: "POST",
      token: null,
      body: {
        agentId: "agent-2",
        enrollToken: (await api(ctx, "/v1/admin/teams")).json.teams[0].enrollToken,
        pubkeyFingerprint: id2.fingerprint,
        pubkey: id2.publicKey,
      },
    });
    expect(enroll2.status).toBe(200);

    const rev = await api(ctx, "/v1/admin/revocations", {
      method: "POST",
      body: { teamId, agentId: "*", reason: "team incident drill" },
    });
    expect(rev.status).toBe(201);
    expect(rev.json.agentId).toBe("*");

    // Every enrolled agent is marked revoked.
    const agents = await api(ctx, `/v1/admin/agents?teamId=${teamId}`);
    expect((agents.json.agents as { revoked: boolean }[]).every((a) => a.revoked)).toBe(true);

    // The feed carries the wildcard entry (what gateways poll).
    const feed = await api(ctx, `/v1/revocations?teamId=${teamId}`, { token: agentSecret });
    expect(feed.status).toBe(200);
    expect((feed.json.revocations as { agentId: string }[]).map((r) => r.agentId)).toContain("*");

    // Reason is still mandatory for the wildcard.
    expect(
      (await api(ctx, "/v1/admin/revocations", {
        method: "POST",
        body: { teamId, agentId: "*" },
      })).status,
    ).toBe(400);
  });

  /* ----------------------------- audit export ---------------------- */
  it("audit export downloads the signed NDJSON feed, chronological", async () => {
    const { teamId, identity, agentSecret } = await setupTeamAndAgent(ctx, "agent-1");
    await ingest(ctx, identity, agentSecret, [
      { kind: "tool_call", detail: { tool: "github__get_issue" } },
      { kind: "grant_issued", detail: { id: "g1", capability: "c", ttlMs: 1, expiresAt: new Date(Date.now() + 1000).toISOString() } },
    ]);

    const res = await fetch(ctx.base + `/v1/admin/audit/export?teamId=${teamId}`, {
      headers: { authorization: `Bearer ${ADMIN}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/x-ndjson");
    expect(res.headers.get("content-disposition")).toContain("attachment");
    const lines = (await res.text()).trim().split("\n");
    expect(lines.length).toBe(2);
    const parsed = lines.map((l) => JSON.parse(l) as { kind: string; seq: number; sig: string });
    expect(parsed.map((p) => p.seq)).toEqual([1, 2]);
    expect(parsed.every((p) => typeof p.sig === "string")).toBe(true);
  });
});
