/**
 * EPIC-06 — QM keychain grants over ScopeGate capabilities (BL-047..BL-052).
 *
 * Covered here (acceptance criteria §5 of the epic):
 *   (a) a `once` grant authorizes EXACTLY ONE call; the second is denied "used";
 *   (b) N concurrent authorizeCall over the same once grant → exactly one winner
 *       (in-process CAS: check+set is synchronous in the single-writer store);
 *   (c) a grant with `audience: "otro-agente"` never covers the requester;
 *   (d) revoking a promoted grant cascades to the org child (recursively);
 *   (e) a grants.json WITHOUT the QM fields loads and authorizes exactly as
 *       before (zero migration: standing + self-audience + active);
 *   (+) purpose is recorded everywhere but NEVER enforced, admin issue/promote
 *       is admin-gated with hard limits re-evaluated, and the signed audit
 *       trail verifies end-to-end after a full lifecycle.
 *
 * Store/engine level tests use the throwaway SCOPEGATE_HOME (helpers.ts);
 * tool-level tests boot the in-process fake gateway (testkit).
 */
import fs from "node:fs";
import path from "node:path";
import type { IncomingMessage } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { PolicyEngine as PolicyEngineT } from "../src/policy/engine.js";
import type { AdminContext } from "../src/gateway/admin.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

const POLICIES = {
  version: 1 as const,
  limits: { deny: ["aws:admin:*"], max_ttl: "1h" },
  agents: {
    "agent-a": {
      capabilities: [
        { match: "huly:call:*", auto_approve: true, ttl: "30m" },
        { match: "vault:read:*", require: "human_approval", ttl: "10m" },
      ],
    },
    "agent-b": {
      capabilities: [{ match: "huly:call:*", auto_approve: true, ttl: "30m" }],
    },
  },
};

type Engine = InstanceType<typeof PolicyEngineT>;

async function freshEngine(policies: unknown = POLICIES): Promise<Engine> {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(policies as never);
}

async function auditKinds(): Promise<string[]> {
  const { readAuditEvents } = await import("../src/audit/verify.js");
  return readAuditEvents().map((e) => e.kind);
}

/* ------------------------------------------------------------------------ */
/* (e) Zero migration: a pre-EPIC-06 grants.json works byte-for-byte          */
/* ------------------------------------------------------------------------ */

describe("compat: grants.json v1 sin campos QM (migración cero)", () => {
  it("loads and authorizes exactly as standing + self-audience + active", async () => {
    const { GRANTS_PATH } = await import("../src/policy/grants.js");
    fs.mkdirSync(path.dirname(GRANTS_PATH), { recursive: true });
    const legacy = {
      id: "g-legacy",
      agentId: "agent-a",
      capability: "huly:call:*",
      grantedAt: Date.now(),
      expiresAt: Date.now() + 600_000,
      rule: "huly:call:*",
    };
    fs.writeFileSync(GRANTS_PATH, JSON.stringify({ version: 1, grants: [legacy] }));

    const engine = await freshEngine();
    // Authorized exactly as before: self covered, others not, no claim semantics.
    expect(engine.isGranted("agent-a", "huly:call:create_issue")).toBe(true);
    expect(engine.isGranted("agent-b", "huly:call:create_issue")).toBe(false);
    const authz = engine.authorizeCall("agent-a", "huly:call:create_issue");
    expect("grant" in authz).toBe(true);
    // Standing: repeated calls keep working (no once consumption).
    expect("grant" in engine.authorizeCall("agent-a", "huly:call:create_issue")).toBe(true);
    // No QM fields materialized out of thin air.
    const grants = JSON.parse(fs.readFileSync(GRANTS_PATH, "utf8")) as {
      grants: Record<string, unknown>[];
    };
    expect(grants.grants[0]).not.toHaveProperty("mode");
    expect(grants.grants[0]).not.toHaveProperty("audience");
    expect(grants.grants[0]).not.toHaveProperty("status");
  });
});

/* ------------------------------------------------------------------------ */
/* (a) + (b): once — atomic claim, exactly-one under concurrency              */
/* ------------------------------------------------------------------------ */

describe("grant once: claim atómico CAS", () => {
  it("(a) authorizes exactly ONE call; the second is denied 'used' with usedBy recorded", async () => {
    const engine = await freshEngine();
    const d = engine.request("agent-a", "huly:call:create_issue", "10m", "one shot", {
      mode: "once",
    });
    expect(d.allow).toBe(true);

    const first = engine.authorizeCall("agent-a", "huly:call:create_issue");
    expect("grant" in first).toBe(true);
    if ("grant" in first) {
      expect(first.grant.status).toBe("used");
      expect(first.grant.usedBy).toBe("agent-a");
      expect(first.grant.usedAt).toBeTypeOf("number");
    }

    const second = engine.authorizeCall("agent-a", "huly:call:create_issue");
    expect(second).toEqual({ denied: "used" });

    // The claim landed in the signed audit trail with the purpose.
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const claimed = readAuditEvents().find((e) => e.kind === "grant_claimed");
    expect(claimed).toBeTruthy();
    expect(claimed?.detail.capability).toBe("huly:call:create_issue");
  });

  it("(b) N concurrent claims over the same once grant → EXACTLY one winner", async () => {
    const engine = await freshEngine();
    // An org-wide once grant (admin-born) so the race is between DIFFERENT
    // agents — the harshest case for the CAS.
    engine.adminIssueGrant("human:console:test", {
      audience: "org",
      capability: "huly:call:close_issue",
      mode: "once",
      purpose: "cerrar la incidencia una sola vez",
    });

    // Fire 16 "simultaneous" authorizations. check+set is synchronous inside
    // the single-writer store, so no interleaving can split them: exactly one
    // winner, everyone else sees "used".
    const racers = ["agent-a", "agent-b"];
    const outcomes = await Promise.all(
      Array.from({ length: 16 }, (_, i) =>
        Promise.resolve().then(() =>
          engine.authorizeCall(racers[i % racers.length], "huly:call:close_issue"),
        ),
      ),
    );
    const winners = outcomes.filter((o) => "grant" in o);
    const losers = outcomes.filter((o) => "denied" in o && o.denied === "used");
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(15);
  });

  it("a consumed org once grant answers 'used' to every later caller", async () => {
    const engine = await freshEngine();
    engine.adminIssueGrant("human:console:test", {
      audience: "org",
      capability: "huly:call:merge",
      mode: "once",
      purpose: "merge único",
    });
    expect("grant" in engine.authorizeCall("agent-a", "huly:call:merge")).toBe(true);
    expect(engine.authorizeCall("agent-b", "huly:call:merge")).toEqual({ denied: "used" });
    expect(engine.authorizeCall("agent-a", "huly:call:merge")).toEqual({ denied: "used" });
  });

  it("claim = use: no refund, and expiry of a used tombstone is NOT re-audited", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:x", "10m", "t", { mode: "once" });
    expect("grant" in engine.authorizeCall("agent-a", "huly:call:x")).toBe(true);
    // Force expiry of everything, then purge — tombstones expire silently.
    const store = (engine as never as { grants: import("../src/policy/grants.js").GrantStore }).grants;
    for (const g of store.all()) {
      g.expiresAt = Date.now() - 1;
    }
    engine.activeGrants("agent-a"); // triggers purgeAndAudit
    const kinds = await auditKinds();
    expect(kinds).toContain("grant_claimed");
    expect(kinds).not.toContain("grant_expired");
  });
});

/* ------------------------------------------------------------------------ */
/* (c): audience — the requester is never covered by an alien grant           */
/* ------------------------------------------------------------------------ */

describe("audience (QM keychain grantee)", () => {
  it("(c) a grant with audience 'agent-b' does NOT cover the requester, and covers agent-b", async () => {
    const engine = await freshEngine();
    // agent-a asks for a grant usable by agent-b → always escalates.
    const d = engine.request("agent-a", "huly:call:create_issue", "10m", "para el hilo B", {
      audience: "agent-b",
    });
    expect(d.allow).toBe(false);
    if (!d.allow) {
      expect(d.escalation).toBe("human_approval");
      expect(d.reason).toContain("agent-b");
    }

    // The human approves → the grant materializes with the audience.
    const { resolveApproval } = await import("../src/policy/approvals.js");
    resolveApproval(d.allow ? "" : (d.approvalId ?? ""), "approved", "human:test");
    const again = engine.request("agent-a", "huly:call:create_issue", "10m", "para el hilo B", {
      audience: "agent-b",
    });
    expect(again.allow).toBe(true); // idempotent re-request (owned)

    // The requester is NOT covered (denied "audience", not a silent re-grant).
    expect(engine.authorizeCall("agent-a", "huly:call:create_issue")).toEqual({
      denied: "audience",
    });
    // The audience IS covered.
    expect("grant" in engine.authorizeCall("agent-b", "huly:call:create_issue")).toBe(true);
  });

  it("audience ≠ self NEVER auto-approves — even with a matching auto_approve rule", async () => {
    const engine = await freshEngine();
    const d = engine.request("agent-a", "huly:call:x", undefined, "t", {
      audience: "agent-b",
    });
    expect(d.allow).toBe(false);
    if (!d.allow) expect(d.escalation).toBe("human_approval");
    // And no grant was issued behind the scenes.
    expect(engine.activeGrants("agent-a")).toHaveLength(0);
  });

  it("audience 'org' cannot be requested by an agent; unknown audiences are denied", async () => {
    const engine = await freshEngine();
    const org = engine.request("agent-a", "huly:call:x", undefined, "t", { audience: "org" });
    expect(org).toMatchObject({ allow: false, code: "audience_denied" });
    const ghost = engine.request("agent-a", "huly:call:x", undefined, "t", {
      audience: "agent-ghost",
    });
    expect(ghost).toMatchObject({ allow: false, code: "audience_denied" });
    if (!ghost.allow) expect(ghost.reason).toContain("not a declared agent identity");
  });

  it("audience fields survive the approval queue (additive contract)", async () => {
    const engine = await freshEngine();
    const d = engine.request("agent-a", "huly:call:x", "5m", "handoff", {
      audience: "agent-b",
      mode: "once",
      purpose: "resolver el ticket del canal",
    });
    expect(d.allow).toBe(false);
    const { readPendingRequests } = await import("../src/policy/approvals.js");
    const pending = readPendingRequests().find((r) => (!d.allow ? r.id === d.approvalId : false));
    expect(pending).toMatchObject({
      agentId: "agent-a",
      audience: "agent-b",
      mode: "once",
      purpose: "resolver el ticket del canal",
    });
  });

  it("hard limits still beat an audience request (deny globs are non-negotiable)", async () => {
    const engine = await freshEngine();
    const d = engine.request("agent-a", "aws:admin:nuke", undefined, "t", {
      audience: "agent-b",
    });
    expect(d).toMatchObject({ allow: false, code: "ceiling_blocked" });
  });
});

/* ------------------------------------------------------------------------ */
/* (d): recursive cascade + promote                                           */
/* ------------------------------------------------------------------------ */

describe("cascada recursiva y promoción admin-gated", () => {
  it("(d) revoking the parent tombstones the WHOLE chain: delegates, their children, promotions", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:*", "30m", "parent");
    const parent = engine.activeGrants("agent-a")[0];

    // Delegate A→B, then B→C (nested chain), and promote the parent to org.
    const childB = engine.delegate("agent-a", {
      grant_id: parent.id,
      child_agent_id: "agent-b",
      scope_subset: "huly:call:create_issue",
    });
    const childC = engine.delegate("agent-b", {
      grant_id: childB.grantId,
      child_agent_id: "agent-c",
      scope_subset: "huly:call:create_issue",
    });
    const promoted = engine.promoteGrant("human:console:test", parent.id, "incidencias soporte");

    const revoked = engine.revokeCascade(parent.id, { via: "test" });
    expect(revoked.count).toBe(4); // parent + B + C + org child
    expect(revoked.chain.map((c) => c.id).sort()).toEqual(
      [parent.id, childB.grantId, childC.grantId, promoted.child.id].sort(),
    );

    // Every descendant is a tombstone: authorization answers "revoked".
    expect(engine.authorizeCall("agent-b", "huly:call:create_issue")).toEqual({
      denied: "revoked",
    });
    expect(engine.authorizeCall("agent-a", "huly:call:create_issue")).toEqual({
      denied: "revoked",
    });

    // The audit carries the chain: count, cascade size and the grant ids.
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const evt = readAuditEvents().find((e) => e.kind === "grants_revoked");
    expect(evt?.detail).toMatchObject({ grantId: parent.id, count: 4, cascade: 3 });
    expect((evt?.detail.chain as string[]).sort()).toEqual(revoked.chain.map((c) => c.id).sort());
  });

  it("promote creates an org child; a second declared agent is covered by it", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:create_issue", "30m", "original");
    const parent = engine.activeGrants("agent-a")[0];
    const { child } = engine.promoteGrant("human:console:test", parent.id, "incidencias soporte");

    expect(child.audience).toBe("org");
    expect(child.parentGrantId).toBe(parent.id);
    expect(child.agentId).toBe("agent-a"); // attribution stays with the holder
    expect(child.expiresAt).toBeLessThanOrEqual(parent.expiresAt);

    // The other declared agent is covered; an UNDECLARED identity gets the
    // honest "audience" denial (the org grant exists but does not cover it).
    const authz = engine.authorizeCall("agent-b", "huly:call:create_issue");
    expect("grant" in authz).toBe(true);
    if ("grant" in authz) expect(authz.grant.id).toBe(child.id);
    expect(engine.authorizeCall("agent-ghost", "huly:call:create_issue")).toEqual({
      denied: "audience",
    });

    const kinds = await auditKinds();
    expect(kinds).toContain("grant_promoted");
  });

  it("promote requires purpose and a live parent", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:x", "30m", "t");
    const parent = engine.activeGrants("agent-a")[0];
    expect(() => engine.promoteGrant("human:console:test", parent.id, "  ")).toThrow(/purpose/);
    expect(() => engine.promoteGrant("human:console:test", "g-nope", "p")).toThrow(/No live grant/);
  });

  it("cross-agent consumption respects the CALLER's deny globs (fail-closed)", async () => {
    const strict = {
      version: 1 as const,
      agents: {
        "agent-a": { capabilities: [{ match: "huly:call:*", auto_approve: true }] },
        "agent-b": {
          limits: { deny: ["huly:call:danger*"] },
          capabilities: [{ match: "huly:call:*", auto_approve: true }],
        },
      },
    };
    const engine = await freshEngine(strict);
    engine.adminIssueGrant("human:console:test", {
      audience: "org",
      capability: "huly:call:*",
      purpose: "todo el equipo",
    });
    // agent-a consumes fine; agent-b's OWN deny glob blocks the dangerous one.
    expect("grant" in engine.authorizeCall("agent-a", "huly:call:danger-op")).toBe(true);
    expect(engine.authorizeCall("agent-b", "huly:call:danger-op")).toEqual({
      denied: "hard_limit",
    });
    expect("grant" in engine.authorizeCall("agent-b", "huly:call:safe")).toBe(true);
  });

  it("revokeOwnGrant is owner-only (attenuation self-service)", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:x", "30m", "t");
    const grant = engine.activeGrants("agent-a")[0];
    expect(() => engine.revokeOwnGrant("agent-b", grant.id)).toThrow(/only revoke its own/);
    const out = engine.revokeOwnGrant("agent-a", grant.id);
    expect(out.count).toBe(1);
    expect(engine.authorizeCall("agent-a", "huly:call:x")).toEqual({ denied: "revoked" });
  });
});

/* ------------------------------------------------------------------------ */
/* purpose: present everywhere, enforced nowhere                              */
/* ------------------------------------------------------------------------ */

describe("purpose: declarativo, NO enforceable (honestidad QM)", () => {
  it("rides the grant + audit + list view, and NO gate ever evaluates it", async () => {
    const engine = await freshEngine();
    const d = engine.request("agent-a", "huly:call:create_issue", "10m", "reason line", {
      purpose: "solo para el canal #soporte",
    });
    expect(d.allow).toBe(true);
    const grant = engine.activeGrants("agent-a")[0];
    expect(grant.purpose).toBe("solo para el canal #soporte");

    // A call utterly unrelated to the declared purpose is STILL authorized —
    // purpose is instruction + audit, never a control. That is the QM honesty
    // contract, pinned by this test.
    const authz = engine.authorizeCall("agent-a", "huly:call:create_issue", {
      channel: "completamente-otro",
    });
    expect("grant" in authz).toBe(true);

    // Present in grant_issued detail and in the list view.
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const issued = readAuditEvents().find((e) => e.kind === "grant_issued");
    expect(issued?.detail.purpose).toBe("solo para el canal #soporte");
    expect(engine.usableGrants("agent-a")[0].purpose).toBe("solo para el canal #soporte");
  });

  it("purpose defaults to the request reason when omitted", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:x", "10m", "just the reason");
    expect(engine.activeGrants("agent-a")[0].purpose).toBe("just the reason");
  });
});

/* ------------------------------------------------------------------------ */
/* Admin direct issue (engine level)                                          */
/* ------------------------------------------------------------------------ */

describe("adminIssueGrant: admin-gated, hard limits re-evaluated", () => {
  it("issues an org grant with mandatory purpose; rejects agent-less bodies and missing purpose", async () => {
    const engine = await freshEngine();
    const grant = engine.adminIssueGrant("human:console:acc-1", {
      audience: "org",
      capability: "huly:call:create_issue",
      ttl: "30m",
      purpose: "incidencias soporte",
    });
    expect(grant.audience).toBe("org");
    expect(grant.requestedBy).toBe("human:console:acc-1");
    expect(engine.authorizeCall("agent-b", "huly:call:create_issue")).toBeTruthy();

    expect(() =>
      engine.adminIssueGrant("human:console:acc-1", {
        audience: "org",
        capability: "huly:call:x",
        purpose: "",
      }),
    ).toThrow(/purpose is required/);
    expect(() =>
      engine.adminIssueGrant("human:console:acc-1", {
        capability: "huly:call:x",
        purpose: "p",
      }),
    ).toThrow(/agentId.*audience|required/);
  });

  it("hard limits bind the admin too: deny globs refuse, max_ttl clamps", async () => {
    const engine = await freshEngine();
    expect(() =>
      engine.adminIssueGrant("human:console:acc-1", {
        audience: "org",
        capability: "aws:admin:nuke",
        purpose: "p",
      }),
    ).toThrow(/hard limit/);
    const grant = engine.adminIssueGrant("human:console:acc-1", {
      agentId: "agent-a",
      capability: "huly:call:x",
      ttl: "4h",
      purpose: "p",
    });
    // max_ttl (1h) clamped the 4h ask.
    expect(grant.expiresAt - grant.grantedAt).toBe(3_600_000);
  });

  it("unknown audience/holder identities are refused fail-closed", async () => {
    const engine = await freshEngine();
    expect(() =>
      engine.adminIssueGrant("human:console:acc-1", {
        agentId: "agent-ghost",
        capability: "huly:call:x",
        purpose: "p",
      }),
    ).toThrow(/not a declared identity/);
    expect(() =>
      engine.adminIssueGrant("human:console:acc-1", {
        agentId: "agent-a",
        audience: "agent-ghost",
        capability: "huly:call:x",
        purpose: "p",
      }),
    ).toThrow(/not a declared agent identity/);
  });

  it("listGrants filters by holder / effective audience / mode", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:a", "10m", "t");
    engine.adminIssueGrant("human:console:test", {
      audience: "org",
      capability: "huly:call:b",
      mode: "once",
      purpose: "p",
    });
    expect(engine.listGrants()).toHaveLength(2);
    expect(engine.listGrants({ agent: "agent-a" })).toHaveLength(1);
    expect(engine.listGrants({ audience: "org" })).toHaveLength(1);
    expect(engine.listGrants({ audience: "agent-a" })).toHaveLength(1); // self-audience
    expect(engine.listGrants({ mode: "once" })).toHaveLength(1);
    expect(engine.listGrants({ mode: "standing" })).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------------ */
/* /admin/grants* routes (admin surface, separate credential)                 */
/* ------------------------------------------------------------------------ */

const ADMIN_TOKEN = "admin-bearer-yyyyyyyy";
const AGENT_TOKEN = "agent-bearer-xxxxxxxx";
const ADMIN_AUTH = { adminToken: ADMIN_TOKEN, agentToken: AGENT_TOKEN };

function adminReq(opts: {
  method?: string;
  url?: string;
  token?: string;
  actor?: string;
}): IncomingMessage {
  return {
    method: opts.method ?? "GET",
    url: opts.url ?? "/admin/grants",
    headers: {
      ...(opts.token !== undefined ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.actor !== undefined ? { "x-scopegate-actor": opts.actor } : {}),
    },
  } as unknown as IncomingMessage;
}

function adminCtx(engine: Engine): AdminContext {
  return {
    vault: {
      listRefs: () => [],
      get: () => "",
      has: () => false,
      set: () => {},
      delete: () => false,
    } as never,
    capabilities: () => ({ active_grants: [], leases: [] }),
    revokeCapability: () => true,
    listGrants: (f) => engine.listGrants(f),
    issueGrant: (actor, input) => engine.adminIssueGrant(actor, input),
    promoteGrant: (actor, id, purpose) => engine.promoteGrant(actor, id, purpose),
    revokeGrantCascade: (id, actor) => {
      const r = engine.revokeCascade(id, { via: "console", author: actor });
      return r.count > 0 ? r : null;
    },
    upstreamNames: () => [],
    agents: () => [],
    upstreamsUsingSecret: () => [],
    reload: async () => {},
  };
}

describe("/admin/grants* (superficie admin)", () => {
  it("the AGENT bearer is refused (403) — admin is a separate credential", async () => {
    const { routeAdmin } = await import("../src/gateway/admin.js");
    const engine = await freshEngine();
    const out = await routeAdmin(
      adminReq({ method: "POST", url: "/admin/grants", token: AGENT_TOKEN, actor: "acc-1" }),
      {} as never,
      { audience: "org", capability: "huly:call:x", purpose: "p" },
      adminCtx(engine),
      ADMIN_AUTH,
    );
    expect(out?.status).toBe(403);
    expect(JSON.stringify(out?.body)).toContain("approve itself");
  });

  it("mutations without X-ScopeGate-Actor are 400 (every change is attributed)", async () => {
    const { routeAdmin } = await import("../src/gateway/admin.js");
    const engine = await freshEngine();
    const out = await routeAdmin(
      adminReq({ method: "POST", url: "/admin/grants", token: ADMIN_TOKEN }),
      {} as never,
      { audience: "org", capability: "huly:call:x", purpose: "p" },
      adminCtx(engine),
      ADMIN_AUTH,
    );
    expect(out?.status).toBe(400);
  });

  it("issue → list → promote → revoke with cascade, all attributed", async () => {
    const { routeAdmin } = await import("../src/gateway/admin.js");
    const engine = await freshEngine();
    const ctx = adminCtx(engine);
    const res = {} as never;

    // Issue an org grant.
    const issued = await routeAdmin(
      adminReq({ method: "POST", url: "/admin/grants", token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      { audience: "org", capability: "huly:call:create_issue", purpose: "incidencias soporte", ttl: "30m" },
      ctx,
      ADMIN_AUTH,
    );
    expect(issued?.status).toBe(200);
    const grant = (issued?.body as { id: string }).id;
    expect(issued?.body).toMatchObject({ audience: "org", purpose: "incidencias soporte" });

    // It appears in the filtered listing.
    const listed = await routeAdmin(
      adminReq({ url: "/admin/grants?audience=org", token: ADMIN_TOKEN }),
      res,
      null,
      ctx,
      ADMIN_AUTH,
    );
    expect((listed?.body as { grants: unknown[] }).grants).toHaveLength(1);

    // An agent's own grant, promoted to org (child of the original).
    engine.request("agent-a", "huly:call:close_issue", "30m", "original");
    const parent = engine.activeGrants("agent-a")[0];
    const promoted = await routeAdmin(
      adminReq({
        method: "POST",
        url: `/admin/grants/${parent.id}/promote`,
        token: ADMIN_TOKEN,
        actor: "acc-1",
      }),
      res,
      { purpose: "cierres para todo el equipo" },
      ctx,
      ADMIN_AUTH,
    );
    expect(promoted?.status).toBe(200);
    const child = (promoted?.body as { child: { id: string; audience: string } }).child;
    expect(child.audience).toBe("org");

    // Revoking the original cascades to the promoted child (count 2).
    const del = await routeAdmin(
      adminReq({ method: "DELETE", url: `/admin/grants/${parent.id}`, token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      null,
      ctx,
      ADMIN_AUTH,
    );
    expect(del?.status).toBe(200);
    expect(del?.body).toMatchObject({ id: parent.id, revoked: 2 });

    // The promotion left grant_promoted in the signed trail, attributed.
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const events = readAuditEvents();
    const promo = events.find((e) => e.kind === "grant_promoted");
    expect(promo?.detail).toMatchObject({ parent: parent.id, actor: "human:console:acc-1" });
    const revoked = events.find((e) => e.kind === "grants_revoked" && e.detail.via === "console");
    expect(revoked?.detail).toMatchObject({ grantId: parent.id, count: 2, cascade: 1 });
  });

  it("hard limits refuse an admin issue (422) and promote without purpose is 422", async () => {
    const { routeAdmin } = await import("../src/gateway/admin.js");
    const engine = await freshEngine();
    const ctx = adminCtx(engine);
    const blocked = await routeAdmin(
      adminReq({ method: "POST", url: "/admin/grants", token: ADMIN_TOKEN, actor: "acc-1" }),
      {} as never,
      { audience: "org", capability: "aws:admin:nuke", purpose: "p" },
      ctx,
      ADMIN_AUTH,
    );
    expect(blocked?.status).toBe(422);
    expect(JSON.stringify(blocked?.body)).toContain("hard limit");

    engine.request("agent-a", "huly:call:x", "30m", "t");
    const parent = engine.activeGrants("agent-a")[0];
    const noPurpose = await routeAdmin(
      adminReq({ method: "POST", url: `/admin/grants/${parent.id}/promote`, token: ADMIN_TOKEN, actor: "acc-1" }),
      {} as never,
      {},
      ctx,
      ADMIN_AUTH,
    );
    expect(noPurpose?.status).toBe(422);
    const notFound = await routeAdmin(
      adminReq({ method: "POST", url: "/admin/grants/g-nope/promote", token: ADMIN_TOKEN, actor: "acc-1" }),
      {} as never,
      { purpose: "p" },
      ctx,
      ADMIN_AUTH,
    );
    expect(notFound?.status).toBe(404);
  });
});

/* ------------------------------------------------------------------------ */
/* Signed audit: full lifecycle verifies end-to-end                           */
/* ------------------------------------------------------------------------ */

describe("audit firmado: ciclo de vida completo verificable", () => {
  it("issue → claim → promote → revoke → `audit verify` stays green", async () => {
    const engine = await freshEngine();
    engine.request("agent-a", "huly:call:create_issue", "30m", "t", { mode: "once" });
    expect("grant" in engine.authorizeCall("agent-a", "huly:call:create_issue")).toBe(true);
    engine.adminIssueGrant("human:console:acc-1", {
      audience: "org",
      capability: "huly:call:close_issue",
      purpose: "cierres equipo",
    });
    const parent = engine.listGrants({ audience: "org" })[0];
    engine.promoteGrant("human:console:acc-1", parent.id, "promoción");
    engine.revokeCascade(parent.id, { via: "console", author: "human:console:acc-1" });

    const { verifyAuditLog } = await import("../src/audit/verify.js");
    const result = verifyAuditLog();
    expect(result.ok).toBe(true);
    if (result.ok) {
      const kinds = result.events.map((e) => e.kind);
      expect(kinds).toContain("grant_issued");
      expect(kinds).toContain("grant_claimed");
      expect(kinds).toContain("grant_promoted");
      expect(kinds).toContain("grants_revoked");
    }
  });
});

/* ------------------------------------------------------------------------ */
/* Tool level (MCP over the in-process fake gateway)                          */
/* ------------------------------------------------------------------------ */

describe("tools scopegate_* (MCP end-to-end)", () => {
  it("request mode:'once' → first call ok → second call denied grant_used → audit verify green", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway();
    try {
      const reqRes = await handle.client.callTool({
        name: "scopegate_request_capability",
        arguments: {
          capability: "fakegit:call:whoami",
          reason: "single shot",
          mode: "once",
          purpose: "identificarme una vez",
        },
      });
      expect(reqRes.isError).not.toBe(true);
      const granted = JSON.parse((reqRes.content as { text: string }[])[0].text);
      expect(granted).toMatchObject({ granted: true, mode: "once", purpose: "identificarme una vez" });

      // The purpose is visible (declarative) in the list view.
      const listRes = await handle.client.callTool({ name: "scopegate_list_capabilities", arguments: {} });
      const list = JSON.parse((listRes.content as { text: string }[])[0].text);
      expect(list.active_grants[0]).toMatchObject({
        mode: "once",
        purpose: "identificarme una vez",
        status: "active",
      });

      const first = await handle.client.callTool({ name: "fakegit__whoami", arguments: {} });
      expect(first.isError).not.toBe(true);

      const second = await handle.client.callTool({ name: "fakegit__whoami", arguments: {} });
      expect(second.isError).toBe(true);
      expect((second.content as { text: string }[])[0].text).toContain("grant_used");

      // The consumed tombstone shows in the list (status + used_by).
      const list2Res = await handle.client.callTool({ name: "scopegate_list_capabilities", arguments: {} });
      const list2 = JSON.parse((list2Res.content as { text: string }[])[0].text);
      expect(list2.active_grants[0]).toMatchObject({ status: "used", used_by: "testkit-agent" });

      const { verifyAuditLog } = await import("../src/audit/verify.js");
      expect(verifyAuditLog().ok).toBe(true);
    } finally {
      await handle.close();
    }
  }, 30_000);

  it("scopegate_revoke_capability: self-service revocation is sticky (explicit re-request required)", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway();
    try {
      await handle.client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:whoami", reason: "t" },
      });
      const listRes = await handle.client.callTool({ name: "scopegate_list_capabilities", arguments: {} });
      const grantId = JSON.parse((listRes.content as { text: string }[])[0].text).active_grants[0].id;

      const revokeRes = await handle.client.callTool({
        name: "scopegate_revoke_capability",
        arguments: { grant_id: grantId },
      });
      expect(revokeRes.isError).not.toBe(true);
      expect(JSON.parse((revokeRes.content as { text: string }[])[0].text)).toMatchObject({
        revoked: true,
        grant_id: grantId,
        cascade_revoked: 0,
      });

      // Sticky: the implicit auto-approve path does NOT silently resurrect it.
      const call = await handle.client.callTool({ name: "fakegit__whoami", arguments: {} });
      expect(call.isError).toBe(true);
      expect((call.content as { text: string }[])[0].text).toContain("grant_revoked");

      // An explicit re-request is the governed way back.
      const again = await handle.client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:whoami", reason: "explicit again" },
      });
      expect(JSON.parse((again.content as { text: string }[])[0].text).granted).toBe(true);
      const revived = await handle.client.callTool({ name: "fakegit__whoami", arguments: {} });
      expect(revived.isError).not.toBe(true);
    } finally {
      await handle.close();
    }
  }, 30_000);

  it("request with audience ≠ self always escalates and carries the audience; agent cannot ask for org", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway({
      extraCapabilities: [{ match: "fakegit:write:*", auto_approve: true, ttl: "15m" }],
    });
    try {
      const res = await handle.client.callTool({
        name: "scopegate_request_capability",
        arguments: {
          capability: "fakegit:write:repo",
          reason: "handoff al subagente",
          audience: "otro-agente",
          purpose: "que complete el push",
        },
      });
      const body = JSON.parse((res.content as { text: string }[])[0].text);
      // 'otro-agente' is not declared on this single-agent gateway → denied.
      expect(body).toMatchObject({ granted: false, code: "audience_denied" });

      const org = await handle.client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:write:repo", reason: "t", audience: "org" },
      });
      expect(JSON.parse((org.content as { text: string }[])[0].text)).toMatchObject({
        granted: false,
        code: "audience_denied",
      });
    } finally {
      await handle.close();
    }
  }, 30_000);

  it("the new tool is listed and request_capability exposes the keychain params", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway();
    try {
      const { tools } = await handle.client.listTools();
      const names = tools.map((t) => t.name);
      expect(names).toContain("scopegate_revoke_capability");
      const req = tools.find((t) => t.name === "scopegate_request_capability");
      const props = Object.keys(
        (req?.inputSchema as { properties?: Record<string, unknown> }).properties ?? {},
      );
      expect(props).toEqual(expect.arrayContaining(["mode", "audience", "purpose"]));
    } finally {
      await handle.close();
    }
  }, 30_000);
});
