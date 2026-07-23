/**
 * Approval-sync client tests (PLAN-LANDING-PANEL F3, gateway side).
 *
 * Covers the panel → gateway approval channel:
 *   - a panel approval lands in the local queue and the policy engine
 *     materializes the one-shot grant on the agent's next request (auditing
 *     exactly once, with decidedBy "human:cloud:panel");
 *   - a decision TTL is applied as a SHORTEN of the pending ask;
 *   - denials land and are audited (the sync itself never audits);
 *   - decisions for other agents / unknown ids are skipped, idempotently;
 *   - the since-cursor advances and transport errors throw (loop backoff).
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts); the cloud is a
 * fetchImpl stub — no network, no server.
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

const CFG = { url: "http://cloud.test", teamId: "team-1", agentSecret: "sec-test" };

const LOCAL = {
  version: 1 as const,
  agents: {
    "test-agent": {
      default_ttl: "30m",
      capabilities: [
        { match: "fakegit:call:danger", require: "human_approval" as const, ttl: "20m" },
      ],
    },
  },
};

function fetchWith(decisions: unknown[], ok = true, status = 200) {
  return (async () => ({
    ok,
    status,
    json: async () => ({ decisions }),
  })) as unknown as typeof fetch;
}

async function syncModule() {
  return import("../src/cloud/client/approval-sync.js");
}

async function approvalsModule() {
  return import("../src/policy/approvals.js");
}

function auditRaw(): string {
  const file = path.join(home, "audit.jsonl");
  return fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
}

describe("approval-sync", () => {
  it("a panel approval materializes the grant on the next request (audited once, panel origin)", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const engine = new PolicyEngine(LOCAL as never);

    // The agent asks for a guarded capability → escalation + pending request.
    const esc = engine.request("test-agent", "fakegit:call:danger", "20m", "need it") as {
      allow: boolean;
      escalation?: string;
      approvalId?: string;
    };
    expect(esc.allow).toBe(false);
    expect(esc.escalation).toBe("human_approval");
    const approvalId = esc.approvalId!;
    expect(typeof approvalId).toBe("string");

    // The panel approves; the sync tick applies it.
    const { syncApprovalsOnce } = await syncModule();
    const r = await syncApprovalsOnce(CFG, "test-agent", null, {
      fetchImpl: fetchWith([
        {
          approvalId,
          agentId: "test-agent",
          decision: "approved",
          decidedBy: "human:cloud:panel",
          ts: new Date().toISOString(),
        },
      ]),
    });
    expect(r.applied).toBe(1);
    expect(r.lastSeen).toBeTruthy();

    // The decision is recorded locally with the panel origin.
    const { checkDecision } = await approvalsModule();
    expect(checkDecision(approvalId)?.decidedBy).toBe("human:cloud:panel");

    // The agent's next request materializes the one-shot grant.
    const g = engine.request("test-agent", "fakegit:call:danger", "20m", "need it") as {
      allow: boolean;
      ttlMs?: number;
    };
    expect(g.allow).toBe(true);
    // The engine clamps the grant to the request's remaining lifetime, so
    // allow a few ms of slack under the nominal 20m.
    expect(g.ttlMs).toBeGreaterThan(20 * 60 * 1000 - 10_000);
    expect(g.ttlMs).toBeLessThanOrEqual(20 * 60 * 1000);

    // The ENGINE audited approval_approved + grant_issued exactly once each,
    // with the panel origin; the sync wrote NO audit events of its own.
    const raw = auditRaw();
    expect(raw.match(/"approval_approved"/g)?.length).toBe(1);
    expect(raw.match(/"grant_issued"/g)?.length).toBe(1);
    expect(raw).toContain("human:cloud:panel");
    expect(raw).toContain('"via":"human_approval"');

    // Idempotent: the same feed applied again records nothing new.
    const r2 = await syncApprovalsOnce(CFG, "test-agent", r.lastSeen, {
      fetchImpl: fetchWith([
        {
          approvalId,
          agentId: "test-agent",
          decision: "approved",
          decidedBy: "human:cloud:panel",
          ts: new Date().toISOString(),
        },
      ]),
    });
    expect(r2.applied).toBe(0);
  });

  it("applies the decision TTL as a SHORTEN of the pending ask", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const engine = new PolicyEngine(LOCAL as never);
    const esc = engine.request("test-agent", "fakegit:call:danger", "20m", "need it") as {
      approvalId?: string;
    };

    const { syncApprovalsOnce } = await syncModule();
    const r = await syncApprovalsOnce(CFG, "test-agent", null, {
      fetchImpl: fetchWith([
        {
          approvalId: esc.approvalId,
          agentId: "test-agent",
          decision: "approved",
          ttl: "5m",
          decidedBy: "human:cloud:panel",
          ts: new Date().toISOString(),
        },
      ]),
    });
    expect(r.applied).toBe(1);

    // The pending line was rewritten to the shortened TTL...
    const { listApprovals } = await approvalsModule();
    const req = listApprovals().find((a) => a.id === esc.approvalId);
    expect(req?.ttl).toBe("5m");

    // ...and the materialized grant honors it (not the 20m the agent asked).
    const g = engine.request("test-agent", "fakegit:call:danger", "20m", "need it") as {
      allow: boolean;
      ttlMs?: number;
    };
    expect(g.allow).toBe(true);
    // ~5m, not the 20m the agent asked (same remaining-lifetime clamp slack).
    expect(g.ttlMs).toBeGreaterThan(5 * 60 * 1000 - 10_000);
    expect(g.ttlMs).toBeLessThanOrEqual(5 * 60 * 1000);
  });

  it("a panel denial is consumed by the engine and audited with the panel origin", async () => {
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const engine = new PolicyEngine(LOCAL as never);
    const esc = engine.request("test-agent", "fakegit:call:danger", "20m", "need it") as {
      approvalId?: string;
    };

    const { syncApprovalsOnce } = await syncModule();
    const r = await syncApprovalsOnce(CFG, "test-agent", null, {
      fetchImpl: fetchWith([
        {
          approvalId: esc.approvalId,
          agentId: "test-agent",
          decision: "denied",
          reason: "not today",
          decidedBy: "human:cloud:panel",
          ts: new Date().toISOString(),
        },
      ]),
    });
    expect(r.applied).toBe(1);

    // The engine consumes the denial on the next evaluation (a re-request is
    // a fresh escalation by design) and audits approval_denied once.
    engine.request("test-agent", "fakegit:call:danger", "20m", "need it");
    const raw = auditRaw();
    expect(raw.match(/"approval_denied"/g)?.length).toBe(1);
    expect(raw).toContain("human:cloud:panel");
  });

  it("skips decisions for other agents and unknown ids; advances the cursor; HTTP errors throw", async () => {
    const { createApprovalRequest, checkDecision } = await approvalsModule();
    const { request } = createApprovalRequest({
      agentId: "test-agent",
      capability: "fakegit:call:danger",
      ttl: "20m",
    });

    const { syncApprovalsOnce } = await syncModule();
    const r = await syncApprovalsOnce(CFG, "test-agent", null, {
      fetchImpl: fetchWith([
        // another agent's decision — ignored
        {
          approvalId: request.id,
          agentId: "someone-else",
          decision: "approved",
          ts: "2026-01-01T00:00:01.000Z",
        },
        // unknown id — skipped
        {
          approvalId: "apr-unknown",
          agentId: "test-agent",
          decision: "approved",
          ts: "2026-01-01T00:00:02.000Z",
        },
      ]),
    });
    expect(r.applied).toBe(0);
    expect(r.lastSeen).toBe("2026-01-01T00:00:02.000Z"); // newest ts wins
    expect(checkDecision(request.id)).toBeNull();

    // Transport/HTTP failure → throws so the loop backs off (local-first).
    await expect(
      syncApprovalsOnce(CFG, "test-agent", null, {
        fetchImpl: fetchWith([], false, 503),
      }),
    ).rejects.toThrow("HTTP 503");
  });

  it("shortenApprovalRequestTtl rewrites the line atomically and preserves foreign lines", async () => {
    const { createApprovalRequest, shortenApprovalRequestTtl, listApprovals, APPROVALS_PENDING_PATH } =
      await approvalsModule();
    const { request } = createApprovalRequest({
      agentId: "test-agent",
      capability: "fakegit:call:danger",
      ttl: "20m",
    });
    // A corrupt line in the file must survive the rewrite byte-for-byte.
    fs.appendFileSync(APPROVALS_PENDING_PATH, "{not json\n");

    shortenApprovalRequestTtl(request.id, "5m");

    const raw = fs.readFileSync(APPROVALS_PENDING_PATH, "utf8");
    expect(raw).toContain("{not json\n");
    const req = listApprovals().find((a) => a.id === request.id);
    expect(req?.ttl).toBe("5m");
    expect(() => shortenApprovalRequestTtl("apr-nope", "5m")).toThrow(/nothing to shorten|not found/);
  });
});
