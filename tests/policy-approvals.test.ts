/**
 * EPIC-04 H-04.3 unit tests: the local human-approval queue and its
 * consumption by the policy engine (pending → decision → one-shot grant).
 */
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
  limits: { max_ttl: "30m" },
  agents: {
    "test-agent": {
      default_ttl: "15m",
      capabilities: [
        { match: "github:write:*", require: "human_approval" as const, ttl: "10m" },
        { match: "github:call:*", auto_approve: true, ttl: "10m" },
      ],
    },
  },
};

async function freshEngine() {
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return new PolicyEngine(POLICIES);
}

async function auditEntries(): Promise<Array<{ kind: string; detail: Record<string, unknown> }>> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  if (!fs.existsSync(AUDIT_LOG_PATH)) return [];
  return fs
    .readFileSync(AUDIT_LOG_PATH, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

describe("approval queue API (contract for the EPIC-08 CLI)", () => {
  it("createApprovalRequest appends the contract line and dedups open requests", async () => {
    const { createApprovalRequest, APPROVALS_PENDING_PATH } = await import(
      "../src/policy/approvals.js"
    );
    const { request, created } = createApprovalRequest({
      agentId: "agent-a",
      capability: "github:write:repo",
      ttl: "5m",
      reason: "push a fix",
    });
    expect(created).toBe(true);
    expect(request.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(request.expiresAt - request.requestedAt).toBe(10 * 60_000); // default 10m

    const line = JSON.parse(
      fs.readFileSync(APPROVALS_PENDING_PATH, "utf8").trim().split("\n")[0],
    );
    expect(line).toMatchObject({
      id: request.id,
      agentId: "agent-a",
      capability: "github:write:repo",
      ttl: "5m",
      reason: "push a fix",
    });
    expect(typeof line.requestedAt).toBe("number");
    expect(typeof line.expiresAt).toBe("number");

    // Same (agent, capability) while open → deduped, no new line.
    const again = createApprovalRequest({ agentId: "agent-a", capability: "github:write:repo" });
    expect(again.created).toBe(false);
    expect(again.request.id).toBe(request.id);
    expect(
      fs.readFileSync(APPROVALS_PENDING_PATH, "utf8").trim().split("\n").filter(Boolean),
    ).toHaveLength(1);
  });

  it("resolveApproval appends a decision, is idempotent, and rejects unknown ids", async () => {
    const { createApprovalRequest, resolveApproval, checkDecision } = await import(
      "../src/policy/approvals.js"
    );
    const { request } = createApprovalRequest({ agentId: "agent-a", capability: "x:y:z" });

    const dec = resolveApproval(request.id, "approved", "human:test");
    expect(dec.decision).toBe("approved");
    expect(dec.decidedBy).toBe("human:test");
    // Idempotent: a second resolve returns the original decision.
    const again = resolveApproval(request.id, "denied", "human:test");
    expect(again.decision).toBe("approved");
    expect(again.decidedAt).toBe(dec.decidedAt);
    // Fresh read (what the gateway sees on its next mtime check).
    expect(checkDecision(request.id)?.decision).toBe("approved");
    expect(() => resolveApproval("00000000-0000-0000-0000-000000000000", "approved")).toThrow(
      /Unknown approval id/,
    );
  });

  it("checkDecision sees decisions written 'by another process' (fresh by mtime)", async () => {
    const { createApprovalRequest, checkDecision, APPROVALS_DECISIONS_PATH } = await import(
      "../src/policy/approvals.js"
    );
    const { request } = createApprovalRequest({ agentId: "agent-a", capability: "x:y:z" });
    expect(checkDecision(request.id)).toBeNull();
    // Simulate the CLI (another process) appending a decision directly.
    fs.appendFileSync(
      APPROVALS_DECISIONS_PATH,
      JSON.stringify({ id: request.id, decision: "denied", decidedAt: Date.now(), decidedBy: "human:cli" }) + "\n",
      { mode: 0o600 },
    );
    expect(checkDecision(request.id)?.decision).toBe("denied");
  });
});

describe("engine approval flow (require: human_approval)", () => {
  it("request → pending → approved → one-shot grant with clamped TTL, audited end-to-end", async () => {
    const e = await freshEngine();
    const { resolveApproval, readPendingRequests } = await import("../src/policy/approvals.js");

    // 1. request escalates with a pending approval id
    const d1 = e.request("test-agent", "github:write:repo", "5m", "push fix");
    expect(d1.allow).toBe(false);
    if (d1.allow) throw new Error("unreachable");
    expect(d1.escalation).toBe("human_approval");
    expect(d1.approvalId).toBeTruthy();

    // 2. human approves (as the CLI would)
    resolveApproval(d1.approvalId!, "approved", "human:test");

    // 3. next request materializes the one-shot grant: min(requested 5m, rule 10m, max 30m)
    const d2 = e.request("test-agent", "github:write:repo", "5m", "push fix");
    expect(d2.allow).toBe(true);
    if (d2.allow) expect(d2.ttlMs).toBeLessThanOrEqual(5 * 60_000 + 500);
    const grants = e.activeGrants("test-agent");
    expect(grants).toHaveLength(1);
    expect(grants[0].approvalId).toBe(d1.approvalId);
    expect(grants[0].expiresAt - grants[0].grantedAt).toBe(5 * 60_000);

    // 4. the pending line is marked resolved → the approval is consumed ONCE
    const pending = readPendingRequests();
    expect(pending.find((r) => r.id === d1.approvalId)?.status).toBe("approved");

    // 5. polling again returns the existing grant, NOT a second materialization
    const d3 = e.request("test-agent", "github:write:repo", "5m", "push fix");
    expect(d3.allow).toBe(true);
    expect(e.activeGrants("test-agent")).toHaveLength(1);

    const entries = await auditEntries();
    const approvedEvents = entries.filter(
      (x) => x.kind === "approval_approved" && x.detail.id === d1.approvalId,
    );
    expect(approvedEvents).toHaveLength(1); // consumed exactly once
    expect(entries.map((x) => x.kind)).toContain("approval_requested");
    expect(entries.map((x) => x.kind)).toContain("grant_issued");
  });

  it("a denied decision is audited and the next request escalates with a NEW pending id", async () => {
    const e = await freshEngine();
    const { resolveApproval } = await import("../src/policy/approvals.js");

    const d1 = e.request("test-agent", "github:write:repo", "5m", "push fix");
    if (d1.allow) throw new Error("unreachable");
    resolveApproval(d1.approvalId!, "denied", "human:test");

    const d2 = e.request("test-agent", "github:write:repo", "5m", "push fix");
    expect(d2.allow).toBe(false);
    if (!d2.allow) {
      expect(d2.escalation).toBe("human_approval");
      expect(d2.approvalId).not.toBe(d1.approvalId); // fresh request, human may reconsider
    }
    const entries = await auditEntries();
    const denied = entries.filter((x) => x.kind === "approval_denied" && x.detail.id === d1.approvalId);
    expect(denied).toHaveLength(1);
  });

  it("an expired pending request is audited as approval_expired exactly once", async () => {
    const e = await freshEngine();
    const { APPROVALS_PENDING_PATH, readPendingRequests } = await import(
      "../src/policy/approvals.js"
    );

    const d1 = e.request("test-agent", "github:write:repo", "5m", "push fix");
    if (d1.allow) throw new Error("unreachable");

    // Age the request beyond its expiry (as if 10 minutes had passed).
    const lines = readPendingRequests().map((r) => ({
      ...r,
      expiresAt: r.id === d1.approvalId ? Date.now() - 1 : r.expiresAt,
    }));
    fs.writeFileSync(
      APPROVALS_PENDING_PATH,
      lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
      { mode: 0o600 },
    );

    e.request("test-agent", "github:write:repo", "5m", "push fix"); // observes expiry
    e.request("test-agent", "github:call:other", "5m", "unrelated"); // must not re-audit

    const entries = await auditEntries();
    const expired = entries.filter(
      (x) => x.kind === "approval_expired" && x.detail.id === d1.approvalId,
    );
    expect(expired).toHaveLength(1);
    expect(readPendingRequests().find((r) => r.id === d1.approvalId)?.status).toBe("expired");
  });

  it("listApprovals reports effective states for the human reviewer", async () => {
    const { createApprovalRequest, resolveApproval, listApprovals } = await import(
      "../src/policy/approvals.js"
    );
    const a = createApprovalRequest({ agentId: "agent-a", capability: "x:1:1" }).request;
    const b = createApprovalRequest({ agentId: "agent-a", capability: "x:2:2" }).request;
    resolveApproval(b.id, "approved");
    const list = listApprovals();
    expect(list.find((r) => r.id === a.id)?.effectiveStatus).toBe("pending");
    expect(list.find((r) => r.id === b.id)?.effectiveStatus).toBe("approved");
  });
});
