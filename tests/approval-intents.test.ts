/**
 * Approval continuation tests (mejora #2).
 *
 *   - queueIntent is idempotent per approval; args persist for execution,
 *     only their hash is auditable.
 *   - When the approval is decided "approved", the engine's materialization
 *     executes the intent through the injected executor and persists the
 *     outcome — scopegate_collect semantics (resultFor) reflect it.
 *   - Executed AND failed outcomes are stored with the intent flipped to the
 *     matching status; stale intents expire without executing.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

const LOCAL = {
  version: 1 as const,
  agents: {
    "test-agent": {
      capabilities: [
        { match: "fakegit:call:danger", require: "human_approval" as const, ttl: "20m" },
      ],
    },
  },
};

async function mods() {
  const approvals = await import("../src/policy/approvals.js");
  const { PolicyEngine } = await import("../src/policy/engine.js");
  return { approvals, PolicyEngine };
}

function escalate(engine: InstanceType<typeof import("../src/policy/engine.js").PolicyEngine>): string {
  const d = engine.request("test-agent", "fakegit:call:danger", "20m", "need it") as {
    escalation?: string;
    approvalId?: string;
  };
  expect(d.escalation).toBe("human_approval");
  return d.approvalId!;
}

describe("approval continuation", () => {
  it("queueIntent is idempotent per approval and keeps args for execution", async () => {
    const { approvals, PolicyEngine } = await mods();
    const engine = new PolicyEngine(LOCAL as never);
    const approvalId = escalate(engine);

    const a = approvals.queueIntent({
      approvalId,
      agentId: "test-agent",
      tool: "fakegit__danger",
      args: { x: 1 },
      expiresAt: Date.now() + 60_000,
    });
    const b = approvals.queueIntent({
      approvalId,
      agentId: "test-agent",
      tool: "fakegit__danger",
      args: { x: 1 },
      expiresAt: Date.now() + 60_000,
    });
    expect(b.id).toBe(a.id); // idempotent
    expect(approvals.pendingIntentFor(approvalId)?.args).toEqual({ x: 1 });
    expect(approvals.pendingIntentFor(approvalId)?.argsHash).toBe(approvals.hashArgs({ x: 1 }));
  });

  it("an approval executes the queued intent with the fresh grant; collect reads the outcome", async () => {
    const { approvals, PolicyEngine } = await mods();
    const engine = new PolicyEngine(LOCAL as never);
    const approvalId = escalate(engine);

    approvals.queueIntent({
      approvalId,
      agentId: "test-agent",
      tool: "fakegit__danger",
      args: { mode: "run" },
      expiresAt: Date.now() + 60_000,
    });

    // The gateway's executor hook (fake): records the call, returns a result.
    const calls: { tool: string; args: unknown }[] = [];
    engine.intentExecutor = async (intent) => {
      calls.push({ tool: intent.tool, args: intent.args });
      return { ok: true, result: { content: [{ type: "text", text: "done" }] } };
    };

    // The human approves (CLI path); the next request materializes + executes.
    approvals.resolveApproval(approvalId, "approved", "human:cli:tty");
    engine.request("test-agent", "fakegit:call:danger", "20m", "need it");
    // Execution is fire-and-forget — let it land.
    await new Promise((r) => setTimeout(r, 50));

    expect(calls).toEqual([{ tool: "fakegit__danger", args: { mode: "run" } }]);
    const result = approvals.resultFor(approvalId);
    expect(result?.status).toBe("executed");
    expect(result?.tool).toBe("fakegit__danger");
    expect(approvals.pendingIntentFor(approvalId)).toBeUndefined(); // no longer queued
    expect(approvals.latestIntentFor(approvalId)?.status).toBe("executed");
  });

  it("a failed execution is stored as failed with the error", async () => {
    const { approvals, PolicyEngine } = await mods();
    const engine = new PolicyEngine(LOCAL as never);
    const approvalId = escalate(engine);
    approvals.queueIntent({
      approvalId,
      agentId: "test-agent",
      tool: "fakegit__danger",
      args: {},
      expiresAt: Date.now() + 60_000,
    });
    engine.intentExecutor = async () => ({ ok: false, error: "upstream said no" });

    approvals.resolveApproval(approvalId, "approved", "human:cli:tty");
    engine.request("test-agent", "fakegit:call:danger", "20m", "need it");
    await new Promise((r) => setTimeout(r, 50));

    const result = approvals.resultFor(approvalId);
    expect(result?.status).toBe("failed");
    expect(result?.error).toBe("upstream said no");
    expect(approvals.latestIntentFor(approvalId)?.status).toBe("failed");
  });

  it("a DENIED approval never executes the intent", async () => {
    const { approvals, PolicyEngine } = await mods();
    const engine = new PolicyEngine(LOCAL as never);
    const approvalId = escalate(engine);
    approvals.queueIntent({
      approvalId,
      agentId: "test-agent",
      tool: "fakegit__danger",
      args: {},
      expiresAt: Date.now() + 60_000,
    });
    let executed = false;
    engine.intentExecutor = async () => {
      executed = true;
      return { ok: true, result: {} };
    };

    approvals.resolveApproval(approvalId, "denied", "human:cli:tty");
    engine.request("test-agent", "fakegit:call:danger", "20m", "need it");
    await new Promise((r) => setTimeout(r, 50));

    expect(executed).toBe(false);
    expect(approvals.resultFor(approvalId)).toBeUndefined();
  });

  it("stale intents expire without executing", async () => {
    const { approvals, PolicyEngine } = await mods();
    const engine = new PolicyEngine(LOCAL as never);
    const approvalId = escalate(engine);
    approvals.queueIntent({
      approvalId,
      agentId: "test-agent",
      tool: "fakegit__danger",
      args: {},
      expiresAt: Date.now() - 1, // already stale
    });
    let executed = false;
    engine.intentExecutor = async () => {
      executed = true;
      return { ok: true, result: {} };
    };

    approvals.resolveApproval(approvalId, "approved", "human:cli:tty");
    engine.request("test-agent", "fakegit:call:danger", "20m", "need it");
    await new Promise((r) => setTimeout(r, 50));

    expect(executed).toBe(false);
    expect(approvals.latestIntentFor(approvalId)?.status).toBe("expired");
  });
});
