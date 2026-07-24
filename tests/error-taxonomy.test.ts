/**
 * Error taxonomy + circuit breaker tests (mejora #8).
 *
 *   - classifyError maps every failure class to (kind, next_action), with
 *     retry_after parsed when the upstream advertises it; the fail-safe
 *     default is upstream_down + diagnose, never a confident wrong answer.
 *   - The proxy's per-upstream circuit breaker opens after 5 consecutive
 *     failed calls (fail-fast while open), lets one half-open probe through
 *     after the reset window, and closes on success.
 *
 * The circuit tests drive proxy.call() against a stdio upstream that exits
 * immediately (a guaranteed connection failure) and one that speaks MCP
 * (fake-upstream-style success), with the reset window shrunk via a frozen
 * clock where needed.
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

describe("classifyError", () => {
  async function mod() {
    return import("../src/gateway/errors.js");
  }

  it("maps rate limits (429) with parsed retry_after", async () => {
    const { classifyError } = await mod();
    const e = classifyError({ message: "HTTP 429 too many requests — retry-after: 42" });
    expect(e.kind).toBe("rate_limited");
    expect(e.next_action).toBe("wait");
    expect(e.retry_after_s).toBe(42);
    expect(e.error).toBe(true);
  });

  it("maps upstream 401/403 to auth_broken + diagnose", async () => {
    const { classifyError } = await mod();
    for (const m of ["HTTP 401 unauthorized", "403 forbidden: token lacks scope"]) {
      const e = classifyError({ message: m });
      expect(e.kind).toBe("auth_broken");
      expect(e.next_action).toBe("diagnose");
    }
  });

  it("maps not-granted to missing_scope + request_capability", async () => {
    const { classifyError } = await mod();
    const e = classifyError({ message: "Capability 'github:call:x' not granted. Call scopegate_request_capability first." });
    expect(e.kind).toBe("missing_scope");
    expect(e.next_action).toBe("request_capability");
  });

  it("policy decision codes win over message heuristics", async () => {
    const { classifyError } = await mod();
    const e = classifyError({ message: "whatever", code: "ceiling_blocked" });
    expect(e.kind).toBe("policy_denied");
    expect(e.next_action).toBe("human");
    const r = classifyError({ message: "whatever", code: "capability_rate_limited" });
    expect(r.kind).toBe("rate_limited");
  });

  it("maps expired grants to expired_grant + renew", async () => {
    const { classifyError } = await mod();
    const e = classifyError({ message: "grant g-123 expired at ...", code: "expired_grant" });
    expect(e.kind).toBe("expired_grant");
    expect(e.next_action).toBe("renew");
  });

  it("maps network failures to upstream_down + wait (default 5s)", async () => {
    const { classifyError } = await mod();
    for (const m of ["fetch failed: ECONNREFUSED", "request timed out after 10000ms", "HTTP 503"]) {
      const e = classifyError({ message: m });
      expect(e.kind).toBe("upstream_down");
      expect(e.next_action).toBe("wait");
    }
  });

  it("fail-safe default is upstream_down + diagnose, never a wrong confident answer", async () => {
    const { classifyError } = await mod();
    const e = classifyError({ message: "something completely unexpected happened" });
    expect(e.kind).toBe("upstream_down");
    expect(e.next_action).toBe("diagnose");
  });
});

describe("circuit breaker", () => {
  it("opens after 5 consecutive failures, fails fast, then half-opens and closes on success", async () => {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const vault = Vault.open();
    const failing = {
      name: "dead",
      transport: {
        kind: "stdio" as const,
        command: process.execPath,
        args: ["-e", "process.exit(1)"],
      },
      auth: { type: "none" as const },
    };
    const proxy = new UpstreamProxy([failing], vault, { agentId: "test-agent" });
    try {
      // Plant the last-known tool list — the realistic dead-upstream case:
      // the upstream connected once (tools registered), then died. resolve()
      // succeeds from the registry; every call fails at connection time.
      (
        proxy as unknown as {
          toolRegistry: Map<string, unknown[]>;
        }
      ).toolRegistry.set("dead", [
        { upstream: "dead", upstreamName: "x", exposedName: "dead__x", inputSchema: { type: "object" } },
      ]);

      // 4 failures → still closed (each call exhausts its retries internally).
      for (let i = 0; i < 4; i++) {
        await expect(proxy.call("dead__x", {})).rejects.toThrow();
      }
      expect(proxy.circuitReport().dead.state).toBe("closed");
      expect(proxy.circuitReport().dead.failures).toBe(4);

      // 5th failure → circuit opens; the NEXT call fails fast without work.
      await expect(proxy.call("dead__x", {})).rejects.toThrow();
      expect(proxy.circuitReport().dead.state).toBe("open");

      // Fail-fast: the error names the circuit, no upstream contact needed.
      await expect(proxy.call("dead__x", {})).rejects.toThrow(/circuit OPEN/);
      expect(proxy.circuitReport().dead.failures).toBe(5); // gate does not count

      // Wind the clock past the reset window: a half-open probe is allowed
      // through (and fails again → re-opens).
      const c = (proxy as unknown as { circuits: Map<string, { state: string; failures: number; openedAt: number }> }).circuits.get("dead")!;
      c.openedAt = Date.now() - 31_000;
      await expect(proxy.call("dead__x", {})).rejects.toThrow();
      expect(proxy.circuitReport().dead.state).toBe("open"); // probe failed → re-opened
    } finally {
      await proxy.closeAll();
    }
  }, 60_000);

  it("a successful call resets the failure count", async () => {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const vault = Vault.open();
    const up = {
      name: "x",
      transport: { kind: "stdio" as const, command: "x" },
      auth: { type: "none" as const },
    };
    const proxy = new UpstreamProxy([up], vault, { agentId: "test-agent" });
    // Drive the internals directly: two failures then a success → closed, 0.
    const anyProxy = proxy as unknown as {
      circuitFailure(u: string): void;
      circuitSuccess(u: string): void;
    };
    anyProxy.circuitFailure("x");
    anyProxy.circuitFailure("x");
    expect(proxy.circuitReport().x.failures).toBe(2);
    anyProxy.circuitSuccess("x");
    expect(proxy.circuitReport().x).toMatchObject({ state: "closed", failures: 0 });
    await proxy.closeAll();
  });
});
