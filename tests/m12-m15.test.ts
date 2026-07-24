/**
 * M12 + M15: host observability (events tool, /health readiness, /events
 * NDJSON) and batch capability requests (scopegate_request_capabilities).
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts).
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { runGateway as runGatewayT } from "../src/gateway/server.js";

type GatewayHandle = NonNullable<Awaited<ReturnType<typeof runGatewayT>>>;

let home: string;

beforeEach(() => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local";
});

afterEach(() => {
  delete process.env.SCOPEGATE_VAULT_MODE;
  cleanupTempHome(home);
});

describe("M15 scopegate_request_capabilities (batch)", () => {
  it("per-item outcomes: granted / no_rule / pending in ONE call", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway({
      extraCapabilities: [
        { match: "otherapi:call:danger", require: "human_approval", ttl: "15m" },
      ],
    });
    try {
      const res = await handle.client.callTool({
        name: "scopegate_request_capabilities",
        arguments: {
          requests: [
            { capability: "fakegit:call:whoami", reason: "auto" },
            { capability: "other:call:x", reason: "no rule" },
            { capability: "otherapi:call:danger", reason: "needs human" },
          ],
        },
      });
      expect(res.isError).not.toBe(true);
      const body = JSON.parse((res.content as { text: string }[])[0].text);
      expect(body.total).toBe(3);
      expect(body.granted).toBe(1);
      const [auto, noRule, pending] = body.results;
      expect(auto).toMatchObject({ capability: "fakegit:call:whoami", granted: true });
      expect(noRule).toMatchObject({ capability: "other:call:x", granted: false, code: "no_rule" });
      expect(pending).toMatchObject({
        capability: "otherapi:call:danger",
        granted: false,
        status: "pending_human_approval",
      });
      expect(pending.approval_id).toBeTruthy();
    } finally {
      await handle.close();
    }
  }, 30_000);

  it("batches over 20 requests are rejected; empty batches too", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway();
    try {
      const tooBig = await handle.client.callTool({
        name: "scopegate_request_capabilities",
        arguments: {
          requests: Array.from({ length: 21 }, (_, i) => ({ capability: `fakegit:call:x${i}` })),
        },
      });
      expect(tooBig.isError).toBe(true);
      expect((tooBig.content as { text: string }[])[0].text).toContain("max 20");

      const empty = await handle.client.callTool({
        name: "scopegate_request_capabilities",
        arguments: { requests: [] },
      });
      expect(empty.isError).toBe(true);
    } finally {
      await handle.close();
    }
  }, 30_000);
});

describe("M12 host observability", () => {
  it("scopegate_events returns a metadata-only tail (no payloads)", async () => {
    const { bootFakeGateway } = await import("../src/testkit/index.js");
    const handle = await bootFakeGateway();
    try {
      await handle.client.callTool({ name: "fakegit__whoami", arguments: {} });
      const res = await handle.client.callTool({
        name: "scopegate_events",
        arguments: { kinds: ["tool_call", "grant_issued"] },
      });
      const body = JSON.parse((res.content as { text: string }[])[0].text);
      expect(body.count).toBeGreaterThan(0);
      const toolCall = body.events.find((e: Record<string, unknown>) => e.kind === "tool_call");
      expect(toolCall).toMatchObject({ tool: "fakegit__whoami", agentId: "testkit-agent" });
      // Metadata only: no args, no result payloads anywhere in the tail.
      for (const e of body.events) {
        expect(e).not.toHaveProperty("args");
        expect(e).not.toHaveProperty("result");
      }
    } finally {
      await handle.close();
    }
  }, 30_000);

  it("/health carries readiness detail and /events serves NDJSON behind the bearer", async () => {
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify({ version: 1, agentId: "m12-agent", upstreams: [] }),
    );
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify({
        version: 1,
        agents: { "m12-agent": { default_ttl: "15m", capabilities: [] } },
      }),
    );
    process.env.SCOPEGATE_HTTP_TOKEN = "m12-token";
    const { runGateway } = await import("../src/gateway/server.js");
    const handle = (await runGateway({
      transport: "http",
      port: 0,
      host: "127.0.0.1",
    })) as GatewayHandle;
    try {
      const base = `http://127.0.0.1:${handle.port}`;

      const health = await fetch(`${base}/health`);
      expect(health.status).toBe(200);
      const body = (await health.json()) as Record<string, never>;
      expect(body.status).toBe("ok");
      expect(typeof body.upstreams).toBe("number"); // legacy shape preserved
      expect(body).toHaveProperty("upstreams_detail");
      expect(body).toHaveProperty("vault_mode");
      expect(body).toHaveProperty("pending_approvals");
      expect(body.pending_approvals).toBe(0);

      // /events requires the bearer.
      const noAuth = await fetch(`${base}/events`);
      expect(noAuth.status).toBe(401);
      const withAuth = await fetch(`${base}/events?limit=10`, {
        headers: { authorization: "Bearer m12-token" },
      });
      expect(withAuth.status).toBe(200);
      expect(withAuth.headers.get("content-type")).toContain("application/x-ndjson");
      const lines = (await withAuth.text()).trim().split("\n").filter(Boolean);
      expect(lines.length).toBeGreaterThan(0);
      const first = JSON.parse(lines[0]);
      expect(first).toHaveProperty("ts");
      expect(first).toHaveProperty("kind");
      expect(first).toHaveProperty("agentId");
    } finally {
      await handle.close().catch(() => {});
      delete process.env.SCOPEGATE_HTTP_TOKEN;
    }
  }, 30_000);
});
