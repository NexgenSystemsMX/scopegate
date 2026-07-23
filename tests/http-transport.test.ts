/**
 * HTTP transport tests (Sprint 6): boots the real gateway in http mode on an
 * ephemeral port against a throwaway SCOPEGATE_HOME (helpers.ts), then
 * asserts the auth contract and the MCP handshake over Streamable HTTP.
 *
 *   - GET /health answers 200 WITHOUT auth
 *   - any MCP request without / with a wrong bearer is 401 JSON
 *   - with the bearer, the SDK client initializes and lists tools
 *   - startup aborts (fail-closed) when SCOPEGATE_HTTP_TOKEN is unset
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { runGateway as runGatewayT } from "../src/gateway/server.js";

type GatewayHandle = NonNullable<Awaited<ReturnType<typeof runGatewayT>>>;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FAKE_UPSTREAM = path.join(HERE, "..", "fake-upstream.mjs");
const TOKEN = "vitest-http-token";

describe("gateway http transport", () => {
  let home: string;
  let handle: GatewayHandle | null = null;

  beforeEach(() => {
    home = useTempHome();
    process.env.SCOPEGATE_VAULT_MODE = "local";
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify({
        version: 1,
        agentId: "test-agent",
        upstreams: [
          {
            name: "fakegit",
            transport: { kind: "stdio", command: process.execPath, args: [FAKE_UPSTREAM] },
            auth: { type: "env", env: { FAKE_TOKEN: "fake_token" } },
          },
        ],
      }),
    );
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify({
        version: 1,
        agents: {
          "test-agent": {
            default_ttl: "15m",
            capabilities: [{ match: "fakegit:call:*", auto_approve: true, ttl: "15m" }],
          },
        },
      }),
    );
  });

  afterEach(async () => {
    await handle?.close().catch(() => {});
    handle = null;
    delete process.env.SCOPEGATE_HTTP_TOKEN;
    delete process.env.SCOPEGATE_VAULT_MODE;
    cleanupTempHome(home);
  });

  it("serves MCP over HTTP: health is public, MCP requires the bearer, initialize works with it", async () => {
    // Deposit the demo secret through the package vault API.
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("fake_token", "supersecret123");

    process.env.SCOPEGATE_HTTP_TOKEN = TOKEN;
    const { runGateway } = await import("../src/gateway/server.js");
    handle = (await runGateway({
      transport: "http",
      port: 0,
      host: "127.0.0.1",
    })) as GatewayHandle;
    expect(handle.port).toBeGreaterThan(0);
    const base = `http://127.0.0.1:${handle.port}`;

    // /health: no auth → 200 with the connected upstream count.
    const health = await fetch(`${base}/health`);
    expect(health.status).toBe(200);
    const healthBody = (await health.json()) as Record<string, unknown>;
    expect(healthBody.status).toBe("ok");
    expect(healthBody.upstreams).toBe(1);
    expect(typeof healthBody.uptime_s).toBe("number");

    // MCP without a token → 401 JSON.
    const noAuth = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    expect(noAuth.status).toBe(401);
    expect(JSON.stringify(await noAuth.json())).toMatch(/unauthorized|Bearer/i);

    // MCP with a WRONG token → 401.
    const badAuth = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer nope" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    expect(badAuth.status).toBe(401);

    // With the bearer: full MCP handshake + tool listing.
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const { StreamableHTTPClientTransport } = await import(
      "@modelcontextprotocol/sdk/client/streamableHttp.js"
    );
    const client = new Client({ name: "vitest-http", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
      }),
    );
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("scopegate_request_capability");
    expect(names).toContain("fakegit__whoami");
    await client.close();
  }, 30_000);

  it("aborts startup (fail-closed) when SCOPEGATE_HTTP_TOKEN is unset", async () => {
    delete process.env.SCOPEGATE_HTTP_TOKEN;
    const { runGateway } = await import("../src/gateway/server.js");
    await expect(
      runGateway({ transport: "http", port: 0, host: "127.0.0.1" }),
    ).rejects.toThrow(/SCOPEGATE_HTTP_TOKEN/);
    handle = null; // nothing started
  }, 15_000);
});
