/**
 * M4: multi-identity over the HTTP transport.
 *
 *   - `X-ScopeGate-Agent` names the logical agent (thread/task) for grants,
 *     audit and approvals. It is validated against the gateway's allowlist
 *     (policies.yaml agents + the default identity): unknown ids get a 403.
 *   - No header → the gateway's default identity (unchanged behavior).
 *   - The bearer remains the perimeter: the header is attribution, not auth.
 *
 * Boots the real gateway in http mode on an ephemeral port against a
 * throwaway SCOPEGATE_HOME (helpers.ts).
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { runGateway as runGatewayT } from "../src/gateway/server.js";

type GatewayHandle = NonNullable<Awaited<ReturnType<typeof runGatewayT>>>;

const TOKEN = "vitest-m4-token";

describe("M4 multi-identity (X-ScopeGate-Agent)", () => {
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
        upstreams: [],
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
          "thread-b": {
            default_ttl: "15m",
            capabilities: [{ match: "otherapi:call:*", auto_approve: true, ttl: "15m" }],
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

  async function connect(agentHeader?: string) {
    const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
    const { StreamableHTTPClientTransport } = await import(
      "@modelcontextprotocol/sdk/client/streamableHttp.js"
    );
    const headers: Record<string, string> = { authorization: `Bearer ${TOKEN}` };
    if (agentHeader) headers["x-scopegate-agent"] = agentHeader;
    const client = new Client({ name: "vitest-m4", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${handle!.port}/mcp`), {
        requestInit: { headers },
      }),
    );
    return client;
  }

  async function requestCapability(client: { callTool: Function }, capability: string) {
    const res = await client.callTool({
      name: "scopegate_request_capability",
      arguments: { capability, reason: "m4 test" },
    });
    const text = (res.content as { type: string; text: string }[])[0].text;
    return JSON.parse(text) as { granted: boolean; code?: string };
  }

  it("the header selects the policy identity; no header keeps the default; unknown ids are 403", async () => {
    process.env.SCOPEGATE_HTTP_TOKEN = TOKEN;
    const { runGateway } = await import("../src/gateway/server.js");
    handle = (await runGateway({ transport: "http", port: 0, host: "127.0.0.1" })) as GatewayHandle;

    // Default identity (test-agent): fakegit allowed, otherapi has no rule.
    const def = await connect();
    expect((await requestCapability(def, "fakegit:call:x")).granted).toBe(true);
    expect((await requestCapability(def, "otherapi:call:x")).granted).toBe(false);
    await def.close();

    // thread-b: otherapi allowed (its own policy), fakegit has no rule there.
    const tb = await connect("thread-b");
    expect((await requestCapability(tb, "otherapi:call:x")).granted).toBe(true);
    expect((await requestCapability(tb, "fakegit:call:x")).granted).toBe(false);
    await tb.close();

    // Unknown agent → 403 unknown_agent (the header is attribution, not auth).
    const ghost = await fetch(`http://127.0.0.1:${handle.port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TOKEN}`,
        "x-scopegate-agent": "ghost",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    expect(ghost.status).toBe(403);
    expect(JSON.stringify(await ghost.json())).toContain("unknown_agent");

    // The grant landed under the right identity: thread-b's grant file entry
    // carries agentId thread-b, not the default.
    const grants = JSON.parse(
      fs.readFileSync(path.join(home, "grants.json"), "utf8"),
    ) as { grants: { agentId: string; capability: string }[] };
    expect(grants.grants).toContainEqual(
      expect.objectContaining({ agentId: "thread-b", capability: "otherapi:call:x" }),
    );
    expect(grants.grants).toContainEqual(
      expect.objectContaining({ agentId: "test-agent", capability: "fakegit:call:x" }),
    );
  }, 30_000);

  it("glob sections govern minted per-work-unit identities, most specific first", async () => {
    // A worker that mints one identity per thread (`nexgen-kimi-<channelId>`)
    // cannot declare them ahead of time. Glob keys make that governable, and
    // a narrower glob must outrank a wider one — otherwise adding a catch-all
    // would silently widen every channel's policy.
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify({
        version: 1,
        agents: {
          "test-agent": { default_ttl: "15m", capabilities: [] },
          // Wider glob: every minted identity may read.
          "nexgen-kimi-*": {
            default_ttl: "15m",
            capabilities: [{ match: "fakegit:read:*", auto_approve: true, ttl: "15m" }],
          },
          // Narrower glob for one channel: may also write. Declared BEFORE the
          // wider one would be a false pass, so it is declared after on
          // purpose — precedence must come from specificity, not file order.
          "nexgen-kimi-chan1*": {
            default_ttl: "15m",
            capabilities: [
              { match: "fakegit:read:*", auto_approve: true, ttl: "15m" },
              { match: "fakegit:write:*", auto_approve: true, ttl: "15m" },
            ],
          },
        },
      }),
    );
    process.env.SCOPEGATE_HTTP_TOKEN = TOKEN;
    const { runGateway } = await import("../src/gateway/server.js");
    handle = (await runGateway({ transport: "http", port: 0, host: "127.0.0.1" })) as GatewayHandle;

    // Matches the narrow glob → both read and write.
    const chan1 = await connect("nexgen-kimi-chan1");
    expect((await requestCapability(chan1, "fakegit:read:x")).granted).toBe(true);
    expect((await requestCapability(chan1, "fakegit:write:x")).granted).toBe(true);
    await chan1.close();

    // Matches only the wide glob → read yes, write no. This is the assertion
    // that would fail if precedence were file order or first match.
    const chan2 = await connect("nexgen-kimi-chan2");
    expect((await requestCapability(chan2, "fakegit:read:x")).granted).toBe(true);
    expect((await requestCapability(chan2, "fakegit:write:x")).granted).toBe(false);
    await chan2.close();

    // Still fail-closed: an id matching no section and no `*` is 403.
    const ghost = await fetch(`http://127.0.0.1:${handle.port}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${TOKEN}`,
        "x-scopegate-agent": "other-worker-chan1",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    expect(ghost.status).toBe(403);

    // Audit attribution is the minted id, not the glob: an operator must be
    // able to tell which channel acted.
    const grants = JSON.parse(
      fs.readFileSync(path.join(home, "grants.json"), "utf8"),
    ) as { grants: { agentId: string; capability: string }[] };
    expect(grants.grants).toContainEqual(
      expect.objectContaining({ agentId: "nexgen-kimi-chan1", capability: "fakegit:write:x" }),
    );
    expect(grants.grants).toContainEqual(
      expect.objectContaining({ agentId: "nexgen-kimi-chan2", capability: "fakegit:read:x" }),
    );
    expect(
      grants.grants.some((g) => g.agentId === "nexgen-kimi-*"),
    ).toBe(false);
  }, 30_000);

  it("rejects agent section keys that could never match an identity", async () => {
    const { validatePoliciesFile } = await import("../src/policy/engine.js");
    const withKey = (key: string) => () =>
      validatePoliciesFile({
        version: 1,
        agents: { [key]: { default_ttl: "15m", capabilities: [] } },
      });

    // Empty and newline-bearing keys are config accidents picomatch or our own
    // check can catch.
    expect(withKey("")).toThrow();
    expect(withKey("nexgen-kimi-\n*")).toThrow(/newline/i);
    // Whitespace can never match: ids arrive trimmed from the header.
    expect(withKey("nexgen kimi *")).toThrow(/whitespace/i);

    // What this does NOT catch, documented so nobody assumes otherwise:
    // picomatch compiles `nexgen-kimi-[` happily and it simply matches
    // nothing. Static validation cannot see that; the 403 message and
    // /admin/agents are the operational defense.
    expect(withKey("nexgen-kimi-[")).not.toThrow();
  });
});
