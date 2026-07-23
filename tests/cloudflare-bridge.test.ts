/**
 * cloudflare-bridge tests (EPIC-17): the MCP server (createBridgeServer) is
 * driven over a linked InMemoryTransport pair against the in-memory mock
 * client — no network, no Cloudflare account, no SCOPEGATE_HOME involved.
 *
 * Covers the frozen contract:
 *   - listTools exposes exactly the 8 bare tool names
 *   - happy path of all 8 tools (write→read round-trips through the mock)
 *   - dns_list filtering (type / name) and zone resolution by name AND by id
 *   - actionable isError results (unknown zone vs unknown record, missing
 *     args, empty patch, unknown account, unknown tool)
 *   - accountId auto-resolution (first account) and explicit pass-through
 *   - factory selection (mock vs real) and secret hygiene: the token never
 *     appears in tool output, schemas, or error messages
 *   - the real client over a stubbed global fetch: Bearer header, envelope
 *     unwrap, 401/403 → scoped-token message, CF [code] message passthrough,
 *     /accounts auto-resolution, record 404 → record-not-found
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createCloudflareClient, RealCloudflareClient } from "../src/upstreams/cloudflare-bridge/client.js";
import { createMockClient } from "../src/upstreams/cloudflare-bridge/mock-client.js";
import { buildToolList, createBridgeServer } from "../src/upstreams/cloudflare-bridge/server.js";

const EXPECTED_TOOLS = [
  "list_zones",
  "dns_list",
  "dns_create",
  "dns_update",
  "dns_delete",
  "workers_list",
  "pages_projects",
  "r2_buckets",
];

let client: Client;
let server: Server;

async function callTool(name: string, args: Record<string, unknown> = {}) {
  return await client.callTool({ name, arguments: args });
}

function parse(res: Awaited<ReturnType<typeof callTool>>): any {
  expect(res.isError).not.toBe(true);
  const text = (res.content as Array<{ type: string; text: string }>)[0]?.text;
  return JSON.parse(text);
}

function parseError(res: Awaited<ReturnType<typeof callTool>>): string {
  expect(res.isError).toBe(true);
  return (res.content as Array<{ type: string; text: string }>)[0]?.text ?? "";
}

beforeEach(async () => {
  client = new Client({ name: "cloudflare-bridge-test", version: "1.0.0" }, { capabilities: {} });
  server = createBridgeServer(createMockClient());
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterEach(async () => {
  await client.close().catch(() => undefined);
  await server.close().catch(() => undefined);
  vi.unstubAllGlobals();
});

describe("cloudflare-bridge tools list", () => {
  it("exposes exactly the 8 frozen bare tool names", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...EXPECTED_TOOLS].sort());
    expect(buildToolList()).toHaveLength(8);
    for (const tool of tools) {
      expect(tool.description).toBeTruthy();
      expect(tool.inputSchema).toBeTruthy();
    }
  });
});

describe("zones + dns tools", () => {
  it("list_zones returns the seeded zones", async () => {
    const res = parse(await callTool("list_zones"));
    expect(res.count).toBe(2);
    expect(res.zones.map((z: { name: string }) => z.name)).toEqual(["demo.dev", "example.com"]);
    expect(res.zones[1]).toMatchObject({ id: "mock-zone-1", status: "active" });
  });

  it("dns_list returns the seeded records of a zone, resolved by name", async () => {
    const res = parse(await callTool("dns_list", { zone: "example.com" }));
    expect(res.zone).toBe("example.com");
    expect(res.count).toBe(2);
    const www = res.records.find((r: { name: string }) => r.name === "www.example.com");
    expect(www).toMatchObject({ id: "mock-record-1", type: "A", content: "192.0.2.1", ttl: 1, proxied: true });
  });

  it("dns_list also resolves the zone by id", async () => {
    const res = parse(await callTool("dns_list", { zone: "mock-zone-1" }));
    expect(res.zone).toBe("example.com");
    expect(res.count).toBe(2);
  });

  it("dns_list filters by type (case-insensitive) and by exact name", async () => {
    const byType = parse(await callTool("dns_list", { zone: "example.com", type: "a" }));
    expect(byType.count).toBe(1);
    expect(byType.records[0].name).toBe("www.example.com");
    const byName = parse(await callTool("dns_list", { zone: "example.com", name: "example.com" }));
    expect(byName.count).toBe(1);
    expect(byName.records[0].type).toBe("MX");
    const noHit = parse(await callTool("dns_list", { zone: "example.com", type: "TXT" }));
    expect(noHit.count).toBe(0);
  });

  it("dns_list fails actionably on an unknown zone", async () => {
    const err = parseError(await callTool("dns_list", { zone: "nope.example" }));
    expect(err).toMatch(/zone not found/i);
    expect(err).toMatch(/list_zones/);
  });

  it("dns_create creates a record with defaults and dns_list finds it", async () => {
    const created = parse(
      await callTool("dns_create", { zone: "example.com", type: "TXT", name: "_dmarc.example.com", content: "v=DMARC1; p=none" }),
    );
    expect(created.id).toBe("mock-record-3");
    expect(created.ttl).toBe(1);
    expect(created.proxied).toBe(false);
    const list = parse(await callTool("dns_list", { zone: "example.com", type: "TXT" }));
    expect(list.count).toBe(1);
    expect(list.records[0].content).toBe("v=DMARC1; p=none");
  });

  it("dns_create validates required args, ttl and proxied", async () => {
    const missing = parseError(await callTool("dns_create", { zone: "example.com", type: "A", name: "a.example.com" }));
    expect(missing).toMatch(/"content"/);
    const badTtl = parseError(
      await callTool("dns_create", { zone: "example.com", type: "A", name: "a.example.com", content: "192.0.2.9", ttl: 0 }),
    );
    expect(badTtl).toMatch(/ttl/);
    const badProxied = parseError(
      await callTool("dns_create", { zone: "example.com", type: "A", name: "a.example.com", content: "192.0.2.9", proxied: "yes" }),
    );
    expect(badProxied).toMatch(/proxied/);
  });

  it("dns_update updates content and ttl", async () => {
    const updated = parse(
      await callTool("dns_update", { zone: "example.com", recordId: "mock-record-1", content: "192.0.2.2", ttl: 300 }),
    );
    expect(updated).toMatchObject({ id: "mock-record-1", content: "192.0.2.2", ttl: 300, proxied: true });
    const list = parse(await callTool("dns_list", { zone: "example.com", name: "www.example.com" }));
    expect(list.records[0].content).toBe("192.0.2.2");
  });

  it("dns_update rejects an empty patch", async () => {
    const err = parseError(await callTool("dns_update", { zone: "example.com", recordId: "mock-record-1" }));
    expect(err).toMatch(/nothing to update/i);
  });

  it("unknown record is distinguished from unknown zone", async () => {
    const errRecord = parseError(await callTool("dns_update", { zone: "example.com", recordId: "nope", content: "x" }));
    expect(errRecord).toMatch(/dns record not found/i);
    expect(errRecord).toMatch(/dns_list/);
    const errZone = parseError(await callTool("dns_update", { zone: "nope.example", recordId: "mock-record-1", content: "x" }));
    expect(errZone).toMatch(/zone not found/i);
    // A record id from another zone must not resolve.
    const errScope = parseError(await callTool("dns_delete", { zone: "demo.dev", recordId: "mock-record-1" }));
    expect(errScope).toMatch(/dns record not found/i);
  });

  it("dns_delete removes the record", async () => {
    const deleted = parse(await callTool("dns_delete", { zone: "example.com", recordId: "mock-record-2" }));
    expect(deleted).toEqual({ id: "mock-record-2", deleted: true });
    const list = parse(await callTool("dns_list", { zone: "example.com" }));
    expect(list.count).toBe(1);
    const again = parseError(await callTool("dns_delete", { zone: "example.com", recordId: "mock-record-2" }));
    expect(again).toMatch(/dns record not found/i);
  });
});

describe("account surfaces (workers / pages / r2)", () => {
  it("workers_list auto-resolves the first account when accountId is omitted", async () => {
    const res = parse(await callTool("workers_list"));
    expect(res.accountId).toBe("mock-account-1");
    expect(res.count).toBe(2);
    expect(res.workers.map((w: { id: string }) => w.id)).toEqual(["api-worker", "auth-worker"]);
  });

  it("pages_projects returns the seeded projects", async () => {
    const res = parse(await callTool("pages_projects"));
    expect(res.accountId).toBe("mock-account-1");
    expect(res.projects[0]).toEqual({ name: "docs-site", subdomain: "docs-site.pages.dev" });
  });

  it("r2_buckets returns the seeded buckets", async () => {
    const res = parse(await callTool("r2_buckets"));
    expect(res.accountId).toBe("mock-account-1");
    expect(res.count).toBe(2);
    expect(res.buckets.map((b: { name: string }) => b.name)).toEqual(["assets", "backups"]);
  });

  it("an explicit accountId is used; an unknown one is actionable", async () => {
    const res = parse(await callTool("workers_list", { accountId: "mock-account-1" }));
    expect(res.accountId).toBe("mock-account-1");
    const err = parseError(await callTool("workers_list", { accountId: "nope" }));
    expect(err).toMatch(/account not found/i);
    expect(err).toMatch(/mock-account-1/);
  });
});

describe("MCP error contract", () => {
  it("unknown tool returns an actionable isError", async () => {
    const err = parseError(await callTool("dns_purge"));
    expect(err).toMatch(/unknown tool/i);
    expect(err).toMatch(/dns_create/);
  });
});

describe("factory + secret hygiene", () => {
  it("CLOUDFLARE_MOCK=1 selects the mock; a token selects the real client", () => {
    expect(createCloudflareClient({ CLOUDFLARE_MOCK: "1" }).constructor.name).toBe("MockCloudflareClient");
    const real = createCloudflareClient({ CLOUDFLARE_API_TOKEN: "tok" });
    expect(real.constructor.name).toBe("RealCloudflareClient");
  });

  it("missing token is an actionable error mentioning only variable names", () => {
    expect(() => createCloudflareClient({})).toThrow(/CLOUDFLARE_API_TOKEN/);
    expect(() => createCloudflareClient({})).toThrow(/CLOUDFLARE_MOCK/);
    expect(() => createCloudflareClient({})).toThrow(/cloudflare_api_token/);
  });

  it("no tool output, schema or error leaks the token", async () => {
    const token = "super-secret-cf-token";
    process.env.CLOUDFLARE_API_TOKEN = token;
    try {
      const outputs: string[] = [JSON.stringify(buildToolList())];
      outputs.push(JSON.stringify(await callTool("list_zones")));
      outputs.push(JSON.stringify(await callTool("dns_list", { zone: "example.com" })));
      outputs.push(JSON.stringify(await callTool("dns_delete", { zone: "example.com", recordId: "nope" })));
      outputs.push(JSON.stringify(await callTool("workers_list")));
      outputs.push(JSON.stringify(await client.listTools()));
      try {
        createCloudflareClient({});
      } catch (err) {
        outputs.push(String(err));
      }
      for (const out of outputs) {
        expect(out).not.toContain(token);
      }
    } finally {
      delete process.env.CLOUDFLARE_API_TOKEN;
    }
  });
});

describe("real client over a stubbed fetch (no network)", () => {
  const TOKEN = "cf-test-token";
  let calls: Array<{ url: string; method: string; authorization?: string; body?: string }>;

  function cfEnvelope(result: unknown, status = 200): Response {
    return new Response(JSON.stringify({ success: status < 400, errors: [], result }), {
      status,
      headers: { "content-type": "application/json" },
    });
  }

  function stubFetch(handler: (url: string, init?: RequestInit) => Response): void {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: unknown, init?: RequestInit) => {
        const url = String(input);
        calls.push({
          url,
          method: init?.method ?? "GET",
          authorization: (init?.headers as Record<string, string> | undefined)?.Authorization,
          body: typeof init?.body === "string" ? init.body : undefined,
        });
        return handler(url, init);
      }),
    );
  }

  beforeEach(() => {
    calls = [];
  });

  it("list_zones unwraps the envelope, sends the Bearer token and hits the default base URL", async () => {
    stubFetch((url) => {
      expect(url).toBe("https://api.cloudflare.com/client/v4/zones");
      return cfEnvelope([{ id: "z1", name: "example.com", status: "active", extra: "dropped" }]);
    });
    const zones = await new RealCloudflareClient({ token: TOKEN }).listZones();
    expect(zones).toEqual([{ id: "z1", name: "example.com", status: "active" }]);
    expect(calls[0].authorization).toBe(`Bearer ${TOKEN}`);
  });

  it("connect() verifies the token; 401 → actionable scoped-token message without the token", async () => {
    stubFetch(
      () =>
        new Response(JSON.stringify({ success: false, errors: [{ code: 1000, message: "Invalid API Token" }], result: null }), {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
    );
    const err = await new RealCloudflareClient({ token: TOKEN }).connect().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    const message = (err as Error).message;
    expect(message).toMatch(/HTTP 401/);
    expect(message).toMatch(/scoped api token/i);
    expect(message).toMatch(/scopegate secret add cloudflare_api_token/);
    expect(message).not.toContain(TOKEN);
  });

  it("a failed envelope surfaces the CF [code] message", async () => {
    stubFetch((url) => {
      if (url.includes("/zones?name=")) return cfEnvelope([{ id: "z1", name: "example.com", status: "active" }]);
      return new Response(
        JSON.stringify({ success: false, errors: [{ code: 81044, message: "Record already exists." }], result: null }),
        { status: 400, headers: { "content-type": "application/json" } },
      );
    });
    const err = await new RealCloudflareClient({ token: TOKEN })
      .createDnsRecord("example.com", { type: "A", name: "www.example.com", content: "192.0.2.1" })
      .catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/\[81044\] Record already exists/);
    expect((err as Error).message).not.toContain(TOKEN);
  });

  it("workers_list without accountId resolves the first account via /accounts (cached)", async () => {
    stubFetch((url) => {
      if (url.endsWith("/accounts")) return cfEnvelope([{ id: "acc-9", name: "Acct" }]);
      if (url.endsWith("/accounts/acc-9/workers/scripts")) return cfEnvelope([{ id: "worker-1" }]);
      if (url.endsWith("/accounts/acc-9/r2/buckets")) return cfEnvelope([{ name: "backups" }]);
      throw new Error(`unexpected URL: ${url}`);
    });
    const real = new RealCloudflareClient({ token: TOKEN });
    const res = await real.listWorkers();
    expect(res).toEqual({ accountId: "acc-9", workers: [{ id: "worker-1" }] });
    await real.listR2Buckets(); // second surface reuses the cached account (no extra /accounts call)
    const accountCalls = calls.filter((c) => c.url.endsWith("/accounts"));
    expect(accountCalls).toHaveLength(1);
  });

  it("dns_update maps a record 404 to the dedicated not-found error (zone already resolved)", async () => {
    stubFetch((url) => {
      if (url.includes("/zones?name=")) return cfEnvelope([{ id: "z1", name: "example.com", status: "active" }]);
      return new Response(JSON.stringify({ success: false, errors: [{ code: 7003, message: "No route for that URI" }], result: null }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    });
    const err = await new RealCloudflareClient({ token: TOKEN })
      .updateDnsRecord("example.com", "missing-record", { content: "192.0.2.3" })
      .catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/dns record not found/i);
    expect((err as Error).message).toMatch(/dns_list/);
  });

  it("CLOUDFLARE_API_URL overrides the default base URL", async () => {
    stubFetch((url) => {
      expect(url.startsWith("https://cf.internal/v4/zones")).toBe(true);
      return cfEnvelope([]);
    });
    const real = createCloudflareClient({ CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_API_URL: "https://cf.internal/v4/" });
    await real.listZones();
    expect(calls[0].url).toBe("https://cf.internal/v4/zones");
  });
});
