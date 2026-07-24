/**
 * M11.2 tests: OpenAPI→MCP importer.
 *
 * A local node:http server plays TWO roles: it serves a small OpenAPI 3.0
 * spec (3 operations: GET with path+query params, POST with a requestBody,
 * and one operation WITHOUT operationId) AND it serves the real API
 * endpoints, echoing back path/query/body/Authorization so the tests can
 * assert exactly what hit the wire.
 *
 * The gateway side is the real UpstreamProxy (same pattern as
 * idempotency.test.ts) on a throwaway SCOPEGATE_HOME (helpers.ts) with the
 * bearer deposited in the real vault. The PolicyEngine assertions run
 * against the real engine + policies.yaml.
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
let server: http.Server;
let port: number;
let specDoc: Record<string, unknown>;

function buildSpec(baseUrl: string): Record<string, unknown> {
  return {
    openapi: "3.0.0",
    info: { title: "Pet API", version: "1.0.0" },
    servers: [{ url: baseUrl }],
    paths: {
      "/pets/{petId}": {
        get: {
          operationId: "getPet",
          summary: "Get a pet by id",
          parameters: [
            { name: "petId", in: "path", required: true, schema: { type: "string" } },
            { name: "limit", in: "query", required: false, schema: { type: "integer" } },
          ],
        },
      },
      "/pets": {
        post: {
          operationId: "createPet",
          summary: "Create a pet",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { name: { type: "string" }, tag: { type: "string" } },
                  required: ["name"],
                },
              },
            },
          },
        },
      },
      "/search": {
        get: {
          // NO operationId on purpose — the importer must derive one.
          summary: "Search pets",
          parameters: [
            { name: "q", in: "query", required: true, schema: { type: "string" } },
          ],
        },
      },
    },
  };
}

function startServer(): Promise<void> {
  return new Promise((resolve) => {
    server = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      if (u.pathname === "/openapi.json") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(specDoc));
        return;
      }
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const auth = req.headers.authorization ?? null;
        const json = (status: number, payload: unknown) => {
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(payload));
        };
        if (req.method === "GET" && u.pathname.startsWith("/pets/")) {
          const id = decodeURIComponent(u.pathname.slice("/pets/".length));
          if (id === "999") return json(404, { message: "pet not found" });
          return json(200, { id, limit: u.searchParams.get("limit"), auth });
        }
        if (req.method === "POST" && u.pathname === "/pets") {
          return json(200, {
            received: JSON.parse(body || "{}"),
            contentType: req.headers["content-type"] ?? null,
            auth,
          });
        }
        if (req.method === "GET" && u.pathname === "/search") {
          return json(200, { q: u.searchParams.get("q"), auth });
        }
        return json(404, { message: "not found" });
      });
    });
    server.listen(0, "127.0.0.1", () => {
      port = (server.address() as AddressInfo).port;
      specDoc = buildSpec(`http://127.0.0.1:${port}`);
      resolve();
    });
  });
}

function closeServer(): Promise<void> {
  return new Promise((resolve) => {
    if (!server) return resolve();
    server.close(() => resolve());
  });
}

beforeEach(async () => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local";
  await startServer();
});

afterEach(async () => {
  await closeServer();
  delete process.env.SCOPEGATE_VAULT_MODE;
  cleanupTempHome(home);
});

/** Real proxy against the local server, bearer deposited in the real vault. */
async function makeProxy(auth: Record<string, unknown> = { type: "bearer", secretRef: "petapi_token" }) {
  const { UpstreamProxy } = await import("../src/gateway/proxy.js");
  const { Vault } = await import("../src/vault/vault.js");
  const vault = Vault.open();
  vault.set("petapi_token", "s3cr3t");
  const upstream = {
    name: "petapi",
    transport: {
      kind: "openapi" as const,
      spec: `http://127.0.0.1:${port}/openapi.json`,
      // No baseUrl on purpose: resolution must come from servers[0].url.
    },
    auth,
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proxy = new UpstreamProxy([upstream as any], vault, { agentId: "test-agent" });
  return proxy;
}

type McpResult = { content: { type: string; text: string }[]; isError?: boolean };

function resultJson(result: unknown): Record<string, unknown> {
  const r = result as McpResult;
  return JSON.parse(r.content[0].text) as Record<string, unknown>;
}

describe("M11.2: openapi transport", () => {
  it("connects by loading the spec and generates one tool per operation with correct schemas", async () => {
    const proxy = await makeProxy();
    try {
      const status = await proxy.connectAll();
      expect(status.petapi.ok).toBe(true);
      expect(status.petapi.tools).toBe(3);

      const tools = proxy.listProxiedTools();
      const names = tools.map((t) => t.exposedName).sort();
      expect(names).toEqual(["petapi__createPet", "petapi__getPet", "petapi__get_search"]);

      const getPet = proxy.resolve("petapi__getPet")!;
      expect(getPet.description).toBe("Get a pet by id");
      const schema = getPet.inputSchema as {
        type: string;
        properties: Record<string, Record<string, unknown>>;
        required?: string[];
        additionalProperties?: boolean;
      };
      expect(schema.type).toBe("object");
      expect(schema.properties.petId).toBeDefined();
      expect(schema.properties.petId["x-scopegate-in"]).toBe("path");
      expect(schema.properties.limit).toBeDefined();
      expect(schema.properties.limit["x-scopegate-in"]).toBe("query");
      expect(schema.required).toEqual(["petId"]);
      expect(schema.additionalProperties).toBe(false);

      const createPet = proxy.resolve("petapi__createPet")!;
      const postSchema = createPet.inputSchema as {
        properties: Record<string, Record<string, unknown>>;
        required?: string[];
      };
      expect(postSchema.properties.body).toBeDefined();
      expect(postSchema.required).toContain("body");

      // No operationId in the spec → derived `<method>_<sanitized path>`.
      const search = proxy.resolve("petapi__get_search")!;
      const searchSchema = search.inputSchema as { required?: string[] };
      expect(search.description).toBe("Search pets");
      expect(searchSchema.required).toEqual(["q"]);
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("executes a GET with path+query params and injects the vault bearer on the wire", async () => {
    const proxy = await makeProxy();
    try {
      await proxy.connectAll();
      const result = await proxy.call("petapi__getPet", { petId: "42", limit: 5 });
      const body = resultJson(result);
      expect(body.id).toBe("42");
      expect(body.limit).toBe("5");
      // The credential left the vault at the outbound hop — never the agent.
      expect(body.auth).toBe("Bearer s3cr3t");
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("executes a POST with a JSON requestBody (content-type and payload intact)", async () => {
    const proxy = await makeProxy();
    try {
      await proxy.connectAll();
      const result = await proxy.call("petapi__createPet", {
        body: { name: "fido", tag: "dog" },
      });
      const body = resultJson(result);
      expect(body.received).toEqual({ name: "fido", tag: "dog" });
      expect(body.contentType).toBe("application/json");
      expect(body.auth).toBe("Bearer s3cr3t");
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("derives and calls the operationId-less tool (get_search)", async () => {
    const proxy = await makeProxy();
    try {
      await proxy.connectAll();
      const result = await proxy.call("petapi__get_search", { q: "cats" });
      const body = resultJson(result);
      expect(body.q).toBe("cats");
      expect(body.auth).toBe("Bearer s3cr3t");
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("maps an upstream HTTP error to an in-band isError result (no throw, no retry storm)", async () => {
    const proxy = await makeProxy();
    try {
      await proxy.connectAll();
      const result = (await proxy.call("petapi__getPet", { petId: "999" })) as McpResult;
      expect(result.isError).toBe(true);
      const body = resultJson(result);
      expect(body.error).toBe(true);
      expect(body.status).toBe(404);
      expect((body.body as Record<string, unknown>).message).toBe("pet not found");
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("refuses auth types other than bearer|none with a clear connect error", async () => {
    const proxy = await makeProxy({ type: "env", env: { SOME_TOKEN: "petapi_token" } });
    try {
      const status = await proxy.connectAll();
      expect(status.petapi.ok).toBe(false);
      expect(status.petapi.error).toMatch(/openapi transport supports bearer\|none auth in v1/);
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("enforces the SSRF guard: a non-localhost http baseUrl is refused", async () => {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const upstream = {
      name: "evil",
      transport: {
        kind: "openapi" as const,
        spec: `http://127.0.0.1:${port}/openapi.json`,
        baseUrl: "http://169.254.169.254/latest",
      },
      auth: { type: "none" as const },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const proxy = new UpstreamProxy([upstream as any], Vault.open(), { agentId: "test-agent" });
    try {
      const status = await proxy.connectAll();
      expect(status.evil.ok).toBe(false);
      expect(status.evil.error).toMatch(/https is required/);
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("works with auth type 'none' (no credential headers injected)", async () => {
    const proxy = await makeProxy({ type: "none" });
    try {
      await proxy.connectAll();
      const result = await proxy.call("petapi__get_search", { q: "birds" });
      const body = resultJson(result);
      expect(body.q).toBe("birds");
      expect(body.auth).toBeNull();
    } finally {
      await proxy.closeAll();
    }
  }, 15_000);

  it("passes the capability `<up>:call:<operationId>` through the real PolicyEngine", async () => {
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify({
        version: 1,
        agents: {
          "test-agent": {
            default_ttl: "15m",
            capabilities: [
              { match: "petapi:call:getPet", auto_approve: true, ttl: "15m" },
            ],
          },
        },
      }),
    );
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const engine = PolicyEngine.load();

    // No matching rule → not granted (escalates to a human, never auto-approved).
    const denied = engine.request("test-agent", "petapi:call:createPet");
    expect(denied.allow).toBe(false);

    // auto_approve rule → granted with a TTL.
    const granted = engine.request("test-agent", "petapi:call:getPet");
    expect(granted.allow).toBe(true);
    expect(granted.ttlMs).toBeGreaterThan(0);
  }, 15_000);
});

describe("M11.2: spec loading", () => {
  it("falls back to the 24h disk cache when the spec fetch fails", async () => {
    const { loadOpenApiSpec } = await import("../src/upstreams/openapi.js");
    const ref = `http://127.0.0.1:${port}/openapi.json`;
    const first = await loadOpenApiSpec(ref);
    expect(first.info?.title).toBe("Pet API");
    // The cache file exists under SCOPEGATE_HOME/openapi-cache.
    const cacheDir = path.join(home, "openapi-cache");
    expect(fs.readdirSync(cacheDir).filter((f) => f.endsWith(".json")).length).toBe(1);
    // Kill the server — the next load must come from the cache.
    await closeServer();
    const second = await loadOpenApiSpec(ref);
    expect(second).toEqual(first);
    await startServer();
  }, 15_000);

  it("loads a spec from a local YAML file", async () => {
    const { loadOpenApiSpec, toolsFromSpec } = await import("../src/upstreams/openapi.js");
    const YAML = (await import("yaml")).default;
    const file = path.join(home, "pet-api.yaml");
    fs.writeFileSync(file, YAML.stringify(buildSpec(`http://127.0.0.1:${port}`)));
    const spec = await loadOpenApiSpec(file);
    expect(spec.info?.title).toBe("Pet API");
    const { tools } = toolsFromSpec(spec, "petapi");
    expect(tools.map((t) => t.name).sort()).toEqual(["createPet", "getPet", "get_search"]);
  }, 15_000);
});

describe("M11.2: config validation", () => {
  it("loadConfig accepts a valid openapi transport and rejects a missing spec", async () => {
    const { loadConfig } = await import("../src/config/config.js");
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify({
        version: 1,
        agentId: "test-agent",
        upstreams: [
          {
            name: "petapi",
            transport: { kind: "openapi", spec: `http://127.0.0.1:${port}/openapi.json` },
            auth: { type: "bearer", secretRef: "petapi_token" },
          },
        ],
      }),
    );
    const cfg = loadConfig();
    expect(cfg.upstreams[0].transport.kind).toBe("openapi");

    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify({
        version: 1,
        agentId: "test-agent",
        upstreams: [
          {
            name: "broken",
            transport: { kind: "openapi" },
            auth: { type: "none" },
          },
        ],
      }),
    );
    expect(() => loadConfig()).toThrow(/openapi transport requires transport\.spec/);
  }, 15_000);

  it("loadConfig rejects a plain-http spec URL outside localhost (SSRF guard at load time)", async () => {
    const { loadConfig } = await import("../src/config/config.js");
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify({
        version: 1,
        agentId: "test-agent",
        upstreams: [
          {
            name: "broken",
            transport: { kind: "openapi", spec: "http://example.com/openapi.json" },
            auth: { type: "none" },
          },
        ],
      }),
    );
    expect(() => loadConfig()).toThrow(/must be an https URL/);
  }, 15_000);
});
