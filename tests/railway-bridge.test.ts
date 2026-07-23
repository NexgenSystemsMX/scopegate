/**
 * railway-bridge tests (EPIC-16): the MCP server (createBridgeServer) is
 * driven over a linked InMemoryTransport pair against the in-memory mock
 * client — no network, no Railway account, no SCOPEGATE_HOME involved.
 *
 * Covers the frozen contract:
 *   - listTools exposes exactly the 7 bare tool names
 *   - happy path of all 7 tools against the seeded mock state
 *   - projectId-less resolution: grouped listing, unique/ambiguous/not-found
 *   - actionable isError results (unknown service/project/tool, missing args,
 *     invalid lines, no-deployments cases)
 *   - variable redaction: names only, every value "[redacted]", no seeded
 *     value ever leaks
 *   - factory selection (mock vs real) and secret hygiene: the token never
 *     appears in tool output, schemas, or error messages
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRailwayClient } from "../src/upstreams/railway-bridge/client.js";
import { createMockClient } from "../src/upstreams/railway-bridge/mock-client.js";
import { buildToolList, createBridgeServer } from "../src/upstreams/railway-bridge/server.js";

const EXPECTED_TOOLS = [
  "list_services",
  "service_status",
  "deploy",
  "redeploy",
  "get_logs",
  "variables_list",
  "domain_status",
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
  client = new Client({ name: "railway-bridge-test", version: "1.0.0" }, { capabilities: {} });
  server = createBridgeServer(createMockClient());
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterEach(async () => {
  await client.close().catch(() => undefined);
  await server.close().catch(() => undefined);
});

describe("railway-bridge tools list", () => {
  it("exposes exactly the 7 frozen bare tool names", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...EXPECTED_TOOLS].sort());
    expect(buildToolList()).toHaveLength(7);
    for (const tool of tools) {
      expect(tool.description).toBeTruthy();
      expect(tool.inputSchema).toBeTruthy();
    }
  });
});

describe("list_services", () => {
  it("without projectId returns every project with its services grouped", async () => {
    const res = parse(await callTool("list_services"));
    expect(res.count).toBe(2);
    const demo = res.projects.find((p: { name: string }) => p.name === "Demo Project");
    const infra = res.projects.find((p: { name: string }) => p.name === "Infra");
    expect(demo).toBeTruthy();
    expect(infra).toBeTruthy();
    expect(demo.services.map((s: { name: string }) => s.name)).toEqual(["api", "worker"]);
    expect(infra.services.map((s: { name: string }) => s.name)).toEqual(["postgres", "worker"]);
    expect(demo.services[0].id).toBe("mock-service-1");
  });

  it("with projectId returns only that project", async () => {
    const res = parse(await callTool("list_services", { projectId: "mock-project-1" }));
    expect(res.count).toBe(1);
    expect(res.projects[0].name).toBe("Demo Project");
  });

  it("unknown projectId is an actionable project-not-found error", async () => {
    const err = parseError(await callTool("list_services", { projectId: "nope" }));
    expect(err).toMatch(/project not found/i);
    expect(err).toMatch(/list_services/);
  });
});

describe("service_status", () => {
  it("returns the latest deployment with status, createdAt and url", async () => {
    const res = parse(await callTool("service_status", { service: "api" }));
    expect(res.service).toBe("api");
    expect(res.project).toBe("Demo Project");
    expect(res.environment).toBe("production");
    expect(res.deployment).toMatchObject({
      id: "mock-deploy-1",
      status: "SUCCESS",
      createdAt: "2026-07-20T10:00:00.000Z",
      url: "https://api-demo.up.railway.app",
    });
  });

  it("resolves a service by id too", async () => {
    const res = parse(await callTool("service_status", { service: "mock-service-2", projectId: "mock-project-1" }));
    expect(res.service).toBe("worker");
    expect(res.deployment.status).toBe("FAILED");
  });

  it("a service without deployments returns deployment: null", async () => {
    const res = parse(await callTool("service_status", { service: "postgres" }));
    expect(res.deployment).toBeNull();
  });

  it("unknown service and unknown project are distinguished", async () => {
    const errService = parseError(await callTool("service_status", { service: "nope" }));
    expect(errService).toMatch(/service not found/i);
    expect(errService).toMatch(/list_services/);
    const errProject = parseError(await callTool("service_status", { service: "api", projectId: "nope" }));
    expect(errProject).toMatch(/project not found/i);
    expect(errProject).not.toMatch(/service not found/i);
  });

  it("a service name present in two projects is ambiguous without projectId", async () => {
    const err = parseError(await callTool("service_status", { service: "worker" }));
    expect(err).toMatch(/ambiguous/i);
    expect(err).toMatch(/Demo Project/);
    expect(err).toMatch(/Infra/);
    expect(err).toMatch(/projectId/);
    const resolved = parse(await callTool("service_status", { service: "worker", projectId: "mock-project-2" }));
    expect(resolved.project).toBe("Infra");
    expect(resolved.deployment.status).toBe("BUILDING");
  });
});

describe("deploy / redeploy", () => {
  it("deploy returns an acceptance and the new deployment becomes the latest", async () => {
    const res = parse(await callTool("deploy", { service: "api" }));
    expect(res.accepted).toBe(true);
    expect(res.kind).toBe("deploy");
    expect(res.deploymentId).toBeTruthy();
    expect(res.service).toBe("api");
    const status = parse(await callTool("service_status", { service: "api" }));
    expect(status.deployment.id).toBe(res.deploymentId);
    expect(status.deployment.status).toBe("QUEUED");
  });

  it("redeploy returns an acceptance with the latest deployment id", async () => {
    const res = parse(await callTool("redeploy", { service: "api" }));
    expect(res.accepted).toBe(true);
    expect(res.kind).toBe("redeploy");
    expect(res.deploymentId).toBe("mock-deploy-1");
  });

  it("redeploy on a service without deployments is actionable", async () => {
    const err = parseError(await callTool("redeploy", { service: "postgres" }));
    expect(err).toMatch(/no deployments/i);
    expect(err).toMatch(/deploy/);
  });

  it("deploy on an unknown service is an isError", async () => {
    const err = parseError(await callTool("deploy", { service: "nope" }));
    expect(err).toMatch(/service not found/i);
  });
});

describe("get_logs", () => {
  it("returns the deploy logs of the latest deployment", async () => {
    const res = parse(await callTool("get_logs", { service: "api" }));
    expect(res.deploymentId).toBe("mock-deploy-1");
    expect(res.count).toBe(3);
    expect(res.logs[0].message).toBe("Starting deployment");
    expect(res.logs[2].message).toBe("Healthcheck passed");
  });

  it("honours the lines argument (most recent last)", async () => {
    const res = parse(await callTool("get_logs", { service: "api", lines: 2 }));
    expect(res.count).toBe(2);
    expect(res.logs[0].message).toBe("Build succeeded");
    expect(res.logs[1].message).toBe("Healthcheck passed");
  });

  it("a service without deployments has no logs", async () => {
    const err = parseError(await callTool("get_logs", { service: "postgres" }));
    expect(err).toMatch(/no deployments/i);
  });

  it("invalid lines is rejected", async () => {
    const err = parseError(await callTool("get_logs", { service: "api", lines: -3 }));
    expect(err).toMatch(/lines/);
  });
});

describe("variables_list (hard redaction)", () => {
  it("returns names only, every value '[redacted]'", async () => {
    const res = parse(await callTool("variables_list", { service: "api" }));
    expect(res.count).toBe(3);
    expect(res.variables.map((v: { name: string }) => v.name)).toEqual(["API_KEY", "DATABASE_URL", "NODE_ENV"]);
    for (const v of res.variables) {
      expect(v.value).toBe("[redacted]");
    }
    // No seeded value may leak anywhere in the response payload.
    const raw = JSON.stringify(res);
    expect(raw).not.toContain("sk-railway-demo-secret");
    expect(raw).not.toContain("postgres://user:pass");
  });

  it("redacts single-secret services too", async () => {
    const res = parse(await callTool("variables_list", { service: "postgres" }));
    expect(res.variables).toEqual([{ name: "POSTGRES_PASSWORD", value: "[redacted]" }]);
    expect(JSON.stringify(res)).not.toContain("super-secret-pw");
  });

  it("a service without variables returns an empty list", async () => {
    const res = parse(await callTool("variables_list", { service: "worker", projectId: "mock-project-1" }));
    expect(res.count).toBe(0);
    expect(res.variables).toEqual([]);
  });
});

describe("domain_status", () => {
  it("returns service domains and custom domains with DNS status", async () => {
    const res = parse(await callTool("domain_status", { service: "api" }));
    expect(res.serviceDomains).toEqual([{ id: "mock-sdom-1", domain: "api-demo.up.railway.app" }]);
    expect(res.customDomains).toEqual([{ id: "mock-cdom-1", domain: "api.example.com", dnsStatus: "VALID" }]);
  });

  it("a service without domains returns empty lists", async () => {
    const res = parse(await callTool("domain_status", { service: "worker", projectId: "mock-project-1" }));
    expect(res.serviceDomains).toEqual([]);
    expect(res.customDomains).toEqual([]);
  });
});

describe("MCP error contract", () => {
  it("unknown tool returns an actionable isError", async () => {
    const err = parseError(await callTool("variables_set"));
    expect(err).toMatch(/unknown tool/i);
    expect(err).toMatch(/variables_list/);
  });

  it("missing required service argument is rejected", async () => {
    const err = parseError(await callTool("service_status", {}));
    expect(err).toMatch(/"service"/);
    expect(err).toMatch(/list_services/);
  });
});

describe("factory + secret hygiene", () => {
  it("RAILWAY_MOCK=1 selects the mock; a live env selects the real client", () => {
    expect(createRailwayClient({ RAILWAY_MOCK: "1" }).constructor.name).toBe("MockRailwayClient");
    expect(createRailwayClient({ RAILWAY_TOKEN: "tok" }).constructor.name).toBe("RealRailwayClient");
    expect(
      createRailwayClient({ RAILWAY_TOKEN: "tok", RAILWAY_API_URL: "https://example.internal/graphql" }).constructor.name,
    ).toBe("RealRailwayClient");
  });

  it("a missing token is an actionable error that points at depositing it", () => {
    expect(() => createRailwayClient({})).toThrow(/RAILWAY_TOKEN/);
    expect(() => createRailwayClient({})).toThrow(/scopegate secret add railway_token/);
    expect(() => createRailwayClient({})).toThrow(/RAILWAY_MOCK/);
  });

  it("no tool output, schema or error leaks the token or seeded variable values", async () => {
    const token = "super-secret-railway-token";
    process.env.RAILWAY_TOKEN = token;
    try {
      const outputs: string[] = [JSON.stringify(buildToolList())];
      parse(await callTool("variables_list", { service: "api" }));
      outputs.push(JSON.stringify(await callTool("variables_list", { service: "api" })));
      outputs.push(JSON.stringify(await callTool("variables_list", { service: "postgres" })));
      outputs.push(JSON.stringify(await callTool("service_status", { service: "nope" })));
      outputs.push(JSON.stringify(await callTool("list_services")));
      outputs.push(JSON.stringify(await client.listTools()));
      try {
        createRailwayClient({});
      } catch (err) {
        outputs.push(String(err));
      }
      for (const out of outputs) {
        expect(out).not.toContain(token);
        expect(out).not.toContain("sk-railway-demo-secret");
        expect(out).not.toContain("super-secret-pw");
        expect(out).not.toContain("postgres://user:pass");
      }
    } finally {
      delete process.env.RAILWAY_TOKEN;
    }
  });
});
