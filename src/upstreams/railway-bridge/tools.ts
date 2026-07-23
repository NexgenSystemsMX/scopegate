/**
 * Railway tools (EPIC-16): the closed list of 7 tools. Bare tool names — the
 * gateway adds the `railway__` namespace when proxying. Handlers validate args
 * and delegate to the RailwayBridgeClient; all errors surface as actionable
 * MCP isError messages via server.ts.
 *
 * Frozen contract notes:
 *   - variables_list NEVER returns values (names only, values "[redacted]").
 *   - deploy/redeploy are write operations — the gateway policy gates them
 *     (registry/railway.yaml recommends require: human_approval).
 */
import type { RailwayBridgeClient } from "./client.js";

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export type ToolHandler = (args: Record<string, unknown>) => Promise<unknown>;

export function requireString(args: Record<string, unknown>, name: string, hint?: string): string {
  const v = args[name];
  if (typeof v === "string" && v.trim() !== "") return v;
  throw new Error(
    `Missing or invalid required argument "${name}" (non-empty string)${hint !== undefined ? ` — ${hint}` : ""}`,
  );
}

export function optionalString(args: Record<string, unknown>, name: string): string | undefined {
  const v = args[name];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string") throw new Error(`Invalid argument "${name}" (expected string)`);
  return v;
}

export function optionalLines(args: Record<string, unknown>, def = 100): number {
  const v = args.lines;
  if (v === undefined || v === null) return def;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
    throw new Error('Invalid argument "lines" (expected a positive number)');
  }
  return Math.min(Math.floor(v), 500);
}

const PROJECT_ID_SCHEMA = {
  type: "string",
  description: "Project id; omit to resolve across every accessible project",
};

const SERVICE_SCHEMA = {
  type: "string",
  description: "Service name (e.g. api) or id — use list_services to see them",
};

export const railwayTools: ToolDefinition[] = [
  {
    name: "list_services",
    description:
      "List Railway projects with their services. Without projectId it lists every accessible project and groups services under each one",
    inputSchema: {
      type: "object",
      properties: {
        projectId: { type: "string", description: "Project id; omit to list all accessible projects" },
      },
    },
  },
  {
    name: "service_status",
    description: "Latest deployment of a service: status, createdAt and url (when the deployment exposes one)",
    inputSchema: {
      type: "object",
      properties: {
        service: SERVICE_SCHEMA,
        projectId: PROJECT_ID_SCHEMA,
      },
      required: ["service"],
    },
  },
  {
    name: "deploy",
    description:
      "Trigger a NEW deployment of a service (serviceInstanceDeployV2). Write operation — returns an acceptance with the new deployment id",
    inputSchema: {
      type: "object",
      properties: {
        service: SERVICE_SCHEMA,
        projectId: PROJECT_ID_SCHEMA,
      },
      required: ["service"],
    },
  },
  {
    name: "redeploy",
    description:
      "Redeploy the LATEST deployment of a service (deploymentRedeploy). Write operation — returns an acceptance with the redeployed deployment id",
    inputSchema: {
      type: "object",
      properties: {
        service: SERVICE_SCHEMA,
        projectId: PROJECT_ID_SCHEMA,
      },
      required: ["service"],
    },
  },
  {
    name: "get_logs",
    description: "Deploy (runtime) logs of the latest deployment of a service, most recent last",
    inputSchema: {
      type: "object",
      properties: {
        service: SERVICE_SCHEMA,
        lines: { type: "number", description: "Max log lines to return (default 100, max 500)" },
        projectId: PROJECT_ID_SCHEMA,
      },
      required: ["service"],
    },
  },
  {
    name: "variables_list",
    description:
      "List the NAMES of the environment variables of a service. Values are NEVER returned — every value comes out as '[redacted]'",
    inputSchema: {
      type: "object",
      properties: {
        service: SERVICE_SCHEMA,
        projectId: PROJECT_ID_SCHEMA,
      },
      required: ["service"],
    },
  },
  {
    name: "domain_status",
    description: "Railway-provided service domains and custom domains (with DNS status) of a service",
    inputSchema: {
      type: "object",
      properties: {
        service: SERVICE_SCHEMA,
        projectId: PROJECT_ID_SCHEMA,
      },
      required: ["service"],
    },
  },
];

export function createRailwayHandlers(client: RailwayBridgeClient): Record<string, ToolHandler> {
  const serviceArg = (args: Record<string, unknown>): string =>
    requireString(args, "service", "use list_services to see names and ids");

  return {
    list_services: async (args) => {
      const projects = await client.listServices(optionalString(args, "projectId"));
      return { projects, count: projects.length };
    },

    service_status: async (args) =>
      await client.getServiceStatus(serviceArg(args), optionalString(args, "projectId")),

    deploy: async (args) => await client.deploy(serviceArg(args), optionalString(args, "projectId")),

    redeploy: async (args) => await client.redeploy(serviceArg(args), optionalString(args, "projectId")),

    get_logs: async (args) =>
      await client.getLogs(serviceArg(args), optionalLines(args), optionalString(args, "projectId")),

    variables_list: async (args) =>
      await client.listVariables(serviceArg(args), optionalString(args, "projectId")),

    domain_status: async (args) => await client.getDomains(serviceArg(args), optionalString(args, "projectId")),
  };
}
