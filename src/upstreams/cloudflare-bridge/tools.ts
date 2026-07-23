/**
 * cloudflare-bridge tools (EPIC-17): the closed list of 8 tools over zones,
 * DNS records, Workers, Pages and R2. Bare tool names — the gateway adds the
 * `cloudflare__` namespace when proxying. Handlers validate args and delegate
 * to the CloudflareBridgeClient; all errors surface as actionable MCP isError
 * messages via server.ts.
 *
 * The bridge imposes NO extra authorization: destructive ops (dns_delete) are
 * gated by the gateway POLICY (require: human_approval), not here.
 */
import type { CloudflareBridgeClient } from "./client.js";

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export type ToolHandler = (args: Record<string, unknown>) => Promise<unknown>;

export function requireString(args: Record<string, unknown>, name: string, hint?: string): string {
  const v = args[name];
  if (typeof v === "string" && v.trim() !== "") return v;
  throw new Error(`Missing or invalid required argument "${name}" (non-empty string)${hint !== undefined ? ` — ${hint}` : ""}`);
}

export function optionalString(args: Record<string, unknown>, name: string): string | undefined {
  const v = args[name];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string" || v.trim() === "") throw new Error(`Invalid argument "${name}" (expected a non-empty string)`);
  return v;
}

export function optionalTtl(args: Record<string, unknown>): number | undefined {
  const v = args.ttl;
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
    throw new Error('Invalid argument "ttl" (expected a positive integer in seconds; 1 = automatic)');
  }
  return v;
}

export function optionalProxied(args: Record<string, unknown>): boolean | undefined {
  const v = args.proxied;
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "boolean") throw new Error('Invalid argument "proxied" (expected a boolean)');
  return v;
}

const ZONE_SCHEMA = { type: "string", description: "Zone name (example.com) or zone id — see list_zones" };
const TTL_SCHEMA = { type: "number", description: "TTL in seconds (1 = automatic)" };
const PROXIED_SCHEMA = { type: "boolean", description: "Proxy through Cloudflare (orange cloud)" };
const ACCOUNT_SCHEMA = {
  type: "string",
  description: "Cloudflare account id. Optional: when omitted, the first account from GET /accounts is used",
};

/** The closed list of 8 tools (frozen contract). */
export const cloudflareTools: ToolDefinition[] = [
  {
    name: "list_zones",
    description: "List the Cloudflare zones this token can access",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dns_list",
    description: "List DNS records of a zone, optionally filtered by type and/or exact name",
    inputSchema: {
      type: "object",
      properties: {
        zone: ZONE_SCHEMA,
        type: { type: "string", description: "Record type filter (A, AAAA, CNAME, MX, TXT, …)" },
        name: { type: "string", description: "Exact record name filter (e.g. www.example.com)" },
      },
      required: ["zone"],
    },
  },
  {
    name: "dns_create",
    description: "Create a DNS record in a zone",
    inputSchema: {
      type: "object",
      properties: {
        zone: ZONE_SCHEMA,
        type: { type: "string", description: "Record type (A, AAAA, CNAME, MX, TXT, …)" },
        name: { type: "string", description: "Record name (e.g. www.example.com)" },
        content: { type: "string", description: "Record content (IP, hostname, text, …)" },
        ttl: TTL_SCHEMA,
        proxied: PROXIED_SCHEMA,
      },
      required: ["zone", "type", "name", "content"],
    },
  },
  {
    name: "dns_update",
    description: "Update fields of an existing DNS record (at least one)",
    inputSchema: {
      type: "object",
      properties: {
        zone: ZONE_SCHEMA,
        recordId: { type: "string", description: "Record id (from dns_list)" },
        type: { type: "string" },
        name: { type: "string" },
        content: { type: "string" },
        ttl: TTL_SCHEMA,
        proxied: PROXIED_SCHEMA,
      },
      required: ["zone", "recordId"],
    },
  },
  {
    name: "dns_delete",
    description: "Delete a DNS record (gated by gateway policy: human approval)",
    inputSchema: {
      type: "object",
      properties: {
        zone: ZONE_SCHEMA,
        recordId: { type: "string", description: "Record id (from dns_list)" },
      },
      required: ["zone", "recordId"],
    },
  },
  {
    name: "workers_list",
    description: "List Workers scripts of an account (first account when accountId is omitted)",
    inputSchema: { type: "object", properties: { accountId: ACCOUNT_SCHEMA } },
  },
  {
    name: "pages_projects",
    description: "List Pages projects of an account (first account when accountId is omitted)",
    inputSchema: { type: "object", properties: { accountId: ACCOUNT_SCHEMA } },
  },
  {
    name: "r2_buckets",
    description: "List R2 buckets of an account (first account when accountId is omitted)",
    inputSchema: { type: "object", properties: { accountId: ACCOUNT_SCHEMA } },
  },
];

export function createCloudflareHandlers(client: CloudflareBridgeClient): Record<string, ToolHandler> {
  return {
    list_zones: async () => {
      const zones = await client.listZones();
      return { zones, count: zones.length };
    },

    dns_list: async (args) => {
      const { zone, records } = await client.listDnsRecords({
        zone: requireString(args, "zone", "pass a zone name (example.com) or zone id — use list_zones"),
        type: optionalString(args, "type"),
        name: optionalString(args, "name"),
      });
      return { zone: zone.name, records, count: records.length };
    },

    dns_create: async (args) => {
      return await client.createDnsRecord(requireString(args, "zone", "use list_zones to see zones"), {
        type: requireString(args, "type", "A, AAAA, CNAME, MX, TXT, …"),
        name: requireString(args, "name", "e.g. www.example.com"),
        content: requireString(args, "content", "IP, hostname or text"),
        ttl: optionalTtl(args),
        proxied: optionalProxied(args),
      });
    },

    dns_update: async (args) => {
      const zone = requireString(args, "zone", "use list_zones to see zones");
      const recordId = requireString(args, "recordId", "pass a record id from dns_list");
      const patch = {
        type: optionalString(args, "type"),
        name: optionalString(args, "name"),
        content: optionalString(args, "content"),
        ttl: optionalTtl(args),
        proxied: optionalProxied(args),
      };
      if (Object.values(patch).every((v) => v === undefined)) {
        throw new Error("Nothing to update: pass at least one of type/name/content/ttl/proxied");
      }
      return await client.updateDnsRecord(zone, recordId, patch);
    },

    dns_delete: async (args) => {
      return await client.deleteDnsRecord(
        requireString(args, "zone", "use list_zones to see zones"),
        requireString(args, "recordId", "pass a record id from dns_list"),
      );
    },

    workers_list: async (args) => {
      const { accountId, workers } = await client.listWorkers(optionalString(args, "accountId"));
      return { accountId, workers, count: workers.length };
    },

    pages_projects: async (args) => {
      const { accountId, projects } = await client.listPagesProjects(optionalString(args, "accountId"));
      return { accountId, projects, count: projects.length };
    },

    r2_buckets: async (args) => {
      const { accountId, buckets } = await client.listR2Buckets(optionalString(args, "accountId"));
      return { accountId, buckets, count: buckets.length };
    },
  };
}
