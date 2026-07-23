/**
 * Tracker tools (EPIC-14): issues + projects. Bare tool names — the gateway
 * adds the `huly__` namespace when proxying. Handlers validate args and
 * delegate to the HulyBridgeClient; all errors surface as actionable MCP
 * isError messages via server.ts.
 */
import type { HulyBridgeClient } from "./client.js";

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
  if (typeof v !== "string") throw new Error(`Invalid argument "${name}" (expected string)`);
  return v;
}

export function optionalLimit(args: Record<string, unknown>, def = 20): number | undefined {
  const v = args.limit;
  if (v === undefined || v === null) return def;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
    throw new Error('Invalid argument "limit" (expected a positive number)');
  }
  return Math.min(Math.floor(v), 100);
}

const PRIORITY_SCHEMA = {
  anyOf: [{ type: "string" }, { type: "number" }],
  description: "Issue priority: urgent|high|medium|low|none or 0-4",
};

export const trackerTools: ToolDefinition[] = [
  {
    name: "tracker_create_issue",
    description: "Create an issue in a Huly tracker project",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string", description: "Project identifier (e.g. DEMO) or id" },
        title: { type: "string", description: "Issue title" },
        description: { type: "string", description: "Issue description (markdown)" },
        priority: PRIORITY_SCHEMA,
        assignee: { type: "string", description: "Assignee (Huly account/person ref)" },
      },
      required: ["project", "title"],
    },
  },
  {
    name: "tracker_update_issue",
    description: "Update fields of an existing issue",
    inputSchema: {
      type: "object",
      properties: {
        issueId: { type: "string", description: "Issue identifier (e.g. DEMO-1) or id" },
        fields: {
          type: "object",
          description: "Fields to update (at least one)",
          properties: {
            title: { type: "string" },
            description: { type: "string", description: "New description (markdown)" },
            status: { type: "string", description: "backlog|todo|in_progress|done|canceled" },
            priority: PRIORITY_SCHEMA,
            assignee: { type: "string" },
          },
        },
      },
      required: ["issueId", "fields"],
    },
  },
  {
    name: "tracker_comment_issue",
    description: "Add a comment to an issue",
    inputSchema: {
      type: "object",
      properties: {
        issueId: { type: "string", description: "Issue identifier (e.g. DEMO-1) or id" },
        message: { type: "string", description: "Comment body (markdown)" },
      },
      required: ["issueId", "message"],
    },
  },
  {
    name: "tracker_search_issues",
    description: "Search issues by text, project and/or status",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Case-insensitive substring matched against the title" },
        project: { type: "string", description: "Project identifier (e.g. DEMO) or id" },
        status: { type: "string", description: "backlog|todo|in_progress|done|canceled" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
      },
    },
  },
  {
    name: "tracker_list_projects",
    description: "List tracker projects with their issue counts",
    inputSchema: { type: "object", properties: {} },
  },
];

export function createTrackerHandlers(client: HulyBridgeClient): Record<string, ToolHandler> {
  return {
    tracker_create_issue: async (args) => {
      const created = await client.createIssue({
        project: requireString(args, "project", "use tracker_list_projects to see identifiers"),
        title: requireString(args, "title"),
        description: optionalString(args, "description"),
        priority: args.priority as string | number | undefined,
        assignee: optionalString(args, "assignee"),
      });
      return created;
    },

    tracker_update_issue: async (args) => {
      const issueId = requireString(args, "issueId", "pass an identifier like DEMO-1 or an id");
      const fields = args.fields;
      if (typeof fields !== "object" || fields === null || Array.isArray(fields)) {
        throw new Error(
          'Missing or invalid required argument "fields" (object with title/description/status/priority/assignee)',
        );
      }
      const f = fields as Record<string, unknown>;
      return await client.updateIssue(issueId, {
        title: optionalString(f, "title"),
        description: optionalString(f, "description"),
        status: optionalString(f, "status"),
        priority: f.priority as string | number | undefined,
        assignee: optionalString(f, "assignee"),
      });
    },

    tracker_comment_issue: async (args) => {
      return await client.commentIssue(
        requireString(args, "issueId", "pass an identifier like DEMO-1 or an id"),
        requireString(args, "message"),
      );
    },

    tracker_search_issues: async (args) => {
      const issues = await client.searchIssues({
        query: optionalString(args, "query"),
        project: optionalString(args, "project"),
        status: optionalString(args, "status"),
        limit: optionalLimit(args),
      });
      return { issues, count: issues.length };
    },

    tracker_list_projects: async () => {
      const projects = await client.listProjects();
      return { projects, count: projects.length };
    },
  };
}
