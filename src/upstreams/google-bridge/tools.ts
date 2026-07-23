/**
 * google-bridge tools (EPIC-18): Drive + Gmail + Calendar. Bare tool names —
 * the gateway adds the `google__` namespace when proxying. Handlers validate
 * args and delegate to the GoogleBridgeClient; all errors surface as
 * actionable MCP isError messages via server.ts.
 *
 * The drive_read content cap (DRIVE_READ_MAX_CHARS, client.ts) is applied
 * HERE, at the tools layer, so both backends share the exact same contract.
 */
import {
  capDriveContent,
  DRIVE_READ_MAX_CHARS,
  type GoogleBridgeClient,
} from "./client.js";

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

export function optionalLimit(args: Record<string, unknown>, def = 20): number | undefined {
  const v = args.limit;
  if (v === undefined || v === null) return def;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) {
    throw new Error('Invalid argument "limit" (expected a positive number)');
  }
  return Math.min(Math.floor(v), 100);
}

function optionalStringArray(args: Record<string, unknown>, name: string): string[] | undefined {
  const v = args[name];
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || (x as string).trim() === "")) {
    throw new Error(`Invalid argument "${name}" (expected an array of non-empty strings)`);
  }
  return v as string[];
}

/** Validates an ISO 8601 datetime (or YYYY-MM-DD date) argument. */
function requireDateArg(args: Record<string, unknown>, name: string): string {
  const v = requireString(args, name, "pass an ISO 8601 datetime (e.g. 2026-03-02T09:00:00Z) or a date (YYYY-MM-DD)");
  if (Number.isNaN(Date.parse(v))) {
    throw new Error(
      `Invalid argument "${name}" ("${v}") — pass an ISO 8601 datetime (e.g. 2026-03-02T09:00:00Z) or a date (YYYY-MM-DD)`,
    );
  }
  return v;
}

/** The closed list of 7 tools (frozen contract). */
export const googleTools: ToolDefinition[] = [
  {
    name: "drive_list",
    description: "List Drive files, optionally filtered by name substring",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Case-insensitive substring matched against the file name" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
      },
    },
  },
  {
    name: "drive_search",
    description: "Full-text search across Drive file names and contents",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Full-text search expression" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
      },
      required: ["query"],
    },
  },
  {
    name: "drive_read",
    description:
      "Read a Drive file: metadata plus text content (raw text files; Docs/Sheets/Slides exported to text). " +
      `Content is capped at ${DRIVE_READ_MAX_CHARS} chars (1 MiB) — larger texts return truncated=true`,
    inputSchema: {
      type: "object",
      properties: {
        fileId: { type: "string", description: "Drive file id (from drive_list or drive_search)" },
      },
      required: ["fileId"],
    },
  },
  {
    name: "gmail_send",
    description: "Send an email as the authenticated user (RFC 822 text/plain)",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string", description: "Recipient address" },
        subject: { type: "string", description: "Subject line" },
        body: { type: "string", description: "Plain-text body (UTF-8)" },
        cc: { type: "string", description: "Optional Cc address" },
      },
      required: ["to", "subject", "body"],
    },
  },
  {
    name: "gmail_list",
    description: "List messages of the authenticated user, optionally filtered",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Gmail search query (e.g. subject text, from:...)" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
      },
    },
  },
  {
    name: "calendar_list",
    description: "List events of a calendar (default: primary), starting at timeMin",
    inputSchema: {
      type: "object",
      properties: {
        calendarId: { type: "string", description: "Calendar id (default: primary)" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
        timeMin: { type: "string", description: "ISO 8601 lower bound (default: now)" },
      },
    },
  },
  {
    name: "calendar_create",
    description: "Create an event in a calendar (default: primary)",
    inputSchema: {
      type: "object",
      properties: {
        summary: { type: "string", description: "Event title" },
        start: { type: "string", description: "ISO 8601 datetime (or YYYY-MM-DD for all-day)" },
        end: { type: "string", description: "ISO 8601 datetime (or YYYY-MM-DD for all-day)" },
        calendarId: { type: "string", description: "Calendar id (default: primary)" },
        description: { type: "string", description: "Event description" },
        attendees: { type: "array", items: { type: "string" }, description: "Attendee email addresses" },
      },
      required: ["summary", "start", "end"],
    },
  },
];

export function createGoogleHandlers(client: GoogleBridgeClient): Record<string, ToolHandler> {
  return {
    drive_list: async (args) => {
      const files = await client.driveList({
        query: optionalString(args, "query"),
        limit: optionalLimit(args),
      });
      return { files, count: files.length };
    },

    drive_search: async (args) => {
      const files = await client.driveSearch({
        query: requireString(args, "query", "drive_search is full-text; use drive_list to browse by name"),
        limit: optionalLimit(args),
      });
      return { files, count: files.length };
    },

    drive_read: async (args) => {
      const fileId = requireString(args, "fileId", "use drive_list or drive_search to locate file ids");
      const result = await client.driveRead(fileId);
      if (typeof result.content !== "string") return result;
      const capped = capDriveContent(result.content);
      if (!capped.truncated) return result;
      return {
        ...result,
        content: capped.content,
        truncated: true,
        note: `content capped at ${DRIVE_READ_MAX_CHARS} chars (1 MiB) — download the file outside the bridge for the full text`,
      };
    },

    gmail_send: async (args) => {
      return await client.gmailSend({
        to: requireString(args, "to"),
        subject: requireString(args, "subject"),
        body: requireString(args, "body", "pass the plain-text body"),
        cc: optionalString(args, "cc"),
      });
    },

    gmail_list: async (args) => {
      const messages = await client.gmailList({
        query: optionalString(args, "query"),
        limit: optionalLimit(args),
      });
      return { messages, count: messages.length };
    },

    calendar_list: async (args) => {
      const timeMin = optionalString(args, "timeMin");
      if (timeMin !== undefined && Number.isNaN(Date.parse(timeMin))) {
        throw new Error(
          `Invalid argument "timeMin" ("${timeMin}") — pass an ISO 8601 datetime (e.g. 2026-03-02T09:00:00Z)`,
        );
      }
      const events = await client.calendarList({
        calendarId: optionalString(args, "calendarId"),
        limit: optionalLimit(args),
        timeMin,
      });
      return { events, count: events.length };
    },

    calendar_create: async (args) => {
      return await client.calendarCreate({
        summary: requireString(args, "summary"),
        start: requireDateArg(args, "start"),
        end: requireDateArg(args, "end"),
        calendarId: optionalString(args, "calendarId"),
        description: optionalString(args, "description"),
        attendees: optionalStringArray(args, "attendees"),
      });
    },
  };
}
