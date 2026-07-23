/**
 * google-bridge client (EPIC-18): semantic interface over Google Workspace
 * (Drive + Gmail + Calendar) plus the factory the MCP server uses to pick a
 * backend:
 *
 *   createGoogleClient(env)
 *     GOOGLE_MOCK=1  → in-memory mock (mock-client.ts) — tests & local e2e
 *     otherwise      → real client over the Google REST APIs (native fetch)
 *
 * Connection contract (frozen):
 *   GOOGLE_ACCESS_TOKEN  access token minted by the gateway from the
 *                        service-account key (google_sa provider); injected at
 *                        spawn. NEVER logged, NEVER embedded in errors.
 *   GOOGLE_API_URL       optional API base URL (default
 *                        https://www.googleapis.com) — tests / private endpoints.
 *   GOOGLE_MOCK=1        in-memory mock; the token is not validated.
 *
 * The real client validates the token lazily (first API call), mapping
 * 401/403/404 to actionable errors via googleApiError() — a bridge that dies
 * at startup would be harder to diagnose than an isError that tells the agent
 * exactly what to fix.
 *
 * drive_read content cap (frozen, documented in README.md): the tools layer
 * truncates text content at DRIVE_READ_MAX_CHARS (1 MiB) via capDriveContent()
 * — single place for both backends. Binary files are never downloaded by the
 * real client (metadata + note only); Google Docs/Sheets/Slides are exported
 * to text (plain/csv) per EXPORT_MIMES.
 */
import { createMockClient } from "./mock-client.js";

export const DEFAULT_API_URL = "https://www.googleapis.com";

/** Documented drive_read cap: 1 MiB of UTF-8 text. */
export const DRIVE_READ_MAX_CHARS = 1_048_576;

/** Google Workspace types exportable to text, and the export MIME used. */
export const EXPORT_MIMES: Record<string, string> = {
  "application/vnd.google-apps.document": "text/plain",
  "application/vnd.google-apps.spreadsheet": "text/csv",
  "application/vnd.google-apps.presentation": "text/plain",
};

/** MIME types whose raw bytes are returned as UTF-8 text by drive_read. */
export function isTextMime(mimeType: string): boolean {
  const m = mimeType.toLowerCase();
  return (
    m.startsWith("text/") ||
    m === "application/json" ||
    m === "application/xml" ||
    m === "application/javascript" ||
    m === "application/x-yaml" ||
    m === "application/yaml" ||
    m === "application/csv" ||
    m === "image/svg+xml" ||
    m.endsWith("+json") ||
    m.endsWith("+xml")
  );
}

/** Applies the documented drive_read cap (used by the tools layer). */
export function capDriveContent(content: string): { content: string; truncated: boolean } {
  return content.length > DRIVE_READ_MAX_CHARS
    ? { content: content.slice(0, DRIVE_READ_MAX_CHARS), truncated: true }
    : { content, truncated: false };
}

// --- Semantic output shapes (compact JSON — the frozen response contract) ---

export interface DriveFileInfo {
  id: string;
  name: string;
  mimeType: string;
  size?: number;
  modifiedTime?: string;
}

export interface DriveReadResult extends DriveFileInfo {
  /** UTF-8 text (raw text file or export); absent for binary/non-exportable. */
  content?: string;
  /** Set by the tools layer when content was capped at DRIVE_READ_MAX_CHARS. */
  truncated?: boolean;
  /** Human note when content is absent (binary / non-exportable). */
  note?: string;
}

export interface GmailSendInput {
  to: string;
  subject: string;
  body: string;
  cc?: string;
}

export interface GmailSendResult {
  id: string;
  threadId: string;
  labelIds: string[];
}

export interface GmailMessageInfo {
  id: string;
  threadId: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
}

export interface CalendarEventInfo {
  id: string;
  summary: string;
  start: string;
  end: string;
  status: string;
  description?: string;
  attendees?: string[];
}

export interface CalendarCreateInput {
  summary: string;
  start: string;
  end: string;
  calendarId?: string;
  description?: string;
  attendees?: string[];
}

// --- The bridge client contract (real and mock both implement it) ---

export interface GoogleBridgeClient {
  connect: () => Promise<void>;
  close: () => Promise<void>;

  driveList: (filter: { query?: string; limit?: number }) => Promise<DriveFileInfo[]>;
  driveSearch: (filter: { query: string; limit?: number }) => Promise<DriveFileInfo[]>;
  driveRead: (fileId: string) => Promise<DriveReadResult>;

  gmailSend: (input: GmailSendInput) => Promise<GmailSendResult>;
  gmailList: (filter: { query?: string; limit?: number }) => Promise<GmailMessageInfo[]>;

  calendarList: (filter: {
    calendarId?: string;
    limit?: number;
    timeMin?: string;
  }) => Promise<CalendarEventInfo[]>;
  calendarCreate: (input: CalendarCreateInput) => Promise<CalendarEventInfo>;
}

// --- RFC 822 message construction (gmail_send) ---

/** RFC 2047 base64 encoding for non-ASCII header values. */
function encodeHeaderValue(value: string): string {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7e]*$/.test(value) ? value : `=?UTF-8?B?${Buffer.from(value, "utf8").toString("base64")}?=`;
}

function requireHeaderSafe(name: string, value: string): void {
  if (/[\r\n]/.test(value)) {
    throw new Error(`Invalid argument "${name}": header values must not contain newlines`);
  }
}

/**
 * Builds the RFC 822 message gmail_send uploads (base64url) as `raw`.
 * Header-injection safe: To/Cc/Subject reject newlines; non-ASCII subjects
 * are RFC 2047 encoded. Body is UTF-8 text/plain.
 */
export function buildRfc822(input: GmailSendInput): string {
  requireHeaderSafe("to", input.to);
  requireHeaderSafe("subject", input.subject);
  if (input.cc !== undefined) requireHeaderSafe("cc", input.cc);
  const headers = [
    `To: ${input.to}`,
    ...(input.cc !== undefined && input.cc !== "" ? [`Cc: ${input.cc}`] : []),
    `Subject: ${encodeHeaderValue(input.subject)}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="UTF-8"',
    "Content-Transfer-Encoding: 8bit",
  ];
  return `${headers.join("\r\n")}\r\n\r\n${input.body}`;
}

// --- Error mapping (actionable, secret-free) ---

/**
 * Maps a Google API failure to an actionable error. NEVER carries the access
 * token: 401 points at the mint flow, 403 at the scopes config, 404 at the
 * listing tools.
 */
export function googleApiError(status: number, surface: string, detail?: string): Error {
  const suffix = detail !== undefined && detail !== "" ? ` (${detail.slice(0, 200)})` : "";
  if (status === 401) {
    return new Error(
      `Google API rejected the access token (HTTP 401) on ${surface}${suffix} — the gateway mints ` +
        `it from the google_sa vault blob; retry the call to force a re-mint, and if it persists ` +
        `re-check the blob (client_email/private_key) and that the service account is enabled`,
    );
  }
  if (status === 403) {
    return new Error(
      `Google API denied the call (HTTP 403) on ${surface}${suffix} — insufficient scope: add the ` +
        `required scope to auth.scopes of the upstream config (default: drive.readonly, gmail.send, ` +
        `calendar.readonly) and grant it to the service account / domain-wide delegation`,
    );
  }
  if (status === 404) {
    return new Error(
      `Not found on ${surface} (HTTP 404)${suffix} — check the id; use the drive_list/drive_search, ` +
        `gmail_list or calendar_list tools to locate it`,
    );
  }
  return new Error(`Google API call failed (HTTP ${status}) on ${surface}${suffix}`);
}

// --- Real client -------------------------------------------------------------

type FetchLike = (
  url: string,
  init?: Record<string, unknown>,
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export interface RealClientOptions {
  token: string;
  apiUrl?: string;
  fetchFn?: FetchLike;
}

/** Escapes a literal for a Drive q= expression (single-quoted). */
function escapeDriveQuery(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

interface RawDriveFile {
  id?: string;
  name?: string;
  mimeType?: string;
  size?: string;
  modifiedTime?: string;
}

function mapDriveFile(raw: RawDriveFile): DriveFileInfo {
  const size = raw.size !== undefined && raw.size !== "" ? Number(raw.size) : undefined;
  return {
    id: String(raw.id ?? ""),
    name: String(raw.name ?? ""),
    mimeType: String(raw.mimeType ?? ""),
    ...(size !== undefined && Number.isFinite(size) ? { size } : {}),
    ...(raw.modifiedTime !== undefined ? { modifiedTime: String(raw.modifiedTime) } : {}),
  };
}

interface RawEventTime {
  dateTime?: string;
  date?: string;
}

interface RawCalendarEvent {
  id?: string;
  summary?: string;
  status?: string;
  description?: string;
  start?: RawEventTime;
  end?: RawEventTime;
  attendees?: Array<{ email?: string }>;
}

function mapCalendarEvent(raw: RawCalendarEvent): CalendarEventInfo {
  const attendees = (raw.attendees ?? [])
    .map((a) => a.email)
    .filter((e): e is string => typeof e === "string" && e !== "");
  return {
    id: String(raw.id ?? ""),
    summary: String(raw.summary ?? "(no title)"),
    start: String(raw.start?.dateTime ?? raw.start?.date ?? ""),
    end: String(raw.end?.dateTime ?? raw.end?.date ?? ""),
    status: String(raw.status ?? "confirmed"),
    ...(raw.description !== undefined ? { description: String(raw.description) } : {}),
    ...(attendees.length > 0 ? { attendees } : {}),
  };
}

/** start/end input → Google event time (date-only values become all-day). */
function toEventTime(value: string): RawEventTime {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? { date: value } : { dateTime: value };
}

export class RealGoogleClient implements GoogleBridgeClient {
  private readonly token: string;
  private readonly apiUrl: string;
  private readonly fetchFn: FetchLike;

  constructor(opts: RealClientOptions) {
    this.token = opts.token;
    this.apiUrl = (opts.apiUrl ?? DEFAULT_API_URL).replace(/\/+$/, "");
    this.fetchFn = opts.fetchFn ?? (fetch as unknown as FetchLike);
  }

  /** Lazy by design: the first failing call surfaces an actionable isError. */
  async connect(): Promise<void> {}
  async close(): Promise<void> {}

  private async request(
    method: string,
    path: string,
    opts: {
      query?: Record<string, string | number | string[] | undefined>;
      body?: unknown;
      surface: string;
      rawText?: boolean;
    },
  ): Promise<unknown> {
    const url = new URL(`${this.apiUrl}${path}`);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined) continue;
      if (Array.isArray(v)) {
        for (const item of v) url.searchParams.append(k, item);
      } else {
        url.searchParams.set(k, String(v));
      }
    }
    const res = await this.fetchFn(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
    });
    if (!res.ok) {
      let detail = "";
      try {
        const errBody = (await res.json()) as {
          error?: { message?: unknown } | string;
        };
        const message =
          typeof errBody.error === "object" && errBody.error !== null
            ? errBody.error.message
            : errBody.error;
        if (typeof message === "string") detail = message;
      } catch {
        /* non-JSON error body: the status is enough */
      }
      throw googleApiError(res.status, opts.surface, detail);
    }
    return opts.rawText === true ? res.text() : res.json();
  }

  private driveQuery(query: string | undefined, fullText: boolean): string {
    const base = "trashed = false";
    if (query === undefined || query.trim() === "") return base;
    const field = fullText ? "fullText" : "name";
    return `${field} contains '${escapeDriveQuery(query.trim())}' and ${base}`;
  }

  async driveList(filter: { query?: string; limit?: number }): Promise<DriveFileInfo[]> {
    const data = (await this.request("GET", "/drive/v3/files", {
      query: {
        q: this.driveQuery(filter.query, false),
        pageSize: filter.limit ?? 20,
        fields: "files(id,name,mimeType,size,modifiedTime)",
      },
      surface: "drive_list",
    })) as { files?: RawDriveFile[] };
    return (data.files ?? []).map(mapDriveFile);
  }

  async driveSearch(filter: { query: string; limit?: number }): Promise<DriveFileInfo[]> {
    const data = (await this.request("GET", "/drive/v3/files", {
      query: {
        q: this.driveQuery(filter.query, true),
        pageSize: filter.limit ?? 20,
        fields: "files(id,name,mimeType,size,modifiedTime)",
      },
      surface: "drive_search",
    })) as { files?: RawDriveFile[] };
    return (data.files ?? []).map(mapDriveFile);
  }

  async driveRead(fileId: string): Promise<DriveReadResult> {
    const meta = mapDriveFile(
      (await this.request("GET", `/drive/v3/files/${encodeURIComponent(fileId)}`, {
        query: { fields: "id,name,mimeType,size,modifiedTime" },
        surface: "drive_read",
      })) as RawDriveFile,
    );
    const exportMime = EXPORT_MIMES[meta.mimeType];
    if (exportMime !== undefined) {
      const content = (await this.request("GET", `/drive/v3/files/${encodeURIComponent(fileId)}/export`, {
        query: { mimeType: exportMime },
        surface: "drive_read",
        rawText: true,
      })) as string;
      return { ...meta, content };
    }
    if (meta.mimeType.startsWith("application/vnd.google-apps.")) {
      return {
        ...meta,
        note: `Google Workspace type '${meta.mimeType}' is not text-exportable — drive_read exports Docs, Sheets and Slides only`,
      };
    }
    if (isTextMime(meta.mimeType)) {
      const content = (await this.request("GET", `/drive/v3/files/${encodeURIComponent(fileId)}`, {
        query: { alt: "media" },
        surface: "drive_read",
        rawText: true,
      })) as string;
      return { ...meta, content };
    }
    return { ...meta, note: `binary file ('${meta.mimeType}') — content not returned by drive_read` };
  }

  async gmailSend(input: GmailSendInput): Promise<GmailSendResult> {
    const raw = Buffer.from(buildRfc822(input), "utf8").toString("base64url");
    const data = (await this.request("POST", "/gmail/v1/users/me/messages/send", {
      body: { raw },
      surface: "gmail_send",
    })) as { id?: string; threadId?: string; labelIds?: string[] };
    return {
      id: String(data.id ?? ""),
      threadId: String(data.threadId ?? ""),
      labelIds: Array.isArray(data.labelIds) ? data.labelIds.map(String) : ["SENT"],
    };
  }

  async gmailList(filter: { query?: string; limit?: number }): Promise<GmailMessageInfo[]> {
    const data = (await this.request("GET", "/gmail/v1/users/me/messages", {
      query: { q: filter.query, maxResults: filter.limit ?? 20 },
      surface: "gmail_list",
    })) as { messages?: Array<{ id?: string; threadId?: string }> };
    const out: GmailMessageInfo[] = [];
    for (const m of data.messages ?? []) {
      if (typeof m.id !== "string" || m.id === "") continue;
      const full = (await this.request("GET", `/gmail/v1/users/me/messages/${encodeURIComponent(m.id)}`, {
        query: { format: "metadata", metadataHeaders: ["Subject", "From", "Date"] },
        surface: "gmail_list",
      })) as {
        id?: string;
        threadId?: string;
        snippet?: string;
        payload?: { headers?: Array<{ name?: string; value?: string }> };
      };
      const headers = new Map(
        (full.payload?.headers ?? [])
          .filter((h) => typeof h.name === "string")
          .map((h) => [String(h.name).toLowerCase(), String(h.value ?? "")]),
      );
      out.push({
        id: String(full.id ?? m.id),
        threadId: String(full.threadId ?? m.threadId ?? ""),
        subject: headers.get("subject") ?? "(no subject)",
        from: headers.get("from") ?? "",
        date: headers.get("date") ?? "",
        snippet: String(full.snippet ?? ""),
      });
    }
    return out;
  }

  async calendarList(filter: {
    calendarId?: string;
    limit?: number;
    timeMin?: string;
  }): Promise<CalendarEventInfo[]> {
    const calendarId = filter.calendarId ?? "primary";
    const data = (await this.request(
      "GET",
      `/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`,
      {
        query: {
          timeMin: filter.timeMin ?? new Date().toISOString(),
          maxResults: filter.limit ?? 20,
          singleEvents: "true",
          orderBy: "startTime",
        },
        surface: "calendar_list",
      },
    )) as { items?: RawCalendarEvent[] };
    return (data.items ?? []).map(mapCalendarEvent);
  }

  async calendarCreate(input: CalendarCreateInput): Promise<CalendarEventInfo> {
    const calendarId = input.calendarId ?? "primary";
    const data = (await this.request(
      "POST",
      `/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`,
      {
        body: {
          summary: input.summary,
          ...(input.description !== undefined ? { description: input.description } : {}),
          start: toEventTime(input.start),
          end: toEventTime(input.end),
          ...(input.attendees !== undefined && input.attendees.length > 0
            ? { attendees: input.attendees.map((email) => ({ email })) }
            : {}),
        },
        surface: "calendar_create",
      },
    )) as RawCalendarEvent;
    return mapCalendarEvent(data);
  }
}

// --- Factory -----------------------------------------------------------------

/**
 * Picks the backend from the environment (frozen contract):
 *   GOOGLE_MOCK=1 → in-memory mock (no network, token not validated);
 *   otherwise     → real client (requires GOOGLE_ACCESS_TOKEN;
 *                   GOOGLE_API_URL overrides the API base URL).
 */
export function createGoogleClient(env: NodeJS.ProcessEnv = process.env): GoogleBridgeClient {
  if (env.GOOGLE_MOCK === "1") return createMockClient();
  const token = env.GOOGLE_ACCESS_TOKEN;
  if (token === undefined || token.trim() === "") {
    throw new Error(
      `google-bridge: missing required env GOOGLE_ACCESS_TOKEN — the gateway injects it via the ` +
        `minter (auth type google_sa) at spawn (or set GOOGLE_MOCK=1 for the in-memory mock)`,
    );
  }
  return new RealGoogleClient({ token, apiUrl: env.GOOGLE_API_URL });
}
