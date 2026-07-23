/**
 * In-memory mock of GoogleBridgeClient (EPIC-18) — same semantics as the real
 * client, backed by plain Maps/arrays. Used when GOOGLE_MOCK=1: unit tests and
 * the local e2e run WITHOUT Google credentials (the token is not validated).
 *
 * The mock works at the semantic level: drive file contents are stored as
 * UTF-8 text (export only exists at the real-client boundary — a google-apps
 * file's stored text IS its export), so a write→read round-trip through the
 * mock returns the original text. The drive_read cap is NOT applied here but
 * in the tools layer (capDriveContent, client.ts), exactly like the real
 * backend path.
 *
 * Seeded state (deterministic, so tests/e2e can assert against it):
 *   - drive files  "Roadmap.md" (text/markdown), "Team budget" (Google Sheet),
 *                  "Spec doc" (Google Doc), "logo.pdf" (binary, no content)
 *   - gmail        "Welcome to ScopeGate" from ada@example.com,
 *                  "Invoice March" from billing@vendor.io
 *   - calendar     primary: "Daily standup"
 */
import {
  buildRfc822,
  EXPORT_MIMES,
  isTextMime,
  type CalendarCreateInput,
  type CalendarEventInfo,
  type DriveFileInfo,
  type DriveReadResult,
  type GmailMessageInfo,
  type GmailSendInput,
  type GmailSendResult,
  type GoogleBridgeClient,
} from "./client.js";

interface MockDriveFile extends DriveFileInfo {
  /** Stored UTF-8 text (absent for binary files). */
  content?: string;
}

interface MockGmailMessage extends GmailMessageInfo {
  /** RFC 822 raw message (set by gmail_send; undefined for seeded mail). */
  raw?: string;
}

interface MockCalendarEvent extends CalendarEventInfo {
  calendarId: string;
}

export interface MockSeed {
  files?: MockDriveFile[];
}

function defaultFiles(): MockDriveFile[] {
  return [
    {
      id: "mock-file-1",
      name: "Roadmap.md",
      mimeType: "text/markdown",
      size: 36,
      modifiedTime: "2026-01-15T10:00:00.000Z",
      content: "# Roadmap\n\n- ship google-bridge",
    },
    {
      id: "mock-file-2",
      name: "Team budget",
      mimeType: "application/vnd.google-apps.spreadsheet",
      modifiedTime: "2026-01-16T11:00:00.000Z",
      content: "item,cost\nbridge,0",
    },
    {
      id: "mock-file-3",
      name: "Spec doc",
      mimeType: "application/vnd.google-apps.document",
      modifiedTime: "2026-01-17T12:00:00.000Z",
      content: "Bridge spec body",
    },
    {
      id: "mock-file-4",
      name: "logo.pdf",
      mimeType: "application/pdf",
      size: 204800,
      modifiedTime: "2026-01-18T13:00:00.000Z",
    },
  ];
}

function defaultMessages(): MockGmailMessage[] {
  return [
    {
      id: "mock-msg-1",
      threadId: "mock-thread-1",
      subject: "Welcome to ScopeGate",
      from: "ada@example.com",
      date: "2026-01-10T09:00:00.000Z",
      snippet: "Welcome aboard…",
    },
    {
      id: "mock-msg-2",
      threadId: "mock-thread-2",
      subject: "Invoice March",
      from: "billing@vendor.io",
      date: "2026-03-01T08:30:00.000Z",
      snippet: "Your invoice for March is attached",
    },
  ];
}

function defaultEvents(): MockCalendarEvent[] {
  return [
    {
      id: "mock-evt-1",
      calendarId: "primary",
      summary: "Daily standup",
      start: "2026-03-02T09:00:00.000Z",
      end: "2026-03-02T09:15:00.000Z",
      status: "confirmed",
    },
  ];
}

export class MockGoogleClient implements GoogleBridgeClient {
  private seq = 0;
  private readonly files = new Map<string, MockDriveFile>();
  private readonly messages: MockGmailMessage[] = [];
  private readonly events: MockCalendarEvent[] = [];

  constructor(seed: MockSeed = {}) {
    for (const f of [...defaultFiles(), ...(seed.files ?? [])]) this.files.set(f.id, f);
    this.messages.push(...defaultMessages());
    this.events.push(...defaultEvents());
  }

  private nextId(prefix: string): string {
    this.seq += 1;
    return `${prefix}-${this.seq}`;
  }

  async connect(): Promise<void> {}
  async close(): Promise<void> {}

  // --- drive ---

  private static fileInfo(f: MockDriveFile): DriveFileInfo {
    return {
      id: f.id,
      name: f.name,
      mimeType: f.mimeType,
      ...(f.size !== undefined ? { size: f.size } : {}),
      ...(f.modifiedTime !== undefined ? { modifiedTime: f.modifiedTime } : {}),
    };
  }

  private resolveFile(fileId: string): MockDriveFile {
    const file = this.files.get(fileId);
    if (file !== undefined) return file;
    throw new Error(
      `File not found: "${fileId}" — pass a file id returned by drive_list or drive_search`,
    );
  }

  async driveList(filter: { query?: string; limit?: number }): Promise<DriveFileInfo[]> {
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    let files = [...this.files.values()];
    if (filter.query !== undefined && filter.query.trim() !== "") {
      const needle = filter.query.trim().toLowerCase();
      files = files.filter((f) => f.name.toLowerCase().includes(needle));
    }
    return files
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit)
      .map(MockGoogleClient.fileInfo);
  }

  async driveSearch(filter: { query: string; limit?: number }): Promise<DriveFileInfo[]> {
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    const needle = filter.query.trim().toLowerCase();
    return [...this.files.values()]
      .filter(
        (f) =>
          f.name.toLowerCase().includes(needle) ||
          (f.content !== undefined && f.content.toLowerCase().includes(needle)),
      )
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit)
      .map(MockGoogleClient.fileInfo);
  }

  async driveRead(fileId: string): Promise<DriveReadResult> {
    const file = this.resolveFile(fileId);
    if (EXPORT_MIMES[file.mimeType] !== undefined || isTextMime(file.mimeType)) {
      return { ...MockGoogleClient.fileInfo(file), content: file.content ?? "" };
    }
    if (file.mimeType.startsWith("application/vnd.google-apps.")) {
      return {
        ...MockGoogleClient.fileInfo(file),
        note: `Google Workspace type '${file.mimeType}' is not text-exportable — drive_read exports Docs, Sheets and Slides only`,
      };
    }
    return {
      ...MockGoogleClient.fileInfo(file),
      note: `binary file ('${file.mimeType}') — content not returned by drive_read`,
    };
  }

  // --- gmail ---

  async gmailSend(input: GmailSendInput): Promise<GmailSendResult> {
    // buildRfc822 validates header injection exactly like the real client.
    const raw = buildRfc822(input);
    const id = this.nextId("mock-msg");
    const threadId = this.nextId("mock-thread");
    this.messages.push({
      id,
      threadId,
      subject: input.subject,
      from: "me",
      date: new Date().toISOString(),
      snippet: input.body.slice(0, 100),
      raw,
    });
    return { id, threadId, labelIds: ["SENT"] };
  }

  async gmailList(filter: { query?: string; limit?: number }): Promise<GmailMessageInfo[]> {
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    let msgs = [...this.messages];
    if (filter.query !== undefined && filter.query.trim() !== "") {
      const needle = filter.query.trim().toLowerCase();
      msgs = msgs.filter(
        (m) =>
          m.subject.toLowerCase().includes(needle) ||
          m.from.toLowerCase().includes(needle) ||
          m.snippet.toLowerCase().includes(needle),
      );
    }
    return msgs
      .sort((a, b) => b.date.localeCompare(a.date))
      .slice(0, limit)
      .map((m) => ({
        id: m.id,
        threadId: m.threadId,
        subject: m.subject,
        from: m.from,
        date: m.date,
        snippet: m.snippet,
      }));
  }

  // --- calendar ---

  async calendarList(filter: {
    calendarId?: string;
    limit?: number;
    timeMin?: string;
  }): Promise<CalendarEventInfo[]> {
    const calendarId = filter.calendarId ?? "primary";
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    let events = this.events.filter((e) => e.calendarId === calendarId);
    if (filter.timeMin !== undefined && filter.timeMin !== "") {
      // Same semantics as the API: events not yet ended at timeMin.
      events = events.filter((e) => e.end >= filter.timeMin!);
    }
    return events
      .sort((a, b) => a.start.localeCompare(b.start))
      .slice(0, limit)
      .map((e) => {
        const { calendarId: _calendarId, ...info } = e;
        return info;
      });
  }

  async calendarCreate(input: CalendarCreateInput): Promise<CalendarEventInfo> {
    const event: MockCalendarEvent = {
      id: this.nextId("mock-evt"),
      calendarId: input.calendarId ?? "primary",
      summary: input.summary,
      start: input.start,
      end: input.end,
      status: "confirmed",
      ...(input.description !== undefined ? { description: input.description } : {}),
      ...(input.attendees !== undefined && input.attendees.length > 0
        ? { attendees: [...input.attendees] }
        : {}),
    };
    this.events.push(event);
    const { calendarId: _calendarId, ...info } = event;
    return info;
  }
}

export function createMockClient(seed?: MockSeed): MockGoogleClient {
  return new MockGoogleClient(seed);
}
