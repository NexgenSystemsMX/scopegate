/**
 * google-bridge tests (EPIC-18): the MCP server (createBridgeServer) is driven
 * over a linked InMemoryTransport pair against the in-memory mock client —
 * no network, no Google credentials, no SCOPEGATE_HOME involved.
 *
 * Covers the frozen contract:
 *   - listTools exposes exactly the 7 bare tool names
 *   - happy path of all 7 tools (write→read round-trips through the mock)
 *   - drive_read: text round-trip, google-apps export, binary note, 1 MiB cap
 *   - gmail_send: RFC 822 construction (headers, Cc, RFC 2047 subject, CRLF
 *     injection rejected) and base64url upload in the real client
 *   - actionable isError results (unknown tool/file, missing args, bad dates)
 *   - real client request shape + 401/403/404 error mapping (injected fetch)
 *   - factory selection (mock vs real) and secret hygiene: the token never
 *     appears in tool output, schemas, or error messages
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildRfc822,
  capDriveContent,
  createGoogleClient,
  DRIVE_READ_MAX_CHARS,
  RealGoogleClient,
} from "../src/upstreams/google-bridge/client.js";
import { createMockClient } from "../src/upstreams/google-bridge/mock-client.js";
import { buildToolList, createBridgeServer } from "../src/upstreams/google-bridge/server.js";

const EXPECTED_TOOLS = [
  "drive_list",
  "drive_search",
  "drive_read",
  "gmail_send",
  "gmail_list",
  "calendar_list",
  "calendar_create",
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
  client = new Client({ name: "google-bridge-test", version: "1.0.0" }, { capabilities: {} });
  server = createBridgeServer(createMockClient());
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterEach(async () => {
  await client.close().catch(() => undefined);
  await server.close().catch(() => undefined);
});

describe("google-bridge tools list", () => {
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

describe("drive tools", () => {
  it("drive_list returns the seeded files sorted by name", async () => {
    const res = parse(await callTool("drive_list"));
    expect(res.count).toBe(4);
    expect(res.files.map((f: { name: string }) => f.name)).toEqual([
      "logo.pdf",
      "Roadmap.md",
      "Spec doc",
      "Team budget",
    ]);
    expect(res.files[1]).toMatchObject({ id: "mock-file-1", mimeType: "text/markdown" });
  });

  it("drive_list filters by name substring and honors limit", async () => {
    const res = parse(await callTool("drive_list", { query: "roadmap" }));
    expect(res.count).toBe(1);
    expect(res.files[0].id).toBe("mock-file-1");
    const limited = parse(await callTool("drive_list", { limit: 2 }));
    expect(limited.count).toBe(2);
  });

  it("drive_search finds by content and by name; query is required", async () => {
    const byContent = parse(await callTool("drive_search", { query: "ship google-bridge" }));
    expect(byContent.count).toBe(1);
    expect(byContent.files[0].id).toBe("mock-file-1");
    const byName = parse(await callTool("drive_search", { query: "budget" }));
    expect(byName.files[0].id).toBe("mock-file-2");
    const noHit = parse(await callTool("drive_search", { query: "zzz-no-match" }));
    expect(noHit.count).toBe(0);
    const missing = parseError(await callTool("drive_search", {}));
    expect(missing).toMatch(/"query"/);
    expect(missing).toMatch(/drive_list/);
  });

  it("drive_read round-trips a raw text file", async () => {
    const res = parse(await callTool("drive_read", { fileId: "mock-file-1" }));
    expect(res).toMatchObject({ id: "mock-file-1", name: "Roadmap.md", mimeType: "text/markdown" });
    expect(res.content).toBe("# Roadmap\n\n- ship google-bridge");
    expect(res.truncated).toBeUndefined();
  });

  it("drive_read exports Google Docs/Sheets as text", async () => {
    const sheet = parse(await callTool("drive_read", { fileId: "mock-file-2" }));
    expect(sheet.mimeType).toBe("application/vnd.google-apps.spreadsheet");
    expect(sheet.content).toBe("item,cost\nbridge,0");
    const doc = parse(await callTool("drive_read", { fileId: "mock-file-3" }));
    expect(doc.content).toBe("Bridge spec body");
  });

  it("drive_read returns metadata + note for binary files, no content", async () => {
    const res = parse(await callTool("drive_read", { fileId: "mock-file-4" }));
    expect(res.mimeType).toBe("application/pdf");
    expect(res.content).toBeUndefined();
    expect(res.note).toMatch(/binary file/i);
  });

  it("drive_read is actionable for an unknown file id", async () => {
    const err = parseError(await callTool("drive_read", { fileId: "nope" }));
    expect(err).toMatch(/file not found/i);
    expect(err).toMatch(/drive_list/);
  });

  it("drive_read caps content at 1 MiB and flags truncated", async () => {
    // A big file seeded into a dedicated mock (the cap lives in the tools
    // layer, shared by both backends).
    const big = "x".repeat(DRIVE_READ_MAX_CHARS + 500);
    const cappedClient = new Client({ name: "cap-test", version: "1.0.0" }, { capabilities: {} });
    const cappedServer = createBridgeServer(
      createMockClient({ files: [{ id: "big-1", name: "big.txt", mimeType: "text/plain", content: big }] }),
    );
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await Promise.all([cappedServer.connect(st), cappedClient.connect(ct)]);
    try {
      const res = await cappedClient.callTool({ name: "drive_read", arguments: { fileId: "big-1" } });
      expect(res.isError).not.toBe(true);
      const out = JSON.parse((res.content as Array<{ type: string; text: string }>)[0]!.text);
      expect(out.truncated).toBe(true);
      expect(out.content).toHaveLength(DRIVE_READ_MAX_CHARS);
      expect(out.note).toMatch(/capped at/);
    } finally {
      await cappedClient.close().catch(() => undefined);
      await cappedServer.close().catch(() => undefined);
    }
    // And the shared helper itself: exact boundary behavior.
    expect(capDriveContent("abc")).toEqual({ content: "abc", truncated: false });
    expect(capDriveContent("y".repeat(DRIVE_READ_MAX_CHARS)).truncated).toBe(false);
    expect(capDriveContent("y".repeat(DRIVE_READ_MAX_CHARS + 1)).truncated).toBe(true);
  });
});

describe("gmail tools", () => {
  it("gmail_send returns an id and the message becomes listable", async () => {
    const res = parse(
      await callTool("gmail_send", { to: "grace@example.com", subject: "Ship it", body: "The bridge is ready." }),
    );
    expect(res.id).toBeTruthy();
    expect(res.threadId).toBeTruthy();
    expect(res.labelIds).toContain("SENT");
    const found = parse(await callTool("gmail_list", { query: "Ship it" }));
    expect(found.count).toBe(1);
    expect(found.messages[0].subject).toBe("Ship it");
  });

  it("gmail_send requires to/subject/body", async () => {
    const err = parseError(await callTool("gmail_send", { subject: "x", body: "y" }));
    expect(err).toMatch(/"to"/);
  });

  it("gmail_list returns seeded messages newest-first and filters by query", async () => {
    const all = parse(await callTool("gmail_list"));
    expect(all.count).toBe(2);
    expect(all.messages[0].subject).toBe("Invoice March");
    expect(all.messages[1].subject).toBe("Welcome to ScopeGate");
    const filtered = parse(await callTool("gmail_list", { query: "billing" }));
    expect(filtered.count).toBe(1);
    expect(filtered.messages[0].from).toBe("billing@vendor.io");
  });

  it("buildRfc822 builds a header-safe MIME message", () => {
    const raw = buildRfc822({ to: "a@b.c", subject: "Hola", body: "line1\nline2" });
    expect(raw).toContain("To: a@b.c\r\n");
    expect(raw).toContain("Subject: Hola\r\n");
    expect(raw).toContain('Content-Type: text/plain; charset="UTF-8"');
    expect(raw).not.toContain("Cc:");
    expect(raw.endsWith("\r\n\r\nline1\nline2")).toBe(true);

    const withCc = buildRfc822({ to: "a@b.c", cc: "d@e.f", subject: "s", body: "b" });
    expect(withCc).toContain("Cc: d@e.f\r\n");
  });

  it("buildRfc822 RFC2047-encodes non-ASCII subjects", () => {
    const raw = buildRfc822({ to: "a@b.c", subject: "Reunión mañana", body: "b" });
    expect(raw).toMatch(/Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=\r\n/);
    expect(raw).not.toContain("Reunión");
  });

  it("buildRfc822 rejects CRLF header injection", async () => {
    expect(() => buildRfc822({ to: "a@b.c\r\nBcc: evil@x.y", subject: "s", body: "b" })).toThrow(/"to"/);
    expect(() => buildRfc822({ to: "a@b.c", subject: "s\nBcc: evil@x.y", body: "b" })).toThrow(/"subject"/);
    expect(() => buildRfc822({ to: "a@b.c", cc: "d@e.f\r\nBcc: evil@x.y", subject: "s", body: "b" })).toThrow(
      /"cc"/,
    );
    const err = parseError(
      await callTool("gmail_send", { to: "a@b.c\nBcc: evil@x.y", subject: "s", body: "b" }),
    );
    expect(err).toMatch(/"to"/);
  });
});

describe("calendar tools", () => {
  it("calendar_list returns the seeded standup of the primary calendar", async () => {
    const res = parse(await callTool("calendar_list"));
    expect(res.count).toBe(1);
    expect(res.events[0]).toMatchObject({ summary: "Daily standup", status: "confirmed" });
  });

  it("calendar_list honors timeMin and calendarId", async () => {
    // The seeded standup ends 2026-03-02T09:15Z — a later timeMin excludes it.
    const later = parse(await callTool("calendar_list", { timeMin: "2026-03-02T10:00:00.000Z" }));
    expect(later.count).toBe(0);
    const earlier = parse(await callTool("calendar_list", { timeMin: "2026-03-01T00:00:00.000Z" }));
    expect(earlier.count).toBe(1);
    const other = parse(await callTool("calendar_list", { calendarId: "team@group.calendar.google.com" }));
    expect(other.count).toBe(0);
    const badTime = parseError(await callTool("calendar_list", { timeMin: "not-a-date" }));
    expect(badTime).toMatch(/timeMin/);
  });

  it("calendar_create creates an event that becomes listable", async () => {
    const created = parse(
      await callTool("calendar_create", {
        summary: "Sprint review",
        start: "2026-03-05T14:00:00.000Z",
        end: "2026-03-05T15:00:00.000Z",
        attendees: ["ada@example.com", "grace@example.com"],
        description: "Demo of the bridge",
      }),
    );
    expect(created.id).toBeTruthy();
    expect(created.status).toBe("confirmed");
    expect(created.attendees).toEqual(["ada@example.com", "grace@example.com"]);
    const list = parse(await callTool("calendar_list", { timeMin: "2026-03-03T00:00:00.000Z" }));
    expect(list.count).toBe(1);
    expect(list.events[0].summary).toBe("Sprint review");
  });

  it("calendar_create validates required args and dates", async () => {
    const missing = parseError(await callTool("calendar_create", { start: "2026-03-05T14:00:00.000Z" }));
    expect(missing).toMatch(/"summary"/);
    const badStart = parseError(
      await callTool("calendar_create", { summary: "x", start: "tomorrow", end: "2026-03-05T15:00:00.000Z" }),
    );
    expect(badStart).toMatch(/"start"/);
    expect(badStart).toMatch(/ISO 8601/);
    const badAttendees = parseError(
      await callTool("calendar_create", {
        summary: "x",
        start: "2026-03-05T14:00:00.000Z",
        end: "2026-03-05T15:00:00.000Z",
        attendees: ["ok@x.y", 42],
      }),
    );
    expect(badAttendees).toMatch(/"attendees"/);
  });

  it("calendar_create accepts all-day (date-only) events", async () => {
    const created = parse(
      await callTool("calendar_create", { summary: "Holiday", start: "2026-05-01", end: "2026-05-02" }),
    );
    expect(created.start).toBe("2026-05-01");
  });
});

describe("MCP error contract", () => {
  it("unknown tool returns an actionable isError", async () => {
    const err = parseError(await callTool("drive_delete"));
    expect(err).toMatch(/unknown tool/i);
    expect(err).toMatch(/drive_list/);
  });

  it("invalid limit is rejected", async () => {
    const err = parseError(await callTool("drive_list", { limit: -3 }));
    expect(err).toMatch(/limit/);
  });
});

describe("real client (injected fetch)", () => {
  type FetchCall = { url: string; init?: Record<string, unknown> };

  function recordingFetch(responder: (call: FetchCall) => { status: number; body?: unknown; text?: string }) {
    const calls: FetchCall[] = [];
    const fetchFn = async (url: string, init?: Record<string, unknown>) => {
      calls.push({ url, init });
      const r = responder({ url, init });
      return {
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        json: async () => r.body ?? {},
        text: async () => r.text ?? "",
      };
    };
    return { calls, fetchFn };
  }

  it("drive_list hits the Drive API with q/pageSize/fields and the bearer token", async () => {
    const { calls, fetchFn } = recordingFetch(() => ({
      status: 200,
      body: { files: [{ id: "f1", name: "a.txt", mimeType: "text/plain", size: "12" }] },
    }));
    const real = new RealGoogleClient({ token: "tok-123", fetchFn });
    const files = await real.driveList({ query: "a", limit: 5 });
    expect(files).toEqual([{ id: "f1", name: "a.txt", mimeType: "text/plain", size: 12 }]);
    const call = calls[0]!;
    const url = new URL(call.url);
    expect(`${url.origin}${url.pathname}`).toBe("https://www.googleapis.com/drive/v3/files");
    expect(url.searchParams.get("q")).toBe("name contains 'a' and trashed = false");
    expect(url.searchParams.get("pageSize")).toBe("5");
    expect(url.searchParams.get("fields")).toBe("files(id,name,mimeType,size,modifiedTime)");
    expect((call.init!.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
  });

  it("gmail_send uploads the base64url RFC 822 raw message", async () => {
    const { calls, fetchFn } = recordingFetch(() => ({ status: 200, body: { id: "m1", threadId: "t1" } }));
    const real = new RealGoogleClient({ token: "tok-123", fetchFn });
    const res = await real.gmailSend({ to: "a@b.c", subject: "Hi", body: "body text" });
    expect(res).toMatchObject({ id: "m1", threadId: "t1" });
    const body = JSON.parse((calls[0]!.init as { body: string }).body) as { raw: string };
    expect(Buffer.from(body.raw, "base64url").toString("utf8")).toBe(
      buildRfc822({ to: "a@b.c", subject: "Hi", body: "body text" }),
    );
  });

  it("drive_read exports Google Docs via the export endpoint", async () => {
    const { calls, fetchFn } = recordingFetch(({ url }) => {
      if (url.includes("/export")) return { status: 200, text: "exported text" };
      return { status: 200, body: { id: "d1", name: "Doc", mimeType: "application/vnd.google-apps.document" } };
    });
    const real = new RealGoogleClient({ token: "tok-123", fetchFn });
    const res = await real.driveRead("d1");
    expect(res.content).toBe("exported text");
    expect(calls.some((c) => c.url.includes("/export?") && c.url.includes("text%2Fplain"))).toBe(true);
  });

  it("maps 401/403/404 to actionable errors without the token", async () => {
    for (const [status, pattern] of [
      [401, /rejected the access token.*re-mint/is],
      [403, /insufficient scope.*auth\.scopes/is],
      [404, /not found.*calendar_list/is],
    ] as const) {
      const { fetchFn } = recordingFetch(() => ({ status, body: { error: { message: "diag detail" } } }));
      const real = new RealGoogleClient({ token: "tok-SECRET-123", fetchFn });
      const err = await real.calendarList({}).then(() => null, (e: unknown) => e as Error);
      expect(err!.message).toMatch(pattern);
      expect(err!.message).toContain("diag detail");
      expect(err!.message).not.toContain("tok-SECRET-123");
    }
  });
});

describe("factory + secret hygiene", () => {
  it("GOOGLE_MOCK=1 selects the mock; live env selects the real client", () => {
    expect(createGoogleClient({ GOOGLE_MOCK: "1" }).constructor.name).toBe("MockGoogleClient");
    const real = createGoogleClient({ GOOGLE_ACCESS_TOKEN: "tok" });
    expect(real.constructor.name).toBe("RealGoogleClient");
    const custom = createGoogleClient({ GOOGLE_ACCESS_TOKEN: "tok", GOOGLE_API_URL: "https://g.example.internal/" });
    expect(custom.constructor.name).toBe("RealGoogleClient");
  });

  it("missing live env is an actionable error mentioning only variable names", () => {
    expect(() => createGoogleClient({})).toThrow(/GOOGLE_ACCESS_TOKEN/);
    expect(() => createGoogleClient({})).toThrow(/GOOGLE_MOCK/);
  });

  it("no tool output, schema or error leaks the token", async () => {
    const token = "ya29.super-secret-token";
    process.env.GOOGLE_ACCESS_TOKEN = token;
    try {
      const outputs: string[] = [JSON.stringify(buildToolList())];
      outputs.push(JSON.stringify(await callTool("drive_list")));
      outputs.push(JSON.stringify(await callTool("drive_read", { fileId: "nope" })));
      outputs.push(JSON.stringify(await callTool("gmail_send", { to: "a@b.c", subject: "s", body: "b" })));
      outputs.push(JSON.stringify(await callTool("calendar_list")));
      outputs.push(JSON.stringify(await client.listTools()));
      try {
        createGoogleClient({ GOOGLE_API_URL: "https://g.example" });
      } catch (err) {
        outputs.push(String(err));
      }
      for (const out of outputs) {
        expect(out).not.toContain(token);
      }
    } finally {
      delete process.env.GOOGLE_ACCESS_TOKEN;
    }
  });
});
