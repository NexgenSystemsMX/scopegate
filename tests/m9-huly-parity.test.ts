/**
 * M9 — huly-bridge parity tests: the seven capabilities added on top of the
 * EPIC-14 surface, driven over a linked InMemoryTransport pair against the
 * in-memory mock client (same boot pattern as huly-bridge.test.ts):
 *
 *   1. tracker_read_issue      — single issue WITH its markdown description
 *   2. tracker_read_comments   — issue comments (author, date, markdown body)
 *   3. chunter_edit_message    — edit an existing message (bot checklist)
 *   4. chunter_post_message    — optional `thinking` flag (💭 prefix)
 *   5. tracker_search_issues   — optional `assignee` filter
 *   6. tracker_update_issue    — `milestone` + `dueDate` fields
 *   7. tracker_create_issue    — optional initial `status`
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createMockClient } from "../src/upstreams/huly-bridge/mock-client.js";
import { createBridgeServer } from "../src/upstreams/huly-bridge/server.js";

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
  client = new Client({ name: "m9-huly-parity-test", version: "1.0.0" }, { capabilities: {} });
  server = createBridgeServer(createMockClient());
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterEach(async () => {
  await client.close().catch(() => undefined);
  await server.close().catch(() => undefined);
});

describe("M9.1 tracker_read_issue", () => {
  it("returns the full issue including its markdown description", async () => {
    parse(
      await callTool("tracker_create_issue", {
        project: "DEMO",
        title: "Readable",
        description: "# Spec\n\nBody **bold**",
        priority: "high",
        assignee: "mock-person-1",
      }),
    );
    const issue = parse(await callTool("tracker_read_issue", { issueId: "DEMO-1" }));
    expect(issue.id).toBeTruthy();
    expect(issue.identifier).toBe("DEMO-1");
    expect(issue.title).toBe("Readable");
    expect(issue.description).toBe("# Spec\n\nBody **bold**");
    expect(issue.status).toBe("backlog");
    expect(issue.priority).toBe("high");
    expect(issue.assignee).toBe("mock-person-1");
    expect(issue.project).toBe("DEMO");
  });

  it("reflects later updates and rejects unknown issues actionably", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "x" }));
    parse(await callTool("tracker_update_issue", { issueId: "DEMO-1", fields: { status: "done" } }));
    const issue = parse(await callTool("tracker_read_issue", { issueId: "DEMO-1" }));
    expect(issue.status).toBe("done");
    const err = parseError(await callTool("tracker_read_issue", { issueId: "NOPE-9" }));
    expect(err).toMatch(/issue not found/i);
    expect(err).toMatch(/tracker_search_issues/);
    const missing = parseError(await callTool("tracker_read_issue", {}));
    expect(missing).toMatch(/"issueId"/);
  });
});

describe("M9.2 tracker_read_comments", () => {
  it("lists comments oldest-first with author, date and markdown body", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "commented" }));
    parse(await callTool("tracker_comment_issue", { issueId: "DEMO-1", message: "first **note**" }));
    parse(await callTool("tracker_comment_issue", { issueId: "DEMO-1", message: "second" }));
    const res = parse(await callTool("tracker_read_comments", { issueId: "DEMO-1" }));
    expect(res.count).toBe(2);
    expect(res.comments[0]).toMatchObject({ author: "mock-bot", text: "first **note**" });
    expect(res.comments[0].createdAt).toBeGreaterThan(0);
    expect(res.comments[1].text).toBe("second");
    const limited = parse(await callTool("tracker_read_comments", { issueId: "DEMO-1", limit: 1 }));
    expect(limited.count).toBe(1);
    expect(limited.comments[0].text).toBe("second");
  });

  it("is actionable for unknown issues", async () => {
    const err = parseError(await callTool("tracker_read_comments", { issueId: "NOPE-9" }));
    expect(err).toMatch(/issue not found/i);
  });
});

describe("M9.3 chunter_edit_message", () => {
  it("replaces the body of an existing message", async () => {
    const posted = parse(await callTool("chunter_post_message", { channel: "general", message: "checklist v1" }));
    const edited = parse(
      await callTool("chunter_edit_message", { channel: "general", messageId: posted.id, content: "checklist v2" }),
    );
    expect(edited.id).toBe(posted.id);
    expect(edited.channel).toBe("general");
    const list = parse(await callTool("chunter_list_messages", { channel: "general" }));
    expect(list.messages[0].text).toBe("checklist v2");
  });

  it("edits thread replies too and is actionable for unknown ids/channels", async () => {
    const parent = parse(await callTool("chunter_post_message", { channel: "general", message: "parent" }));
    const reply = parse(
      await callTool("chunter_post_message", { channel: "general", message: "reply", thread: parent.id }),
    );
    parse(await callTool("chunter_edit_message", { channel: "general", messageId: reply.id, content: "reply v2" }));
    const thread = parse(await callTool("chunter_list_messages", { channel: "general", thread: parent.id }));
    expect(thread.messages[1].text).toBe("reply v2");

    const errId = parseError(
      await callTool("chunter_edit_message", { channel: "general", messageId: "nope", content: "x" }),
    );
    expect(errId).toMatch(/message not found/i);
    expect(errId).toMatch(/chunter_list_messages/);
    // A message that lives in another channel must not be editable through this one.
    const errChannel = parseError(
      await callTool("chunter_edit_message", { channel: "random", messageId: parent.id, content: "x" }),
    );
    expect(errChannel).toMatch(/message not found/i);
    const missing = parseError(await callTool("chunter_edit_message", { channel: "general", messageId: parent.id }));
    expect(missing).toMatch(/"content"/);
  });
});

describe("M9.4 chunter_post_message thinking flag", () => {
  it("prefixes the body with 💭 when thinking is true", async () => {
    parse(await callTool("chunter_post_message", { channel: "general", message: "reasoning…", thinking: true }));
    parse(await callTool("chunter_post_message", { channel: "general", message: "plain" }));
    const list = parse(await callTool("chunter_list_messages", { channel: "general" }));
    expect(list.messages[0].text).toBe("💭 reasoning…");
    expect(list.messages[1].text).toBe("plain");
  });

  it("rejects a non-boolean thinking flag", async () => {
    const err = parseError(await callTool("chunter_post_message", { channel: "general", message: "x", thinking: "yes" }));
    expect(err).toMatch(/"thinking"/);
    expect(err).toMatch(/boolean/);
  });
});

describe("M9.5 tracker_search_issues assignee filter", () => {
  it("filters by assignee ref", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "for ada", assignee: "mock-person-1" }));
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "for grace", assignee: "mock-person-2" }));
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "unassigned" }));
    const res = parse(await callTool("tracker_search_issues", { assignee: "mock-person-1" }));
    expect(res.count).toBe(1);
    expect(res.issues[0]).toMatchObject({ identifier: "DEMO-1", assignee: "mock-person-1" });
    const combined = parse(await callTool("tracker_search_issues", { assignee: "mock-person-2", query: "grace" }));
    expect(combined.count).toBe(1);
  });
});

describe("M9.6 tracker_update_issue milestone + dueDate", () => {
  it("updates milestone and dueDate and reports them in `updated`", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "planned" }));
    const res = parse(
      await callTool("tracker_update_issue", {
        issueId: "DEMO-1",
        fields: { milestone: "tracker:milestone:M1", dueDate: "2026-08-01" },
      }),
    );
    expect(res.updated).toEqual(expect.arrayContaining(["milestone", "dueDate"]));
    const cleared = parse(await callTool("tracker_update_issue", { issueId: "DEMO-1", fields: { dueDate: "" } }));
    expect(cleared.updated).toContain("dueDate");
  });

  it("rejects an unparseable dueDate actionably", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "x" }));
    const err = parseError(
      await callTool("tracker_update_issue", { issueId: "DEMO-1", fields: { dueDate: "next friday-ish" } }),
    );
    expect(err).toMatch(/invalid duedate/i);
    expect(err).toMatch(/ISO date/);
  });
});

describe("M9.7 tracker_create_issue initial status", () => {
  it("creates in the given status instead of backlog", async () => {
    const created = parse(
      await callTool("tracker_create_issue", { project: "DEMO", title: "started", status: "in_progress" }),
    );
    expect(created.identifier).toBe("DEMO-1");
    const issue = parse(await callTool("tracker_read_issue", { issueId: "DEMO-1" }));
    expect(issue.status).toBe("in_progress");
    const found = parse(await callTool("tracker_search_issues", { status: "in_progress" }));
    expect(found.count).toBe(1);
  });

  it("still defaults to backlog and rejects an invalid status", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "default" }));
    const issue = parse(await callTool("tracker_read_issue", { issueId: "DEMO-1" }));
    expect(issue.status).toBe("backlog");
    const err = parseError(await callTool("tracker_create_issue", { project: "DEMO", title: "bad", status: "nope" }));
    expect(err).toMatch(/invalid status/i);
  });
});
