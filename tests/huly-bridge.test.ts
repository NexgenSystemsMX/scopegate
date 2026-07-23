/**
 * huly-bridge tests (EPIC-14): the MCP server (createBridgeServer) is driven
 * over a linked InMemoryTransport pair against the in-memory mock client —
 * no network, no Huly instance, no SCOPEGATE_HOME involved.
 *
 * Covers the frozen contract:
 *   - listTools exposes exactly the 13 bare tool names
 *   - happy path of all 13 tools (write→read round-trips through the mock)
 *   - actionable isError results (unknown issue/channel/document/teamspace,
 *     missing required args, unknown tool)
 *   - markup conversion: markdown ↔ Huly PM-JSON round-trip, plain-text fallback
 *   - factory selection (mock vs real) and secret hygiene: the token never
 *     appears in tool output, schemas, or error messages
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createHulyClient,
  hulyMarkupToMarkdown,
  markdownToHulyMarkup,
  normalizeEndpoint,
} from "../src/upstreams/huly-bridge/client.js";
import { createMockClient } from "../src/upstreams/huly-bridge/mock-client.js";
import { buildToolList, createBridgeServer } from "../src/upstreams/huly-bridge/server.js";

const EXPECTED_TOOLS = [
  "tracker_create_issue",
  "tracker_update_issue",
  "tracker_comment_issue",
  "tracker_search_issues",
  "tracker_list_projects",
  "documents_create",
  "documents_read",
  "documents_update",
  "documents_list",
  "chunter_post_message",
  "chunter_list_channels",
  "chunter_list_messages",
  "contact_list_persons",
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
  client = new Client({ name: "huly-bridge-test", version: "1.0.0" }, { capabilities: {} });
  server = createBridgeServer(createMockClient());
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
});

afterEach(async () => {
  await client.close().catch(() => undefined);
  await server.close().catch(() => undefined);
});

describe("huly-bridge tools list", () => {
  it("exposes exactly the 13 frozen bare tool names", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...EXPECTED_TOOLS].sort());
    expect(buildToolList()).toHaveLength(13);
    for (const tool of tools) {
      expect(tool.description).toBeTruthy();
      expect(tool.inputSchema).toBeTruthy();
    }
  });
});

describe("tracker tools", () => {
  it("tracker_list_projects returns the seeded DEMO project", async () => {
    const res = parse(await callTool("tracker_list_projects"));
    expect(res.projects).toHaveLength(1);
    expect(res.projects[0]).toMatchObject({ identifier: "DEMO", name: "Demo Project", issues: 0 });
  });

  it("tracker_create_issue creates DEMO-1 with defaults", async () => {
    const res = parse(await callTool("tracker_create_issue", { project: "DEMO", title: "First issue" }));
    expect(res.identifier).toBe("DEMO-1");
    expect(res.id).toBeTruthy();
    expect(res.title).toBe("First issue");
    expect(res.updatedAt).toBeGreaterThan(0);
  });

  it("tracker_create_issue accepts priority by name and by number", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "p-name", priority: "urgent" }));
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "p-num", priority: 2 }));
    const byName = parse(await callTool("tracker_search_issues", { query: "p-name" }));
    expect(byName.issues[0].priority).toBe("urgent");
    const byNum = parse(await callTool("tracker_search_issues", { query: "p-num" }));
    expect(byNum.issues[0].priority).toBe("high");
  });

  it("tracker_update_issue updates status and title", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "to update" }));
    const res = parse(
      await callTool("tracker_update_issue", { issueId: "DEMO-1", fields: { status: "in_progress", title: "updated" } }),
    );
    expect(res.identifier).toBe("DEMO-1");
    expect(res.updated).toEqual(expect.arrayContaining(["status", "title"]));
    const found = parse(await callTool("tracker_search_issues", { query: "updated", status: "in_progress" }));
    expect(found.count).toBe(1);
  });

  it("tracker_update_issue rejects an empty fields object", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "x" }));
    const err = parseError(await callTool("tracker_update_issue", { issueId: "DEMO-1", fields: {} }));
    expect(err).toMatch(/nothing to update/i);
  });

  it("tracker_update_issue / tracker_comment_issue fail on unknown issue", async () => {
    const errUpdate = parseError(
      await callTool("tracker_update_issue", { issueId: "NOPE-9", fields: { title: "x" } }),
    );
    expect(errUpdate).toMatch(/issue not found/i);
    expect(errUpdate).toMatch(/tracker_search_issues/);
    const errComment = parseError(await callTool("tracker_comment_issue", { issueId: "NOPE-9", message: "hi" }));
    expect(errComment).toMatch(/issue not found/i);
  });

  it("tracker_comment_issue returns a comment id", async () => {
    parse(await callTool("tracker_create_issue", { project: "DEMO", title: "commentable" }));
    const res = parse(await callTool("tracker_comment_issue", { issueId: "DEMO-1", message: "looks good" }));
    expect(res.id).toBeTruthy();
    expect(res.issue).toBe("DEMO-1");
  });

  it("tracker_search_issues filters by project, status, text and limit", async () => {
    for (const title of ["alpha one", "alpha two", "beta three"]) {
      parse(await callTool("tracker_create_issue", { project: "DEMO", title }));
    }
    parse(await callTool("tracker_update_issue", { issueId: "DEMO-3", fields: { status: "done" } }));

    const alpha = parse(await callTool("tracker_search_issues", { query: "alpha" }));
    expect(alpha.count).toBe(2);
    const done = parse(await callTool("tracker_search_issues", { status: "done" }));
    expect(done.count).toBe(1);
    expect(done.issues[0].identifier).toBe("DEMO-3");
    const byProject = parse(await callTool("tracker_search_issues", { project: "DEMO", limit: 2 }));
    expect(byProject.count).toBe(2);
    const noHit = parse(await callTool("tracker_search_issues", { query: "zzz-no-match" }));
    expect(noHit.count).toBe(0);
  });

  it("tracker_create_issue validates required args and unknown project", async () => {
    const missing = parseError(await callTool("tracker_create_issue", { title: "no project" }));
    expect(missing).toMatch(/"project"/);
    expect(missing).toMatch(/tracker_list_projects/);
    const unknown = parseError(await callTool("tracker_create_issue", { project: "NOPE", title: "x" }));
    expect(unknown).toMatch(/project not found/i);
  });
});

describe("documents tools", () => {
  it("create → read round-trips markdown content", async () => {
    const created = parse(
      await callTool("documents_create", { teamspace: "general", title: "Spec", content: "# Title\n\nBody **bold**" }),
    );
    expect(created.id).toBeTruthy();
    expect(created.teamspace).toBe("general");
    const read = parse(await callTool("documents_read", { documentId: created.id }));
    expect(read.title).toBe("Spec");
    expect(read.content).toBe("# Title\n\nBody **bold**");
    expect(read.updatedAt).toBeGreaterThan(0);
  });

  it("documents_update replaces the content", async () => {
    const created = parse(await callTool("documents_create", { teamspace: "general", title: "Doc", content: "v1" }));
    const updated = parse(await callTool("documents_update", { documentId: created.id, content: "v2 content" }));
    expect(updated.id).toBe(created.id);
    const read = parse(await callTool("documents_read", { documentId: created.id }));
    expect(read.content).toBe("v2 content");
  });

  it("documents_list filters by teamspace and limit", async () => {
    parse(await callTool("documents_create", { teamspace: "general", title: "A", content: "a" }));
    parse(await callTool("documents_create", { teamspace: "general", title: "B", content: "b" }));
    const all = parse(await callTool("documents_list"));
    expect(all.count).toBe(2);
    const filtered = parse(await callTool("documents_list", { teamspace: "general", limit: 1 }));
    expect(filtered.count).toBe(1);
    expect(filtered.documents[0].teamspace).toBe("general");
  });

  it("errors are actionable for unknown teamspace / document", async () => {
    const errTeam = parseError(await callTool("documents_create", { teamspace: "void", title: "x", content: "y" }));
    expect(errTeam).toMatch(/teamspace not found/i);
    const errRead = parseError(await callTool("documents_read", { documentId: "nope" }));
    expect(errRead).toMatch(/document not found/i);
    expect(errRead).toMatch(/documents_list/);
    const errUpdate = parseError(await callTool("documents_update", { documentId: "nope", content: "z" }));
    expect(errUpdate).toMatch(/document not found/i);
  });
});

describe("chunter tools", () => {
  it("chunter_list_channels returns the seeded channels", async () => {
    const res = parse(await callTool("chunter_list_channels"));
    const names = res.channels.map((c: { name: string }) => c.name);
    expect(names).toEqual(["general", "random"]);
  });

  it("post → list round-trips the message text", async () => {
    const posted = parse(await callTool("chunter_post_message", { channel: "general", message: "hello **world**" }));
    expect(posted.id).toBeTruthy();
    expect(posted.channel).toBe("general");
    const list = parse(await callTool("chunter_list_messages", { channel: "general" }));
    expect(list.count).toBe(1);
    expect(list.messages[0].text).toBe("hello **world**");
  });

  it("thread replies are listed via the parent id", async () => {
    const parent = parse(await callTool("chunter_post_message", { channel: "general", message: "parent" }));
    const reply = parse(
      await callTool("chunter_post_message", { channel: "general", message: "reply", thread: parent.id }),
    );
    expect(reply.thread).toBe(parent.id);
    const thread = parse(await callTool("chunter_list_messages", { channel: "general", thread: parent.id }));
    expect(thread.count).toBe(2);
    expect(thread.messages[0].text).toBe("parent");
    expect(thread.messages[1].text).toBe("reply");
    // Channel view only shows top-level messages.
    const channelView = parse(await callTool("chunter_list_messages", { channel: "general" }));
    expect(channelView.count).toBe(1);
  });

  it("errors are actionable for unknown channel / thread parent", async () => {
    const errChannel = parseError(await callTool("chunter_post_message", { channel: "void", message: "x" }));
    expect(errChannel).toMatch(/channel not found/i);
    expect(errChannel).toMatch(/chunter_list_channels/);
    const errThread = parseError(
      await callTool("chunter_post_message", { channel: "general", message: "x", thread: "nope" }),
    );
    expect(errThread).toMatch(/thread parent message not found/i);
    const errList = parseError(await callTool("chunter_list_messages", { channel: "void" }));
    expect(errList).toMatch(/channel not found/i);
  });
});

describe("contact tools", () => {
  it("contact_list_persons returns the seeded persons", async () => {
    const res = parse(await callTool("contact_list_persons"));
    expect(res.count).toBe(2);
    const names = res.persons.map((p: { name: string }) => p.name);
    expect(names).toContain("Ada Lovelace");
    expect(names).toContain("Grace Hopper");
  });
});

describe("MCP error contract", () => {
  it("unknown tool returns an actionable isError", async () => {
    const err = parseError(await callTool("tracker_delete_issue"));
    expect(err).toMatch(/unknown tool/i);
    expect(err).toMatch(/tracker_create_issue/);
  });

  it("invalid limit is rejected", async () => {
    const err = parseError(await callTool("tracker_search_issues", { limit: -3 }));
    expect(err).toMatch(/limit/);
  });
});

describe("markup conversion", () => {
  it("markdown → PM-JSON markup → markdown round-trips", () => {
    const md = "# Hola\n\nTexto con **negrita** y lista:\n\n- uno\n- dos";
    const markup = markdownToHulyMarkup(md);
    expect(markup.startsWith("{")).toBe(true);
    expect(markup).toContain('"type":"doc"');
    const back = hulyMarkupToMarkdown(markup);
    expect(back).toContain("# Hola");
    expect(back).toContain("**negrita**");
    expect(back).toContain("- uno");
  });

  it("empty and plain values pass through", () => {
    expect(hulyMarkupToMarkdown("")).toBe("");
    expect(hulyMarkupToMarkdown("not markup at all")).toBe("not markup at all");
  });

  it("normalizeEndpoint maps wss/ws to https/http and strips trailing slashes", () => {
    expect(normalizeEndpoint("wss://huly2.nexgen.systems")).toBe("https://huly2.nexgen.systems");
    expect(normalizeEndpoint("ws://internal:3333/")).toBe("http://internal:3333");
    expect(normalizeEndpoint("https://huly2.nexgen.systems/")).toBe("https://huly2.nexgen.systems");
  });
});

describe("factory + secret hygiene", () => {
  it("HULY_CLIENT_MOCK=1 selects the mock; live env selects the real client", () => {
    expect(createHulyClient({ HULY_CLIENT_MOCK: "1" }).constructor.name).toBe("MockHulyClient");
    const real = createHulyClient({
      HULY_TOKEN: "tok",
      HULY_ENDPOINT: "wss://huly2.nexgen.systems",
      HULY_WORKSPACE: "demo",
    });
    expect(real.constructor.name).toBe("RealHulyClient");
  });

  it("missing live env is an actionable error mentioning only variable names", () => {
    expect(() => createHulyClient({})).toThrow(/HULY_TOKEN/);
    expect(() => createHulyClient({})).toThrow(/HULY_CLIENT_MOCK/);
  });

  it("no tool output, schema or error leaks the token", async () => {
    const token = "super-secret-huly-token";
    process.env.HULY_TOKEN = token;
    try {
      const outputs: string[] = [JSON.stringify(buildToolList())];
      parse(await callTool("tracker_create_issue", { project: "DEMO", title: "hygiene" }));
      outputs.push(JSON.stringify(await callTool("tracker_create_issue", { project: "DEMO", title: "hygiene2" })));
      outputs.push(JSON.stringify(await callTool("tracker_update_issue", { issueId: "NOPE-1", fields: {} })));
      outputs.push(JSON.stringify(await callTool("tracker_list_projects")));
      outputs.push(JSON.stringify(await client.listTools()));
      try {
        createHulyClient({ HULY_ENDPOINT: "x", HULY_WORKSPACE: "y" });
      } catch (err) {
        outputs.push(String(err));
      }
      for (const out of outputs) {
        expect(out).not.toContain(token);
      }
    } finally {
      delete process.env.HULY_TOKEN;
    }
  });
});
