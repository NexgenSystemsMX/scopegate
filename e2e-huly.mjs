#!/usr/bin/env node
/**
 * Portable end-to-end test for the huly-bridge upstream (EPIC-14):
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start)
 *     → huly-bridge (dist/upstreams/huly-bridge/server.js, HULY_CLIENT_MOCK=1)
 *
 * Runs WITHOUT a live Huly instance: the bridge uses its in-memory mock (the
 * demo token is never validated). Everything is isolated in a mkdtemp
 * SCOPEGATE_HOME created and removed by this script.
 *
 * Asserts through the gateway:
 *   - listTools exposes the huly__*-namespaced bridge tools
 *   - tracker: create issue → comment → update → search finds it → projects
 *   - documents: create → read (markdown round-trip) → update → list
 *   - chunter: post → list messages → list channels (plus a thread reply)
 *   - contact: list persons
 *   - audit.jsonl records tool calls and never leaks the token
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js and dist/upstreams/huly-bridge/).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const HULY_BRIDGE = path.join(ROOT, "dist", "upstreams", "huly-bridge", "server.js");
const DEMO_TOKEN = "demo-token";

const watchdog = setTimeout(() => {
  console.error("e2e-huly FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(fs.existsSync(HULY_BRIDGE), `dist/upstreams/huly-bridge/server.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-huly-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-agent" };
  console.log(`e2e home: ${home}`);

  const client = new Client({ name: "e2e-huly-harness", version: "1.0.0" }, { capabilities: {} });
  try {
    // 2. Config + policies (written as JSON: valid YAML 1.2). The bridge runs
    // in mock mode; auth is none — the gateway injects the env at spawn.
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify(
        {
          version: 1,
          agentId: "e2e-agent",
          upstreams: [
            {
              name: "huly",
              transport: {
                kind: "stdio",
                command: process.execPath,
                args: [HULY_BRIDGE],
                env: {
                  HULY_TOKEN: DEMO_TOKEN,
                  HULY_ENDPOINT: "mock",
                  HULY_WORKSPACE: "demo",
                  HULY_CLIENT_MOCK: "1",
                },
              },
              auth: { type: "none" },
            },
          ],
        },
        null,
        2,
      ),
    );
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify(
        {
          version: 1,
          agents: {
            "e2e-agent": {
              default_ttl: "15m",
              capabilities: [{ match: "huly:call:*", auto_approve: true, ttl: "10m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Launch the gateway as the harness would (stdio MCP).
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }));
    pass("gateway started with the huly stdio upstream (mock mode)");

    // 4. listTools: the bridge tools appear under the huly__ namespace.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const required of [
      "huly__tracker_create_issue",
      "huly__tracker_update_issue",
      "huly__tracker_comment_issue",
      "huly__tracker_search_issues",
      "huly__tracker_list_projects",
      "huly__documents_create",
      "huly__documents_read",
      "huly__documents_update",
      "huly__documents_list",
      "huly__chunter_post_message",
      "huly__chunter_list_channels",
      "huly__chunter_list_messages",
      "huly__contact_list_persons",
    ]) {
      assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
    }
    pass("listTools exposes all 13 huly__* tools");

    const parse = (res) => {
      assert.notEqual(res.isError, true, `proxied call failed: ${res.content[0].text}`);
      return JSON.parse(res.content[0].text);
    };

    // 5. Tracker: create → comment → update → search → list projects.
    const issue = parse(
      await client.callTool({ name: "huly__tracker_create_issue", arguments: { project: "DEMO", title: "e2e issue" } }),
    );
    assert.equal(issue.identifier, "DEMO-1", `expected DEMO-1, got: ${JSON.stringify(issue)}`);
    assert.ok(issue.id, "create_issue must return an id");
    pass("huly__tracker_create_issue → DEMO-1");

    const comment = parse(
      await client.callTool({
        name: "huly__tracker_comment_issue",
        arguments: { issueId: "DEMO-1", message: "first comment via gateway" },
      }),
    );
    assert.ok(comment.id, "comment_issue must return a comment id");
    assert.equal(comment.issue, "DEMO-1");
    pass("huly__tracker_comment_issue → comment id");

    const updated = parse(
      await client.callTool({
        name: "huly__tracker_update_issue",
        arguments: { issueId: "DEMO-1", fields: { status: "in_progress", priority: "high" } },
      }),
    );
    assert.deepEqual([...updated.updated].sort(), ["priority", "status"]);
    pass("huly__tracker_update_issue → status+priority");

    const search = parse(
      await client.callTool({ name: "huly__tracker_search_issues", arguments: { query: "e2e issue" } }),
    );
    assert.equal(search.count, 1, `search must find the created issue: ${JSON.stringify(search)}`);
    assert.equal(search.issues[0].identifier, "DEMO-1");
    assert.equal(search.issues[0].status, "in_progress");
    const searchDone = parse(
      await client.callTool({ name: "huly__tracker_search_issues", arguments: { status: "done" } }),
    );
    assert.equal(searchDone.count, 0, "no done issues expected");
    pass("huly__tracker_search_issues finds it by text and by status");

    const projects = parse(await client.callTool({ name: "huly__tracker_list_projects", arguments: {} }));
    assert.equal(projects.projects[0].identifier, "DEMO");
    assert.equal(projects.projects[0].issues, 1);
    pass("huly__tracker_list_projects → DEMO with 1 issue");

    // 6. Documents: create → read (markdown round-trip) → update → list.
    const doc = parse(
      await client.callTool({
        name: "huly__documents_create",
        arguments: { teamspace: "general", title: "e2e doc", content: "# Spec\n\nBody **text**" },
      }),
    );
    assert.ok(doc.id, "documents_create must return an id");
    const read = parse(await client.callTool({ name: "huly__documents_read", arguments: { documentId: doc.id } }));
    assert.equal(read.content, "# Spec\n\nBody **text**", "read must round-trip the markdown content");
    const docUpdated = parse(
      await client.callTool({ name: "huly__documents_update", arguments: { documentId: doc.id, content: "v2" } }),
    );
    assert.equal(docUpdated.id, doc.id);
    const readV2 = parse(await client.callTool({ name: "huly__documents_read", arguments: { documentId: doc.id } }));
    assert.equal(readV2.content, "v2");
    const docs = parse(await client.callTool({ name: "huly__documents_list", arguments: { teamspace: "general" } }));
    assert.equal(docs.count, 1, "documents_list must show the created doc");
    pass("huly__documents_* create/read/update/list with markdown round-trip");

    // 7. Chunter: post → thread reply → list → channels.
    const posted = parse(
      await client.callTool({ name: "huly__chunter_post_message", arguments: { channel: "general", message: "hello huly" } }),
    );
    assert.ok(posted.id, "chunter_post_message must return a message id");
    const reply = parse(
      await client.callTool({
        name: "huly__chunter_post_message",
        arguments: { channel: "general", message: "thread reply", thread: posted.id },
      }),
    );
    assert.equal(reply.thread, posted.id);
    const messages = parse(
      await client.callTool({ name: "huly__chunter_list_messages", arguments: { channel: "general" } }),
    );
    assert.equal(messages.count, 1, "channel view shows only top-level messages");
    assert.equal(messages.messages[0].text, "hello huly");
    const thread = parse(
      await client.callTool({ name: "huly__chunter_list_messages", arguments: { channel: "general", thread: posted.id } }),
    );
    assert.equal(thread.count, 2, "thread view shows parent + reply");
    const channels = parse(await client.callTool({ name: "huly__chunter_list_channels", arguments: {} }));
    assert.deepEqual(channels.channels.map((c) => c.name), ["general", "random"]);
    pass("huly__chunter_* post/thread/list/channels");

    // 8. Contact: list persons.
    const persons = parse(await client.callTool({ name: "huly__contact_list_persons", arguments: {} }));
    assert.ok(persons.count >= 2, `expected seeded persons, got: ${JSON.stringify(persons)}`);
    pass("huly__contact_list_persons → seeded persons");

    // 9. Error contract through the gateway: actionable isError, no token.
    const errRes = await client.callTool({ name: "huly__tracker_update_issue", arguments: { issueId: "NOPE-9", fields: { title: "x" } } });
    assert.equal(errRes.isError, true, "unknown issue must be an MCP error");
    assert.match(errRes.content[0].text, /issue not found/i);
    pass("unknown issue surfaces an actionable isError through the gateway");

    // 10. Audit trail records the calls and never leaks the token.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"tool_call"'), "audit log missing tool_call events");
    assert.ok(auditRaw.includes("huly__tracker_create_issue"), "audit log missing the huly tool name");
    assert.ok(!auditRaw.includes(DEMO_TOKEN), "audit log leaked the HULY_TOKEN value");
    pass("audit.jsonl records huly tool calls and never leaks the token");
  } finally {
    await client.close().catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-huly: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-huly FAILED: ${e.message}`);
    process.exit(1);
  });
