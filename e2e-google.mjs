#!/usr/bin/env node
/**
 * Portable end-to-end test for the google-bridge upstream (EPIC-18):
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start)
 *     → google-bridge (dist/upstreams/google-bridge/server.js, GOOGLE_MOCK=1)
 *
 * Runs WITHOUT Google credentials: the bridge uses its in-memory mock (the
 * demo token is never validated). Everything is isolated in a mkdtemp
 * SCOPEGATE_HOME created and removed by this script.
 *
 * Asserts through the gateway:
 *   - listTools exposes the google__*-namespaced bridge tools (7)
 *   - drive: list → search → read (text round-trip, binary note)
 *   - gmail: send (accepted) → list finds it
 *   - calendar: list seeded event → create → list again
 *   - actionable isError through the gateway
 *   - audit.jsonl records tool calls and never leaks the token
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js and dist/upstreams/google-bridge/).
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
const GOOGLE_BRIDGE = path.join(ROOT, "dist", "upstreams", "google-bridge", "server.js");
const DEMO_TOKEN = "demo-token";

const watchdog = setTimeout(() => {
  console.error("e2e-google FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(fs.existsSync(GOOGLE_BRIDGE), `dist/upstreams/google-bridge/server.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-google-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-agent" };
  console.log(`e2e home: ${home}`);

  const client = new Client({ name: "e2e-google-harness", version: "1.0.0" }, { capabilities: {} });
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
              name: "google",
              transport: {
                kind: "stdio",
                command: process.execPath,
                args: [GOOGLE_BRIDGE],
                env: {
                  GOOGLE_ACCESS_TOKEN: DEMO_TOKEN,
                  GOOGLE_MOCK: "1",
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
              capabilities: [{ match: "google:call:*", auto_approve: true, ttl: "10m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Launch the gateway as the harness would (stdio MCP).
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }));
    pass("gateway started with the google stdio upstream (mock mode)");

    // 4. listTools: the bridge tools appear under the google__ namespace.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const required of [
      "google__drive_list",
      "google__drive_search",
      "google__drive_read",
      "google__gmail_send",
      "google__gmail_list",
      "google__calendar_list",
      "google__calendar_create",
    ]) {
      assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
    }
    pass("listTools exposes all 7 google__* tools");

    const parse = (res) => {
      assert.notEqual(res.isError, true, `proxied call failed: ${res.content[0].text}`);
      return JSON.parse(res.content[0].text);
    };

    // 5. Drive: list → search → read (text round-trip + binary note).
    const files = parse(await client.callTool({ name: "google__drive_list", arguments: {} }));
    assert.equal(files.count, 4, `expected 4 seeded files, got: ${JSON.stringify(files)}`);
    pass("google__drive_list → 4 seeded files");

    const search = parse(await client.callTool({ name: "google__drive_search", arguments: { query: "ship google-bridge" } }));
    assert.equal(search.count, 1, `search must find Roadmap.md: ${JSON.stringify(search)}`);
    assert.equal(search.files[0].id, "mock-file-1");
    pass("google__drive_search finds the roadmap by content");

    const read = parse(await client.callTool({ name: "google__drive_read", arguments: { fileId: "mock-file-1" } }));
    assert.equal(read.content, "# Roadmap\n\n- ship google-bridge", "read must round-trip the text content");
    const binary = parse(await client.callTool({ name: "google__drive_read", arguments: { fileId: "mock-file-4" } }));
    assert.equal(binary.content, undefined, "binary files return no content");
    assert.match(binary.note, /binary file/i);
    pass("google__drive_read → text round-trip and binary note");

    // 6. Gmail: send (accepted) → list finds it.
    const sent = parse(
      await client.callTool({
        name: "google__gmail_send",
        arguments: { to: "grace@example.com", subject: "e2e google bridge", body: "sent through the gateway" },
      }),
    );
    assert.ok(sent.id, "gmail_send must return a message id");
    assert.ok(sent.labelIds.includes("SENT"));
    const mail = parse(await client.callTool({ name: "google__gmail_list", arguments: { query: "e2e google bridge" } }));
    assert.equal(mail.count, 1, `gmail_list must find the sent message: ${JSON.stringify(mail)}`);
    assert.equal(mail.messages[0].subject, "e2e google bridge");
    pass("google__gmail_send accepted and gmail_list finds it");

    // 7. Calendar: list seeded → create → list again.
    const events = parse(
      await client.callTool({ name: "google__calendar_list", arguments: { timeMin: "2026-03-01T00:00:00.000Z" } }),
    );
    assert.equal(events.count, 1, `expected the seeded standup, got: ${JSON.stringify(events)}`);
    assert.equal(events.events[0].summary, "Daily standup");
    const created = parse(
      await client.callTool({
        name: "google__calendar_create",
        arguments: {
          summary: "e2e review",
          start: "2026-03-05T14:00:00.000Z",
          end: "2026-03-05T15:00:00.000Z",
          attendees: ["ada@example.com"],
        },
      }),
    );
    assert.ok(created.id, "calendar_create must return an event id");
    assert.deepEqual(created.attendees, ["ada@example.com"]);
    const after = parse(
      await client.callTool({ name: "google__calendar_list", arguments: { timeMin: "2026-03-03T00:00:00.000Z" } }),
    );
    assert.equal(after.count, 1, "only the created event is after timeMin");
    assert.equal(after.events[0].summary, "e2e review");
    pass("google__calendar_list seeded + calendar_create round-trip");

    // 8. Error contract through the gateway: actionable isError, no token.
    const errRes = await client.callTool({ name: "google__drive_read", arguments: { fileId: "nope" } });
    assert.equal(errRes.isError, true, "unknown file must be an MCP error");
    assert.match(errRes.content[0].text, /file not found/i);
    assert.match(errRes.content[0].text, /drive_list/);
    pass("unknown file surfaces an actionable isError through the gateway");

    // 9. Audit trail records the calls and never leaks the token.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"tool_call"'), "audit log missing tool_call events");
    assert.ok(auditRaw.includes("google__drive_list"), "audit log missing the google tool name");
    assert.ok(!auditRaw.includes(DEMO_TOKEN), "audit log leaked the GOOGLE_ACCESS_TOKEN value");
    pass("audit.jsonl records google tool calls and never leaks the token");
  } finally {
    await client.close().catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-google: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-google FAILED: ${e.message}`);
    process.exit(1);
  });
