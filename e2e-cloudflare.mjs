#!/usr/bin/env node
/**
 * Portable end-to-end test for the cloudflare-bridge upstream (EPIC-17):
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start)
 *     → cloudflare-bridge (dist/upstreams/cloudflare-bridge/server.js, CLOUDFLARE_MOCK=1)
 *
 * Runs WITHOUT network access or a live Cloudflare account: the bridge uses
 * its in-memory mock (the demo token is never validated). Everything is
 * isolated in a mkdtemp SCOPEGATE_HOME created and removed by this script.
 *
 * Asserts through the gateway:
 *   - listTools exposes the 8 cloudflare__*-namespaced bridge tools
 *   - list_zones, dns_list (with a type filter), dns_create → id, dns_update
 *   - workers_list / pages_projects / r2_buckets (accountId auto-resolved)
 *   - actionable isError (unknown zone), and audit.jsonl without secrets
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js and dist/upstreams/cloudflare-bridge/).
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
const CF_BRIDGE = path.join(ROOT, "dist", "upstreams", "cloudflare-bridge", "server.js");
const DEMO_TOKEN = "demo-token";

const watchdog = setTimeout(() => {
  console.error("e2e-cloudflare FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(fs.existsSync(CF_BRIDGE), `dist/upstreams/cloudflare-bridge/server.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-cloudflare-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-agent" };
  console.log(`e2e home: ${home}`);

  const client = new Client({ name: "e2e-cloudflare-harness", version: "1.0.0" }, { capabilities: {} });
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
              name: "cloudflare",
              transport: {
                kind: "stdio",
                command: process.execPath,
                args: [CF_BRIDGE],
                env: {
                  CLOUDFLARE_API_TOKEN: DEMO_TOKEN,
                  CLOUDFLARE_MOCK: "1",
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
              capabilities: [{ match: "cloudflare:call:*", auto_approve: true, ttl: "10m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Launch the gateway as the harness would (stdio MCP).
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }));
    pass("gateway started with the cloudflare stdio upstream (mock mode)");

    // 4. listTools: the bridge tools appear under the cloudflare__ namespace.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const required of [
      "cloudflare__list_zones",
      "cloudflare__dns_list",
      "cloudflare__dns_create",
      "cloudflare__dns_update",
      "cloudflare__dns_delete",
      "cloudflare__workers_list",
      "cloudflare__pages_projects",
      "cloudflare__r2_buckets",
    ]) {
      assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
    }
    pass("listTools exposes all 8 cloudflare__* tools");

    const parse = (res) => {
      assert.notEqual(res.isError, true, `proxied call failed: ${res.content[0].text}`);
      return JSON.parse(res.content[0].text);
    };

    // 5. Zones + DNS: list → filter → create → update.
    const zones = parse(await client.callTool({ name: "cloudflare__list_zones", arguments: {} }));
    assert.ok(
      zones.zones.some((z) => z.name === "example.com"),
      `expected the seeded example.com zone: ${JSON.stringify(zones)}`,
    );
    pass("cloudflare__list_zones → seeded zones");

    const aRecords = parse(
      await client.callTool({ name: "cloudflare__dns_list", arguments: { zone: "example.com", type: "A" } }),
    );
    assert.equal(aRecords.count, 1, `type filter must keep only A records: ${JSON.stringify(aRecords)}`);
    assert.equal(aRecords.records[0].name, "www.example.com");
    pass("cloudflare__dns_list with a type filter");

    const created = parse(
      await client.callTool({
        name: "cloudflare__dns_create",
        arguments: { zone: "example.com", type: "A", name: "api.example.com", content: "192.0.2.10", ttl: 300 },
      }),
    );
    assert.ok(created.id, "dns_create must return an id");
    assert.equal(created.ttl, 300);
    pass("cloudflare__dns_create → record id");

    const updated = parse(
      await client.callTool({
        name: "cloudflare__dns_update",
        arguments: { zone: "example.com", recordId: created.id, content: "192.0.2.11", proxied: true },
      }),
    );
    assert.equal(updated.content, "192.0.2.11");
    assert.equal(updated.proxied, true);
    const afterUpdate = parse(
      await client.callTool({ name: "cloudflare__dns_list", arguments: { zone: "example.com", name: "api.example.com" } }),
    );
    assert.equal(afterUpdate.records[0].content, "192.0.2.11");
    pass("cloudflare__dns_update → content+proxied (verified via dns_list)");

    // 6. Account surfaces: accountId auto-resolved via the mock's /accounts.
    const workers = parse(await client.callTool({ name: "cloudflare__workers_list", arguments: {} }));
    assert.equal(workers.accountId, "mock-account-1");
    assert.ok(workers.count >= 2, `expected seeded workers: ${JSON.stringify(workers)}`);
    pass("cloudflare__workers_list → auto-resolved account");

    const pages = parse(await client.callTool({ name: "cloudflare__pages_projects", arguments: {} }));
    assert.equal(pages.projects[0].name, "docs-site");
    pass("cloudflare__pages_projects → docs-site");

    const buckets = parse(await client.callTool({ name: "cloudflare__r2_buckets", arguments: {} }));
    assert.ok(
      buckets.buckets.some((b) => b.name === "backups"),
      `expected the backups bucket: ${JSON.stringify(buckets)}`,
    );
    pass("cloudflare__r2_buckets → seeded buckets");

    // 7. Error contract through the gateway: actionable isError, no token.
    const errRes = await client.callTool({ name: "cloudflare__dns_list", arguments: { zone: "nope.example" } });
    assert.equal(errRes.isError, true, "unknown zone must be an MCP error");
    assert.match(errRes.content[0].text, /zone not found/i);
    assert.match(errRes.content[0].text, /list_zones/);
    assert.ok(!errRes.content[0].text.includes(DEMO_TOKEN), "error leaked the token");
    pass("unknown zone surfaces an actionable isError through the gateway");

    // 8. Audit trail records the calls and never leaks the token.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"tool_call"'), "audit log missing tool_call events");
    assert.ok(auditRaw.includes("cloudflare__dns_create"), "audit log missing the cloudflare tool name");
    assert.ok(!auditRaw.includes(DEMO_TOKEN), "audit log leaked the CLOUDFLARE_API_TOKEN value");
    pass("audit.jsonl records cloudflare tool calls and never leaks the token");
  } finally {
    await client.close().catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-cloudflare: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-cloudflare FAILED: ${e.message}`);
    process.exit(1);
  });
