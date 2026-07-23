#!/usr/bin/env node
/**
 * Portable end-to-end test for the railway-bridge upstream (EPIC-16):
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start)
 *     → railway-bridge (dist/upstreams/railway-bridge/server.js, RAILWAY_MOCK=1)
 *
 * Runs WITHOUT network or a live Railway account: the bridge uses its
 * in-memory mock (the demo token is never validated). Everything is isolated
 * in a mkdtemp SCOPEGATE_HOME created and removed by this script.
 *
 * Asserts through the gateway:
 *   - listTools exposes the 7 railway__*-namespaced bridge tools
 *   - list_services groups services per project
 *   - service_status returns the latest deployment (status + url)
 *   - get_logs returns deploy logs and honours `lines`
 *   - variables_list returns NAMES only, every value "[redacted]"
 *   - domain_status returns service + custom domains
 *   - deploy returns an acceptance with a deployment id
 *   - errors are actionable isError results
 *   - audit.jsonl records tool calls and never leaks the token nor variable values
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js and dist/upstreams/railway-bridge/).
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
const RAILWAY_BRIDGE = path.join(ROOT, "dist", "upstreams", "railway-bridge", "server.js");
const DEMO_TOKEN = "demo-token";
const MOCK_SECRET = "sk-railway-demo-secret";

const watchdog = setTimeout(() => {
  console.error("e2e-railway FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(
    fs.existsSync(RAILWAY_BRIDGE),
    `dist/upstreams/railway-bridge/server.js not found — run \`npm run build\` first`,
  );

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-railway-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-agent" };
  console.log(`e2e home: ${home}`);

  const client = new Client({ name: "e2e-railway-harness", version: "1.0.0" }, { capabilities: {} });
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
              name: "railway",
              transport: {
                kind: "stdio",
                command: process.execPath,
                args: [RAILWAY_BRIDGE],
                env: {
                  RAILWAY_TOKEN: DEMO_TOKEN,
                  RAILWAY_MOCK: "1",
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
              capabilities: [{ match: "railway:call:*", auto_approve: true, ttl: "10m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Launch the gateway as the harness would (stdio MCP).
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }));
    pass("gateway started with the railway stdio upstream (mock mode)");

    // 4. listTools: the bridge tools appear under the railway__ namespace.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const required of [
      "railway__list_services",
      "railway__service_status",
      "railway__deploy",
      "railway__redeploy",
      "railway__get_logs",
      "railway__variables_list",
      "railway__domain_status",
    ]) {
      assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
    }
    pass("listTools exposes all 7 railway__* tools");

    const parse = (res) => {
      assert.notEqual(res.isError, true, `proxied call failed: ${res.content[0].text}`);
      return JSON.parse(res.content[0].text);
    };

    // 5. list_services: services grouped per project.
    const listed = parse(await client.callTool({ name: "railway__list_services", arguments: {} }));
    assert.equal(listed.count, 2, `expected 2 seeded projects: ${JSON.stringify(listed)}`);
    const demo = listed.projects.find((p) => p.name === "Demo Project");
    assert.ok(demo, "Demo Project missing from list_services");
    assert.deepEqual(demo.services.map((s) => s.name), ["api", "worker"]);
    pass("railway__list_services → projects with grouped services");

    // 6. service_status: latest deployment of api (SUCCESS + url).
    const status = parse(await client.callTool({ name: "railway__service_status", arguments: { service: "api" } }));
    assert.equal(status.deployment.status, "SUCCESS", `unexpected status: ${JSON.stringify(status)}`);
    assert.equal(status.deployment.url, "https://api-demo.up.railway.app");
    assert.equal(status.environment, "production");
    pass("railway__service_status → SUCCESS deployment with url");

    // 7. get_logs: deploy logs of the latest deployment, honouring lines.
    const logs = parse(await client.callTool({ name: "railway__get_logs", arguments: { service: "api", lines: 2 } }));
    assert.equal(logs.count, 2, `expected 2 log lines: ${JSON.stringify(logs)}`);
    assert.equal(logs.logs[1].message, "Healthcheck passed");
    pass("railway__get_logs → deploy logs with lines honoured");

    // 8. variables_list: NAMES only — values are always "[redacted]".
    const vars = parse(await client.callTool({ name: "railway__variables_list", arguments: { service: "api" } }));
    assert.deepEqual(vars.variables.map((v) => v.name), ["API_KEY", "DATABASE_URL", "NODE_ENV"]);
    for (const v of vars.variables) {
      assert.equal(v.value, "[redacted]", `variable ${v.name} leaked a value`);
    }
    assert.ok(!JSON.stringify(vars).includes(MOCK_SECRET), "variables_list leaked the seeded secret value");
    pass("railway__variables_list → names only, values '[redacted]'");

    // 9. domain_status: service + custom domains.
    const domains = parse(await client.callTool({ name: "railway__domain_status", arguments: { service: "api" } }));
    assert.equal(domains.serviceDomains[0].domain, "api-demo.up.railway.app");
    assert.equal(domains.customDomains[0].domain, "api.example.com");
    assert.equal(domains.customDomains[0].dnsStatus, "VALID");
    pass("railway__domain_status → service + custom domains");

    // 10. deploy: acceptance with a new deployment id.
    const deploy = parse(await client.callTool({ name: "railway__deploy", arguments: { service: "api" } }));
    assert.equal(deploy.accepted, true, `deploy not accepted: ${JSON.stringify(deploy)}`);
    assert.equal(deploy.kind, "deploy");
    assert.ok(deploy.deploymentId, "deploy must return a deploymentId");
    pass("railway__deploy → acceptance with deployment id");

    // 11. Error contract through the gateway: actionable isError, no token.
    const errRes = await client.callTool({ name: "railway__service_status", arguments: { service: "nope" } });
    assert.equal(errRes.isError, true, "unknown service must be an MCP error");
    assert.match(errRes.content[0].text, /service not found/i);
    const errAmb = await client.callTool({ name: "railway__service_status", arguments: { service: "worker" } });
    assert.equal(errAmb.isError, true, "ambiguous service must be an MCP error");
    assert.match(errAmb.content[0].text, /ambiguous/i);
    pass("unknown/ambiguous services surface actionable isError results");

    // 12. Audit trail records the calls and never leaks secrets.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"tool_call"'), "audit log missing tool_call events");
    assert.ok(auditRaw.includes("railway__service_status"), "audit log missing the railway tool name");
    assert.ok(!auditRaw.includes(DEMO_TOKEN), "audit log leaked the RAILWAY_TOKEN value");
    assert.ok(!auditRaw.includes(MOCK_SECRET), "audit log leaked a variable value");
    pass("audit.jsonl records railway tool calls and never leaks secrets");
  } finally {
    await client.close().catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-railway: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-railway FAILED: ${e.message}`);
    process.exit(1);
  });
