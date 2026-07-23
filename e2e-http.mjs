#!/usr/bin/env node
/**
 * Local end-to-end test for the HTTP transport (Sprint 6).
 *
 *   this script (MCP client over Streamable HTTP + raw fetch)
 *     → gateway child (dist/cli.js start --http --port 0)
 *       → fake-upstream.mjs (stdio)
 *
 * Portable: every path is resolved relative to this file; SCOPEGATE_HOME is
 * a mkdtemp dir created and removed by the script. The gateway prints
 * "SCOPEGATE_HTTP_LISTENING port=<n>" on stdout once listening (the line is
 * the parseable contract this script consumes).
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js).
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");
// Test-only bearer (never a real secret; regenerated per run).
const TOKEN = `e2e-http-${crypto.randomBytes(16).toString("hex")}`;

const watchdog = setTimeout(() => {
  console.error("e2e-http FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/** Spawn the gateway in http mode and resolve with its listening port. */
function startGatewayHttp(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [CLI, "start", "--http", "--port", "0", "--host", "127.0.0.1"],
      { stdio: ["ignore", "pipe", "inherit"], env },
    );
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /SCOPEGATE_HTTP_LISTENING port=(\d+)/.exec(buf);
      if (m) resolve({ child, port: Number(m[1]) });
    });
    child.on("error", reject);
    child.on("exit", (code) =>
      reject(new Error(`gateway exited before listening (${code})`)),
    );
    setTimeout(() => reject(new Error("gateway did not report its port")), 30_000);
  });
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-http-"));
  const env = {
    ...process.env,
    SCOPEGATE_HOME: home,
    SCOPEGATE_AGENT_ID: "e2e-http-agent",
    SCOPEGATE_HTTP_TOKEN: TOKEN,
    SCOPEGATE_VAULT_MODE: "local", // no vaultd in tests
  };
  console.log(`e2e-http home: ${home}`);

  let gateway = null;
  try {
    // 2. Config + policies (JSON: valid YAML 1.2). Same shape as the demo
    // seed: `danger` requires human approval (rule order: first match wins),
    // everything else on fakegit is auto-approved.
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify(
        {
          version: 1,
          agentId: "e2e-http-agent",
          upstreams: [
            {
              name: "fakegit",
              transport: { kind: "stdio", command: process.execPath, args: [FAKE_UPSTREAM] },
              auth: { type: "env", env: { FAKE_TOKEN: "fake_token" } },
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
          limits: { max_ttl: "30m", deny: ["\\*:*"] },
          agents: {
            "e2e-http-agent": {
              default_ttl: "15m",
              capabilities: [
                { match: "fakegit:call:danger", require: "human_approval", ttl: "5m" },
                { match: "fakegit:call:*", auto_approve: true, ttl: "15m" },
              ],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Deposit the secret through the human path (CLI + piped stdin).
    const add = spawnSync(process.execPath, [CLI, "secret", "add", "fake_token"], {
      input: "supersecret123\n",
      env,
      encoding: "utf8",
    });
    assert.equal(add.status, 0, `secret add failed: ${add.stderr || add.stdout}`);
    pass("secret deposited via CLI (stdin)");

    // 4. Fail-closed boot: without SCOPEGATE_HTTP_TOKEN the gateway must
    // abort with an actionable message (and never open a port).
    const noTokenEnv = { ...env };
    delete noTokenEnv.SCOPEGATE_HTTP_TOKEN;
    const noToken = spawnSync(
      process.execPath,
      [CLI, "start", "--http", "--port", "0", "--host", "127.0.0.1"],
      { env: noTokenEnv, encoding: "utf8", timeout: 30_000 },
    );
    assert.notEqual(noToken.status, 0, "gateway must refuse to start without SCOPEGATE_HTTP_TOKEN");
    assert.match(
      noToken.stderr ?? "",
      /SCOPEGATE_HTTP_TOKEN/,
      `abort message must name the missing env var: ${noToken.stderr}`,
    );
    pass("startup without SCOPEGATE_HTTP_TOKEN aborts with an actionable message");

    // 5. Launch the gateway over HTTP (ephemeral port).
    gateway = await startGatewayHttp(env);
    const base = `http://127.0.0.1:${gateway.port}`;
    pass(`gateway listening on ${base} (SCOPEGATE_HTTP_LISTENING parsed)`);

    // 6. GET /health — NO auth — reports ok + the connected upstream.
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200, `/health must be 200, got ${health.status}`);
    const healthBody = await health.json();
    assert.equal(healthBody.status, "ok", `/health body: ${JSON.stringify(healthBody)}`);
    assert.equal(healthBody.upstreams, 1, `one upstream connected: ${JSON.stringify(healthBody)}`);
    assert.ok(typeof healthBody.uptime_s === "number" && healthBody.uptime_s >= 0);
    pass("GET /health answers 200 {status:ok, upstreams:1} without auth");

    // 7. MCP without a token → 401 JSON.
    const noAuth = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    assert.equal(noAuth.status, 401, `no-token request must be 401, got ${noAuth.status}`);
    const noAuthBody = await noAuth.json();
    assert.match(JSON.stringify(noAuthBody), /unauthorized|credentials|Bearer/i);
    pass("MCP request without token is rejected with 401 JSON");

    // 8. MCP with a WRONG token → 401.
    const badAuth = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer wrong-token" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    assert.equal(badAuth.status, 401, `bad-token request must be 401, got ${badAuth.status}`);
    pass("MCP request with a wrong token is rejected with 401");

    // 9. With the token: full MCP handshake over Streamable HTTP.
    const client = new Client({ name: "e2e-http-harness", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
      }),
    );
    pass("MCP initialize over HTTP with bearer token succeeds");

    // 10. listTools: management tools + proxied fakegit tools.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const required of [
      "scopegate_request_capability",
      "scopegate_diagnose",
      "scopegate_vault_status",
      "fakegit__whoami",
      "fakegit__danger",
    ]) {
      assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
    }
    pass("listTools exposes scopegate_* and fakegit__* tools over HTTP");

    const parse = (res) => JSON.parse(res.content[0].text);

    // 11. request_capability granted (auto_approve rule).
    const grant = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:whoami", reason: "e2e-http" },
      }),
    );
    assert.equal(grant.granted, true, `expected grant, got: ${JSON.stringify(grant)}`);
    pass("request_capability granted over HTTP");

    // 12. Proxied call: the vault secret is injected at the outbound hop.
    const call = await client.callTool({ name: "fakegit__whoami", arguments: {} });
    assert.notEqual(call.isError, true, `proxied call failed: ${call.content[0].text}`);
    assert.match(call.content[0].text, /authenticated=true/, "env secret not injected upstream");
    pass("proxied call fakegit__whoami authenticates (secret injected at the hop)");

    // 13. Call without a grant on a human-approval rule → denied with an
    // actionable instruction.
    const blocked = await client.callTool({ name: "fakegit__danger", arguments: {} });
    assert.equal(blocked.isError, true, "ungranted proxied call must be an error");
    assert.match(blocked.content[0].text, /scopegate_request_capability/);
    pass("proxied call without capability is denied and points to request_capability");

    // 14. diagnose reports the upstream healthy.
    const diag = parse(await client.callTool({ name: "scopegate_diagnose", arguments: {} }));
    assert.equal(diag.upstreams?.fakegit?.ok, true, `diagnose: ${JSON.stringify(diag)}`);
    pass("scopegate_diagnose reports fakegit ok over HTTP");

    await client.close().catch(() => {});
  } finally {
    gateway?.child.kill();
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-http: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-http FAILED: ${e.message}`);
    process.exit(1);
  });
