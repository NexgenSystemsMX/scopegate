#!/usr/bin/env node
/**
 * Production smoke e2e for the HTTP transport (Sprint 6) — runs against a
 * DEPLOYED gateway (e.g. Railway). It starts NOTHING locally and touches no
 * local state: pure network assertions against the public URL.
 *
 * Required env:
 *   SCOPEGATE_PROD_URL    e.g. https://scopegate-demo.up.railway.app
 *   SCOPEGATE_HTTP_TOKEN  the bearer the gateway was started with
 *
 *   SCOPEGATE_PROD_URL=https://xxx.up.railway.app SCOPEGATE_HTTP_TOKEN=*** node e2e-prod.mjs
 *
 * The token is NEVER logged. Exits 0 on success, 1 on the first failure,
 * 2 on the global timeout (~60s).
 */
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const watchdog = setTimeout(() => {
  console.error("e2e-prod FAILED: global timeout (60s)");
  process.exit(2);
}, 60_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

function failEarly(message) {
  console.error(`e2e-prod FAILED: ${message}`);
  process.exit(1);
}

const PROD_URL = (process.env.SCOPEGATE_PROD_URL ?? "").trim().replace(/\/+$/, "");
const TOKEN = (process.env.SCOPEGATE_HTTP_TOKEN ?? "").trim();
if (!PROD_URL) {
  failEarly(
    "SCOPEGATE_PROD_URL is not set. Point it at the deployed gateway, e.g. " +
      "SCOPEGATE_PROD_URL=https://xxx.up.railway.app",
  );
}
if (!TOKEN) {
  failEarly(
    "SCOPEGATE_HTTP_TOKEN is not set. Use the SAME bearer the gateway was deployed with " +
      "(Railway variable SCOPEGATE_HTTP_TOKEN).",
  );
}
if (!/^https?:\/\//.test(PROD_URL)) {
  failEarly(`SCOPEGATE_PROD_URL must start with http(s):// — got '${PROD_URL}'`);
}

async function main() {
  console.log(`e2e-prod target: ${PROD_URL} (token: set, ${TOKEN.length} chars — never printed)`);

  // 1. GET /health — no auth — must be 200 {status:"ok", …}.
  const health = await fetch(`${PROD_URL}/health`);
  assert.equal(health.status, 200, `/health must be 200, got ${health.status}`);
  const healthBody = await health.json();
  assert.equal(healthBody.status, "ok", `/health body: ${JSON.stringify(healthBody)}`);
  assert.ok(
    typeof healthBody.upstreams === "number" && healthBody.upstreams >= 1,
    `expected >=1 connected upstream: ${JSON.stringify(healthBody)}`,
  );
  pass(`GET /health 200 {status:ok, upstreams:${healthBody.upstreams}} (no auth)`);

  // 2. MCP without a token → 401.
  const noAuth = await fetch(`${PROD_URL}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(noAuth.status, 401, `no-token MCP request must be 401, got ${noAuth.status}`);
  pass("MCP without token is 401");

  // 3. Full MCP session over Streamable HTTP with the bearer.
  const client = new Client({ name: "e2e-prod-smoke", version: "1.0.0" }, { capabilities: {} });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${PROD_URL}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
    }),
  );
  pass("MCP initialize with bearer token succeeds");

  // 4. listTools: management + proxied fakegit tools (demo seed).
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  for (const required of [
    "scopegate_request_capability",
    "scopegate_diagnose",
    "fakegit__whoami",
    "fakegit__danger",
  ]) {
    assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
  }
  pass("listTools exposes scopegate_* and fakegit__*");

  const parse = (res) => JSON.parse(res.content[0].text);

  // 5. request_capability fakegit:call:whoami → granted (demo auto_approve).
  const grant = parse(
    await client.callTool({
      name: "scopegate_request_capability",
      arguments: { capability: "fakegit:call:whoami", reason: "e2e-prod smoke" },
    }),
  );
  assert.equal(grant.granted, true, `expected grant, got: ${JSON.stringify(grant)}`);
  pass("request_capability fakegit:call:whoami granted");

  // 6. Proxied call: secret injected at the hop (fake upstream echoes auth).
  const call = await client.callTool({ name: "fakegit__whoami", arguments: {} });
  assert.notEqual(call.isError, true, `proxied call failed: ${call.content[0].text}`);
  assert.match(call.content[0].text, /authenticated=true/, `unexpected whoami: ${call.content[0].text}`);
  pass("proxied call fakegit__whoami returns authenticated=true");

  // 7. scopegate_diagnose answers and the demo upstream is healthy.
  const diag = parse(await client.callTool({ name: "scopegate_diagnose", arguments: {} }));
  assert.ok(diag.upstreams, `diagnose missing upstreams: ${JSON.stringify(diag)}`);
  assert.equal(diag.upstreams?.fakegit?.ok, true, `diagnose: ${JSON.stringify(diag)}`);
  pass("scopegate_diagnose responds (fakegit ok)");

  // 8. A call WITHOUT a capability must be denied WITH an actionable
  // instruction (demo seed: fakegit:call:danger requires human approval).
  const blocked = await client.callTool({ name: "fakegit__danger", arguments: {} });
  assert.equal(blocked.isError, true, "ungranted proxied call must be an error");
  assert.match(
    blocked.content[0].text,
    /scopegate_request_capability/,
    `denial must point to request_capability: ${blocked.content[0].text}`,
  );
  pass("proxied call without capability denied with actionable instruction");

  await client.close().catch(() => {});
  console.log("\ne2e-prod: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-prod FAILED: ${e.message}`);
    process.exit(1);
  });
