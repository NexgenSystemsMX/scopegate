#!/usr/bin/env node
/**
 * Portable end-to-end test for EPIC-12: agent attestation + warm pool.
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start)
 *     → fake-upstream.mjs --http with FAKE_REQUIRE_ATTESTATION=1
 *       (a VERIFYING third-party MCP: rejects any request without a valid
 *        X-ScopeGate-Attestation JWT, checked against the real JWKS the
 *        gateway publishes at $SCOPEGATE_HOME/jwks.json)
 *
 * Covered:
 *   - proxied call to an attestation-requiring upstream PASSES (the fake
 *     verifies the injected JWT against the real jwks.json of the temp HOME)
 *   - the JWKS kid is the SAME fingerprint as the audit identity (identity.json)
 *     — unified identity, one keypair for audit + attestation
 *   - negative controls: raw requests without the header / with a garbage
 *     token are rejected 401 with a JSONRPC-shaped error
 *   - documented OFF mode: an upstream with `attestation: false` cannot talk
 *     to the verifying upstream (startup probe and register probe both fail)
 *   - warm pool: `pool.min: 1` pre-establishes a connection (diagnose
 *     pool.size >= 1) and a proxied call reuses it (pool.hits >= 1)
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 * Prereq: `npm run build` (needs dist/cli.js and dist/attestation/verify.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");

const watchdog = setTimeout(() => {
  console.error("e2e FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/** Spawn fake-upstream.mjs --http in attest-check mode; resolve with its port. */
function startAttestUpstream(home) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [FAKE_UPSTREAM, "--http"], {
      stdio: ["ignore", "pipe", "inherit"],
      env: { ...process.env, SCOPEGATE_HOME: home, FAKE_REQUIRE_ATTESTATION: "1" },
    });
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /FAKE_UPSTREAM_PORT=(\d+)/.exec(buf);
      if (m) resolve({ child, port: Number(m[1]) });
    });
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`attest fake upstream exited early (${code})`)));
    setTimeout(() => reject(new Error("attest fake upstream did not report its port")), 10_000);
  });
}

/** Raw JSONRPC-less POST used for the negative controls (no MCP client). */
async function rawPost(url, headers) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(
    fs.existsSync(path.join(ROOT, "dist", "attestation", "verify.js")),
    `dist/attestation/verify.js not found — run \`npm run build\` first`,
  );

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-attest-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-attest-agent" };
  console.log(`e2e home: ${home}`);

  const client = new Client({ name: "e2e-harness", version: "1.0.0" }, { capabilities: {} });
  // The verifying upstream must be up before the gateway's connectAll runs.
  const upstream = await startAttestUpstream(home);
  const mcpUrl = `http://127.0.0.1:${upstream.port}/mcp`;
  try {
    // 2. Config + policies (written as JSON: valid YAML 1.2).
    //    - attested: default attestation + a warm pool (min 1, max 2)
    //    - plain:    attestation:false — the documented OFF mode; its startup
    //                connect fails (the fake 401s it) but the gateway must
    //                still come up for the rest.
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify(
        {
          version: 1,
          agentId: "e2e-attest-agent",
          upstreams: [
            {
              name: "attested",
              transport: { kind: "http", url: mcpUrl },
              auth: { type: "none" },
              pool: { min: 1, max: 2, idleTimeoutMs: 300000 },
            },
            {
              name: "plain",
              transport: { kind: "http", url: mcpUrl },
              auth: { type: "none" },
              attestation: false,
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
            "e2e-attest-agent": {
              default_ttl: "15m",
              capabilities: [{ match: "attested:call:echo_auth", auto_approve: true, ttl: "5m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Launch the gateway as the harness would (stdio MCP). The `plain`
    //    upstream fails its startup connect (401) — by design connectAll
    //    never rejects, so the gateway still starts.
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }),
    );
    pass("gateway started against a verifying upstream (attestation-required)");

    // 4. listTools: the attested upstream's tools are exposed; the OFF-mode
    //    one never connected, so its tools are absent.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes("attested__echo_auth"), `missing attested__echo_auth (${names.join(", ")})`);
    assert.ok(!names.includes("plain__echo_auth"), "attestation:false upstream must not connect to a verifying MCP");
    pass("listTools exposes attested__echo_auth; the attestation:false upstream stays out");

    // 5. Negative controls straight against the fake upstream: no header and
    //    a garbage token are both rejected 401 with a JSONRPC-shaped error.
    const noHeader = await rawPost(mcpUrl, {});
    assert.equal(noHeader.status, 401, `expected 401 without header, got ${noHeader.status}`);
    assert.match(noHeader.body?.error?.message ?? "", /attestation/i);
    const garbage = await rawPost(mcpUrl, { "x-scopegate-attestation": "aaa.bbb.ccc" });
    assert.equal(garbage.status, 401, `expected 401 for a garbage token, got ${garbage.status}`);
    assert.match(garbage.body?.error?.message ?? "", /attestation/i);
    pass("verifying upstream rejects missing/garbage attestation with 401 JSONRPC errors");

    // 6. Warm pool: min=1 was pre-established at startup — diagnose reports it
    //    BEFORE any call (the diagnose probe itself is not counted as a hit).
    const parse = (res) => JSON.parse(res.content[0].text);
    const diag0 = parse(await client.callTool({ name: "scopegate_diagnose", arguments: {} }));
    assert.equal(diag0.upstreams?.attested?.ok, true, `diagnose: ${JSON.stringify(diag0)}`);
    assert.ok(diag0.upstreams.attested.pool, `no pool metrics in diagnose: ${JSON.stringify(diag0)}`);
    assert.ok(diag0.upstreams.attested.pool.size >= 1, `pool.size must be >= 1: ${JSON.stringify(diag0)}`);
    assert.equal(diag0.upstreams.attested.pool.hits, 0, `no calls yet — hits must be 0: ${JSON.stringify(diag0)}`);
    assert.equal(diag0.upstreams?.plain?.ok, false, `plain must be failing: ${JSON.stringify(diag0)}`);
    pass("diagnose shows pool.size >= 1 (pre-established), hits = 0, plain ok = false");

    // 7. Proxied call: the gateway's attestation JWT is accepted by the
    //    verifying upstream — and the call is served by the warm connection.
    const call = await client.callTool({ name: "attested__echo_auth", arguments: {} });
    assert.notEqual(call.isError, true, `proxied call failed: ${call.content[0].text}`);
    const diag1 = parse(await client.callTool({ name: "scopegate_diagnose", arguments: {} }));
    assert.ok(diag1.upstreams.attested.pool.hits >= 1, `call must reuse the warm connection: ${JSON.stringify(diag1)}`);
    pass("proxied call PASSES attestation verification and reuses the warm connection (hits >= 1)");

    // 8. Unified identity: the JWKS on disk is keyed by the SAME fingerprint
    //    as the audit identity — one keypair signs audit log and attestation.
    const identity = JSON.parse(fs.readFileSync(path.join(home, "identity.json"), "utf8"));
    const jwks = JSON.parse(fs.readFileSync(path.join(home, "jwks.json"), "utf8"));
    assert.equal(jwks.keys.length, 1, `jwks must hold the current key: ${JSON.stringify(jwks)}`);
    assert.equal(jwks.keys[0].kid, identity.fingerprint, "JWKS kid must equal the audit identity fingerprint");
    assert.equal(jwks.keys[0].kty, "OKP");
    assert.equal(jwks.keys[0].crv, "Ed25519");
    pass("jwks.json is keyed by the audit identity fingerprint (kid rotation contract)");

    // 9. Documented OFF mode, dynamically: registering a new upstream with
    //    attestation:false probes it — the verifying upstream 401s the probe.
    const reg = parse(
      await client.callTool({
        name: "scopegate_register_upstream",
        arguments: {
          name: "late",
          transport: { kind: "http", url: mcpUrl },
          auth: { type: "none" },
          attestation: false,
        },
      }),
    );
    assert.equal(reg.registered, "late", `register response: ${JSON.stringify(reg)}`);
    assert.equal(reg.connection?.ok, false, `attestation:false probe must fail: ${JSON.stringify(reg)}`);
    assert.match(reg.connection?.error ?? "", /401|attestation/i);
    pass("OFF mode documented: attestation:false against a verifying MCP fails with a clear 401");
  } finally {
    await client.close().catch(() => {});
    upstream.child.kill();
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e FAILED: ${e.message}`);
    process.exit(1);
  });
