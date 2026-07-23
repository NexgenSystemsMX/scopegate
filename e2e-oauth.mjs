#!/usr/bin/env node
/**
 * Portable end-to-end test for the OAuth Refresh Daemon (EPIC-03).
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start)
 *     → fake-upstream.mjs --oauth  (authorization server + protected MCP)
 *
 * Scenario (the "Notion 4 h" case in miniature):
 *   1. Upstream access tokens live 3 s. The gateway refreshes them on its own
 *      (~80% of the TTL) and a proxied call at ~5 s succeeds WITHOUT any
 *      intervention — zero auth errors visible to the agent.
 *   2. The refresh grant is then revoked (invalid_grant): the daemon marks
 *      needs_reauth, writes reauth-required.json, diagnose returns the literal
 *      instruction, and calls fail fast with an actionable message.
 *   3. The human runs the device-code login (runAuthLogin, separate process)
 *      and the flow returns to green WITHOUT restarting the gateway.
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js and dist/commands/oauth-login.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const OAUTH_LOGIN = path.join(ROOT, "dist", "commands", "oauth-login.js");
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");

const watchdog = setTimeout(() => {
  console.error("e2e-oauth FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Spawn fake-upstream.mjs --oauth and resolve with its listening port. */
function startOAuthUpstream() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [FAKE_UPSTREAM, "--oauth"], {
      env: { ...process.env, FAKE_OAUTH_ACCESS_TTL_S: "3" },
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /FAKE_OAUTH_PORT=(\d+)/.exec(buf);
      if (m) resolve({ child, port: Number(m[1]) });
    });
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`oauth fake upstream exited early (${code})`)));
    setTimeout(() => reject(new Error("oauth fake upstream did not report its port")), 10_000);
  });
}

/** Run `runAuthLogin` in a separate process (as `scopegate auth login` would). */
function startAuthLoginProcess(env) {
  const code =
    `import { runAuthLogin } from ${JSON.stringify(pathToFileURL(OAUTH_LOGIN).href)};\n` +
    `await runAuthLogin({ upstream: "notion" });`;
  return spawn(process.execPath, ["--input-type=module", "--eval", code], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(fs.existsSync(OAUTH_LOGIN), `dist/commands/oauth-login.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-oauth-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-agent" };
  console.log(`e2e-oauth home: ${home}`);

  const client = new Client({ name: "e2e-harness", version: "1.0.0" }, { capabilities: {} });
  const upstream = await startOAuthUpstream();
  const base = `http://127.0.0.1:${upstream.port}`;
  try {
    // 2. Config + policies (JSON is valid YAML 1.2).
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify(
        {
          version: 1,
          agentId: "e2e-agent",
          upstreams: [
            {
              name: "notion",
              transport: { kind: "http", url: `${base}/mcp` },
              auth: { type: "oauth2", secretRef: "oauth2:notion" },
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
              capabilities: [{ match: "notion:call:oauth_ping", auto_approve: true, ttl: "10m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Deposit the initial OAuth blob (bootstrap tokens, 3 s of life).
    // NOTE: the frozen ref convention `oauth2:<upstream>` contains a colon,
    // which `scopegate secret add` rejects (its ref charset is [a-z0-9_.-]) —
    // so the e2e deposits through the Vault API in a SEPARATE process (the
    // same out-of-band channel the login flow uses), never through the agent.
    const blob = {
      v: 1,
      access_token: "at-bootstrap",
      refresh_token: "rt-bootstrap",
      expires_at: Date.now() + 3_000,
      obtained_at: Date.now(),
      token_url: `${base}/token`,
      client_id: "scopegate-e2e",
    };
    const vaultCode =
      `import { Vault } from ${JSON.stringify(pathToFileURL(path.join(ROOT, "dist", "vault", "vault.js")).href)};\n` +
      `Vault.open().set("oauth2:notion", process.env.SCOPEGATE_E2E_BLOB);`;
    const add = spawnSync(process.execPath, ["--input-type=module", "--eval", vaultCode], {
      env: { ...env, SCOPEGATE_E2E_BLOB: JSON.stringify(blob) },
      encoding: "utf8",
    });
    assert.equal(add.status, 0, `blob deposit failed: ${add.stderr || add.stdout}`);
    pass("initial OAuth blob deposited out-of-band (bootstrap tokens, 3s TTL)");

    // 4. Launch the gateway as the harness would (stdio MCP).
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }),
    );
    pass("gateway started with the oauth upstream");

    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes("notion__oauth_ping"), `listTools missing notion__oauth_ping (${names})`);
    assert.ok(names.includes("notion__pii_echo"), `listTools missing notion__pii_echo (${names})`);

    // 5. Immediate call: bootstrap token works.
    const first = await client.callTool({ name: "notion__oauth_ping", arguments: {} });
    assert.notEqual(first.isError, true, `first call failed: ${first.content[0].text}`);
    assert.match(first.content[0].text, /token=at-bootstrap/, `unexpected token: ${first.content[0].text}`);
    pass("proxied call works with the bootstrap token");

    // 6. The daemon renews on its own (~80% of 3 s): at ~5 s the bootstrap
    // token is long dead, yet the call succeeds with a ROTATED token.
    await sleep(5_000);
    const second = await client.callTool({ name: "notion__oauth_ping", arguments: {} });
    assert.notEqual(second.isError, true, `call after expiry failed: ${second.content[0].text}`);
    const m2 = /token=(\S+)/.exec(second.content[0].text);
    assert.ok(m2, `no token id in response: ${second.content[0].text}`);
    assert.notEqual(m2[1], "at-bootstrap", "daemon did not rotate the access token");
    pass("proactive refresh: call at ~5s succeeds WITHOUT intervention (Notion-4h in miniature)");

    let auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"token_refreshed"'), "audit log missing token_refreshed events");
    pass("audit records token_refreshed (metadata only)");

    // 7. Revoke the refresh grant family → the next scheduled refresh gets
    // invalid_grant → needs_reauth (file + audit + diagnose instruction).
    const revoke = await fetch(`${base}/oauth/revoke`, { method: "POST" });
    assert.equal(revoke.status, 200, `revoke failed: ${revoke.status}`);
    await sleep(4_000); // the scheduler's next tick (≤ ~2.6 s) hits the dead grant

    const signalPath = path.join(home, "reauth-required.json");
    assert.ok(fs.existsSync(signalPath), "reauth-required.json was not written");
    const signal = JSON.parse(fs.readFileSync(signalPath, "utf8"));
    assert.equal(signal.upstream, "notion", `unexpected signal: ${JSON.stringify(signal)}`);
    pass("invalid_grant → reauth-required.json written (0600 signal for the human)");

    auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"oauth_reauth_required"'), "audit missing oauth_reauth_required");

    const diagRes = await client.callTool({ name: "scopegate_diagnose", arguments: {} });
    const diagText = diagRes.content[0].text;
    assert.ok(
      diagText.includes("run in your terminal: scopegate auth login notion"),
      `diagnose lacks the literal instruction: ${diagText}`,
    );
    const diag = JSON.parse(diagText);
    assert.equal(diag.upstreams?.notion?.oauth?.state, "needs_reauth", `diagnose: ${diagText}`);
    pass("diagnose reports needs_reauth + literal 'run in your terminal: scopegate auth login notion'");

    // 8. Calls fail FAST with an actionable message — no retry loop.
    const blocked = await client.callTool({ name: "notion__oauth_ping", arguments: {} });
    assert.equal(blocked.isError, true, "call with a dead grant must fail");
    assert.match(
      blocked.content[0].text,
      /scopegate auth login notion/,
      `error is not actionable: ${blocked.content[0].text}`,
    );
    pass("calls with a dead grant fail fast with an actionable message");

    // 9. The human re-authorizes out-of-band: runAuthLogin in a separate
    // process (device-code flow); this script plays the approving human.
    const login = startAuthLoginProcess(env);
    let loginErr = "";
    login.stderr.on("data", (d) => (loginErr += d.toString()));
    let approved = false;
    for (let i = 0; i < 60 && !approved; i++) {
      await sleep(250);
      const pending = await (await fetch(`${base}/device/pending`)).json();
      if (pending.user_codes?.length > 0) {
        const res = await fetch(`${base}/device/approve`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ user_code: pending.user_codes[0] }),
        });
        assert.equal(res.status, 200, `device approve failed: ${res.status}`);
        approved = true;
      }
    }
    assert.ok(approved, "no device user_code ever appeared at the fake IdP");
    const loginCode = await new Promise((resolve) => login.on("exit", resolve));
    assert.equal(loginCode, 0, `auth login failed (${loginCode}): ${loginErr}`);
    assert.ok(!fs.existsSync(signalPath), "reauth-required.json was not cleared by the login");
    pass("device-code login completes: blob deposited, reauth signal cleared");

    auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"oauth_reauth_completed"'), "audit missing oauth_reauth_completed");

    // 10. Back to green WITHOUT restarting the gateway: the running daemon
    // notices the cleared signal, reloads the fresh blob, and the 401 hook
    // reconnects with the new token.
    const third = await client.callTool({ name: "notion__oauth_ping", arguments: {} });
    assert.notEqual(third.isError, true, `call after re-auth failed: ${third.content[0].text}`);
    const m3 = /token=(\S+)/.exec(third.content[0].text);
    assert.ok(m3 && m3[1] !== "at-bootstrap", `unexpected token after re-auth: ${third.content[0].text}`);
    pass("flow returns to green after device login — no gateway restart");

    // The scheduler is alive again: another call after one more TTL succeeds.
    await sleep(4_000);
    const fourth = await client.callTool({ name: "notion__oauth_ping", arguments: {} });
    assert.notEqual(fourth.isError, true, `post-recovery refresh failed: ${fourth.content[0].text}`);
    pass("refresh scheduler resumed after recovery");

    // 11. Secret hygiene: no token values in the audit trail.
    auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    for (const secret of ["rt-bootstrap", "at-bootstrap", m2[1], m3[1]]) {
      assert.ok(!auditRaw.includes(secret), `audit log leaked token value '${secret}'`);
    }
    pass("audit.jsonl never contains access_token/refresh_token values");
  } finally {
    await client.close().catch(() => {});
    upstream.child.kill();
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-oauth: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-oauth FAILED: ${e.message}`);
    process.exit(1);
  });
