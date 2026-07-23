#!/usr/bin/env node
/**
 * End-to-end test for the EPIC-12 upstream registry:
 *
 *   harness (this script) → gateway (dist/cli.js start)
 *     → scopegate_register_upstream { from_registry: "fakegit" }
 *     → waiting_for_secrets (with the manifest hint)
 *     → human deposits the secret via the real CLI
 *     → diagnose green → proxied call works (secret injected at the hop)
 *
 * Also covers the fail-closed path (unknown registry entry) and the github
 * manifest's waiting_for_secrets hint. `fakegit` is the signed TEST FIXTURE
 * manifest (registry/fakegit.yaml) pointing at fake-upstream.mjs — the
 * gateway is launched from the package root (process.chdir below) so the
 * fixture's relative `node fake-upstream.mjs` command resolves.
 *
 * vaultd runs alongside (same pattern as e2e-vaultd.mjs) so the mid-session
 * human deposit is visible to the already-running gateway — the production
 * flow (in local-vault mode a running gateway holds its in-memory copy and
 * would only pick the secret up on restart).
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 * Prereq: `npm run build` (needs dist/cli.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import YAML from "yaml";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const VAULTD_JS = path.join(ROOT, "dist", "commands", "vaultd.js");
const REGISTRY = path.join(ROOT, "registry");

// The fakegit fixture manifest runs `node fake-upstream.mjs` relative to the
// gateway's cwd — pin this process (and its children) to the package root.
process.chdir(ROOT);

const watchdog = setTimeout(() => {
  console.error("e2e-registry FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/** Spawn vaultd and resolve with { child, socketPath, pid } from its ready line. */
function startVaultd(env) {
  return new Promise((resolve, reject) => {
    const runner = path.join(env.SCOPEGATE_HOME, "run-vaultd.mjs");
    fs.writeFileSync(
      runner,
      `import { runVaultd } from ${JSON.stringify(pathToFileURL(VAULTD_JS).href)};\nawait runVaultd({});\n`,
    );
    const child = spawn(process.execPath, [runner], { env, stdio: ["ignore", "pipe", "inherit"] });
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /vaultd listening on (.+?) \(pid (\d+)\)/.exec(buf);
      if (m) resolve({ child, socketPath: m[1], pid: Number(m[2]) });
    });
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`vaultd exited early (${code}): ${buf}`)));
    setTimeout(() => reject(new Error(`vaultd did not report readiness: ${buf}`)), 15_000);
  });
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);
  assert.ok(fs.existsSync(VAULTD_JS), `dist/commands/vaultd.js not found — run \`npm run build\` first`);
  assert.ok(fs.existsSync(path.join(REGISTRY, "index.sig")), `registry not signed — run node registry/sign-index.mjs`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-registry-"));
  const env = {
    ...process.env,
    SCOPEGATE_HOME: home,
    SCOPEGATE_AGENT_ID: "e2e-agent",
    SCOPEGATE_REGISTRY_PATH: REGISTRY,
    SCOPEGATE_MASTER_KEY_BACKEND: "file", // deterministic across vaultd/gateway/CLI
  };
  console.log(`e2e-registry home: ${home}`);

  const client = new Client({ name: "e2e-registry-harness", version: "1.0.0" }, { capabilities: {} });
  const daemon = await startVaultd(env);
  try {
    pass(`vaultd started (pid ${daemon.pid}) — mid-session deposits are visible to the gateway`);
    // 2. Empty config + a policy that auto-approves the fixture tool.
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify({ version: 1, agentId: "e2e-agent", upstreams: [] }, null, 2),
    );
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify(
        {
          version: 1,
          limits: { max_ttl: "30m" },
          agents: {
            "e2e-agent": {
              default_ttl: "15m",
              capabilities: [{ match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" }],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Launch the gateway as the harness would (stdio MCP).
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }));
    pass("gateway started with an empty upstream list");

    const parse = (res) => JSON.parse(res.content[0].text);

    // 4. 1-click registration of the fakegit fixture → waiting_for_secrets
    //    with the manifest's hint (fail-open would have probed/connect first).
    const reg = parse(
      await client.callTool({ name: "scopegate_register_upstream", arguments: { from_registry: "fakegit" } }),
    );
    assert.equal(reg.registered, "fakegit", `unexpected registration: ${JSON.stringify(reg)}`);
    assert.equal(reg.status, "waiting_for_secrets", `expected waiting_for_secrets: ${JSON.stringify(reg)}`);
    assert.equal(reg.from_registry, "fakegit");
    assert.match(reg.action_required, /scopegate secret add fake_token/);
    assert.ok(reg.setup_hints?.fake_token, `manifest hint missing: ${JSON.stringify(reg)}`);
    pass("register_upstream {from_registry:'fakegit'} → waiting_for_secrets with the manifest hint");

    // 4b. The registered config is the manifest's, not caller-supplied input.
    const cfgOnDisk = YAML.parse(fs.readFileSync(path.join(home, "scopegate.yaml"), "utf8"));
    const fakegit = cfgOnDisk.upstreams.find((u) => u.name === "fakegit");
    assert.ok(fakegit, "fakegit not persisted in scopegate.yaml");
    assert.deepEqual(fakegit.transport, { kind: "stdio", command: "node", args: ["fake-upstream.mjs"] });
    assert.deepEqual(fakegit.auth, { type: "env", env: { FAKE_TOKEN: "fake_token" } });
    pass("scopegate.yaml carries the manifest's UpstreamConfig verbatim (stdio node fake-upstream.mjs)");

    // 5. The human deposits the secret through the out-of-band CLI path.
    const add = spawnSync(process.execPath, [CLI, "secret", "add", "fake_token"], {
      input: "supersecret123\n",
      env,
      encoding: "utf8",
    });
    assert.equal(add.status, 0, `secret add failed: ${add.stderr || add.stdout}`);
    pass("secret deposited via CLI (stdin)");

    // 6. diagnose is green for the registry-registered upstream.
    const diag = parse(await client.callTool({ name: "scopegate_diagnose", arguments: {} }));
    assert.equal(diag.upstreams?.fakegit?.ok, true, `diagnose: ${JSON.stringify(diag)}`);
    pass("diagnose reports the registry-registered fakegit upstream ok");

    // 7. Proxied tools appear and the call works with the secret injected.
    const { tools } = await client.listTools();
    assert.ok(
      tools.some((t) => t.name === "fakegit__whoami"),
      `fakegit__whoami missing from listTools (${tools.map((t) => t.name).join(", ")})`,
    );
    const call = await client.callTool({ name: "fakegit__whoami", arguments: {} });
    assert.notEqual(call.isError, true, `proxied call failed: ${call.content[0].text}`);
    assert.match(call.content[0].text, /authenticated=true/, "env secret not injected upstream");
    pass("proxied call fakegit__whoami works end-to-end after the single human step");

    // 8. Fail-closed: an unknown registry entry registers NOTHING.
    const bad = await client.callTool({
      name: "scopegate_register_upstream",
      arguments: { from_registry: "definitely-not-in-the-registry" },
    });
    assert.equal(bad.isError, true, `unknown registry entry must fail: ${bad.content[0].text}`);
    assert.match(bad.content[0].text, /fail-closed/);
    const cfgAfterBad = YAML.parse(fs.readFileSync(path.join(home, "scopegate.yaml"), "utf8"));
    assert.equal(cfgAfterBad.upstreams.length, 1, "a failed registry lookup must not mutate config");
    pass("unknown from_registry is rejected fail-closed and mutates nothing");

    // 9. The real github manifest: waiting_for_secrets with its setup hint.
    //    (Registered LAST on purpose: nothing ever probes it, so the e2e does
    //    not depend on npx/network for @modelcontextprotocol/server-github.)
    const gh = parse(
      await client.callTool({ name: "scopegate_register_upstream", arguments: { from_registry: "github" } }),
    );
    assert.equal(gh.registered, "github", `unexpected github registration: ${JSON.stringify(gh)}`);
    assert.equal(gh.status, "waiting_for_secrets", `expected waiting_for_secrets: ${JSON.stringify(gh)}`);
    assert.match(gh.action_required, /scopegate secret add github_pat/);
    assert.match(gh.setup_hints?.github_pat ?? "", /personal-access-tokens/);
    pass("register_upstream {from_registry:'github'} → waiting_for_secrets with the PAT hint");

    // 10. Audit: both registrations recorded with their from_registry origin;
    //     the secret value never appears anywhere.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.match(auditRaw, /"upstream_registered"[^\n]*"from_registry":"fakegit"/, "audit missing fakegit from_registry");
    assert.match(auditRaw, /"upstream_registered"[^\n]*"from_registry":"github"/, "audit missing github from_registry");
    assert.match(auditRaw, /"registry_verification_failed"/, "audit missing the fail-closed denial");
    assert.ok(!auditRaw.includes("supersecret123"), "audit log leaked a secret value");
    pass("audit records upstream_registered with from_registry + the fail-closed denial, never secrets");

    // 11. from_registry composes with the manual path (additive, no regressions).
    const manual = parse(
      await client.callTool({
        name: "scopegate_register_upstream",
        arguments: {
          name: "manualapi",
          transport: { kind: "http", url: "https://api.example.com/mcp" },
          auth: { type: "bearer", secretRef: "manual_key" },
        },
      }),
    );
    assert.equal(manual.registered, "manualapi", `manual registration broke: ${JSON.stringify(manual)}`);
    assert.equal(manual.status, "waiting_for_secrets");
    assert.equal(manual.from_registry, undefined, "manual registration must not carry from_registry");
    pass("manual register_upstream keeps working unchanged alongside from_registry");
  } finally {
    await client.close().catch(() => {});
    daemon.child.kill();
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-registry: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-registry FAILED: ${e.message}`);
    process.exit(1);
  });
