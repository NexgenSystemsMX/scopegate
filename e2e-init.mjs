#!/usr/bin/env node
/**
 * Portable end-to-end test for multi-harness `scopegate init` (EPIC-06).
 *
 *   fixtures (4 harnesses) → node dist/cli.js init → secret add → gateway
 *   (dist/cli.js start) → first tool call through fake-upstream.mjs
 *
 * Mounts a throwaway HOME with fixture configs for Claude Code, Kimi Code,
 * Cursor and OpenCode, runs the REAL init as a child process, completes a
 * pending oauth2 migration via piped `secret add`, and measures the
 * time-to-first-tool-call SLO (< 90 s). Also asserts: backups created and
 * immutable, no plaintext secrets left in any config, agent identity
 * coherence (SCOPEGATE_AGENT_ID == scopegate.yaml agentId), and that a
 * second `init` run is a byte-identical no-op.
 *
 * Portable: every path is resolved relative to this file; the temp tree is
 * created and removed by this script. No network access (remote fixtures
 * point at 127.0.0.1:9 and fail fast by design).
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");
const SLO_MS = 90_000;

const watchdog = setTimeout(() => {
  console.error("e2e-init FAILED: global timeout (120s)");
  process.exit(2);
}, 120_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/** Run a CLI command as a child process; assert exit 0; return stdout. */
function runCli(args, { env, cwd, input } = {}) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    env,
    cwd,
    input,
    encoding: "utf8",
  });
  assert.equal(res.status, 0, `cli ${args.join(" ")} failed (${res.status}): ${res.stderr || res.stdout}`);
  return res.stdout;
}

const writeJson = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const raw = JSON.stringify(value, null, 2);
  fs.writeFileSync(file, raw);
  return raw;
};

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway tree: user home + project dir + SCOPEGATE_HOME.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-init-"));
  const home = path.join(root, "home");
  const project = path.join(root, "project");
  const sgHome = path.join(root, "scopegate");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  console.log(`e2e-init sandbox: ${root}`);

  // Child env: harness home override, NO inherited KIMI_CODE_HOME /
  // SCOPEGATE_PROJECT_DIR / KIMI_SVC_TOKEN (the last one stays unset so the
  // kimi fixture migrates as oauth2-pending).
  const env = { ...process.env, SCOPEGATE_HOME: sgHome, HOME: home, USERPROFILE: home };
  delete env.KIMI_CODE_HOME;
  delete env.SCOPEGATE_PROJECT_DIR;
  delete env.KIMI_SVC_TOKEN;

  const files = {
    claudeProject: path.join(project, ".mcp.json"),
    claudeUser: path.join(home, ".claude.json"),
    kimiUser: path.join(home, ".kimi-code", "mcp.json"),
    cursorUser: path.join(home, ".cursor", "mcp.json"),
    opencodeProject: path.join(project, "opencode.json"),
  };

  // 2. Fixture configs for the four harnesses, with plaintext secrets.
  const originals = {
    [files.claudeProject]: writeJson(files.claudeProject, {
      mcpServers: {
        fakegit: {
          command: process.execPath,
          args: [FAKE_UPSTREAM],
          env: { FAKE_TOKEN: "supersecret123", PLAIN: "not-a-secret" },
        },
      },
    }),
    [files.claudeUser]: writeJson(files.claudeUser, {
      mcpServers: {
        remotesvc: {
          type: "http",
          url: "http://127.0.0.1:9/mcp",
          headers: { Authorization: "Bearer remote-secret-aaa", "X-Api-Key": "remote-secret-bbb" },
        },
      },
    }),
    [files.kimiUser]: writeJson(files.kimiUser, {
      mcpServers: {
        kimisvc: { url: "http://127.0.0.1:9/kimi", bearerTokenEnvVar: "KIMI_SVC_TOKEN" },
      },
    }),
    [files.cursorUser]: writeJson(files.cursorUser, {
      mcpServers: {
        cursorsvc: { url: "http://127.0.0.1:9/cursor", headers: { "X-Api-Key": "cursor-secret" } },
      },
    }),
    [files.opencodeProject]: writeJson(files.opencodeProject, {
      $schema: "https://opencode.ai/config.json",
      mcp: {
        oclocal: {
          type: "local",
          command: [process.execPath, FAKE_UPSTREAM],
          environment: { FAKE_TOKEN: "supersecret123" },
        },
        ocremote: { type: "remote", url: "http://127.0.0.1:9/oc", headers: { Authorization: "Bearer oc-secret" } },
      },
    }),
  };
  const PLAINTEXTS = [
    "supersecret123",
    "remote-secret-aaa",
    "remote-secret-bbb",
    "cursor-secret",
    "oc-secret",
    "kimi-secret-xyz", // deposited later; must never land in a config
  ];

  const client = new Client({ name: "e2e-init-harness", version: "1.0.0" }, { capabilities: {} });
  try {
    // 3. THE CLOCK STARTS: real init as a child process.
    const t0 = Date.now();
    const initOut = runCli(["init"], { env, cwd: project });
    assert.match(initOut, /DONE\. Upstreams behind the gateway/);
    assert.match(initOut, /PENDING auth \(oauth2\)/, "kimi bearerTokenEnvVar must migrate as pending, with a warning");
    pass("init migrated all 4 harnesses (5 config files), exit 0");

    // 4. Every config rewritten: scopegate as the only entry, in each
    //    harness's own format, carrying the scopegate.yaml agentId.
    const cfg = YAML.parse(fs.readFileSync(path.join(sgHome, "scopegate.yaml"), "utf8"));
    const agentId = cfg.agentId;
    for (const f of [files.claudeProject, files.claudeUser, files.kimiUser, files.cursorUser]) {
      const json = JSON.parse(fs.readFileSync(f, "utf8"));
      assert.deepEqual(Object.keys(json.mcpServers), ["scopegate"], `${f} must expose only scopegate`);
      assert.equal(json.mcpServers.scopegate.command, "scopegate");
      assert.deepEqual(json.mcpServers.scopegate.args, ["start"]);
      assert.equal(json.mcpServers.scopegate.env.SCOPEGATE_AGENT_ID, agentId);
    }
    const oc = JSON.parse(fs.readFileSync(files.opencodeProject, "utf8"));
    assert.deepEqual(oc.mcp, {
      scopegate: {
        type: "local",
        command: ["scopegate", "start"],
        environment: { SCOPEGATE_AGENT_ID: agentId },
        enabled: true,
      },
    });
    pass("every harness config: scopegate is the only MCP entry, SCOPEGATE_AGENT_ID == scopegate.yaml agentId");

    // 5. Immutable backups with the exact original bytes.
    for (const [f, raw] of Object.entries(originals)) {
      assert.equal(fs.readFileSync(f + ".pre-scopegate.bak", "utf8"), raw, `backup of ${f} must hold the original bytes`);
    }
    pass("all .pre-scopegate.bak backups created with the original bytes");

    // 6. scopegate.yaml: 6 upstreams, oauth2-pending never degraded,
    //    migration fingerprints persisted.
    const names = cfg.upstreams.map((u) => u.name).sort();
    assert.deepEqual(names, ["cursorsvc", "fakegit", "kimisvc", "oclocal", "ocremote", "remotesvc"]);
    const kimisvc = cfg.upstreams.find((u) => u.name === "kimisvc");
    assert.equal(kimisvc.auth.type, "oauth2", "pending auth must never degrade to none");
    assert.equal(kimisvc.auth.secretRef, "kimisvc_bearer_token");
    const remotesvc = cfg.upstreams.find((u) => u.name === "remotesvc");
    assert.equal(remotesvc.auth.type, "bearer");
    assert.equal(remotesvc.auth.header, "Authorization");
    assert.ok(cfg.migrations, "scopegate.yaml must persist migration fingerprints");
    for (const perConfig of Object.values(cfg.migrations)) {
      for (const fp of Object.values(perConfig)) assert.match(fp, /^sha256:[0-9a-f]{64}$/);
    }
    assert.ok(fs.existsSync(path.join(sgHome, "identity.json")), "agent identity must exist");
    pass("scopegate.yaml: 6 upstreams, kimisvc oauth2-pending (not none), sha256 fingerprints, identity created");

    // 7. No plaintext secret survives in any rewritten config or scopegate.yaml
    //    (backups intentionally keep the pre-migration original — they are the
    //    rollback target, excluded from this scan by design).
    for (const f of [...Object.keys(originals), path.join(sgHome, "scopegate.yaml")]) {
      const raw = fs.readFileSync(f, "utf8");
      for (const secret of PLAINTEXTS) {
        assert.ok(!raw.includes(secret), `${f} still contains a plaintext secret`);
      }
    }
    pass("no plaintext secrets in rewritten configs or scopegate.yaml");

    // 8. Complete the pending migration through the human path: piped secret add.
    runCli(["secret", "add", "kimisvc_bearer_token"], { env, input: "kimi-secret-xyz\n" });
    const ls = runCli(["secret", "ls"], { env });
    assert.match(ls, /kimisvc_bearer_token/);
    pass("pending oauth2 secret deposited via piped `secret add`");

    // 9. Start the gateway as the harness would and make the first tool call.
    const gatewayEnv = { ...env, SCOPEGATE_AGENT_ID: agentId };
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env: gatewayEnv }));
    const { tools } = await client.listTools();
    const toolNames = tools.map((t) => t.name);
    for (const required of ["fakegit__whoami", "oclocal__whoami"]) {
      assert.ok(toolNames.includes(required), `listTools missing '${required}' (got: ${toolNames.join(", ")})`);
    }
    const grant = JSON.parse(
      (await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:whoami", ttl: "15m", reason: "e2e-init" },
      })).content[0].text,
    );
    assert.equal(grant.granted, true, `expected grant, got: ${JSON.stringify(grant)}`);
    const call = await client.callTool({ name: "fakegit__whoami", arguments: {} });
    assert.notEqual(call.isError, true, `proxied call failed: ${call.content[0].text}`);
    assert.match(call.content[0].text, /authenticated=true/, "vaulted secret not injected upstream");
    const ocCall = await client.callTool({ name: "oclocal__whoami", arguments: {} });
    assert.match(ocCall.content[0].text, /authenticated=true/, "opencode-migrated upstream not authenticated");
    const elapsed = Date.now() - t0;
    pass("first tool call succeeded through 2 migrated stdio upstreams (claude + opencode)");

    console.log(`\ntime-to-first-tool-call: ${(elapsed / 1000).toFixed(2)}s (budget: ${SLO_MS / 1000}s)`);
    assert.ok(elapsed < SLO_MS, `SLO violated: ${elapsed}ms >= ${SLO_MS}ms`);
    pass(`SLO met: time-to-first-tool-call < 90s`);

    // 10. Re-run init: byte-identical no-op across configs, backups and
    //     scopegate.yaml.
    const watched = [...Object.keys(originals), ...Object.keys(originals).map((f) => f + ".pre-scopegate.bak"), path.join(sgHome, "scopegate.yaml")];
    const before = watched.map((f) => fs.readFileSync(f, "utf8"));
    const rerunOut = runCli(["init"], { env, cwd: project });
    const after = watched.map((f) => fs.readFileSync(f, "utf8"));
    assert.deepEqual(after, before, "second init run must change nothing on disk");
    assert.match(rerunOut, /already up to date — no changes/);
    assert.doesNotMatch(rerunOut, /migrated MCP '/);
    pass("second init run is a byte-identical no-op (immutable backups kept)");
  } finally {
    await client.close().catch(() => {});
    fs.rmSync(root, { recursive: true, force: true });
  }

  console.log("\ne2e-init: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-init FAILED: ${e.message}`);
    process.exit(1);
  });
