#!/usr/bin/env node
/**
 * EPIC-11 (Fase 0) — automated red team pipeline for ScopeGate.
 *
 *   red team (this script, MCP client) → gateway (dist/cli.js start) → fake-upstream.mjs
 *
 * Follows the e2e-client.mjs pattern: every path is resolved relative to
 * this file; SCOPEGATE_HOME is a mkdtemp dir created and removed here, so
 * NOTHING touches the real ~/.scopegate.
 *
 * Each attack is an independent module in redteam/attacks/ exporting:
 *   export const name: string;
 *   export async function run(ctx): Promise<void>  — throws on any failed
 *     assertion. Every attack performs the DOUBLE ASSERT required by the
 *     EPIC: (a) the gateway rejected/contained the action, (b) the incident
 *     is evidenced in audit.jsonl with attribution to the agent.
 *
 * To add a new attack: drop a NN-name.mjs module in redteam/attacks/. Files
 * run in filename order — 06-honeytoken.mjs MUST stay last because it
 * suspends the agent (by design, everything afterwards is denied).
 *
 * Exit code: 0 when every attack was repelled, 1 otherwise, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url)); // scopegate/redteam
const PKG = path.dirname(ROOT); // scopegate
const CLI = path.join(PKG, "dist", "cli.js");
const FAKE_UPSTREAM = path.join(PKG, "fake-upstream.mjs");
const AGENT_ID = "red-agent";

const watchdog = setTimeout(() => {
  console.error("redteam FAILED: global timeout (120s)");
  process.exit(2);
}, 120_000);

async function loadAttacks() {
  const dir = path.join(ROOT, "attacks");
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".mjs"))
    .sort();
  const out = [];
  for (const f of files) {
    const mod = await import(pathToFileURL(path.join(dir, f)).href);
    assert.ok(mod.name && typeof mod.run === "function", `attack ${f} must export name and run(ctx)`);
    out.push(mod);
  }
  return out;
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-redteam-"));
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: AGENT_ID };
  console.log(`redteam home: ${home}`);

  const client = new Client({ name: "redteam", version: "1.0.0" }, { capabilities: {} });
  try {
    // 2. Config + policies. Hard limits are the mitigations under test:
    //    '*:*' and prod are off-limits no matter what the agent asks.
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify(
        {
          version: 1,
          agentId: AGENT_ID,
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
          limits: {
            max_ttl: "30m",
            deny: ["aws:*:production", "\\*:*"],
          },
          agents: {
            [AGENT_ID]: {
              default_ttl: "15m",
              capabilities: [
                { match: "fakegit:call:leaky", auto_approve: true, ttl: "5m" },
                { match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" },
                // rule ttl (45m) above limits.max_ttl (30m) → proves the clamp
                { match: "fakegit:call:slow", auto_approve: true, ttl: "45m" },
                // NOTE: no rule for fakegit:call:danger → attack 04.
              ],
            },
          },
        },
        null,
        2,
      ),
    );

    // 3. Secrets via the human path (CLI + piped stdin).
    for (const ref of ["fake_token", "legit_token"]) {
      const add = spawnSync(process.execPath, [CLI, "secret", "add", ref], {
        input: "supersecret123\n",
        env,
        encoding: "utf8",
      });
      assert.equal(add.status, 0, `secret add ${ref} failed: ${add.stderr || add.stdout}`);
    }

    // 4. Plant the honeytoken canary (operator action): value into the vault
    //    under canary:deploy-key, registration into honeytoken-state.json.
    process.env.SCOPEGATE_HOME = home;
    process.env.SCOPEGATE_VAULT_MODE = "local";
    const { Vault } = await import(pathToFileURL(path.join(PKG, "dist", "vault", "vault.js")).href);
    const { plantCanary } = await import(
      pathToFileURL(path.join(PKG, "dist", "honeytoken", "honeytoken.js")).href
    );
    const canary = plantCanary(Vault.open(), {
      name: "deploy-key",
      agentId: AGENT_ID,
      upstream: "github",
    });
    console.log(`canary planted: ${canary.ref}`);

    // 5. Shared attack context.
    const auditPath = path.join(home, "audit.jsonl");
    const ctx = {
      home,
      env,
      client,
      agentId: AGENT_ID,
      PKG,
      CLI,
      FAKE_UPSTREAM,
      canary,
      parse: (res) => JSON.parse(res.content[0].text),
      auditRaw: () => (fs.existsSync(auditPath) ? fs.readFileSync(auditPath, "utf8") : ""),
      auditEvents: () =>
        (fs.existsSync(auditPath) ? fs.readFileSync(auditPath, "utf8") : "")
          .split("\n")
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l)),
    };

    // 6. Gateway as the harness would launch it (stdio MCP).
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }),
    );

    // 7. Run every attack module in order; a failure never stops the rest.
    const attacks = await loadAttacks();
    const failures = [];
    for (const attack of attacks) {
      try {
        await attack.run(ctx);
        console.log(`PASS - ${attack.name}`);
      } catch (e) {
        failures.push(attack.name);
        console.error(`FAIL - ${attack.name}: ${e.message}`);
      }
    }

    if (failures.length > 0) {
      console.error(`\nredteam: ${failures.length}/${attacks.length} attacks GOT THROUGH: ${failures.join(", ")}`);
      process.exitCode = 1;
    } else {
      console.log(`\nredteam: ALL ${attacks.length} ATTACKS REPELLED (double-asserted vs audit.jsonl)`);
    }
  } finally {
    await client.close().catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
    delete process.env.SCOPEGATE_HOME;
  }
}

main()
  .then(() => clearTimeout(watchdog))
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\nredteam FAILED: ${e.message}`);
    process.exit(1);
  });
