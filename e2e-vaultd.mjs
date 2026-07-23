#!/usr/bin/env node
/**
 * Portable end-to-end test for vaultd (EPIC-05).
 *
 *   this script (Vault facade, daemon transport) → vaultd (child process)
 *
 * Covers: vaultd startup on the platform transport (named pipe on Windows,
 * unix socket on POSIX), the unchanged sync Vault API over IPC, ciphertext
 * only on disk, status/rotate ops, failover to the local vault when the
 * daemon dies, and a local `vault rotate-key` afterwards.
 *
 * Portable: every path resolves relative to this file; SCOPEGATE_HOME is a
 * mkdtemp dir removed at the end; the master key backend is pinned to `file`
 * for determinism (OS backends are covered by tests/vaultd.test.ts). The
 * daemon is launched straight from dist/commands/vaultd.js because wiring the
 * `vaultd` command into cli.ts belongs to the orchestrator, not to this file.
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(ROOT, "dist");
const VAULTD_JS = path.join(DIST, "commands", "vaultd.js");
const VAULT_JS = path.join(DIST, "vault", "vault.js");
const CLIENT_JS = path.join(DIST, "vault", "client.js");
const ROTATE_JS = path.join(DIST, "commands", "vault-rotate.js");

const watchdog = setTimeout(() => {
  console.error("e2e-vaultd FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Spawn vaultd and resolve with { child, socketPath, pid } from its ready line. */
function startVaultd(env) {
  return new Promise((resolve, reject) => {
    const home = env.SCOPEGATE_HOME;
    const runner = path.join(home, "run-vaultd.mjs");
    fs.writeFileSync(
      runner,
      `import { runVaultd } from ${JSON.stringify(pathToFileURL(VAULTD_JS).href)};\nawait runVaultd({});\n`,
    );
    const child = spawn(process.execPath, [runner], {
      env,
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /vaultd listening on (.+?) \(pid (\d+)\)/.exec(buf);
      if (m) resolve({ child, socketPath: m[1], pid: Number(m[2]) });
    });
    child.on("error", reject);
    child.on("exit", (code) =>
      reject(new Error(`vaultd exited early (${code}): ${buf}`)),
    );
    setTimeout(() => reject(new Error(`vaultd did not report readiness: ${buf}`)), 15_000);
  });
}

async function main() {
  for (const f of [VAULTD_JS, VAULT_JS, CLIENT_JS, ROTATE_JS]) {
    assert.ok(fs.existsSync(f), `${f} not found — run \`npm run build\` first`);
  }

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-vaultd-e2e-"));
  const env = {
    ...process.env,
    SCOPEGATE_HOME: home,
    SCOPEGATE_MASTER_KEY_BACKEND: "file",
  };
  process.env.SCOPEGATE_HOME = home;
  process.env.SCOPEGATE_MASTER_KEY_BACKEND = "file";
  console.log(`e2e-vaultd home: ${home}`);
  console.log(`transport: ${process.platform === "win32" ? "named pipe" : "unix socket"}`);

  const daemon = await startVaultd(env);
  try {
    pass(`vaultd started (pid ${daemon.pid}) at ${daemon.socketPath}`);

    const { Vault } = await import(pathToFileURL(VAULT_JS).href);
    const { VaultIpcClient } = await import(pathToFileURL(CLIENT_JS).href);
    const vaultEncPath = path.join(home, "vault.enc");

    // 2. status op: identifies the daemon, never leaks values.
    const ipc = await VaultIpcClient.connect(daemon.socketPath, 2_000);
    const status = await ipc.request("status", {}, 2_000);
    assert.equal(status.pid, daemon.pid, "status pid must be the vaultd child");
    assert.equal(status.masterKeyBackend, "file");
    assert.ok(status.kid, "status must report the current kid");
    assert.ok(!JSON.stringify(status).includes("secret"), "status leaked data");
    ipc.close();
    pass("status op reports pid/backend/kid and no secret material");

    // 3. The unchanged public Vault API works over the daemon transport.
    process.env.SCOPEGATE_VAULT_MODE = "daemon";
    const v = Vault.open();
    v.set("github_token", "ghp_e2e_secret_1234567890abcdef");
    v.set("aws_key", "AKIA_e2e_secret_value");
    assert.equal(v.get("github_token"), "ghp_e2e_secret_1234567890abcdef");
    assert.equal(v.has("aws_key"), true);
    assert.deepEqual(v.listRefs(), ["aws_key", "github_token"]);
    v.delete("aws_key");
    assert.equal(v.has("aws_key"), false);
    pass("set/get/has/listRefs/delete through Vault in daemon mode");

    // 4. vault.enc holds ciphertext only, in VaultFile v2 form.
    const raw1 = fs.readFileSync(vaultEncPath, "utf8");
    assert.ok(!raw1.includes("ghp_e2e_secret"), "plaintext secret in vault.enc");
    assert.ok(!raw1.includes("AKIA_e2e_secret"), "plaintext secret in vault.enc");
    const parsed1 = JSON.parse(raw1);
    assert.equal(parsed1.v, 2, "vault.enc must be VaultFile v2");
    assert.ok(parsed1.kid, "vault.enc must carry a kid");
    pass("vault.enc never contains plaintext (v=2, kid present)");

    // 5. rotate through the daemon: kid changes, secrets survive, backup written.
    const ipc2 = await VaultIpcClient.connect(daemon.socketPath, 2_000);
    const rot = await ipc2.request("rotate", {}, 30_000);
    ipc2.close();
    assert.ok(rot.newKid && rot.newKid !== rot.oldKid, "rotate must change the kid");
    assert.ok(fs.existsSync(rot.backupPath), "rotate must write a backup");
    assert.equal(Vault.open().get("github_token"), "ghp_e2e_secret_1234567890abcdef");
    pass(`rotate via vaultd: kid ${rot.oldKid} → ${rot.newKid}, backup verified`);

    // 6. Kill the daemon: the SAME Vault instance fails over to local.
    process.env.SCOPEGATE_VAULT_MODE = "auto";
    const vf = Vault.open(); // daemon alive → daemon transport
    assert.equal(vf.get("github_token"), "ghp_e2e_secret_1234567890abcdef");
    daemon.child.kill();
    await new Promise((r) => daemon.child.once("exit", r));
    await sleep(300);
    assert.equal(vf.get("github_token"), "ghp_e2e_secret_1234567890abcdef");
    vf.set("post_failover", "local_only_value_999");
    assert.equal(Vault.open().get("post_failover"), "local_only_value_999");
    pass("vaultd killed mid-session → transparent failover to the local vault");

    // 7. Local `vault rotate-key` with the daemon down.
    const { runVaultRotateKey } = await import(pathToFileURL(ROTATE_JS).href);
    await runVaultRotateKey({});
    const parsed2 = JSON.parse(fs.readFileSync(vaultEncPath, "utf8"));
    assert.ok(parsed2.kid !== rot.newKid, "local rotate must change the kid again");
    assert.equal(Vault.open().get("github_token"), "ghp_e2e_secret_1234567890abcdef");
    pass("local vault rotate-key keeps secrets readable and changes kid");

    // 8. Final plaintext sweep across every file vaultd/rotate produced.
    for (const f of fs.readdirSync(home)) {
      if (!f.startsWith("vault.enc")) continue;
      const content = fs.readFileSync(path.join(home, f), "utf8");
      assert.ok(!content.includes("ghp_e2e_secret"), `${f} contains plaintext`);
      assert.ok(!content.includes("local_only_value"), `${f} contains plaintext`);
    }
    pass("no vault.enc* file (including backups) ever contains plaintext");
  } finally {
    daemon.child.kill("SIGKILL");
    await sleep(100);
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e-vaultd: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-vaultd FAILED: ${e.message}`);
    process.exit(1);
  });
