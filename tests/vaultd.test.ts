/**
 * EPIC-05 tests: vault core v2/kid, rotate-key, MasterKeyStore backends,
 * vaultd IPC protocol, and the Vault facade's daemon transport + failover.
 *
 * Layout notes:
 * - In-process vaultd servers are only ever driven with the ASYNC client
 *   (VaultIpcClient). The sync facade blocks the event loop by design, so it
 *   is always tested against vaultd running as a CHILD PROCESS.
 * - Child-process tests run dist/ code (a test process cannot import src/.ts
 *   into a child); they skip elegantly when `npm run build` has not produced
 *   dist/commands/vaultd.js.
 */
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST_VAULTD = path.resolve(HERE, "..", "dist", "commands", "vaultd.js");
const hasDistVaultd = fs.existsSync(DIST_VAULTD);
/** Tests that spawn vaultd from dist/ — skipped without a build. */
const itDist = hasDistVaultd ? it : it.skip;

let home: string;
const daemonChildren: ChildProcess[] = [];

beforeEach(() => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local";
  process.env.SCOPEGATE_MASTER_KEY_BACKEND = "file";
});

afterEach(async () => {
  for (const child of daemonChildren.splice(0)) child.kill("SIGKILL");
  delete process.env.SCOPEGATE_VAULT_MODE;
  delete process.env.SCOPEGATE_MASTER_KEY_BACKEND;
  delete process.env.SCOPEGATE_VAULT_SOCKET;
  const { closeVaultTransports } = await import("../src/vault/client.js");
  closeVaultTransports();
  cleanupTempHome(home);
});

function testSocketPath(name: string): string {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\scopegate-test-${process.pid}-${Date.now()}-${name}`;
  }
  return path.join(home, `${name}.sock`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Craft a Fase 0 (v1) vault.enc with the given hex master key. */
function craftV1VaultFile(
  vaultPath: string,
  masterKeyHex: string,
  secrets: Record<string, string>,
): void {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(Buffer.from(masterKeyHex, "hex"), salt, 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([
    cipher.update(JSON.stringify(secrets), "utf8"),
    cipher.final(),
  ]);
  fs.writeFileSync(
    vaultPath,
    JSON.stringify({
      v: 1,
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      data: data.toString("base64"),
    }),
    { mode: 0o600 },
  );
}

/** Decrypt a vault.enc (v1 or v2) with a hex master key (test helper). */
function decryptVaultFileWithHex(
  f: { v: number; salt: string; iv: string; tag: string; data: string },
  masterKeyHex: string,
): Record<string, string> {
  const key = crypto.scryptSync(
    Buffer.from(masterKeyHex, "hex"),
    Buffer.from(f.salt, "base64"),
    32,
  );
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(f.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(f.tag, "base64"));
  return JSON.parse(
    Buffer.concat([
      decipher.update(Buffer.from(f.data, "base64")),
      decipher.final(),
    ]).toString("utf8"),
  ) as Record<string, string>;
}

/** Spawn vaultd (dist) as a child process and wait until it answers status. */
async function startDaemonChild(sock: string): Promise<ChildProcess> {
  const runner = path.join(home, "run-vaultd.mjs");
  fs.writeFileSync(
    runner,
    `import { runVaultd } from ${JSON.stringify(pathToFileURL(DIST_VAULTD).href)};\n` +
      "await runVaultd({ socket: process.env.VAULTD_SOCK });\n",
  );
  const child = spawn(process.execPath, [runner], {
    env: {
      ...process.env,
      SCOPEGATE_HOME: home,
      SCOPEGATE_MASTER_KEY_BACKEND: "file",
      VAULTD_SOCK: sock,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemonChildren.push(child);
  const { probeVaultd } = await import("../src/vault/client.js");
  const deadline = Date.now() + 15_000;
  for (;;) {
    if (await probeVaultd(sock, 250)) return child;
    if (child.exitCode !== null) {
      throw new Error(`vaultd child exited early (code ${child.exitCode})`);
    }
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error("vaultd child did not become ready within 15s");
    }
    await sleep(100);
  }
}

// ---------------------------------------------------------------------------
// LocalVaultCore: v2 format, v1 compat, rotation
// ---------------------------------------------------------------------------

describe("LocalVaultCore", () => {
  it("writes VaultFile v2 with the kid of the current master key", async () => {
    const { LocalVaultCore, kidForKey } = await import("../src/vault/core.js");
    const { VAULT_PATH, MASTER_KEY_PATH } = await import(
      "../src/config/config.js"
    );
    const core = LocalVaultCore.open();
    core.set("api_key", "supersecret123");
    const parsed = JSON.parse(fs.readFileSync(VAULT_PATH, "utf8"));
    expect(parsed.v).toBe(2);
    const keyHex = fs.readFileSync(MASTER_KEY_PATH, "utf8").trim();
    expect(parsed.kid).toBe(kidForKey(Buffer.from(keyHex, "hex")));
    expect(core.kid).toBe(parsed.kid);
    expect(fs.readFileSync(VAULT_PATH, "utf8")).not.toContain("supersecret123");
  });

  it("reads v1 files (kid 'legacy') and upgrades them to v2 on next write", async () => {
    const { LocalVaultCore } = await import("../src/vault/core.js");
    const { VAULT_PATH, MASTER_KEY_PATH, ensureDir } = await import(
      "../src/config/config.js"
    );
    ensureDir();
    const keyHex = crypto.randomBytes(32).toString("hex");
    fs.writeFileSync(MASTER_KEY_PATH, keyHex + "\n", { mode: 0o600 });
    craftV1VaultFile(VAULT_PATH, keyHex, { old_ref: "old_value" });

    const core = LocalVaultCore.open();
    expect(core.get("old_ref")).toBe("old_value");
    expect(core.kid).toBe("legacy");

    core.set("new_ref", "new_value");
    const parsed = JSON.parse(fs.readFileSync(VAULT_PATH, "utf8"));
    expect(parsed.v).toBe(2);
    expect(parsed.kid).not.toBe("legacy");
    expect(LocalVaultCore.open().get("old_ref")).toBe("old_value");
  });

  it("rotate-key keeps secrets readable, changes kid and writes a verified backup", async () => {
    const { LocalVaultCore, kidForKey } = await import("../src/vault/core.js");
    const { VAULT_PATH, MASTER_KEY_PATH } = await import(
      "../src/config/config.js"
    );
    const core = LocalVaultCore.open();
    core.set("alpha", "value-alpha");
    core.set("beta", "value-beta");
    core.set("gamma", "value-gamma");
    const oldKeyHex = fs.readFileSync(MASTER_KEY_PATH, "utf8").trim();
    const oldKid = kidForKey(Buffer.from(oldKeyHex, "hex"));

    const res = core.rotateMasterKey({ backend: "file" });
    expect(res.oldKid).toBe(oldKid);
    expect(res.newKid).not.toBe(oldKid);
    expect(res.backend).toBe("file");
    expect(core.kid).toBe(res.newKid);

    // Backup exists, is the pre-rotation file, and decrypts with the OLD key.
    expect(res.backupPath).toBe(`${VAULT_PATH}.${oldKid}.bak`);
    const bak = JSON.parse(fs.readFileSync(res.backupPath, "utf8"));
    expect(decryptVaultFileWithHex(bak, oldKeyHex)).toEqual({
      alpha: "value-alpha",
      beta: "value-beta",
      gamma: "value-gamma",
    });

    // The key on disk changed; a fresh open reads every secret.
    const newKeyHex = fs.readFileSync(MASTER_KEY_PATH, "utf8").trim();
    expect(newKeyHex).not.toBe(oldKeyHex);
    const fresh = LocalVaultCore.open();
    expect(fresh.listRefs()).toEqual(["alpha", "beta", "gamma"]);
    expect(fresh.get("beta")).toBe("value-beta");
    expect(fresh.kid).toBe(res.newKid);

    // The current vault.enc is v2 under the NEW kid and undecryptable by the old key.
    const current = JSON.parse(fs.readFileSync(VAULT_PATH, "utf8"));
    expect(current.v).toBe(2);
    expect(current.kid).toBe(res.newKid);
    expect(() => decryptVaultFileWithHex(current, oldKeyHex)).toThrow();
  });

  it("rotate-key on a legacy v1 vault reports oldKid 'legacy' and backs up the v1 bytes", async () => {
    const { LocalVaultCore } = await import("../src/vault/core.js");
    const { VAULT_PATH, MASTER_KEY_PATH, ensureDir } = await import(
      "../src/config/config.js"
    );
    ensureDir();
    const keyHex = crypto.randomBytes(32).toString("hex");
    fs.writeFileSync(MASTER_KEY_PATH, keyHex + "\n", { mode: 0o600 });
    craftV1VaultFile(VAULT_PATH, keyHex, { legacy_ref: "legacy_value" });

    const res = LocalVaultCore.open().rotateMasterKey({ backend: "file" });
    expect(res.oldKid).toBe("legacy");
    const bak = JSON.parse(fs.readFileSync(res.backupPath, "utf8"));
    expect(bak.v).toBe(1);
    expect(decryptVaultFileWithHex(bak, keyHex)).toEqual({
      legacy_ref: "legacy_value",
    });
    expect(LocalVaultCore.open().get("legacy_ref")).toBe("legacy_value");
  });

  it("runVaultRotateKey rotates locally when no vaultd answers", async () => {
    const { LocalVaultCore } = await import("../src/vault/core.js");
    const { VAULT_PATH } = await import("../src/config/config.js");
    const core = LocalVaultCore.open();
    core.set("k", "v");
    const kidBefore = core.kid;

    const { runVaultRotateKey } = await import(
      "../src/commands/vault-rotate.js"
    );
    await runVaultRotateKey({});

    const after = LocalVaultCore.open();
    expect(after.get("k")).toBe("v");
    expect(after.kid).not.toBe(kidBefore);
    expect(
      fs.existsSync(`${VAULT_PATH}.${kidBefore}.bak`),
      "pre-rotation backup must exist",
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// MasterKeyStore backends
// ---------------------------------------------------------------------------

describe("MasterKeyStore", () => {
  it("file backend: load() is null before store(), then roundtrips", async () => {
    const { selectMasterKeyStore } = await import("../src/vault/masterkey.js");
    const store = selectMasterKeyStore("file");
    expect(store.backend).toBe("file");
    expect(store.load()).toBeNull();
    const key = crypto.randomBytes(32);
    store.store(key);
    expect(store.load()?.equals(key)).toBe(true);
  });

  it("rejects an unknown backend name with an actionable error", async () => {
    const { selectMasterKeyStore } = await import("../src/vault/masterkey.js");
    expect(() => selectMasterKeyStore("bogus")).toThrow(
      /unknown master key backend 'bogus'/,
    );
  });

  it("auto-selects per platform (OS backend when available, else file)", async () => {
    delete process.env.SCOPEGATE_MASTER_KEY_BACKEND;
    const mk = await import("../src/vault/masterkey.js");
    const store = mk.selectMasterKeyStore();
    if (process.platform === "win32" && mk.isDpapiAvailable()) {
      expect(store.backend).toBe("dpapi");
    } else if (process.platform === "darwin") {
      expect(store.backend).toBe("keychain");
    } else if (process.platform === "linux") {
      expect(["secret-service", "file"]).toContain(store.backend);
    } else {
      expect(store.backend).toBe("file");
    }
  });

  const itDpapi = process.platform === "win32" ? it : it.skip;
  itDpapi("dpapi backend: blob holds no plaintext key and unprotects via DPAPI", async () => {
    const mk = await import("../src/vault/masterkey.js");
    if (!mk.isDpapiAvailable()) {
      console.warn("powershell.exe unavailable in this environment — skipping dpapi assertions");
      return;
    }
    const store = mk.selectMasterKeyStore("dpapi");
    expect(store.backend).toBe("dpapi");
    expect(store.load()).toBeNull();

    const key = crypto.randomBytes(32);
    store.store(key);
    const blobPath = path.join(home, "master.dpapi");
    const blob = fs.readFileSync(blobPath, "utf8").trim();
    expect(blob).not.toContain(key.toString("hex"));
    expect(blob).not.toContain(key.toString("base64"));

    // Independent verification: unprotect the blob with a raw powershell call
    // (not the store's in-memory cache).
    const unprotectPs = [
      "$ErrorActionPreference='Stop'",
      "Add-Type -AssemblyName System.Security",
      "$in=[Console]::In.ReadToEnd().Trim()",
      "$p=[Convert]::FromBase64String($in)",
      "$b=[System.Security.Cryptography.ProtectedData]::Unprotect($p,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
      "[Console]::Out.Write([Convert]::ToBase64String($b))",
    ].join("\n");
    const r = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", unprotectPs],
      { input: blob, encoding: "utf8", timeout: 15_000 },
    );
    expect(r.status).toBe(0);
    expect(Buffer.from(r.stdout.trim(), "base64").equals(key)).toBe(true);
  });

  itDpapi("dpapi backend: end-to-end vault open/set/get without master.key", async () => {
    const mk = await import("../src/vault/masterkey.js");
    if (!mk.isDpapiAvailable()) {
      console.warn("powershell.exe unavailable in this environment — skipping dpapi assertions");
      return;
    }
    process.env.SCOPEGATE_MASTER_KEY_BACKEND = "dpapi";
    const { LocalVaultCore } = await import("../src/vault/core.js");
    const core = LocalVaultCore.open();
    expect(core.masterKeyBackend).toBe("dpapi");
    core.set("token", "dpapi-protected-value");
    expect(LocalVaultCore.open().get("token")).toBe("dpapi-protected-value");
    expect(fs.existsSync(path.join(home, "master.key"))).toBe(false);
    expect(fs.existsSync(path.join(home, "master.dpapi"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// vaultd IPC (in-process server, async client)
// ---------------------------------------------------------------------------

describe("vaultd IPC (in-process server)", () => {
  it("resolves the default socket path per platform", async () => {
    const { defaultVaultSocketPath, vaultTransportKind } = await import(
      "../src/vault/transport.js"
    );
    const p = defaultVaultSocketPath();
    if (process.platform === "win32") {
      expect(p).toMatch(/^\\\\\.\\pipe\\scopegate-vault-[0-9a-f]{8}$/);
      expect(vaultTransportKind(p)).toBe("pipe");
    } else {
      expect(p).toBe(path.join(home, "vault.sock"));
      expect(vaultTransportKind(p)).toBe("unix");
    }
  });

  it("serves ops roundtrip and status; socket is 0600 on POSIX", async () => {
    const { startVaultdServer } = await import("../src/vault/daemon.js");
    const { VaultIpcClient } = await import("../src/vault/client.js");
    const sock = testSocketPath("ops");
    const server = await startVaultdServer({ socket: sock });
    try {
      if (process.platform !== "win32") {
        expect(fs.statSync(sock).mode & 0o777).toBe(0o600);
      }
      const client = await VaultIpcClient.connect(sock, 2_000);
      await client.request("set", { ref: "github_token", value: "ghp_test_value" });
      await client.request("set", { ref: "aws_key", value: "AKIA_test_value" });
      expect(await client.request("get", { ref: "github_token" })).toBe("ghp_test_value");
      expect(await client.request("has", { ref: "aws_key" })).toBe(true);
      expect(await client.request("has", { ref: "missing" })).toBe(false);
      expect(await client.request("listRefs")).toEqual(["aws_key", "github_token"]);
      await client.request("delete", { ref: "aws_key" });
      expect(await client.request("listRefs")).toEqual(["github_token"]);

      const status = (await client.request("status")) as Record<string, unknown>;
      expect(status.status).toBe("ok");
      expect(status.pid).toBe(process.pid);
      expect(status.masterKeyBackend).toBe("file");
      expect(status.refs).toBe(1);
      expect(typeof status.kid).toBe("string");
      expect(status.transport).toBe(
        process.platform === "win32" ? "pipe" : "unix",
      );
      expect(JSON.stringify(status)).not.toContain("ghp_test_value");
      client.close();
    } finally {
      await server.close();
    }
  });

  it("returns the exact local not-found message for missing refs", async () => {
    const { startVaultdServer } = await import("../src/vault/daemon.js");
    const { VaultIpcClient } = await import("../src/vault/client.js");
    const sock = testSocketPath("notfound");
    const server = await startVaultdServer({ socket: sock });
    try {
      const client = await VaultIpcClient.connect(sock, 2_000);
      await expect(client.request("get", { ref: "nope" })).rejects.toThrow(
        /Vault: secret 'nope' not found\. Deposit it with: scopegate secret add nope/,
      );
      client.close();
    } finally {
      await server.close();
    }
  });

  it("rejects oversize frames, unknown ops and malformed JSON", async () => {
    const { startVaultdServer } = await import("../src/vault/daemon.js");
    const sock = testSocketPath("frames");
    const server = await startVaultdServer({ socket: sock });
    try {
      // 1. Unknown op (well-formed frame).
      const reply1 = await rawExchange(sock, JSON.stringify({ id: 1, op: "bogus" }) + "\n");
      expect(reply1.ok).toBe(false);
      expect(reply1.error).toMatch(/unknown op 'bogus'/);

      // 2. Malformed JSON.
      const reply2 = await rawExchange(sock, "this is not json\n");
      expect(reply2.ok).toBe(false);
      expect(reply2.error).toMatch(/invalid JSON frame/);

      // 3. Oversize frame (> 64 KiB single line) → error + connection dropped.
      const big = JSON.stringify({ id: 3, op: "set", ref: "a", value: "x".repeat(80 * 1024) }) + "\n";
      const reply3 = await rawExchange(sock, big);
      expect(reply3.ok).toBe(false);
      expect(reply3.error).toMatch(/frame exceeds/);
    } finally {
      await server.close();
    }
  });

  it("rotate op re-encrypts, changes kid and keeps secrets readable", async () => {
    const { startVaultdServer } = await import("../src/vault/daemon.js");
    const { VaultIpcClient } = await import("../src/vault/client.js");
    const { LocalVaultCore } = await import("../src/vault/core.js");
    const sock = testSocketPath("rotate");
    const server = await startVaultdServer({ socket: sock });
    try {
      const client = await VaultIpcClient.connect(sock, 2_000);
      await client.request("set", { ref: "k", value: "rotated-value" });
      const before = (await client.request("status")) as { kid: string };
      const res = (await client.request("rotate", {}, 30_000)) as {
        oldKid: string;
        newKid: string;
        backupPath: string;
        backend: string;
      };
      expect(res.oldKid).toBe(before.kid);
      expect(res.newKid).not.toBe(res.oldKid);
      expect(fs.existsSync(res.backupPath)).toBe(true);
      expect(await client.request("get", { ref: "k" })).toBe("rotated-value");
      // The on-disk file is readable by a fresh local open too.
      expect(LocalVaultCore.open().get("k")).toBe("rotated-value");
      client.close();
    } finally {
      await server.close();
    }
  });
});

/** Send one raw frame and read one response line from vaultd. */
function rawExchange(
  sock: string,
  frame: string,
): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(sock);
    let buf = "";
    const timer = setTimeout(() => {
      conn.destroy();
      reject(new Error("rawExchange timed out"));
    }, 5_000);
    conn.on("connect", () => conn.write(frame));
    conn.on("data", (d) => {
      buf += d.toString("utf8");
      const idx = buf.indexOf("\n");
      if (idx >= 0) {
        clearTimeout(timer);
        conn.destroy();
        resolve(JSON.parse(buf.slice(0, idx)));
      }
    });
    conn.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// ---------------------------------------------------------------------------
// Vault facade over a vaultd CHILD PROCESS (sync bridge)
// ---------------------------------------------------------------------------

describe("Vault facade over vaultd (child process)", () => {
  it("auto mode without vaultd falls back to the local vault", async () => {
    process.env.SCOPEGATE_VAULT_MODE = "auto";
    process.env.SCOPEGATE_VAULT_SOCKET = testSocketPath("absent");
    const { Vault } = await import("../src/vault/vault.js");
    const v = Vault.open();
    v.set("local_key", "local_value");
    expect(v.get("local_key")).toBe("local_value");
    expect(v.listRefs()).toEqual(["local_key"]);
  });

  it("daemon mode without vaultd fails fast with an actionable error", async () => {
    process.env.SCOPEGATE_VAULT_MODE = "daemon";
    process.env.SCOPEGATE_VAULT_SOCKET = testSocketPath("absent2");
    const { Vault } = await import("../src/vault/vault.js");
    expect(() => Vault.open()).toThrow(/scopegate vaultd/);
  });

  itDist("daemon mode serves the full sync API through vaultd", async () => {
    const sock = testSocketPath("facade");
    await startDaemonChild(sock);
    process.env.SCOPEGATE_VAULT_MODE = "daemon";
    process.env.SCOPEGATE_VAULT_SOCKET = sock;
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_PATH } = await import("../src/config/config.js");

    const v = Vault.open();
    v.set("github_token", "ghp_facade_value");
    v.set("aws_key", "AKIA_facade_value");
    expect(v.get("github_token")).toBe("ghp_facade_value");
    expect(v.has("aws_key")).toBe(true);
    expect(v.listRefs()).toEqual(["aws_key", "github_token"]);
    v.delete("aws_key");
    expect(v.has("aws_key")).toBe(false);
    expect(() => v.get("aws_key")).toThrow(/scopegate secret add aws_key/);

    // A second open shares the same bridge and still works.
    expect(Vault.open().get("github_token")).toBe("ghp_facade_value");

    const raw = fs.readFileSync(VAULT_PATH, "utf8");
    expect(raw).not.toContain("ghp_facade_value");
    expect(JSON.parse(raw).v).toBe(2);
  });

  itDist("auto mode fails over to local when vaultd dies mid-session", async () => {
    const sock = testSocketPath("failover");
    const child = await startDaemonChild(sock);
    process.env.SCOPEGATE_VAULT_MODE = "auto";
    process.env.SCOPEGATE_VAULT_SOCKET = sock;
    const { Vault } = await import("../src/vault/vault.js");

    const v = Vault.open(); // daemon answers the probe → daemon transport
    v.set("k1", "value-one");
    expect(v.get("k1")).toBe("value-one");

    child.kill("SIGKILL");
    await new Promise((r) => child.once("exit", r));
    await sleep(200);

    // Same instance: the next op detects the dead daemon and goes local.
    expect(v.get("k1")).toBe("value-one");
    v.set("k2", "value-two");
    expect(v.listRefs()).toEqual(["k1", "k2"]);
    expect(Vault.open().get("k2")).toBe("value-two");
  });
});
