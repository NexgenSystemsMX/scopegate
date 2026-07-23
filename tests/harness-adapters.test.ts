/**
 * Harness adapter tests (EPIC-06): detection with an isolated HOME fixture,
 * migration of every harness format, idempotency (second run = empty diff),
 * multi-header secret capture, oauth2-pending (never degraded), immutable
 * backup and byte-exact rollback.
 *
 * Isolation: SCOPEGATE_HOME via useTempHome() plus a throwaway user HOME
 * (HOME + USERPROFILE), a throwaway project dir (SCOPEGATE_PROJECT_DIR) and
 * a controlled PATH, so the real machine's configs/CLIs are never seen.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let sgHome: string;
let userHome: string;
let project: string;
let emptyPathDir: string;
let saved: Record<string, string | undefined>;

const ENV_KEYS = [
  "HOME",
  "USERPROFILE",
  "KIMI_CODE_HOME",
  "SCOPEGATE_PROJECT_DIR",
  "PATH",
  "PATHEXT",
  "KIMI_SVC_TOKEN",
];

beforeEach(() => {
  sgHome = useTempHome(); // sets SCOPEGATE_HOME + vi.resetModules()
  userHome = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-userhome-"));
  project = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-project-"));
  emptyPathDir = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-path-"));
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  process.env.HOME = userHome;
  process.env.USERPROFILE = userHome;
  delete process.env.KIMI_CODE_HOME;
  delete process.env.KIMI_SVC_TOKEN;
  process.env.SCOPEGATE_PROJECT_DIR = project;
  process.env.PATH = emptyPathDir; // controlled: no real harness CLIs
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  cleanupTempHome(sgHome);
  fs.rmSync(userHome, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
  fs.rmSync(emptyPathDir, { recursive: true, force: true });
});

// --- helpers ---------------------------------------------------------------

function writeJson(file: string, value: unknown): string {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const raw = JSON.stringify(value, null, 2);
  fs.writeFileSync(file, raw);
  return raw;
}

function read(file: string): string {
  return fs.readFileSync(file, "utf8");
}

/** Run the real init in-process, capturing its log lines. */
async function runInitLogged(opts: { dryRun?: boolean; harness?: string } = {}) {
  const lines: string[] = [];
  const orig = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    const { runInit } = await import("../src/commands/init.js");
    await runInit(opts);
  } finally {
    console.log = orig;
  }
  return lines;
}

async function loadYamlConfig() {
  const { loadConfig } = await import("../src/config/config.js");
  return loadConfig() as Awaited<ReturnType<typeof loadConfig>> & {
    migrations?: Record<string, Record<string, string>>;
  };
}

async function openVault() {
  const { Vault } = await import("../src/vault/vault.js");
  return Vault.open();
}

const CLAUDE_PROJECT = () => path.join(project, ".mcp.json");
const CLAUDE_USER = () => path.join(userHome, ".claude.json");
const KIMI_USER = () => path.join(userHome, ".kimi-code", "mcp.json");
const CURSOR_USER = () => path.join(userHome, ".cursor", "mcp.json");
const OPENCODE_PROJECT = () => path.join(project, "opencode.json");
const OPENCODE_USER = () =>
  path.join(userHome, ".config", "opencode", "opencode.json");

// --- detection -------------------------------------------------------------

describe("detect", () => {
  it("finds existing configs for all four harnesses with the right scope", async () => {
    writeJson(CLAUDE_PROJECT(), { mcpServers: {} });
    writeJson(CLAUDE_USER(), { mcpServers: {} });
    writeJson(KIMI_USER(), { mcpServers: {} });
    writeJson(path.join(project, ".kimi-code", "mcp.json"), { mcpServers: {} });
    writeJson(CURSOR_USER(), { mcpServers: {} });
    writeJson(OPENCODE_PROJECT(), { mcp: {} });
    writeJson(OPENCODE_USER(), { mcp: {} });

    const { getAdapter } = await import("../src/harness/index.js");
    const claude = await getAdapter("claude-code").detect();
    expect(claude.map((i) => [i.scope, i.path])).toEqual([
      ["project", CLAUDE_PROJECT()],
      ["user", CLAUDE_USER()],
    ]);
    const kimi = await getAdapter("kimi-code").detect();
    expect(kimi.map((i) => [i.scope, i.path])).toEqual([
      ["project", path.join(project, ".kimi-code", "mcp.json")],
      ["user", KIMI_USER()],
    ]);
    const cursor = await getAdapter("cursor").detect();
    expect(cursor.map((i) => [i.scope, i.path])).toEqual([["user", CURSOR_USER()]]);
    const opencode = await getAdapter("opencode").detect();
    expect(opencode.map((i) => [i.scope, i.path])).toEqual([
      ["project", OPENCODE_PROJECT()],
      ["user", OPENCODE_USER()],
    ]);
    for (const installs of [claude, kimi, cursor, opencode]) {
      for (const i of installs) expect(i.exists).toBe(true);
    }
  });

  it("honours KIMI_CODE_HOME for the user-level kimi config", async () => {
    const kch = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-kch-"));
    const cfgPath = path.join(kch, "mcp.json");
    writeJson(cfgPath, { mcpServers: {} });
    process.env.KIMI_CODE_HOME = kch;
    const { getAdapter } = await import("../src/harness/index.js");
    const kimi = getAdapter("kimi-code");
    expect(kimi.candidatePaths().map((c) => c.path)).toContain(cfgPath);
    const found = await kimi.detect();
    expect(found.map((i) => i.path)).toEqual([cfgPath]);
    fs.rmSync(kch, { recursive: true, force: true });
  });

  it("falls back to the harness CLI on PATH when no config exists", async () => {
    fs.writeFileSync(path.join(emptyPathDir, "opencode"), "#!/bin/sh\n");
    const { getAdapter } = await import("../src/harness/index.js");
    const found = await getAdapter("opencode").detect();
    expect(found).toEqual([
      {
        adapterId: "opencode",
        scope: "user",
        path: OPENCODE_USER(),
        exists: false,
      },
    ]);
  });

  it("returns empty when neither config nor CLI exists", async () => {
    const { getAdapter } = await import("../src/harness/index.js");
    expect(await getAdapter("cursor").detect()).toEqual([]);
  });
});

// --- migration per harness -------------------------------------------------

describe("migration (runInit)", () => {
  it("migrates Claude Code project + user configs, vaulting env and header secrets", async () => {
    const projectRaw = writeJson(CLAUDE_PROJECT(), {
      mcpServers: {
        svc: {
          command: "node",
          args: ["server.js"],
          env: { SVC_API_KEY: "sk-claude-aaa", PLAIN: "visible" },
        },
      },
    });
    const userRaw = writeJson(CLAUDE_USER(), {
      numStartups: 3,
      mcpServers: {
        remotesvc: {
          type: "http",
          url: "https://api.example.com/mcp",
          headers: { Authorization: "Bearer tok-claude-bbb", "X-Trace": "keep" },
        },
      },
    });

    await runInitLogged();

    // Rewritten: scopegate is the only entry, carrying the config's agentId.
    const cfg = await loadYamlConfig();
    const projectJson = JSON.parse(read(CLAUDE_PROJECT()));
    expect(Object.keys(projectJson.mcpServers)).toEqual(["scopegate"]);
    expect(projectJson.mcpServers.scopegate).toEqual({
      command: "scopegate",
      args: ["start"],
      env: { SCOPEGATE_AGENT_ID: cfg.agentId },
    });
    const userJson = JSON.parse(read(CLAUDE_USER()));
    expect(userJson.numStartups).toBe(3); // untouched top-level keys preserved
    expect(Object.keys(userJson.mcpServers)).toEqual(["scopegate"]);

    // Immutable backups hold the exact pre-migration bytes.
    expect(read(CLAUDE_PROJECT() + ".pre-scopegate.bak")).toBe(projectRaw);
    expect(read(CLAUDE_USER() + ".pre-scopegate.bak")).toBe(userRaw);

    // Upstreams behind the gateway with secretRefs, no plaintext anywhere.
    const svc = cfg.upstreams.find((u) => u.name === "svc");
    expect(svc?.transport).toEqual({
      kind: "stdio",
      command: "node",
      args: ["server.js"],
      env: { PLAIN: "visible" },
    });
    expect(svc?.auth).toEqual({ type: "env", env: { SVC_API_KEY: "svc_svc_api_key" } });
    const remote = cfg.upstreams.find((u) => u.name === "remotesvc");
    expect(remote?.auth).toEqual({
      type: "bearer",
      secretRef: "remotesvc_authorization",
      header: "Authorization",
      scheme: "Bearer",
    });

    const vault = await openVault();
    expect(vault.get("svc_svc_api_key")).toBe("sk-claude-aaa");
    expect(vault.get("remotesvc_authorization")).toBe("tok-claude-bbb");
    for (const file of [CLAUDE_PROJECT(), CLAUDE_USER()]) {
      expect(read(file)).not.toContain("sk-claude-aaa");
      expect(read(file)).not.toContain("tok-claude-bbb");
    }
    expect(read((await import("../src/config/config.js")).CONFIG_PATH)).not.toContain(
      "sk-claude-aaa",
    );
  });

  it("migrates Kimi Code: bearerTokenEnvVar resolved, sse disabled+warned, enabledTools → exposeTools", async () => {
    process.env.KIMI_SVC_TOKEN = "kimi-env-token-123";
    writeJson(KIMI_USER(), {
      mcpServers: {
        kimiremote: { url: "https://kimi.example.com/mcp", bearerTokenEnvVar: "KIMI_SVC_TOKEN" },
        kimisse: { url: "https://kimi.example.com/sse", transport: "sse" },
        kimitools: {
          command: "node",
          args: ["t.js"],
          enabledTools: ["read", "grep"],
        },
      },
    });

    const lines = await runInitLogged();

    const cfg = await loadYamlConfig();
    const remote = cfg.upstreams.find((u) => u.name === "kimiremote");
    expect(remote?.auth).toEqual({
      type: "bearer",
      secretRef: "kimiremote_bearer_token",
      header: "Authorization",
      scheme: "Bearer",
    });
    const vault = await openVault();
    expect(vault.get("kimiremote_bearer_token")).toBe("kimi-env-token-123");

    const sse = cfg.upstreams.find((u) => u.name === "kimisse");
    expect(sse?.enabled).toBe(false);
    expect(lines.join("\n")).toMatch(/kimisse.*SSE transport is not proxied/);

    const tools = cfg.upstreams.find((u) => u.name === "kimitools");
    expect(tools?.exposeTools).toEqual(["grep", "read"]);

    const rewritten = JSON.parse(read(KIMI_USER()));
    expect(Object.keys(rewritten.mcpServers)).toEqual(["scopegate"]);
  });

  it("migrates Cursor configs (shared mcpServers format)", async () => {
    writeJson(CURSOR_USER(), {
      mcpServers: {
        cursordb: {
          command: "uvx",
          args: ["db-mcp"],
          env: { CURSOR_DB_PASSWORD: "cursor-pw-789" },
        },
      },
    });
    await runInitLogged();
    const cfg = await loadYamlConfig();
    const up = cfg.upstreams.find((u) => u.name === "cursordb");
    expect(up?.auth).toEqual({
      type: "env",
      env: { CURSOR_DB_PASSWORD: "cursordb_cursor_db_password" },
    });
    const rewritten = JSON.parse(read(CURSOR_USER()));
    expect(Object.keys(rewritten.mcpServers)).toEqual(["scopegate"]);
  });

  it("migrates OpenCode: type local → stdio, type remote → http, gateway entry in opencode format", async () => {
    const raw = writeJson(OPENCODE_PROJECT(), {
      $schema: "https://opencode.ai/config.json",
      mcp: {
        oclocal: {
          type: "local",
          command: ["bun", "x", "oc-mcp", "--fast"],
          environment: { OC_TOKEN: "oc-secret-local" },
          enabled: true,
        },
        ocremote: {
          type: "remote",
          url: "https://oc.example.com/mcp",
          headers: { Authorization: "Bearer oc-secret-remote" },
        },
      },
    });

    await runInitLogged();

    const cfg = await loadYamlConfig();
    const local = cfg.upstreams.find((u) => u.name === "oclocal");
    expect(local?.transport).toEqual({
      kind: "stdio",
      command: "bun",
      args: ["x", "oc-mcp", "--fast"],
      env: {},
    });
    expect(local?.auth).toEqual({ type: "env", env: { OC_TOKEN: "oclocal_oc_token" } });
    const remote = cfg.upstreams.find((u) => u.name === "ocremote");
    expect(remote?.transport).toEqual({ kind: "http", url: "https://oc.example.com/mcp" });
    expect(remote?.auth.type).toBe("bearer");

    const rewritten = JSON.parse(read(OPENCODE_PROJECT()));
    expect(rewritten.$schema).toBe("https://opencode.ai/config.json");
    expect(rewritten.mcp).toEqual({
      scopegate: {
        type: "local",
        command: ["scopegate", "start"],
        environment: { SCOPEGATE_AGENT_ID: cfg.agentId },
        enabled: true,
      },
    });
    expect(read(OPENCODE_PROJECT() + ".pre-scopegate.bak")).toBe(raw);
  });
});

// --- multi-header capture ---------------------------------------------------

describe("multi-header secret capture", () => {
  it("vaults EVERY credential header, wires Authorization, warns about the rest", async () => {
    writeJson(CLAUDE_USER(), {
      mcpServers: {
        multi: {
          url: "https://multi.example.com/mcp",
          headers: {
            "X-Api-Key": "multi-key-111",
            Authorization: "Bearer multi-tok-222",
            "X-Trace-Id": "not-a-secret",
          },
        },
      },
    });

    const lines = await runInitLogged();

    const cfg = await loadYamlConfig();
    const up = cfg.upstreams.find((u) => u.name === "multi");
    expect(up?.auth).toEqual({
      type: "bearer",
      secretRef: "multi_authorization",
      header: "Authorization",
      scheme: "Bearer",
    });
    const vault = await openVault();
    expect(vault.get("multi_authorization")).toBe("multi-tok-222");
    expect(vault.get("multi_x_api_key")).toBe("multi-key-111"); // old bug: only the first header was captured
    expect(lines.join("\n")).toMatch(/multi.*extra secret header.*multi_x_api_key/s);
    const rewritten = read(CLAUDE_USER());
    expect(rewritten).not.toContain("multi-key-111");
    expect(rewritten).not.toContain("multi-tok-222");
    // The whole server entry is replaced by the gateway entry — no header
    // value, secret or not, survives in the rewritten config.
    expect(rewritten).not.toContain("X-Trace-Id");
  });
});

// --- oauth never degraded ---------------------------------------------------

describe("oauth2-pending (never degraded to auth none)", () => {
  it("bearerTokenEnvVar unset → oauth2 pending, explicit WARN, ref absent from vault", async () => {
    writeJson(KIMI_USER(), {
      mcpServers: {
        pendingkim: { url: "https://k.example.com/mcp", bearerTokenEnvVar: "KIMI_SVC_TOKEN" },
      },
    });

    const lines = await runInitLogged();

    const cfg = await loadYamlConfig();
    const up = cfg.upstreams.find((u) => u.name === "pendingkim");
    expect(up?.auth.type).toBe("oauth2");
    expect(up?.auth.type).not.toBe("none");
    expect((up?.auth as { secretRef: string }).secretRef).toBe("pendingkim_bearer_token");
    const vault = await openVault();
    expect(vault.has("pendingkim_bearer_token")).toBe(false);
    const out = lines.join("\n");
    expect(out).toMatch(/pendingkim.*PENDING auth \(oauth2\)/);
    expect(out).toContain("scopegate secret add pendingkim_bearer_token");
  });

  it("opencode remote with oauth flow → oauth2 pending, not auth none", async () => {
    writeJson(OPENCODE_PROJECT(), {
      mcp: {
        ocauth: { type: "remote", url: "https://oc.example.com/x", oauth: { scopes: [] } },
      },
    });
    const lines = await runInitLogged();
    const cfg = await loadYamlConfig();
    const up = cfg.upstreams.find((u) => u.name === "ocauth");
    expect(up?.auth.type).toBe("oauth2");
    expect(lines.join("\n")).toMatch(/ocauth.*PENDING auth \(oauth2\)/);
  });
});

// --- idempotency ------------------------------------------------------------

describe("idempotency", () => {
  it("second init run is a verifiable no-op (byte-identical state, original backup kept)", async () => {
    writeJson(CLAUDE_PROJECT(), {
      mcpServers: { svc: { command: "node", env: { SVC_KEY: "idem-secret" } } },
    });
    writeJson(OPENCODE_PROJECT(), {
      mcp: { oc: { type: "local", command: ["node", "x.js"] } },
    });

    await runInitLogged();
    const { CONFIG_PATH } = await import("../src/config/config.js");
    const files = [
      CLAUDE_PROJECT(),
      CLAUDE_PROJECT() + ".pre-scopegate.bak",
      OPENCODE_PROJECT(),
      OPENCODE_PROJECT() + ".pre-scopegate.bak",
      CONFIG_PATH,
    ];
    const before = files.map(read);

    const lines = await runInitLogged();
    const after = files.map(read);

    expect(after).toEqual(before); // empty diff on every file, backup included
    expect(lines.join("\n")).toMatch(/already up to date — no changes/);
    expect(lines.join("\n")).not.toMatch(/migrated MCP/);
  });

  it("re-migrates when a server spec changes (fingerprint mismatch)", async () => {
    writeJson(CLAUDE_PROJECT(), {
      mcpServers: { svc: { command: "node", env: { SVC_KEY: "v1-secret" } } },
    });
    await runInitLogged();

    // Human re-adds the server to the live config with a rotated secret.
    const live = JSON.parse(read(CLAUDE_PROJECT()));
    live.mcpServers.svc = { command: "node", env: { SVC_KEY: "v2-secret" } };
    fs.writeFileSync(CLAUDE_PROJECT(), JSON.stringify(live, null, 2));

    await runInitLogged();
    const vault = await openVault();
    expect(vault.get("svc_svc_key")).toBe("v2-secret");
    const cfg = await loadYamlConfig();
    expect(cfg.upstreams.filter((u) => u.name === "svc")).toHaveLength(1);
  });
});

// --- rollback ---------------------------------------------------------------

describe("rollback (restoreFromBackup)", () => {
  it("restores byte-identical originals, keeps the immutable backup, leaves scopegate.yaml intact", async () => {
    const claudeRaw = writeJson(CLAUDE_PROJECT(), {
      mcpServers: { svc: { command: "node", env: { SVC_KEY: "rb-secret" } } },
    });
    const opencodeRaw = writeJson(OPENCODE_PROJECT(), {
      mcp: { oc: { type: "remote", url: "https://oc.example.com/mcp" } },
    });
    writeJson(CURSOR_USER(), { mcpServers: {} }); // no servers: still rewritten, but rollback must restore

    await runInitLogged();
    expect(read(CLAUDE_PROJECT())).not.toBe(claudeRaw);

    const { restoreFromBackup } = await import("../src/harness/migrate.js");
    const { ALL_ADAPTERS } = await import("../src/harness/index.js");
    const logs: string[] = [];
    const results = restoreFromBackup(ALL_ADAPTERS, (m) => logs.push(m));

    expect(read(CLAUDE_PROJECT())).toBe(claudeRaw);
    expect(read(OPENCODE_PROJECT())).toBe(opencodeRaw);
    // Backups are immutable: still present after the restore.
    expect(fs.existsSync(CLAUDE_PROJECT() + ".pre-scopegate.bak")).toBe(true);
    expect(fs.existsSync(OPENCODE_PROJECT() + ".pre-scopegate.bak")).toBe(true);
    const restored = results.filter((r) => r.restored).map((r) => r.path);
    expect(restored).toContain(CLAUDE_PROJECT());
    expect(restored).toContain(OPENCODE_PROJECT());
    // Conservative: upstreams and vault secrets are NOT removed.
    const cfg = await loadYamlConfig();
    expect(cfg.upstreams.map((u) => u.name)).toContain("svc");
    expect(logs.join("\n")).toMatch(/left untouched/);
  });
});

// --- conflicts, dry-run, --harness ------------------------------------------

describe("conflicts, dry-run and --harness", () => {
  it("rejects a foreign 'scopegate' entry with an actionable error", async () => {
    writeJson(CLAUDE_PROJECT(), {
      mcpServers: { scopegate: { command: "not-scopegate" } },
    });
    const { runInit } = await import("../src/commands/init.js");
    await expect(runInit({})).rejects.toThrow(/Rename or remove it/);
  });

  it("skips unrecognized entries with a warning instead of failing", async () => {
    writeJson(CLAUDE_PROJECT(), { mcpServers: { broken: { nonsense: true } } });
    const lines = await runInitLogged();
    expect(lines.join("\n")).toMatch(/broken.*unrecognized MCP entry/);
    const cfg = await loadYamlConfig();
    expect(cfg.upstreams).toHaveLength(0);
    expect(JSON.parse(read(CLAUDE_PROJECT())).mcpServers.scopegate).toBeDefined();
  });

  it("--dry-run creates nothing and writes nothing", async () => {
    const raw = writeJson(CLAUDE_PROJECT(), {
      mcpServers: { svc: { command: "node", env: { SVC_KEY: "dry-secret" } } },
    });
    const lines = await runInitLogged({ dryRun: true });
    expect(lines.join("\n")).toMatch(/would migrate MCP 'svc'/);
    expect(read(CLAUDE_PROJECT())).toBe(raw);
    expect(fs.existsSync(CLAUDE_PROJECT() + ".pre-scopegate.bak")).toBe(false);
    // Pure inspection: no scopegate state files at all (sgHome itself is the
    // mkdtemp dir, which always exists).
    for (const f of ["scopegate.yaml", "master.key", "vault.enc", "identity.json", "policies.yaml"]) {
      expect(fs.existsSync(path.join(sgHome, f)), f).toBe(false);
    }
  });

  it("--harness restricts migration to one adapter and rejects unknown ids", async () => {
    const claudeRaw = writeJson(CLAUDE_PROJECT(), {
      mcpServers: { svc: { command: "node" } },
    });
    writeJson(CURSOR_USER(), { mcpServers: { cur: { command: "node" } } });

    await runInitLogged({ harness: "cursor" });

    expect(read(CLAUDE_PROJECT())).toBe(claudeRaw); // untouched
    const cfg = await loadYamlConfig();
    expect(cfg.upstreams.map((u) => u.name)).toEqual(["cur"]);

    const { runInit } = await import("../src/commands/init.js");
    await expect(runInit({ harness: "emacs" })).rejects.toThrow(/Unknown harness 'emacs'/);
  });
});
