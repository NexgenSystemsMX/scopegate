import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

const SAMPLE = {
  version: 1 as const,
  agentId: "test-agent",
  upstreams: [
    {
      name: "fakegit",
      transport: { kind: "stdio" as const, command: "node", args: ["u.mjs"] },
      auth: { type: "env" as const, env: { FAKE_TOKEN: "fake_token" } },
    },
  ],
};

describe("config paths", () => {
  it("honours the SCOPEGATE_HOME override", async () => {
    const cfg = await import("../src/config/config.js");
    expect(cfg.SCOPEGATE_DIR).toBe(home);
    expect(cfg.CONFIG_PATH.startsWith(home)).toBe(true);
    expect(cfg.POLICIES_PATH.startsWith(home)).toBe(true);
    expect(cfg.VAULT_PATH.startsWith(home)).toBe(true);
    expect(cfg.MASTER_KEY_PATH.startsWith(home)).toBe(true);
    expect(cfg.AUDIT_LOG_PATH.startsWith(home)).toBe(true);
    expect(cfg.PENDING_POLICIES_PATH.startsWith(home)).toBe(true);
  });
});

describe("loadConfig / saveConfig", () => {
  it("roundtrips a config", async () => {
    const { loadConfig, saveConfig, configExists } = await import(
      "../src/config/config.js"
    );
    expect(configExists()).toBe(false);
    saveConfig(SAMPLE);
    expect(configExists()).toBe(true);
    expect(loadConfig()).toEqual(SAMPLE);
  });

  it("loadConfig throws an actionable error when no config exists", async () => {
    const { loadConfig } = await import("../src/config/config.js");
    expect(() => loadConfig()).toThrow(/scopegate init/);
  });

  it("loadConfig rejects an unsupported version", async () => {
    const { loadConfig, CONFIG_PATH, ensureDir } = await import(
      "../src/config/config.js"
    );
    ensureDir();
    fs.writeFileSync(CONFIG_PATH, "version: 2\nagentId: x\n");
    expect(() => loadConfig()).toThrow(/Unsupported or corrupt config/);
  });

  it("loadConfig rejects broken YAML", async () => {
    const { loadConfig, CONFIG_PATH, ensureDir } = await import(
      "../src/config/config.js"
    );
    ensureDir();
    fs.writeFileSync(CONFIG_PATH, "version: [1,\n");
    expect(() => loadConfig()).toThrow();
  });

  it("loadConfig defaults upstreams to [] when omitted", async () => {
    const { loadConfig, CONFIG_PATH, ensureDir } = await import(
      "../src/config/config.js"
    );
    ensureDir();
    fs.writeFileSync(CONFIG_PATH, "version: 1\nagentId: solo\n");
    const cfg = loadConfig();
    expect(cfg.agentId).toBe("solo");
    expect(cfg.upstreams).toEqual([]);
  });
});

describe("upsertUpstream", () => {
  it("inserts when the name is new", async () => {
    const { upsertUpstream } = await import("../src/config/config.js");
    const cfg = { version: 1 as const, agentId: "a", upstreams: [] };
    upsertUpstream(cfg, {
      name: "one",
      transport: { kind: "http", url: "http://localhost:1/mcp" },
      auth: { type: "none" },
    });
    expect(cfg.upstreams).toHaveLength(1);
    expect(cfg.upstreams[0].name).toBe("one");
  });

  it("replaces in place when the name exists (idempotent by name)", async () => {
    const { upsertUpstream, loadConfig, saveConfig } = await import(
      "../src/config/config.js"
    );
    saveConfig(SAMPLE);
    const cfg = loadConfig();
    upsertUpstream(cfg, {
      name: "fakegit",
      transport: { kind: "http", url: "http://localhost:9/mcp" },
      auth: { type: "none" },
    });
    upsertUpstream(cfg, {
      name: "fakegit",
      transport: { kind: "http", url: "http://localhost:10/mcp" },
      auth: { type: "none" },
    });
    expect(cfg.upstreams).toHaveLength(1);
    expect(cfg.upstreams[0].transport).toEqual({
      kind: "http",
      url: "http://localhost:10/mcp",
    });
    // Roundtrip the mutation to disk as well.
    saveConfig(cfg);
    expect(loadConfig().upstreams).toHaveLength(1);
  });
});
