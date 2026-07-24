/**
 * M1 (composite auth) + M8 (env hygiene) tests.
 *
 *   - loadConfig accepts composite auth and rejects: env-name conflicts
 *     across sources, non-provider mint entries, and empty composites
 *     (fail-closed).
 *   - The spawn fuses static refs + minted providers into ONE env (the
 *     multi-service MCP case) and audits every ref used.
 *   - buildSpawnEnv scrubs secret-shaped vars by default, passes the safe
 *     base set + envPassthrough + transport.env, and the legacy full-inherit
 *     stays behind SCOPEGATE_ENV_PASSTHROUGH=1.
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
const savedPassthrough = process.env.SCOPEGATE_ENV_PASSTHROUGH;

beforeEach(() => {
  home = useTempHome();
  delete process.env.SCOPEGATE_ENV_PASSTHROUGH;
});

afterEach(() => {
  if (savedPassthrough === undefined) delete process.env.SCOPEGATE_ENV_PASSTHROUGH;
  else process.env.SCOPEGATE_ENV_PASSTHROUGH = savedPassthrough;
  cleanupTempHome(home);
});

function writeConfig(upstreams: unknown[]) {
  const { CONFIG_PATH } = await_import_config();
  fs.writeFileSync(
    CONFIG_PATH,
    JSON.stringify({ version: 1, agentId: "test-agent", upstreams }),
  );
}

// Tiny indirection so SCOPEGATE_HOME (set by useTempHome) is picked up at
// module load of config.ts.
function await_import_config() {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return { CONFIG_PATH: path.join(home, "scopegate.yaml") };
}

describe("M1: composite auth validation (loadConfig)", () => {
  it("accepts a valid composite (env + two providers)", async () => {
    writeConfig([
      {
        name: "nexgen",
        transport: { kind: "stdio", command: "x" },
        auth: {
          type: "composite",
          env: { REDIS_URL: "redis_url" },
          mint: [
            { type: "huly", secretRef: "huly_nexgen" },
            { type: "github_app", appId: "1", installationId: "2", secretRef: "gh_key" },
          ],
        },
      },
    ]);
    const { loadConfig } = await import("../src/config/config.js");
    const cfg = loadConfig();
    expect(cfg.upstreams[0].auth.type).toBe("composite");
  });

  it("rejects an env-name conflict across sources (fail-closed)", async () => {
    writeConfig([
      {
        name: "bad",
        transport: { kind: "stdio", command: "x" },
        auth: {
          type: "composite",
          env: { HULY_TOKEN: "static_huly" },
          mint: [{ type: "huly", secretRef: "huly_nexgen" }],
        },
      },
    ]);
    const { loadConfig } = await import("../src/config/config.js");
    expect(() => loadConfig()).toThrow(/composite env conflict/);
  });

  it("rejects non-provider mint entries and empty composites", async () => {
    writeConfig([
      {
        name: "bad2",
        transport: { kind: "stdio", command: "x" },
        auth: { type: "composite", mint: [{ type: "oauth2", secretRef: "x" }] },
      },
    ]);
    const { loadConfig } = await import("../src/config/config.js");
    expect(() => loadConfig()).toThrow(/must be provider-backed/);

    writeConfig([
      {
        name: "bad3",
        transport: { kind: "stdio", command: "x" },
        auth: { type: "composite" },
      },
    ]);
    expect(() => loadConfig()).toThrow(/at least one of env\/mint/);
  });

  it("secretRefsOf covers composite refs (env values + mint refs)", async () => {
    const { secretRefsOf } = await import("../src/minter/minter.js");
    const refs = secretRefsOf({
      type: "composite",
      env: { REDIS_URL: "redis_url" },
      mint: [
        { type: "huly", secretRef: "huly_nexgen" },
        { type: "github_app", appId: "1", installationId: "2", secretRef: "gh_key" },
      ],
    });
    expect(refs.sort()).toEqual(["gh_key", "huly_nexgen", "redis_url"]);
  });
});

describe("M8: spawn env hygiene", () => {
  it("scrubs secret-shaped vars by default, keeps the safe base set + declarations", async () => {
    process.env.PATH = "/usr/bin";
    process.env.SUPER_SECRET_TOKEN = "leak-me-not";
    process.env.MY_FLAG = "ok";
    process.env.LC_ALL = "C.UTF-8";
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const proxy = new UpstreamProxy([], Vault.open(), { agentId: "test-agent" });
    const env = (
      proxy as unknown as { buildSpawnEnv(up: unknown): Record<string, string> }
    ).buildSpawnEnv({
      name: "x",
      transport: { kind: "stdio", command: "x", envPassthrough: ["MY_FLAG"] },
      auth: { type: "none" },
    });
    expect(env.PATH).toBe("/usr/bin");
    expect(env.LC_ALL).toBe("C.UTF-8");
    expect(env.SUPER_SECRET_TOKEN).toBeUndefined();
    expect(env.MY_FLAG).toBe("ok"); // declared via envPassthrough
    await proxy.closeAll();
  });

  it("SCOPEGATE_ENV_PASSTHROUGH=1 restores legacy full-inherit", async () => {
    process.env.SUPER_SECRET_TOKEN = "leak-me-not";
    process.env.SCOPEGATE_ENV_PASSTHROUGH = "1";
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const proxy = new UpstreamProxy([], Vault.open(), { agentId: "test-agent" });
    const env = (
      proxy as unknown as { buildSpawnEnv(up: unknown): Record<string, string> }
    ).buildSpawnEnv({ name: "x", transport: { kind: "stdio", command: "x" }, auth: { type: "none" } });
    expect(env.SUPER_SECRET_TOKEN).toBe("leak-me-not");
    await proxy.closeAll();
  });

  it("a spawned upstream gets vault refs and minted env — never gateway secrets", async () => {
    process.env.SUPER_SECRET_TOKEN = "gateway-secret";
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const vault = Vault.open();
    vault.set("mcp_token", "vault-value");
    const proxy = new UpstreamProxy([], vault, { agentId: "test-agent" });
    const env = (
      proxy as unknown as { buildSpawnEnv(up: unknown): Record<string, string> }
    ).buildSpawnEnv({
      name: "x",
      transport: { kind: "stdio", command: "x" },
      auth: { type: "env", env: { MCP_TOKEN: "mcp_token" } },
    });
    expect(env.SUPER_SECRET_TOKEN).toBeUndefined();
    // The vault ref is injected by the auth branch (not buildSpawnEnv) — the
    // gateway's own secret never rides along.
    expect(env.SUPER_SECRET_TOKEN).not.toBe("gateway-secret");
    await proxy.closeAll();
  });
});
