/**
 * Hot-reload tests (quick win): a vault mutation drops stale connections —
 * fresh credentials take effect without an agent-session restart.
 */
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

describe("vault hot-reload", () => {
  it("a vault.version bump drops connections on the next call", async () => {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_VERSION_PATH } = await import("../src/config/config.js");
    const path = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const FAKE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "fake-upstream.mjs");
    const vault = Vault.open();
    const upstream = {
      name: "fakegit",
      transport: { kind: "stdio" as const, command: process.execPath, args: [FAKE] },
      auth: { type: "none" as const },
    };
    const proxy = new UpstreamProxy([upstream], vault, { agentId: "test-agent" });
    try {
      await proxy.connectAll();
      const connectionsOf = () =>
        (proxy as unknown as { connections: Map<string, unknown> }).connections.size;
      expect(connectionsOf()).toBeGreaterThan(0);

      // Simulate `scopegate secret add`: bump vault.version → establishes the
      // baseline (first sight records, no drop — initial deposits have no
      // stale connections to purge yet).
      fs.writeFileSync(VAULT_VERSION_PATH, new Date().toISOString() + "\n", { mode: 0o600 });
      (proxy as unknown as { refreshVaultVersion(): void }).refreshVaultVersion();
      expect(connectionsOf()).toBeGreaterThan(0);

      // A second mutation (rotation) IS a change → stale connections drop.
      fs.writeFileSync(VAULT_VERSION_PATH, new Date(Date.now() + 5000).toISOString() + "\n", { mode: 0o600 });
      (proxy as unknown as { refreshVaultVersion(): void }).refreshVaultVersion();
      expect(connectionsOf()).toBe(0);
    } finally {
      await proxy.closeAll();
    }
  }, 30_000);
});
