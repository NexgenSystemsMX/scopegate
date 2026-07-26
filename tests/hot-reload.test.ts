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
      //
      // Both writes land within the same millisecond, so on a filesystem with
      // coarse timestamps they share an mtime. Detection therefore cannot rest
      // on mtime alone: it reads the file's content (the ISO stamp `secret add`
      // writes). A rotation the gateway cannot see means it keeps serving the
      // OLD credential — the exact failure hot-reload exists to prevent.
      fs.writeFileSync(VAULT_VERSION_PATH, new Date(Date.now() + 5000).toISOString() + "\n", { mode: 0o600 });
      (proxy as unknown as { refreshVaultVersion(): void }).refreshVaultVersion();
      expect(connectionsOf()).toBe(0);
    } finally {
      await proxy.closeAll();
    }
  }, 30_000);

  it("detecta dos rotaciones seguidas aunque compartan mtime", async () => {
    // Aísla la invariante del test de arriba: mismo mtime forzado a mano, y
    // el cambio se tiene que ver igual.
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const { VAULT_VERSION_PATH } = await import("../src/config/config.js");
    const proxy = new UpstreamProxy([], Vault.open(), { agentId: "test-agent" });
    const refresh = (): void =>
      (proxy as unknown as { refreshVaultVersion(): void }).refreshVaultVersion();
    const stampOf = (): unknown =>
      (proxy as unknown as { lastVaultVersionCheck: { stamp: string | null } })
        .lastVaultVersionCheck.stamp;

    fs.writeFileSync(VAULT_VERSION_PATH, "2026-01-01T00:00:00.000Z\n", { mode: 0o600 });
    const fixed = new Date(1_700_000_000_000);
    fs.utimesSync(VAULT_VERSION_PATH, fixed, fixed);
    refresh();
    const first = stampOf();

    fs.writeFileSync(VAULT_VERSION_PATH, "2026-01-01T00:00:01.000Z\n", { mode: 0o600 });
    fs.utimesSync(VAULT_VERSION_PATH, fixed, fixed); // MISMO mtime a propósito
    refresh();
    expect(stampOf()).not.toBe(first);
  });
});
