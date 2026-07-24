/**
 * M2 tests: proactive mint refresh for stdio + isError self-heal + minter
 * invalidation.
 *
 *   - scheduleMintRefresh respawns the connection at ~80% of the credential
 *     TTL (fresh connection first, old closed after grace).
 *   - minter.invalidate drops cached credentials per upstream (revoked tokens
 *     are never retried as-is).
 *   - an in-band isError auth failure invalidates the mint cache and heals
 *     with a fresh credential on the next attempt.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

describe("M2.3: minter.invalidate", () => {
  it("drops cached credentials of one upstream only", async () => {
    const { Minter } = await import("../src/minter/minter.js");
    const { Vault } = await import("../src/vault/vault.js");
    const minter = new Minter(Vault.open());
    const cache = (minter as unknown as { cache: Map<string, unknown> }).cache;
    cache.set("github refs ", { cred: {}, mintedAt: 0, expiresAt: 1 });
    cache.set("github other", { cred: {}, mintedAt: 0, expiresAt: 1 });
    cache.set("huly refs", { cred: {}, mintedAt: 0, expiresAt: 1 });
    expect(minter.invalidate("github")).toBe(2);
    expect(cache.size).toBe(1);
    expect(minter.invalidate("github")).toBe(0);
  });
});

describe("M2.1: proactive respawn scheduler", () => {
  it("respawns the connection at ~80% of the credential TTL", async () => {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const path = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const FAKE = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "fake-upstream.mjs");
    const proxy = new UpstreamProxy(
      [
        {
          name: "fakegit",
          transport: { kind: "stdio", command: process.execPath, args: [FAKE] },
          auth: { type: "none" },
        },
      ],
      Vault.open(),
      { agentId: "test-agent" },
    );
    try {
      await proxy.connectAll();
      const conns = (proxy as unknown as { connections: Map<string, unknown> }).connections;
      const before = conns.get("fakegit");
      (
        proxy as unknown as { scheduleMintRefresh(name: string, expiresAt: number): void }
      ).scheduleMintRefresh("fakegit", Date.now() + 900); // fires at ~720ms
      await new Promise((r) => setTimeout(r, 1500));
      const after = conns.get("fakegit");
      expect(after).toBeDefined();
      expect(after).not.toBe(before); // swapped with a fresh connection
    } finally {
      await proxy.closeAll();
    }
  }, 30_000);
});

describe("M2.2: isError auth self-heal", () => {
  it("detects in-band auth failures on minted upstreams and ignores clean errors", async () => {
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const proxy = new UpstreamProxy([], Vault.open(), { agentId: "test-agent" });
    const isAuth = (
      proxy as unknown as {
        isAuthErrorResult(r: unknown, up: unknown): boolean;
      }
    ).isAuthErrorResult.bind(proxy);

    const jwtUp = {
      name: "x",
      transport: { kind: "http", url: "http://x" },
      auth: { type: "jwt", secretRef: "k" },
    };
    expect(isAuth({ isError: true, content: [{ text: "401 unauthorized" }] }, jwtUp)).toBe(true);
    expect(isAuth({ isError: true, content: [{ text: "expired token" }] }, jwtUp)).toBe(true);
    expect(isAuth({ isError: true, content: [{ text: "issue not found" }] }, jwtUp)).toBe(false);
    expect(isAuth({ isError: false, content: [] }, jwtUp)).toBe(false);
    expect(isAuth("not-a-result", jwtUp)).toBe(false);
    // Static bearer upstreams are NOT self-healed (no mint to refresh).
    const bearerUp = {
      name: "y",
      transport: { kind: "http", url: "http://y" },
      auth: { type: "bearer", secretRef: "k" },
    };
    expect(isAuth({ isError: true, content: [{ text: "401" }] }, bearerUp)).toBe(false);
    await proxy.closeAll();
  });
});
