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
      // Poll instead of a fixed sleep: under parallel-suite CPU load the
      // respawn (child spawn + MCP handshake) can outlast a hardcoded wait.
      // The entry can also be briefly absent between close and reconnect.
      let after = conns.get("fakegit");
      const deadline = Date.now() + 15_000;
      while ((after === before || after === undefined) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 100));
        after = conns.get("fakegit");
      }
      expect(after).toBeDefined();
      expect(after).not.toBe(before); // swapped with a fresh connection
    } finally {
      await proxy.closeAll();
    }
  }, 30_000);
});

describe("respawn forzado: la credencial minteada cambia de verdad", () => {
  /** Spawn fake-upstream --http and resolve once it reports its port. */
  function startHttpUpstream(): Promise<{
    child: import("node:child_process").ChildProcess;
    port: number;
  }> {
    return new Promise(async (resolve, reject) => {
      const { spawn } = await import("node:child_process");
      const path = await import("node:path");
      const { fileURLToPath } = await import("node:url");
      const FAKE = path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        "..",
        "fake-upstream.mjs",
      );
      const child = spawn(process.execPath, [FAKE, "--http"], {
        stdio: ["ignore", "pipe", "inherit"],
        env: { ...process.env, SCOPEGATE_HOME: home },
      });
      let buf = "";
      child.stdout?.on("data", (d) => {
        buf += d.toString();
        const m = /FAKE_UPSTREAM_PORT=(\d+)/.exec(buf);
        if (m) resolve({ child, port: Number(m[1]) });
      });
      child.on("error", reject);
      child.on("exit", (code) =>
        reject(new Error(`http fake upstream exited early (${code})`)),
      );
      setTimeout(() => reject(new Error("no port reported")), 10_000);
    });
  }

  it("`respawnUpstreams` invalida la caché del minter: el token NO se repite", async () => {
    // El respawn sólo reconectaba los hijos. Para auth minteada eso sirve el
    // TOKEN CACHEADO — el mismo que el hijo ya tenía — porque `Minter.resolve`
    // devuelve el cache hit mientras le quede vida. Es decir: la rotación se
    // verificaba por fingerprint y el upstream seguía autenticando con el token
    // viejo hasta el refresh natural (~1h GitHub / ~12h Huly). El caso `env` no
    // lo delataba (ese hijo relee el vault al arrancar), y por eso `redis_url`
    // parecía demostrar que estaba cerrado.
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");

    let mints = 0;
    // Provider falso: cada mint emite un valor distinto, así que "mismo token"
    // sólo puede significar "cache hit".
    const provider = {
      type: "jwt",
      supports: (a: { type: string }) => a.type === "jwt",
      maxTtlMs: () => 3_600_000,
      mint: async () => {
        mints++;
        const value = `tok-${mints}`;
        return {
          value,
          headers: { Authorization: `Bearer ${value}` },
          expiresAt: Date.now() + 3_600_000,
        };
      },
    };

    const { child, port } = await startHttpUpstream();
    const vault = Vault.open();
    const proxy = new UpstreamProxy(
      [
        {
          name: "fakehttp",
          transport: { kind: "http", url: `http://127.0.0.1:${port}` },
          auth: { type: "jwt", secretRef: "fake_key" },
        },
      ],
      vault,
      {
        agentId: "test-agent",
        minter: new Minter(vault, [provider as never]),
        // Sin attestation: no es lo que se mide aquí y sólo añade firma por hop.
        attestationDefault: false,
      },
    );
    const authOf = async (): Promise<string> => {
      const res = (await proxy.call("fakehttp__echo_auth", {})) as {
        content: { text: string }[];
      };
      return res.content[0].text;
    };
    try {
      await proxy.connectAll();
      const before = await authOf();
      expect(before).toContain("Bearer tok-");

      const respawned = await proxy.respawnUpstreams(["fakehttp"]);
      expect(respawned).toEqual(["fakehttp"]);

      const after = await authOf();
      expect(after).not.toBe(before);
      expect(after).toContain("Bearer tok-");
    } finally {
      await proxy.closeAll();
      child.kill();
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

  it("heals composite upstreams too — the shape production actually runs", async () => {
    // Regression: `providerFor({type:"composite"})` is undefined, because the
    // proxy expands composite into its `mint:` entries instead of asking a
    // provider. The old gate therefore classified the most-minted shape as
    // "not minted", and an in-band 401 from `nexgen` (env REDIS_URL + mint
    // huly + github_app) reached the agent as a bare isError with no retry.
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const proxy = new UpstreamProxy([], Vault.open(), { agentId: "test-agent" });
    const isAuth = (
      proxy as unknown as { isAuthErrorResult(r: unknown, up: unknown): boolean }
    ).isAuthErrorResult.bind(proxy);

    const nexgenUp = {
      name: "nexgen",
      transport: { kind: "stdio", command: "node", args: ["server.js"] },
      auth: {
        type: "composite",
        env: { REDIS_URL: "redis_url" },
        mint: [
          { type: "huly", secretRef: "huly_nexgen" },
          { type: "github_app", appId: "1", installationId: "2", secretRef: "gh_app_key" },
        ],
      },
    };
    expect(isAuth({ isError: true, content: [{ text: "401 unauthorized" }] }, nexgenUp)).toBe(true);
    // Still discriminating: a domain error on the same upstream is not auth.
    expect(isAuth({ isError: true, content: [{ text: "issue not found" }] }, nexgenUp)).toBe(false);

    // A composite whose mint half has no provider is NOT refreshable: there is
    // nothing to re-mint, so retrying would just replay the same static creds.
    const staticOnly = {
      name: "z",
      transport: { kind: "stdio", command: "node", args: [] },
      auth: { type: "composite", env: { API_KEY: "k" }, mint: [] },
    };
    expect(isAuth({ isError: true, content: [{ text: "401" }] }, staticOnly)).toBe(false);
    await proxy.closeAll();
  });
});
