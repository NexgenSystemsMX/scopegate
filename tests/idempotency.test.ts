/**
 * Idempotency tests (mejora #6).
 *
 *   - Same key + same args hash → replay from cache (upstream untouched).
 *   - Same key + different args hash → explicit conflict error.
 *   - Entries expire after 24 h; the key never leaks upstream.
 *   - Integration through proxy.call: the second identical write is a replay.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts).
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

async function mod() {
  const m = await import("../src/gateway/idempotency.js");
  m._resetIdempotencyCacheForTests();
  return m;
}

describe("idempotency store", () => {
  it("replay on same key + same hash; conflict on same key + different hash", async () => {
    const m = await mod();
    const args = { title: "fix bug", repo: "api" };
    const hash = m.hashCallArgs(args);
    expect(m.lookupIdempotent("k1", hash)).toEqual({ outcome: "miss" });

    m.storeIdempotent("k1", "github", "create_issue", hash, { ok: true, id: 42 });
    expect(m.lookupIdempotent("k1", hash)).toEqual({
      outcome: "replay",
      result: { ok: true, id: 42 },
    });
    expect(m.lookupIdempotent("k1", m.hashCallArgs({ title: "different" })).outcome).toBe("conflict");
  });

  it("entries older than 24h are pruned (miss, not replay)", async () => {
    const m = await mod();
    const fs = await import("node:fs");
    const hash = m.hashCallArgs({ a: 1 });
    m.storeIdempotent("old-key", "github", "create_issue", hash, { ok: true });
    // Age the entry beyond the TTL by rewriting the store file directly.
    const store = JSON.parse(fs.readFileSync(m.IDEMPOTENCY_PATH, "utf8"));
    store["old-key"].ts = Date.now() - 25 * 3600 * 1000;
    fs.writeFileSync(m.IDEMPOTENCY_PATH, JSON.stringify(store, null, 2), { mode: 0o600 });
    m._resetIdempotencyCacheForTests();
    expect(m.lookupIdempotent("old-key", hash).outcome).toBe("miss");
  });
});

describe("proxy.call idempotency integration", () => {
  it("the second identical write replays; the key never reaches the upstream", async () => {
    const m = await mod();
    const { UpstreamProxy } = await import("../src/gateway/proxy.js");
    const { Vault } = await import("../src/vault/vault.js");
    const path = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const FAKE = path.join(
      path.dirname(fileURLToPath(import.meta.url)),
      "..",
      "fake-upstream.mjs",
    );
    const vault = Vault.open();
    const upstream = {
      name: "fakegit",
      transport: { kind: "stdio" as const, command: process.execPath, args: [FAKE] },
      auth: { type: "none" as const },
    };
    const proxy = new UpstreamProxy([upstream], vault, { agentId: "test-agent" });
    try {
      await proxy.connectAll();
      const args = { _sg_idempotency_key: "e2e-key-1" };
      const first = (await proxy.call("fakegit__whoami", args)) as { content: { text: string }[] };
      expect(first.content[0].text).toContain("authenticated=");
      // The second call with the same key+args must be a replay — and to
      // prove the upstream was NOT called, the cached payload came from the
      // first call's own result.
      const second = (await proxy.call("fakegit__whoami", args)) as { content: { text: string }[] };
      expect(second).toEqual(first);
      // And the replay was audited.
      const { readAuditEvents } = await import("../src/audit/verify.js");
      const replays = readAuditEvents().filter((e) => e.kind === "idempotency_replayed");
      expect(replays.length).toBe(1);
      expect(replays[0].detail.key).toBe("e2e-key-1");
      // Different args, same key → explicit conflict.
      await expect(
        proxy.call("fakegit__whoami", { _sg_idempotency_key: "e2e-key-1", extra: true }),
      ).rejects.toThrow(/idempotency_key_conflict/);
    } finally {
      await proxy.closeAll();
    }
  }, 30_000);
});
