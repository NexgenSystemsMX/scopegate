/**
 * OAuth Refresh Daemon tests (EPIC-03): proactive scheduling at 80% of the
 * TTL, refresh-token rotation, the per-upstream mutex, invalid_grant →
 * needs_reauth (no retry loop), out-of-band recovery after `scopegate auth
 * login`, and the RFC 8628 device-code flow end to end against the fake
 * upstream (fake-upstream.mjs --oauth, spawned on an ephemeral port).
 *
 * Isolation: every test gets its own throwaway SCOPEGATE_HOME via helpers;
 * src modules are imported dynamically AFTER useTempHome() (config paths are
 * resolved at module load). The token endpoint is a mock fetchImpl except in
 * the device-code test, which spawns the real fake authorization server.
 */
import fs from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { UpstreamConfig } from "../src/config/config.js";

const FAKE_UPSTREAM = fileURLToPath(new URL("../fake-upstream.mjs", import.meta.url));

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  cleanupTempHome(home);
});

function notionUpstream(tokenUrl = "http://127.0.0.1:1/token"): UpstreamConfig {
  return {
    name: "notion",
    transport: { kind: "http", url: "http://127.0.0.1:1/mcp" },
    auth: { type: "oauth2", secretRef: "oauth2:notion" },
  };
}

function blobJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 1,
    access_token: "at-0",
    refresh_token: "rt-0",
    expires_at: Date.now() + 100_000,
    obtained_at: Date.now(),
    token_url: "http://127.0.0.1:1/token",
    client_id: "scopegate-test",
    ...overrides,
  });
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function newDaemon(
  fetchImpl: typeof fetch,
  opts: { random?: () => number; upstream?: UpstreamConfig } = {},
) {
  const { Vault } = await import("../src/vault/vault.js");
  const { OAuthRefreshDaemon } = await import("../src/oauth/daemon.js");
  const vault = Vault.open();
  const upstream = opts.upstream ?? notionUpstream();
  vault.set("oauth2:notion", blobJson());
  const daemon = new OAuthRefreshDaemon({
    vault,
    upstreams: [upstream],
    agentId: "test-agent",
    fetchImpl,
    random: opts.random ?? (() => 0.5), // zero jitter → deterministic delays
  });
  return { vault, daemon, upstream };
}

describe("scheduler", () => {
  it("renews proactively at 80% of the remaining TTL (fake timers)", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      return jsonResponse(200, {
        access_token: `at-${calls}`,
        refresh_token: `rt-${calls}`,
        expires_in: 100,
      });
    }) as unknown as typeof fetch;
    const { daemon } = await newDaemon(fetchImpl);
    daemon.start();

    // Blob has 100 s left → tick at 80 s (zero jitter).
    await vi.advanceTimersByTimeAsync(79_999);
    expect(calls).toBe(0);
    await vi.advanceTimersByTimeAsync(2);
    expect(calls).toBe(1);
    // After the refresh the next tick is rescheduled (~another 80 s).
    await vi.advanceTimersByTimeAsync(80_001);
    expect(calls).toBe(2);
    daemon.stop();
  });

  it("stop() cancels pending timers (clean shutdown)", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      return jsonResponse(200, { access_token: "at-x", expires_in: 100 });
    }) as unknown as typeof fetch;
    const { daemon } = await newDaemon(fetchImpl);
    daemon.start();
    daemon.stop();
    await vi.advanceTimersByTimeAsync(1_000_000);
    expect(calls).toBe(0);
  });
});

describe("refresh client + rotation", () => {
  it("persists a rotated refresh_token atomically (old value gone from the vault)", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, {
        access_token: "at-new",
        refresh_token: "rt-new",
        expires_in: 3600,
      }),
    ) as unknown as typeof fetch;
    const { vault, daemon } = await newDaemon(fetchImpl);
    const res = await daemon.refreshNow("notion");
    expect(res.ok).toBe(true);

    const raw = vault.get("oauth2:notion");
    const blob = JSON.parse(raw);
    expect(blob.access_token).toBe("at-new");
    expect(blob.refresh_token).toBe("rt-new");
    expect(raw).not.toContain("rt-0");
    expect(blob.expires_at).toBeGreaterThan(Date.now() + 3_500_000);

    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    expect(auditRaw).toContain('"token_refreshed"');
    expect(auditRaw).toContain('"rotated":true');
    // Never token material in the audit trail.
    expect(auditRaw).not.toContain("at-new");
    expect(auditRaw).not.toContain("rt-new");
  });

  it("keeps the previous refresh_token when the server does not rotate", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(200, { access_token: "at-new", expires_in: 3600 }),
    ) as unknown as typeof fetch;
    const { vault, daemon } = await newDaemon(fetchImpl);
    await daemon.refreshNow("notion");
    const blob = JSON.parse(vault.get("oauth2:notion"));
    expect(blob.refresh_token).toBe("rt-0");
    expect(blob.access_token).toBe("at-new");
  });
});

describe("mutex (rotating refresh tokens)", () => {
  it("serializes concurrent refreshes: two refreshNow → one endpoint call", async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      await new Promise((r) => setTimeout(r, 25));
      return jsonResponse(200, {
        access_token: "at-1",
        refresh_token: "rt-1",
        expires_in: 3600,
      });
    }) as unknown as typeof fetch;
    const { daemon } = await newDaemon(fetchImpl);
    const [a, b] = await Promise.all([
      daemon.refreshNow("notion"),
      daemon.refreshNow("notion"),
    ]);
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    expect(calls).toBe(1);
  });
});

describe("invalid_grant → needs_reauth", () => {
  it("marks needs_reauth, signals the human, and never retries in a loop", async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      return jsonResponse(400, { error: "invalid_grant" });
    }) as unknown as typeof fetch;
    const { daemon } = await newDaemon(fetchImpl);

    const r1 = await daemon.refreshNow("notion");
    expect(r1.ok).toBe(false);
    expect(r1.state).toBe("needs_reauth");
    expect(r1.error).toContain("run in your terminal: scopegate auth login notion");

    // On-disk signal (contract: ~/.scopegate/reauth-required.json).
    const signal = JSON.parse(
      fs.readFileSync(path.join(home, "reauth-required.json"), "utf8"),
    );
    expect(signal.upstream).toBe("notion");

    // Audit lifecycle event, typed and token-free.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    expect(auditRaw).toContain('"oauth_reauth_required"');

    // No retry loop: further refreshes fail fast WITHOUT hitting the endpoint.
    const r2 = await daemon.refreshNow("notion");
    expect(r2.ok).toBe(false);
    expect(r2.state).toBe("needs_reauth");
    expect(calls).toBe(1);

    // diagnose surface carries the state + the literal instruction.
    const health = daemon.statusFor("notion");
    expect(health?.state).toBe("needs_reauth");
    expect(daemon.reauthBlockReason("notion")).toContain(
      "scopegate auth login notion",
    );
  });

  it("recovers without a restart once reauth-required.json disappears (login completed)", async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      return jsonResponse(400, { error: "invalid_grant" });
    }) as unknown as typeof fetch;
    const { vault, daemon } = await newDaemon(fetchImpl);
    await daemon.refreshNow("notion");
    expect(daemon.needsReauth("notion")).toBe(true);

    // Simulate `scopegate auth login` in a SEPARATE process: a fresh vault
    // instance writes the new blob to disk, then the signal file is deleted.
    const { Vault } = await import("../src/vault/vault.js");
    const { clearReauthRequired } = await import("../src/oauth/reauth.js");
    Vault.open().set(
      "oauth2:notion",
      blobJson({ access_token: "at-fresh", refresh_token: "rt-fresh" }),
    );
    clearReauthRequired("notion");

    const res = await daemon.refreshNow("notion");
    expect(res.ok).toBe(true);
    expect(res.recovered).toBe(true);
    expect(calls).toBe(1); // recovery needs no endpoint call
    // The live vault (the instance the proxy injects from) now holds the
    // fresh token written by the other process.
    expect(vault.get("oauth2:notion")).toContain("at-fresh");
    expect(daemon.needsReauth("notion")).toBe(false);
  });
});

describe("backoff + circuit breaker", () => {
  it("backs off on retryable errors and opens the circuit after 5 failures", async () => {
    vi.useFakeTimers();
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      return jsonResponse(503, { error: "temporarily_unavailable" });
    }) as unknown as typeof fetch;
    const { daemon } = await newDaemon(fetchImpl);
    daemon.start();

    await vi.advanceTimersByTimeAsync(80_001); // proactive tick at 80 s
    expect(calls).toBe(1);
    expect(daemon.statusFor("notion")?.state).toBe("backoff");

    // Backoff schedule (zero jitter): 5 s, 10 s, 20 s, 40 s — then the 5th
    // consecutive failure trips the circuit breaker.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(calls).toBe(2);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(calls).toBe(3);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(calls).toBe(4);
    await vi.advanceTimersByTimeAsync(40_000);
    expect(calls).toBe(5);
    expect(daemon.statusFor("notion")?.state).toBe("circuit_open");

    // Circuit open: no more scheduled retries.
    await vi.advanceTimersByTimeAsync(30 * 60_000);
    expect(calls).toBe(5);

    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    expect(auditRaw).toContain('"token_refresh_failed"');
    daemon.stop();
  });
});

describe("device-code flow (RFC 8628) against the fake upstream", () => {
  it("runAuthLogin completes the flow: blob deposited, signal cleared, audited", async () => {
    // Real fake authorization server on an ephemeral port.
    const child: ChildProcess = spawn(process.execPath, [FAKE_UPSTREAM, "--oauth"], {
      env: { ...process.env, FAKE_OAUTH_ACCESS_TTL_S: "30" },
      stdio: ["ignore", "pipe", "inherit"],
    });
    const port = await new Promise<number>((resolve, reject) => {
      let buf = "";
      child.stdout!.on("data", (d) => {
        buf += d.toString();
        const m = /FAKE_OAUTH_PORT=(\d+)/.exec(buf);
        if (m) resolve(Number(m[1]));
      });
      child.on("error", reject);
      child.on("exit", (code) => reject(new Error(`fake oauth server exited early (${code})`)));
      setTimeout(() => reject(new Error("fake oauth server did not report its port")), 10_000);
    });

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const { Vault } = await import("../src/vault/vault.js");
      const { saveConfig } = await import("../src/config/config.js");
      const { writeReauthRequired } = await import("../src/oauth/reauth.js");
      const { runAuthLogin } = await import("../src/commands/oauth-login.js");

      const base = `http://127.0.0.1:${port}`;
      saveConfig({
        version: 1,
        agentId: "test-agent",
        upstreams: [
          {
            name: "notion",
            transport: { kind: "http", url: `${base}/mcp` },
            auth: { type: "oauth2", secretRef: "oauth2:notion" },
          },
        ],
      });
      // Dead-grant blob: endpoints + client identity survive, tokens are dead.
      Vault.open().set(
        "oauth2:notion",
        blobJson({
          token_url: `${base}/token`,
          expires_at: Date.now() - 1_000,
        }),
      );
      writeReauthRequired({
        upstream: "notion",
        reason: "test: grant revoked",
        since: new Date().toISOString(),
      });

      // The human: watch for the user_code and approve it (fake's helper).
      const login = runAuthLogin({ upstream: "notion" });
      let approved = false;
      for (let i = 0; i < 50 && !approved; i++) {
        await new Promise((r) => setTimeout(r, 200));
        const pending = (await (
          await fetch(`${base}/device/pending`)
        ).json()) as { user_codes: string[] };
        if (pending.user_codes.length > 0) {
          const res = await fetch(`${base}/device/approve`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ user_code: pending.user_codes[0] }),
          });
          expect(res.status).toBe(200);
          approved = true;
        }
      }
      expect(approved).toBe(true);
      await login;

      // The user_code + verification_uri went to STDERR, never stdout.
      const errOut = errSpy.mock.calls.map((c) => String(c[0])).join("\n");
      expect(errOut).toContain(`${base}/verify`);
      expect(errOut).toMatch(/CODE-\d{4}/);

      // Blob v1 deposited under the frozen secretRef, tokens rotated.
      const blob = JSON.parse(Vault.open().get("oauth2:notion"));
      expect(blob.v).toBe(1);
      expect(blob.access_token).toMatch(/^at-/);
      expect(blob.access_token).not.toBe("at-0");
      expect(blob.refresh_token).toMatch(/^rt-/);
      expect(blob.refresh_token).not.toBe("rt-0");
      expect(blob.client_id).toBe("scopegate-test");
      expect(blob.expires_at).toBeGreaterThan(Date.now() + 25_000);

      // Re-auth signal cleared; lifecycle audited.
      expect(fs.existsSync(path.join(home, "reauth-required.json"))).toBe(false);
      const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
      expect(auditRaw).toContain('"oauth_reauth_completed"');
      expect(auditRaw).not.toContain(blob.access_token);
      expect(auditRaw).not.toContain(blob.refresh_token);
    } finally {
      child.kill();
    }
  }, 30_000);
});
