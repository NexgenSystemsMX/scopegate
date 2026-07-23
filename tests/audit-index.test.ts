/**
 * EPIC-07 H7.4 (fallback ADR: pure-TS index instead of better-sqlite3):
 * derived, rebuildable in-memory index + optional JSON snapshot, and the
 * "what did this agent/token touch in a window" query. Isolated from the real
 * HOME via tests/helpers.ts.
 */
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  home = useTempHome();
  // Silence the lazy-identity WARN from audit(); nothing here asserts on it.
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  errSpy.mockRestore();
  cleanupTempHome(home);
});

function syntheticEvent(
  seq: number,
  ts: string,
  agentId: string,
  kind: string,
  detail: Record<string, unknown> = {},
) {
  return {
    ts,
    agentId,
    kind,
    detail,
    prev: seq === 1 ? "genesis" : `h${seq - 1}`,
    seq,
    sig: "ed25519:synthetic",
    hash: `h${seq}`,
  };
}

describe("audit index (EPIC-07)", () => {
  it("query filters by agent, kind and time window (inclusive bounds)", async () => {
    const { buildIndex, queryIndex } = await import("../src/audit/index.js");
    const idx = buildIndex([
      syntheticEvent(1, "2026-07-22T10:00:00.000Z", "agent-a", "tool_call", { tool: "t1" }),
      syntheticEvent(2, "2026-07-22T11:00:00.000Z", "agent-a", "secret_ref_used", { secretRef: "tok" }),
      syntheticEvent(3, "2026-07-22T12:00:00.000Z", "agent-b", "tool_call", { tool: "t2" }),
    ]);

    // Window 10:30–11:30 catches only the 11:00 event.
    expect(
      queryIndex(idx, { since: "2026-07-22T10:30:00Z", until: "2026-07-22T11:30:00Z" }).map(
        (e) => e.seq,
      ),
    ).toEqual([2]);
    // Inclusive bounds: since exactly at an event's ts includes it.
    expect(queryIndex(idx, { since: "2026-07-22T11:00:00.000Z" }).map((e) => e.seq)).toEqual([2, 3]);
    // Agent filter.
    expect(queryIndex(idx, { agent: "agent-b" }).map((e) => e.seq)).toEqual([3]);
    // Kind filter.
    expect(queryIndex(idx, { kind: "secret_ref_used" }).map((e) => e.seq)).toEqual([2]);
    // Combined: agent + kind + window.
    expect(
      queryIndex(idx, { agent: "agent-a", kind: "tool_call", since: "2026-07-22T00:00:00Z" }).map(
        (e) => e.seq,
      ),
    ).toEqual([1]);
    // Limit.
    expect(queryIndex(idx, { limit: 2 })).toHaveLength(2);
    // Invalid window bound is an actionable error.
    expect(() => queryIndex(idx, { since: "yesterday" })).toThrow(/Invalid --since/);
  });

  it("queries the real log written by audit() (in-memory rebuild, no snapshot)", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" });
    audit("agent-b", "tool_call", { tool: "github__y" });
    audit("agent-a", "capability_denied", { capability: "github:write:x" });

    const { AUDIT_INDEX_PATH, loadOrBuildIndex, queryIndex } = await import(
      "../src/audit/index.js"
    );
    expect(fs.existsSync(AUDIT_INDEX_PATH)).toBe(false); // query never writes a snapshot
    const idx = loadOrBuildIndex();
    expect(idx.lastSeq).toBe(4);
    expect(queryIndex(idx, { agent: "agent-a", kind: "tool_call" })).toHaveLength(1);
    expect(queryIndex(idx, { kind: "tool_call" })).toHaveLength(2);
    expect(queryIndex(idx, { since: new Date(Date.now() + 60_000).toISOString() })).toHaveLength(0);
  });

  it("reindex verifies the trail and writes a fresh snapshot used by later queries", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "secret_ref_used", { secretRef: "github_token", upstream: "github" });

    const { AUDIT_INDEX_PATH, loadOrBuildIndex, queryIndex, reindex } = await import(
      "../src/audit/index.js"
    );
    const idx = reindex();
    expect(idx.lastSeq).toBe(2);
    expect(fs.existsSync(AUDIT_INDEX_PATH)).toBe(true);

    // Snapshot on disk is the same derived data and is served back when fresh.
    const snap = JSON.parse(fs.readFileSync(AUDIT_INDEX_PATH, "utf8"));
    expect(snap.v).toBe(1);
    expect(snap.events).toHaveLength(2);
    const again = loadOrBuildIndex();
    expect(again.builtAt).toBe(snap.builtAt); // came from the snapshot, not a rebuild
    expect(queryIndex(again, { kind: "secret_ref_used" })).toHaveLength(1);
  });

  it("ignores a stale snapshot after new events arrive", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { loadOrBuildIndex, reindex } = await import("../src/audit/index.js");
    audit("agent-a", "gateway_start", {});
    reindex();

    audit("agent-a", "tool_call", { tool: "github__x" }); // snapshot now stale

    const idx = loadOrBuildIndex();
    expect(idx.lastSeq).toBe(2);
    expect(idx.events).toHaveLength(2);
  });

  it("reindex refuses to index a manipulated log", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" });

    const lines = fs.readFileSync(AUDIT_LOG_PATH, "utf8").trim().split("\n");
    const forged = JSON.parse(lines[1]);
    forged.detail = { tool: "github__pwned" };
    lines[1] = JSON.stringify(forged);
    fs.writeFileSync(AUDIT_LOG_PATH, lines.join("\n") + "\n");

    const { AUDIT_INDEX_PATH, reindex } = await import("../src/audit/index.js");
    expect(() => reindex()).toThrow(/refusing to index a broken audit log: first invalid event seq=2/);
    expect(fs.existsSync(AUDIT_INDEX_PATH)).toBe(false);
  });
});
