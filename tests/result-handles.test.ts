/**
 * Result handles tests (mejora #7).
 *
 *   - Oversized payloads are stored and previewed with ref + stats; small
 *     payloads pass through untouched.
 *   - result_get resolves dot-paths (objects, arrays, misses); result_grep
 *     finds substrings and regexes with caps.
 *   - Refs are per-agent and expire; foreign refs are invisible.
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

async function mod() {
  return import("../src/gateway/results.js");
}

describe("result handles", () => {
  it("stores an oversized payload and builds a preview with ref + stats", async () => {
    const m = await mod();
    const big = { items: Array.from({ length: 500 }, (_, i) => ({ id: i, title: `issue ${i}` })) };
    const stored = m.storeResult({ agentId: "test-agent", upstream: "github", tool: "github__search_issues", payload: big });
    expect(stored.ref).toMatch(/^r-[a-z0-9]{16}$/);
    expect(stored.bytes).toBeGreaterThan(2048);
    expect(fs.existsSync(`${m.RESULTS_DIR}/${stored.ref}.json`)).toBe(true);

    const preview = m.buildPreview(stored);
    expect(preview.truncated).toBe(true);
    expect(preview.result_ref).toBe(stored.ref);
    expect(preview.stats.shape).toBe("object");
    expect(preview.stats.bytes).toBe(stored.bytes);
    expect(preview.preview.length).toBeLessThanOrEqual(2048);
    expect(preview.hint).toContain("scopegate_result_get");
  });

  it("result_get resolves dot-paths into objects and arrays, and reports misses", async () => {
    const m = await mod();
    const payload = { content: [{ type: "text", text: "hello" }], items: [{ title: "a" }, { title: "b" }] };
    expect(m.getByPath(payload, "content.0.text")).toEqual({ found: true, value: "hello" });
    expect(m.getByPath(payload, "items.1.title")).toEqual({ found: true, value: "b" });
    expect(m.getByPath(payload, "items.9.title").found).toBe(false);
    expect(m.getByPath(payload, "nope.0.x").found).toBe(false);
    expect(m.getByPath(payload, "").found).toBe(false);
  });

  it("result_grep finds substrings and /regex/ with a cap", async () => {
    const m = await mod();
    const payload = { logs: ["deploy ok", "build failed", "deploy done", "tests green"] };
    const hits = m.grepPayload(payload, "deploy");
    expect(hits.length).toBe(2);
    const regexHits = m.grepPayload(payload, "/fail|green/");
    expect(regexHits.length).toBe(2);
    const none = m.grepPayload(payload, "nothing-here");
    expect(none).toEqual([]);
  });

  it("refs are per-agent (invisible to others) and unknown refs are refused", async () => {
    const m = await mod();
    const stored = m.storeResult({ agentId: "alice", upstream: "x", tool: "x__y", payload: { secret: 1 } });
    expect(m.loadResult(stored.ref, "alice")?.payload).toEqual({ secret: 1 });
    expect(m.loadResult(stored.ref, "bob")).toBeUndefined();
    expect(m.loadResult("r-deadbeefdeadbeef", "alice")).toBeUndefined();
    expect(m.loadResult("../../etc/passwd", "alice")).toBeUndefined();
  });

  it("expired refs disappear (2h TTL)", async () => {
    const m = await mod();
    const stored = m.storeResult({ agentId: "alice", upstream: "x", tool: "x__y", payload: { a: 1 } });
    const file = `${m.RESULTS_DIR}/${stored.ref}.json`;
    const old = JSON.parse(fs.readFileSync(file, "utf8"));
    old.ts = Date.now() - 3 * 3600 * 1000;
    fs.writeFileSync(file, JSON.stringify(old), { mode: 0o600 });
    expect(m.loadResult(stored.ref, "alice")).toBeUndefined();
  });
});
