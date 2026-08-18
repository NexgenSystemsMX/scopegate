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

/**
 * capSlice: the inline budget for a result_get slice.
 *
 * Before this, result_get was the one tool result in the gateway that returned
 * an unbounded payload: a broad dot-path handed back nearly the whole stored
 * object. It matters downstream because the agent SDK's own >50 000-char spill
 * abstains on results already flagged `truncated`, and the MCP layer sets that
 * flag when it cuts at 100 000 chars — so an uncapped slice reached the model's
 * history at full size and was re-sent on every later step of the turn.
 */
// The budget is a parameter, so these drive it DOWN instead of building payloads
// up. Same branches, ~1 KB of serialization instead of megabytes: the first
// version of this block used 4000-item arrays and 40 KB blobs, and the extra CPU
// was enough to make the fake-timer test in oauth-daemon.test.ts time out when
// the suite runs in parallel. Cheap tests are not just polite here, they are the
// difference between a green suite and a phantom failure two files away.
describe("capSlice", () => {
  type Capped = import("../src/gateway/results.js").CappedSlice;

  it("passes a slice under the budget through untouched, identity included", async () => {
    const m = await mod();
    const small = { title: "issue 1", body: "short" };
    // Same reference back, not a copy: the common path must not serialize.
    expect(m.capSlice(small, 16 * 1024)).toBe(small);
    expect(m.capSlice("plain string", 16 * 1024)).toBe("plain string");
    expect(m.capSlice(null, 16 * 1024)).toBe(null);
  });

  it("caps a slice over the budget and reports the real size", async () => {
    const m = await mod();
    const slice = { items: [{ id: 1, title: "issue 1" }, { id: 2, title: "issue 2" }] };
    const bytes = m.payloadBytes(slice);

    const capped = m.capSlice(slice, 32) as Capped;
    expect(capped.capped).toBe(true);
    expect(capped.bytes).toBe(bytes);
    expect(capped.max_bytes).toBe(32);
    // What reaches the model is the 2 KB preview, whatever the slice weighed.
    expect(capped.preview.length).toBeLessThanOrEqual(2048);
  });

  it("bounds what reaches the model even when the slice is far over budget", async () => {
    const m = await mod();
    const slice = { blob: "x".repeat(8000) };
    const capped = m.capSlice(slice, 512) as Capped;
    expect(capped.bytes).toBeGreaterThan(8000);
    // The whole capped envelope, preview included, stays near the preview cap —
    // that is the property the fix exists for.
    expect(m.payloadBytes(capped)).toBeLessThan(3000);
  });

  it("tells the model that retrying wider is pointless, and offers result_grep", async () => {
    // The note is what makes this terminate. capSlice deliberately does NOT
    // store a new ref (the input is already a ref, so chaining could loop
    // forever on the same broad path); instead the model is told the one thing
    // it cannot infer — that asking again returns no more.
    const m = await mod();
    const capped = m.capSlice({ blob: "x".repeat(200) }, 32) as Capped;
    expect(capped.note).toContain("scopegate_result_grep");
    expect(capped.note).toContain("do NOT retry");
    expect(capped).not.toHaveProperty("result_ref");
  });

  it("honours the budget it is given, since it is per-agent policy", async () => {
    // handleOversizedResult reads policy.maxInlineBytesFor(agentId); the cap has
    // to follow the same number or the two disagree for that agent.
    const m = await mod();
    const payload = { blob: "y".repeat(200) };
    expect(m.capSlice(payload, 64 * 1024)).toBe(payload);
    expect((m.capSlice(payload, 32) as Capped).capped).toBe(true);
  });

  it("defaults to the same budget as the spill mechanism", async () => {
    const m = await mod();
    expect(m.DEFAULT_MAX_INLINE_BYTES).toBe(16 * 1024);
    // Just over the default, without building anything large.
    const justOver = { blob: "z".repeat(m.DEFAULT_MAX_INLINE_BYTES) };
    expect((m.capSlice(justOver) as Capped).capped).toBe(true);
    expect(m.capSlice({ a: 1 })).toEqual({ a: 1 });
  });
});
