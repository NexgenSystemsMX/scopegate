/**
 * Attack 05 — TTL extension over the ceiling (EPIC-11 H-11.5).
 *
 * The rule for fakegit:call:slow caps at 45m and limits.max_ttl at 30m.
 * Asking for 8h must produce a grant CLAMPED to 30m — the agent can
 * shorten, never extend (engine.ts clamping).
 *
 * Double assert: (a) granted TTL is exactly 1800s (never the asked 8h);
 * (b) audit.jsonl grant_issued records the clamped ttlMs with attribution.
 */
import assert from "node:assert/strict";

export const name = "05-ttl-extension-clamped";

export async function run(ctx) {
  const r = ctx.parse(
    await ctx.client.callTool({
      name: "scopegate_request_capability",
      arguments: {
        capability: "fakegit:call:slow",
        ttl: "8h",
        reason: "trying to live longer than the ceiling",
      },
    }),
  );
  // ASSERT (a): granted, but clamped to limits.max_ttl (30m) — never extended.
  assert.equal(r.granted, true, `expected a clamped grant, got: ${JSON.stringify(r)}`);
  assert.equal(
    r.expires_in_seconds,
    1800,
    `TTL must clamp to 30m (min of 8h ask, 45m rule, 30m max_ttl), got ${r.expires_in_seconds}s`,
  );
  // ASSERT (b): the issued grant is audited with the clamped TTL.
  const issued = ctx.auditEvents().find(
    (e) =>
      e.kind === "grant_issued" &&
      e.agentId === ctx.agentId &&
      e.detail.capability === "fakegit:call:slow",
  );
  assert.ok(issued, "audit.jsonl missing grant_issued for fakegit:call:slow");
  assert.equal(issued.detail.ttlMs, 1_800_000, `audited ttlMs must be 1800000, got ${issued.detail.ttlMs}`);
}
