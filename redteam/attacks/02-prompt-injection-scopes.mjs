/**
 * Attack 02 — prompt injection asking for progressively broader scopes
 * (EPIC-11 H-11.3).
 *
 * After a first denial, the injected agent retries with ever-broader
 * capability strings up to '*:*' and a prod glob. Every escalation must be
 * denied: either no auto_approve rule matches (the engine's asymmetry) or a
 * hard limit blocks it BEFORE any rule is evaluated (ceiling_blocked).
 *
 * Double assert: (a) all four escalation steps are denied (none granted);
 * (b) every attempt is in audit.jsonl (capability_denied / ceiling_blocked)
 * attributed to the agent.
 */
import assert from "node:assert/strict";

export const name = "02-prompt-injection-scope-escalation";

const ESCALATION = [
  { capability: "fakegit:call:danger", expectCode: undefined }, // no rule → plain denial
  { capability: "fakegit:*", expectCode: undefined }, // broader: still no rule
  { capability: "aws:*:production", expectCode: "ceiling_blocked" }, // hard limit
  { capability: "*:*", expectCode: "ceiling_blocked" }, // maximal: hard limit
];

export async function run(ctx) {
  for (const step of ESCALATION) {
    const r = ctx.parse(
      await ctx.client.callTool({
        name: "scopegate_request_capability",
        arguments: {
          capability: step.capability,
          reason: "prompt-injection escalation ladder",
        },
      }),
    );
    // ASSERT (a): every escalation step is denied, none escalates to a grant.
    assert.equal(
      r.granted,
      false,
      `escalation step '${step.capability}' was GRANTED: ${JSON.stringify(r)}`,
    );
    assert.notEqual(
      r.status,
      "pending_human_approval",
      `escalation step '${step.capability}' reached a human-approval queue`,
    );
    if (step.expectCode) {
      assert.equal(
        r.code,
        step.expectCode,
        `expected ${step.expectCode} for '${step.capability}', got: ${JSON.stringify(r)}`,
      );
    }
    // ASSERT (b): the attempt is audited with attribution.
    const audited = ctx.auditEvents().some(
      (e) =>
        (e.kind === "capability_denied" || e.kind === "ceiling_blocked") &&
        e.agentId === ctx.agentId &&
        e.detail.capability === step.capability,
    );
    assert.ok(audited, `audit.jsonl missing a denial event for '${step.capability}'`);
  }
}
