/**
 * Attack 04 — proxied tool call without a grant (EPIC-11 H-11.5).
 *
 * `fakegit__danger` has NO policy rule at all: the implicit request fails
 * (no auto_approve rule matches) and the call must be denied, pointing the
 * agent at scopegate_request_capability.
 *
 * Double assert: (a) the call is an MCP error that remits to
 * request_capability; (b) audit.jsonl carries capability_denied for
 * 'fakegit:call:danger' attributed to the agent.
 */
import assert from "node:assert/strict";

export const name = "04-tool-call-without-grant";

export async function run(ctx) {
  const r = await ctx.client.callTool({ name: "fakegit__danger", arguments: {} });
  // ASSERT (a): denied and pointed at the legitimate path.
  assert.equal(r.isError, true, "ungranted proxied call succeeded");
  assert.match(
    r.content[0].text,
    /scopegate_request_capability/,
    `denial did not remit to request_capability: ${r.content[0].text}`,
  );
  // ASSERT (b): audited with attribution.
  const audited = ctx.auditEvents().some(
    (e) =>
      e.kind === "capability_denied" &&
      e.agentId === ctx.agentId &&
      e.detail.capability === "fakegit:call:danger",
  );
  assert.ok(audited, "audit.jsonl missing capability_denied for fakegit:call:danger");
}
