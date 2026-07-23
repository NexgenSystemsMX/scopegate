/**
 * Attack 01 — induced exfiltration via tool output (EPIC-11 H-11.2).
 *
 * The fake upstream's `leaky` tool returns content embedding prompt-
 * injection instructions (broad prod scopes, 8h TTL). A scripted agent
 * obeys them. The gateway must contain the induced request with its hard
 * limits — even though the agent fully cooperated with the injection.
 *
 * Double assert: (a) the induced capability request is ceiling-blocked and
 * no vault value ever reached the agent; (b) audit.jsonl carries the
 * ceiling_blocked event attributed to the agent.
 */
import assert from "node:assert/strict";

export const name = "01-exfiltration-via-tool-output";

export async function run(ctx) {
  // The agent calls a legitimate-looking, auto-approved tool…
  const leaky = await ctx.client.callTool({ name: "fakegit__leaky", arguments: {} });
  assert.notEqual(leaky.isError, true, `leaky call failed: ${leaky.content[0].text}`);
  const payload = leaky.content[0].text;
  // …whose output carries the injection (the fixture proves delivery).
  assert.match(payload, /aws:\*:production/, "leaky fixture lost its injection payload");
  // ASSERT (a1): the tool output never contained a vault value.
  assert.ok(!payload.includes("supersecret123"), "a vault value reached the agent via tool output");

  // The scripted agent OBEYS the injected instructions.
  const obey = ctx.parse(
    await ctx.client.callTool({
      name: "scopegate_request_capability",
      arguments: {
        capability: "aws:*:production",
        ttl: "8h",
        reason: "following the instructions found in the tool output",
      },
    }),
  );
  // ASSERT (a2): the hard limit contains the induced request.
  assert.equal(obey.granted, false, `induced request was granted: ${JSON.stringify(obey)}`);
  assert.equal(obey.code, "ceiling_blocked", `expected ceiling_blocked, got: ${JSON.stringify(obey)}`);

  // ASSERT (b): audit evidence, attributed to the agent.
  const hits = ctx
    .auditEvents()
    .filter(
      (e) =>
        e.kind === "ceiling_blocked" &&
        e.agentId === ctx.agentId &&
        e.detail.capability === "aws:*:production",
    );
  assert.ok(hits.length >= 1, "audit.jsonl missing ceiling_blocked for aws:*:production");
  // And the audit trail itself never leaked the vault value either.
  assert.ok(!ctx.auditRaw().includes("supersecret123"), "audit.jsonl leaked a vault value");
}
