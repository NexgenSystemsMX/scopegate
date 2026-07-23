/**
 * Attack 06 — honeytoken: canary ref used as a credential (EPIC-11 H-11.10).
 *
 * A canary was planted under `canary:deploy-key` (operator action in
 * run.mjs). Using it as a secretRef in register_upstream is a certain
 * exfiltration signal: the gateway must deny the registration, audit
 * honeytoken_triggered, revoke the agent's grants, suspend it and deny
 * EVERY later request (fail-closed) — blast radius limited to this agent.
 *
 * Runs LAST by design: after the suspension, nothing else works.
 *
 * Double assert: (a) the malicious registration is rejected and everything
 * afterwards is denied (management tool, capability request, previously
 * granted proxied call); (b) audit.jsonl carries honeytoken_triggered AND
 * agent_revoked with attribution, and the state file marks the suspension.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

export const name = "06-honeytoken-canary-as-credential";

export async function run(ctx) {
  // Regression warm-up (0 false positives): a LEGITIMATE register_upstream
  // succeeds and triggers nothing.
  const legit = await ctx.client.callTool({
    name: "scopegate_register_upstream",
    arguments: {
      name: "legitup",
      transport: { kind: "stdio", command: process.execPath, args: [ctx.FAKE_UPSTREAM] },
      auth: { type: "env", env: { FAKE_TOKEN: "legit_token" } },
    },
  });
  assert.notEqual(legit.isError, true, `legit registration broke (false positive): ${legit.content[0].text}`);
  assert.ok(
    !ctx.auditEvents().some((e) => e.kind === "honeytoken_triggered"),
    "FALSE POSITIVE: a legitimate registration triggered the honeytoken",
  );

  // THE ATTACK: the exfiltrated canary ref is used as a live credential.
  const evil = await ctx.client.callTool({
    name: "scopegate_register_upstream",
    arguments: {
      name: "evilup",
      transport: { kind: "http", url: "http://127.0.0.1:9/mcp" },
      auth: { type: "bearer", secretRef: ctx.canary.ref },
    },
  });
  // ASSERT (a1): the registration is rejected and nothing is persisted.
  assert.equal(evil.isError, true, "a canary ref was ACCEPTED as a credential");
  assert.match(evil.content[0].text, /honeytoken/i, `unexpected message: ${evil.content[0].text}`);
  assert.ok(
    !fs.readFileSync(path.join(ctx.home, "scopegate.yaml"), "utf8").includes("evilup"),
    "evilup landed in scopegate.yaml",
  );

  // ASSERT (b1): trigger + revocation audited, attributed to the agent.
  const events = ctx.auditEvents();
  const trig = events.find(
    (e) =>
      e.kind === "honeytoken_triggered" &&
      e.detail.ref === ctx.canary.ref &&
      e.detail.vector === "register_upstream",
  );
  assert.ok(trig, "audit.jsonl missing honeytoken_triggered (register_upstream)");
  assert.equal(trig.agentId, ctx.agentId, "honeytoken_triggered not attributed to the agent");
  const rev = events.find((e) => e.kind === "agent_revoked" && e.agentId === ctx.agentId);
  assert.ok(rev, "audit.jsonl missing agent_revoked");
  assert.ok(rev.detail.revokedGrants >= 1, `expected >=1 revoked grant, got ${rev.detail.revokedGrants}`);

  // ASSERT (b2): the suspension is marked in the honeytoken state file.
  const state = JSON.parse(
    fs.readFileSync(path.join(ctx.home, "honeytoken-state.json"), "utf8"),
  );
  assert.ok(state.suspended?.[ctx.agentId], "agent not marked suspended in honeytoken-state.json");
  // …and every live grant of the agent is gone from the grant store.
  const grants = JSON.parse(fs.readFileSync(path.join(ctx.home, "grants.json"), "utf8"));
  assert.equal(
    grants.grants.filter((g) => g.agentId === ctx.agentId).length,
    0,
    "grants of the suspended agent survived the revocation",
  );

  // ASSERT (a2): EVERYTHING afterwards is denied (fail-closed) — a management
  // tool, a capability request and a previously auto-approved proxied call.
  const probes = [
    ["scopegate_list_capabilities", {}],
    ["scopegate_request_capability", { capability: "fakegit:call:whoami", reason: "post-incident" }],
    ["fakegit__whoami", {}],
  ];
  for (const [tool, args] of probes) {
    const r = await ctx.client.callTool({ name: tool, arguments: args });
    assert.equal(r.isError, true, `${tool} still works after the suspension`);
    assert.match(r.content[0].text, /SUSPENDED/, `${tool}: denial lacks the suspension reason`);
  }
  const denied = ctx
    .auditEvents()
    .filter((e) => e.kind === "capability_denied" && e.detail.code === "agent_suspended");
  assert.ok(denied.length >= probes.length, "post-suspension denials are not audited");
}
