/**
 * Attack 03 — raw secret smuggled as secretRef (EPIC-11 H-11.4).
 *
 * register_upstream must only accept vault ref NAMES. Four credential
 * formats (GitHub PAT, AWS access key, JWT, long base64) are passed as
 * `secretRef`; looksLikeSecret() must reject every one.
 *
 * Double assert: (a) all four registrations are rejected with the "raw
 * secret" message and nothing is persisted (config unchanged, no
 * upstream_registered audit); (b) every rejection is audited
 * (capability_denied, code raw_secret_rejected) with attribution.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

export const name = "03-secretref-smuggling";

const SMUGGLED = [
  ["ghp_" + "A".repeat(36), "GitHub PAT"],
  ["AKIA" + "B".repeat(16), "AWS access key id"],
  ["eyJhbGciOiJIUzI1NiJ9." + "C".repeat(43) + "." + "D".repeat(43), "JWT"],
  [Buffer.from("scopegate-redteam-payload-0123456789").toString("base64"), "base64 blob"],
];

export async function run(ctx) {
  for (const [i, [secretRef, label]] of SMUGGLED.entries()) {
    const upName = `smuggle${i}`;
    const r = await ctx.client.callTool({
      name: "scopegate_register_upstream",
      arguments: {
        name: upName,
        transport: { kind: "http", url: "http://127.0.0.1:9/mcp" },
        auth: { type: "bearer", secretRef },
      },
    });
    // ASSERT (a1): rejected with the actionable message.
    assert.equal(r.isError, true, `${label} was ACCEPTED as a secretRef`);
    assert.match(
      r.content[0].text,
      /raw secret|secret add/,
      `${label}: unexpected rejection message: ${r.content[0].text}`,
    );
    // ASSERT (a2): nothing persisted.
    const cfg = fs.readFileSync(path.join(ctx.home, "scopegate.yaml"), "utf8");
    assert.ok(!cfg.includes(upName), `${label}: upstream '${upName}' landed in scopegate.yaml`);
    assert.ok(
      !ctx.auditEvents().some((e) => e.kind === "upstream_registered" && e.detail.name === upName),
      `${label}: upstream_registered audited for '${upName}'`,
    );
    // ASSERT (b): the rejection itself is evidenced with attribution.
    const audited = ctx.auditEvents().some(
      (e) =>
        e.kind === "capability_denied" &&
        e.agentId === ctx.agentId &&
        e.detail.code === "raw_secret_rejected" &&
        e.detail.name === upName,
    );
    assert.ok(audited, `${label}: audit.jsonl missing the raw_secret_rejected event`);
  }
  // The smuggled values never reached the audit trail.
  for (const [secretRef, label] of SMUGGLED) {
    assert.ok(!ctx.auditRaw().includes(secretRef), `${label}: smuggled value leaked into audit.jsonl`);
  }
}
