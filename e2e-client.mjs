#!/usr/bin/env node
/**
 * Portable end-to-end test for ScopeGate.
 *
 *   harness (this script, MCP client) → gateway (dist/cli.js start) → fake-upstream.mjs
 *
 * Portable: every path is resolved relative to this file; SCOPEGATE_HOME is a
 * mkdtemp dir created and removed by this script. No Linux-only paths, no
 * manual steps: the fake upstream is spawned by the gateway itself via the
 * generated config, and the test secret is deposited through the CLI.
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 *
 * Prereq: `npm run build` (needs dist/cli.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");

const watchdog = setTimeout(() => {
  console.error("e2e FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/** Spawn fake-upstream.mjs --http and resolve with its listening port. */
function startHttpUpstream() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [FAKE_UPSTREAM, "--http"], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buf = "";
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /FAKE_UPSTREAM_PORT=(\d+)/.exec(buf);
      if (m) resolve({ child, port: Number(m[1]) });
    });
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`http fake upstream exited early (${code})`)));
    setTimeout(() => reject(new Error("http fake upstream did not report its port")), 10_000);
  });
}

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);

  // 1. Isolated throwaway home. NOTHING touches the real ~/.scopegate.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-"));
  const env = {
    ...process.env,
    SCOPEGATE_HOME: home,
    SCOPEGATE_AGENT_ID: "e2e-agent",
    // Mejora #10 e2e: the enforce gate degrades cross-upstream writes while tainted.
    SCOPEGATE_TAINT_MODE: "enforce",
    // M8 e2e: decoys that must NOT reach the upstream child (the vault wins
    // for FAKE_TOKEN via the composite env; DECOY_SECRET must never arrive).
    FAKE_TOKEN: "WRONG-DECOY",
    DECOY_SECRET: "must-not-leak",
  };
  console.log(`e2e home: ${home}`);

  const client = new Client({ name: "e2e-harness", version: "1.0.0" }, { capabilities: {} });
  // HTTP fake upstream for the minted-JWT scenario (must be up before the
  // gateway's connectAll runs).
  const httpUpstream = await startHttpUpstream();
  try {
    // 2. Config + policies (written as JSON: valid YAML 1.2).
    fs.writeFileSync(
      path.join(home, "scopegate.yaml"),
      JSON.stringify(
        {
          version: 1,
          agentId: "e2e-agent",
          upstreams: [
            {
              name: "fakegit",
              transport: { kind: "stdio", command: process.execPath, args: [FAKE_UPSTREAM] },
              // M1: composite auth — static vault ref + a jwt mint, fused into
              // ONE stdio upstream. The whole suite runs over composite.
              auth: {
                type: "composite",
                env: { FAKE_TOKEN: "fake_token" },
                mint: [{ type: "jwt", secretRef: "jwt_signing_key" }],
              },
            },
            {
              name: "jwtupstream",
              transport: { kind: "http", url: `http://127.0.0.1:${httpUpstream.port}/mcp` },
              auth: { type: "jwt", secretRef: "jwt_signing_key", ttl: "5m" },
            },
          ],
        },
        null,
        2,
      ),
    );
    // Policy document (EPIC-04): hard limits + a require: human_approval rule
    // + a redact rule over the pii_echo fixture. Kept in a const because the
    // hot-reload section rewrites the file from it.
    const policiesDoc = {
      version: 1,
      limits: {
        max_ttl: "30m", // absolute ceiling: nothing outlives 30m
        max_inline_bytes: 1024, // mejora #7: oversized payloads truncate to handles
        deny: [
          "aws:*:production", // prod is off-limits no matter what rules say
          "\\*:*", // literal '*:*' injection asks (escaped glob, matches nothing else)
        ],
      },
      agents: {
        "e2e-agent": {
          default_ttl: "15m",
          capabilities: [
            { match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" },
            { match: "jwtupstream:call:echo_auth", auto_approve: true, ttl: "5m" },
            // rule ttl (45m) sits ABOVE limits.max_ttl (30m) → proves the clamp
            { match: "fakegit:call:slow", auto_approve: true, ttl: "45m" },
            // escalates to the human-approval queue
            { match: "fakegit:call:danger", require: "human_approval", ttl: "10m" },
            // approval-continuation fixture (mejora #2) — separate capability
            // so its grant lifecycle never collides with the danger flow
            { match: "fakegit:call:danger2", require: "human_approval", ttl: "10m" },
            // preflight-only fixture (mejora #3) — never requested, so no
            // live grant ever covers it in this run
            { match: "fakegit:call:danger3", require: "human_approval", ttl: "10m" },
            // lease fixture (mejora #1) — fresh capability, never requested
            // outside the lease section (lease binding applies to NEW grants)
            { match: "fakegit:call:leased", auto_approve: true, ttl: "10m" },
            // oversized-payload fixture (mejora #7)
            { match: "fakegit:call:big_report", auto_approve: true, ttl: "10m" },
            // env-hygiene fixture (M8)
            { match: "fakegit:call:env_probe", auto_approve: true, ttl: "10m" },
            // M5 wait:true fixture — fresh capability, only used by the wait section
            { match: "fakegit:call:danger4", require: "human_approval", ttl: "10m" },
            // M6 when:-guard fixtures — branch kimi/* auto-approves, the rest escalates
            { match: "fakegit:call:branch_push", auto_approve: true, ttl: "10m", when: { branch: "kimi/*" } },
            { match: "fakegit:call:branch_push", require: "human_approval", ttl: "10m" },
            // PII in the RESPONSE is masked under this rule
            { match: "fakegit:call:pii_echo", auto_approve: true, ttl: "5m", redact: ["pii"] },
          ],
        },
      },
    };
    fs.writeFileSync(path.join(home, "policies.yaml"), JSON.stringify(policiesDoc, null, 2));

    // 3. Deposit the secret through the human path (CLI + piped stdin).
    const add = spawnSync(process.execPath, [CLI, "secret", "add", "fake_token"], {
      input: "supersecret123\n",
      env,
      encoding: "utf8",
    });
    assert.equal(add.status, 0, `secret add failed: ${add.stderr || add.stdout}`);
    pass("secret deposited via CLI (stdin)");

    // 3b. Same for the JWT signing key the minter will use.
    const addJwt = spawnSync(process.execPath, [CLI, "secret", "add", "jwt_signing_key"], {
      input: "e2e-hmac-signing-key-0123456789abcdef\n",
      env,
      encoding: "utf8",
    });
    assert.equal(addJwt.status, 0, `secret add failed: ${addJwt.stderr || addJwt.stdout}`);
    pass("JWT signing key deposited via CLI (stdin)");

    // 4. Launch the gateway as the harness would (stdio MCP).
    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }),
    );
    pass("gateway started and MCP handshake completed");

    // 5. listTools: management tools + proxied tools.
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    for (const required of [
      "scopegate_request_capability",
      "scopegate_list_capabilities",
      "scopegate_register_upstream",
      "scopegate_diagnose",
      "scopegate_propose_policy",
      "scopegate_vault_status",
      "fakegit__whoami",
      "fakegit__danger",
      "fakegit__pii_echo",
      "jwtupstream__echo_auth",
    ]) {
      assert.ok(names.includes(required), `listTools missing '${required}' (got: ${names.join(", ")})`);
    }
    pass("listTools exposes scopegate_* management tools and proxied fakegit__* tools");

    const parse = (res) => JSON.parse(res.content[0].text);

    // 6. request_capability granted, TTL clamped to the 10m policy ceiling.
    const grant = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:whoami", ttl: "1h", reason: "e2e" },
      }),
    );
    assert.equal(grant.granted, true, `expected grant, got: ${JSON.stringify(grant)}`);
    assert.equal(grant.expires_in_seconds, 600, "TTL must clamp to the 10m policy ceiling");
    assert.equal(grant.matched_rule, "fakegit:call:whoami");
    pass("request_capability granted with TTL clamped to policy ceiling (1h → 600s)");

    // 7. request_capability denied when no auto_approve rule matches.
    const deny = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:danger", reason: "e2e" },
      }),
    );
    assert.equal(deny.granted, false, `expected denial, got: ${JSON.stringify(deny)}`);
    pass("request_capability denied without matching auto_approve rule");

    // 8. Proxied call WITH grant: secret injected at the outbound hop.
    const call = await client.callTool({ name: "fakegit__whoami", arguments: {} });
    assert.notEqual(call.isError, true, `proxied call failed: ${call.content[0].text}`);
    assert.match(call.content[0].text, /authenticated=true/, "env secret not injected upstream");
    pass("proxied call fakegit__whoami works with env secret injected at the hop");

    // 9. Proxied call WITHOUT grant and without auto_approve rule → isError.
    const blocked = await client.callTool({ name: "fakegit__danger", arguments: {} });
    assert.equal(blocked.isError, true, "ungranted proxied call must be an error");
    assert.match(blocked.content[0].text, /scopegate_request_capability/);
    pass("proxied call without grant is blocked and points to request_capability");

    // 10. vault_status lists refs, never values.
    const vault = parse(await client.callTool({ name: "scopegate_vault_status", arguments: {} }));
    assert.ok(Array.isArray(vault.secret_refs), "vault_status must return secret_refs");
    assert.ok(vault.secret_refs.includes("fake_token"), `fake_token missing from ${vault.secret_refs}`);
    assert.ok(!JSON.stringify(vault).includes("supersecret123"), "vault_status leaked a secret value");
    pass("vault_status lists refs (fake_token) without values");

    // 11. diagnose reports the upstream healthy.
    const diag = parse(await client.callTool({ name: "scopegate_diagnose", arguments: {} }));
    assert.equal(diag.upstreams?.fakegit?.ok, true, `diagnose: ${JSON.stringify(diag)}`);
    pass("diagnose reports fakegit upstream ok");

    // 11b. diagnose declares the credential mode per upstream:
    // minted by the minter vs pure fallback injection (never an error).
    assert.equal(diag.upstreams?.jwtupstream?.mode, "minted:jwt", `diagnose modes: ${JSON.stringify(diag)}`);
    assert.equal(diag.upstreams?.fakegit?.mode, "fallback:injection", `diagnose modes: ${JSON.stringify(diag)}`);
    pass("diagnose exposes credential mode per upstream (minted:jwt / fallback:injection)");

    // 12. Proxied call on a jwt upstream: the Authorization header that
    // reaches the upstream is a MINTED JWT — never the vault signing key.
    const echo = await client.callTool({ name: "jwtupstream__echo_auth", arguments: {} });
    assert.notEqual(echo.isError, true, `jwt proxied call failed: ${echo.content[0].text}`);
    const echoText = echo.content[0].text;
    const m = /authorization=Bearer (\S+)/.exec(echoText);
    assert.ok(m, `no Bearer token echoed upstream: ${echoText}`);
    const [h, p] = m[1].split(".");
    const jwtHeader = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
    const jwtPayload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    assert.equal(jwtHeader.alg, "HS256", `expected HS256 JWT, got: ${JSON.stringify(jwtHeader)}`);
    assert.equal(jwtPayload.iss, "scopegate");
    assert.equal(jwtPayload.aud, "jwtupstream");
    assert.ok(jwtPayload.jti, "minted JWT must carry a jti");
    assert.ok(
      jwtPayload.exp - jwtPayload.iat <= 300,
      `token TTL ${jwtPayload.exp - jwtPayload.iat}s exceeds the 5m clamp`,
    );
    assert.ok(!echoText.includes("e2e-hmac-signing-key"), "upstream received the vault signing key");
    pass("jwt upstream receives a minted HS256 JWT (clamped to 5m), not the vault secret");

    // 13. Audit trail exists, records minter events, and contains no plaintext secret.
    const auditRaw = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRaw.includes('"tool_call"'), "audit log missing tool_call events");
    assert.ok(auditRaw.includes('"secret_ref_used"'), "audit log missing secret_ref_used events");
    assert.ok(auditRaw.includes('"token_minted"'), "audit log missing token_minted events");
    assert.ok(!auditRaw.includes("supersecret123"), "audit log leaked a secret value");
    assert.ok(!auditRaw.includes("e2e-hmac-signing-key"), "audit log leaked the signing key");
    assert.ok(!auditRaw.includes(m[1]), "audit log leaked a minted token value");
    pass("audit.jsonl records actions and minter events, and never leaks secret values");

    /* ------------------------------------------------------------------ */
    /* EPIC-04 — policy engine: hard limits, approvals, redact, hot-reload */
    /* ------------------------------------------------------------------ */

    // 14. Hard ceiling: a prompt-injection style ask for '*:*' (and a prod
    // capability) is denied BEFORE any rule is evaluated.
    const ceiling = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "*:*", reason: "simulated injection: grab everything" },
      }),
    );
    assert.equal(ceiling.granted, false, `expected ceiling denial, got: ${JSON.stringify(ceiling)}`);
    assert.equal(ceiling.code, "ceiling_blocked", `expected ceiling_blocked, got: ${JSON.stringify(ceiling)}`);
    assert.match(ceiling.reason, /hard limit/);
    const ceilingProd = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "aws:delete:production", reason: "simulated injection: prod" },
      }),
    );
    assert.equal(ceilingProd.granted, false);
    assert.equal(ceilingProd.code, "ceiling_blocked");
    pass("hard limits deny '*:*' and prod capabilities before any auto_approve (ceiling_blocked)");

    // 15. limits.max_ttl clamps BELOW the rule ceiling (45m rule → 30m grant).
    const maxTtl = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:slow", ttl: "1h", reason: "e2e" },
      }),
    );
    assert.equal(maxTtl.granted, true, `expected grant, got: ${JSON.stringify(maxTtl)}`);
    assert.equal(maxTtl.expires_in_seconds, 1800, "max_ttl (30m) must clamp below the 45m rule ttl");
    pass("limits.max_ttl clamps grants below the rule ceiling (1h ask → 45m rule → 30m grant)");

    // 16. Human approval flow: request → pending → human decision on disk →
    // one-shot grant with TTL min(requested, rule, max_ttl) → proxied call OK.
    const apReq = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:danger", ttl: "10m", reason: "needs danger for e2e" },
      }),
    );
    assert.equal(apReq.granted, false, `expected escalation, got: ${JSON.stringify(apReq)}`);
    assert.equal(apReq.status, "pending_human_approval", `expected pending status, got: ${JSON.stringify(apReq)}`);
    assert.ok(apReq.approval_id, "pending response must carry approval_id");
    assert.match(apReq.instructions, /scopegate approve/);
    // The human approves — exactly what `scopegate approve <id>` will write (EPIC-08).
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({ id: apReq.approval_id, decision: "approved", decidedAt: Date.now(), decidedBy: "human:e2e" }) + "\n",
      { mode: 0o600 },
    );
    const apGrant = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:danger", ttl: "10m", reason: "needs danger for e2e" },
      }),
    );
    assert.equal(apGrant.granted, true, `expected one-shot grant after approval, got: ${JSON.stringify(apGrant)}`);
    assert.equal(apGrant.expires_in_seconds, 600, "one-shot TTL = min(10m requested, 10m rule, 30m max_ttl)");
    const apLine = fs
      .readFileSync(path.join(home, "approvals.pending.jsonl"), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l))
      .find((r) => r.id === apReq.approval_id);
    assert.equal(apLine.status, "approved", "consumed approval must be marked resolved (one-shot)");
    const dangerNow = await client.callTool({ name: "fakegit__danger", arguments: {} });
    assert.notEqual(dangerNow.isError, true, `approved proxied call failed: ${dangerNow.content[0].text}`);
    pass("require: human_approval → pending → approved on disk → one-shot grant (600s) → call passes");

    // 16b. Mejora #2 (approval continuation): execute_on_approval queues the
    // intent → human approves on disk → the gateway EXECUTES the intent with
    // the fresh grant → scopegate_wait/collect return the upstream result.
    const contReq = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: {
          capability: "fakegit:call:danger2",
          ttl: "10m",
          reason: "continuation e2e",
          execute_on_approval: { tool: "fakegit__danger2", args: {} },
        },
      }),
    );
    assert.equal(contReq.status, "pending_human_approval", `expected pending, got: ${JSON.stringify(contReq)}`);
    assert.equal(contReq.continuation?.queued, true, `continuation not queued: ${JSON.stringify(contReq)}`);
    assert.ok(contReq.continuation.intent_id, "continuation must carry intent_id");
    const contApprovalId = contReq.approval_id;
    // A mismatched intent capability is refused fail-closed (no smuggling).
    const mismatch = await client.callTool({
      name: "scopegate_request_capability",
      arguments: {
        capability: "fakegit:call:danger2",
        ttl: "10m",
        reason: "smuggle attempt",
        execute_on_approval: { tool: "fakegit__whoami", args: {} },
      },
    });
    assert.equal(mismatch.isError, true, "intent/capability mismatch must be rejected");
    assert.match(mismatch.content[0].text, /must equal the requested capability/);
    pass("execute_on_approval queues the continuation (mismatched intents refused fail-closed)");
    // The human approves on disk — the gateway executes the intent itself.
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({ id: contApprovalId, decision: "approved", decidedAt: Date.now(), decidedBy: "human:e2e" }) + "\n",
      { mode: 0o600 },
    );
    const collected = parse(
      await client.callTool({
        name: "scopegate_wait",
        arguments: { approval_id: contApprovalId, timeout_s: 15 },
      }),
    );
    assert.equal(collected.status, "executed", `intent must be executed, got: ${JSON.stringify(collected)}`);
    assert.equal(collected.tool, "fakegit__danger2");
    assert.ok(
      JSON.stringify(collected.result).includes("danger2 executed"),
      `intent result must be the upstream payload: ${JSON.stringify(collected.result)}`,
    );
    // scopegate_collect reads the same stored outcome again (idempotent).
    const recollect = parse(
      await client.callTool({ name: "scopegate_collect", arguments: { approval_id: contApprovalId } }),
    );
    assert.equal(recollect.status, "executed");
    pass("approval continuation: approve → gateway executes → wait/collect return the result");

    // 16c. Mejora #8: machine-readable error envelopes + upstream health tool.
    const health = parse(await client.callTool({ name: "scopegate_upstream_health", arguments: {} }));
    assert.ok(health.upstreams?.fakegit, `health must cover fakegit: ${JSON.stringify(health)}`);
    assert.equal(health.upstreams.fakegit.circuit.state, "closed");
    assert.equal(health.upstreams.fakegit.ok, true, `fakegit must be healthy: ${JSON.stringify(health.upstreams.fakegit)}`);
    pass("scopegate_upstream_health reports liveness + circuit state per upstream");
    // A denied implicit call returns a structured envelope (kind + next_action).
    const envelope = await client.callTool({ name: "fakegit__leaky", arguments: {} });
    assert.equal(envelope.isError, true, "not-granted tool must be an error");
    const envParsed = JSON.parse(envelope.content[0].text);
    assert.equal(envParsed.error, true);
    assert.equal(envParsed.kind, "missing_scope", `expected missing_scope kind: ${envelope.content[0].text}`);
    assert.equal(envParsed.next_action, "request_capability", `expected request_capability action: ${envelope.content[0].text}`);
    pass("failures surface as machine-readable envelopes (kind + next_action)");

    // 16c2. M5 (native approvals): request_capability wait:true long-polls the
    // human decision inline — the approval on disk materializes the grant in
    // the SAME call (no re-request, no continuation).
    const waitPromise = client.callTool({
      name: "scopegate_request_capability",
      arguments: { capability: "fakegit:call:danger4", ttl: "10m", reason: "wait e2e", wait: true, timeout_s: 30 },
    });
    // Wait for the pending approval to land on disk, then approve it.
    let waitApprovalId;
    {
      const pendingPath = path.join(home, "approvals.pending.jsonl");
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline && !waitApprovalId) {
        if (fs.existsSync(pendingPath)) {
          const hit = fs.readFileSync(pendingPath, "utf8")
            .trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
            .find((r) => r.capability === "fakegit:call:danger4" && (!r.status || r.status === "pending"));
          if (hit) waitApprovalId = hit.id;
        }
        if (!waitApprovalId) await new Promise((r) => setTimeout(r, 200));
      }
    }
    assert.ok(waitApprovalId, "wait:true must queue a pending approval");
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({ id: waitApprovalId, decision: "approved", decidedAt: Date.now(), decidedBy: "human:e2e" }) + "\n",
      { mode: 0o600 },
    );
    const waited = parse(await waitPromise);
    assert.equal(waited.granted, true, `wait:true must return the grant inline, got: ${JSON.stringify(waited)}`);
    assert.equal(waited.via, "human_approval", `expected via human_approval: ${JSON.stringify(waited)}`);
    assert.equal(waited.expires_in_seconds, 600, "wait-grant TTL = min(10m requested, 10m rule, 30m max_ttl)");
    pass("request_capability wait:true — approval on disk returns the grant inline (via human_approval)");
    const d4 = await client.callTool({ name: "fakegit__danger4", arguments: {} });
    assert.notEqual(d4.isError, true, `danger4 after the wait-grant failed: ${d4.content[0].text}`);
    assert.ok(
      fs.readFileSync(path.join(home, "audit.jsonl"), "utf8").includes('"approval_waited"'),
      "approval_waited must be audited",
    );

    // 16c3. M6 (when: guards): kimi/* branches auto-approve; main escalates.
    const kimiPush = await client.callTool({ name: "fakegit__branch_push", arguments: { branch: "kimi/feat-x" } });
    assert.notEqual(kimiPush.isError, true, `kimi/* push must auto-approve: ${kimiPush.content[0].text}`);
    assert.match(kimiPush.content[0].text, /pushed kimi\/feat-x/);
    const mainPush = await client.callTool({ name: "fakegit__branch_push", arguments: { branch: "main" } });
    assert.equal(mainPush.isError, true, "main push must escalate, not pass");
    assert.match(mainPush.content[0].text, /scopegate approve/);
    pass("when: guard — branch kimi/* auto-approves, branch main escalates to human approval");

    // 16d. Mejora #3 (policy preflight) + mejora #9 (recall as session memory).
    const canAllow = parse(
      await client.callTool({ name: "scopegate_can_i", arguments: { capability: "fakegit:call:whoami" } }),
    );
    assert.equal(canAllow.decision, "allow", `expected allow: ${JSON.stringify(canAllow)}`);
    assert.ok(canAllow.ttl_ms > 0, "allow must carry the effective ttl_ms");
    assert.ok(canAllow.recommended_next, "preflight must recommend the next step");
    // danger2 is covered by the continuation's live grant (covered branch).
    const canCovered = parse(
      await client.callTool({ name: "scopegate_can_i", arguments: { capability: "fakegit:call:danger2" } }),
    );
    assert.equal(canCovered.decision, "allow", `expected covered allow: ${JSON.stringify(canCovered)}`);
    assert.equal(canCovered.covered_by_existing_grant, true);
    // danger3 is never requested in this run → needs_approval, via local_policy.
    const canApprove = parse(
      await client.callTool({ name: "scopegate_can_i", arguments: { capability: "fakegit:call:danger3" } }),
    );
    assert.equal(canApprove.decision, "needs_approval", `expected needs_approval: ${JSON.stringify(canApprove)}`);
    assert.equal(canApprove.via, "local_policy");
    const canDeny = parse(
      await client.callTool({ name: "scopegate_can_i", arguments: { capability: "stripe:write:*" } }),
    );
    assert.equal(canDeny.decision, "deny", `expected deny: ${JSON.stringify(canDeny)}`);
    assert.equal(canDeny.code, "no_rule");
    // Zero side effects: the preflight must NOT have queued an approval for danger2
    // (the queue file exists from earlier flows, but no new pending line for it).
    const pendingNow = fs.existsSync(path.join(home, "approvals.pending.jsonl"))
      ? fs.readFileSync(path.join(home, "approvals.pending.jsonl"), "utf8")
      : "";
    assert.ok(
      !pendingNow.includes("fakegit:call:danger2") || pendingNow.split("fakegit:call:danger2").length <= 2,
      "preflight must not queue approval requests",
    );
    pass("scopegate_can_i preflights allow/needs_approval/deny with zero side effects");

    const summary = parse(await client.callTool({ name: "scopegate_policy_summary", arguments: {} }));
    assert.ok(summary.auto_approve.includes("fakegit:call:whoami"), `summary auto_approve: ${JSON.stringify(summary)}`);
    assert.ok(summary.requires_approval.includes("fakegit:call:danger2"), `summary requires_approval: ${JSON.stringify(summary)}`);
    assert.ok(summary.deny_globs.includes("aws:*:production"), `summary deny_globs: ${JSON.stringify(summary)}`);
    assert.equal(summary.max_ttl, "30m");
    pass("scopegate_policy_summary digests rules + ceilings for planning");

    const recall = parse(await client.callTool({ name: "scopegate_recall", arguments: {} }));
    assert.equal(recall.agentId, "e2e-agent");
    assert.ok(recall.counts.actions > 0, "recall must see my earlier actions");
    assert.ok(
      recall.recent_actions.some((a) => a.kind === "intent_executed" && a.tool === "fakegit__danger2"),
      `recall must include the continuation execution: ${JSON.stringify(recall.recent_actions.slice(-5))}`,
    );
    assert.ok(
      recall.recent_actions.some((a) => a.kind === "tool_call" && a.tool === "fakegit__whoami"),
      "recall must include direct tool calls",
    );
    assert.ok(Array.isArray(recall.active_grants) && Array.isArray(recall.writes));
    pass("scopegate_recall returns my actions, writes, grants and pending approvals");

    // 16e. Mejora #1 (task leases) + mejora #6 (idempotent writes).
    const leaseRes = parse(
      await client.callTool({
        name: "scopegate_open_task_lease",
        arguments: { goal: "e2e long task", upstreams: ["fakegit"], max_total: "1h", max_writes: 3 },
      }),
    );
    assert.ok(leaseRes.lease_id, `expected lease_id: ${JSON.stringify(leaseRes)}`);
    assert.equal(leaseRes.total_ms, 3600_000);
    assert.equal(leaseRes.max_writes, 3);
    const leaseId = leaseRes.lease_id;
    pass("scopegate_open_task_lease opens a lease with the double budget");

    // Lease binding applies to NEW grants (fakegit:call:leased is fresh here).
    const bound = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:leased", ttl: "10m", reason: "lease-bound", lease_id: leaseId },
      }),
    );
    assert.equal(bound.granted, true, `expected grant: ${JSON.stringify(bound)}`);
    assert.equal(bound.lease_id, leaseId);
    assert.equal(bound.renewable, true);
    pass("lease-bound request issues a grant carrying lease_id + renewable");

    const capsForLease = parse(await client.callTool({ name: "scopegate_list_capabilities", arguments: {} }));
    const leaseGrant = capsForLease.active_grants.find((g) => g.lease_id === leaseId);
    assert.ok(leaseGrant, `grant must be bound to the lease: ${JSON.stringify(capsForLease.active_grants)}`);
    assert.ok(capsForLease.leases.some((l) => l.lease_id === leaseId && l.status === "open"));
    const renewed = parse(
      await client.callTool({ name: "scopegate_renew_capability", arguments: { grant_id: leaseGrant.id } }),
    );
    assert.equal(renewed.renewed, true, `expected renew: ${JSON.stringify(renewed)}`);
    assert.equal(renewed.lease_id, leaseId);
    assert.ok(renewed.expires_in_seconds > 0);
    pass("scopegate_renew_capability slides the grant expiry while the lease lives");

    // Out-of-scope lease usage is refused fail-closed.
    const outOfScope = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "jwtupstream:call:echo_auth", ttl: "5m", reason: "out of scope", lease_id: leaseId },
      }),
    );
    assert.equal(outOfScope.granted, false, `expected refusal: ${JSON.stringify(outOfScope)}`);
    assert.equal(outOfScope.code, "lease_error");
    assert.match(outOfScope.reason, /out of scope/);
    pass("out-of-scope lease usage is refused (lease_error)");

    // Idempotency: the second identical call replays; a different payload with
    // the same key is an explicit conflict.
    const idemArgs = { _sg_idempotency_key: "e2e-idem-1" };
    const w1 = await client.callTool({ name: "fakegit__whoami", arguments: idemArgs });
    assert.notEqual(w1.isError, true, `first call failed: ${w1.content[0].text}`);
    const w2 = await client.callTool({ name: "fakegit__whoami", arguments: idemArgs });
    assert.deepEqual(JSON.parse(JSON.stringify(w2)), JSON.parse(JSON.stringify(w1)));
    const w3 = await client.callTool({ name: "fakegit__whoami", arguments: { _sg_idempotency_key: "e2e-idem-1", other: 1 } });
    assert.equal(w3.isError, true, "same key + different args must conflict");
    assert.match(w3.content[0].text, /idempotency_key_conflict/);
    pass("idempotency: same key+args replays, same key+different args conflicts");

    // 16f. Mejora #7 (result handles) + mejora #4 (capability plan).
    // fakegit__big_report returns >1KB; limits.max_inline_bytes is 1024.
    // An auto rule does not exist for big_report → implicit request fails… so
    // grant it first via the leased fakegit:call:* coverage? No: request it.
    const bigGrant = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:big_report", ttl: "5m", reason: "result handles e2e" },
      }),
    );
    // big_report has no explicit rule; the fakegit:call:* glob… none either.
    // The e2e policy auto-approves only specific tools — request must deny.
    // Use pii_echo instead for the oversized path: it's auto-approved.
    void bigGrant;
    const big = parse(await client.callTool({ name: "fakegit__big_report", arguments: {} }));
    assert.equal(big.isError ?? false, false);
    assert.equal(big.truncated, true, `expected truncation: ${JSON.stringify(big).slice(0, 200)}`);
    assert.ok(big.result_ref, "truncation must carry result_ref");
    assert.ok(big.stats.bytes > 1024, `stats must report the real size: ${JSON.stringify(big.stats)}`);
    const got = parse(
      await client.callTool({
        name: "scopegate_result_get",
        arguments: { ref: big.result_ref, path: "items.0.title" },
      }),
    );
    assert.equal(got.found, true, `expected found: ${JSON.stringify(got)}`);
    assert.match(got.value, /item-0/);
    const grepd = parse(
      await client.callTool({
        name: "scopegate_result_grep",
        arguments: { ref: big.result_ref, pattern: "item-42" },
      }),
    );
    assert.ok(grepd.count >= 1, `expected hits: ${JSON.stringify(grepd)}`);
    const missed = parse(
      await client.callTool({
        name: "scopegate_result_get",
        arguments: { ref: big.result_ref, path: "items.999.title" },
      }),
    );
    assert.equal(missed.found, false);
    pass("oversized payloads truncate to result_ref; get/grep page through them");

    // Capability plan: auto (pii_echo), needs_approval (danger3), hard deny (aws prod).
    const plan = parse(
      await client.callTool({
        name: "scopegate_request_plan",
        arguments: {
          goal: "e2e plan: redact read + guarded write + denied prod",
          capabilities: [
            { capability: "fakegit:call:pii_echo" },
            { capability: "fakegit:call:danger3" },
            { capability: "aws:write:production" },
          ],
        },
      }),
    );
    assert.ok(
      plan.auto.some((a) => a.capability === "fakegit:call:pii_echo" && a.granted),
      `pii_echo must auto-grant: ${JSON.stringify(plan)}`,
    );
    assert.ok(
      plan.auto.some((a) => a.capability === "aws:write:production" && !a.granted && a.code === "ceiling_blocked"),
      `aws prod must be denied: ${JSON.stringify(plan.auto)}`,
    );
    assert.equal(plan.pending.items.length, 1);
    assert.equal(plan.pending.items[0].capability, "fakegit:call:danger3");
    pass("request_plan partitions auto/bundle/deny into ONE aggregated approval");

    // Approve the bundle → the next request materializes the danger3 grant.
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({ id: plan.pending.approvalId, decision: "approved", decidedAt: Date.now(), decidedBy: "human:e2e" }) + "\n",
      { mode: 0o600 },
    );
    await client.callTool({
      name: "scopegate_request_capability",
      arguments: { capability: "fakegit:call:pii_echo", ttl: "5m", reason: "trigger materialization" },
    });
    const capsAfterPlan = parse(await client.callTool({ name: "scopegate_list_capabilities", arguments: {} }));
    assert.ok(
      capsAfterPlan.active_grants.some((g) => g.capability === "fakegit:call:danger3"),
      `bundled grant must materialize: ${JSON.stringify(capsAfterPlan.active_grants)}`,
    );
    pass("one approval issues every bundled capability at once");

    // 16g. Mejora #5 (delegation) + #10 (taint) + quick win (hot-reload).
    // Delegation: the whoami grant delegates attenuated to a subagent.
    const capsForDeleg = parse(await client.callTool({ name: "scopegate_list_capabilities", arguments: {} }));
    const parentGrant = capsForDeleg.active_grants.find((g) => g.capability === "fakegit:call:whoami");
    assert.ok(parentGrant, "parent grant must exist");
    const delegated = parse(
      await client.callTool({
        name: "scopegate_delegate",
        arguments: {
          grant_id: parentGrant.id,
          child_agent_id: "e2e-subagent",
          scope_subset: "fakegit:call:whoami",
          ttl: "5m",
        },
      }),
    );
    assert.equal(delegated.delegated, true, `expected delegation: ${JSON.stringify(delegated)}`);
    assert.equal(delegated.child_agent_id, "e2e-subagent");
    // Widening is refused fail-closed.
    const widen = await client.callTool({
      name: "scopegate_delegate",
      arguments: {
        grant_id: parentGrant.id,
        child_agent_id: "e2e-subagent",
        scope_subset: "fakegit:call:danger",
      },
    });
    assert.equal(widen.isError, true, "widening delegation must be refused");
    assert.match(widen.content[0].text, /Attenuation violation/);
    // The child grant exists with the parent chain; revoking the parent cascades.
    const grantsFile = JSON.parse(fs.readFileSync(path.join(home, "grants.json"), "utf8"));
    const childEntry = grantsFile.grants.find((g) => g.agentId === "e2e-subagent");
    assert.ok(childEntry, "child grant must persist");
    assert.equal(childEntry.parentGrantId, parentGrant.id);
    pass("delegation: attenuated child grant + widening refused + parent chain recorded");

    // Taint: hot-add the leaky rule (the response must EXECUTE to be scanned),
    // then the injected payload marks the session and a cross-upstream write degrades.
    const taintDoc = structuredClone(policiesDoc);
    taintDoc.agents["e2e-agent"].capabilities.push({ match: "fakegit:call:leaky", auto_approve: true, ttl: "5m" });
    fs.writeFileSync(path.join(home, "policies.yaml"), JSON.stringify(taintDoc, null, 2));
    let leakyOk = false;
    const taintDeadline = Date.now() + 3000;
    while (Date.now() < taintDeadline && !leakyOk) {
      const r = await client.callTool({ name: "fakegit__leaky", arguments: {} });
      leakyOk = !r.isError;
      if (!leakyOk) await new Promise((res) => setTimeout(res, 150));
    }
    assert.ok(leakyOk, "leaky must execute after the hot-added rule (response gets scanned)");
    const taintedReq = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "huly:write:issue", ttl: "5m", reason: "exfil-shaped write after tainted content" },
      }),
    );
    assert.equal(taintedReq.status, "pending_human_approval",
      `cross-upstream write while tainted must degrade: ${JSON.stringify(taintedReq)}`);
    const auditRawTaint = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.ok(auditRawTaint.includes('"taint_detected"'), "taint_detected must be audited");
    assert.ok(auditRawTaint.includes('"via":"taint_guard"'), "the degradation must carry via taint_guard");
    pass("taint: injected response marks the session; cross-upstream write degrades to approval");

    // Quick win: a NEW secret deposit hot-reloads — the gateway keeps serving
    // (stale connections are dropped and rebuilt on the next call).
    const add2 = spawnSync(process.execPath, [CLI, "secret", "add", "fake_token2"], {
      input: "anothersecret456\n",
      env,
      encoding: "utf8",
    });
    assert.equal(add2.status, 0, `second secret add failed: ${add2.stderr || add2.stdout}`);
    const afterAdd = await client.callTool({ name: "fakegit__whoami", arguments: {} });
    assert.notEqual(afterAdd.isError, true, `call after vault mutation failed: ${afterAdd.content[0].text}`);
    assert.match(afterAdd.content[0].text, /authenticated=true/);
    pass("hot-reload: secret add while running drops stale connections; the gateway keeps serving");

    // 16h. M1 (composite auth) + M8 (env hygiene). The suite booted with
    // fakegit on composite auth (static ref + jwt mint) and decoys in env.
    const whoamiComp = await client.callTool({ name: "fakegit__whoami", arguments: {} });
    assert.notEqual(whoamiComp.isError, true, `composite whoami failed: ${whoamiComp.content[0].text}`);
    assert.match(
      whoamiComp.content[0].text,
      /authenticated=true/,
      `the vault ref must win over the WRONG-DECOY in process env: ${whoamiComp.content[0].text}`,
    );
    pass("M1: composite auth fuses static ref + mint; vault value wins over the decoy env");
    const probeDecoy = await client.callTool({ name: "fakegit__env_probe", arguments: { name: "DECOY_SECRET" } });
    assert.match(probeDecoy.content[0].text, /DECOY_SECRET=absent/, `decoy leaked into the child: ${probeDecoy.content[0].text}`);
    const probeToken = await client.callTool({ name: "fakegit__env_probe", arguments: { name: "FAKE_TOKEN" } });
    assert.match(probeToken.content[0].text, /FAKE_TOKEN=present/, `vault ref not injected: ${probeToken.content[0].text}`);
    const probeMinted = await client.callTool({ name: "fakegit__env_probe", arguments: { name: "FAKEGIT_ACCESS_TOKEN" } });
    assert.match(
      probeMinted.content[0].text,
      /FAKEGIT_ACCESS_TOKEN=present/,
      `jwt mint not injected as <NAME>_ACCESS_TOKEN: ${probeMinted.content[0].text}`,
    );
    pass("M8: gateway secrets never reach the child (scrub) — only vault refs and minted env");

    // 17. redact: [pii] masks email/card in the proxied tool RESPONSE.
    const pii = await client.callTool({ name: "fakegit__pii_echo", arguments: {} });
    assert.notEqual(pii.isError, true, `pii_echo call failed: ${pii.content[0].text}`);
    const piiText = pii.content[0].text;
    assert.ok(!piiText.includes("alice@example.com"), `email not redacted: ${piiText}`);
    assert.ok(!piiText.includes("4242424242424242"), `card not redacted: ${piiText}`);
    assert.match(piiText, /\[REDACTED:email\]/);
    assert.match(piiText, /\[REDACTED:card\]/);
    pass("redact: [pii] masks email and Luhn card in the proxied response");

    // 18. Hot-reload: a policies.yaml edit takes effect <2s; invalid YAML
    // keeps the last-good set (and is audited, asserted in section 19).
    const hotDoc = structuredClone(policiesDoc);
    hotDoc.agents["e2e-agent"].capabilities.push({ match: "fakegit:call:hot*", auto_approve: true, ttl: "3m" });
    fs.writeFileSync(path.join(home, "policies.yaml"), JSON.stringify(hotDoc, null, 2));
    let hotGranted = false;
    const hotDeadline = Date.now() + 2000;
    while (Date.now() < hotDeadline && !hotGranted) {
      const r = parse(
        await client.callTool({
          name: "scopegate_request_capability",
          arguments: { capability: "fakegit:call:hot", ttl: "1m", reason: "hot-reload probe" },
        }),
      );
      hotGranted = r.granted === true;
      if (!hotGranted) await new Promise((r2) => setTimeout(r2, 150));
    }
    assert.ok(hotGranted, "policies.yaml edit was not picked up within 2s");
    // Break the file: the last-good set (which now includes the hot* rule)
    // must keep serving — probe with a NEW capability so no existing grant
    // can mask the policy evaluation.
    fs.writeFileSync(path.join(home, "policies.yaml"), "version: 1\nagents: {broken: [");
    await new Promise((r) => setTimeout(r, 800)); // debounce (250ms) + margin
    const lastGood = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:hot2", ttl: "1m", reason: "last-good probe" },
      }),
    );
    assert.equal(lastGood.granted, true, `last-good policy set must survive invalid YAML, got: ${JSON.stringify(lastGood)}`);
    // Restore a valid file so the gateway does not linger on the error path.
    fs.writeFileSync(path.join(home, "policies.yaml"), JSON.stringify(hotDoc, null, 2));
    pass("hot-reload picks up edits <2s and keeps last-good (+ audit) on invalid YAML");

    // 19. EPIC-04 audit trail: every lifecycle event landed, PII never did.
    const auditRaw2 = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    for (const kind of [
      '"ceiling_blocked"',
      '"approval_requested"',
      '"approval_approved"',
      '"grant_issued"',
      '"redaction_applied"',
      '"policy_reload_error"',
    ]) {
      assert.ok(auditRaw2.includes(kind), `audit log missing ${kind} events`);
    }
    assert.ok(!auditRaw2.includes("alice@example.com"), "audit log leaked PII content");
    assert.ok(!auditRaw2.includes("4242424242424242"), "audit log leaked PII content");
    assert.match(auditRaw2, /"redaction_applied".*"counts"/, "redaction audit must carry counts only");
    pass("audit records ceiling/approval/grant/redaction/reload events — counts only, never PII");

    /* ------------------------------------------------------------------ */
    /* EPIC-08 — human approval via the real CLI (child process)           */
    /* ------------------------------------------------------------------ */

    // 20. Escalation → pending → `scopegate approve <id>` as a child process
    // (no TTY, so SCOPEGATE_APPROVAL_TOKEN supplies the human origin) → the
    // next request is granted with the SHORTENED TTL → audit records the
    // approval with its token origin. Also: no approval tool is exposed to
    // the agent, and the CLI refuses to decide without a human origin.
    assert.ok(
      !names.some((n) => /approve|deny/i.test(n)),
      `agent-facing tools must never include approval tools (got: ${names.join(", ")})`,
    );
    // Rule for this section (added via hot-reload, policies.yaml untouched by hand elsewhere).
    const cliDoc = structuredClone(hotDoc);
    cliDoc.agents["e2e-agent"].capabilities.push({ match: "fakegit:call:danger_cli", require: "human_approval", ttl: "10m" });
    fs.writeFileSync(path.join(home, "policies.yaml"), JSON.stringify(cliDoc, null, 2));
    let cliReq = null;
    const cliDeadline = Date.now() + 3000;
    while (Date.now() < cliDeadline && !cliReq) {
      const r = parse(
        await client.callTool({
          name: "scopegate_request_capability",
          arguments: { capability: "fakegit:call:danger_cli", ttl: "10m", reason: "e2e EPIC-08" },
        }),
      );
      if (r.status === "pending_human_approval") cliReq = r;
      else await new Promise((r2) => setTimeout(r2, 150));
    }
    assert.ok(cliReq, "escalation to pending_human_approval did not happen within 3s");
    assert.ok(cliReq.approval_id, "pending response must carry approval_id");

    // The guard: no TTY (spawned child) and no token → refused, actionable.
    const refused = spawnSync(process.execPath, [CLI, "approve", cliReq.approval_id], {
      env,
      encoding: "utf8",
    });
    assert.notEqual(refused.status, 0, "approve without TTY/token must fail");
    assert.match(refused.stderr, /human-only/, `guard error must be actionable: ${refused.stderr}`);

    // The human reviews the queue: the pending request is listed.
    const listed = spawnSync(process.execPath, [CLI, "approvals", "list"], { env, encoding: "utf8" });
    assert.equal(listed.status, 0, `approvals list failed: ${listed.stderr}`);
    assert.ok(listed.stdout.includes(cliReq.approval_id), `approvals list must show the request: ${listed.stdout}`);

    // The human approves via the real CLI, shortening the TTL to 5m.
    const approved = spawnSync(
      process.execPath,
      [CLI, "approve", cliReq.approval_id, "--ttl", "5m"],
      { env: { ...env, SCOPEGATE_APPROVAL_TOKEN: "e2e-human-token" }, encoding: "utf8" },
    );
    assert.equal(approved.status, 0, `approve failed: ${approved.stderr || approved.stdout}`);
    assert.match(approved.stdout, /APPROVED/, `approve must confirm: ${approved.stdout}`);

    // …and the decided request now shows as APPROVED in the full listing.
    const listedAll = spawnSync(process.execPath, [CLI, "approvals", "list", "--all"], { env, encoding: "utf8" });
    assert.equal(listedAll.status, 0, `approvals list --all failed: ${listedAll.stderr}`);
    assert.match(listedAll.stdout, /\[APPROVED\]/, `decided request must show as APPROVED: ${listedAll.stdout}`);

    // Next tool call passes: one-shot grant with TTL shortened to 5m (300s).
    const cliGrant = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability: "fakegit:call:danger_cli", ttl: "10m", reason: "e2e EPIC-08" },
      }),
    );
    assert.equal(cliGrant.granted, true, `expected grant after CLI approval, got: ${JSON.stringify(cliGrant)}`);
    assert.equal(cliGrant.expires_in_seconds, 300, "approve --ttl 5m must shorten the one-shot grant to 300s");

    const auditRaw3 = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    assert.match(
      auditRaw3,
      new RegExp(`"approval_approved"[^\\n]*"human:cli:token"`),
      "audit must record approval_approved with the CLI token origin",
    );
    pass("human approval via real CLI: guard refuses agents, approve --ttl shortens, grant passes, audit carries origin");
  } finally {
    await client.close().catch(() => {});
    httpUpstream.child.kill();
    fs.rmSync(home, { recursive: true, force: true });
  }

  console.log("\ne2e: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e FAILED: ${e.message}`);
    process.exit(1);
  });
