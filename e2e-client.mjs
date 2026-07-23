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
  const env = { ...process.env, SCOPEGATE_HOME: home, SCOPEGATE_AGENT_ID: "e2e-agent" };
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
              auth: { type: "env", env: { FAKE_TOKEN: "fake_token" } },
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
