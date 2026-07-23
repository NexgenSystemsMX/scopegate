#!/usr/bin/env node
/**
 * EPIC-10 end-to-end — ScopeGate Cloud sync (gateway side) against a cloud
 * management-plane server, orchestrating BOTH sides from one script:
 *
 *   cloud (server) ← enroll/policy/audit/revocations → gateway (dist/cli.js start)
 *
 * Cloud side (two interchangeable backends):
 *   1. REAL: `node dist/cli.js cloud serve --port <n> --home <dir>` (AGENTE
 *      CLOUD-CORE's server; the frozen contract prints
 *      "SCOPEGATE_CLOUD_LISTENING port=<n>"). Used whenever the CLI command
 *      exists and boots.
 *   2. EMBEDDED REFERENCE (fallback): a contract-faithful in-process server
 *      built below, used while CLOUD-CORE's CLI has not landed yet. It
 *      implements exactly the frozen wire contract (real Ed25519 keys,
 *      signed policies, batch-signature verification, dedup by agentId+seq).
 *   Force with SCOPEGATE_CLOUD_E2E_SERVER=cli|embedded (default: auto).
 *
 * Enroll: the `scopegate cloud enroll` CLI command belongs to CLOUD-CORE, so
 * this e2e enrolls the gateway through the frozen API (POST /v1/enroll) and
 * writes ~/.scopegate/cloud.json directly — the exact same state the CLI
 * command would produce (documented in the assignment).
 *
 * Assertions:
 *   (a) a restrictive team policy is applied (team denies / is silent on
 *       what local allows → denied; TTL = min) — signature-verified sync;
 *   (b) gateway audit events show up in GET /v1/admin/audit;
 *   (c) a fleet revocation denies the NEXT gateway call in < 30 s;
 *   (d) with the cloud process KILLED the gateway keeps serving (local-first,
 *       local policy + signed cache) and re-engages when the cloud returns.
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 * Prereq: `npm run build` (needs dist/cli.js + dist/cloud/client/*).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { canonicalTeamPolicyPayload } from "./dist/cloud/client/policy-sync.js";
import { canonicalAuditBatch } from "./dist/cloud/client/audit-exporter.js";
import { verifyCanonical, fingerprintOf } from "./dist/audit/identity.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");
const FAKE_UPSTREAM = path.join(ROOT, "fake-upstream.mjs");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "dev-admin-token";

const watchdog = setTimeout(() => {
  console.error("e2e-cloud FAILED: global timeout (120s)");
  process.exit(2);
}, 120_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/* ------------------------------------------------------------------------ */
/* Embedded reference cloud (fallback while CLOUD-CORE's CLI lands)          */
/* ------------------------------------------------------------------------ */

function createEmbeddedCloudState() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    teams: new Map(), // teamId -> { enrollToken, policyVersion, policyYaml, policySignedAt, revocations[], agents: Map(agentId -> {fingerprint, secret}), events: Map("agentId:seq" -> event) }
    nextTeam: 0,
  };
}

function startEmbeddedCloud(state, port) {
  const json = (res, status, obj) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  const server = http.createServer((req, res) => {
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      let body = {};
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        /* keep {} */
      }
      const teamId = u.searchParams.get("teamId") ?? body.teamId;
      const team = state.teams.get(teamId);

      /* ------------------------- gateway-facing API ---------------------- */
      if (req.method === "POST" && u.pathname === "/v1/enroll") {
        for (const [tid, t] of state.teams) {
          if (t.enrollToken === body.enrollToken) {
            const secret = "sec-" + crypto.randomBytes(8).toString("hex");
            t.agents.set(String(body.agentId), {
              fingerprint: String(body.pubkeyFingerprint),
              secret,
            });
            return json(res, 200, { agentSecret: secret, teamId: tid, cloudPubkey: state.pub });
          }
        }
        return json(res, 403, { error: "invalid enroll token" });
      }
      if (req.method === "GET" && u.pathname === "/v1/policy") {
        if (!team) return json(res, 404, { error: "unknown team" });
        if (team.policyVersion === 0) return json(res, 404, { error: "no policy yet" });
        const payload = {
          teamId,
          version: team.policyVersion,
          yaml: team.policyYaml,
          signedAt: team.policySignedAt,
        };
        return json(res, 200, {
          ...payload,
          signature:
            "ed25519:" +
            crypto
              .sign(null, Buffer.from(canonicalTeamPolicyPayload(payload), "utf8"), state.priv)
              .toString("base64"),
        });
      }
      if (req.method === "POST" && u.pathname === "/v1/audit/batch") {
        const events = Array.isArray(body.events) ? body.events : [];
        const agentId = String(body.agentId ?? "");
        // Contract-faithful verification: batch signature must verify with
        // the transported pubkey, whose fingerprint must be the enrolled one.
        let verified = false;
        let stored = null;
        for (const t of state.teams.values()) {
          const a = t.agents.get(agentId);
          if (a) stored = t.events;
          if (
            a &&
            typeof body.pubkey === "string" &&
            fingerprintOf(body.pubkey) === a.fingerprint &&
            verifyCanonical(body.pubkey, canonicalAuditBatch({ agentId, events }), String(body.signature))
          ) {
            verified = true;
          }
        }
        if (!verified || !stored) return json(res, 200, { accepted: 0, rejected: events.length });
        for (const e of events) stored.set(`${agentId}:${e.seq}`, e);
        return json(res, 200, { accepted: events.length, rejected: 0 });
      }
      if (req.method === "GET" && u.pathname === "/v1/revocations") {
        if (!team) return json(res, 404, { error: "unknown team" });
        const since = u.searchParams.get("since");
        return json(res, 200, {
          revocations: team.revocations.filter((r) => !since || String(r.revokedAt) > since),
        });
      }

      /* ------------------------------ admin ------------------------------ */
      const authz = req.headers.authorization ?? "";
      if (authz !== `Bearer ${ADMIN_TOKEN}`) return json(res, 401, { error: "admin auth required" });
      if (req.method === "POST" && u.pathname === "/v1/admin/teams") {
        state.nextTeam += 1;
        const tid = `team-${state.nextTeam}`;
        state.teams.set(tid, {
          enrollToken: "tok-" + crypto.randomBytes(8).toString("hex"),
          policyVersion: 0,
          policyYaml: "",
          policySignedAt: "",
          revocations: [],
          agents: new Map(),
          events: new Map(),
        });
        const t = state.teams.get(tid);
        return json(res, 200, { teamId: tid, enrollToken: t.enrollToken });
      }
      if (req.method === "PUT" && u.pathname === "/v1/admin/policy") {
        if (!team) return json(res, 404, { error: "unknown team" });
        team.policyVersion += 1;
        team.policyYaml = String(body.yaml ?? "");
        team.policySignedAt = new Date().toISOString();
        return json(res, 200, { version: team.policyVersion, signedAt: team.policySignedAt });
      }
      if (req.method === "POST" && u.pathname === "/v1/admin/revocations") {
        if (!team) return json(res, 404, { error: "unknown team" });
        team.revocations.push({
          agentId: String(body.agentId),
          reason: String(body.reason ?? "revoked by admin"),
          revokedAt: new Date().toISOString(),
        });
        return json(res, 200, { ok: true });
      }
      if (req.method === "GET" && u.pathname === "/v1/admin/audit") {
        if (!team) return json(res, 404, { error: "unknown team" });
        return json(res, 200, { events: [...team.events.values()] });
      }
      return json(res, 404, { error: "not_found" });
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

/* ------------------------------------------------------------------------ */
/* Cloud backend launcher: real CLI when available, embedded otherwise       */
/* ------------------------------------------------------------------------ */

async function freePort() {
  const srv = http.createServer();
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const p = srv.address().port;
  await new Promise((r) => srv.close(r));
  return p;
}

function startCliCloud(port, cloudHome) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "cloud", "serve", "--port", String(port), "--home", cloudHome], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buf = "";
    let done = false;
    const finish = (v) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        resolve(v);
      }
    };
    child.stdout.on("data", (d) => {
      buf += d.toString();
      const m = /SCOPEGATE_CLOUD_LISTENING port=(\d+)/.exec(buf);
      if (m) finish({ kind: "cli", child, port: Number(m[1]) });
    });
    child.on("error", () => finish(null));
    child.on("exit", () => finish(null)); // e.g. "unknown command" (CLI not landed yet)
    const timer = setTimeout(() => {
      child.kill();
      finish(null);
    }, 10_000);
  });
}

/* ------------------------------------------------------------------------ */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------ */

async function adminFetch(base, method, p, body) {
  const res = await fetch(`${base}${p}`, {
    method,
    headers: { "content-type": "application/json", authorization: `Bearer ${ADMIN_TOKEN}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    /* tolerate empty/non-JSON */
  }
  assert.ok(res.ok, `admin ${method} ${p} failed (HTTP ${res.status}): ${text.slice(0, 200)}`);
  return parsed;
}

async function waitFor(desc, fn, timeoutMs = 10_000, stepMs = 200) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  throw new Error(`timeout waiting for: ${desc}`);
}

/* ------------------------------------------------------------------------ */
/* Main                                                                      */
/* ------------------------------------------------------------------------ */

async function main() {
  assert.ok(fs.existsSync(CLI), `dist/cli.js not found — run \`npm run build\` first`);

  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-cloud-"));
  const cloudHome = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-e2e-cloudhome-"));
  const env = {
    ...process.env,
    SCOPEGATE_HOME: home,
    SCOPEGATE_AGENT_ID: "e2e-agent",
    // Fast sync loops so the e2e observes cloud effects in well under 30 s.
    SCOPEGATE_CLOUD_SYNC_INTERVAL_MS: "300",
    SCOPEGATE_CLOUD_AUDIT_INTERVAL_MS: "300",
    SCOPEGATE_CLOUD_REVOCATION_INTERVAL_MS: "300",
  };
  console.log(`e2e-cloud home: ${home}`);

  /* ----------------------------- cloud side ----------------------------- */
  const port = await freePort();
  const mode = (process.env.SCOPEGATE_CLOUD_E2E_SERVER ?? "auto").toLowerCase();
  let backend = null;
  if (mode !== "embedded") {
    backend = await startCliCloud(port, cloudHome);
    if (!backend && mode === "cli") {
      throw new Error("SCOPEGATE_CLOUD_E2E_SERVER=cli but `cloud serve` did not come up");
    }
  }
  const embeddedState = createEmbeddedCloudState(); // persists across restarts
  let embeddedServer = null;
  if (backend) {
    pass(`cloud up via REAL CLI (dist/cli.js cloud serve, port ${backend.port})`);
  } else {
    embeddedServer = await startEmbeddedCloud(embeddedState, port);
    console.log(
      "note: `scopegate cloud serve` not available yet (AGENTE CLOUD-CORE in flight) — " +
        "using the embedded contract-faithful reference server",
    );
    pass(`cloud up via embedded reference server (frozen contract, port ${port})`);
  }
  const cloudBase = `http://127.0.0.1:${port}`;

  const stopCloud = async () => {
    if (backend?.kind === "cli") backend.child.kill();
    if (embeddedServer) await new Promise((r) => embeddedServer.close(r));
    embeddedServer = null;
  };
  const restartCloud = async () => {
    if (backend?.kind === "cli") {
      backend = await startCliCloud(port, cloudHome);
      assert.ok(backend, "cloud CLI did not come back up");
    } else {
      embeddedServer = await startEmbeddedCloud(embeddedState, port);
    }
  };

  const client = new Client({ name: "e2e-cloud-harness", version: "1.0.0" }, { capabilities: {} });
  try {
    /* ------------------------- team + enroll ---------------------------- */
    const team = await adminFetch(cloudBase, "POST", "/v1/admin/teams", { name: "e2e" });
    const teamId = team.teamId ?? team.id;
    const enrollToken = team.enrollToken ?? team.enroll_token ?? team.token;
    assert.ok(teamId && enrollToken, `admin teams response lacks teamId/enrollToken: ${JSON.stringify(team)}`);
    pass(`team created via admin API (${teamId})`);

    // Enroll through the frozen API + write cloud.json directly (the
    // `scopegate cloud enroll` CLI belongs to AGENTE CLOUD-CORE; this e2e
    // produces exactly the same state). The identity is provisioned in a
    // CHILD process with SCOPEGATE_HOME set — the e2e process itself must
    // never bind src/config paths (they resolve at module load).
    const provision = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `import { createIdentity } from ${JSON.stringify(pathToFileURL(path.join(ROOT, "dist", "audit", "identity.js")).href)}; createIdentity();`,
      ],
      { env, encoding: "utf8" },
    );
    assert.equal(provision.status, 0, `identity provisioning failed: ${provision.stderr}`);
    const identity = JSON.parse(fs.readFileSync(path.join(home, "identity.json"), "utf8"));
    // Deposit the upstream secret through the human path (CLI + piped stdin),
    // exactly like e2e-client.mjs — the gateway child reads it from the vault.
    const addSecret = spawnSync(process.execPath, [CLI, "secret", "add", "fake_token"], {
      input: "supersecret123\n",
      env,
      encoding: "utf8",
    });
    assert.equal(addSecret.status, 0, `secret add failed: ${addSecret.stderr || addSecret.stdout}`);
    const enrollRes = await fetch(`${cloudBase}/v1/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: "e2e-agent",
        enrollToken,
        pubkeyFingerprint: identity.fingerprint,
        // Additive (reconciled contract): the server stores the PEM to
        // verify audit batch signatures at ingest.
        pubkey: identity.publicKey,
      }),
    });
    assert.ok(enrollRes.ok, `enroll failed (HTTP ${enrollRes.status})`);
    const enrolled = await enrollRes.json();
    assert.ok(enrolled.agentSecret && enrolled.teamId && enrolled.cloudPubkey, `bad enroll response: ${JSON.stringify(enrolled)}`);
    fs.writeFileSync(
      path.join(home, "cloud.json"),
      JSON.stringify(
        {
          url: cloudBase,
          agentId: "e2e-agent",
          teamId: enrolled.teamId,
          agentSecret: enrolled.agentSecret,
          cloudPubkey: enrolled.cloudPubkey,
          enrolledAt: new Date().toISOString(),
        },
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    );
    pass("gateway enrolled via POST /v1/enroll + cloud.json written (CLI enroll is CLOUD-CORE's)");

    /* ------------------------- gateway config --------------------------- */
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
          ],
        },
        null,
        2,
      ),
    );
    // Local policy: allows whoami/danger/pii_echo (10m). The team policy will
    // restrict all three in different ways. The rate limit ceiling is lifted
    // because this e2e polls request_capability while waiting for sync loops.
    fs.writeFileSync(
      path.join(home, "policies.yaml"),
      JSON.stringify(
        {
          version: 1,
          limits: { rate_limit: "500/m" },
          agents: {
            "e2e-agent": {
              capabilities: [
                { match: "fakegit:call:whoami", auto_approve: true, ttl: "10m" },
                { match: "fakegit:call:danger", auto_approve: true, ttl: "10m" },
                { match: "fakegit:call:pii_echo", auto_approve: true, ttl: "10m" },
              ],
            },
          },
        },
        null,
        2,
      ),
    );

    await client.connect(
      new StdioClientTransport({ command: process.execPath, args: [CLI, "start"], env }),
    );
    pass("gateway started (enrolled — cloud sync loops active)");

    // Tolerant probe: a policy decision comes back as a JSON payload, but a
    // fail-closed GATE denial (honeytoken/cloud revocation) is an MCP-level
    // isError with plain text. Both shapes are normalized here.
    const requestCap = async (capability, ttl) => {
      const raw = await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability, ...(ttl ? { ttl } : {}), reason: "e2e-cloud" },
      });
      const text = raw.content?.[0]?.text ?? "";
      if (raw.isError) return { isError: true, granted: false, text };
      try {
        return { ...JSON.parse(text), text };
      } catch {
        return { granted: false, text };
      }
    };

    // Baseline BEFORE any team policy exists: local policy alone decides.
    const baseDanger = await requestCap("fakegit:call:danger", "10m");
    assert.equal(baseDanger.granted, true, `baseline danger should be locally granted: ${JSON.stringify(baseDanger)}`);
    pass("baseline: without a team policy the local policy decides (danger granted)");

    /* ------------------- (a) restrictive team policy --------------------- */
    const teamPolicyV1 = {
      version: 1,
      limits: { deny: ["fakegit:call:danger"] },
      agents: {
        "e2e-agent": {
          capabilities: [{ match: "fakegit:call:whoami", auto_approve: true, ttl: "5m" }],
        },
      },
    };
    await adminFetch(cloudBase, "PUT", "/v1/admin/policy", {
      teamId,
      yaml: JSON.stringify(teamPolicyV1),
    });
    // Wait for the signed sync to land: danger flips from granted to denied.
    const deniedDanger = await waitFor("team policy sync (danger denied)", async () => {
      const r = await requestCap("fakegit:call:danger", "10m");
      return r.granted === false ? r : null;
    });
    assert.equal(deniedDanger.code, "ceiling_blocked", `expected team ceiling_blocked: ${JSON.stringify(deniedDanger)}`);
    assert.match(deniedDanger.reason, /\[team policy\]/, `team provenance missing: ${deniedDanger.reason}`);
    const whoami = await requestCap("fakegit:call:whoami", "1h");
    assert.equal(whoami.granted, true, `whoami should survive: ${JSON.stringify(whoami)}`);
    assert.ok(whoami.expires_in_seconds <= 300, `TTL must be min(local 10m, team 5m) → ≤300s, got ${whoami.expires_in_seconds}`);
    const silent = await requestCap("fakegit:call:pii_echo", "10m");
    assert.equal(silent.granted, false, `team silence must deny: ${JSON.stringify(silent)}`);
    assert.equal(silent.code, "no_rule", `expected team no_rule: ${JSON.stringify(silent)}`);
    assert.match(silent.reason, /\[team policy\]/);
    pass("(a) signed team policy applied as restrictive intersection (deny glob / TTL min / silence = deny)");

    /* ------------------- (b) audit export to the cloud ------------------- */
    const auditSeen = await waitFor("audit events in GET /v1/admin/audit", async () => {
      const res = await fetch(`${cloudBase}/v1/admin/audit?teamId=${encodeURIComponent(teamId)}`, {
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
      }).catch(() => null);
      if (!res || !res.ok) return null;
      const body = await res.json();
      const events = Array.isArray(body) ? body : (body.events ?? []);
      const mine = events.filter((e) => e.agentId === "e2e-agent");
      return mine.length > 0 ? mine : null;
    });
    const kinds = new Set(auditSeen.map((e) => e.kind));
    assert.ok(
      kinds.has("capability_request") || kinds.has("capability_denied") || kinds.has("ceiling_blocked"),
      `expected policy-decision events in the cloud store, got kinds: ${[...kinds].join(", ")}`,
    );
    pass(`(b) gateway audit events exported and visible in the cloud (${auditSeen.length} events, batch signature verified server-side)`);

    /* ---------------- (c) fleet revocation < 30 s ------------------------ */
    const revokeStart = Date.now();
    await adminFetch(cloudBase, "POST", "/v1/admin/revocations", {
      teamId,
      agentId: "e2e-agent",
      reason: "e2e fleet-revocation drill",
    });
    const revokedDenial = await waitFor(
      "revocation to reach the gateway",
      async () => {
        const r = await requestCap("fakegit:call:whoami", "1m");
        return r.granted === false && /revoked/i.test(r.text) ? r : null;
      },
      30_000,
      250,
    );
    const revokeMs = Date.now() - revokeStart;
    assert.match(revokedDenial.text, /REVOKED|revoked/i, `denial should mention the revocation: ${revokedDenial.text}`);
    assert.ok(revokeMs < 30_000, `revocation took ${revokeMs}ms (target < 30s)`);
    pass(`(c) fleet revocation effective in ${revokeMs}ms (< 30s target) — every call now denied fail-closed`);

    // Human re-enable (documented process): remove cloud-revoked.json.
    fs.rmSync(path.join(home, "cloud-revoked.json"), { force: true });
    const back = await requestCap("fakegit:call:whoami", "1m");
    assert.equal(back.granted, true, `after human re-enable the agent works again: ${JSON.stringify(back)}`);
    pass("human re-enable: removing cloud-revoked.json restores service");

    /* ------------- (d) local-first: cloud down, cloud back --------------- */
    await stopCloud();
    pass("cloud process killed");
    // The gateway must keep deciding with local policy + last signed cache:
    // whoami still granted (both allow), danger still denied (cached team deny).
    const offlineWhoami = await requestCap("fakegit:call:whoami", "1m");
    assert.equal(offlineWhoami.granted, true, `cloud down: whoami must still be granted: ${JSON.stringify(offlineWhoami)}`);
    const offlineDanger = await requestCap("fakegit:call:danger", "1m");
    assert.equal(offlineDanger.granted, false, `cloud down: cached team deny must hold: ${JSON.stringify(offlineDanger)}`);
    assert.match(offlineDanger.reason, /\[team policy\]/);
    pass("(d) local-first: with the cloud DOWN the gateway keeps serving (local policy + signed cache)");

    await restartCloud();
    pass("cloud process back up (same port, same state)");
    // Re-engagement proof: a NEW team policy version propagates.
    const teamPolicyV2 = {
      version: 1,
      limits: { deny: ["fakegit:call:danger"] },
      agents: {
        "e2e-agent": {
          capabilities: [{ match: "fakegit:call:whoami", auto_approve: true, ttl: "1m" }],
        },
      },
    };
    await adminFetch(cloudBase, "PUT", "/v1/admin/policy", { teamId, yaml: JSON.stringify(teamPolicyV2) });
    const tightened = await waitFor("re-engagement (policy v2 applied)", async () => {
      const r = await requestCap("fakegit:call:whoami", "10m");
      return r.granted === true && r.expires_in_seconds <= 60 ? r : null;
    });
    assert.ok(tightened.expires_in_seconds <= 60, `policy v2 ttl clamp (1m) not applied: ${JSON.stringify(tightened)}`);
    pass("(d) re-engaged: new team policy version propagates after the cloud returns (whoami TTL ≤ 60s)");
  } finally {
    await client.close().catch(() => {});
    await stopCloud().catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(cloudHome, { recursive: true, force: true });
  }

  console.log("\ne2e-cloud: ALL ASSERTIONS PASSED");
}

main()
  .then(() => {
    clearTimeout(watchdog);
  })
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-cloud FAILED: ${e.message}`);
    process.exit(1);
  });
