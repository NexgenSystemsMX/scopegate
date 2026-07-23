#!/usr/bin/env node
/**
 * Panel demo seed (dev utility) — enrolls demo agents and ingests properly
 * chained+signed audit events against a running control plane, so the panel
 * has realistic data for manual/Playwright verification.
 *
 * Usage:
 *   node scripts/seed-panel-demo.mjs <baseUrl> <adminToken>
 * Example:
 *   node scripts/seed-panel-demo.mjs http://127.0.0.1:8471 dev-admin-token
 *
 * Creates a team "demo" (prints the enroll token ONCE), enrolls agents
 * "claude-code-luis" and "kimi-code-kevin" and pushes a mixed event feed:
 * tool calls, active grants, a denial, a honeytoken hit and one PENDING
 * approval request (resolve it from the panel to see the full loop).
 */
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const [base, adminToken] = process.argv.slice(2);
if (!base || !adminToken) {
  console.error("usage: node scripts/seed-panel-demo.mjs <baseUrl> <adminToken>");
  process.exit(1);
}

const { signCanonical, fingerprintOf } = await import(
  pathToFileURL(path.join(ROOT, "dist", "audit", "identity.js")).href
);
const { canonicalSigned, canonicalUnsigned } = await import(
  pathToFileURL(path.join(ROOT, "dist", "audit", "log.js")).href
);

async function api(p, { method = "GET", token = adminToken, body } = {}) {
  const res = await fetch(base + p, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* ndjson etc. */ }
  if (!res.ok) throw new Error(`${method} ${p} → HTTP ${res.status}: ${text.slice(0, 200)}`);
  return json;
}

function makeIdentity(agentId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    agentId,
    publicKey: pub,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    fingerprint: fingerprintOf(pub),
  };
}

function signEvent(id, partial) {
  const identity = {
    v: 1,
    algo: "ed25519",
    publicKey: id.publicKey,
    privateKey: id.privateKey,
    fingerprint: id.fingerprint,
    createdAt: new Date().toISOString(),
  };
  const sig = signCanonical(identity, canonicalUnsigned(partial));
  const signed = { ...partial, sig };
  const hash = crypto
    .createHash("sha256")
    .update(partial.prev + canonicalSigned(signed))
    .digest("hex");
  return { ...signed, hash };
}

function makeChain(id, specs) {
  const events = [];
  let prev = "genesis";
  specs.forEach((s, i) => {
    const e = signEvent(id, {
      ts: s.ts ?? new Date().toISOString(),
      agentId: id.agentId,
      kind: s.kind,
      detail: s.detail,
      prev,
      seq: i + 1,
    });
    events.push(e);
    prev = e.hash;
  });
  return events;
}

function batchSig(id, events) {
  return signCanonical(
    {
      v: 1,
      algo: "ed25519",
      publicKey: id.publicKey,
      privateKey: id.privateKey,
      fingerprint: id.fingerprint,
      createdAt: new Date().toISOString(),
    },
    JSON.stringify(events),
  );
}

const inN = (ms) => new Date(Date.now() + ms).toISOString();
const ago = (ms) => new Date(Date.now() - ms).toISOString();

async function main() {
  // Team (idempotent-ish: reuse the first team if one exists).
  let teams = (await api("/v1/admin/teams")).teams;
  let team;
  if (teams.length > 0) {
    team = teams[0];
    console.log(`reusing team ${team.name} (${team.teamId})`);
  } else {
    team = await api("/v1/admin/teams", { method: "POST", body: { name: "demo" } });
    console.log(`team created: ${team.teamId}`);
    console.log(`ENROLL TOKEN (shown once): ${team.enrollToken}`);
  }
  const teamId = team.teamId;
  const enrollToken = team.enrollToken;

  async function enroll(agentId) {
    const id = makeIdentity(agentId);
    const r = await api("/v1/enroll", {
      method: "POST",
      token: null,
      body: { agentId, enrollToken, pubkeyFingerprint: id.fingerprint, pubkey: id.publicKey },
    });
    console.log(`enrolled ${agentId} (fingerprint ${id.fingerprint.slice(0, 24)}…)`);
    return { id, agentSecret: r.agentSecret };
  }

  async function ingest(agent, specs) {
    const events = makeChain(agent.id, specs);
    const signature = batchSig(agent.id, events);
    const r = await api("/v1/audit/batch", {
      method: "POST",
      token: agent.agentSecret,
      body: { agentId: agent.id.agentId, events, signature },
    });
    console.log(`ingested ${r.accepted} events for ${agent.id.agentId} (rejected ${r.rejected})`);
  }

  const luis = await enroll("claude-code-luis");
  const kevin = await enroll("kimi-code-kevin");

  await ingest(luis, [
    { kind: "grant_issued", detail: { id: "g-luis-1", capability: "github:write:scopegate/*", ttlMs: 900_000, expiresAt: inN(13 * 60_000), rule: "github:write:scopegate/*" } },
    { kind: "tool_call", detail: { tool: "github__create_pull_request", upstream: "github", capability: "github:write:scopegate/*" } },
    { kind: "grant_issued", detail: { id: "g-luis-2", capability: "aws:deploy:staging", ttlMs: 600_000, expiresAt: inN(42_000), rule: "aws:deploy:staging" } },
    { kind: "tool_call", detail: { tool: "railway__deploy", upstream: "railway", capability: "aws:deploy:staging" } },
    { kind: "capability_denied", detail: { capability: "aws:*:production", code: "ceiling_blocked", reason: "[team policy] matches limits.deny" } },
    { kind: "approval_requested", detail: { id: crypto.randomUUID(), capability: "aws:deploy:production", ttl: "10m", reason: "hotfix: payment webhook retries", expiresAt: inN(9 * 60_000) } },
  ]);
  // Note: the pending approval id is random per seed — find it in the panel.

  await ingest(kevin, [
    { kind: "grant_issued", detail: { id: "g-kevin-1", capability: "db:read:analytics", ttlMs: 1_800_000, expiresAt: inN(27 * 60_000), rule: "db:read:*" } },
    { kind: "tool_call", detail: { tool: "postgres__query", upstream: "analytics-db", capability: "db:read:analytics" } },
    { kind: "honeytoken_triggered", detail: { ref: "canary_stripe_live", capability: "stripe:write:*", action: "surgical_revocation" } },
    { kind: "agent_revoked", detail: { revokedAgentId: "kimi-code-kevin", via: "honeytoken", reason: "canary_stripe_live touched", revokedGrants: 1, suspended: false }, ts: ago(60_000) },
  ]);

  console.log("\nDemo seed complete. Open the panel: " + base + "/panel");
  console.log("Expected state:");
  console.log("  · overview: 2 agents, 1 pending approval, events in 24 h, 1 honeytoken hit");
  console.log("  · capabilities: 3 active grants (one expiring in <1 min → highlighted)");
  console.log("  · approvals: 1 pending (aws:deploy:production) — approve/deny it");
  console.log("  · audit: full signed feed; export downloads the JSONL");
}

main().catch((e) => {
  console.error("seed failed:", e.message);
  process.exit(1);
});
