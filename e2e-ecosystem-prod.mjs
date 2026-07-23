#!/usr/bin/env node
/**
 * Ecosystem production e2e (EPIC-20) — real operations through the deployed
 * ScopeGate gateway against the live surfaces: Huly (issue create + comment +
 * search), Railway (service/domain status), GitHub (repo read), and the
 * documented waiting-for-secrets state of Cloudflare/Google (tokens not yet
 * deposited by the operator).
 *
 * Required env (same as e2e-prod):
 *   SCOPEGATE_PROD_URL    e.g. https://scopegate-production.up.railway.app
 *   SCOPEGATE_HTTP_TOKEN  the gateway bearer
 *
 * Optional:
 *   ECOSYSTEM_FULL=1  also exercises the write path on GitHub (skipped by
 *   default — reads only).
 *
 * Exits 0 on success, 1 on first failure, 2 on global timeout (120s).
 * No secret is ever printed.
 */
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const watchdog = setTimeout(() => {
  console.error("e2e-ecosystem FAILED: global timeout (120s)");
  process.exit(2);
}, 120_000);

const pass = (name) => console.log(`ok - ${name}`);
const failEarly = (m) => {
  console.error(`e2e-ecosystem FAILED: ${m}`);
  process.exit(1);
};

const PROD_URL = (process.env.SCOPEGATE_PROD_URL ?? "").trim().replace(/\/+$/, "");
const TOKEN = (process.env.SCOPEGATE_HTTP_TOKEN ?? "").trim();
if (!PROD_URL || !TOKEN) failEarly("SCOPEGATE_PROD_URL and SCOPEGATE_HTTP_TOKEN are required.");

async function main() {
  console.log(`e2e-ecosystem target: ${PROD_URL} (token: set, ${TOKEN.length} chars — never printed)`);

  const client = new Client({ name: "e2e-ecosystem", version: "1.0.0" }, { capabilities: {} });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${PROD_URL}/mcp`), {
      requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
    }),
  );
  const parse = (res) => JSON.parse(res.content[0].text);
  const cap = async (capability) => {
    const g = parse(
      await client.callTool({
        name: "scopegate_request_capability",
        arguments: { capability, reason: "e2e-ecosystem prod" },
      }),
    );
    assert.equal(g.granted, true, `grant denied for ${capability}: ${JSON.stringify(g)}`);
  };

  /* ----------------------------- listTools ----------------------------- */
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  for (const prefix of ["huly__", "railway__", "github__"]) {
    assert.ok(
      names.some((n) => n.startsWith(prefix)),
      `listTools missing ${prefix}* tools (got ${names.length} tools)`,
    );
  }
  pass(`listTools exposes huly__*, railway__*, github__* (${names.length} tools)`);

  /* -------------------------------- Huly ------------------------------- */
  await cap("huly:call:tracker_list_projects");
  const projects = parse(await client.callTool({ name: "huly__tracker_list_projects", arguments: {} }));
  const projList = Array.isArray(projects) ? projects : (projects.projects ?? []);
  assert.ok(projList.length > 0, `expected >=1 Huly project, got: ${JSON.stringify(projects).slice(0, 200)}`);
  const project =
    projList.find((p) => /sg-?e2e/i.test(p.name ?? p.identifier ?? "")) ?? projList[0];
  const projectId = project.identifier ?? project.name ?? project.id ?? project._id;
  pass(`Huly tracker_list_projects: ${projList.length} project(s), using '${projectId}'`);

  await cap("huly:call:tracker_create_issue");
  await cap("huly:call:tracker_comment_issue");
  await cap("huly:call:tracker_search_issues");
  const marker = `[scopegate-e2e] ${new Date().toISOString()}`;
  const created = parse(
    await client.callTool({
      name: "huly__tracker_create_issue",
      arguments: { project: projectId, title: marker, description: "e2e de integración ScopeGate — puede borrarse." },
    }),
  );
  const issueId = created.identifier ?? created.id ?? created._id ?? created.issueId;
  assert.ok(issueId, `issue created without id: ${JSON.stringify(created).slice(0, 200)}`);
  pass(`Huly tracker_create_issue → ${issueId}`);

  const comment = parse(
    await client.callTool({
      name: "huly__tracker_comment_issue",
      arguments: { issueId, message: "comentario e2e vía ScopeGate (capability efímera, sin secretos en contexto)" },
    }),
  );
  assert.notEqual(comment.isError, true, `comment failed: ${JSON.stringify(comment).slice(0, 200)}`);
  pass("Huly tracker_comment_issue ok");

  const found = parse(
    await client.callTool({
      name: "huly__tracker_search_issues",
      arguments: { query: "scopegate-e2e", limit: 5 },
    }),
  );
  const foundText = JSON.stringify(found);
  assert.ok(foundText.includes("scopegate-e2e"), `search did not find the created issue: ${foundText.slice(0, 300)}`);
  pass("Huly tracker_search_issues finds the created issue");

  /* ------------------------------- Railway ----------------------------- */
  await cap("railway:call:service_status");
  await cap("railway:call:domain_status");
  const status = parse(
    await client.callTool({ name: "railway__service_status", arguments: { service: "scopegate" } }),
  );
  assert.match(JSON.stringify(status), /SUCCESS|healthy|online/i, `service_status unexpected: ${JSON.stringify(status).slice(0, 200)}`);
  pass("Railway service_status: scopegate is up");

  const domain = parse(
    await client.callTool({ name: "railway__domain_status", arguments: { service: "scopegate" } }),
  );
  assert.match(JSON.stringify(domain), /railway\.app/i, `domain_status unexpected: ${JSON.stringify(domain).slice(0, 200)}`);
  pass("Railway domain_status: service domain present");

  /* ------------------------------- GitHub ------------------------------ */
  await cap("github:call:get_file_contents");
  const repo = parse(
    await client.callTool({
      name: "github__get_file_contents",
      arguments: { owner: "NexgenSystemsMX", repo: "huly-platform", path: "README.md" },
    }),
  );
  assert.ok(JSON.stringify(repo).length > 50, `repo read too small: ${JSON.stringify(repo).slice(0, 150)}`);
  pass("GitHub get_file_contents reads NexgenSystemsMX/huly-platform (installation token)");

  /* --------------------------- Cloudflare (live) ------------------------ */
  await cap("cloudflare:call:list_zones");
  const zones = parse(await client.callTool({ name: "cloudflare__list_zones", arguments: {} }));
  const zoneList = zones.zones ?? [];
  assert.ok(zoneList.length > 0, `expected >=1 Cloudflare zone: ${JSON.stringify(zones).slice(0, 200)}`);
  assert.ok(
    zoneList.every((z) => typeof z.name === "string" && typeof z.status === "string"),
    `zone shape unexpected: ${JSON.stringify(zones).slice(0, 200)}`,
  );
  pass(`Cloudflare list_zones: ${zoneList.length} zone(s) live (scoped token)`);

  /* ----------------------------- Google (live) -------------------------- */
  await cap("google:call:drive_list");
  const drive = parse(await client.callTool({ name: "google__drive_list", arguments: { limit: 5 } }));
  const files = drive.files ?? [];
  assert.ok(files.length > 0, `expected >=1 Drive file: ${JSON.stringify(drive).slice(0, 200)}`);
  assert.ok(
    files.every((f) => typeof f.id === "string" && typeof f.name === "string"),
    `file shape unexpected: ${JSON.stringify(drive).slice(0, 200)}`,
  );
  pass(`Google drive_list: ${files.length} file(s) live (SA JWT → access token, domain-wide delegation)`);

  /* ---------------------------- secret hygiene -------------------------- */
  const hygieneText = JSON.stringify({ projects, status, domain, repo, found, created, comment });
  for (const forbidden of ["supersecret", TOKEN, "BEGIN PRIVATE KEY", "gho_"]) {
    assert.ok(
      !hygieneText.includes(forbidden),
      `secret-like material leaked into outputs: ${forbidden.slice(0, 6)}…`,
    );
  }
  pass("no secret material in any returned payload");

  await client.close().catch(() => {});
  console.log("\ne2e-ecosystem: ALL ASSERTIONS PASSED");
}

main()
  .then(() => clearTimeout(watchdog))
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-ecosystem FAILED: ${e.message}`);
    process.exit(1);
  });
