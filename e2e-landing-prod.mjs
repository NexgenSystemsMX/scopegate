#!/usr/bin/env node
/**
 * Landing production e2e (EPIC-25) — asserts that EVERY call-to-action on the
 * deployed landing is TRUE, against the live services:
 *
 *   1. Landing page (cloud service) 200 with key copy and CORRECT GitHub
 *      hrefs (NexgenSystemsMX/scopegate, master branch).
 *   2. /panel reachable; admin API auth-gated (401 anonymous).
 *   3. GET /install.sh on the gateway: 200, shell content, mentions scopegate.
 *   4. npm: the `scopegate` package RESOLVES on the public registry
 *      (post EPIC-22 — until the package is published this section fails,
 *      which is the intended signal).
 *   5. The ecosystem e2e (Huly/Railway/GitHub/Cloudflare/Google) is re-run
 *      implicitly by CI; here we re-check the gateway /health.
 *
 * Env: none required (URLs are the production defaults; overridable via
 * LANDING_URL / GATEWAY_URL). Exits 0 on success, 1 on first failure, 2 on
 * global timeout (90s). No secrets involved.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

const LANDING = (process.env.LANDING_URL ?? "https://scopegate-cloud-production.up.railway.app").replace(/\/+$/, "");
const GATEWAY = (process.env.GATEWAY_URL ?? "https://scopegate-production.up.railway.app").replace(/\/+$/, "");

const watchdog = setTimeout(() => {
  console.error("e2e-landing-prod FAILED: global timeout (90s)");
  process.exit(2);
}, 90_000);

const pass = (name) => console.log(`ok - ${name}`);
const failEarly = (m) => {
  console.error(`e2e-landing-prod FAILED: ${m}`);
  process.exit(1);
};

async function main() {
  console.log(`e2e-landing-prod: landing=${LANDING} gateway=${GATEWAY}`);

  /* 1. Landing page content + links */
  const landing = await fetch(`${LANDING}/`);
  assert.equal(landing.status, 200, `landing status ${landing.status}`);
  const html = await landing.text();
  for (const marker of [
    "Your agents hold",
    "capabilities",
    "Connectors",
    "Pricing",
    "Security model",
    "FAQ",
  ]) {
    assert.ok(html.includes(marker), `landing missing marker ${JSON.stringify(marker)}`);
  }
  pass("landing 200 with all key sections");

  assert.ok(
    html.includes('href="https://github.com/NexgenSystemsMX/scopegate"'),
    "landing must link the real repo (NexgenSystemsMX/scopegate)",
  );
  assert.ok(
    !html.includes("github.com/nexgen/scopegate") && !html.includes("get.scopegate.dev"),
    "landing must not link the wrong org nor the unowned get.scopegate.dev",
  );
  assert.ok(
    html.includes("/tree/master/") || html.includes("/blob/master/"),
    "docs/license links must point at the master branch",
  );
  pass("landing GitHub/docs/license links are correct (org + master)");

  /* 2. Panel reachable + admin API auth-gated */
  const panel = await fetch(`${LANDING}/panel`);
  assert.equal(panel.status, 200, `/panel status ${panel.status}`);
  pass("/panel reachable");

  const anon = await fetch(`${LANDING}/v1/admin/teams`);
  assert.equal(anon.status, 401, `anonymous admin call must be 401, got ${anon.status}`);
  pass("admin API is auth-gated (401 anonymous)");

  /* 3. Installer served by the gateway */
  const sh = await fetch(`${GATEWAY}/install.sh`);
  assert.equal(sh.status, 200, `/install.sh status ${sh.status}`);
  const shBody = await sh.text();
  assert.ok(
    shBody.startsWith("#!/bin/sh") || shBody.startsWith("#!/usr/bin/env sh"),
    "/install.sh must be a shell script",
  );
  assert.ok(shBody.includes("scopegate"), "/install.sh must mention scopegate");
  assert.ok(
    (sh.headers.get("content-type") ?? "").includes("text/x-sh"),
    "/install.sh content-type",
  );
  pass("GET /install.sh 200 + valid shell script on the gateway");

  /* 4. npm package resolves on the public registry */
  try {
    const out = execFileSync("npm", ["view", "scopegate", "version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    assert.ok(/^\d+\.\d+\.\d+/.test(out), `unexpected version: ${out}`);
    pass(`npm: scopegate@${out} resolves on the registry`);
  } catch {
    failEarly(
      "npm: package 'scopegate' does not resolve on the registry yet (EPIC-22 pending: run npm login, then npm publish --access public)",
    );
  }

  /* 5. Gateway healthy with ecosystem upstreams */
  const health = await (await fetch(`${GATEWAY}/health`)).json();
  assert.equal(health.status, "ok", `gateway /health: ${JSON.stringify(health)}`);
  assert.ok(health.upstreams >= 5, `expected >=5 connected upstreams: ${JSON.stringify(health)}`);
  pass(`gateway healthy (${health.upstreams} upstreams connected)`);

  console.log("\ne2e-landing-prod: ALL ASSERTIONS PASSED");
}

main()
  .then(() => clearTimeout(watchdog))
  .catch((e) => {
    clearTimeout(watchdog);
    console.error(`\ne2e-landing-prod FAILED: ${e.message}`);
    process.exit(1);
  });
