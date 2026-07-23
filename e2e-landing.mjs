#!/usr/bin/env node
/**
 * Landing page + panel static-serving e2e (PLAN-LANDING-PANEL, F1).
 *
 * Boots the REAL control plane (`node dist/cli.js cloud serve --port 0`) with a
 * temp home and asserts the full static routing contract:
 *
 *   GET /               → 200 landing page (all key sections present)
 *   GET /styles.css     → 200 text/css
 *   GET /favicon.svg    → 200 image/svg+xml
 *   GET /panel          → 200 product panel (ScopeGate Cloud)
 *   GET /panel/app.js   → 200 panel JS
 *   GET /index.html     → 302 → /panel        (backward-compat: old panel root)
 *   GET /app.js         → 302 → /panel/app.js
 *   GET /health         → 200 {status:"ok"}   (public probe)
 *   GET /nope           → 404 JSON
 *
 * Exits 0 when every assertion passes, 1 on the first failure, 2 on timeout.
 * Prereq: `npm run build` (needs dist/cli.js).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(ROOT, "dist", "cli.js");

const watchdog = setTimeout(() => {
  console.error("e2e-landing FAILED: global timeout (60s)");
  process.exit(2);
}, 60_000);

function pass(name) {
  console.log(`ok - ${name}`);
}

/** Spawn `cloud serve` and resolve with the actual port from the frozen line. */
function startCloud(home) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "cloud", "serve", "--port", "0", "--home", home], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let buf = "";
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const m = buf.match(/SCOPEGATE_CLOUD_LISTENING port=(\d+)/);
      if (m) resolve({ child, port: Number(m[1]) });
    });
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`cloud serve exited early (${code})`)));
  });
}

async function main() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-landing-e2e-"));
  const { child, port } = await startCloud(home);
  const base = `http://127.0.0.1:${port}`;
  try {
    // -- landing at / --------------------------------------------------------
    const landing = await fetch(base + "/");
    assert.equal(landing.status, 200, "GET / status");
    assert.match(landing.headers.get("content-type") ?? "", /text\/html/, "GET / content-type");
    const html = await landing.text();
    for (const marker of [
      "capabilities",                 // hero claim
      'id="how-it-works"',
      'id="features"',
      'id="connectors"',
      'id="cloud"',
      'id="pricing"',
      'id="security"',
      'id="faq"',
      'href="/panel"',                // link to the product panel
      'href="/styles.css"',
      "scopegate init",               // install command
    ]) {
      assert.ok(html.includes(marker), `landing contains ${JSON.stringify(marker)}`);
    }
    pass("GET / serves the complete landing page");

    // -- landing assets ------------------------------------------------------
    const css = await fetch(base + "/styles.css");
    assert.equal(css.status, 200, "GET /styles.css status");
    assert.match(css.headers.get("content-type") ?? "", /text\/css/, "css content-type");
    assert.ok((await css.text()).includes("--accent"), "css has theme vars");

    const favicon = await fetch(base + "/favicon.svg");
    assert.equal(favicon.status, 200, "GET /favicon.svg status");
    assert.match(favicon.headers.get("content-type") ?? "", /image\/svg\+xml/, "favicon content-type");
    pass("landing assets served (/styles.css, /favicon.svg)");

    // -- panel at /panel -----------------------------------------------------
    const panel = await fetch(base + "/panel");
    assert.equal(panel.status, 200, "GET /panel status");
    const panelHtml = await panel.text();
    assert.ok(panelHtml.includes("ScopeGate Cloud"), "panel html marker");
    assert.ok(panelHtml.includes("/panel/app.js"), "panel references /panel/app.js");

    const appJs = await fetch(base + "/panel/app.js");
    assert.equal(appJs.status, 200, "GET /panel/app.js status");
    assert.ok((await appJs.text()).includes("/v1/admin/teams"), "panel js talks to /v1");
    pass("GET /panel serves the product panel");

    // -- backward-compat redirects -------------------------------------------
    const oldIndex = await fetch(base + "/index.html", { redirect: "manual" });
    assert.equal(oldIndex.status, 302, "GET /index.html status");
    assert.equal(oldIndex.headers.get("location"), "/panel", "/index.html redirect target");
    const oldJs = await fetch(base + "/app.js", { redirect: "manual" });
    assert.equal(oldJs.status, 302, "GET /app.js status");
    assert.equal(oldJs.headers.get("location"), "/panel/app.js", "/app.js redirect target");
    pass("old panel URLs redirect to /panel (backward-compat)");

    // -- health + 404 ---------------------------------------------------------
    const health = await fetch(base + "/health");
    assert.equal(health.status, 200, "GET /health status");
    assert.equal((await health.json()).status, "ok", "health payload");

    const missing = await fetch(base + "/nope");
    assert.equal(missing.status, 404, "GET /nope status");
    pass("GET /health public probe + 404 for unknown paths");

    console.log("\ne2e-landing: ALL ASSERTIONS PASSED");
  } finally {
    child.kill("SIGTERM");
    fs.rmSync(home, { recursive: true, force: true });
  }
  clearTimeout(watchdog);
  process.exit(0);
}

main().catch((e) => {
  console.error("e2e-landing FAILED:", e.message ?? e);
  process.exit(1);
});
