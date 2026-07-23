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

    /* ---------------- SEO / GEO (PLAN-SEO-GEO) ------------------------------ */

    // robots.txt: crawlable landing, panel + API disallowed, sitemap declared.
    const robots = await fetch(base + "/robots.txt");
    assert.equal(robots.status, 200, "GET /robots.txt status");
    assert.match(robots.headers.get("content-type") ?? "", /text\/plain/, "robots content-type");
    const robotsTxt = await robots.text();
    assert.ok(robotsTxt.includes("User-agent: *"), "robots user-agent");
    assert.ok(robotsTxt.includes("Disallow: /panel"), "robots disallows /panel");
    assert.ok(robotsTxt.includes("Disallow: /v1"), "robots disallows /v1");
    assert.ok(robotsTxt.includes("Sitemap: https://scopegate.io/sitemap.xml"), "robots sitemap line");
    pass("GET /robots.txt — panel/API disallowed, sitemap declared");

    // sitemap.xml: well-formed, lists public pages, excludes panel/API.
    const sitemap = await fetch(base + "/sitemap.xml");
    assert.equal(sitemap.status, 200, "GET /sitemap.xml status");
    assert.match(sitemap.headers.get("content-type") ?? "", /application\/xml/, "sitemap content-type");
    const sitemapTxt = await sitemap.text();
    assert.ok(sitemapTxt.includes("<urlset"), "sitemap urlset");
    for (const u of ["/", "/docs/", "/docs/quickstart", "/docs/agents/", "/docs/agents/02-protocol"]) {
      const loc = u === "/" ? "https://scopegate.io/</loc>" : `https://scopegate.io${u}</loc>`;
      assert.ok(sitemapTxt.includes(loc), `sitemap contains ${u}`);
    }
    assert.ok(!sitemapTxt.includes("/panel"), "sitemap excludes /panel");
    assert.ok(!sitemapTxt.includes("/v1"), "sitemap excludes /v1");
    pass("GET /sitemap.xml — public pages listed, panel/API excluded");

    // llms.txt / llms-full.txt for AI engines.
    const llms = await fetch(base + "/llms.txt");
    assert.equal(llms.status, 200, "GET /llms.txt status");
    assert.match(llms.headers.get("content-type") ?? "", /text\/plain/, "llms content-type");
    const llmsTxt = await llms.text();
    assert.ok(llmsTxt.includes("# ScopeGate"), "llms title");
    assert.ok(llmsTxt.includes("ephemeral-credentials gateway"), "llms definition");
    assert.ok(llmsTxt.includes("/docs/agents/02-protocol"), "llms links to guides");
    const llmsFull = await fetch(base + "/llms-full.txt");
    assert.equal(llmsFull.status, 200, "GET /llms-full.txt status");
    assert.ok((await llmsFull.text()).includes("scopegate_request_capability"), "llms-full lists the tools");
    pass("GET /llms.txt + /llms-full.txt — GEO entry points");

    // OG image present and really a PNG.
    const og = await fetch(base + "/og.png");
    assert.equal(og.status, 200, "GET /og.png status");
    assert.match(og.headers.get("content-type") ?? "", /image\/png/, "og content-type");
    const ogBuf = Buffer.from(await og.arrayBuffer());
    assert.ok(ogBuf.length > 10_000, "og.png is a real image (>10KB)");
    assert.deepEqual([...ogBuf.subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47], "og.png PNG signature");
    pass("GET /og.png — valid PNG social card");

    // Landing head: canonical, OG/Twitter, and 4 valid JSON-LD blocks.
    assert.ok(html.includes('<link rel="canonical" href="https://scopegate.io/">'), "canonical");
    assert.ok(html.includes('property="og:image"'), "og:image meta");
    assert.ok(html.includes('name="twitter:card" content="summary_large_image"'), "twitter card");
    const ldBlocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)]
      .map((m) => JSON.parse(m[1]));
    const ldTypes = ldBlocks.map((b) => b["@type"]).sort();
    assert.deepEqual(ldTypes, ["FAQPage", "HowTo", "Organization", "SoftwareApplication"], "JSON-LD @types");
    const faq = ldBlocks.find((b) => b["@type"] === "FAQPage");
    assert.ok(faq.mainEntity.length >= 5, "FAQPage has the questions");
    pass("landing head — canonical, OG/Twitter, 4 valid JSON-LD blocks");

    // Citable definition + hard facts on-page.
    for (const marker of [
      'id="what-is"',
      "ephemeral-credentials gateway for",
      "install → first tool call",
      "fleet revocation, online",
    ]) {
      assert.ok(html.includes(marker), `landing citable section contains ${JSON.stringify(marker)}`);
    }
    pass("landing — citable definition + hard facts row");

    // Interactive containers present (content readable without JS).
    for (const marker of [
      'id="flow-diagram"',
      'id="ttl-demo"',
      'id="before-after"',
      'id="terminal-demo"',
      'id="health-badge"',
      '<script src="/main.js" defer></script>',
      'href="/docs/"', // nav points to on-site docs
    ]) {
      assert.ok(html.includes(marker), `landing interactive contains ${JSON.stringify(marker)}`);
    }
    const mainJs = await fetch(base + "/main.js");
    assert.equal(mainJs.status, 200, "GET /main.js status");
    assert.match(mainJs.headers.get("content-type") ?? "", /javascript/, "main.js content-type");
    pass("landing — interactive pieces + main.js");

    // Docs served as crawlable HTML + raw markdown.
    for (const route of ["/docs/", "/docs/quickstart", "/docs/agents/", "/docs/agents/02-protocol"]) {
      const r = await fetch(base + route);
      assert.equal(r.status, 200, `GET ${route} status`);
      assert.match(r.headers.get("content-type") ?? "", /text\/html/, `${route} content-type`);
    }
    const guide = await (await fetch(base + "/docs/agents/02-protocol")).text();
    for (const marker of [
      "The Agent Protocol",
      'class="breadcrumb"',
      'rel="canonical" href="https://scopegate.io/docs/agents/02-protocol"',
      'data-lang="json"', // fenced code keeps the language tag
    ]) {
      assert.ok(guide.includes(marker), `guide 02 contains ${JSON.stringify(marker)}`);
    }
    const guide3 = await (await fetch(base + "/docs/agents/03-tools-reference")).text();
    assert.ok(guide3.includes("<table>"), "guide 03 renders markdown tables as HTML");
    assert.ok(guide3.includes("<th>"), "guide 03 table has a header row");
    const rawMd = await fetch(base + "/docs/agents/02-protocol.md");
    assert.equal(rawMd.status, 200, "GET raw .md status");
    assert.match(rawMd.headers.get("content-type") ?? "", /text\/markdown/, "raw .md content-type");
    assert.ok((await rawMd.text()).startsWith("# 02"), "raw .md is the source");
    // Traversal is refused.
    const trav = await fetch(base + "/docs/..%2f..%2fpackage.json");
    assert.notEqual(trav.status, 200, "docs traversal refused");
    pass("docs — HTML pages + raw markdown + traversal guard");

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
