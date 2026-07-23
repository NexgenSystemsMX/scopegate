#!/usr/bin/env node
/**
 * generate-og-image.mjs — render site/og-card.html to site/og.png (1200×630)
 * using the locally available Playwright CLI against a throwaway control
 * plane (cloud serve serves /og-card.html like any other static asset).
 *
 *   npm run build && node scripts/generate-og-image.mjs
 *
 * Requires: dist/cli.js built, and Playwright available to npx
 * (`npx --no-install playwright --version` must succeed).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const CLI = path.join(ROOT, "dist", "cli.js");
const OUT = path.join(ROOT, "site", "og.png");

if (!fs.existsSync(CLI)) {
  console.error("dist/cli.js not found — run `npm run build` first");
  process.exit(1);
}

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

const home = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-og-"));
const { child, port } = await startCloud(home);
try {
  const url = `http://127.0.0.1:${port}/og-card.html`;
  const r = spawnSync(
    `npx --no-install playwright screenshot --viewport-size=1200,630 --wait-for-timeout=800 "${url}" "${OUT}"`,
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], shell: true },
  );
  if (r.error || r.status !== 0) {
    console.error("playwright screenshot failed:", r.error?.message ?? (r.stderr || r.stdout || `exit ${r.status}`));
    process.exit(1);
  }
  const size = fs.statSync(OUT).size;
  if (size < 10_000) {
    console.error(`og.png looks too small (${size} bytes) — capture probably failed`);
    process.exit(1);
  }
  console.log(`og.png written (${(size / 1024).toFixed(1)} KB, 1200×630) at ${path.relative(ROOT, OUT)}`);
} finally {
  child.kill("SIGTERM");
  fs.rmSync(home, { recursive: true, force: true });
}
