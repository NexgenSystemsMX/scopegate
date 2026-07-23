/**
 * ScopeGate Cloud control plane — server factory (EPIC-10).
 *
 *   scopegate cloud serve --port <n> --home <dir>
 *
 * On successful boot it prints TWO parseable stdout lines (the FROZEN
 * contract with the gateway-side CLOUD-SYNC client and e2e):
 *   SCOPEGATE_CLOUD_LISTENING port=<n>          (actual port, also with --port 0)
 *   SCOPEGATE_CLOUD_FINGERPRINT sha256=<hex>    (cloud identity fingerprint)
 * Everything human-oriented goes to stderr, keeping stdout machine-clean.
 *
 * LOCAL-FIRST (§3): this control plane is an OPTIONAL layer. It never holds
 * secrets (metadata-only, enforced at ingest), and the gateway keeps working
 * with its local policies.yaml/audit.jsonl when the cloud is down.
 *
 * Data home (default ~/.scopegate-cloud, NOT the gateway's ~/.scopegate):
 *   cloud-identity.json   cloud Ed25519 keypair, keep-first (keys.ts)
 *   data/*.json           teams / agents / policies / revocations (store.ts)
 *   data/audit-*.jsonl    append-only audit per team
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { makeSlackAlerter, type AlertPoster } from "./alerts.js";
import { loadOrCreateCloudIdentity, type CloudIdentity } from "./keys.js";
import { HttpError } from "./model.js";
import { handleApiRequest } from "./router.js";
import { makeDevSsoAdapter } from "./sso.js";
import { FileStore, type Store } from "./store.js";

export const DEFAULT_ADMIN_TOKEN = "dev-admin-token";

export interface CloudServerOptions {
  /** Listen port. 0 = ephemeral (tests); the actual port is on the result. */
  port: number;
  /** Cloud data home (created on first boot). */
  home: string;
  /** Admin bearer. Default: env ADMIN_TOKEN ?? SCOPEGATE_CLOUD_ADMIN_TOKEN ?? DEFAULT_ADMIN_TOKEN. */
  adminToken?: string;
  /** Injectable for tests — defaults to the real Slack webhook POST. */
  alertPoster?: AlertPoster;
  /** Print the SCOPEGATE_CLOUD_* lines on listen (default true). */
  announce?: boolean;
}

export interface RunningCloud {
  port: number;
  home: string;
  adminToken: string;
  cloudIdentity: CloudIdentity;
  store: Store;
  close: () => Promise<void>;
}

export function resolveAdminToken(option?: string): string {
  return (
    option ??
    process.env.ADMIN_TOKEN ??
    process.env.SCOPEGATE_CLOUD_ADMIN_TOKEN ??
    DEFAULT_ADMIN_TOKEN
  );
}

/* ------------------------------------------------------------------ */
/* Static files: landing site + panel (vanilla HTML/JS, no build step).*/
/*                                                                     */
/* Routing contract:                                                   */
/*   /                     → site/index.html      (public landing)     */
/*   /styles.css           → site/styles.css                           */
/*   /favicon.svg          → site/favicon.svg                          */
/*   /panel[/index.html]   → dashboard/index.html (the product panel)  */
/*   /panel/app.js         → dashboard/app.js                          */
/*   /index.html, /app.js  → 302 redirects to /panel (backward-compat: */
/*                           the panel used to live at /)              */
/*   /health               → 200 JSON (public, for uptime checks)      */
/*                                                                     */
/* tsc only compiles *.ts, so the assets are read from the SOURCE tree */
/* at runtime. Candidates cover both layouts:                          */
/*   src/cloud/server → ../dashboard | ../../site   (vitest / tsx)     */
/*   dist/cloud/server → <pkg>/src/cloud/...        (built cli in repo)*/
/* A packaged install that prunes src/ serves a small inline fallback  */
/* page explaining the situation instead of crashing (documented).     */
/* ------------------------------------------------------------------ */

interface StaticEntry {
  file: string;
  contentType: string;
}

const LANDING_FILES: Record<string, StaticEntry> = {
  "/": { file: "index.html", contentType: "text/html; charset=utf-8" },
  "/styles.css": { file: "styles.css", contentType: "text/css; charset=utf-8" },
  "/main.js": { file: "main.js", contentType: "text/javascript; charset=utf-8" },
  "/favicon.svg": { file: "favicon.svg", contentType: "image/svg+xml" },
  "/og.png": { file: "og.png", contentType: "image/png" },
  "/og-card.html": { file: "og-card.html", contentType: "text/html; charset=utf-8" },
  "/robots.txt": { file: "robots.txt", contentType: "text/plain; charset=utf-8" },
  "/sitemap.xml": { file: "sitemap.xml", contentType: "application/xml; charset=utf-8" },
  "/llms.txt": { file: "llms.txt", contentType: "text/plain; charset=utf-8" },
  "/llms-full.txt": { file: "llms-full.txt", contentType: "text/plain; charset=utf-8" },
};

const DOCS_CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
};

/**
 * Serve the generated documentation pages under /docs/ (SEO: crawlable HTML)
 * and their raw .md sources (GEO: text/markdown for AI crawlers). Extension-
 * less paths resolve to <path>.html; directory paths to index.html. Traversal
 * outside site/docs is refused.
 */
function serveDocsFile(res: http.ServerResponse, pathname: string, siteDir: string): boolean {
  let rel: string;
  try {
    rel = decodeURIComponent(pathname.slice("/docs".length));
  } catch {
    return false;
  }
  if (rel === "" || rel === "/") rel = "/index.html";
  else if (rel.endsWith("/")) rel += "index.html";
  else if (!/\.[a-z0-9]+$/i.test(rel)) rel += ".html";

  const base = path.join(siteDir, "docs");
  const abs = path.normalize(path.join(base, rel));
  if (abs !== base && !abs.startsWith(base + path.sep)) return false;
  const contentType = DOCS_CONTENT_TYPES[path.extname(abs).toLowerCase()];
  if (!contentType || !fs.existsSync(abs)) return false;

  const body = fs.readFileSync(abs);
  res.writeHead(200, {
    "content-type": contentType,
    "content-length": body.length,
    "cache-control": "no-store",
  });
  res.end(body);
  return true;
}

const PANEL_FILES: Record<string, StaticEntry> = {
  "/panel": { file: "index.html", contentType: "text/html; charset=utf-8" },
  "/panel/": { file: "index.html", contentType: "text/html; charset=utf-8" },
  "/panel/index.html": { file: "index.html", contentType: "text/html; charset=utf-8" },
  "/panel/app.js": { file: "app.js", contentType: "text/javascript; charset=utf-8" },
};

const REDIRECTS: Record<string, string> = {
  "/index.html": "/panel",
  "/app.js": "/panel/app.js",
  "/dashboard": "/panel",
};

function resolveStaticDir(relFromServerDir: string, pkgRel: string): string | null {
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    // Running on the source tree (vitest / tsx): sibling of src/cloud/server.
    path.join(moduleDir, relFromServerDir),
    // Running the built CLI from the repo: <pkg>/<pkgRel>.
    path.join(moduleDir, "..", "..", "..", pkgRel),
    // Repo root as cwd.
    path.join(process.cwd(), pkgRel),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "index.html"))) return dir;
  }
  return null;
}

const FALLBACK_HTML = `<!doctype html><html><body style="font-family:sans-serif;max-width:40em;margin:4em auto">
<h1>ScopeGate Cloud</h1>
<p>The static assets (<code>site/</code> and <code>src/cloud/dashboard/</code>) are
not present in this installation — the management API under <code>/v1</code> is
fully functional regardless. Reinstall from a full checkout to get the landing
page and the panel.</p>
</body></html>`;

function serveStatic(
  res: http.ServerResponse,
  pathname: string,
): boolean {
  // Public health probe — no auth, no store access.
  if (pathname === "/health") {
    const body = JSON.stringify({ status: "ok", service: "scopegate-cloud" });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "content-length": Buffer.byteLength(body),
      "cache-control": "no-store",
    });
    res.end(body);
    return true;
  }

  const redirect = REDIRECTS[pathname];
  if (redirect) {
    res.writeHead(302, { location: redirect, "content-length": 0 });
    res.end();
    return true;
  }

  const landing = LANDING_FILES[pathname];
  const panel = PANEL_FILES[pathname];
  if (!landing && !panel) {
    if (pathname.startsWith("/docs")) {
      const dir = resolveStaticDir(path.join("..", "..", "site"), "site");
      if (dir !== null && serveDocsFile(res, pathname, dir)) return true;
    }
    return false;
  }

  const dir = landing
    ? resolveStaticDir(path.join("..", "..", "site"), "site")
    : resolveStaticDir(path.join("..", "dashboard"), path.join("src", "cloud", "dashboard"));
  const entry = (landing ?? panel)!;
  const body =
    dir !== null
      ? fs.readFileSync(path.join(dir, entry.file))
      : Buffer.from(FALLBACK_HTML, "utf8");
  res.writeHead(200, {
    "content-type": entry.contentType,
    "content-length": body.length,
    "cache-control": "no-store",
  });
  res.end(body);
  return true;
}

export async function startCloudServer(
  opts: CloudServerOptions,
): Promise<RunningCloud> {
  const home = path.resolve(opts.home);
  const cloudIdentity = loadOrCreateCloudIdentity(home);
  const retentionDays = Number(process.env.AUDIT_RETENTION_DAYS ?? 90);
  const store = new FileStore(home, {
    auditRetentionDays: Number.isFinite(retentionDays) ? retentionDays : 90,
  });
  const adminToken = resolveAdminToken(opts.adminToken);
  const announce = opts.announce ?? true;

  if (adminToken === DEFAULT_ADMIN_TOKEN) {
    console.error(
      "[scopegate-cloud] WARN: using the default admin token 'dev-admin-token' " +
        "(env ADMIN_TOKEN unset). Dev-grade only — set ADMIN_TOKEN before " +
        "exposing this control plane beyond localhost.",
    );
  }

  const deps = {
    store,
    cloudIdentity,
    adminToken,
    sso: makeDevSsoAdapter(adminToken),
    alerter: makeSlackAlerter(opts.alertPoster),
  };

  const server = http.createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://localhost");
      try {
        if (await handleApiRequest(req, res, url, deps)) return;
        if ((req.method === "GET" || req.method === "HEAD") &&
            serveStatic(res, url.pathname)) {
          return;
        }
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `not found: ${url.pathname}` }));
      } catch (e) {
        if (e instanceof HttpError) {
          res.writeHead(e.status, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: e.message, ...(e.code ? { code: e.code } : {}) }));
        } else {
          console.error(
            "[scopegate-cloud] internal error:",
            e instanceof Error ? (e.stack ?? e.message) : String(e),
          );
          if (!res.headersSent) {
            res.writeHead(500, { "content-type": "application/json" });
          }
          res.end(JSON.stringify({ error: "internal server error" }));
        }
      }
    })();
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, () => resolve());
  });

  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : opts.port;

  if (announce) {
    // FROZEN contract lines — parseable, one per line, nothing else on stdout.
    console.log(`SCOPEGATE_CLOUD_LISTENING port=${port}`);
    console.log(`SCOPEGATE_CLOUD_FINGERPRINT ${cloudIdentity.fingerprint}`);
  }
  console.error(
    `[scopegate-cloud] landing at http://127.0.0.1:${port}/ · panel at /panel — data home: ${home}`,
  );

  return {
    port,
    home,
    adminToken,
    cloudIdentity,
    store,
    // Idempotent: closing an already-closed server is a no-op, not an error.
    close: () =>
      new Promise<void>((resolve) => {
        if (!server.listening) return resolve();
        server.close(() => resolve());
      }),
  };
}
