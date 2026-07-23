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
/* Dashboard static files (vanilla HTML/JS, no build step).            */
/*                                                                     */
/* tsc only compiles *.ts, so the dashboard assets are read from the   */
/* SOURCE tree at runtime. Candidates cover both layouts:              */
/*   src/cloud/server → ../dashboard          (vitest / tsx on src)    */
/*   dist/cloud/server → <pkg>/src/cloud/dashboard  (built cli in repo)*/
/* A packaged install that prunes src/ serves a small inline fallback  */
/* page explaining the situation instead of crashing (documented).     */
/* ------------------------------------------------------------------ */

const STATIC_FILES: Record<string, { file: string; contentType: string }> = {
  "/": { file: "index.html", contentType: "text/html; charset=utf-8" },
  "/index.html": { file: "index.html", contentType: "text/html; charset=utf-8" },
  "/app.js": { file: "app.js", contentType: "text/javascript; charset=utf-8" },
};

function resolveDashboardDir(): string | null {
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.join(moduleDir, "..", "dashboard"),
    path.join(moduleDir, "..", "..", "..", "src", "cloud", "dashboard"),
    path.join(process.cwd(), "src", "cloud", "dashboard"),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "index.html"))) return dir;
  }
  return null;
}

const FALLBACK_HTML = `<!doctype html><html><body style="font-family:sans-serif;max-width:40em;margin:4em auto">
<h1>ScopeGate Cloud</h1>
<p>The dashboard assets (<code>src/cloud/dashboard/</code>) are not present in
this installation — the management API under <code>/v1</code> is fully
functional regardless. Reinstall from a full checkout to get the dashboard.</p>
</body></html>`;

function serveDashboard(res: http.ServerResponse, pathname: string): boolean {
  const entry = STATIC_FILES[pathname];
  if (!entry) return false;
  const dir = resolveDashboardDir();
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
  const store = new FileStore(home);
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
            serveDashboard(res, url.pathname)) {
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
    `[scopegate-cloud] dashboard at http://127.0.0.1:${port}/ — data home: ${home}`,
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
