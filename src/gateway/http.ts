/**
 * HTTP transport for the agent-facing gateway (Sprint 6): the SAME MCP
 * server as stdio mode, served over the MCP Streamable HTTP transport for
 * networked deployments (Railway, Docker).
 *
 * Decisions (part of the sprint contract):
 * - STATELESS sessions (sessionIdGenerator: undefined): a fresh Server +
 *   transport per request. There is no in-memory session map, so container
 *   redeploys and multi-replica rollouts never strand a client on a dead
 *   session id (a stateful gateway would answer 404 after every deploy).
 *   The gateway is single-tenant — one agent identity per instance — so
 *   per-session state buys nothing. The per-request cost is just handler
 *   registration: all expensive state (upstream connections, vault, policy)
 *   is shared through the createAgentServer closure.
 * - AuthN: EVERY request except GET /health requires
 *   `Authorization: Bearer $SCOPEGATE_HTTP_TOKEN` (timing-safe compare).
 *   The env var is MANDATORY in http mode: startup aborts without it
 *   (fail-closed — a gateway on a network port must never be unauthenticated).
 * - GET /health is UNAUTHENTICATED (Docker HEALTHCHECK / Railway probe) and
 *   leaks nothing: { status, uptime_s, upstreams: <connected count> }.
 * - Logs go to stderr ONLY. stdout carries exactly one parseable line at
 *   boot: `SCOPEGATE_HTTP_LISTENING port=<n>` (contract with e2e-http.mjs).
 */
import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { log, errorMessage } from "./proxy.js";
import { routeAdmin, type AdminContext } from "./admin.js";

/** Hard cap on a single JSON-RPC body (generous for tool args). */
const MAX_BODY_BYTES = 4 * 1024 * 1024;
/** MCP endpoint path (the hosted-MCP convention; mirrors fake-upstream). */
export const MCP_PATH = "/mcp";

export interface HttpGatewayContext {
  /**
   * Factory for the configured agent-facing MCP server (one per request).
   * M4: receives the per-request logical agent identity (from the validated
   * `X-ScopeGate-Agent` header, or undefined for the gateway default).
   */
  createAgentServer: (agentId?: string) => Server;
  /**
   * M4: the logical agent ids accepted on `X-ScopeGate-Agent` (the policies'
   * agent sections + the gateway default). Unknown ids are 403 — the header
   * names work units (thread/task), it is not an auth credential.
   */
  allowedAgents: () => string[];
  /** Live count of connected upstreams, surfaced by /health. */
  connectedUpstreams: () => number;
  /**
   * M12: readiness details for /health — additive fields
   * (upstreams stays a number for existing probes).
   */
  readiness?: () => {
    upstreams_detail: { ok: number; failed: string[] };
    vault_mode: string;
    pending_approvals: number;
  };
  /** M12: metadata-only event tail for GET /events (NDJSON, bearer-required). */
  recentEvents?: (opts: { since?: string; limit: number }) => Record<string, unknown>[];
  /** Write path for a human console (/admin/*). Absent → 501. */
  admin?: AdminContext;
  /** Transport-independent cleanup (cloud sync, policy watcher, proxy). */
  shutdown: () => Promise<void>;
}

export interface HttpGatewayOptions {
  /** Listen port. 0 = ephemeral (tests/e2e); the real port is on the handle. */
  port: number;
  /** Bind host (e.g. 127.0.0.1 local, 0.0.0.0 in a container). */
  host: string;
  /** Bearer token. Default: process.env.SCOPEGATE_HTTP_TOKEN (required). */
  token?: string;
}

export interface HttpGatewayHandle {
  port: number;
  host: string;
  /** Idempotent: closes the listener and runs the gateway cleanup. */
  close: () => Promise<void>;
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

/**
 * Resolve the http-mode bearer (option overrides the env var) or throw an
 * actionable error — fail-closed: a gateway on a network port must never
 * run unauthenticated. Called early by runGateway AND re-checked here.
 */
export function requireHttpToken(option?: string): string {
  const token = (option ?? process.env.SCOPEGATE_HTTP_TOKEN ?? "").trim();
  if (!token) {
    throw new Error(
      "SCOPEGATE_HTTP_TOKEN is required in --http mode. " +
        "Set a long random token (e.g. `openssl rand -hex 32`) in the environment " +
        "and pass it to clients as `Authorization: Bearer <token>`.",
    );
  }
  return token;
}

function unauthorized(res: http.ServerResponse, message: string): void {
  sendJson(res, 401, { error: "unauthorized", message });
}

/** Constant-time bearer comparison (length-guarded; never throws). */
function bearerOk(header: string | undefined, token: string): boolean {
  const m = /^Bearer\s+(.+)$/.exec(header ?? "");
  if (!m) return false;
  const presented = Buffer.from(m[1], "utf8");
  const expected = Buffer.from(token, "utf8");
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/**
 * Reads the request body up to MAX_BODY_BYTES. On overflow the rest of the
 * upload is drained and discarded so the socket stays usable for the 413.
 */
function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let overflow = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES && !overflow) {
        overflow = true;
        req.removeAllListeners("data");
        req.resume(); // drain and discard
        reject(new Error("payload too large"));
        return;
      }
      if (!overflow) chunks.push(c);
    });
    req.on("end", () => {
      if (!overflow) resolve(Buffer.concat(chunks).toString("utf8"));
    });
    req.on("error", reject);
  });
}

export async function startHttpGateway(
  ctx: HttpGatewayContext,
  options: HttpGatewayOptions,
): Promise<HttpGatewayHandle> {
  // Fail-closed: no token configured → refuse to open a network port.
  const token = requireHttpToken(options.token);

  async function handle(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");

    // Public liveness/readiness probe (Docker HEALTHCHECK / Railway).
    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, {
        status: "ok",
        uptime_s: Math.round(process.uptime()),
        upstreams: ctx.connectedUpstreams(),
        // M12: readiness detail (additive — upstreams stays a number).
        ...(ctx.readiness ? ctx.readiness() : {}),
      });
      return;
    }

    // Public curl|sh installer — no secret inside by design (it installs the
    // public npm package). Served from <pkg>/install/install.sh.
    if (req.method === "GET" && url.pathname === "/install.sh") {
      const installerPath = fileURLToPath(
        new URL("../../install/install.sh", import.meta.url),
      );
      try {
        const body = readFileSync(installerPath, "utf8");
        res.writeHead(200, {
          "content-type": "text/x-sh; charset=utf-8",
          "cache-control": "public, max-age=300",
        });
        res.end(body);
      } catch {
        sendJson(res, 404, {
          error: "not_found",
          message: "Installer not bundled in this build.",
        });
      }
      return;
    }

    // Admin surface: its OWN credential, checked before the agent bearer gate
    // so the agent token is rejected with a reason instead of silently passing
    // into MCP routing. See gateway/admin.ts for why they must stay separate.
    if (url.pathname.startsWith("/admin")) {
      if (!ctx.admin) {
        sendJson(res, 501, {
          error: "not_implemented",
          message: "admin surface is not wired on this gateway.",
        });
        return;
      }
      let body: unknown = null;
      if (req.method !== "GET" && req.method !== "DELETE") {
        try {
          const raw = await readBody(req);
          body = raw.trim() === "" ? null : JSON.parse(raw);
        } catch {
          sendJson(res, 400, { error: "bad_request", message: "Body must be valid JSON." });
          return;
        }
      }
      const result = await routeAdmin(req, res, body, ctx.admin, {
        adminToken: (process.env.SCOPEGATE_ADMIN_TOKEN ?? "").trim(),
        agentToken: token,
      });
      if (result !== null) {
        sendJson(res, result.status, result.body);
        return;
      }
    }

    // Everything else is MCP and requires the bearer (fail-closed).
    if (!bearerOk(req.headers.authorization, token)) {
      unauthorized(
        res,
        "Missing or invalid credentials. Send `Authorization: Bearer <SCOPEGATE_HTTP_TOKEN>`.",
      );
      return;
    }

    // M12: host-observability event tail (NDJSON, metadata only — never
    // payloads). Poll with ?since=<ISO> for incremental reads.
    if (req.method === "GET" && url.pathname === "/events") {
      if (!ctx.recentEvents) {
        sendJson(res, 501, { error: "not_implemented", message: "events are not wired on this gateway." });
        return;
      }
      const since = url.searchParams.get("since") ?? undefined;
      const limitRaw = Number(url.searchParams.get("limit") ?? 100);
      const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? limitRaw : 100, 1), 500);
      const events = ctx.recentEvents({ since, limit });
      res.writeHead(200, {
        "content-type": "application/x-ndjson; charset=utf-8",
        "cache-control": "no-store",
      });
      res.end(events.map((e) => JSON.stringify(e)).join("\n") + (events.length > 0 ? "\n" : ""));
      return;
    }

    // M4: per-request logical identity. `X-ScopeGate-Agent` names the work
    // unit (thread/task) for grants, audit and approvals — validated against
    // the gateway's allowlist (it is attribution, not authentication: the
    // bearer remains the perimeter).
    let agentId: string | undefined;
    const agentHeader = req.headers["x-scopegate-agent"];
    if (typeof agentHeader === "string" && agentHeader.trim().length > 0) {
      const candidate = agentHeader.trim();
      if (!ctx.allowedAgents().includes(candidate)) {
        sendJson(res, 403, {
          error: "unknown_agent",
          message: `Agent '${candidate}' is not in this gateway's allowlist (see policies.yaml agents + the default identity).`,
        });
        return;
      }
      agentId = candidate;
    }

    if (url.pathname !== MCP_PATH) {
      sendJson(res, 404, {
        error: "not_found",
        message: `Unknown path '${url.pathname}'. The MCP endpoint is ${MCP_PATH}; the health probe is GET /health.`,
      });
      return;
    }

    let parsedBody: unknown;
    if (req.method === "POST") {
      let raw: string;
      try {
        raw = await readBody(req);
      } catch {
        sendJson(res, 413, {
          jsonrpc: "2.0",
          error: { code: -32000, message: `Payload too large (max ${MAX_BODY_BYTES} bytes).` },
          id: null,
        });
        return;
      }
      try {
        parsedBody = raw ? JSON.parse(raw) : undefined;
      } catch {
        sendJson(res, 400, {
          jsonrpc: "2.0",
          error: { code: -32700, message: "Parse error: body must be valid JSON-RPC." },
          id: null,
        });
        return;
      }
    }

    // Stateless mode: the SDK forbids reusing a stateless transport across
    // requests — fresh Server + transport per request, closed with the
    // response (same pattern as fake-upstream.mjs --http). M4: the server is
    // built with the request's logical identity (or the gateway default).
    const server = ctx.createAgentServer(agentId);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  }

  const httpServer = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      log("error", `http request failed: ${errorMessage(e)}`, {
        stack: e instanceof Error ? e.stack : undefined,
      });
      if (!res.headersSent) sendJson(res, 500, { error: "internal_error" });
    });
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(options.port, options.host, () => resolve());
  });
  const address = httpServer.address();
  const port =
    typeof address === "object" && address !== null ? address.port : options.port;

  // The ONLY stdout line in http mode — parseable contract with e2e/CI.
  console.log(`SCOPEGATE_HTTP_LISTENING port=${port}`);
  log(
    "info",
    `http transport listening on ${options.host}:${port} (mcp=${MCP_PATH}, health=/health)`,
  );

  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await ctx.shutdown();
  };
  const onSignal = () => {
    void close().finally(() => process.exit(0));
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  return { port, host: options.host, close };
}
