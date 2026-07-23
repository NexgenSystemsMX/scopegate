/**
 * HTTP router for the ScopeGate Cloud control plane (EPIC-10).
 *
 * Auth model — `Authorization: Bearer <token>` with THREE token scopes:
 *   - ADMIN scope: the server admin token (env ADMIN_TOKEN, default
 *     'dev-admin-token' — DEV ONLY, warned at boot) OR an identity from the
 *     SSO adapter (sso.ts; dev impl: X-Admin-Token header). Admin can do
 *     everything, including reading agent-scope endpoints.
 *   - AGENT scope: the agentSecret issued at enroll — authenticates exactly
 *     one agent; teamId params must match its team, and audit batches must
 *     carry its own agentId.
 *   - TEAM scope: the team enrollToken — authenticates team-level reads
 *     (policy pull, revocations feed, billing) and batches of any agent
 *     enrolled in that team.
 * POST /v1/enroll needs no Bearer: the enrollToken travels in the body.
 *
 * Comparisons are constant-time. No cookies, no CORS headers: the dashboard
 * is served same-origin and the API is not meant for cross-origin browsers.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual, createHash, randomBytes } from "node:crypto";
import type { Alerter } from "./alerts.js";
import { billingUsage } from "./billing.js";
import { enrollAgent, hashAgentSecret } from "./enroll.js";
import { ingestBatch, type IngestHooks } from "./ingest.js";
import type { CloudIdentity } from "./keys.js";
import {
  asNonEmptyString,
  badRequest,
  forbidden,
  HttpError,
  isRecord,
  notFound,
  unauthorized,
  type Agent,
  type Team,
} from "./model.js";
import { getPolicy, putPolicy } from "./policies.js";
import { addRevocation, listRevocations } from "./revocations.js";
import type { SsoAdapter } from "./sso.js";
import type { Store } from "./store.js";

export interface RouterDeps {
  store: Store;
  cloudIdentity: CloudIdentity;
  adminToken: string;
  sso: SsoAdapter;
  alerter: Alerter;
}

const MAX_BODY_BYTES = 8 * 1024 * 1024; // 8 MiB — audit batches can be chunky

type Auth =
  | { kind: "admin" }
  | { kind: "agent"; agent: Agent }
  | { kind: "team"; team: Team }
  | { kind: "none" };

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  // Hash both sides so the compare never leaks the expected length.
  const ha = createHash("sha256").update(ba).digest();
  const hb = createHash("sha256").update(bb).digest();
  return timingSafeEqual(ha, hb);
}

function bearerToken(req: IncomingMessage): string | null {
  const h = req.headers.authorization;
  if (typeof h !== "string" || !h.startsWith("Bearer ")) return null;
  const token = h.slice("Bearer ".length).trim();
  return token.length > 0 ? token : null;
}

function authenticate(req: IncomingMessage, deps: RouterDeps): Auth {
  const token = bearerToken(req);
  if (token !== null) {
    if (safeEqual(token, deps.adminToken)) return { kind: "admin" };
    const agent = deps.store.findAgentBySecretHash(hashAgentSecret(token));
    if (agent) return { kind: "agent", agent };
    const team = deps.store.findTeamByEnrollToken(token);
    if (team) return { kind: "team", team };
  }
  // SSO adapter (admin-equivalent in this dev-grade plane — see sso.ts).
  if (deps.sso.authenticate(req) !== null) return { kind: "admin" };
  return { kind: "none" };
}

/** Require admin scope. */
function requireAdmin(auth: Auth): void {
  if (auth.kind !== "admin") {
    throw auth.kind === "none" ? unauthorized() : forbidden("admin scope required");
  }
}

/**
 * Require access to `teamId`: admin, the team's own enrollToken, or an agent
 * of that team. Returns the acting agent when agent-scoped (null otherwise).
 */
function requireTeamAccess(auth: Auth, teamId: string): Agent | null {
  switch (auth.kind) {
    case "admin":
      return null;
    case "team":
      if (auth.team.teamId === teamId) return null;
      break;
    case "agent":
      if (auth.agent.teamId === teamId) return auth.agent;
      break;
  }
  throw auth.kind === "none" ? unauthorized() : forbidden("wrong team scope");
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) {
      throw new HttpError(413, "request body too large", "body_too_large");
    }
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw badRequest("body is not valid JSON");
  }
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

/** Public agent shape — never leaks secretHash. */
function publicAgent(a: Agent) {
  return {
    agentId: a.agentId,
    teamId: a.teamId,
    fingerprint: a.fingerprint,
    hasPubkey: a.publicKey !== undefined,
    enrolledAt: a.enrolledAt,
    lastSeen: a.lastSeen,
    revoked: a.revoked,
    ...(a.revokedAt ? { revokedAt: a.revokedAt } : {}),
  };
}

/**
 * Route one API request. Returns true when the request was handled here;
 * false when the path is not an API route (the caller falls through to the
 * dashboard static handler). Throws HttpError for expected client errors.
 */
export async function handleApiRequest(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  deps: RouterDeps,
): Promise<boolean> {
  const path = url.pathname;
  if (path !== "/v1" && !path.startsWith("/v1/")) return false;
  const method = req.method ?? "GET";
  const { store, cloudIdentity } = deps;

  // -- open: cloud public key (public material by definition) --------------
  if (method === "GET" && path === "/v1/pubkey") {
    sendJson(res, 200, {
      cloudPubkey: cloudIdentity.publicKey,
      fingerprint: cloudIdentity.fingerprint,
    });
    return true;
  }

  // -- enroll: enrollToken in the body IS the credential --------------------
  if (method === "POST" && path === "/v1/enroll") {
    const result = enrollAgent(store, cloudIdentity, await readJsonBody(req));
    sendJson(res, 200, result);
    return true;
  }

  const auth = authenticate(req, deps);

  // -- agent-scope: team policy pull ----------------------------------------
  if (method === "GET" && path === "/v1/policy") {
    const teamId = asNonEmptyString(url.searchParams.get("teamId"));
    if (!teamId) throw badRequest("teamId query param is required");
    requireTeamAccess(auth, teamId);
    sendJson(res, 200, getPolicy(store, teamId));
    return true;
  }

  // -- agent-scope: audit ingest --------------------------------------------
  if (method === "POST" && path === "/v1/audit/batch") {
    const body = await readJsonBody(req);
    const agentId = isRecord(body) ? asNonEmptyString(body.agentId) : null;
    let team: Team;
    if (auth.kind === "admin") {
      // Admin can push on behalf of any enrolled agent (dashboard/SIEM tools).
      if (!agentId) throw badRequest("agentId is required");
      const agent = store
        .listTeams()
        .map((t) => store.getAgent(t.teamId, agentId))
        .find((a) => a !== undefined);
      if (!agent) throw notFound(`agent ${agentId} is not enrolled`);
      team = store.getTeam(agent.teamId)!;
    } else if (auth.kind === "agent") {
      if (agentId !== null && agentId !== auth.agent.agentId) {
        throw forbidden("agent credentials cannot ingest for another agent");
      }
      team = store.getTeam(auth.agent.teamId)!;
    } else if (auth.kind === "team") {
      team = auth.team;
    } else {
      throw unauthorized();
    }
    const hooks: IngestHooks = {
      onAcceptedEvents: (t, events) => deps.alerter.onAcceptedEvents(t, events),
      onChainGap: (t, a, detail) => deps.alerter.onChainGap(t, a, detail),
    };
    sendJson(res, 200, ingestBatch(store, team, body, hooks));
    return true;
  }

  // -- agent-scope: revocations feed -----------------------------------------
  if (method === "GET" && path === "/v1/revocations") {
    const teamId = asNonEmptyString(url.searchParams.get("teamId"));
    if (!teamId) throw badRequest("teamId query param is required");
    requireTeamAccess(auth, teamId);
    const since = asNonEmptyString(url.searchParams.get("since")) ?? undefined;
    sendJson(res, 200, { revocations: listRevocations(store, teamId, since) });
    return true;
  }

  // -- agent-scope: billing usage --------------------------------------------
  if (method === "GET" && path === "/v1/billing/usage") {
    const teamId = asNonEmptyString(url.searchParams.get("teamId"));
    if (!teamId) throw badRequest("teamId query param is required");
    requireTeamAccess(auth, teamId);
    const month = asNonEmptyString(url.searchParams.get("month")) ?? undefined;
    sendJson(res, 200, billingUsage(store, teamId, month));
    return true;
  }

  // -- admin scope ------------------------------------------------------------
  if (path.startsWith("/v1/admin/")) {
    requireAdmin(auth);

    if (method === "POST" && path === "/v1/admin/teams") {
      const body = await readJsonBody(req);
      const name = isRecord(body) ? asNonEmptyString(body.name) : null;
      if (!name) throw badRequest("name is required");
      const team: Team = {
        teamId: "team-" + randomBytes(9).toString("hex"),
        name,
        enrollToken: "sge_" + randomBytes(24).toString("base64url"),
        createdAt: new Date().toISOString(),
      };
      store.createTeam(team);
      sendJson(res, 201, { teamId: team.teamId, enrollToken: team.enrollToken });
      return true;
    }

    if (method === "GET" && path === "/v1/admin/teams") {
      sendJson(res, 200, {
        teams: store.listTeams().map((t) => ({
          teamId: t.teamId,
          name: t.name,
          enrollToken: t.enrollToken,
          createdAt: t.createdAt,
          slackWebhookConfigured: t.slackWebhookUrl !== undefined,
          agentCount: store.listAgents(t.teamId).length,
        })),
      });
      return true;
    }

    if (method === "PUT" && path === "/v1/admin/policy") {
      sendJson(res, 200, putPolicy(store, cloudIdentity, await readJsonBody(req)));
      return true;
    }

    if (method === "POST" && path === "/v1/admin/revocations") {
      sendJson(res, 201, addRevocation(store, await readJsonBody(req)));
      return true;
    }

    if (method === "GET" && path === "/v1/admin/agents") {
      const teamId = asNonEmptyString(url.searchParams.get("teamId"));
      if (!teamId) throw badRequest("teamId query param is required");
      if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);
      sendJson(res, 200, { agents: store.listAgents(teamId).map(publicAgent) });
      return true;
    }

    if (method === "GET" && path === "/v1/admin/audit") {
      const teamId = asNonEmptyString(url.searchParams.get("teamId"));
      if (!teamId) throw badRequest("teamId query param is required");
      if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);
      const limitRaw = asNonEmptyString(url.searchParams.get("limit"));
      const limit = limitRaw ? Number(limitRaw) : undefined;
      if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) {
        throw badRequest("limit must be a positive integer");
      }
      sendJson(res, 200, {
        events: store.queryAuditEvents(teamId, {
          agentId: asNonEmptyString(url.searchParams.get("agentId")) ?? undefined,
          kind: asNonEmptyString(url.searchParams.get("kind")) ?? undefined,
          since: asNonEmptyString(url.searchParams.get("since")) ?? undefined,
          limit,
        }),
      });
      return true;
    }

    if (method === "POST" && path === "/v1/admin/alerts") {
      const body = await readJsonBody(req);
      const teamId = isRecord(body) ? asNonEmptyString(body.teamId) : null;
      const webhookUrl = isRecord(body) ? asNonEmptyString(body.webhookUrl) : null;
      if (!teamId) throw badRequest("teamId is required");
      if (!webhookUrl) throw badRequest("webhookUrl is required");
      if (!/^https?:\/\//.test(webhookUrl)) {
        throw badRequest("webhookUrl must be an http(s) URL");
      }
      if (!store.getTeam(teamId)) throw notFound(`no such team: ${teamId}`);
      store.updateTeam(teamId, { slackWebhookUrl: webhookUrl });
      sendJson(res, 200, { ok: true, teamId, slackWebhookConfigured: true });
      return true;
    }

    throw notFound(`unknown admin route: ${method} ${path}`);
  }

  throw notFound(`unknown route: ${method} ${path}`);
}
