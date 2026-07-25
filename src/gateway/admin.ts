/**
 * Admin surface (`/admin/*`) — the write path for a human console.
 *
 * Why a SEPARATE surface with a SEPARATE credential:
 *
 * The agent talks to the gateway with `SCOPEGATE_HTTP_TOKEN`. If administration
 * lived behind that same bearer, an agent could grant itself capabilities,
 * approve its own escalations or rewrite the policies that constrain it — the
 * whole point of ScopeGate would be gone. So `/admin/*` requires
 * `SCOPEGATE_ADMIN_TOKEN` and EXPLICITLY rejects the agent bearer, even though
 * both arrive in the same header.
 *
 * Invariants enforced here:
 *   1. Secret VALUES only travel inbound. `GET /admin/secrets` returns names,
 *      a sha256[:8] fingerprint and rotation dates — never the value, not even
 *      masked. There is no endpoint that reads a secret back.
 *   2. Every mutation carries `X-ScopeGate-Actor` (the human's account id from
 *      the console) and lands in the audit log as `human:console:<actor>`.
 *      "console" alone is not an actor: the header is required.
 *   3. Policy writes are validated before they touch disk, and the previous
 *      file is kept alongside so a bad edit is recoverable.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { audit } from "../audit/log.js";
import { POLICIES_PATH, ensureDir } from "../config/config.js";
import { validatePoliciesFile } from "../policy/engine.js";
import { listApprovals } from "../policy/approvals.js";
import { approveRequest, denyRequest, approvalsForReview } from "../commands/approvals-cli.js";
import type { Vault } from "../vault/vault.js";
import { log } from "./proxy.js";

export interface AdminContext {
  vault: Vault;
  /** Live grants + leases, same source the agent-facing tool uses. */
  capabilities: () => { active_grants: unknown[]; leases: unknown[] };
  /** Revoke a grant/lease by id. Returns false when the id is unknown. */
  revokeCapability: (id: string) => boolean;
  /** Upstream names declared in the running config. */
  upstreamNames: () => string[];
  /** Which upstreams reference a given secret ref (blocks unsafe deletes). */
  upstreamsUsingSecret: (ref: string) => string[];
  /** Ask the gateway to reload config + policies after a write. */
  reload: () => Promise<void>;
}

export interface AdminAuth {
  /** SCOPEGATE_ADMIN_TOKEN. When empty the whole surface answers 503. */
  adminToken: string;
  /** The agent bearer — rejected here on purpose (see file header). */
  agentToken: string;
}

const ACTOR_HEADER = "x-scopegate-actor";

export interface AdminResult {
  status: number;
  body: unknown;
}

const ok = (body: unknown): AdminResult => ({ status: 200, body });
const bad = (status: number, error: string): AdminResult => ({ status, body: { error } });

/** sha256[:8] of a secret value — lets a human verify a rotation happened. */
export function fingerprint(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 8);
}

function timingSafeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

/**
 * Authorizes an /admin request. Returns the actor on success.
 *
 * A request carrying the AGENT bearer is rejected with a message that names
 * the reason: silently 401-ing would send someone hunting a config problem
 * when the real answer is "this credential must never work here".
 */
export function authorizeAdmin(
  req: IncomingMessage,
  auth: AdminAuth,
  mutating: boolean,
): { ok: true; actor: string } | { ok: false; result: AdminResult } {
  if (auth.adminToken === "") {
    return {
      ok: false,
      result: bad(503, "Admin surface disabled: set SCOPEGATE_ADMIN_TOKEN to enable it."),
    };
  }
  const header = req.headers.authorization ?? "";
  const presented = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (presented === "") {
    return { ok: false, result: bad(401, "Send `Authorization: Bearer <SCOPEGATE_ADMIN_TOKEN>`.") };
  }
  if (auth.agentToken !== "" && timingSafeEqual(presented, auth.agentToken)) {
    return {
      ok: false,
      result: bad(
        403,
        "The agent bearer is not accepted on /admin: administration must not be reachable " +
          "with the same credential the agent uses, or an agent could approve itself.",
      ),
    };
  }
  if (!timingSafeEqual(presented, auth.adminToken)) {
    return { ok: false, result: bad(401, "Invalid admin credentials.") };
  }
  const actor = String(req.headers[ACTOR_HEADER] ?? "").trim();
  if (mutating && actor === "") {
    return {
      ok: false,
      result: bad(
        400,
        "Mutations require `X-ScopeGate-Actor` with the human's account id — every change is attributed.",
      ),
    };
  }
  return { ok: true, actor: actor === "" ? "unknown" : actor };
}

/** Audit label for a console-originated action. */
export function decidedByConsole(actor: string): string {
  return `human:console:${actor}`;
}

/**
 * Routes `/admin/*`. Returns null when the path is not an admin path so the
 * caller can continue with the rest of the routes.
 */
export async function routeAdmin(
  req: IncomingMessage,
  _res: ServerResponse,
  body: unknown,
  ctx: AdminContext,
  auth: AdminAuth,
): Promise<AdminResult | null> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const p = url.pathname;
  if (!p.startsWith("/admin")) return null;

  const method = (req.method ?? "GET").toUpperCase();
  const mutating = method !== "GET";
  const authorized = authorizeAdmin(req, auth, mutating);
  if (!authorized.ok) return authorized.result;
  const { actor } = authorized;

  try {
    // --- secrets ----------------------------------------------------------
    if (p === "/admin/secrets" && method === "GET") {
      const refs = ctx.vault.listRefs();
      return ok({
        secrets: refs.map((ref) => ({
          ref,
          // The value never leaves; the fingerprint is enough to confirm a rotation.
          fingerprint: safeFingerprint(ctx, ref),
          usedBy: ctx.upstreamsUsingSecret(ref),
        })),
      });
    }

    const secretMatch = /^\/admin\/secrets\/([\w.-]+)$/.exec(p);
    if (secretMatch) {
      const ref = secretMatch[1];
      if (method === "PUT") {
        const value = (body as { value?: unknown } | null)?.value;
        if (typeof value !== "string" || value === "") {
          return bad(400, "Body must be {\"value\": \"<secret>\"} with a non-empty string.");
        }
        const existed = ctx.vault.has(ref);
        ctx.vault.set(ref, value);
        await ctx.reload();
        audit(decidedByConsole(actor), existed ? "secret_rotated" : "secret_added", {
          ref,
          fingerprint: fingerprint(value),
        });
        log("info", `secret '${ref}' ${existed ? "rotated" : "added"} from the console`, { actor });
        return ok({ ref, rotated: existed, added: !existed, fingerprint: fingerprint(value) });
      }
      if (method === "DELETE") {
        const users = ctx.upstreamsUsingSecret(ref);
        if (users.length > 0) {
          return bad(409, `Refusing to delete '${ref}': still referenced by ${users.join(", ")}.`);
        }
        if (!ctx.vault.has(ref)) return bad(404, `Unknown secret '${ref}'.`);
        ctx.vault.delete(ref);
        await ctx.reload();
        audit(decidedByConsole(actor), "secret_deleted", { ref });
        return ok({ ref, deleted: true });
      }
      return bad(405, "Method not allowed on this secret.");
    }

    // --- capabilities -----------------------------------------------------
    if (p === "/admin/capabilities" && method === "GET") {
      return ok(ctx.capabilities());
    }
    const capMatch = /^\/admin\/capabilities\/([\w:.*/-]+)$/.exec(p);
    if (capMatch && method === "DELETE") {
      const id = decodeURIComponent(capMatch[1]);
      const revoked = ctx.revokeCapability(id);
      if (!revoked) return bad(404, `Unknown capability or lease '${id}'.`);
      // Reutiliza el kind existente: la lista de auditoría es append-only y
      // grants_revoked ya describe exactamente esto.
      audit(decidedByConsole(actor), "grants_revoked", { id, via: "console" });
      return ok({ id, revoked: true });
    }

    // --- approvals --------------------------------------------------------
    if (p === "/admin/approvals" && method === "GET") {
      const all = url.searchParams.get("all") === "true";
      return ok({ approvals: approvalsForReview(all) });
    }
    const apprMatch = /^\/admin\/approvals\/([\w-]+)$/.exec(p);
    if (apprMatch && method === "POST") {
      const id = apprMatch[1];
      const b = (body ?? {}) as { decision?: string; reason?: string; ttl?: string };
      const origin = { console: actor };
      if (b.decision === "approve") {
        // Origin `console` beats the old SCOPEGATE_APPROVAL_TOKEN path: that
        // one proves "some shell", this one names the person.
        const res = approveRequest({
          id,
          origin,
          ...(b.ttl !== undefined ? { ttl: b.ttl } : {}),
        });
        return ok({ id, decision: "approved", alreadyDecided: res.alreadyDecided });
      }
      if (b.decision === "deny") {
        const res = denyRequest({ id, origin, reason: b.reason ?? "denegado desde la consola" });
        return ok({ id, decision: "denied", alreadyDecided: res.alreadyDecided });
      }
      return bad(400, 'Body must be {"decision": "approve" | "deny", "reason"?: string}.');
    }

    // --- policies ---------------------------------------------------------
    if (p === "/admin/policies") {
      if (method === "GET") {
        const raw = fs.existsSync(POLICIES_PATH) ? fs.readFileSync(POLICIES_PATH, "utf8") : "";
        return ok({ path: POLICIES_PATH, raw });
      }
      if (method === "PUT") {
        const raw = (body as { raw?: unknown } | null)?.raw;
        if (typeof raw !== "string" || raw.trim() === "") {
          return bad(400, 'Body must be {"raw": "<policies.yaml>"}.');
        }
        let parsed: unknown;
        try {
          const YAML = await import("yaml");
          parsed = YAML.parse(raw);
        } catch (e) {
          return bad(422, `Not valid YAML: ${e instanceof Error ? e.message : String(e)}`);
        }
        try {
          validatePoliciesFile(parsed);
        } catch (e) {
          return bad(422, `Invalid policies: ${e instanceof Error ? e.message : String(e)}`);
        }
        // Keep the previous file next to the new one: a bad edit stays
        // recoverable without digging through the volume.
        if (fs.existsSync(POLICIES_PATH)) {
          fs.copyFileSync(POLICIES_PATH, `${POLICIES_PATH}.prev`);
        }
        ensureDir();
        fs.writeFileSync(POLICIES_PATH, raw, { mode: 0o600 });
        await ctx.reload();
        audit(decidedByConsole(actor), "policy_accepted", { via: "console" });
        log("info", "policies updated from the console", { actor });
        return ok({ applied: true, backup: `${POLICIES_PATH}.prev` });
      }
      return bad(405, "Method not allowed on /admin/policies.");
    }

    // --- upstreams --------------------------------------------------------
    if (p === "/admin/upstreams" && method === "GET") {
      return ok({ upstreams: ctx.upstreamNames() });
    }

    // --- summary (one call for the console's first paint) -----------------
    if (p === "/admin/summary" && method === "GET") {
      return ok({
        secrets: ctx.vault.listRefs().map((ref) => ({
          ref,
          fingerprint: safeFingerprint(ctx, ref),
          usedBy: ctx.upstreamsUsingSecret(ref),
        })),
        upstreams: ctx.upstreamNames(),
        capabilities: ctx.capabilities(),
        pendingApprovals: listApprovals().filter((a) => a.effectiveStatus === "pending").length,
      });
    }

    return bad(404, `Unknown admin route '${p}'.`);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log("error", "admin route failed", { path: p, error: msg });
    // The message can carry vault/file detail — never echo it to the client.
    return bad(500, "Admin operation failed; check the gateway logs.");
  }
}

/** Fingerprint without letting a vault error take the whole listing down. */
function safeFingerprint(ctx: AdminContext, ref: string): string | null {
  try {
    return fingerprint(ctx.vault.get(ref));
  } catch {
    return null;
  }
}
