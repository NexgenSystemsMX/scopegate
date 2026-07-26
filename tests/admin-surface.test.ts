import { describe, expect, it, vi, beforeEach, afterAll } from "vitest";
import type { IncomingMessage } from "node:http";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import { authorizeAdmin, decidedByConsole, fingerprint, routeAdmin } from "../src/gateway/admin.js";
import type { AdminContext } from "../src/gateway/admin.js";

// Las mutaciones auditan, y auditar ESCRIBE en SCOPEGATE_HOME. Sin un home
// propio este archivo contaminaba el de los demás (hot-reload rompía justo
// después de él) y tocaría el ~/.scopegate real.
const HOME = useTempHome();
afterAll(() => {
  cleanupTempHome(HOME);
});

/**
 * La superficie /admin es el camino de ESCRITURA de la consola humana. Sus
 * tres invariantes son de seguridad, no de comodidad, así que se fijan aquí:
 *
 *   1. El bearer del agente NO sirve (si sirviera, un agente podría aprobarse
 *      a sí mismo y ScopeGate dejaría de significar nada).
 *   2. Ninguna respuesta devuelve el VALOR de un secreto.
 *   3. Toda mutación va atribuida a una persona (X-ScopeGate-Actor).
 */

const AGENT_TOKEN = "agent-bearer-xxxxxxxx";
const ADMIN_TOKEN = "admin-bearer-yyyyyyyy";
const auth = { adminToken: ADMIN_TOKEN, agentToken: AGENT_TOKEN };

function req(opts: { method?: string; url?: string; token?: string; actor?: string }): IncomingMessage {
  return {
    method: opts.method ?? "GET",
    url: opts.url ?? "/admin/secrets",
    headers: {
      ...(opts.token !== undefined ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.actor !== undefined ? { "x-scopegate-actor": opts.actor } : {}),
    },
  } as unknown as IncomingMessage;
}

function ctx(over: Partial<AdminContext> = {}): AdminContext {
  const store = new Map<string, string>([["github_app_key", "-----BEGIN KEY-----super-secreto"]]);
  return {
    vault: {
      listRefs: () => [...store.keys()],
      get: (r: string) => store.get(r) ?? "",
      has: (r: string) => store.has(r),
      set: (r: string, v: string) => store.set(r, v),
      delete: (r: string) => store.delete(r),
    } as never,
    capabilities: () => ({ active_grants: [], leases: [] }),
    revokeCapability: () => true,
    upstreamNames: () => ["nexgen", "railway"],
    agents: () => [
      { agentId: "nexgen-kimi", defaultTtl: "15m", rules: 20, activeGrants: 0 },
      { agentId: "git", defaultTtl: "10m", rules: 1, activeGrants: 0 },
    ],
    upstreamsUsingSecret: () => [],
    reload: async () => {},
    ...over,
  };
}

const res = {} as never;

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("invariante 1: el bearer del agente no entra en /admin", () => {
  it("rechaza con 403 y explica por qué", () => {
    const r = authorizeAdmin(req({ token: AGENT_TOKEN }), auth, false);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.result.status).toBe(403);
      expect(JSON.stringify(r.result.body)).toContain("approve itself");
    }
  });

  it("acepta el token de administración", () => {
    const r = authorizeAdmin(req({ token: ADMIN_TOKEN }), auth, false);
    expect(r.ok).toBe(true);
  });

  it("401 sin credencial y 401 con una equivocada", () => {
    expect(authorizeAdmin(req({}), auth, false).ok).toBe(false);
    expect(authorizeAdmin(req({ token: "otra-cosa-distinta" }), auth, false).ok).toBe(false);
  });

  it("503 cuando la superficie no está habilitada", () => {
    const r = authorizeAdmin(req({ token: ADMIN_TOKEN }), { adminToken: "", agentToken: AGENT_TOKEN }, false);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.result.status).toBe(503);
  });
});

describe("invariante 2: los valores de los secretos no salen", () => {
  it("GET /admin/secrets devuelve huella, nunca el valor", async () => {
    const out = await routeAdmin(req({ token: ADMIN_TOKEN }), res, null, ctx(), auth);
    const body = JSON.stringify(out?.body);
    expect(body).toContain("github_app_key");
    expect(body).toContain(fingerprint("-----BEGIN KEY-----super-secreto"));
    expect(body).not.toContain("super-secreto");
    expect(body).not.toContain("BEGIN KEY");
  });

  it("no existe ninguna ruta que lea un secreto de vuelta", async () => {
    const out = await routeAdmin(
      req({ method: "GET", url: "/admin/secrets/github_app_key", token: ADMIN_TOKEN }),
      res,
      null,
      ctx(),
      auth,
    );
    expect(out?.status).toBe(405)
  });

  it("la respuesta del alta confirma con la huella, no con el valor", async () => {
    const out = await routeAdmin(
      req({ method: "PUT", url: "/admin/secrets/railway_token", token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      { value: "rw-token-secreto" },
      ctx(),
      auth,
    );
    expect(out?.status).toBe(200)
    const body = JSON.stringify(out?.body)
    expect(body).toContain(fingerprint("rw-token-secreto"))
    expect(body).not.toContain("rw-token-secreto")
  });
});

describe("invariante 3: toda mutación va atribuida", () => {
  it("rechaza una mutación sin actor", async () => {
    const out = await routeAdmin(
      req({ method: "PUT", url: "/admin/secrets/x", token: ADMIN_TOKEN }),
      res,
      { value: "v" },
      ctx(),
      auth,
    );
    expect(out?.status).toBe(400);
    expect(JSON.stringify(out?.body)).toContain("X-ScopeGate-Actor");
  });

  it("las lecturas no exigen actor", async () => {
    const out = await routeAdmin(req({ token: ADMIN_TOKEN }), res, null, ctx(), auth);
    expect(out?.status).toBe(200);
  });

  it("la etiqueta de auditoría nombra a la persona", () => {
    expect(decidedByConsole("9b204adb")).toBe("human:console:9b204adb");
  });
});

describe("rutas", () => {
  it("devuelve null para rutas que no son de admin (el caller sigue)", async () => {
    const out = await routeAdmin(req({ url: "/health", token: ADMIN_TOKEN }), res, null, ctx(), auth);
    expect(out).toBeNull();
  });

  it("no borra un secreto que un upstream sigue usando", async () => {
    const out = await routeAdmin(
      req({ method: "DELETE", url: "/admin/secrets/github_app_key", token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      null,
      ctx({ upstreamsUsingSecret: () => ["nexgen"] }),
      auth,
    );
    expect(out?.status).toBe(409);
    expect(JSON.stringify(out?.body)).toContain("nexgen");
  });

  it("revocar una capacidad inexistente da 404", async () => {
    const out = await routeAdmin(
      req({ method: "DELETE", url: "/admin/capabilities/no-existe", token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      null,
      ctx({ revokeCapability: () => false }),
      auth,
    );
    expect(out?.status).toBe(404);
  });

  it("una política con YAML inválido se rechaza sin tocar disco", async () => {
    const out = await routeAdmin(
      req({ method: "PUT", url: "/admin/policies", token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      { raw: "esto: [no cierra" },
      ctx(),
      auth,
    );
    expect(out?.status).toBe(422);
  });

  it("no filtra el detalle interno cuando algo revienta", async () => {
    const out = await routeAdmin(
      req({ method: "PUT", url: "/admin/secrets/x", token: ADMIN_TOKEN, actor: "acc-1" }),
      res,
      { value: "v" },
      ctx({
        reload: async () => {
          throw new Error("vault path /data/secreto/vault.enc corrupto");
        },
      }),
      auth,
    );
    expect(out?.status).toBe(500);
    expect(JSON.stringify(out?.body)).not.toContain("vault.enc");
  });
});

describe("multi-agente", () => {
  it("lista las identidades desde las políticas, no desde un registro aparte", async () => {
    const out = await routeAdmin(
      req({ url: "/admin/agents", token: ADMIN_TOKEN }),
      res,
      null,
      ctx(),
      auth,
    );
    expect(out?.status).toBe(200);
    const body = out?.body as { agents: Array<{ agentId: string }> };
    expect(body.agents.map((a) => a.agentId)).toEqual(["nexgen-kimi", "git"]);
  });
});
