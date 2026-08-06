/**
 * EPIC-49.1 — el invariante de audiencia, escrito como prueba.
 *
 * El invariante: **una instancia de gateway sirve exactamente un workspace**
 * (src/gateway/http.ts). De él depende `GrantStore.coversCaller` para la rama
 * `audience: "org"`: `"org"` es un literal, el plano de política no tiene
 * noción de workspace, y `agentAccepted` responde "declarada aquí", nunca
 * "del mismo workspace".
 *
 * Qué fija cada prueba:
 *   (1) el conjunto de identidades que el arranque de producción declara
 *       — falla el día que alguien mete otra identidad en la misma instancia,
 *         que es exactamente el día en que hay que releer el invariante;
 *   (2) que el catch-all `*` hace que `agentIdAccepted` acepte cualquier id,
 *       es decir que el predicado NO es una frontera de workspace;
 *   (3) la consecuencia ejecutable: un grant `audience: "org"` cubre a toda
 *       identidad aceptada, incluida una que su titular nunca declaró;
 *   (4) el fail-closed: sin `agentAccepted` cableado, `"org"` no cubre a nadie
 *       — la línea que un "simplifiquemos esto a return true" rompería;
 *   (5) control positivo: una audiencia que NO es "org" sigue siendo exacta,
 *       para que (3) y (4) midan la rama `org` y no "todo matchea".
 *
 * Lo que estas pruebas NO demuestran: que la instancia de un cliente sirva a
 * un solo workspace. Eso no es comprobable desde el repo — el `policies.yaml`
 * vive en `$SCOPEGATE_HOME` de cada despliegue. La comprobación de despliegue
 * es la guarda de arranque fail-closed de EPIC-49.3 (V2), que todavía no
 * existe. Ver docs/runbook/invariante-audiencia.md.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { PoliciesFile } from "../src/policy/engine.js";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BOOTSTRAP_PROD = path.join(REPO, "docker", "bootstrap-prod.mjs");

/**
 * Las identidades que `docker/bootstrap-prod.mjs` deja escritas en el
 * `policies.yaml` de la instancia de producción. Se fijan a propósito: este
 * literal es el punto donde un revisor humano se entera de que la instancia
 * pasó a declarar una identidad más.
 */
const IDENTIDADES_DE_PRODUCCION = ["*", "demo-agent", "nexgen-kimi"];

/** Un conjunto de política con la MISMA forma que el de producción. */
const POLITICA_DE_PRODUCCION: PoliciesFile = {
  version: 1,
  agents: {
    "nexgen-kimi": { default_ttl: "15m", capabilities: [] },
    "demo-agent": { default_ttl: "15m", capabilities: [] },
    "*": { default_ttl: "5m", capabilities: [] },
  },
};

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

describe("EPIC-49.1 · el invariante de audiencia", () => {
  it("(1) el arranque de produccion declara EXACTAMENTE estas identidades", () => {
    const src = fs.readFileSync(BOOTSTRAP_PROD, "utf8");

    // Denominador: si algun acceso usara una clave dinamica, esta prueba seria
    // ciega y su verde no significaria nada. Debe ser SKIP mental, no PASS.
    const accesos = [...src.matchAll(/policies\.agents\[([^\]]*)\]/g)].map((m) =>
      m[1].trim(),
    );
    expect(accesos.length).toBeGreaterThan(0);
    expect(accesos.filter((k) => !/^"[^"]*"$/.test(k))).toEqual([]);

    const declaradas = new Set(
      [...src.matchAll(/policies\.agents\[\s*"([^"]+)"\s*\]\s*\??\??=[^=]/g)].map(
        (m) => m[1],
      ),
    );

    // Si esto falla porque hay una identidad NUEVA: la respuesta no es ampliar
    // la lista. Es el paso 2 de docs/runbook/invariante-audiencia.md —
    // ¿pertenece al mismo workspace? Si no, hacen falta EPIC-49.2 y 49.3
    // ANTES, porque cada grant `audience: "org"` vivo pasa a alcanzarla.
    expect([...declaradas].sort()).toEqual([...IDENTIDADES_DE_PRODUCCION].sort());
  });

  it("(2) el catch-all `*` acepta cualquier identidad: agentAccepted NO es una frontera de workspace", async () => {
    const { agentIdAccepted } = await import("../src/policy/engine.js");

    expect(agentIdAccepted(POLITICA_DE_PRODUCCION, "nexgen-kimi")).toBe(true);
    // Una identidad que nadie declaro, de un workspace que no existe aqui:
    expect(agentIdAccepted(POLITICA_DE_PRODUCCION, "agente-de-otro-workspace")).toBe(
      true,
    );

    // Control positivo: sin el catch-all, el predicado SI discrimina — luego lo
    // de arriba mide el catch-all y no un `return true` en el predicado.
    const sinCatchAll: PoliciesFile = {
      version: 1,
      agents: { "nexgen-kimi": POLITICA_DE_PRODUCCION.agents["nexgen-kimi"] },
    };
    expect(agentIdAccepted(sinCatchAll, "nexgen-kimi")).toBe(true);
    expect(agentIdAccepted(sinCatchAll, "agente-de-otro-workspace")).toBe(false);
  });

  it("(3) un grant `audience: \"org\"` cubre a TODA identidad aceptada, tambien a una que su titular nunca declaro", async () => {
    const { GrantStore } = await import("../src/policy/grants.js");
    const { agentIdAccepted } = await import("../src/policy/engine.js");

    const store = new GrantStore(path.join(home, "grants-org.json"));
    store.agentAccepted = (id: string) => agentIdAccepted(POLITICA_DE_PRODUCCION, id);
    store.issue({
      agentId: "nexgen-kimi",
      capability: "huly:call:*",
      ttlMs: 60_000,
      audience: "org",
    });

    expect(store.isGranted("nexgen-kimi", "huly:call:createIssue")).toBe(true);
    expect(store.isGranted("demo-agent", "huly:call:createIssue")).toBe(true);
    // Esta es la linea del invariante: lo unico que mantiene a este llamante
    // dentro del mismo workspace es que la instancia sirva a uno solo.
    expect(store.isGranted("agente-de-otro-workspace", "huly:call:createIssue")).toBe(
      true,
    );
  });

  it("(4) sin `agentAccepted` cableado, `org` no cubre a nadie (fail-closed)", async () => {
    const { GrantStore } = await import("../src/policy/grants.js");

    const store = new GrantStore(path.join(home, "grants-failclosed.json"));
    // agentAccepted deliberadamente SIN cablear (lo cablea el PolicyEngine).
    store.issue({
      agentId: "nexgen-kimi",
      capability: "huly:call:*",
      ttlMs: 60_000,
      audience: "org",
    });

    expect(store.isGranted("nexgen-kimi", "huly:call:createIssue")).toBe(false);
    expect(store.isGranted("agente-de-otro-workspace", "huly:call:createIssue")).toBe(
      false,
    );
  });

  it("(5) control positivo: una audiencia que no es `org` sigue siendo exacta", async () => {
    const { GrantStore } = await import("../src/policy/grants.js");
    const { agentIdAccepted } = await import("../src/policy/engine.js");

    const store = new GrantStore(path.join(home, "grants-exacta.json"));
    store.agentAccepted = (id: string) => agentIdAccepted(POLITICA_DE_PRODUCCION, id);
    store.issue({
      agentId: "nexgen-kimi",
      capability: "huly:call:*",
      ttlMs: 60_000,
      audience: "demo-agent",
    });

    expect(store.isGranted("demo-agent", "huly:call:createIssue")).toBe(true);
    // Aceptada por el gateway, pero fuera de la audiencia: NO cubierta.
    expect(store.isGranted("agente-de-otro-workspace", "huly:call:createIssue")).toBe(
      false,
    );
    // Ni siquiera el titular, cuando la audiencia nombra a otro.
    expect(store.isGranted("nexgen-kimi", "huly:call:createIssue")).toBe(false);
  });
});
