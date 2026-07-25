import { describe, expect, it } from "vitest";
import { UpstreamProxy } from "../src/gateway/proxy.js";

/**
 * Regresión del bug de /health: `readiness()` calculaba los upstreams caídos
 * desde el snapshot de `connectAll()` tomado en el arranque. Un upstream que
 * conecta después —o que el refresh proactivo M2 respawnea— seguía marcado
 * como `failed` para siempre, mientras sus tools respondían con normalidad
 * (observado 20 h en producción, contradiciendo a scopegate_upstream_health).
 *
 * `liveStatus()` es la fuente que arregla eso: lee el cache de conexiones
 * vivas, es síncrono y no abre sockets (a /health lo golpean sin parar).
 */
describe("UpstreamProxy.liveStatus", () => {
  const cfg = (names: string[]) =>
    names.map((name) => ({
      name,
      transport: { kind: "stdio" as const, command: "node", args: ["-e", ""] },
      auth: { type: "env" as const, env: {} },
    }));

  it("no reporta upstreams que aún no han conectado", () => {
    const proxy = new UpstreamProxy(cfg(["a", "b"]) as never, {} as never, { minter: {} as never });
    // Sin conexiones ni pools: el mapa va vacío para que quien llama pueda
    // caer al snapshot en vez de asumir que todo está caído.
    expect(proxy.liveStatus()).toEqual({});
  });

  it("reporta como vivo un upstream conectado después del arranque", () => {
    const proxy = new UpstreamProxy(cfg(["a", "b"]) as never, {} as never, { minter: {} as never });
    // Simula la conexión perezosa/respawn: entra en el cache de conexiones.
    (proxy as unknown as { connections: Map<string, unknown> }).connections.set("b", {
      client: {},
      tools: [],
      connectedAt: Date.now(),
    });
    expect(proxy.liveStatus()).toEqual({ b: true });
  });

  it("ignora upstreams deshabilitados", () => {
    const ups = cfg(["a"]).map((u) => ({ ...u, enabled: false }));
    const proxy = new UpstreamProxy(ups as never, {} as never, { minter: {} as never });
    (proxy as unknown as { connections: Map<string, unknown> }).connections.set("a", {
      client: {},
      tools: [],
      connectedAt: Date.now(),
    });
    expect(proxy.liveStatus()).toEqual({});
  });
});
