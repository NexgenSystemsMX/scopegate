/**
 * Orphan child processes from the stdio respawn.
 *
 * The gateway rebuilds stdio connections every few hours for the proactive
 * mint refresh. It closed them with `client.close()` — which closes stdin and
 * asks nicely. An MCP server that ignores that, or hangs on shutdown, leaves a
 * child with nothing pointing at it; over days the orphans pile up until a
 * gateway restart. Nothing reported it, because from the gateway's side the
 * close "succeeded".
 *
 * These tests use REAL processes: the escalation only matters against a child
 * that actually refuses to die, and a mocked `process.kill` would prove nothing.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { alive, ensureChildGone } from "../src/gateway/proxy.js";

const spawned: ChildProcess[] = [];
let errSpy: ReturnType<typeof vi.spyOn> | null = null;

afterEach(() => {
  for (const c of spawned.splice(0)) {
    try {
      if (c.pid !== undefined) process.kill(c.pid, "SIGKILL");
    } catch {
      /* already gone */
    }
  }
  errSpy?.mockRestore();
  errSpy = null;
});

function quiet(): void {
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
}

/** A node child that stays alive; `deaf` makes it ignore SIGTERM. */
function child(deaf: boolean): ChildProcess {
  const body = deaf
    ? "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"
    : "setInterval(() => {}, 1000)";
  const c = spawn(process.execPath, ["-e", body], { stdio: "ignore" });
  spawned.push(c);
  return c;
}

const settle = async (ms = 150): Promise<void> => {
  await new Promise((r) => setTimeout(r, ms));
};

describe("alive()", () => {
  it("ve un proceso vivo", () => {
    const c = child(false);
    expect(alive(c.pid as number)).toBe(true);
  });

  it("no ve un pid que ya murió", async () => {
    const c = child(false);
    const pid = c.pid as number;
    process.kill(pid, "SIGKILL");
    await settle(300);
    expect(alive(pid)).toBe(false);
  });

  it("un pid imposible no lanza", () => {
    expect(alive(2_147_483_646)).toBe(false);
  });
});

describe("ensureChildGone", () => {
  it("un proceso que ya salió no necesita nada", async () => {
    const c = child(false);
    const pid = c.pid as number;
    process.kill(pid, "SIGKILL");
    await settle(300);
    expect(await ensureChildGone(pid, "up", 10)).toBe("exited");
  });

  it("un proceso normal cae con SIGTERM", async () => {
    quiet();
    const pid = child(false).pid as number;
    expect(await ensureChildGone(pid, "up", 50)).toBe("sigterm");
    expect(alive(pid)).toBe(false);
  });

  it("un proceso que ignora SIGTERM acaba muerto igual", async () => {
    // Este es el caso real que se fugaba: close() no lo tumbaba y el hijo se
    // quedaba para siempre. Lo que importa aquí es el resultado — muerto.
    quiet();
    const pid = child(true).pid as number;
    const outcome = await ensureChildGone(pid, "terco", 300);
    expect(["sigterm", "sigkill"]).toContain(outcome);
    expect(alive(pid)).toBe(false);
  });

  it("avisa por stderr antes de escalar, con el pid dentro", async () => {
    // Sin el pid en el mensaje no se puede investigar nada.
    quiet();
    const pid = child(true).pid as number;
    await ensureChildGone(pid, "terco", 300);
    const lines = (errSpy?.mock.calls ?? []).map((c) => String(c[0]));
    expect(lines.some((l) => l.includes("survived close()") && l.includes(String(pid)))).toBe(true);
  });

  // En Windows `process.kill(pid,'SIGTERM')` NO manda una señal: Node termina
  // el proceso a la fuerza, así que un hijo "sordo" muere igual y la escalada
  // nunca llega a SIGKILL. El gateway corre en Linux (Docker) y ahí CI sí la
  // ejercita — saltarlo aquí es honesto; afirmarlo en Windows sería falso.
  it.skipIf(process.platform === "win32")(
    "en POSIX, un proceso sordo a SIGTERM exige SIGKILL y queda registrado",
    async () => {
      quiet();
      const pid = child(true).pid as number;
      expect(await ensureChildGone(pid, "terco", 300)).toBe("sigkill");
      const lines = (errSpy?.mock.calls ?? []).map((c) => String(c[0]));
      expect(lines.some((l) => l.includes("ignored SIGTERM"))).toBe(true);
    },
  );
});
