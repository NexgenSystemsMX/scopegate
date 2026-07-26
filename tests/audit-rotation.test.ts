/**
 * Rotation of audit.jsonl.
 *
 * The log is a hash chain: every event carries the previous event's hash and a
 * monotonic seq. Rotating it naively — move the file aside, start an empty one
 * — restarts the chain at genesis and makes the trail unverifiable. That is the
 * failure these tests exist to prevent: rotation must be invisible to anyone
 * reading the log, and retention must be LOUD when it breaks the link back to
 * genesis instead of looking like tampering.
 *
 * Isolated from the real HOME via tests/helpers.ts, modules imported
 * dynamically after useTempHome() (same pattern as audit-signing.test.ts).
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  home = useTempHome();
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  errSpy.mockRestore();
  delete process.env.SCOPEGATE_AUDIT_MAX_MB;
  delete process.env.SCOPEGATE_AUDIT_KEEP;
  cleanupTempHome(home);
});

/** Force a rotation on virtually every append. */
function tinySegments(): void {
  process.env.SCOPEGATE_AUDIT_MAX_MB = String(1 / 1024 / 1024); // ~1 byte
}

async function paths(): Promise<{ live: string; seg: (n: number) => string }> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  return { live: AUDIT_LOG_PATH, seg: (n: number) => `${AUDIT_LOG_PATH}.${n}` };
}

describe("rotación de audit.jsonl", () => {
  it("no rota mientras el segmento cabe", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { seg } = await paths();
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "x" });
    expect(fs.existsSync(seg(1))).toBe(false);
  });

  it("al rotar, la cadena CONTINÚA en el segmento nuevo (no vuelve a genesis)", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { live, seg } = await paths();
    audit("agent-a", "gateway_start", {});
    tinySegments();
    audit("agent-a", "tool_call", { tool: "x" });

    expect(fs.existsSync(seg(1))).toBe(true);
    const rotated = JSON.parse(fs.readFileSync(seg(1), "utf8").trim());
    const current = JSON.parse(fs.readFileSync(live, "utf8").trim());
    // El fallo que esto atrapa: prev === "genesis" y seq === 1 otra vez.
    expect(current.prev).toBe(rotated.hash);
    expect(current.seq).toBe(rotated.seq + 1);
  });

  it("el log rotado se verifica entero, como si fuera un solo archivo", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    tinySegments();
    audit("agent-a", "tool_call", { tool: "x" });
    audit("agent-a", "secret_added", { secretRef: "k" });

    const { verifyAuditLog } = await import("../src/audit/verify.js");
    const r = verifyAuditLog();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.count).toBe(3);
      expect(r.verifiedFromSeq).toBeUndefined(); // llega a genesis
    }
  });

  it("los segmentos se leen del más viejo al más nuevo", async () => {
    const { audit } = await import("../src/audit/log.js");
    tinySegments();
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "primero" });
    audit("agent-a", "tool_call", { tool: "segundo" });

    const { readAuditEvents } = await import("../src/audit/verify.js");
    const seqs = readAuditEvents().map((e) => e.seq);
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
  });

  it("el tail se toma del segmento rotado cuando el vivo está vacío", async () => {
    // Sin esto, un reinicio justo después de rotar reabriría la cadena en
    // genesis y el log entero dejaría de verificar.
    const { audit } = await import("../src/audit/log.js");
    const { live, seg } = await paths();
    audit("agent-a", "gateway_start", {});
    fs.renameSync(live, seg(1));
    fs.writeFileSync(live, "");
    vi.resetModules();
    const { audit: audit2 } = await import("../src/audit/log.js");
    audit2("agent-a", "tool_call", { tool: "tras reinicio" });

    const rotated = JSON.parse(fs.readFileSync(seg(1), "utf8").trim());
    const current = JSON.parse(fs.readFileSync(live, "utf8").trim());
    expect(current.prev).toBe(rotated.hash);
    expect(current.seq).toBe(rotated.seq + 1);
  });
});

describe("retención", () => {
  it("borra los segmentos más viejos y deja marca", async () => {
    process.env.SCOPEGATE_AUDIT_KEEP = "1";
    const { audit } = await import("../src/audit/log.js");
    const { seg } = await paths();
    audit("agent-a", "gateway_start", {});
    tinySegments();
    for (let i = 0; i < 4; i++) audit("agent-a", "tool_call", { tool: `t${i}` });

    expect(fs.existsSync(seg(2))).toBe(false); // más allá de la retención
    expect(fs.existsSync(seg(1))).toBe(true);
    const { isPruned } = await import("../src/audit/segments.js");
    expect(isPruned()).toBe(true);
  });

  it("un log podado verifica desde su primer evento y LO DICE", async () => {
    process.env.SCOPEGATE_AUDIT_KEEP = "1";
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    tinySegments();
    for (let i = 0; i < 4; i++) audit("agent-a", "tool_call", { tool: `t${i}` });

    const { verifyAuditLog } = await import("../src/audit/verify.js");
    const r = verifyAuditLog();
    expect(r.ok).toBe(true);
    if (r.ok) {
      // "OK" sobre una ventana podada es una afirmación MÁS DÉBIL que "OK"
      // sobre toda la historia: quien lo lea tiene que poder distinguirlo.
      expect(r.verifiedFromSeq).toBeGreaterThan(1);
    }
  });

  it("un log que empieza tarde SIN marca de poda es un fallo, no una poda", async () => {
    // Es la diferencia entre "retención hizo su trabajo" y "alguien borró el
    // principio del log". Sin la marca, lo segundo.
    const { audit } = await import("../src/audit/log.js");
    const { live } = await paths();
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "x" });
    const lines = fs.readFileSync(live, "utf8").trim().split("\n");
    fs.writeFileSync(live, lines.slice(1).join("\n") + "\n"); // se borra el primero

    const { verifyAuditLog } = await import("../src/audit/verify.js");
    const r = verifyAuditLog();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/does not start at seq 1/);
  });

  it("KEEP=0 conserva todos los segmentos (disco a cambio de cadena completa)", async () => {
    process.env.SCOPEGATE_AUDIT_KEEP = "0";
    const { audit } = await import("../src/audit/log.js");
    const { seg } = await paths();
    audit("agent-a", "gateway_start", {});
    tinySegments();
    for (let i = 0; i < 3; i++) audit("agent-a", "tool_call", { tool: `t${i}` });

    expect(fs.existsSync(seg(3))).toBe(true);
    const { verifyAuditLog } = await import("../src/audit/verify.js");
    const r = verifyAuditLog();
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.verifiedFromSeq).toBeUndefined();
  });
});

describe("lectores que no pueden quedarse con medio log", () => {
  it("el exportador a cloud ve los eventos que quedaron en un segmento rotado", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    tinySegments();
    audit("agent-a", "tool_call", { tool: "x" });

    const { readEventsAfter } = await import("../src/cloud/client/audit-exporter.js");
    // Con el cursor a 0 tiene que ver los DOS: si solo leyera el archivo vivo,
    // el primero no se exportaría nunca (el cursor solo avanza).
    expect(readEventsAfter(0, 100)).toHaveLength(2);
  });

  it("auditSizeBytes suma todos los segmentos", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    tinySegments();
    audit("agent-a", "tool_call", { tool: "x" });

    const { auditSizeBytes } = await import("../src/audit/segments.js");
    const { live, seg } = await paths();
    const expected = fs.statSync(live).size + fs.statSync(seg(1)).size;
    expect(auditSizeBytes()).toBe(expected);
  });
});

describe("configuración", () => {
  it("SCOPEGATE_AUDIT_MAX_MB manda; por defecto 100 MB", async () => {
    const { maxSegmentBytes } = await import("../src/audit/segments.js");
    expect(maxSegmentBytes({} as NodeJS.ProcessEnv)).toBe(100 * 1024 * 1024);
    expect(maxSegmentBytes({ SCOPEGATE_AUDIT_MAX_MB: "5" } as NodeJS.ProcessEnv)).toBe(
      5 * 1024 * 1024,
    );
    // Una basura en la variable no debe desactivar la rotación en silencio.
    expect(maxSegmentBytes({ SCOPEGATE_AUDIT_MAX_MB: "cero" } as NodeJS.ProcessEnv)).toBe(
      100 * 1024 * 1024,
    );
    expect(maxSegmentBytes({ SCOPEGATE_AUDIT_MAX_MB: "-3" } as NodeJS.ProcessEnv)).toBe(
      100 * 1024 * 1024,
    );
  });

  it("SCOPEGATE_AUDIT_KEEP admite 0 pero no basura", async () => {
    const { keepSegments } = await import("../src/audit/segments.js");
    expect(keepSegments({} as NodeJS.ProcessEnv)).toBe(5);
    expect(keepSegments({ SCOPEGATE_AUDIT_KEEP: "0" } as NodeJS.ProcessEnv)).toBe(0);
    expect(keepSegments({ SCOPEGATE_AUDIT_KEEP: "nope" } as NodeJS.ProcessEnv)).toBe(5);
  });

  it("no deja segmentos fuera del directorio de scopegate", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    tinySegments();
    audit("agent-a", "tool_call", { tool: "x" });
    const { auditSegmentPaths } = await import("../src/audit/segments.js");
    for (const p of auditSegmentPaths()) {
      expect(path.resolve(p).startsWith(path.resolve(home))).toBe(true);
    }
  });
});
