import crypto from "node:crypto";
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

interface AuditLine {
  ts: string;
  agentId: string;
  kind: string;
  detail: Record<string, unknown>;
  inputHash?: string;
  prev: string;
  hash: string;
}

/** Recomputes the whole hash chain; returns false on any break. */
function verifyChain(lines: string[]): boolean {
  let prev = "genesis";
  for (const line of lines) {
    const e = JSON.parse(line) as AuditLine;
    if (e.prev !== prev) return false;
    const { hash, ...base } = e;
    const recomputed = crypto
      .createHash("sha256")
      .update(prev + JSON.stringify(base))
      .digest("hex");
    if (recomputed !== hash) return false;
    prev = hash;
  }
  return true;
}

async function readLines(): Promise<string[]> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  return fs.readFileSync(AUDIT_LOG_PATH, "utf8").trim().split("\n");
}

describe("audit log", () => {
  it("appends JSONL entries with an intact, recomputable hash chain", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", { upstreams: {} });
    audit("agent-a", "capability_request", { capability: "github:call:x" });
    audit("agent-a", "tool_call", { tool: "github__x" });

    const lines = await readLines();
    expect(lines).toHaveLength(3);
    const first = JSON.parse(lines[0]) as AuditLine;
    expect(first.prev).toBe("genesis");
    expect(verifyChain(lines)).toBe(true);
  });

  it("detects tampering with a past entry", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" });
    audit("agent-a", "tool_call", { tool: "github__y" });

    const lines = await readLines();
    const forged = JSON.parse(lines[1]) as AuditLine;
    forged.detail = { tool: "github__pwned" };
    lines[1] = JSON.stringify(forged);
    fs.writeFileSync(AUDIT_LOG_PATH, lines.join("\n") + "\n");

    expect(verifyChain(await readLines())).toBe(false);
  });

  it("hashes inputs (SHA-256) and never stores them in clear", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
    const secretInput = { token: "supersecret123", note: "do not store" };
    audit("agent-a", "tool_call", { tool: "github__x" }, secretInput);

    const raw = fs.readFileSync(AUDIT_LOG_PATH, "utf8");
    expect(raw).not.toContain("supersecret123");
    expect(raw).not.toContain("do not store");

    const line = JSON.parse(raw.trim()) as AuditLine;
    const expected = crypto
      .createHash("sha256")
      .update(JSON.stringify(secretInput))
      .digest("hex");
    expect(line.inputHash).toBe(expected);
  });

  it("continues the chain from the on-disk tail after a 'process restart'", async () => {
    const mod1 = await import("../src/audit/log.js");
    mod1.audit("agent-a", "gateway_start", {});
    mod1.audit("agent-a", "tool_call", { tool: "t1" });

    // Simulate a restart: drop module state (lastHash) so tailHash() must
    // re-read the file to find the previous hash.
    vi.resetModules();
    const mod2 = await import("../src/audit/log.js");
    mod2.audit("agent-a", "tool_call", { tool: "t2" });

    const lines = await readLines();
    expect(lines).toHaveLength(3);
    expect(verifyChain(lines)).toBe(true);
    const second = JSON.parse(lines[1]) as AuditLine;
    const third = JSON.parse(lines[2]) as AuditLine;
    expect(third.prev).toBe(second.hash);
  });

  it("writes only inside SCOPEGATE_HOME", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
    audit("agent-a", "gateway_start", {});
    expect(AUDIT_LOG_PATH.startsWith(home)).toBe(true);
    expect(fs.existsSync(AUDIT_LOG_PATH)).toBe(true);
  });
});
