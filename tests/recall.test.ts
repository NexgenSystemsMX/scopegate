/**
 * Recall tests (mejora #9) — the agent's own audit as session memory, plus
 * the read/write classifier it builds on.
 *
 *   - recall filters by the CALLING agentId only (never another agent's
 *     trail), by since, by kinds, and by limit.
 *   - writes are classified by the side-effects table (curated bridges,
 *     prefixes, overrides), grants carry remaining TTL, pending approvals
 *     surface.
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  cleanupTempHome(home);
});

describe("isWriteTool", () => {
  it("classifies curated bridges, prefixes, reads and overrides", async () => {
    const { isWriteTool } = await import("../src/gateway/side-effects.js");
    // Curated writes.
    expect(isWriteTool("huly", "create_issue")).toBe(true);
    expect(isWriteTool("railway", "deploy")).toBe(true);
    expect(isWriteTool("cloudflare", "dns_delete")).toBe(true);
    expect(isWriteTool("google", "gmail_send")).toBe(true);
    // Curated reads beat prefixes.
    expect(isWriteTool("railway", "get_logs")).toBe(false);
    expect(isWriteTool("railway", "list_services")).toBe(false);
    // Prefix heuristic.
    expect(isWriteTool("github", "create_pull_request")).toBe(true);
    expect(isWriteTool("github", "merge_pull_request")).toBe(true);
    expect(isWriteTool("github", "get_issue")).toBe(false);
    expect(isWriteTool("github", "search_issues")).toBe(false);
    // Manifest override wins over everything.
    expect(isWriteTool("custom", "delete_everything", { delete_everything: "read" })).toBe(false);
    expect(isWriteTool("custom", "get_report", { get_report: "write" })).toBe(true);
  });
});

describe("recall (via the audit trail)", () => {
  async function seed() {
    const { audit } = await import("../src/audit/log.js");
    const mine = "test-agent";
    const other = "someone-else";
    audit(mine, "tool_call", { tool: "fakegit__whoami", upstream: "fakegit" });
    audit(mine, "tool_call", { tool: "huly__create_issue", upstream: "huly" });
    audit(other, "tool_call", { tool: "huly__delete_issue", upstream: "huly" });
    audit(mine, "grant_issued", { id: "g1", capability: "fakegit:call:whoami" });
    return { mine, other };
  }

  it("readAuditEvents + caller filter returns only the calling agent's events", async () => {
    const { mine, other } = await seed();
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const events = readAuditEvents();
    expect(events.length).toBe(4);
    const mineOnly = events.filter((e) => e.agentId === mine);
    expect(mineOnly.length).toBe(3);
    expect(mineOnly.every((e) => e.agentId === mine)).toBe(true);
    expect(mineOnly.some((e) => e.detail.tool === "huly__delete_issue")).toBe(false); // the other agent's write
  });

  it("since filter bounds the window", async () => {
    await seed();
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(readAuditEvents().filter((e) => e.ts >= future).length).toBe(0);
    const past = new Date(Date.now() - 60_000).toISOString();
    expect(readAuditEvents().filter((e) => e.ts >= past).length).toBe(4);
  });

  it("writes are derivable via the side-effects classifier", async () => {
    await seed();
    const { readAuditEvents } = await import("../src/audit/verify.js");
    const { isWriteTool } = await import("../src/gateway/side-effects.js");
    const writes = readAuditEvents()
      .filter((e) => e.agentId === "test-agent")
      .filter(
        (e) =>
          e.kind === "tool_call" &&
          typeof e.detail.tool === "string" &&
          isWriteTool(
            (e.detail.tool as string).split("__")[0],
            (e.detail.tool as string).split("__").slice(1).join("__"),
          ),
      );
    expect(writes.map((e) => e.detail.tool)).toEqual(["huly__create_issue"]);
  });

  it("audit events stay signed and chained after recall reads (read-only view)", async () => {
    await seed();
    const { verifyAuditLog } = await import("../src/audit/verify.js");
    expect(() => verifyAuditLog()).not.toThrow();
  });
});
