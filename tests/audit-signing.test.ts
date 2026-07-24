/**
 * EPIC-07: per-event Ed25519 signatures, seq monotonicity and tamper
 * detection with exact-seq reporting. Isolated from the real HOME via
 * tests/helpers.ts (SCOPEGATE_HOME + mkdtemp), modules imported dynamically
 * after useTempHome().
 */
import crypto from "node:crypto";
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  home = useTempHome();
  // audit() lazily creates the identity with a stderr WARN on a fresh home;
  // keep test output clean (the lazy-creation test asserts on this spy).
  errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  errSpy.mockRestore();
  cleanupTempHome(home);
});

async function readLines(): Promise<string[]> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  return fs.readFileSync(AUDIT_LOG_PATH, "utf8").trim().split("\n");
}

async function writeLines(lines: string[]): Promise<void> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  fs.writeFileSync(AUDIT_LOG_PATH, lines.join("\n") + "\n");
}

describe("audit signing (EPIC-07)", () => {
  it("signs every event with monotonic seq and verifies the whole trail", async () => {
    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" }, { args: "secret-ish" });
    audit("agent-a", "secret_ref_used", { secretRef: "github_token", upstream: "github" });

    const lines = await readLines();
    expect(lines).toHaveLength(3);
    const events = lines.map((l) => JSON.parse(l));
    expect(events.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(events[0].prev).toBe("genesis");
    for (const e of events) expect(e.sig).toMatch(/^ed25519:/);

    const { verifyAuditLog } = await import("../src/audit/verify.js");
    const r = verifyAuditLog();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.count).toBe(3);
      expect(r.fingerprint).toMatch(/^sha256:/);
    }
  });

  it("signature verifies cryptographically against the identity public key", async () => {
    const { audit, canonicalUnsigned } = await import("../src/audit/log.js");
    audit("agent-a", "tool_call", { tool: "github__x" });

    const [line] = await readLines();
    const e = JSON.parse(line);
    const { loadIdentity } = await import("../src/audit/identity.js");
    const id = loadIdentity();
    expect(
      crypto.verify(
        null,
        Buffer.from(canonicalUnsigned(e), "utf8"),
        id.publicKey,
        Buffer.from(e.sig.slice("ed25519:".length), "base64"),
      ),
    ).toBe(true);
  });

  it("canonical serialization reproduces the stored line (fixed key order)", async () => {
    const { audit, canonicalSigned } = await import("../src/audit/log.js");
    audit("agent-a", "tool_call", { tool: "github__x" }, { a: 1 });

    const [line] = await readLines();
    const e = JSON.parse(line);
    const { hash, ...withoutHash } = e;
    expect(JSON.stringify(withoutHash)).toBe(canonicalSigned(e));
    expect(hash).toBe(
      crypto.createHash("sha256").update(e.prev + canonicalSigned(e)).digest("hex"),
    );
  });

  it("detects tampering with an old event and reports its exact seq", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { verifyAuditLog } = await import("../src/audit/verify.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" });
    audit("agent-a", "tool_call", { tool: "github__y" });

    const lines = await readLines();
    const forged = JSON.parse(lines[1]);
    forged.detail = { tool: "github__pwned" }; // edit without fixing hash/sig
    lines[1] = JSON.stringify(forged);
    await writeLines(lines);

    const r = verifyAuditLog();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.seq).toBe(2);
      expect(r.line).toBe(2);
      expect(r.reason).toMatch(/hash mismatch/);
    }
  });

  it("detects a forged event even when the attacker recomputes the hash", async () => {
    const { audit, canonicalSigned } = await import("../src/audit/log.js");
    const { verifyAuditLog } = await import("../src/audit/verify.js");
    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" });
    audit("agent-a", "tool_call", { tool: "github__y" });

    // Attacker with disk access (no private key): edit AND repair the hash,
    // and also repair the NEXT event's prev so the chain looks continuous.
    const lines = await readLines();
    const forged = JSON.parse(lines[1]);
    forged.detail = { tool: "github__pwned" };
    forged.hash = crypto
      .createHash("sha256")
      .update(forged.prev + canonicalSigned(forged))
      .digest("hex");
    const next = JSON.parse(lines[2]);
    next.prev = forged.hash;
    next.hash = crypto
      .createHash("sha256")
      .update(next.prev + canonicalSigned(next))
      .digest("hex");
    lines[1] = JSON.stringify(forged);
    lines[2] = JSON.stringify(next);
    await writeLines(lines);

    const r = verifyAuditLog();
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.seq).toBe(2);
      expect(r.reason).toMatch(/signature/);
    }
  });

  it("keeps seq monotonic across a process restart (tail read from disk)", async () => {
    const mod1 = await import("../src/audit/log.js");
    mod1.audit("agent-a", "gateway_start", {});
    mod1.audit("agent-a", "tool_call", { tool: "t1" });

    vi.resetModules(); // simulate restart: drop lastTail + identity caches

    const mod2 = await import("../src/audit/log.js");
    mod2.audit("agent-a", "tool_call", { tool: "t2" });

    const lines = await readLines();
    const events = lines.map((l) => JSON.parse(l));
    expect(events.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(events[2].prev).toBe(events[1].hash);

    const { verifyAuditLog } = await import("../src/audit/verify.js");
    expect(verifyAuditLog().ok).toBe(true);
  });

  it("creates the identity lazily (with stderr WARN) when audit runs without one", async () => {
    const { IDENTITY_PATH, identityExists } = await import("../src/audit/identity.js");
    expect(identityExists()).toBe(false);

    const { audit } = await import("../src/audit/log.js");
    audit("agent-a", "gateway_start", {});

    expect(fs.existsSync(IDENTITY_PATH)).toBe(true);
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining("WARN"));
    const { verifyAuditLog } = await import("../src/audit/verify.js");
    expect(verifyAuditLog().ok).toBe(true);
  });

  it("keeps an init-provisioned identity (keep-first) — lazy path never overwrites", async () => {
    const { createIdentity, loadIdentity } = await import("../src/audit/identity.js");
    const id1 = createIdentity();
    const id2 = createIdentity();
    expect(id2.fingerprint).toBe(id1.fingerprint);
    expect(loadIdentity().fingerprint).toBe(id1.fingerprint);
  });

  it("freezes the event taxonomy (contract with EPIC-02 and future sprints)", async () => {
    const { AUDIT_KINDS } = await import("../src/audit/log.js");
    const expected = [
      // pre-existing
      "tool_call", "capability_request", "capability_denied", "secret_ref_used",
      "upstream_registered", "policy_proposed", "gateway_start",
      // frozen additions
      "token_minted", "token_mint_failed", "token_refreshed", "token_refresh_failed",
      "oauth_reauth_required", "oauth_reauth_completed", "ceiling_blocked",
      "approval_requested", "approval_approved", "approval_denied", "approval_expired",
      "policy_accepted", "policy_rejected", "grant_issued", "grant_expired",
      "grants_revoked", "redaction_applied", "policy_reload_error",
      "honeytoken_triggered", "agent_revoked",
      // Mejoras del agente (append-only, wave A): approval continuation.
      "intent_queued", "intent_executed",
      // Mejoras del agente (append-only, wave C): task leases.
      "lease_opened", "lease_renewed", "lease_revoked", "idempotency_replayed",
      // Mejoras del agente (append-only, wave D): plans + result handles.
      "plan_requested", "result_stored",
      // Mejoras del agente (append-only, wave E): delegation + taint.
      "grant_delegated", "taint_detected",
      // M3: git credential-helper mints.
      "git_credential_minted",
      // M5: native approval wait.
      "approval_waited",
    ];
    expect([...AUDIT_KINDS].sort()).toEqual(expected.sort());
  });

  it("runVerifyCli: exit 0 on an intact log, exit 1 with seq on manipulation", async () => {
    const { audit } = await import("../src/audit/log.js");
    const { runVerifyCli } = await import("../src/audit/verify.js");
    const outSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    audit("agent-a", "gateway_start", {});
    audit("agent-a", "tool_call", { tool: "github__x" });
    expect(runVerifyCli()).toBe(0);

    const lines = await readLines();
    const forged = JSON.parse(lines[0]);
    forged.agentId = "agent-evil";
    lines[0] = JSON.stringify(forged);
    await writeLines(lines);

    expect(runVerifyCli()).toBe(1);
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining("seq=1"));
    outSpy.mockRestore();
  });
});
