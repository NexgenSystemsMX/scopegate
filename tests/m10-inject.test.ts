/**
 * M10: governed secret materialization into files (`scopegate inject`).
 *
 *   - vault:inject:<ref> escalates to human approval BY DEFAULT (inverted
 *     default — silence is not a plain no_rule denial).
 *   - approval on disk → the next materialize call writes the file
 *     (atomic, backup of the previous, sidecar manifest, signed audit with
 *     the sha256 — never the value).
 *   - an explicit auto_approve rule lifts the default (the escape hatch).
 *   - limits.deny still wins over the default escalation (hard limits first).
 *   - --refresh re-materializes from the sidecar after the secret rotates.
 *   - templates must contain {{secret}}; a missing ref points at secret add.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
let outDir: string;

beforeEach(async () => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local";
  outDir = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-inject-out-"));
  const { Vault } = await import("../src/vault/vault.js");
  Vault.open().set("moonshot_api_key", "sk-test-1234567890abcdef");
});

afterEach(() => {
  delete process.env.SCOPEGATE_VAULT_MODE;
  fs.rmSync(outDir, { recursive: true, force: true });
  cleanupTempHome(home);
});

function writePolicies(doc: unknown) {
  fs.writeFileSync(path.join(home, "policies.yaml"), JSON.stringify(doc));
}

const AUTO_APPROVE = {
  version: 1,
  agents: {
    kimi: {
      default_ttl: "10m",
      capabilities: [{ match: "vault:inject:moonshot_*", auto_approve: true, ttl: "10m" }],
    },
  },
};

function outFile(name = "config.toml") {
  return path.join(outDir, name);
}

describe("M10 inject — inverted default", () => {
  it("no rule → pending_human_approval (not no_rule), then approval on disk materializes", async () => {
    writePolicies({ version: 1, agents: { kimi: { default_ttl: "10m", capabilities: [] } } });
    const { materializeSecret } = await import("../src/inject/inject.js");
    const out = outFile();

    const first = await materializeSecret({
      ref: "moonshot_api_key",
      out,
      template: 'api_key = "{{secret}}"',
      agentId: "kimi",
    });
    expect(first.status).toBe("pending_human_approval");
    expect(first.approvalId).toBeTruthy();
    expect(fs.existsSync(out)).toBe(false);

    // The human approves on disk (what `scopegate approve <id>` writes).
    fs.appendFileSync(
      path.join(home, "approvals.decisions.jsonl"),
      JSON.stringify({ id: first.approvalId, decision: "approved", decidedAt: Date.now(), decidedBy: "human:test" }) + "\n",
    );

    const second = await materializeSecret({
      ref: "moonshot_api_key",
      out,
      template: 'api_key = "{{secret}}"',
      agentId: "kimi",
    });
    expect(second.status).toBe("materialized");
    expect(fs.readFileSync(out, "utf8")).toBe('api_key = "sk-test-1234567890abcdef"');
    // Sidecar manifest for --refresh; audit carries the sha256, never the value.
    const manifest = JSON.parse(fs.readFileSync(out + ".scopegate.json", "utf8"));
    expect(manifest.ref).toBe("moonshot_api_key");
    expect(manifest.sha256).toBe(second.sha256);
    const auditLog = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    expect(auditLog).toContain("secret_materialized");
    expect(auditLog).not.toContain("sk-test-1234567890abcdef");
    if (process.platform !== "win32") {
      expect(fs.statSync(out).mode & 0o777).toBe(0o600);
    }
  });

  it("evaluate() mirrors the default escalation (preflight says needs_approval)", async () => {
    writePolicies({ version: 1, agents: { kimi: { default_ttl: "10m", capabilities: [] } } });
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const engine = PolicyEngine.load();
    expect(engine.evaluate("kimi", "vault:inject:moonshot_api_key").decision).toBe("needs_approval");
    // Preflight has zero side effects.
    expect(fs.existsSync(path.join(home, "approvals.pending.jsonl"))).toBe(false);
  });

  it("an explicit auto_approve rule lifts the default; a second write keeps a .bak", async () => {
    writePolicies(AUTO_APPROVE);
    const { materializeSecret } = await import("../src/inject/inject.js");
    const out = outFile();

    const res = await materializeSecret({ ref: "moonshot_api_key", out, agentId: "kimi" });
    expect(res.status).toBe("materialized");
    expect(fs.readFileSync(out, "utf8")).toBe("sk-test-1234567890abcdef");

    const res2 = await materializeSecret({ ref: "moonshot_api_key", out, agentId: "kimi" });
    expect(res2.status).toBe("materialized");
    expect(fs.readFileSync(out + ".bak", "utf8")).toBe("sk-test-1234567890abcdef");
  });

  it("limits.deny still wins over the default escalation (hard limits first)", async () => {
    writePolicies({
      version: 1,
      limits: { deny: ["vault:inject:*"] },
      agents: { kimi: { default_ttl: "10m", capabilities: [] } },
    });
    const { materializeSecret } = await import("../src/inject/inject.js");
    const res = await materializeSecret({
      ref: "moonshot_api_key",
      out: outFile(),
      agentId: "kimi",
    });
    expect(res.status).toBe("denied");
  });

  it("refresh re-materializes from the sidecar after the secret rotates", async () => {
    writePolicies(AUTO_APPROVE);
    const { materializeSecret, refreshInject } = await import("../src/inject/inject.js");
    const { Vault } = await import("../src/vault/vault.js");
    const out = outFile();

    await materializeSecret({
      ref: "moonshot_api_key",
      out,
      template: 'api_key = "{{secret}}"',
      agentId: "kimi",
    });
    Vault.open().set("moonshot_api_key", "sk-rotated-9999");

    const res = await refreshInject(out, "kimi");
    expect(res.status).toBe("materialized");
    expect(fs.readFileSync(out, "utf8")).toBe('api_key = "sk-rotated-9999"');
    expect(fs.readFileSync(out + ".bak", "utf8")).toBe('api_key = "sk-test-1234567890abcdef"');
  });

  it("template without {{secret}} and a missing ref are loud errors", async () => {
    writePolicies({
      version: 1,
      agents: {
        kimi: {
          default_ttl: "10m",
          capabilities: [{ match: "vault:inject:*", auto_approve: true, ttl: "10m" }],
        },
      },
    });
    const { materializeSecret } = await import("../src/inject/inject.js");
    await expect(
      materializeSecret({ ref: "moonshot_api_key", out: outFile(), template: "no placeholder", agentId: "kimi" }),
    ).rejects.toThrow(/\{\{secret\}\}/);
    await expect(
      materializeSecret({ ref: "missing_ref", out: outFile(), agentId: "kimi" }),
    ).rejects.toThrow(/scopegate secret add missing_ref/);
  });
});
