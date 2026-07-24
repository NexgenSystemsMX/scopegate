/**
 * M10: governed secret materialization into files (legacy CLI configs).
 *
 * Many CLIs read credentials from files (config.toml, ~/.aws/credentials,
 * .npmrc, kubeconfig). This is the GOVERNED EXCEPTION to "secrets never leave
 * the vault": the egress surface widens in exchange for
 *   - human approval BY DEFAULT (the engine's inverted default on
 *     `vault:inject:<ref>` — a policy must explicitly auto_approve to lift it),
 *   - an atomic 0600 write with a backup of the previous file,
 *   - a signed audit event with the sha256 of the rendered content (never
 *     the value),
 *   - a sidecar manifest (<out>.scopegate.json) so `inject --refresh` can
 *     re-materialize when the secret rotates (the vault is the source; the
 *     file is a view).
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Vault } from "../vault/vault.js";
import { PolicyEngine } from "../policy/engine.js";
import { audit } from "../audit/log.js";

const PLACEHOLDER = "{{secret}}";

export interface InjectOptions {
  /** Vault secretRef to materialize. */
  ref: string;
  /** Destination file (written 0600, atomically). */
  out: string;
  /** Inline template containing {{secret}}. Default: the raw secret. */
  template?: string;
  /** Path to a template file containing {{secret}} (wins over template). */
  templateFile?: string;
  agentId: string;
  /** Injected for tests; default PolicyEngine.load(). */
  policy?: PolicyEngine;
}

export type InjectStatus = "materialized" | "pending_human_approval" | "denied";

export interface InjectResult {
  ok: boolean;
  status: InjectStatus;
  out?: string;
  sha256?: string;
  approvalId?: string;
  approvalExpiresAt?: number;
  reason?: string;
}

function manifestPath(out: string): string {
  return out + ".scopegate.json";
}

/** Evaluate policy, read the vault, render the template, write atomically. */
export async function materializeSecret(opts: InjectOptions): Promise<InjectResult> {
  const capability = `vault:inject:${opts.ref}`;
  const policy = opts.policy ?? PolicyEngine.load();
  const decision = policy.request(
    opts.agentId,
    capability,
    undefined,
    `inject ${opts.ref} → ${opts.out}`,
  );
  if (!decision.allow) {
    if (decision.escalation === "human_approval") {
      return {
        ok: false,
        status: "pending_human_approval",
        approvalId: decision.approvalId,
        approvalExpiresAt: decision.approvalExpiresAt,
        reason: decision.reason,
      };
    }
    audit(opts.agentId, "capability_denied", {
      capability,
      code: decision.code,
      reason: decision.reason,
      via: "inject",
    });
    return { ok: false, status: "denied", reason: decision.reason };
  }

  let template: string;
  let templateSource: string;
  if (opts.templateFile) {
    template = fs.readFileSync(opts.templateFile, "utf8");
    templateSource = opts.templateFile;
  } else if (opts.template !== undefined) {
    template = opts.template;
    templateSource = "inline";
  } else {
    template = PLACEHOLDER;
    templateSource = "raw";
  }
  if (!template.includes(PLACEHOLDER)) {
    throw new Error(`the template must contain the ${PLACEHOLDER} placeholder`);
  }

  const vault = Vault.open();
  if (!vault.has(opts.ref)) {
    throw new Error(
      `secretRef '${opts.ref}' not found in the vault — ask the human to run: scopegate secret add ${opts.ref}`,
    );
  }
  const rendered = template.split(PLACEHOLDER).join(vault.get(opts.ref));

  const out = path.resolve(opts.out);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  if (fs.existsSync(out)) fs.copyFileSync(out, out + ".bak");
  const tmp = `${out}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, rendered, { mode: 0o600 });
  fs.renameSync(tmp, out);
  fs.chmodSync(out, 0o600);

  const sha256 = crypto.createHash("sha256").update(rendered).digest("hex");
  audit(opts.agentId, "secret_materialized", {
    ref: opts.ref,
    out,
    sha256,
    template: templateSource,
  });
  fs.writeFileSync(
    manifestPath(out),
    JSON.stringify(
      {
        ref: opts.ref,
        out,
        templateFile: opts.templateFile ?? null,
        inline: opts.templateFile ? null : opts.template ?? null,
        sha256,
        materializedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  return { ok: true, status: "materialized", out, sha256 };
}

/**
 * Re-materialize a file from its sidecar manifest (secret rotated in the
 * vault → the view refreshes). Still policy-gated like any inject.
 */
export async function refreshInject(
  outPath: string,
  agentId: string,
  policy?: PolicyEngine,
): Promise<InjectResult> {
  const out = path.resolve(outPath);
  const manifest = JSON.parse(fs.readFileSync(manifestPath(out), "utf8")) as {
    ref: string;
    out: string;
    templateFile: string | null;
    inline: string | null;
  };
  return materializeSecret({
    ref: manifest.ref,
    out: manifest.out,
    template: manifest.inline ?? undefined,
    templateFile: manifest.templateFile ?? undefined,
    agentId,
    policy,
  });
}
