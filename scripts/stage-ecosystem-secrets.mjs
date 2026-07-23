#!/usr/bin/env node
/**
 * stage-ecosystem-secrets.mjs (EPIC-19, run LOCALLY by the operator)
 *
 * Migrates the ecosystem's real credentials from the kimi-tag Railway
 * project's variables into the ScopeGate production vault — WITHOUT any
 * value touching stdout, this conversation, or a file on disk.
 *
 * Flow:
 *   1. `railway variable list --json` on the SOURCE project (kimi-tag).
 *   2. Map the relevant variables to ScopeGate vault refs (see MAP below).
 *   3. base64-encode the payload and set it as SCOPEGATE_BOOTSTRAP_SECRETS
 *      on the TARGET service (the linked scopegate project).
 *
 * Only ref NAMES are printed. Usage:
 *   node scripts/stage-ecosystem-secrets.mjs            # stage everything found
 *   node scripts/stage-ecosystem-secrets.mjs --dry-run  # print the mapping only
 */
import { execFileSync, execSync } from "node:child_process";

const SOURCE_PROJECT = "f2c3a796-074e-4451-aff1-b80313abc0af"; // kimi-tag
const DRY = process.argv.includes("--dry-run");

// The CLI is a .cmd/sh shim in C:\nodejs — execFileSync can't resolve it from
// Node; execSync (cmd.exe) runs railway.cmd fine. The b64 payload travels via
// env, never as an argv (quoting) and never on stdout.
const railList = (cwd) =>
  execSync(`railway variable list --json -p ${SOURCE_PROJECT} -e production -s worker`, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
const railSet = (b64, cwd) =>
  execSync('railway variable set "SCOPEGATE_BOOTSTRAP_SECRETS=%SCOPEGATE_STAGE_B64%"', {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, SCOPEGATE_STAGE_B64: b64 },
  });

/** kimi-tag env name → vault ref (only secrets we migrate; structural vars skipped) */
const buildPayload = (v) => {
  const secrets = {};
  const missing = [];
  const need = (envName, ref, transform = (x) => x) => {
    const raw = v[envName];
    if (raw) secrets[ref] = transform(raw);
    else missing.push(envName);
  };

  // Huly workspace login → single blob the `huly` minter consumes
  if (v.HULY_BOT_EMAIL && v.HULY_BOT_PASSWORD && v.HULY_WORKSPACE) {
    secrets.huly_nexgen = JSON.stringify({
      email: v.HULY_BOT_EMAIL,
      password: v.HULY_BOT_PASSWORD,
      workspace: v.HULY_WORKSPACE,
      ...(v.HULY_URL ? { accountsUrl: v.HULY_URL } : {}),
    });
  } else missing.push("HULY_BOT_EMAIL/HULY_BOT_PASSWORD/HULY_WORKSPACE");

  need("RAILWAY_TOKEN", "railway_token");
  need("MOONSHOT_API_KEY", "moonshot_api_key");
  need("GH_WEBHOOK_SECRET", "gh_webhook_secret");
  need("GH_APP_PRIVATE_KEY", "github_app_key", (pem) =>
    pem.startsWith("base64:") ? Buffer.from(pem.slice(7), "base64").toString("utf8") : pem.replace(/\\n/g, "\n"),
  );

  const githubApp =
    v.GH_APP_ID && v.GH_APP_INSTALLATION_ID
      ? { appId: v.GH_APP_ID, installationId: v.GH_APP_INSTALLATION_ID }
      : undefined;
  if (!githubApp) missing.push("GH_APP_ID/GH_APP_INSTALLATION_ID");

  return { secrets, githubApp, missing };
};

const varsJson = railList(process.cwd());
const payload = buildPayload(JSON.parse(varsJson));
const staged = Object.keys(payload.secrets);

console.log(`[stage] refs staged: [${staged.join(", ")}]`);
console.log(`[stage] githubApp: ${payload.githubApp ? "present (appId+installationId)" : "MISSING"}`);
if (payload.missing.length) console.log(`[stage] source vars not found (skipped): ${payload.missing.join(", ")}`);
console.log("[stage] not staged (no source found anywhere): cloudflare_api_token, google_sa");

if (DRY) {
  console.log("[stage] dry-run — nothing was written anywhere.");
  process.exit(0);
}

const b64 = Buffer.from(
  JSON.stringify({ secrets: payload.secrets, githubApp: payload.githubApp }),
  "utf8",
).toString("base64");

railSet(b64, process.cwd());
console.log("[stage] SCOPEGATE_BOOTSTRAP_SECRETS set on the linked scopegate service.");
console.log("[stage] next: `railway up` — the container bootstrap deposits into the vault; then DELETE the variable.");
