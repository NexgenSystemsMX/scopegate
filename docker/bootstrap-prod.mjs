#!/usr/bin/env node
/**
 * ScopeGate PRODUCTION bootstrap (EPIC-19): migrate the ecosystem's secrets
 * into the vault and wire the real upstreams — without any value ever
 * passing through a chat or a log line.
 *
 * Channel: the operator stages a base64 JSON payload as the
 * SCOPEGATE_BOOTSTRAP_SECRETS service variable (see
 * scripts/stage-ecosystem-secrets.mjs). On boot this script:
 *
 *   1. Deposits every payload secret into the vault (keep-first: existing
 *      refs are never overwritten).
 *   2. Upserts the ecosystem upstreams into scopegate.yaml (merge — the demo
 *      `fakegit` upstream, if present, is preserved).
 *   3. Ensures policies.yaml exists for the ecosystem agent.
 *
 * Idempotent per item. Prints ONLY ref/upstream names — never values.
 *
 * Payload shape (base64 of JSON):
 *   {
 *     "secrets": { "<vaultRef>": "<value>", ... },
 *     "githubApp": { "appId": "...", "installationId": "..." }   // optional
 *   }
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url)); // /app/docker
const APP = path.dirname(HERE); // /app
const HOME = process.env.SCOPEGATE_HOME ?? "/data";
const CONFIG_PATH = path.join(HOME, "scopegate.yaml");
const POLICIES_PATH = path.join(HOME, "policies.yaml");

const say = (msg) => console.log(`[bootstrap-prod] ${msg}`);

const raw = process.env.SCOPEGATE_BOOTSTRAP_SECRETS;
if (!raw) {
  say("SCOPEGATE_BOOTSTRAP_SECRETS not set — no-op (demo seed stays in charge).");
  process.exit(0);
}

let payload;
try {
  payload = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
} catch {
  say("ERROR: SCOPEGATE_BOOTSTRAP_SECRETS is not valid base64 JSON — refusing to continue.");
  process.exit(1);
}
const secrets = payload.secrets ?? {};
const githubApp = payload.githubApp;

fs.mkdirSync(HOME, { recursive: true });
// Resolve paths from SCOPEGATE_HOME at module load — set env BEFORE imports.
process.env.SCOPEGATE_HOME = HOME;
process.env.SCOPEGATE_VAULT_MODE ??= "local";

/* ----------------------------- 1. vault refs ---------------------------- */
const { Vault } = await import(
  pathToFileURL(path.join(APP, "dist", "vault", "vault.js")).href
);
const vault = Vault.open();
const deposited = [];
for (const [ref, value] of Object.entries(secrets)) {
  if (typeof value !== "string" || value.length === 0) continue;
  if (vault.has(ref)) continue; // keep-first
  vault.set(ref, value);
  deposited.push(ref);
}

/* ---------------------------- 2. upstreams ------------------------------ */
const readConfig = () => {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  } catch {
    return { version: 1, agentId: "nexgen-kimi", upstreams: [] };
  }
};

const ECOSYSTEM_UPSTREAMS = [
  {
    name: "huly",
    transport: {
      kind: "stdio",
      command: "node",
      args: [path.join(APP, "dist", "upstreams", "huly-bridge", "server.js")],
    },
    auth: { type: "huly", secretRef: "huly_nexgen" },
  },
  {
    name: "railway",
    transport: {
      kind: "stdio",
      command: "node",
      args: [path.join(APP, "dist", "upstreams", "railway-bridge", "server.js")],
    },
    auth: { type: "env", env: { RAILWAY_TOKEN: "railway_token" } },
  },
  {
    name: "cloudflare",
    transport: {
      kind: "stdio",
      command: "node",
      args: [path.join(APP, "dist", "upstreams", "cloudflare-bridge", "server.js")],
    },
    auth: { type: "env", env: { CLOUDFLARE_API_TOKEN: "cloudflare_api_token" } },
  },
  {
    name: "google",
    transport: {
      kind: "stdio",
      command: "node",
      args: [path.join(APP, "dist", "upstreams", "google-bridge", "server.js")],
    },
    auth: { type: "google_sa", secretRef: "google_sa" },
  },
];

if (githubApp?.appId && githubApp?.installationId) {
  ECOSYSTEM_UPSTREAMS.push({
    name: "github",
    transport: {
      kind: "stdio",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
    },
    auth: {
      type: "github_app",
      appId: String(githubApp.appId),
      installationId: String(githubApp.installationId),
      secretRef: "github_app_key",
    },
  });
}

const cfg = readConfig();
cfg.agentId ??= "nexgen-kimi";
cfg.upstreams ??= [];
const wired = [];
for (const up of ECOSYSTEM_UPSTREAMS) {
  const i = cfg.upstreams.findIndex((u) => u.name === up.name);
  if (i >= 0) {
    cfg.upstreams[i] = { ...up, enabled: cfg.upstreams[i].enabled ?? true };
  } else {
    cfg.upstreams.push({ ...up, enabled: true });
    wired.push(up.name);
  }
}
fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });

/* ---------------------------- 3. policies ------------------------------- */
const ECOSYSTEM_AGENT_POLICY = {
  default_ttl: "15m",
  capabilities: [
    { match: "railway:call:{deploy,redeploy}", require: "human_approval" },
    { match: "cloudflare:call:dns_delete", require: "human_approval" },
    {
      match: "github:call:{merge_pull_request,create_or_update_file,delete_file}",
      require: "human_approval",
    },
    { match: "huly:call:*", auto_approve: true, ttl: "15m" },
    { match: "railway:call:*", auto_approve: true, ttl: "15m" },
    { match: "cloudflare:call:*", auto_approve: true, ttl: "15m" },
    { match: "google:call:*", auto_approve: true, ttl: "10m" },
    { match: "github:call:*", auto_approve: true, ttl: "15m" },
    { match: "fakegit:call:*", auto_approve: true, ttl: "15m" },
  ],
};

let policies;
if (fs.existsSync(POLICIES_PATH)) {
  // Merge into the EXISTING file: upsert the ecosystem agent section and
  // preserve everything else (demo-agent, humans' edits). JSON is YAML 1.2;
  // if the file is real YAML, fall back to the yaml package.
  const raw = fs.readFileSync(POLICIES_PATH, "utf8");
  try {
    policies = JSON.parse(raw);
  } catch {
    const YAML = (await import(pathToFileURL(path.join(APP, "node_modules", "yaml", "dist", "index.js")).href)).default;
    policies = YAML.parse(raw);
  }
} else {
  policies = { version: 1, limits: { max_ttl: "1h", deny: ["\\*:*"] }, agents: {} };
}
policies.version ??= 1;
policies.limits ??= { max_ttl: "1h", deny: ["\\*:*"] };
policies.agents ??= {};
const agentWas = policies.agents["nexgen-kimi"] ? "updated" : "added";
policies.agents["nexgen-kimi"] = ECOSYSTEM_AGENT_POLICY;
policies.agents["demo-agent"] ??= {
  default_ttl: "15m",
  capabilities: [
    { match: "fakegit:call:danger", require: "human_approval", ttl: "5m" },
    { match: "fakegit:call:*", auto_approve: true, ttl: "15m" },
  ],
};
policies.agents["*"] ??= { default_ttl: "5m", capabilities: [] };
fs.writeFileSync(POLICIES_PATH, JSON.stringify(policies, null, 2), { mode: 0o600 });
say(`policies: agent 'nexgen-kimi' ${agentWas} (others preserved)`);

say(
  `secrets deposited (keep-first): [${deposited.join(", ")}] (${Object.keys(secrets).length} staged)`,
);
say(`upstreams wired: [${wired.join(", ")}] (total in config: ${cfg.upstreams.length})`);
say(`config: ${CONFIG_PATH} · policies: ${POLICIES_PATH}`);
say("SECURITY NOTE: remove SCOPEGATE_BOOTSTRAP_SECRETS from the service variables now.");
