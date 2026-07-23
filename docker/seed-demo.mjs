#!/usr/bin/env node
/**
 * ScopeGate DEMO seed (container only). EVERYTHING this script creates is
 * FAKE and for demos: a fake upstream (fakegit backed by fake-upstream.mjs),
 * a fake vault secret (demo-fake-token) and demo policies. It never reads,
 * generates or deposits a real secret.
 *
 * Idempotent: if $SCOPEGATE_HOME/scopegate.yaml already exists, this is a
 * no-op (the entrypoint also guards on that file, so this is belt & braces).
 *
 * Layout it produces in $SCOPEGATE_HOME (default /data):
 *   scopegate.yaml   config: one stdio upstream `fakegit` (env FAKE_TOKEN ←
 *                    vault ref `fake_token`) — refs only, never values
 *   policies.yaml    demo-agent: auto_approve fakegit:call:* (ttl 15m);
 *                    fakegit:call:danger requires human approval (shows the
 *                    EPIC-08 flow); limits deny the literal '*:*' injection
 *   vault.enc        fake_token deposited through the package vault API
 *                    (encrypted at rest like any secret). The value is the
 *                    fixture the demo upstream treats as its valid credential
 *                    ("supersecret123", hardcoded in fake-upstream.mjs whoami)
 *                    — a fake demo string, never a real secret.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url)); // /app/docker
const APP = path.dirname(HERE); // /app
const HOME = process.env.SCOPEGATE_HOME ?? "/data";
const CONFIG_PATH = path.join(HOME, "scopegate.yaml");
const POLICIES_PATH = path.join(HOME, "policies.yaml");

const say = (msg) => console.log(`[seed-demo] ${msg}`);

if (fs.existsSync(CONFIG_PATH)) {
  say(`config already exists at ${CONFIG_PATH} — no-op (idempotent).`);
  process.exit(0);
}

fs.mkdirSync(HOME, { recursive: true });
// dist/config/config.js resolves paths from SCOPEGATE_HOME at module load —
// fix the env BEFORE the dynamic import of the vault API.
process.env.SCOPEGATE_HOME = HOME;
// No vaultd in the demo container: use the in-process vault deterministically.
process.env.SCOPEGATE_VAULT_MODE ??= "local";

// JSON is valid YAML 1.2 — same trick as the e2e suite. No secrets here:
// the config references the vault by NAME (`fake_token`) only.
const config = {
  version: 1,
  agentId: "demo-agent",
  upstreams: [
    {
      name: "fakegit",
      transport: {
        kind: "stdio",
        command: "node",
        args: [path.join(APP, "fake-upstream.mjs")],
      },
      auth: { type: "env", env: { FAKE_TOKEN: "fake_token" } },
    },
  ],
};
fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });

// Rule order matters: the engine evaluates capabilities top-down, first
// match wins — so the human-approval showcase (danger) precedes the broad
// auto_approve glob.
const policies = {
  version: 1,
  limits: {
    max_ttl: "1h",
    deny: ["\\*:*"], // literal '*:*' injection asks (escaped glob)
  },
  agents: {
    "demo-agent": {
      default_ttl: "15m",
      capabilities: [
        { match: "fakegit:call:danger", require: "human_approval", ttl: "5m" },
        { match: "fakegit:call:*", auto_approve: true, ttl: "15m" },
      ],
    },
  },
};
fs.writeFileSync(POLICIES_PATH, JSON.stringify(policies, null, 2), { mode: 0o600 });

// Deposit the FAKE token through the package vault API (encrypted at rest).
// The value is the credential the demo upstream recognizes (its whoami
// fixture answers authenticated=true only for it) — fake by construction.
const { Vault } = await import(
  pathToFileURL(path.join(APP, "dist", "vault", "vault.js")).href
);
const vault = Vault.open();
if (!vault.has("fake_token")) {
  vault.set("fake_token", "supersecret123");
}

say("DEMO home seeded — everything below is fake, zero real secrets:");
say(`  home:      ${HOME}`);
say(`  config:    ${CONFIG_PATH} (upstream: fakegit → node fake-upstream.mjs)`);
say(`  policies:  ${POLICIES_PATH} (demo-agent: auto fakegit:call:* 15m; danger ⇒ human approval)`);
say(`  vault:     fake_token deposited (the FAKE credential the demo upstream recognizes)`);
say("next: scopegate start --http --port 8080 --host 0.0.0.0 (the image CMD)");
