#!/usr/bin/env node
/**
 * scopegate — ephemeral credentials & persistent connections for coding agents.
 *
 *   scopegate init             one-shot, idempotent, agent-executable setup
 *   scopegate start            run the gateway (harness launches this via MCP)
 *   scopegate secret add REF   deposit a secret (human, out-of-band)
 *   scopegate secret ls|rm
 *   scopegate status           config + vault refs + upstream health
 *   scopegate audit verify     check hash chain + Ed25519 signatures (exit 1 on tamper)
 *   scopegate audit query      what did an agent/token touch in a time window
 *   scopegate audit reindex    rebuild the derived audit-index.json snapshot
 *   scopegate auth login REF   OAuth device-code re-auth for an upstream (human)
 *   scopegate approvals list   show pending human-approval requests
 *   scopegate approve|deny ID  decide a pending approval (human: TTY or token)
 *   scopegate policies review|accept|reject   PR-style flow for agent proposals
 *   scopegate vaultd           run the vault as an isolated process (IPC socket)
 *   scopegate vault rotate-key re-encrypt the vault with a fresh master key
 *   scopegate rollback         restore harness configs from *.pre-scopegate.bak
 *   scopegate cloud serve      run the ScopeGate Cloud control plane (EPIC-10)
  scopegate cloud enroll     bind this gateway to a cloud team (writes cloud.json)
 */
import { Command } from "commander";
import os from "node:os";
import path from "node:path";
import { runInit } from "./commands/init.js";
import { runGateway } from "./gateway/server.js";
import { startCloudServer } from "./cloud/server/index.js";
import { secretAdd, secretLs, secretRm } from "./commands/secret.js";
import { loadConfig, configExists, CONFIG_PATH } from "./config/config.js";
import { Vault } from "./vault/vault.js";
import { UpstreamProxy, errorMessage } from "./gateway/proxy.js";
import { runVerifyCli } from "./audit/verify.js";
import { runAuthLogin } from "./commands/oauth-login.js";
import { runVaultd } from "./commands/vaultd.js";
import { runVaultRotateKey } from "./commands/vault-rotate.js";
import { restoreFromBackup } from "./commands/init.js";
import { ALL_ADAPTERS, getAdapter } from "./harness/index.js";
import { trackEvent } from "./telemetry/telemetry.js";
import {
  runApprovalsList,
  runApprove,
  runDeny,
} from "./commands/approvals-cli.js";
import {
  runPoliciesAccept,
  runPoliciesReject,
  runPoliciesReview,
} from "./commands/policies-cli.js";
import {
  AUDIT_INDEX_PATH,
  loadOrBuildIndex,
  queryIndex,
  reindex,
} from "./audit/index.js";

const program = new Command();
program
  .name("scopegate")
  .description(
    "Ephemeral credentials & persistent MCP connections gateway for coding agents",
  )
  .version("0.1.0");

program
  .command("init")
  .description("Idempotent setup: vault, policies, harness detection & migration")
  .option("--dry-run", "show what would change without writing harness configs")
  .option("--harness <id>", "only run detection/migration for one harness (e.g. claude-code, kimi-code, cursor, opencode)")
  .action(async (opts) => {
    await runInit({ dryRun: !!opts.dryRun, harness: opts.harness });
    // Opt-in only (SCOPEGATE_TELEMETRY=1); fire-and-forget, never throws.
    trackEvent("init_completed", { version: "0.1.0" });
  });

program
  .command("rollback")
  .description("Restore harness configs from their *.pre-scopegate.bak backups")
  .option("--harness <id>", "only roll back one harness")
  .action((opts) => {
    const adapters = opts.harness ? [getAdapter(opts.harness)] : ALL_ADAPTERS;
    const results = restoreFromBackup(adapters);
    if (results.length === 0) console.log("No backups found — nothing to restore.");
  });

program
  .command("git-credential")
  .description(
    "Git credential-helper (M3): mint an ephemeral GitHub App token per fill, " +
      "governed by the git:credential:<path> capability — no tokens in remote URLs",
  )
  .action(async () => {
    const { runGitCredential } = await import("./commands/git-credential.js");
    await runGitCredential();
  });

program
  .command("inject")
  .description(
    "Materialize a vault secret into a file (M10, governed exception): atomic 0600 write, " +
      "backup, signed audit; vault:inject:<ref> requires human approval by default",
  )
  .option("--ref <secretRef>", "vault secret reference to materialize")
  .option("--out <path>", "destination file (0600)")
  .option("--template <inline>", "inline template containing {{secret}}")
  .option("--template-file <path>", "template file containing {{secret}}")
  .option("--refresh <path>", "re-materialize from the sidecar manifest (secret rotated)")
  .action(async (opts) => {
    const { runInject } = await import("./commands/inject.js");
    await runInject(opts);
  });

program
  .command("honeytoken")
  .description("Honeytoken canaries (decoy credentials that trigger surgical revocation when touched)")
  .addCommand(
    new Command("plant")
      .argument("<name>", "canary name — the decoy lands in the vault as canary:<name>")
      .option("--agent <id>", "attribute the canary to an agent")
      .option("--upstream <name>", "attribute the canary to an upstream")
      .action(async (name: string, opts: { agent?: string; upstream?: string }) => {
        const { Vault } = await import("./vault/vault.js");
        const { plantCanary } = await import("./honeytoken/honeytoken.js");
        const planted = plantCanary(Vault.open(), {
          name,
          agentId: opts.agent,
          upstream: opts.upstream,
        });
        // The VALUE is printed once — deposit it as a decoy wherever a leak
        // would prove exfiltration (a fake repo secret, a bogus .env line).
        console.log(
          JSON.stringify({
            planted: planted.name,
            ref: planted.ref,
            value: planted.value,
            note: "Decoy planted in the vault. Any use of this value as a credential triggers an alert + surgical revocation.",
          }),
        );
      }),
  );

program
  .command("start")
  .description("Run the gateway MCP server (stdio by default; --http for networked deployments)")
  .option(
    "--http",
    "serve MCP over Streamable HTTP instead of stdio (requires SCOPEGATE_HTTP_TOKEN)",
  )
  .option(
    "--port <n>",
    "HTTP listen port (0 = ephemeral; prints 'SCOPEGATE_HTTP_LISTENING port=<n>')",
    "8080",
  )
  .option("--host <h>", "HTTP bind host", "127.0.0.1")
  .action(async (opts) => {
    if (!opts.http) {
      await runGateway();
      return;
    }
    const port = Number(opts.port);
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new Error(`invalid --port: ${opts.port}`);
    }
    await runGateway({ transport: "http", port, host: opts.host });
  });

const auth = program.command("auth").description("Upstream authentication flows");
auth
  .command("login <upstream>")
  .description("OAuth device-code re-authorization for an upstream (human, out-of-band)")
  .action(async (upstream: string) => runAuthLogin({ upstream }));

program
  .command("vaultd")
  .description("Run the vault as an isolated process (unix socket / Windows named pipe)")
  .option("--socket <path>", "override the IPC socket/pipe path")
  .action(async (opts) => runVaultd({ socket: opts.socket }));

const vaultCmd = program.command("vault").description("Vault maintenance");
vaultCmd
  .command("rotate-key")
  .description("Re-encrypt the vault with a fresh master key (optionally migrating backend)")
  .option("--backend <name>", "master key backend: file | dpapi | keychain | secret-service")
  .action(async (opts) => runVaultRotateKey({ backend: opts.backend }));

const secret = program.command("secret").description("Manage vault secrets (human-only path)");
secret
  .command("add <ref>")
  .description("Store a secret. Value via hidden prompt or piped stdin — never argv.")
  .action(async (ref: string) => secretAdd(ref));
secret.command("ls").description("List secret ref names (never values)").action(secretLs);
secret.command("rm <ref>").description("Delete a secret").action((ref: string) => secretRm(ref));

// EPIC-08 — human approval channels. Deciding is guarded (interactive TTY or
// SCOPEGATE_APPROVAL_TOKEN) so the agent can never approve its own escalations.
const approvalsCmd = program
  .command("approvals")
  .description("Human approval queue (EPIC-08)");
approvalsCmd
  .command("list")
  .description("List pending approval requests (agent, capability, reason, countdown)")
  .option("--all", "include resolved/expired requests")
  .action((opts) => runApprovalsList({ all: !!opts.all }));

program
  .command("approve <id>")
  .description("Approve a pending capability request (human-only: TTY or SCOPEGATE_APPROVAL_TOKEN)")
  .option("--ttl <ttl>", "shorten the requested TTL (e.g. 5m) — can only shorten, never extend")
  .action((id: string, opts) => runApprove(id, { ttl: opts.ttl }));

program
  .command("deny <id>")
  .description("Deny a pending capability request (human-only: TTY or SCOPEGATE_APPROVAL_TOKEN)")
  .requiredOption("--reason <reason>", "why the request is denied (shown to the agent)")
  .action((id: string, opts) => runDeny(id, { reason: opts.reason }));

const policiesCmd = program
  .command("policies")
  .description("PR-style review of agent-proposed policy rules (EPIC-08)");
policiesCmd
  .command("review")
  .description("List proposals in policies.pending.yaml awaiting human review")
  .option("--all", "include accepted/rejected proposals (history)")
  .action((opts) => runPoliciesReview({ all: !!opts.all }));
policiesCmd
  .command("accept <n>")
  .description("Append proposal #n to policies.yaml (human-only; the ONLY automated writer of policies.yaml)")
  .action((n: string) => runPoliciesAccept(n));
policiesCmd
  .command("reject <n>")
  .description("Mark proposal #n as rejected, kept as history (human-only)")
  .requiredOption("--reason <reason>", "why the proposal is rejected")
  .action((n: string, opts) => runPoliciesReject(n, { reason: opts.reason }));

program
  .command("status")
  .description("Show config, vault refs and upstream health")
  .action(async () => {
    if (!configExists()) {
      console.log(`No config at ${CONFIG_PATH}. Run: scopegate init`);
      return;
    }
    const cfg = loadConfig();
    const vault = Vault.open();
    console.log(`agentId:   ${cfg.agentId}`);
    console.log(`upstreams: ${cfg.upstreams.map((u) => u.name).join(", ") || "(none)"}`);
    console.log(`vault:     [${vault.listRefs().join(", ")}]`);
    const proxy = new UpstreamProxy(cfg.upstreams, vault);
    const report = await proxy.diagnose();
    for (const [name, r] of Object.entries(report)) {
      console.log(
        `  ${r.ok ? "✓" : "✗"} ${name}${r.ok ? ` (${r.tools} tools)` : ` — ${r.error}`}`,
      );
    }
    await proxy.closeAll();
  });

const auditCmd = program
  .command("audit")
  .description("Verify and query the signed audit trail (EPIC-07)");
auditCmd
  .command("verify")
  .description(
    "Verify seq continuity, the hash chain and the Ed25519 signature of every event. Exit 1 names the first invalid event's seq.",
  )
  .action(() => {
    process.exitCode = runVerifyCli();
  });
auditCmd
  .command("query")
  .description(
    "Answer 'what did this agent/token touch in a window'. Matching events as JSONL on stdout.",
  )
  .option("--agent <id>", "filter by agentId")
  .option("--kind <kind>", "filter by event kind (e.g. tool_call, secret_ref_used)")
  .option("--since <iso>", "inclusive window start (ISO 8601)")
  .option("--until <iso>", "inclusive window end (ISO 8601)")
  .option("--limit <n>", "max events to print")
  .action((opts) => {
    const events = queryIndex(loadOrBuildIndex(), {
      agent: opts.agent,
      kind: opts.kind,
      since: opts.since,
      until: opts.until,
      limit: opts.limit !== undefined ? Number(opts.limit) : undefined,
    });
    for (const e of events) console.log(JSON.stringify(e));
    console.error(`${events.length} event(s) matched.`);
  });
auditCmd
  .command("reindex")
  .description(
    "Rebuild the derived audit-index.json snapshot from audit.jsonl (verifies the trail first).",
  )
  .action(() => {
    const idx = reindex();
    console.log(`reindexed ${idx.events.length} event(s) → ${AUDIT_INDEX_PATH}`);
  });

// EPIC-10 — ScopeGate Cloud control plane (optional layer; the gateway is
// local-first and never needs this to operate).
const cloudCmd = program
  .command("cloud")
  .description("ScopeGate Cloud management plane (EPIC-10)");
cloudCmd
  .command("serve")
  .description(
    "Run the multi-tenant control plane: /v1 API + dashboard. Prints " +
      "'SCOPEGATE_CLOUD_LISTENING port=<n>' on stdout once listening.",
  )
  .option(
    "--port <n>",
    "listen port (0 = ephemeral; default: env PORT, else 8787)",
  )
  .option(
    "--home <dir>",
    "cloud data home (identity + data/)",
    path.join(os.homedir(), ".scopegate-cloud"),
  )
  .action(async (opts) => {
    // PaaS convention (Railway/Fly/Heroku): the platform injects PORT and the
    // process must bind it — env wins over the built-in default, never over
    // an explicit --port flag.
    const portRaw = opts.port ?? process.env.PORT ?? "8787";
    const port = Number(portRaw);
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new Error(`invalid --port: ${portRaw}`);
    }
    // The listening server keeps the process alive; the parseable
    // SCOPEGATE_CLOUD_* lines are printed by startCloudServer.
    await startCloudServer({ port, home: opts.home });
  });

cloudCmd
  .command("enroll")
  .description(
    "Bind this gateway to a ScopeGate Cloud team (M13): sends the identity " +
      "PUBKEY fingerprint (never private keys, never vault secrets) plus the " +
      "one-shot enroll token, and writes cloud.json. Prints the enrolled " +
      "config as JSON (agentSecret omitted — it only lands in cloud.json, mode 0600).",
  )
  .requiredOption("--cloud <url>", "base URL of the cloud API (e.g. http://127.0.0.1:8787)")
  .requiredOption("--token <enrollToken>", "one-shot enroll token from the dashboard / admin API")
  .option("--agent <id>", "override the agent identity to enroll (default: env/config agentId)")
  .action(async (opts) => {
    const { enrollGateway } = await import("./cloud/client/enroll.js");
    const cfg = await enrollGateway({
      url: opts.cloud,
      enrollToken: opts.token,
      agentId: opts.agent,
    });
    const { agentSecret: _withheld, ...printable } = cfg;
    console.log(JSON.stringify(printable, null, 2));
  });

// Single exit point for CLI failures: actionable message to stderr, non-zero
// exit code, no stack trace (stacks only at SCOPEGATE_LOG_LEVEL=debug).
program.parseAsync(process.argv).catch((e: unknown) => {
  console.error(`[scopegate] ERROR: ${errorMessage(e)}`);
  if (
    (process.env.SCOPEGATE_LOG_LEVEL ?? "").toLowerCase() === "debug" &&
    e instanceof Error &&
    e.stack
  ) {
    console.error(e.stack);
  }
  process.exitCode = 1;
});
