/**
 * `scopegate git-credential` — native git credential-helper (M3).
 *
 *   git config --global credential.helper "!scopegate git-credential"
 *
 * Git invokes this on `credential fill` (stdin: protocol/host/path) and reads
 * `username`/`password` from stdout. The installation token is minted on the
 * spot (github_app provider, TTL = min(grant, provider ceiling) and goes
 * STRAIGHT to git — it never passes through the agent's context, never sits
 * in a remote URL, never lands in .git/config for hours.
 *
 * Governance (the four valves, same as everything else):
 *   - capability `git:credential:<path>` evaluated by the SAME policy engine
 *     (auto_approve for e.g. `git:credential:kimi/*`, human approval for the
 *     rest) — a denial or pending approval exits 1 with an actionable
 *     message on stderr (git surfaces it);
 *   - scope per repo path; deny globs fail-closed; revocation <30 s;
 *   - every mint lands in audit.jsonl (`git_credential_minted`).
 *
 * Operations other than `get` (store/erase) exit silently — the vault is the
 * store, git does not write to it.
 */
import readline from "node:readline";
import { loadConfig, type UpstreamAuth } from "../config/config.js";
import { Vault } from "../vault/vault.js";
import { Minter } from "../minter/minter.js";
import { PolicyEngine } from "../policy/engine.js";
import { audit } from "../audit/log.js";

/** The github_app auth of the first configured GitHub App upstream. */
function githubAppAuth(): Extract<UpstreamAuth, { type: "github_app" }> {
  const cfg = loadConfig();
  const up = cfg.upstreams.find((u) => u.auth.type === "github_app");
  if (!up || up.auth.type !== "github_app") {
    throw new Error(
      "No github_app upstream configured — scopegate git-credential mints from the " +
        "GitHub App of your scopegate.yaml (add one with auth.type github_app).",
    );
  }
  return up.auth;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    let buf = "";
    rl.on("line", (l) => {
      buf += l + "\n";
      if (l === "") resolve(buf); // blank line terminates the request
    });
    rl.on("close", () => resolve(buf));
  });
}

/** git credential-helper operations. Anything else is not ours to answer. */
const GIT_CREDENTIAL_OPS = new Set(["get", "store", "erase"]);

/**
 * Resolves the credential operation git asked for.
 *
 * Why this is not `process.argv[2]`: git runs `<helper> <operation>`, and the
 * helper configured in git config is `scopegate git-credential`. So the real
 * argv is `[node, cli.js, "git-credential", "get"]` — argv[2] is the
 * SUBCOMMAND, not the operation, and the helper used to return silently on
 * every fill. The unit test passed because it stubbed argv without the
 * subcommand token, so nothing ever exercised the real shape.
 *
 * Scanning for the first recognized operation makes both invocations work and
 * survives an extra argv element appearing in front (a wrapper script, a
 * different launcher). Absent → "get", which is what git means by a bare fill.
 */
export function resolveGitCredentialOp(argv: readonly string[]): string {
  for (const a of argv.slice(2)) {
    if (GIT_CREDENTIAL_OPS.has(a)) return a;
  }
  return "get";
}

export async function runGitCredential(operation?: string): Promise<void> {
  // The CLI passes the operation explicitly; the argv scan is the fallback for
  // direct invocation of the binary.
  const op = operation ?? resolveGitCredentialOp(process.argv);
  if (op !== "get") return; // store/erase: no-op, the vault is the store

  const raw = await readStdin();
  const fields = Object.fromEntries(
    raw
      .split("\n")
      .filter((l) => l.includes("="))
      .map((l) => {
        const i = l.indexOf("=");
        return [l.slice(0, i), l.slice(i + 1)];
      }),
  ) as Record<string, string>;
  const host = fields.host ?? "";
  if (!/(^|\.)github\.com$/i.test(host) && !/github/i.test(host)) {
    // Not a GitHub host — nothing for us to mint (exit silently, other
    // helpers in the chain may answer).
    return;
  }
  const repoPath = (fields.path ?? "*").replace(/\.git$/, "");

  const agentId = process.env.SCOPEGATE_AGENT_ID ?? "git";
  const policy = PolicyEngine.load();
  const capability = `git:credential:${repoPath}`;
  const decision = policy.request(agentId, capability, undefined, "git credential fill");

  if (!decision.allow) {
    const approvalHint =
      decision.escalation === "human_approval" && decision.approvalId
        ? ` — ask the human to run: scopegate approve ${decision.approvalId}`
        : "";
    audit(agentId, "capability_denied", {
      capability,
      code: decision.code,
      reason: decision.reason,
      via: "git-credential",
    });
    process.stderr.write(
      `scopegate git-credential: capability '${capability}' not granted: ${decision.reason}${approvalHint}\n`,
    );
    process.exit(1);
  }

  const auth = githubAppAuth();
  const minter = new Minter(Vault.open());
  const res = await minter.resolve(
    {
      name: "git-credential",
      transport: { kind: "http", url: auth.apiUrl ?? "https://api.github.com" },
      auth,
    },
    { grantTtlMs: decision.ttlMs, agentId },
  );
  if (!res) {
    process.stderr.write("scopegate git-credential: no credential provider available\n");
    process.exit(1);
  }

  audit(agentId, "git_credential_minted", {
    repo: repoPath,
    capability,
    ttlMs: res.ttlMs,
    provider: res.provider,
  });

  process.stdout.write(`username=x-access-token\npassword=${res.cred.value}\n\n`);
}
