/**
 * M3: `scopegate git-credential` — the native git credential-helper.
 *
 *   - `credential fill` for a GitHub host mints an installation token via the
 *     github_app provider and prints username/password to stdout (the token
 *     goes straight to git, never through the agent's context).
 *   - The capability `git:credential:<path>` is evaluated by the SAME policy
 *     engine: auto_approve mints; no rule (or require) exits 1 with an
 *     actionable stderr message (git surfaces it).
 *   - Non-GitHub hosts exit silently (other helpers in the chain may answer).
 *   - store/erase are no-ops (the vault is the store).
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts); process argv /
 * stdin / stdout / stderr / exit are stubbed per test.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;
const origArgv = process.argv;
const stdinDescriptor = Object.getOwnPropertyDescriptor(process, "stdin")!;
let exitSpy: ReturnType<typeof vi.spyOn>;
let stdoutSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  home = useTempHome();
  process.env.SCOPEGATE_VAULT_MODE = "local";
  fs.writeFileSync(
    path.join(home, "scopegate.yaml"),
    JSON.stringify({
      version: 1,
      agentId: "git",
      upstreams: [
        {
          name: "ghapp",
          transport: { kind: "http", url: "https://api.test/mcp" },
          auth: {
            type: "github_app",
            appId: "123",
            installationId: "456",
            secretRef: "gh_app_key",
            apiUrl: "https://api.test",
          },
        },
      ],
    }),
  );
  fs.writeFileSync(
    path.join(home, "policies.yaml"),
    JSON.stringify({
      version: 1,
      agents: {
        git: {
          default_ttl: "10m",
          capabilities: [
            { match: "git:credential:easyorder/*", auto_approve: true, ttl: "10m" },
            { match: "git:credential:secret/*", require: "human_approval", ttl: "10m" },
          ],
        },
      },
    }),
  );
  exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw new Error(`__exit_${code ?? 0}__`);
  }) as never);
  stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});

afterEach(() => {
  process.argv = origArgv;
  Object.defineProperty(process, "stdin", stdinDescriptor);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env.SCOPEGATE_VAULT_MODE;
  cleanupTempHome(home);
});

function stubStdin(text: string) {
  Object.defineProperty(process, "stdin", {
    value: Readable.from([text]),
    configurable: true,
  });
}

function stdoutText(): string {
  return stdoutSpy.mock.calls.map((c) => String(c[0])).join("");
}

function stderrText(): string {
  return stderrSpy.mock.calls.map((c) => String(c[0])).join("");
}

describe("scopegate git-credential", () => {
  it("fill for an allowed repo mints an installation token and prints it to stdout", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    Vault.open().set("gh_app_key", privateKey.export({ type: "pkcs8", format: "pem" }).toString());

    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 201,
      json: async () => ({
        token: "ghs_installation_token_123",
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      }),
    }));
    vi.stubGlobal("fetch", fetchMock);

    process.argv = ["node", "scopegate", "get"];
    stubStdin("protocol=https\nhost=github.com\npath=easyorder/api.git\n\n");

    const { runGitCredential } = await import("../src/commands/git-credential.js");
    await runGitCredential();

    expect(exitSpy).not.toHaveBeenCalled();
    const out = stdoutText();
    expect(out).toContain("username=x-access-token");
    expect(out).toContain("password=ghs_installation_token_123");

    // The exchange hit the configured apiUrl installation endpoint.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "https://api.test/app/installations/456/access_tokens",
    );

    // The mint is audited with the repo path (.git stripped).
    const auditLog = fs.readFileSync(path.join(home, "audit.jsonl"), "utf8");
    expect(auditLog).toContain("git_credential_minted");
    expect(auditLog).toContain("easyorder/api");
  });

  it("fill for a repo without a rule exits 1 with an actionable stderr message", async () => {
    process.argv = ["node", "scopegate", "get"];
    stubStdin("protocol=https\nhost=github.com\npath=other/repo\n\n");

    const { runGitCredential } = await import("../src/commands/git-credential.js");
    await expect(runGitCredential()).rejects.toThrow("__exit_1__");
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(stderrText()).toContain("git:credential:other/repo");
    expect(stdoutText()).toBe("");
  });

  it("fill for a repo requiring human approval exits 1 pointing at scopegate approve", async () => {
    process.argv = ["node", "scopegate", "get"];
    stubStdin("protocol=https\nhost=github.com\npath=secret/repo\n\n");

    const { runGitCredential } = await import("../src/commands/git-credential.js");
    await expect(runGitCredential()).rejects.toThrow("__exit_1__");
    expect(stderrText()).toContain("scopegate approve");
  });

  it("non-GitHub hosts exit silently (other helpers in the chain may answer)", async () => {
    process.argv = ["node", "scopegate", "get"];
    stubStdin("protocol=https\nhost=gitlab.com\npath=easyorder/api\n\n");

    const { runGitCredential } = await import("../src/commands/git-credential.js");
    await runGitCredential();
    expect(exitSpy).not.toHaveBeenCalled();
    expect(stdoutText()).toBe("");
    expect(stderrText()).toBe("");
  });

  it("store/erase are no-ops (the vault is the store)", async () => {
    process.argv = ["node", "scopegate", "store"];
    stubStdin("protocol=https\nhost=github.com\n\n");

    const { runGitCredential } = await import("../src/commands/git-credential.js");
    await runGitCredential();
    expect(exitSpy).not.toHaveBeenCalled();
    expect(stdoutText()).toBe("");
  });
});
