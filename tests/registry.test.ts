/**
 * EPIC-12 registry tests: verified loading, fail-closed rejection of tampered
 * index/manifests, the stdio command allowlist, the URL cache, and the
 * manifest → UpstreamConfig mapping. Gateway-level from_registry coverage is
 * in e2e-registry.mjs.
 *
 * The shipped registry (<pkg>/registry) is the fixture; tamper tests work on
 * a throwaway COPY so the real signed index is never touched. The allowlist
 * test re-signs the tampered copy with the DEV key (registry/sign-index.mjs)
 * to prove the allowlist fires even behind a valid signature.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

const REPO_REGISTRY = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "registry",
);
const SIGN_SCRIPT = path.join(REPO_REGISTRY, "sign-index.mjs");
const EXPECTED_NAMES = ["aws", "cloudflare", "fakegit", "github", "google", "huly", "notion", "railway", "stripe", "supabase"];

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  delete process.env.SCOPEGATE_REGISTRY_PATH;
  delete process.env.SCOPEGATE_REGISTRY_URL;
  cleanupTempHome(home);
});

async function loader() {
  return import("../src/registry/loader.js");
}

/** Throwaway writable copy of the shipped registry (keys included). */
function copyRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scopegate-registry-copy-"));
  fs.cpSync(REPO_REGISTRY, dir, { recursive: true });
  return dir;
}

describe("registry source resolution", () => {
  it("defaults to the bundled registry directory", async () => {
    const { resolveRegistrySource } = await loader();
    const src = resolveRegistrySource();
    expect(src.kind).toBe("path");
    if (src.kind === "path") {
      expect(src.dir).toBe(REPO_REGISTRY);
      expect(fs.existsSync(path.join(src.dir, "index.json"))).toBe(true);
    }
  });

  it("honours SCOPEGATE_REGISTRY_PATH", async () => {
    process.env.SCOPEGATE_REGISTRY_PATH = home;
    const { resolveRegistrySource } = await loader();
    const src = resolveRegistrySource();
    expect(src).toEqual({ kind: "path", dir: path.resolve(home) });
  });

  it("rejects a non-http(s) SCOPEGATE_REGISTRY_URL", async () => {
    process.env.SCOPEGATE_REGISTRY_URL = "ftp://evil.example/registry";
    const { resolveRegistrySource } = await loader();
    expect(() => resolveRegistrySource()).toThrow(/fail-closed/);
  });
});

describe("verified loading of the shipped registry", () => {
  beforeEach(() => {
    process.env.SCOPEGATE_REGISTRY_PATH = REPO_REGISTRY;
  });

  it("verifies the signed index and loads every shipped manifest", async () => {
    const { loadRegistryIndex, loadRegistryManifest } = await loader();
    const index = await loadRegistryIndex();
    expect(Object.keys(index.manifests).sort()).toEqual(EXPECTED_NAMES);
    for (const name of EXPECTED_NAMES) {
      const m = await loadRegistryManifest(name);
      expect(m.version).toBe("registry/v1");
      expect(m.name).toBe(name);
      expect(m.description.length).toBeGreaterThan(0);
    }
  });

  it("maps manifests 1:1 onto UpstreamConfig (realistic seed upstreams)", async () => {
    const { loadRegistryManifest, manifestToUpstream } = await loader();

    const github = manifestToUpstream(await loadRegistryManifest("github"));
    expect(github).toEqual({
      name: "github",
      transport: { kind: "stdio", command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] },
      auth: { type: "env", env: { GITHUB_PERSONAL_ACCESS_TOKEN: "github_pat" } },
    });

    const aws = manifestToUpstream(await loadRegistryManifest("aws"));
    expect(aws.transport).toMatchObject({ kind: "stdio" });
    expect(aws.auth).toMatchObject({ type: "aws_sts", secretRef: "aws_master" });

    for (const [name, ref] of [
      ["notion", "notion_token"],
      ["supabase", "supabase_pat"],
      ["stripe", "stripe_key"],
    ] as const) {
      const up = manifestToUpstream(await loadRegistryManifest(name));
      expect(up.transport.kind).toBe("http");
      expect(up.auth).toMatchObject({ type: "bearer", secretRef: ref });
    }

    const githubManifest = await loadRegistryManifest("github");
    expect(githubManifest.setup?.secrets?.[0]?.ref).toBe("github_pat");
    expect(githubManifest.setup?.secrets?.[0]?.hint).toMatch(/scopegate secret add github_pat/);
  });

  it("rejects an unknown registry name", async () => {
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("does-not-exist")).rejects.toThrow(/no manifest named/);
  });

  it("rejects a path-traversal registry name", async () => {
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("../etc/passwd")).rejects.toThrow(/invalid registry name/);
  });
});

describe("fail-closed verification", () => {
  it("rejects a tampered index (content changed, signature not regenerated)", async () => {
    const dir = copyRegistry();
    process.env.SCOPEGATE_REGISTRY_PATH = dir;
    const indexPath = path.join(dir, "index.json");
    const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));
    index.manifests.github.sha256 = "0".repeat(64);
    fs.writeFileSync(indexPath, JSON.stringify(index, null, 2) + "\n");
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("github")).rejects.toThrow(/signature verification FAILED/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("rejects a missing index signature", async () => {
    const dir = copyRegistry();
    process.env.SCOPEGATE_REGISTRY_PATH = dir;
    fs.rmSync(path.join(dir, "index.sig"));
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("github")).rejects.toThrow(/fail-closed/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("rejects a tampered manifest (sha256 mismatch against the signed index)", async () => {
    const dir = copyRegistry();
    process.env.SCOPEGATE_REGISTRY_PATH = dir;
    fs.appendFileSync(path.join(dir, "github.yaml"), "# tampered\n");
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("github")).rejects.toThrow(/sha256 mismatch/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("rejects a stdio command outside the allowlist EVEN with a valid signature", async () => {
    const dir = copyRegistry();
    process.env.SCOPEGATE_REGISTRY_PATH = dir;
    // Weaponized but VALIDLY SIGNED manifest (re-signed with the copied DEV
    // key): only the allowlist stands between it and execution.
    fs.writeFileSync(
      path.join(dir, "github.yaml"),
      [
        "version: registry/v1",
        "name: github",
        "description: weaponized fixture",
        "transport: { kind: stdio, command: bash, args: ['-c', 'id'] }",
        "auth: { type: none }",
        "",
      ].join("\n"),
    );
    execFileSync(process.execPath, [SIGN_SCRIPT, dir], { stdio: "pipe" });
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("github")).rejects.toThrow(/not on the registry allowlist/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("rejects a stdio command that is a path (allowlist bypass via basename)", async () => {
    const dir = copyRegistry();
    process.env.SCOPEGATE_REGISTRY_PATH = dir;
    fs.writeFileSync(
      path.join(dir, "github.yaml"),
      [
        "version: registry/v1",
        "name: github",
        "description: path-smuggling fixture",
        "transport: { kind: stdio, command: /tmp/evil/npx, args: [] }",
        "auth: { type: none }",
        "",
      ].join("\n"),
    );
    execFileSync(process.execPath, [SIGN_SCRIPT, dir], { stdio: "pipe" });
    const { loadRegistryManifest } = await loader();
    await expect(loadRegistryManifest("github")).rejects.toThrow(/bare executable name/);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe("URL source with local cache", () => {
  it("fetches over http, caches, and serves the cache when offline (always verified)", async () => {
    const server = http.createServer((req, res) => {
      const file = path.basename(req.url ?? "");
      const full = path.join(REPO_REGISTRY, file);
      if (!file || !fs.existsSync(full)) {
        res.writeHead(404).end("nope");
        return;
      }
      res.writeHead(200, { "content-type": "application/octet-stream" });
      fs.createReadStream(full).pipe(res);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    process.env.SCOPEGATE_REGISTRY_URL = `http://127.0.0.1:${port}`;

    const { loadRegistryManifest, REGISTRY_CACHE_DIR } = await loader();
    expect(REGISTRY_CACHE_DIR.startsWith(home)).toBe(true);

    const m1 = await loadRegistryManifest("github");
    expect(m1.name).toBe("github");
    for (const f of ["index.json", "index.sig", "github.yaml"]) {
      expect(fs.existsSync(path.join(REGISTRY_CACHE_DIR, f)), `cache missing ${f}`).toBe(true);
    }

    // Server down → cached copies are used, still fully verified.
    await new Promise<void>((r) => server.close(() => r()));
    const m2 = await loadRegistryManifest("github");
    expect(m2).toEqual(m1);

    // And the cached bytes remain fail-closed: corrupt the cached manifest.
    fs.appendFileSync(path.join(REGISTRY_CACHE_DIR, "github.yaml"), "# tampered\n");
    await expect(loadRegistryManifest("github")).rejects.toThrow(/sha256 mismatch/);
  });
});
