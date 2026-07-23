/**
 * Token Minter tests (EPIC-02): provider roundtrips, cache renewal at 80% of
 * the TTL, grant-TTL clamping, and the declared fallback:injection mode.
 *
 * Isolation: every test gets its own throwaway SCOPEGATE_HOME via helpers;
 * src modules are imported dynamically AFTER useTempHome() (config paths are
 * resolved at module load).
 */
import crypto from "node:crypto";
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AssumeRoleCommand, GetSessionTokenCommand } from "@aws-sdk/client-sts";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { UpstreamConfig } from "../src/config/config.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  vi.useRealTimers();
  cleanupTempHome(home);
});

function upstreamOf(auth: UpstreamConfig["auth"], name = "up"): UpstreamConfig {
  return { name, transport: { kind: "http", url: "http://127.0.0.1:9/mcp" }, auth };
}

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const [h, p] = token.split(".");
  return {
    header: JSON.parse(Buffer.from(h, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(p, "base64url").toString("utf8")),
  };
}

describe("jwt provider", () => {
  it("mints an HS256 JWT that verifies with the vault key and carries the expected claims", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");
    const { JwtProvider, verifyHs256 } = await import("../src/minter/providers/jwt.js");

    const vault = Vault.open();
    vault.set("jwt_key", "test-signing-key-0123456789abcdef");
    const minter = new Minter(vault, [new JwtProvider()]);

    const res = await minter.resolve(
      upstreamOf({ type: "jwt", secretRef: "jwt_key", ttl: "5m", claims: { sub: "agent-x" } }),
      { grantTtlMs: 300_000, agentId: "agent-x" },
    );
    expect(res).not.toBeNull();
    expect(res!.minted).toBe(true);
    expect(res!.provider).toBe("jwt");

    const token = res!.cred.value;
    expect(res!.cred.headers?.Authorization).toBe(`Bearer ${token}`);
    expect(verifyHs256(token, "test-signing-key-0123456789abcdef")).toBe(true);

    const { header, payload } = decodeJwt(token);
    expect(header.alg).toBe("HS256");
    expect(payload.iss).toBe("scopegate");
    expect(payload.aud).toBe("up");
    expect(payload.sub).toBe("agent-x");
    expect(typeof payload.jti).toBe("string");
    expect(payload.exp as number).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 300);
    // The vault key never leaks into headers/token material.
    expect(JSON.stringify(res!.cred.headers)).not.toContain("test-signing-key");
  });

  it("clamps token TTL to the remaining grant TTL", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");
    const { JwtProvider } = await import("../src/minter/providers/jwt.js");

    const vault = Vault.open();
    vault.set("jwt_key", "k");
    const minter = new Minter(vault, [new JwtProvider()]);

    const res = await minter.resolve(
      upstreamOf({ type: "jwt", secretRef: "jwt_key" }), // provider ceiling: 15m default
      { grantTtlMs: 60_000 },
    );
    expect(res!.ttlMs).toBe(60_000);
    expect(res!.cred.expiresAt - Date.now()).toBeLessThanOrEqual(60_000);
    const { payload } = decodeJwt(res!.cred.value);
    expect((payload.exp as number) - (payload.iat as number)).toBeLessThanOrEqual(60);
  });
});

describe("minter cache", () => {
  it("hits within 80% of the TTL and re-mints past the renewal threshold", async () => {
    vi.useFakeTimers();
    const t0 = 1_700_000_000_000;
    vi.setSystemTime(t0);

    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");
    const { JwtProvider } = await import("../src/minter/providers/jwt.js");

    const vault = Vault.open();
    vault.set("jwt_key", "k");
    const minter = new Minter(vault, [new JwtProvider()]);
    const up = upstreamOf({ type: "jwt", secretRef: "jwt_key", ttl: "10m" }); // 600_000 ms

    const first = await minter.resolve(up);
    expect(first!.minted).toBe(true);

    // Second resolve within the TTL: cache hit, no re-mint, same token.
    const second = await minter.resolve(up);
    expect(second!.minted).toBe(false);
    expect(second!.cred.value).toBe(first!.cred.value);

    // At 79% of the TTL: still a hit.
    vi.setSystemTime(t0 + 474_000);
    const at79 = await minter.resolve(up);
    expect(at79!.minted).toBe(false);

    // Past 80%: renewal — a fresh token is minted.
    vi.setSystemTime(t0 + 481_000);
    const renewed = await minter.resolve(up);
    expect(renewed!.minted).toBe(true);
    expect(renewed!.cred.value).not.toBe(first!.cred.value);
  });
});

describe("github_app provider", () => {
  it("signs a well-formed RS256 App JWT and exchanges it for an installation token", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");
    const { GitHubAppProvider } = await import("../src/minter/providers/github-app.js");

    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();

    const vault = Vault.open();
    vault.set("gh_app_key", privPem);

    const calls: { url: string; init: Record<string, unknown> }[] = [];
    const mockFetch = async (url: string, init?: Record<string, unknown>) => {
      calls.push({ url, init: init ?? {} });
      return {
        ok: true,
        status: 201,
        json: async () => ({
          token: "ghs_minted_installation_token",
          expires_at: new Date(Date.now() + 3_600_000).toISOString(),
        }),
      };
    };

    const minter = new Minter(vault, [new GitHubAppProvider(mockFetch as never)]);
    const up = upstreamOf({
      type: "github_app",
      appId: "123",
      installationId: "456",
      secretRef: "gh_app_key",
      apiUrl: "https://api.test",
      permissions: { contents: "write" },
      repositories: ["easyorder"],
    });

    const res = await minter.resolve(up);
    expect(res!.provider).toBe("github_app");
    expect(res!.cred.headers?.Authorization).toBe("Bearer ghs_minted_installation_token");
    expect(res!.cred.expiresAt).toBeLessThanOrEqual(Date.now() + 3_600_000);

    // The exchange hit the right endpoint with the narrowed body.
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://api.test/app/installations/456/access_tokens");
    expect(calls[0].init.method).toBe("POST");
    const body = JSON.parse(String(calls[0].init.body));
    expect(body).toEqual({ permissions: { contents: "write" }, repositories: ["easyorder"] });

    // The App JWT on the exchange call is a well-formed, verifiable RS256 JWT.
    const authz = (calls[0].init.headers as Record<string, string>).Authorization;
    const appJwt = authz.replace(/^Bearer /, "");
    const { header, payload } = decodeJwt(appJwt);
    expect(header.alg).toBe("RS256");
    expect(payload.iss).toBe("123");
    expect((payload.exp as number) - (payload.iat as number)).toBeLessThanOrEqual(660);
    const [h, p, sig] = appJwt.split(".");
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(`${h}.${p}`);
    expect(verifier.verify(pubPem, Buffer.from(sig, "base64url"))).toBe(true);

    // Cache: a second resolve does not re-hit the GitHub API.
    const again = await minter.resolve(up);
    expect(again!.minted).toBe(false);
    expect(calls).toHaveLength(1);

    // The App private key never leaves the vault boundary.
    expect(JSON.stringify(res!.cred.headers)).not.toContain("PRIVATE KEY");
  });
});

describe("aws_sts provider", () => {
  async function setup(captured: unknown[]) {
    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");
    const { AwsStsProvider } = await import("../src/minter/providers/aws-sts.js");

    const vault = Vault.open();
    vault.set("aws_master_ACCESS_KEY_ID", "AKIAMASTERKEY");
    vault.set("aws_master_SECRET_ACCESS_KEY", "master-secret");

    const client = {
      send: async (cmd: unknown) => {
        captured.push(cmd);
        return {
          Credentials: {
            AccessKeyId: "ASIASESSION",
            SecretAccessKey: "session-secret",
            SessionToken: "session-token",
            Expiration: new Date(Date.now() + 900_000),
          },
        };
      },
    };
    const minter = new Minter(vault, [new AwsStsProvider(() => client)]);
    return { minter };
  }

  it("mints GetSessionToken credentials and injects them as env", async () => {
    const captured: unknown[] = [];
    const { minter } = await setup(captured);

    const res = await minter.resolve(
      upstreamOf({ type: "aws_sts", secretRef: "aws_master", region: "eu-west-1" }),
      { agentId: "agent-x" },
    );
    expect(res!.provider).toBe("aws_sts");
    expect(captured).toHaveLength(1);
    expect(captured[0]).toBeInstanceOf(GetSessionTokenCommand);
    expect((captured[0] as GetSessionTokenCommand).input.DurationSeconds).toBe(900);

    expect(res!.cred.env).toEqual({
      AWS_ACCESS_KEY_ID: "ASIASESSION",
      AWS_SECRET_ACCESS_KEY: "session-secret",
      AWS_SESSION_TOKEN: "session-token",
    });
    // Master credentials are not part of the injected material.
    expect(JSON.stringify(res!.cred.env)).not.toContain("AKIAMASTERKEY");
    expect(JSON.stringify(res!.cred.env)).not.toContain("master-secret");
  });

  it("uses AssumeRole with a scopegate session name when roleArn is set", async () => {
    const captured: unknown[] = [];
    const { minter } = await setup(captured);

    await minter.resolve(
      upstreamOf({
        type: "aws_sts",
        secretRef: "aws_master",
        roleArn: "arn:aws:iam::123456789012:role/staging",
      }),
      { agentId: "agent-x" },
    );
    expect(captured).toHaveLength(1);
    expect(captured[0]).toBeInstanceOf(AssumeRoleCommand);
    const input = (captured[0] as AssumeRoleCommand).input;
    expect(input.RoleArn).toBe("arn:aws:iam::123456789012:role/staging");
    expect(input.RoleSessionName).toBe("scopegate-agent-x");
  });

  it("respects the STS 900s floor while reporting expiry clamped to the grant", async () => {
    const captured: unknown[] = [];
    const { minter } = await setup(captured);

    const res = await minter.resolve(
      upstreamOf({ type: "aws_sts", secretRef: "aws_master" }),
      { grantTtlMs: 300_000 }, // 5 min grant, below the STS floor
    );
    expect((captured[0] as GetSessionTokenCommand).input.DurationSeconds).toBe(900);
    // Reported expiry is clamped to the grant even though the STS token
    // itself lives the 900s floor.
    expect(res!.cred.expiresAt - Date.now()).toBeLessThanOrEqual(300_000);
  });
});

describe("fallback:injection mode", () => {
  it("declares static bearer/env auth as fallback and never mints for it", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    const { Minter } = await import("../src/minter/minter.js");

    const vault = Vault.open();
    const minter = new Minter(vault); // default providers

    expect(minter.modeFor({ type: "bearer", secretRef: "tok" })).toBe("fallback:injection");
    expect(minter.modeFor({ type: "env", env: { A: "ref" } })).toBe("fallback:injection");
    expect(minter.modeFor({ type: "oauth2", secretRef: "blob" })).toBe("fallback:injection");
    expect(minter.modeFor({ type: "none" })).toBe("none");
    expect(minter.modeFor({ type: "jwt", secretRef: "k" })).toBe("minted:jwt");
    expect(
      minter.modeFor({ type: "github_app", appId: "1", installationId: "2", secretRef: "k" }),
    ).toBe("minted:github_app");
    expect(minter.modeFor({ type: "aws_sts", secretRef: "aws" })).toBe("minted:aws_sts");

    // resolve() returns null for static auth: the proxy injects the long
    // secret itself at the outbound hop (pure fallback, plan risk 8).
    const res = await minter.resolve(upstreamOf({ type: "bearer", secretRef: "tok" }));
    expect(res).toBeNull();
  });
});
