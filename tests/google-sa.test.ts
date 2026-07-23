/**
 * google_sa minter provider tests (EPIC-18): RS256 service-account JWT well
 * formed (claims + verifiable signature with a test-generated RSA key),
 * token exchange with an injected fetch, minter cache + renewal at 80% of the
 * TTL, expires_in honored and clamped to the grant, actionable/secret-free
 * errors for every failure mode (invalid blob / bad key / exchange failure),
 * and registry in the default provider set.
 *
 * Isolation: every test gets its own throwaway SCOPEGATE_HOME via helpers;
 * src modules are imported dynamically AFTER useTempHome().
 */
import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

const CLIENT_EMAIL = "scopegate-bot@test-project.iam.gserviceaccount.com";
const SUBJECT = "admin@example.com";

// A real RSA keypair generated per test run — the JWT signature is verified
// against the public key, exactly like Google would.
const { privateKey: PRIVATE_KEY, publicKey: PUBLIC_KEY } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const GOOD_BLOB = { client_email: CLIENT_EMAIL, private_key: PRIVATE_KEY };

function upstreamOf(auth: UpstreamConfig["auth"], name = "up"): UpstreamConfig {
  return { name, transport: { kind: "http", url: "http://127.0.0.1:9/mcp" }, auth };
}

type FetchImpl = (url: string, init?: Record<string, unknown>) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

function okFetch(accessToken: string, expiresIn = 3599): ReturnType<typeof vi.fn<FetchImpl>> {
  return vi.fn<FetchImpl>(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ access_token: accessToken, expires_in: expiresIn, token_type: "Bearer" }),
  }));
}

async function setup(fetchFn: unknown, blob: unknown = GOOD_BLOB) {
  const { Vault } = await import("../src/vault/vault.js");
  const { Minter } = await import("../src/minter/minter.js");
  const { GoogleSaProvider } = await import("../src/minter/providers/google-sa.js");

  const vault = Vault.open();
  vault.set("google_sa", typeof blob === "string" ? blob : JSON.stringify(blob));
  const minter = new Minter(vault, [new GoogleSaProvider(fetchFn as never)]);
  return { minter, vault };
}

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } {
  const parts = token.split(".");
  expect(parts).toHaveLength(3);
  return {
    header: JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")) as Record<string, unknown>,
    payload: JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as Record<string, unknown>,
    signature: parts[2]!,
  };
}

describe("google_sa provider — service-account JWT", () => {
  it("builds a well-formed RS256 JWT with the frozen claims", async () => {
    const { buildServiceAccountJwt, DEFAULT_GOOGLE_SCOPES, GOOGLE_TOKEN_URL } = await import(
      "../src/minter/providers/google-sa.js"
    );
    const t0 = 1_700_000_000_000;
    const jwt = buildServiceAccountJwt(GOOD_BLOB, DEFAULT_GOOGLE_SCOPES, t0);
    const { header, payload, signature } = decodeJwt(jwt);

    expect(header).toEqual({ alg: "RS256", typ: "JWT" });
    expect(payload.iss).toBe(CLIENT_EMAIL);
    expect(payload.scope).toBe(DEFAULT_GOOGLE_SCOPES.join(" "));
    expect(payload.aud).toBe(GOOGLE_TOKEN_URL);
    // iat is back-dated 60s for clock skew; exp = iat + 3600 (frozen contract).
    expect(payload.iat).toBe(Math.floor(t0 / 1000) - 60);
    expect(payload.exp).toBe((payload.iat as number) + 3600);
    expect(payload.sub).toBeUndefined();

    // The signature verifies against the public key — it is genuinely RS256.
    const [h, b] = jwt.split(".");
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(`${h}.${b}`);
    expect(verifier.verify(PUBLIC_KEY, signature, "base64url")).toBe(true);
  });

  it("includes sub when the blob sets a subject (domain-wide delegation)", async () => {
    const { buildServiceAccountJwt, DEFAULT_GOOGLE_SCOPES } = await import(
      "../src/minter/providers/google-sa.js"
    );
    const jwt = buildServiceAccountJwt({ ...GOOD_BLOB, subject: SUBJECT }, DEFAULT_GOOGLE_SCOPES, Date.now());
    expect(decodeJwt(jwt).payload.sub).toBe(SUBJECT);
  });
});

describe("google_sa provider — token exchange", () => {
  it("exchanges the JWT for an access token and injects GOOGLE_ACCESS_TOKEN", async () => {
    const fetchFn = okFetch("ya29.minted-token");
    const { minter } = await setup(fetchFn);

    const res = await minter.resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }));
    expect(res).not.toBeNull();
    expect(res!.provider).toBe("google_sa");
    expect(res!.minted).toBe(true);
    expect(res!.cred.value).toBe("ya29.minted-token");
    expect(res!.cred.env).toEqual({ GOOGLE_ACCESS_TOKEN: "ya29.minted-token" });

    // Exactly one POST to the OAuth token URL with the JWT-bearer grant.
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0]!;
    expect(url).toBe("https://oauth2.googleapis.com/token");
    expect((init as { method: string }).method).toBe("POST");
    const params = new URLSearchParams((init as { body: string }).body);
    expect(params.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const assertion = params.get("assertion")!;
    expect(decodeJwt(assertion).payload.scope).toContain("drive.readonly");
    // Only the access token leaves the gateway — never the private key.
    expect(JSON.stringify(res!.cred.env)).not.toContain("PRIVATE KEY");
  });

  it("honors expires_in and clamps the expiry to the grant TTL", async () => {
    vi.useFakeTimers();
    const t0 = 1_700_000_000_000;
    vi.setSystemTime(t0);

    const { minter } = await setup(okFetch("ya29.ttl"));
    const res = await minter.resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }));
    expect(res!.cred.expiresAt).toBe(t0 + 3599_000);

    const clamped = await minter.resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }, "up2"), {
      grantTtlMs: 60_000,
    });
    expect(clamped!.cred.expiresAt).toBe(t0 + 60_000);
  });

  it("uses custom auth.scopes instead of the default set", async () => {
    const fetchFn = okFetch("ya29.scoped");
    const { minter } = await setup(fetchFn);
    await minter.resolve(
      upstreamOf({
        type: "google_sa",
        secretRef: "google_sa",
        scopes: ["https://www.googleapis.com/auth/calendar.events"],
      }),
    );
    const params = new URLSearchParams((fetchFn.mock.calls[0]![1] as { body: string }).body);
    const { payload } = decodeJwt(params.get("assertion")!);
    expect(payload.scope).toBe("https://www.googleapis.com/auth/calendar.events");
  });
});

describe("google_sa provider — minter cache", () => {
  it("caches the access token: a second resolve does not re-exchange", async () => {
    const fetchFn = okFetch("ya29.cached");
    const { minter } = await setup(fetchFn);
    const up = upstreamOf({ type: "google_sa", secretRef: "google_sa" });

    const first = await minter.resolve(up);
    const second = await minter.resolve(up);
    expect(first!.minted).toBe(true);
    expect(second!.minted).toBe(false);
    expect(second!.cred.value).toBe(first!.cred.value);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("renews past 80% of the TTL", async () => {
    vi.useFakeTimers();
    const t0 = 1_700_000_000_000;
    vi.setSystemTime(t0);

    let n = 0;
    const fetchFn = vi.fn<FetchImpl>(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ access_token: `ya29.token-${++n}`, expires_in: 3600 }),
    }));
    const { minter } = await setup(fetchFn);
    const up = upstreamOf({ type: "google_sa", secretRef: "google_sa" });

    const first = await minter.resolve(up);
    expect(first!.cred.value).toBe("ya29.token-1");

    // 79.7% of the TTL: cache hit, no re-exchange.
    vi.setSystemTime(t0 + 2_870_000);
    const at79 = await minter.resolve(up);
    expect(at79!.minted).toBe(false);
    expect(fetchFn).toHaveBeenCalledTimes(1);

    // Past 80%: transparent renewal — a fresh exchange.
    vi.setSystemTime(t0 + 2_900_000);
    const renewed = await minter.resolve(up);
    expect(renewed!.minted).toBe(true);
    expect(renewed!.cred.value).toBe("ya29.token-2");
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});

describe("google_sa provider — actionable, secret-free errors", () => {
  it("rejects an invalid vault blob without echoing its contents", async () => {
    const fetchFn = okFetch("unused");
    const bad1 = await setup(fetchFn, "not-json{{{");
    const err1 = await bad1.minter
      .resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err1!.message).toMatch(/does not hold a valid Google service-account blob/);
    expect(err1!.message).toContain("google_sa");
    expect(err1!.message).not.toContain("not-json");
    expect(fetchFn).not.toHaveBeenCalled();

    const bad2 = await setup(fetchFn, { client_email: CLIENT_EMAIL });
    const err2 = await bad2.minter
      .resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err2!.message).toMatch(/incomplete Google service-account blob/);
    expect(err2!.message).toContain("private_key");
    expect(err2!.message).not.toContain(CLIENT_EMAIL);
    expect(fetchFn).not.toHaveBeenCalled();

    const bad3 = await setup(fetchFn, { client_email: CLIENT_EMAIL, private_key: "no-pem-here" });
    const err3 = await bad3.minter
      .resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err3!.message).toMatch(/private_key is not a PEM/);
    expect(err3!.message).not.toContain("no-pem-here");
  });

  it("fails the exchange with Google's diagnostics but never the key or assertion", async () => {
    const fetchFn = vi.fn<FetchImpl>(async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: "invalid_grant", error_description: "Invalid JWT Signature." }),
    }));
    const { minter } = await setup(fetchFn);
    const err = await minter
      .resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err!.message).toMatch(/token exchange failed \(HTTP 400\)/);
    expect(err!.message).toContain("invalid_grant");
    expect(err!.message).toContain("Invalid JWT Signature.");
    expect(err!.message).toContain("google_sa");
    expect(err!.message).not.toContain(PRIVATE_KEY);
    expect(err!.message).not.toContain("BEGIN");
    // The signed assertion carries the client_email — the error must not.
    expect(err!.message).not.toContain(CLIENT_EMAIL);
  });

  it("rejects a malformed RSA key at signing time with an actionable message", async () => {
    const fetchFn = okFetch("unused");
    const { minter } = await setup(fetchFn, {
      client_email: CLIENT_EMAIL,
      private_key: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n",
    });
    const err = await minter
      .resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err!.message).toMatch(/failed to sign the service-account JWT/);
    expect(err!.message).not.toContain("not-a-key");
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("rejects an exchange response without access_token", async () => {
    const fetchFn = vi.fn<FetchImpl>(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ token_type: "Bearer" }),
    }));
    const { minter } = await setup(fetchFn);
    const err = await minter
      .resolve(upstreamOf({ type: "google_sa", secretRef: "google_sa" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err!.message).toMatch(/returned no access_token/);
  });
});

describe("google_sa provider — registration", () => {
  it("is in the default providers: modeFor mints and secretRefsOf audits the ref", async () => {
    const { Minter, secretRefsOf, defaultProviders } = await import("../src/minter/minter.js");
    const { Vault } = await import("../src/vault/vault.js");
    const vault = Vault.open();
    const minter = new Minter(vault);

    expect(defaultProviders().map((p) => p.type)).toContain("google_sa");
    expect(minter.modeFor({ type: "google_sa", secretRef: "google_sa" })).toBe("minted:google_sa");
    expect(secretRefsOf({ type: "google_sa", secretRef: "google_sa" })).toEqual(["google_sa"]);
    expect(minter.providerFor({ type: "google_sa", secretRef: "google_sa" })?.type).toBe("google_sa");
  });
});
