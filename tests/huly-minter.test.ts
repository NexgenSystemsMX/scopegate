/**
 * Huly minter provider tests (EPIC-13): chained login -> selectWorkspace with
 * an injected account-client factory, minter cache (no re-login on hit),
 * renewal at 80% of the TTL, actionable errors for each failure mode
 * (invalid blob / bad login / unknown workspace / service down), accountsUrl
 * precedence, JWT exp honored — and no secret material in errors or output.
 *
 * Isolation: every test gets its own throwaway SCOPEGATE_HOME via helpers;
 * src modules are imported dynamically AFTER useTempHome().
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";
import type { UpstreamConfig } from "../src/config/config.js";
import type {
  HulyAccountClientFactory,
  HulyAccountClientLike,
} from "../src/minter/providers/huly.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  vi.useRealTimers();
  cleanupTempHome(home);
});

const EMAIL = "bot@nexgen.io";
const PASSWORD = "s3cret-account-pass";
const LOGIN_TOKEN = "huly-login-session-token";
const WS_TOKEN = "huly-workspace-token";
const WS_ENDPOINT = "wss://huly2.nexgen.systems/ws";

function upstreamOf(auth: UpstreamConfig["auth"], name = "up"): UpstreamConfig {
  return { name, transport: { kind: "http", url: "http://127.0.0.1:9/mcp" }, auth };
}

function fakeJwt(payload: Record<string, unknown>): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(payload)}.sig`;
}

/** PlatformError-shaped error, like @hcengineering/platform throws. */
function platformError(code: string, params: Record<string, unknown>): Error {
  const err = new Error(`ERROR: ${code} ${JSON.stringify(params)}`);
  (err as { status?: unknown }).status = { code, params };
  return err;
}

interface MockHarness {
  factory: HulyAccountClientFactory;
  factoryCalls: { accountsUrl: string; token?: string }[];
  client: HulyAccountClientLike;
  login: ReturnType<typeof vi.fn>;
  selectWorkspace: ReturnType<typeof vi.fn>;
}

/** Factory mock: records (accountsUrl, token) per call, serves one mock client. */
function makeHarness(
  loginImpl: (email: string, password: string) => Promise<{ token?: string }>,
  selectImpl: (workspace: string) => Promise<
    { endpoint?: string; token?: string; workspace?: string } | undefined
  >,
): MockHarness {
  const factoryCalls: { accountsUrl: string; token?: string }[] = [];
  const login = vi.fn(loginImpl);
  const selectWorkspace = vi.fn(selectImpl);
  const client: HulyAccountClientLike = { login, selectWorkspace };
  const factory: HulyAccountClientFactory = (accountsUrl, token) => {
    factoryCalls.push({ accountsUrl, token });
    return client;
  };
  return { factory, factoryCalls, client, login, selectWorkspace };
}

const okLogin = async () => ({ token: LOGIN_TOKEN });
const okSelect = async (workspace: string) => ({
  endpoint: WS_ENDPOINT,
  token: WS_TOKEN,
  workspace,
});

async function setup(factory: HulyAccountClientFactory, blob: unknown) {
  const { Vault } = await import("../src/vault/vault.js");
  const { Minter } = await import("../src/minter/minter.js");
  const { HulyProvider } = await import("../src/minter/providers/huly.js");

  const vault = Vault.open();
  vault.set("huly_nexgen", typeof blob === "string" ? blob : JSON.stringify(blob));
  const minter = new Minter(vault, [
    new HulyProvider(factory, (url) => Promise.resolve(url)),
  ]);
  return { minter };
}

const goodBlob = { email: EMAIL, password: PASSWORD, workspace: "nexgen" };

describe("huly provider", () => {
  it("chains login -> selectWorkspace and injects HULY_* env (default accountsUrl)", async () => {
    const h = makeHarness(okLogin, okSelect);
    const { minter } = await setup(h.factory, goodBlob);

    const res = await minter.resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }));
    expect(res).not.toBeNull();
    expect(res!.provider).toBe("huly");
    expect(res!.minted).toBe(true);

    // login with the blob credentials against the DEFAULT accounts URL...
    expect(h.login).toHaveBeenCalledTimes(1);
    expect(h.login).toHaveBeenCalledWith(EMAIL, PASSWORD);
    expect(h.factoryCalls[0]).toEqual({
      accountsUrl: "https://huly2.nexgen.systems",
      token: undefined,
    });
    // ...then selectWorkspace with the login session token on the second client.
    expect(h.selectWorkspace).toHaveBeenCalledTimes(1);
    expect(h.selectWorkspace).toHaveBeenCalledWith("nexgen");
    expect(h.factoryCalls[1]).toEqual({
      accountsUrl: "https://huly2.nexgen.systems",
      token: LOGIN_TOKEN,
    });

    // Only the workspace token is injected — never the password or login token.
    expect(res!.cred.value).toBe(WS_TOKEN);
    expect(res!.cred.env).toEqual({
      HULY_TOKEN: WS_TOKEN,
      HULY_ENDPOINT: WS_ENDPOINT,
      HULY_WORKSPACE: "nexgen",
    });
    expect(JSON.stringify(res!.cred.env)).not.toContain(PASSWORD);
    expect(JSON.stringify(res!.cred.env)).not.toContain(LOGIN_TOKEN);
    expect(JSON.stringify(res!.cred.env)).not.toContain(EMAIL);

    expect(minter.modeFor({ type: "huly", secretRef: "huly_nexgen" })).toBe("minted:huly");
  });

  it("caches the workspace token: a second resolve does not re-login", async () => {
    const h = makeHarness(okLogin, okSelect);
    const { minter } = await setup(h.factory, goodBlob);
    const up = upstreamOf({ type: "huly", secretRef: "huly_nexgen" });

    const first = await minter.resolve(up);
    const second = await minter.resolve(up);
    expect(first!.minted).toBe(true);
    expect(second!.minted).toBe(false);
    expect(second!.cred.value).toBe(first!.cred.value);
    expect(h.login).toHaveBeenCalledTimes(1);
    expect(h.selectWorkspace).toHaveBeenCalledTimes(1);
  });

  it("renews past 80% of the TTL (12h default when the token carries no exp)", async () => {
    vi.useFakeTimers();
    const t0 = 1_700_000_000_000;
    vi.setSystemTime(t0);

    let n = 0;
    const h = makeHarness(okLogin, async () => ({
      endpoint: WS_ENDPOINT,
      token: `ws-token-${++n}`, // non-JWT: no exp -> 12h default TTL
    }));
    const { minter } = await setup(h.factory, goodBlob);
    const up = upstreamOf({ type: "huly", secretRef: "huly_nexgen" });

    const first = await minter.resolve(up);
    expect(first!.cred.expiresAt - t0).toBe(12 * 60 * 60 * 1000);

    // 79.86% of the TTL: cache hit, no re-login.
    vi.setSystemTime(t0 + 34_500_000);
    const at79 = await minter.resolve(up);
    expect(at79!.minted).toBe(false);
    expect(h.login).toHaveBeenCalledTimes(1);

    // Past 80%: transparent renewal — a fresh login + selectWorkspace.
    vi.setSystemTime(t0 + 34_600_000);
    const renewed = await minter.resolve(up);
    expect(renewed!.minted).toBe(true);
    expect(renewed!.cred.value).not.toBe(first!.cred.value);
    expect(h.login).toHaveBeenCalledTimes(2);
  });

  it("rejects an invalid vault blob with an actionable, secret-free error", async () => {
    const h = makeHarness(okLogin, okSelect);

    const bad1 = await setup(h.factory, "not-json{{{");
    const err1 = await bad1.minter
      .resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err1!.message).toMatch(/does not hold a valid Huly blob/);
    expect(err1!.message).toContain("huly_nexgen");
    expect(err1!.message).not.toContain("not-json");
    expect(h.login).not.toHaveBeenCalled();

    const bad2 = await setup(h.factory, { email: EMAIL });
    const err2 = await bad2.minter
      .resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(err2!.message).toMatch(/incomplete Huly blob/);
    expect(err2!.message).toContain("password");
    expect(err2!.message).toContain("workspace");
    expect(err2!.message).not.toContain(EMAIL);
    expect(h.login).not.toHaveBeenCalled();
  });

  it("accountsUrl precedence: auth field wins over the blob's", async () => {
    const h = makeHarness(okLogin, okSelect);
    const { minter } = await setup(h.factory, {
      ...goodBlob,
      accountsUrl: "https://blob.invalid",
    });

    await minter.resolve(
      upstreamOf({
        type: "huly",
        secretRef: "huly_nexgen",
        accountsUrl: "https://auth.invalid",
      }),
    );
    expect(h.factoryCalls[0]!.accountsUrl).toBe("https://auth.invalid");

    // Without the auth field, the blob's accountsUrl is used.
    const h2 = makeHarness(okLogin, okSelect);
    const { minter: minter2 } = await setup(h2.factory, {
      ...goodBlob,
      accountsUrl: "https://blob.invalid",
    });
    await minter2.resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }));
    expect(h2.factoryCalls[0]!.accountsUrl).toBe("https://blob.invalid");
  });

  it("honors the JWT exp claim and clamps expiry to the grant TTL", async () => {
    vi.useFakeTimers();
    const t0 = 1_700_000_000_000;
    vi.setSystemTime(t0);

    const jwt = fakeJwt({ exp: Math.floor(t0 / 1000) + 3600 });
    const h = makeHarness(okLogin, async () => ({ endpoint: WS_ENDPOINT, token: jwt }));
    const { minter } = await setup(h.factory, goodBlob);

    // exp (1h) wins over the 12h provider ceiling.
    const res = await minter.resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }));
    expect(res!.cred.expiresAt).toBe(t0 + 3_600_000);

    // A narrower grant narrows the reported expiry further.
    const clamped = await minter.resolve(
      upstreamOf({ type: "huly", secretRef: "huly_nexgen" }, "up2"),
      { grantTtlMs: 60_000 },
    );
    expect(clamped!.cred.expiresAt).toBe(t0 + 60_000);
  });

  it("distinguishes bad login / unknown workspace / service down — without leaking secrets", async () => {
    // 1. Bad credentials: PlatformError(InvalidPassword) whose raw message
    //    embeds the account email — the surfaced error must not.
    const badLogin = makeHarness(
      async () => {
        throw platformError("platform:status:InvalidPassword", { account: EMAIL });
      },
      okSelect,
    );
    const { minter: m1 } = await setup(badLogin.factory, goodBlob);
    const errLogin = await m1
      .resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(errLogin!.message).toMatch(/Huly login failed/);
    expect(errLogin!.message).toContain("platform:status:InvalidPassword");
    expect(errLogin!.message).not.toContain(EMAIL);
    expect(errLogin!.message).not.toContain(PASSWORD);

    // 2. Unknown workspace: login ok, selectWorkspace rejected.
    const badWs = makeHarness(okLogin, async () => {
      throw platformError("platform:status:WorkspaceNotFound", { workspaceUrl: "nexgen" });
    });
    const { minter: m2 } = await setup(badWs.factory, goodBlob);
    const errWs = await m2
      .resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(errWs!.message).toMatch(/workspace 'nexgen' not found/);
    expect(errWs!.message).not.toContain(PASSWORD);
    expect(errWs!.message).not.toContain(LOGIN_TOKEN);
    expect(errWs!.message).not.toContain(EMAIL);

    // 3. Account service down: fetch-level failure -> unreachable, with the URL.
    const down = makeHarness(
      async () => {
        throw new TypeError("fetch failed", { cause: { code: "ECONNREFUSED" } });
      },
      okSelect,
    );
    const { minter: m3 } = await setup(down.factory, goodBlob);
    const errDown = await m3
      .resolve(upstreamOf({ type: "huly", secretRef: "huly_nexgen" }))
      .then(() => null, (e: unknown) => e as Error);
    expect(errDown!.message).toMatch(/account service unreachable/);
    expect(errDown!.message).toContain("https://huly2.nexgen.systems");
    expect(errDown!.message).not.toContain(PASSWORD);
    expect(errDown!.message).not.toContain(EMAIL);
  });
});

describe("resolveAccountsUrl (config.json discovery)", () => {
  it("returns the URL unchanged when it already points at /_accounts", async () => {
    const { resolveAccountsUrl } = await import("../src/minter/providers/huly.js");
    const fetchImpl = vi.fn();
    await expect(
      resolveAccountsUrl("https://huly2.nexgen.systems/_accounts", fetchImpl as never),
    ).resolves.toBe("https://huly2.nexgen.systems/_accounts");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("discovers ACCOUNTS_URL from <base>/config.json on a bare base URL", async () => {
    const { resolveAccountsUrl } = await import("../src/minter/providers/huly.js");
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ ACCOUNTS_URL: "https://huly2.nexgen.systems/_accounts" }), {
        status: 200,
      }),
    );
    await expect(
      resolveAccountsUrl("https://huly2.nexgen.systems", fetchImpl as never),
    ).resolves.toBe("https://huly2.nexgen.systems/_accounts");
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://huly2.nexgen.systems/config.json",
      expect.anything(),
    );
  });

  it("falls back to <base>/_accounts when discovery fails", async () => {
    const { resolveAccountsUrl } = await import("../src/minter/providers/huly.js");
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("fetch failed");
    });
    await expect(
      resolveAccountsUrl("https://huly.example", fetchImpl as never),
    ).resolves.toBe("https://huly.example/_accounts");
  });
});
