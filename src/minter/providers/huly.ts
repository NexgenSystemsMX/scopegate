/**
 * Huly provider (EPIC-13): mints a short-lived Huly workspace token from
 * long-lived account credentials, following the flow proven against the
 * Nexgen instance (kimi-tag):
 *
 *   login(email, password) -> selectWorkspace(workspace) -> {endpoint, token}
 *
 * Vault convention: auth.secretRef holds a JSON blob
 * {email, password, workspace, accountsUrl?}. The account password NEVER
 * leaves this call frame — only the workspace token is injected, as env vars
 * (HULY_TOKEN / HULY_ENDPOINT / HULY_WORKSPACE) into stdio-spawned upstreams.
 *
 * TTL: the `exp` claim of the workspace JWT when present, else a 12h default;
 * the Minter cache renews at 80% of the TTL like every other provider.
 * Renewal applies to NEW spawns/connections minted after the renewal —
 * an already-spawned stdio child keeps the env it was born with (env vars
 * cannot be mutated in a live child); the proxy's M2 self-heal respawns on
 * auth failure and picks up the fresh token then.
 *
 * The account client is injectable for tests. @hcengineering/account-client
 * ships CJS with no type declarations, so it is loaded with createRequire
 * (lazily — importing this module stays side-effect free) and typed here with
 * a minimal structural interface.
 */
import { createRequire } from "node:module";
import type { UpstreamAuth } from "../../config/config.js";
import type { Vault } from "../../vault/vault.js";
import type {
  CredentialProvider,
  MintedCredential,
  MintOpts,
} from "../minter.js";

/** Default Nexgen account service; overridden by auth.accountsUrl, then the blob's. */
const DEFAULT_ACCOUNTS_URL = "https://huly2.nexgen.systems";
/** Fallback workspace-token TTL when the JWT carries no usable `exp`: 12h. */
const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;

/** Vault blob v1 stored at auth.secretRef (JSON). */
export interface HulySecretBlob {
  email: string;
  password: string;
  workspace: string;
  accountsUrl?: string;
}

/** Minimal account-client surface used by this provider (tests inject a mock). */
export interface HulyAccountClientLike {
  login(email: string, password: string): Promise<{ token?: string }>;
  selectWorkspace(
    workspace: string,
  ): Promise<{ endpoint?: string; token?: string; workspace?: string } | undefined>;
}

export type HulyAccountClientFactory = (
  accountsUrl: string,
  token?: string,
) => HulyAccountClientLike;

const defaultFactory: HulyAccountClientFactory = (accountsUrl, token) => {
  const { getClient } = createRequire(import.meta.url)(
    "@hcengineering/account-client",
  ) as {
    getClient: (accountsUrl?: string, token?: string) => HulyAccountClientLike;
  };
  return getClient(accountsUrl, token);
};

/** Decodes the `exp` claim (seconds) of a JWT without verifying it. */
export function jwtExpMs(token: string): number | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8"),
    ) as { exp?: unknown };
    return typeof payload.exp === "number" && Number.isFinite(payload.exp)
      ? payload.exp * 1000
      : undefined;
  } catch {
    return undefined;
  }
}

/** PlatformError code (e.g. "platform:status:WorkspaceNotFound"), when the error carries one. */
function platformCodeOf(err: unknown): string | undefined {
  if (typeof err !== "object" || err === null) return undefined;
  const code = (err as { status?: { code?: unknown } }).status?.code;
  return typeof code === "string" ? code : undefined;
}

/**
 * True when the failure is the account service being down/unreachable, not an
 * auth verdict: Node's fetch throws TypeError('fetch failed') whose `cause`
 * carries the OS-level code (ECONNREFUSED, ENOTFOUND, ETIMEDOUT...).
 */
function isNetworkError(err: unknown): boolean {
  if (platformCodeOf(err) !== undefined) return false;
  for (const e of [err, (err as { cause?: unknown })?.cause]) {
    if (typeof e !== "object" || e === null) continue;
    const code = (e as { code?: unknown }).code;
    if (
      typeof code === "string" &&
      /^(ECONNREFUSED|ENOTFOUND|ETIMEDOUT|ECONNRESET|EAI_AGAIN|EHOSTUNREACH|UNABLE_TO_VERIFY|CERT_)/.test(
        code,
      )
    ) {
      return true;
    }
    if (e instanceof TypeError && /fetch failed|network/i.test((e as Error).message)) {
      return true;
    }
  }
  return false;
}

function unreachableError(accountsUrl: string, err: unknown): Error {
  const detail = err instanceof Error ? err.message : String(err);
  return new Error(
    `Huly account service unreachable at ${accountsUrl} (${detail}). ` +
      `Check that the instance is up and the accountsUrl is correct.`,
  );
}

/**
 * Resolves the account-service URL from a Huly base URL, mirroring the real
 * client flow (`loadServerConfig(HULY_URL).ACCOUNTS_URL` in kimi-tag): fetch
 * `<base>/config.json` and read ACCOUNTS_URL. If the URL already points at an
 * `/_accounts` endpoint it is used as-is; if the discovery fetch fails, fall
 * back to the standard `<base>/_accounts` layout. Cached per URL so mints
 * don't re-discover. Never throws — discovery always yields a URL.
 */
const discoveredAccountsUrlCache = new Map<string, string>();

export async function resolveAccountsUrl(
  rawUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const trimmed = rawUrl.replace(/\/+$/, "");
  if (trimmed.endsWith("/_accounts")) return trimmed;
  const cached = discoveredAccountsUrlCache.get(trimmed);
  if (cached) return cached;
  let resolved = `${trimmed}/_accounts`;
  try {
    const res = await fetchImpl(`${trimmed}/config.json`, {
      signal: AbortSignal.timeout(8_000),
    });
    if (res.ok) {
      const cfg = (await res.json()) as { ACCOUNTS_URL?: unknown };
      if (typeof cfg.ACCOUNTS_URL === "string" && cfg.ACCOUNTS_URL.length > 0) {
        resolved = cfg.ACCOUNTS_URL;
      }
    }
  } catch {
    // Discovery failed — keep the conventional `/_accounts` fallback.
  }
  discoveredAccountsUrlCache.set(trimmed, resolved);
  return resolved;
}

/** Parses and validates the vault blob — never echoes blob contents in errors. */
function parseBlob(raw: string, ref: string): HulySecretBlob {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `vault ref '${ref}' does not hold a valid Huly blob: expected JSON ` +
        `{email, password, workspace, accountsUrl?} — rewrite it with \`scopegate vault set ${ref}\``,
    );
  }
  const b = (typeof parsed === "object" && parsed !== null ? parsed : {}) as Record<
    string,
    unknown
  >;
  const missing = ["email", "password", "workspace"].filter(
    (k) => typeof b[k] !== "string" || (b[k] as string).length === 0,
  );
  if (missing.length > 0) {
    throw new Error(
      `vault ref '${ref}' holds an incomplete Huly blob: missing/invalid field(s) ` +
        `${missing.join(", ")} — expected {email, password, workspace, accountsUrl?}; ` +
        `rewrite it with \`scopegate vault set ${ref}\``,
    );
  }
  if (b.accountsUrl !== undefined && typeof b.accountsUrl !== "string") {
    throw new Error(
      `vault ref '${ref}' holds an invalid Huly blob: accountsUrl must be a string`,
    );
  }
  return parsed as HulySecretBlob;
}

export class HulyProvider implements CredentialProvider {
  readonly type = "huly";

  constructor(
    private clientFactory: HulyAccountClientFactory = defaultFactory,
    private discover: (url: string) => Promise<string> = resolveAccountsUrl,
  ) {}

  supports(auth: UpstreamAuth): boolean {
    return auth.type === "huly";
  }

  maxTtlMs(auth: UpstreamAuth): number {
    if (auth.type !== "huly") return 0;
    return DEFAULT_TTL_MS;
  }

  async mint(
    auth: UpstreamAuth,
    vault: Vault,
    opts: MintOpts,
  ): Promise<MintedCredential> {
    if (auth.type !== "huly") {
      throw new Error(`HulyProvider cannot mint for auth type '${auth.type}'`);
    }
    const nowMs = opts.nowMs ?? Date.now();
    const blob = parseBlob(vault.get(auth.secretRef), auth.secretRef);
    const rawUrl = auth.accountsUrl ?? blob.accountsUrl ?? DEFAULT_ACCOUNTS_URL;
    // The blob holds the Huly BASE URL (e.g. https://huly2.nexgen.systems);
    // the account service lives behind it — discover it via /config.json.
    const accountsUrl = await this.discover(rawUrl);

    // 1. login(email, password) against the account service. The password
    //    never leaves this frame; errors never echo it (PlatformError
    //    messages embed status.params, which may carry the account email —
    //    so only the status CODE is interpolated, never the raw message).
    let loginToken: string;
    try {
      const login = await this.clientFactory(accountsUrl).login(blob.email, blob.password);
      if (typeof login?.token !== "string" || login.token === "") {
        throw new Error("no-token");
      }
      loginToken = login.token;
    } catch (err) {
      if (isNetworkError(err)) throw unreachableError(accountsUrl, err);
      if (err instanceof Error && err.message === "no-token") {
        throw new Error(
          `Huly login failed for vault ref '${auth.secretRef}': the account service ` +
            `returned no session token. Verify the credentials in the vault blob.`,
        );
      }
      const code = platformCodeOf(err);
      throw new Error(
        `Huly login failed for vault ref '${auth.secretRef}'` +
          (code ? `: rejected by the account service (${code})` : ": unexpected error") +
          `. Verify the email/password in the vault blob (\`scopegate vault set ${auth.secretRef}\`).`,
      );
    }

    // 2. selectWorkspace(workspace) with the session token -> workspace JWT.
    let ws: { endpoint?: string; token?: string; workspace?: string } | undefined;
    try {
      ws = await this.clientFactory(accountsUrl, loginToken).selectWorkspace(blob.workspace);
    } catch (err) {
      if (isNetworkError(err)) throw unreachableError(accountsUrl, err);
      const code = platformCodeOf(err);
      if (code?.includes("WorkspaceNotFound")) {
        throw new Error(
          `Huly workspace '${blob.workspace}' not found (vault ref '${auth.secretRef}'): ` +
            `the account logged in but has no access to that workspace, or the name is wrong.`,
        );
      }
      throw new Error(
        `Huly selectWorkspace('${blob.workspace}') failed for vault ref '${auth.secretRef}'` +
          (code ? `: ${code}` : ": unexpected error") +
          `. Retry; if it persists, re-check the workspace membership of the account.`,
      );
    }
    if (ws === undefined) {
      throw new Error(
        `Huly workspace '${blob.workspace}' not found (vault ref '${auth.secretRef}'): ` +
          `the account service returned no workspace login info.`,
      );
    }
    if (typeof ws.token !== "string" || ws.token === "" || typeof ws.endpoint !== "string" || ws.endpoint === "") {
      throw new Error(
        `Huly account service at ${accountsUrl} returned incomplete workspace login ` +
          `info for '${blob.workspace}' (missing token or endpoint).`,
      );
    }

    // 3. TTL: the workspace token IS a JWT — honor its `exp` when present,
    //    else fall back to the 12h default; always clamped to the grant.
    const tokenExpiryMs = jwtExpMs(ws.token) ?? nowMs + DEFAULT_TTL_MS;
    return {
      value: ws.token,
      env: {
        HULY_TOKEN: ws.token,
        HULY_ENDPOINT: ws.endpoint,
        HULY_WORKSPACE: blob.workspace,
      },
      expiresAt: Math.min(tokenExpiryMs, nowMs + opts.ttlMs),
    };
  }
}
