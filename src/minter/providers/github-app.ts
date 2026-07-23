/**
 * GitHub App provider (EPIC-02 H3): mints installation access tokens.
 *
 * Flow: sign an App JWT (RS256, <=10 min as the API requires) with the App
 * private key from the vault, then exchange it at
 * POST {apiUrl}/app/installations/{installationId}/access_tokens, optionally
 * narrowed by `permissions`/`repositories` from the config.
 *
 * Only the resulting installation token reaches the upstream
 * (`Authorization: Bearer <token>`); the App private key never leaves the
 * vault. `fetch` and the API URL are injectable for tests.
 */
import crypto from "node:crypto";
import type { UpstreamAuth } from "../../config/config.js";
import type { Vault } from "../../vault/vault.js";
import type { CredentialProvider, MintedCredential, MintOpts } from "../minter.js";
import { base64url } from "./jwt.js";

/** GitHub installation tokens live 1h — the provider ceiling. */
const INSTALLATION_TOKEN_TTL_MS = 3_600_000;
/** App JWT lifetime: GitHub requires <=10 min; 60s back-dated iat for skew. */
const APP_JWT_TTL_S = 600;
const APP_JWT_IAT_SKEW_S = 60;

const DEFAULT_API_URL = "https://api.github.com";

type FetchLike = (url: string, init?: Record<string, unknown>) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/** Build the RS256 App JWT GitHub requires for App-level API calls. */
export function buildAppJwt(appId: string, privateKeyPem: string, nowMs: number): string {
  const nowS = Math.floor(nowMs / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = base64url(
    JSON.stringify({
      iat: nowS - APP_JWT_IAT_SKEW_S,
      exp: nowS + APP_JWT_TTL_S,
      iss: appId,
    }),
  );
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(`${header}.${body}`);
  const sig = signer.sign(privateKeyPem, "base64url");
  return `${header}.${body}.${sig}`;
}

export class GitHubAppProvider implements CredentialProvider {
  readonly type = "github_app";

  constructor(private fetchFn: FetchLike = fetch as unknown as FetchLike) {}

  supports(auth: UpstreamAuth): boolean {
    return auth.type === "github_app";
  }

  maxTtlMs(): number {
    return INSTALLATION_TOKEN_TTL_MS;
  }

  async mint(auth: UpstreamAuth, vault: Vault, opts: MintOpts): Promise<MintedCredential> {
    if (auth.type !== "github_app") {
      throw new Error(`GitHubAppProvider cannot mint for auth type '${auth.type}'`);
    }
    const nowMs = opts.nowMs ?? Date.now();
    const privateKey = vault.get(auth.secretRef);
    const appJwt = buildAppJwt(auth.appId, privateKey, nowMs);

    const apiUrl = (auth.apiUrl ?? DEFAULT_API_URL).replace(/\/+$/, "");
    const body: Record<string, unknown> = {};
    if (auth.permissions) body.permissions = auth.permissions;
    if (auth.repositories) body.repositories = auth.repositories;

    const res = await this.fetchFn(
      `${apiUrl}/app/installations/${auth.installationId}/access_tokens`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${appJwt}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "scopegate",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) {
      throw new Error(
        `GitHub App token exchange failed (HTTP ${res.status}) for installation ${auth.installationId}`,
      );
    }
    const data = (await res.json()) as { token?: string; expires_at?: string };
    if (!data.token) {
      throw new Error("GitHub App token exchange returned no token");
    }
    const apiExpiry = data.expires_at ? Date.parse(data.expires_at) : Number.NaN;
    const fallbackExpiry = nowMs + INSTALLATION_TOKEN_TTL_MS;
    return {
      value: data.token,
      headers: { Authorization: `Bearer ${data.token}` },
      // stdio ecosystem MCPs (e.g. @modelcontextprotocol/server-github) read
      // the token from this env var — inject the minted installation token,
      // never the App key.
      env: { GITHUB_PERSONAL_ACCESS_TOKEN: data.token },
      // GitHub always issues 1h tokens; a narrower grant cannot shorten them
      // upstream-side, so the gateway treats the token as dead at the clamp
      // and re-mints (short tokens are left to expire, never revoked).
      expiresAt: Math.min(
        Number.isNaN(apiExpiry) ? fallbackExpiry : apiExpiry,
        nowMs + opts.ttlMs,
      ),
    };
  }
}
