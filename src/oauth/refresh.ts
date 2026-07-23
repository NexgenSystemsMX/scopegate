/**
 * OAuth2 refresh client (RFC 6749 §6): POST `grant_type=refresh_token` to the
 * blob's token_url and classify the outcome so the daemon can react:
 *
 *   - success            → new access token (+ rotated refresh_token when the
 *                          server sends one — the caller MUST persist it)
 *   - invalid_grant /
     invalid_client     → the grant is dead: human re-authorization required
 *   - network / 429 / 5xx → retryable: back off and try again
 *   - anything else      → fatal: not retryable, not a re-auth signal
 *
 * This module NEVER logs token material and never touches the vault — blob
 * persistence is the daemon's job (single-writer rule).
 */

export type RefreshErrorKind = "invalid_grant" | "retryable" | "fatal";

export class RefreshError extends Error {
  constructor(
    message: string,
    readonly kind: RefreshErrorKind,
    readonly status?: number,
  ) {
    super(message);
    this.name = "RefreshError";
  }
}

export interface RefreshedTokens {
  access_token: string;
  /** Present only when the server rotated the refresh token. */
  refresh_token?: string;
  /** Seconds; servers that omit it default to 3600 (RFC 6749 §5.1). */
  expires_in: number;
  scope?: string;
}

/** Default TTL when the token endpoint omits `expires_in`. */
const DEFAULT_EXPIRES_IN_S = 3600;
/** A hung token endpoint must not stall the daemon's queue forever. */
const TOKEN_REQUEST_TIMEOUT_MS = 10_000;

export async function postRefreshGrant(
  blob: {
    refresh_token?: string;
    token_url: string;
    client_id: string;
    client_secret?: string;
  },
  fetchImpl: typeof fetch = fetch,
): Promise<RefreshedTokens> {
  if (!blob.refresh_token) {
    throw new RefreshError(
      "OAuth blob has no refresh_token — the grant cannot be renewed",
      "invalid_grant",
    );
  }
  const params = new URLSearchParams();
  params.set("grant_type", "refresh_token");
  params.set("refresh_token", blob.refresh_token);
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };
  // Client auth: HTTP Basic when a secret exists (RFC 6749 §2.3.1), else the
  // public-client form (client_id in the body).
  if (blob.client_secret) {
    headers.authorization = `Basic ${Buffer.from(
      `${blob.client_id}:${blob.client_secret}`,
    ).toString("base64")}`;
  } else {
    params.set("client_id", blob.client_id);
  }

  let res: Response;
  try {
    res = await fetchImpl(blob.token_url, {
      method: "POST",
      headers,
      body: params.toString(),
      signal: AbortSignal.timeout(TOKEN_REQUEST_TIMEOUT_MS),
    });
  } catch (e) {
    throw new RefreshError(
      `token endpoint unreachable: ${e instanceof Error ? e.message : String(e)}`,
      "retryable",
    );
  }

  const text = await res.text();
  let data: Record<string, unknown> = {};
  try {
    data = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    /* non-JSON body — handled below via status */
  }

  if (res.ok) {
    if (typeof data.access_token !== "string" || data.access_token.length === 0) {
      throw new RefreshError(
        "token endpoint returned 200 without an access_token",
        "fatal",
        res.status,
      );
    }
    return {
      access_token: data.access_token,
      refresh_token:
        typeof data.refresh_token === "string" ? data.refresh_token : undefined,
      expires_in:
        typeof data.expires_in === "number" && data.expires_in > 0
          ? data.expires_in
          : DEFAULT_EXPIRES_IN_S,
      scope: typeof data.scope === "string" ? data.scope : undefined,
    };
  }

  const errCode = typeof data.error === "string" ? data.error : "";
  if (res.status === 400 && (errCode === "invalid_grant" || errCode === "invalid_client")) {
    throw new RefreshError(
      `refresh grant rejected by the authorization server (${errCode})`,
      "invalid_grant",
      res.status,
    );
  }
  if (res.status === 429 || res.status >= 500) {
    throw new RefreshError(
      `token endpoint answered ${res.status} — will back off`,
      "retryable",
      res.status,
    );
  }
  throw new RefreshError(
    `token endpoint answered ${res.status}${errCode ? ` (${errCode})` : ""}`,
    "fatal",
    res.status,
  );
}
