/**
 * OAuth token blob (format v1) — the FROZEN vault contract for upstreams with
 * `auth.type: "oauth2"`. The blob lives in the encrypted vault under the
 * upstream's `secretRef` (convention: `oauth2:<upstream>`) and is written ONLY
 * by the refresh daemon (single-writer rule — the proxy never writes).
 *
 * Soft migration: a blob that is not JSON, or lacks `token_url`/`client_id`,
 * parses to null; a blob without `expires_at`/`refresh_token` parses but is
 * marked `unknown_expiry` by the daemon, which then leaves it to pure
 * proxy-injection (pre-EPIC-03 behavior) instead of failing the upstream.
 */

export interface OAuthTokenBlob {
  /** Blob format version. Always 1; written back on every persist. */
  v: 1;
  access_token: string;
  refresh_token?: string;
  /** Epoch ms after which the access token is dead. Absent → unknown_expiry. */
  expires_at?: number;
  /** Epoch ms when the current access token was obtained. */
  obtained_at?: number;
  /** OAuth2 token endpoint used for refresh + device-code polling. */
  token_url: string;
  client_id: string;
  client_secret?: string;
  scope?: string;
  /** RFC 8628 device authorization endpoint; derived from token_url when absent. */
  device_authorization_endpoint?: string;
}

/**
 * Parse a vault value into an OAuthTokenBlob. Returns null when the value is
 * not a usable OAuth blob (raw token, non-JSON, missing required fields) —
 * callers fall back to treating it as a static secret.
 */
export function parseOAuthBlob(raw: string): OAuthTokenBlob | null {
  let p: unknown;
  try {
    p = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof p !== "object" || p === null) return null;
  const o = p as Record<string, unknown>;
  if (typeof o.access_token !== "string" || o.access_token.length === 0) return null;
  if (typeof o.token_url !== "string" || o.token_url.length === 0) return null;
  if (typeof o.client_id !== "string" || o.client_id.length === 0) return null;
  return {
    v: 1,
    access_token: o.access_token,
    refresh_token: typeof o.refresh_token === "string" ? o.refresh_token : undefined,
    expires_at:
      typeof o.expires_at === "number" && Number.isFinite(o.expires_at)
        ? o.expires_at
        : undefined,
    obtained_at:
      typeof o.obtained_at === "number" && Number.isFinite(o.obtained_at)
        ? o.obtained_at
        : undefined,
    token_url: o.token_url,
    client_id: o.client_id,
    client_secret: typeof o.client_secret === "string" ? o.client_secret : undefined,
    scope: typeof o.scope === "string" ? o.scope : undefined,
    device_authorization_endpoint:
      typeof o.device_authorization_endpoint === "string"
        ? o.device_authorization_endpoint
        : undefined,
  };
}

export function serializeOAuthBlob(blob: OAuthTokenBlob): string {
  return JSON.stringify({ ...blob, v: 1 });
}

/**
 * Lenient parse for the device-login bootstrap: a seeded blob may not carry a
 * usable access_token yet (first login), so this extracts only the fields the
 * device flow needs. Returns null when token_url/client_id are missing.
 */
export function parseOAuthEndpoints(raw: string): Pick<
  OAuthTokenBlob,
  "token_url" | "client_id" | "client_secret" | "scope" | "device_authorization_endpoint"
> | null {
  let p: unknown;
  try {
    p = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof p !== "object" || p === null) return null;
  const o = p as Record<string, unknown>;
  if (typeof o.token_url !== "string" || o.token_url.length === 0) return null;
  if (typeof o.client_id !== "string" || o.client_id.length === 0) return null;
  return {
    token_url: o.token_url,
    client_id: o.client_id,
    client_secret: typeof o.client_secret === "string" ? o.client_secret : undefined,
    scope: typeof o.scope === "string" ? o.scope : undefined,
    device_authorization_endpoint:
      typeof o.device_authorization_endpoint === "string"
        ? o.device_authorization_endpoint
        : undefined,
  };
}
