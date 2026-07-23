/**
 * Google service-account provider (EPIC-18): mints a Google access token
 * (~1h) from a service-account JSON key — the RS256 sibling of github_app.
 *
 * Flow: sign a JWT (RS256) with the SA private key from the vault —
 * {iss: client_email, scope: join(' '), aud: oauth2 token URL, iat, exp,
 * sub?: subject} — then exchange it at
 * POST https://oauth2.googleapis.com/token with
 * grant_type=urn:ietf:params:oauth:grant-type-jwt-bearer.
 *
 * Vault convention: auth.secretRef holds a JSON blob
 * {client_email, private_key, subject?} (`subject` enables domain-wide
 * delegation and is optional). Only the resulting access token reaches the
 * upstream (GOOGLE_ACCESS_TOKEN env); the private key NEVER leaves this call
 * frame and never appears in errors. `fetch` is injectable for tests.
 *
 * Scopes: auth.scopes wins; the default is the frozen google-bridge set
 * (drive.readonly, gmail.send, calendar.readonly). The Minter cache renews at
 * 80% of the TTL like every other provider, making re-mints transparent.
 */
import crypto from "node:crypto";
import type { UpstreamAuth } from "../../config/config.js";
import type { Vault } from "../../vault/vault.js";
import type { CredentialProvider, MintedCredential, MintOpts } from "../minter.js";
import { base64url } from "./jwt.js";

/** OAuth token endpoint for the JWT-bearer grant (exported for tests). */
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
/** Google SA access tokens live ~1h — the provider ceiling. */
const ACCESS_TOKEN_TTL_MS = 3_600_000;
/** JWT lifetime: 1h (Google's max for the bearer grant); 60s back-dated iat for clock skew. */
const SA_JWT_TTL_S = 3600;
const SA_JWT_IAT_SKEW_S = 60;

/** Frozen default scope set for the google-bridge (see registry/google.yaml). */
export const DEFAULT_GOOGLE_SCOPES: readonly string[] = [
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar.readonly",
];

/** Vault blob v1 stored at auth.secretRef (JSON). */
export interface GoogleSaSecretBlob {
  client_email: string;
  private_key: string;
  subject?: string;
}

type FetchLike = (url: string, init?: Record<string, unknown>) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/** Parses and validates the vault blob — never echoes blob contents in errors. */
export function parseGoogleSaBlob(raw: string, ref: string): GoogleSaSecretBlob {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `vault ref '${ref}' does not hold a valid Google service-account blob: expected JSON ` +
        `{client_email, private_key, subject?} — rewrite it with \`scopegate vault set ${ref}\` ` +
        `(paste the SA JSON key file)`,
    );
  }
  const b = (typeof parsed === "object" && parsed !== null ? parsed : {}) as Record<string, unknown>;
  const missing = ["client_email", "private_key"].filter(
    (k) => typeof b[k] !== "string" || (b[k] as string).length === 0,
  );
  if (missing.length > 0) {
    throw new Error(
      `vault ref '${ref}' holds an incomplete Google service-account blob: missing/invalid field(s) ` +
        `${missing.join(", ")} — expected {client_email, private_key, subject?}; ` +
        `rewrite it with \`scopegate vault set ${ref}\` (paste the SA JSON key file)`,
    );
  }
  if (b.subject !== undefined && typeof b.subject !== "string") {
    throw new Error(
      `vault ref '${ref}' holds an invalid Google service-account blob: subject must be a string`,
    );
  }
  if (!(b.private_key as string).includes("PRIVATE KEY")) {
    throw new Error(
      `vault ref '${ref}' holds an invalid Google service-account blob: private_key is not a PEM ` +
        `(expected a "-----BEGIN ... PRIVATE KEY-----" block from the SA JSON key file)`,
    );
  }
  return parsed as GoogleSaSecretBlob;
}

/**
 * Builds the RS256 JWT Google requires for the JWT-bearer grant:
 * {iss: client_email, scope: join(' '), aud: token URL, iat, exp: iat+3600,
 * sub?: subject}. iat is back-dated 60s for clock skew.
 */
export function buildServiceAccountJwt(
  blob: GoogleSaSecretBlob,
  scopes: readonly string[],
  nowMs: number,
): string {
  const nowS = Math.floor(nowMs / 1000);
  const iat = nowS - SA_JWT_IAT_SKEW_S;
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload: Record<string, unknown> = {
    iss: blob.client_email,
    scope: scopes.join(" "),
    aud: GOOGLE_TOKEN_URL,
    iat,
    exp: iat + SA_JWT_TTL_S,
  };
  if (blob.subject !== undefined && blob.subject !== "") payload.sub = blob.subject;
  const body = base64url(JSON.stringify(payload));
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(`${header}.${body}`);
  let sig: string;
  try {
    sig = signer.sign(blob.private_key, "base64url");
  } catch {
    throw new Error(
      `failed to sign the service-account JWT: the private_key in the vault blob is not a valid ` +
        `RSA PEM — re-deposit the SA JSON key with \`scopegate vault set\``,
    );
  }
  return `${header}.${body}.${sig}`;
}

export class GoogleSaProvider implements CredentialProvider {
  readonly type = "google_sa";

  constructor(private fetchFn: FetchLike = fetch as unknown as FetchLike) {}

  supports(auth: UpstreamAuth): boolean {
    return auth.type === "google_sa";
  }

  maxTtlMs(): number {
    return ACCESS_TOKEN_TTL_MS;
  }

  async mint(auth: UpstreamAuth, vault: Vault, opts: MintOpts): Promise<MintedCredential> {
    if (auth.type !== "google_sa") {
      throw new Error(`GoogleSaProvider cannot mint for auth type '${auth.type}'`);
    }
    const nowMs = opts.nowMs ?? Date.now();
    const blob = parseGoogleSaBlob(vault.get(auth.secretRef), auth.secretRef);
    const scopes = auth.scopes !== undefined && auth.scopes.length > 0 ? auth.scopes : DEFAULT_GOOGLE_SCOPES;
    const assertion = buildServiceAccountJwt(blob, scopes, nowMs);

    const res = await this.fetchFn(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type-jwt-bearer",
        assertion,
      }).toString(),
    });
    if (!res.ok) {
      // Google's error body is {error, error_description} — diagnostics only;
      // the assertion (and never the private key) is NOT echoed back.
      let detail = "";
      try {
        const errBody = (await res.json()) as { error?: unknown; error_description?: unknown };
        const parts = [errBody.error, errBody.error_description]
          .filter((p): p is string => typeof p === "string" && p !== "")
          .map((p) => p.slice(0, 200));
        if (parts.length > 0) detail = `: ${parts.join(" — ")}`;
      } catch {
        /* non-JSON error body: the status is enough */
      }
      throw new Error(
        `Google service-account token exchange failed (HTTP ${res.status})${detail} — check the ` +
          `service-account key in vault ref '${auth.secretRef}', the system clock, and (when the ` +
          `blob sets a subject) that domain-wide delegation is granted for the scopes`,
      );
    }
    const data = (await res.json()) as { access_token?: string; expires_in?: number };
    if (typeof data.access_token !== "string" || data.access_token === "") {
      throw new Error("Google service-account token exchange returned no access_token");
    }
    const apiExpiry =
      typeof data.expires_in === "number" && Number.isFinite(data.expires_in) && data.expires_in > 0
        ? nowMs + data.expires_in * 1000
        : nowMs + ACCESS_TOKEN_TTL_MS;
    return {
      value: data.access_token,
      env: { GOOGLE_ACCESS_TOKEN: data.access_token },
      expiresAt: Math.min(apiExpiry, nowMs + opts.ttlMs),
    };
  }
}
