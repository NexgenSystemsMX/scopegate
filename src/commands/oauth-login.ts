/**
 * `scopegate auth login <upstream>` (EPIC-03 H3.5) — the human, out-of-band
 * path that re-authorizes an OAuth upstream whose refresh grant died
 * (invalid_grant / revoked / rotated away), or seeds it for the first time.
 *
 * Runs the RFC 8628 device-code flow and deposits the resulting blob in the
 * vault under the upstream's `secretRef` (contract: `oauth2:<upstream>`),
 * then deletes the on-disk reauth-required.json signal — the running gateway
 * notices and resumes its refresh scheduler WITHOUT a restart.
 *
 * The orchestrator wires this into cli.ts as `scopegate auth login <upstream>`;
 * this module is the only place in commands/ EPIC-03 is allowed to add.
 *
 * Output discipline: the user_code / verification_uri (and every other
 * message) go to STDERR, never stdout.
 */
import { loadConfig } from "../config/config.js";
import { Vault } from "../vault/vault.js";
import { audit } from "../audit/log.js";
import { errorMessage } from "../gateway/proxy.js";
import { runDeviceCodeFlow } from "../oauth/device-code.js";
import {
  parseOAuthBlob,
  parseOAuthEndpoints,
  serializeOAuthBlob,
  type OAuthTokenBlob,
} from "../oauth/types.js";
import { clearReauthRequired } from "../oauth/reauth.js";

function eprintln(msg: string): void {
  console.error(msg);
}

/** Derive the device authorization endpoint from the token endpoint. */
export function defaultDeviceEndpoint(tokenUrl: string): string {
  const u = new URL(tokenUrl);
  return new URL("/device", u).toString();
}

export async function runAuthLogin(opts: { upstream: string }): Promise<void> {
  const cfg = loadConfig();
  const up = cfg.upstreams.find((u) => u.name === opts.upstream);
  if (!up) {
    throw new Error(
      `Unknown upstream '${opts.upstream}'. Registered upstreams: ${cfg.upstreams
        .map((u) => u.name)
        .join(", ") || "(none)"}.`,
    );
  }
  if (up.auth.type !== "oauth2") {
    throw new Error(
      `Upstream '${up.name}' uses auth '${up.auth.type}', not 'oauth2' — nothing to log into.`,
    );
  }

  const vault = Vault.open();
  const secretRef = up.auth.secretRef;
  // The blob (even a dead one) carries the endpoints and client identity. A
  // full blob parses normally; a first-login bootstrap seed (no access_token
  // yet) still yields the endpoints via the lenient parse.
  const raw = vault.has(secretRef) ? vault.get(secretRef) : null;
  const full = raw ? parseOAuthBlob(raw) : null;
  const endpoints = raw ? parseOAuthEndpoints(raw) : null;
  if (!endpoints) {
    throw new Error(
      `No usable OAuth bootstrap blob at vault ref '${secretRef}'. ` +
        `Seed it first (one line, your terminal): ` +
        `echo '{"token_url":"https://<idp>/token","client_id":"<id>"}' | scopegate secret add ${secretRef}`,
    );
  }

  const deviceEndpoint =
    endpoints.device_authorization_endpoint ??
    defaultDeviceEndpoint(endpoints.token_url);

  eprintln(`[scopegate] starting OAuth device authorization for upstream '${up.name}'`);
  const tokens = await runDeviceCodeFlow({
    deviceEndpoint,
    tokenUrl: endpoints.token_url,
    clientId: endpoints.client_id,
    scope: endpoints.scope,
    onUserCode: (auth) => {
      // STDERR ONLY — these instructions must never enter stdout.
      eprintln(`[scopegate] ────────────────────────────────────────────────`);
      eprintln(`[scopegate] human action required:`);
      eprintln(`[scopegate]   1. open  ${auth.verification_uri}`);
      eprintln(`[scopegate]   2. enter code  ${auth.user_code}`);
      if (auth.verification_uri_complete) {
        eprintln(`[scopegate]   (or open directly: ${auth.verification_uri_complete})`);
      }
      eprintln(
        `[scopegate]   code expires in ${auth.expires_in}s — waiting for approval…`,
      );
      eprintln(`[scopegate] ────────────────────────────────────────────────`);
    },
  });

  const blob: OAuthTokenBlob = {
    ...(full ?? {}),
    ...endpoints,
    v: 1,
    access_token: tokens.access_token,
    // Device grants normally return a fresh refresh_token; keep the old one
    // only if the server omitted it.
    refresh_token: tokens.refresh_token ?? full?.refresh_token,
    expires_at:
      tokens.expires_in !== undefined
        ? Date.now() + tokens.expires_in * 1000
        : full?.expires_at,
    obtained_at: Date.now(),
    scope: tokens.scope ?? endpoints.scope,
    device_authorization_endpoint: deviceEndpoint,
  };
  vault.set(secretRef, serializeOAuthBlob(blob));

  // Signal the running gateway that re-auth completed (it watches for the
  // file to disappear) and record the lifecycle event.
  clearReauthRequired(up.name);
  try {
    audit(cfg.agentId, "oauth_reauth_completed", {
      upstream: up.name,
      via: "device_code",
    });
  } catch (e) {
    eprintln(
      `[scopegate] WARN: could not audit oauth_reauth_completed: ${errorMessage(e)}`,
    );
  }
  eprintln(
    `[scopegate] upstream '${up.name}' re-authorized — the gateway picks the new token up automatically.`,
  );
}
