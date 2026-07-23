/**
 * SSO adapter seam (EPIC-10, H10.7) — HONEST STUB.
 *
 * What this is: the single choke point through which every admin request is
 * authenticated, shaped as a pluggable adapter so a real IdP can be wired in
 * without touching the router:
 *
 *   interface SsoAdapter { authenticate(req): SsoIdentity | null }
 *
 * What ships here: the DEV adapter. It trusts the `X-Admin-Token` header
 * matched against the server's admin token, and yields a synthetic identity
 * with every role. It exists so the dashboard and scripts have one login
 * path, and so the adapter CONTRACT is exercised end-to-end in tests.
 *
 * What this is NOT: real SSO. There is no OIDC/SAML here yet — no session
 * issuance, no token verification, no role enforcement beyond "admin or
 * not". Do not expose this control plane beyond localhost/trusted networks
 * without plugging a real adapter.
 *
 * How to plug real OIDC (the intended Enterprise path):
 *   1. Dashboard login: Authorization Code flow with PKCE against the IdP's
 *      authorization endpoint; the resulting ID token (JWT) is sent as
 *      `Authorization: Bearer <id_token>` (or exchanged for a short-lived
 *      control-plane session cookie — SameSite=Strict, HttpOnly).
 *   2. Adapter: verify the JWT signature against the IdP JWKS from the
 *      OIDC discovery document (`<issuer>/.well-known/openid-configuration`
 *      → `jwks_uri`), checking `iss`, `aud` (this control plane's client id)
 *      and `exp`. Node's node:crypto can verify RS256/ES256; cache the JWKS
 *      with the `kid` rollover window.
 *   3. Identity mapping: `sub` → SsoIdentity.subject; IdP groups claim
 *      (e.g. `groups`) → roles: map to `owner` (billing + policies),
 *      `approver` (approvals + revocation), `viewer` (audit read-only).
 *      Then enforce per-route in router.ts — the asimetría rule (§6.3) is
 *      that approval/revocation actions require `approver` or `owner`.
 *   4. SAML (Enterprise): same adapter shape, with the SAML Response posted
 *      to an ACS endpoint and the assertion verified against the IdP
 *      metadata certificate.
 *   5. MFA: delegated to the IdP (require `acr`/`amr` claims for `owner`
 *      actions — SOC2 control, EPIC-10 H10.9).
 */
import type { IncomingMessage } from "node:http";
import { timingSafeEqual } from "node:crypto";

export interface SsoIdentity {
  /** Stable subject identifier (IdP `sub`; dev: "dev-admin"). */
  subject: string;
  displayName?: string;
  /** Roles: owner | approver | viewer (dev adapter grants all). */
  roles: string[];
  /** Which adapter produced this identity (audit trail). */
  via: string;
}

export interface SsoAdapter {
  readonly name: string;
  authenticate(req: IncomingMessage): SsoIdentity | null;
}

/**
 * Dev adapter: `X-Admin-Token: <token>` equal to the server admin token
 * authenticates as a full-power synthetic identity. Constant-time compare,
 * same as the Bearer path.
 */
export function makeDevSsoAdapter(adminToken: string): SsoAdapter {
  return {
    name: "dev-header",
    authenticate(req) {
      const header = req.headers["x-admin-token"];
      const presented = Array.isArray(header) ? header[0] : header;
      if (
        typeof presented !== "string" ||
        presented.length === 0 ||
        presented.length !== adminToken.length
      ) {
        return null;
      }
      // Lengths equal here — timingSafeEqual is safe to apply directly.
      if (!timingSafeEqual(Buffer.from(presented), Buffer.from(adminToken))) {
        return null;
      }
      return {
        subject: "dev-admin",
        displayName: "Development Admin",
        roles: ["owner", "approver", "viewer"],
        via: "dev-header",
      };
    },
  };
}
