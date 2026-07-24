/**
 * ScopeGate config: paths, upstream registry (scopegate.yaml) loader/writer.
 *
 * Design rule: this file NEVER contains secrets. Secrets live only in the
 * encrypted vault and are referenced here by `secretRef` (a vault key name).
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import YAML from "yaml";

// SCOPEGATE_HOME overrides the base dir (tests, e2e, portable installs).
// Paths are module-level constants: set the env var BEFORE importing this module.
export const SCOPEGATE_DIR = process.env.SCOPEGATE_HOME
  ? path.resolve(process.env.SCOPEGATE_HOME)
  : path.join(os.homedir(), ".scopegate");
export const CONFIG_PATH = path.join(SCOPEGATE_DIR, "scopegate.yaml");
export const POLICIES_PATH = path.join(SCOPEGATE_DIR, "policies.yaml");
export const VAULT_PATH = path.join(SCOPEGATE_DIR, "vault.enc");
export const MASTER_KEY_PATH = path.join(SCOPEGATE_DIR, "master.key");
export const AUDIT_LOG_PATH = path.join(SCOPEGATE_DIR, "audit.jsonl");
/** Quick win (hot-reload): bumped on every vault mutation; the proxy watches it. */
export const VAULT_VERSION_PATH = path.join(SCOPEGATE_DIR, "vault.version");
export const PENDING_POLICIES_PATH = path.join(
  SCOPEGATE_DIR,
  "policies.pending.yaml",
);
/** EPIC-03: on-disk signal that an oauth2 upstream needs human re-auth. */
export const REAUTH_REQUIRED_PATH = path.join(
  SCOPEGATE_DIR,
  "reauth-required.json",
);

/** How to authenticate against an upstream. The secret itself is in the vault. */
export type UpstreamAuth =
  | { type: "none" }
  | {
      /** Static secret injected as a header (default: Authorization: Bearer <secret>). */
      type: "bearer";
      secretRef: string;
      header?: string; // e.g. "X-Api-Key"; default "Authorization"
      scheme?: string; // e.g. "Bearer" | "token" | "" (raw); default "Bearer"
    }
  | {
      /** Secret(s) injected as env vars into a stdio-spawned MCP server. */
      type: "env";
      /** Map of ENV_VAR_NAME -> vault secretRef */
      env: Record<string, string>;
    }
  | {
      /** OAuth2 with refresh handled by the refresh daemon (Phase 1). */
      type: "oauth2";
      /**
       * Vault key holding the OAuthTokenBlob v1:
       * {access_token, refresh_token, expires_at (epoch ms), token_url,
       *  client_id, client_secret?, scope?, obtained_at?,
       *  device_authorization_endpoint?} — written ONLY by the refresh
       * daemon / `scopegate auth login`, read here at the outbound hop.
       */
      secretRef: string;
      header?: string;
      scheme?: string;
      /**
       * Optional regex (case-insensitive) matched against upstream call
       * errors to detect an auth failure that should trigger a token refresh
       * + single retry. Default matches HTTP 401 / unauthorized / invalid_token.
       */
      authErrorPattern?: string;
    }
  | {
      /**
       * Ephemeral JWT minted by the gateway (HS256, node:crypto) for internal
       * APIs/MCPs that accept tokens signed by us. The vault holds the HMAC
       * signing key; the agent never sees it nor the minted token.
       */
      type: "jwt";
      secretRef: string; // vault key holding the HMAC signing secret
      /** Per-upstream TTL cap (e.g. "5m"). Default: 15m. Clamped to the grant TTL. */
      ttl?: string;
      /** Extra claims merged into the token (iss/aud/iat/exp/jti are enforced). */
      claims?: Record<string, unknown>;
    }
  | {
      /**
       * GitHub App installation token (~1h) minted from the App private key:
       * the gateway signs an App JWT (RS256) and exchanges it at the GitHub
       * API. Only the installation token reaches the upstream.
       */
      type: "github_app";
      appId: string;
      installationId: string;
      secretRef: string; // vault key holding the App private key (PEM)
      /** API base URL — GitHub Enterprise or tests. Default: https://api.github.com */
      apiUrl?: string;
      /** Optional permission/repository narrowing for the installation token. */
      permissions?: Record<string, string>;
      repositories?: string[];
    }
  | {
      /**
       * AWS STS session credentials (AssumeRole when roleArn is set, else
       * GetSessionToken) injected as env vars into stdio upstreams.
       *
       * secretRef is a BASE NAME: the vault must hold '<secretRef>_ACCESS_KEY_ID'
       * and '<secretRef>_SECRET_ACCESS_KEY' (master credentials allowed to call
       * STS). The session credentials are the only ones ever injected.
       */
      type: "aws_sts";
      secretRef: string; // base name for '<ref>_ACCESS_KEY_ID' / '<ref>_SECRET_ACCESS_KEY'
      roleArn?: string; // when set: AssumeRole; otherwise GetSessionToken
      region?: string; // default: us-east-1
      /** TTL cap in seconds (STS floor: 900). Default: 900. Clamped to the grant TTL. */
      durationSeconds?: number;
    }
  | {
      /**
       * Huly workspace token minted by the gateway: the vault holds a JSON
       * blob {email, password, workspace, accountsUrl?} at secretRef; the
       * provider logs in against the Huly account service (login ->
       * selectWorkspace) and injects HULY_TOKEN / HULY_ENDPOINT /
       * HULY_WORKSPACE as env into stdio upstreams. Only the short-lived
       * workspace token leaves the gateway — never the account password.
       */
      type: "huly";
      secretRef: string; // vault key holding the JSON blob {email, password, workspace, accountsUrl?}
      /** Account service URL — wins over the blob's. Default: https://huly2.nexgen.systems */
      accountsUrl?: string;
    }
  | {
      /**
       * Google access token (~1h) minted from a service-account key: the vault
       * holds a JSON blob {client_email, private_key, subject?} at secretRef
       * (subject enables domain-wide delegation, optional); the provider signs
       * a JWT (RS256, iss=client_email, scope, aud=oauth2.googleapis.com/token,
       * iat/exp, sub=subject?) and exchanges it for an access token. Only the
       * access token (GOOGLE_ACCESS_TOKEN env) reaches the upstream — the SA
       * private key never leaves the vault.
       */
      type: "google_sa";
      secretRef: string; // vault key holding the JSON blob {client_email, private_key, subject?}
      /**
       * OAuth scopes for the access token. Default: drive.readonly,
       * gmail.send, calendar.readonly (widened here when a deployment needs
       * more, e.g. calendar.events for calendar_create).
       */
      scopes?: string[];
    }
  | {
      /**
       * Composite auth (M1): several credential sources fused into ONE stdio
       * upstream — static vault refs (`env`, same semantics as type "env")
       * PLUS any number of provider-backed mints (`mint`, resolved in order
       * with the minter's cache/single-flight). A multi-service MCP (Huly +
       * GitHub + Redis at once) is 100% minted without splitting upstreams.
       * Env-name conflicts across sources are config errors (fail-closed).
       */
      type: "composite";
      /** Static refs: ENV_VAR_NAME -> vault secretRef (same as type "env"). */
      env?: Record<string, string>;
      /** Provider-backed auth entries (huly, github_app, aws_sts, google_sa, jwt). */
      mint?: UpstreamAuth[];
    };

/**
 * EPIC-12: warm pool of pre-authenticated connections to an upstream.
 * `min: 0` (the default when `pool` is absent) keeps the pre-EPIC-12 lazy
 * behavior: one connection established on first use.
 */
export interface PoolConfig {
  /** Connections pre-established at startup and kept warm. Default 0 (lazy). */
  min?: number;
  /**
   * Hard ceiling of pooled connections. Calls beyond `max` concurrent uses get
   * a throwaway connection that is closed after the call. Default 2.
   */
  max?: number;
  /**
   * Idle pooled connections above `min` are reaped after this many ms.
   * Default 300_000 (5 min).
   */
  idleTimeoutMs?: number;
}

export interface UpstreamConfig {
  /** Unique name; proxied tools are exposed as `<name>__<tool>`. */
  name: string;
  /** Transport to reach the upstream MCP server. */
  transport:
    | { kind: "http"; url: string }
    | {
        /**
         * M11.2: OpenAPI→MCP import. The gateway acts as the MCP server of a
         * plain REST API: one tool per spec operation, executed as direct HTTP
         * calls (no intermediate MCP server, no spawned process).
         */
        kind: "openapi";
        /** https URL or local file path to the OpenAPI spec (JSON or YAML). */
        spec: string;
        /** API base URL override; default: spec's servers[0].url. */
        baseUrl?: string;
      }
    | {
        kind: "stdio";
        command: string;
        args?: string[];
        env?: Record<string, string>;
        /**
         * M8: extra process.env vars to pass through to the spawned child
         * (the default pass set is minimal and secret-scrubbed). Names only —
         * values come from the gateway's own environment.
         */
        envPassthrough?: string[];
      };
  auth: UpstreamAuth;
  /** Optional allowlist of upstream tool names to expose. Empty = all. */
  exposeTools?: string[];
  enabled?: boolean;
  /**
   * EPIC-12: inject the `X-ScopeGate-Attestation` EdDSA JWT on outbound HTTP
   * calls (ADDITIVE — never replaces the credential). Default: the global
   * `ScopeGateConfig.attestation`, else `true` when an agent identity exists.
   * Has no effect on stdio upstreams (no verifying counterpart, by design).
   */
  attestation?: boolean;
  /** EPIC-12: warm pool of pre-authenticated connections. */
  pool?: PoolConfig;
}

export interface ScopeGateConfig {
  version: 1;
  /** Identity of this gateway instance / default agent identity. */
  agentId: string;
  upstreams: UpstreamConfig[];
  /**
   * EPIC-12: global default for per-upstream `attestation` (per-upstream value
   * wins). Honored when the caller wires it into the proxy constructor.
   */
  attestation?: boolean;
}

export function ensureDir(): void {
  fs.mkdirSync(SCOPEGATE_DIR, { recursive: true, mode: 0o700 });
}

export function configExists(): boolean {
  return fs.existsSync(CONFIG_PATH);
}

export function loadConfig(): ScopeGateConfig {
  if (!configExists()) {
    throw new Error(
      `No config at ${CONFIG_PATH}. Run \`scopegate init\` first.`,
    );
  }
  const raw = YAML.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
  if (!raw || raw.version !== 1) {
    throw new Error(`Unsupported or corrupt config at ${CONFIG_PATH}`);
  }
  raw.upstreams ??= [];
  for (const up of raw.upstreams as UpstreamConfig[]) {
    if (up?.auth?.type === "composite") validateCompositeAuth(up);
    if (
      up?.transport?.kind === "stdio" &&
      up.transport.envPassthrough !== undefined &&
      !Array.isArray(up.transport.envPassthrough)
    ) {
      throw new Error(
        `upstream '${up.name}': transport.envPassthrough must be an array of env var names`,
      );
    }
    if (up?.transport?.kind === "openapi") {
      const t = up.transport;
      if (typeof t.spec !== "string" || t.spec.trim().length === 0) {
        throw new Error(
          `upstream '${up.name}': openapi transport requires transport.spec ` +
            `(an https URL or a local file path to a JSON/YAML spec)`,
        );
      }
      if (/^http:\/\//i.test(t.spec) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?([/?#]|$)/i.test(t.spec)) {
        throw new Error(
          `upstream '${up.name}': openapi transport.spec must be an https URL ` +
            `(http is allowed only for localhost/127.0.0.1) or a local file path`,
        );
      }
      if (t.baseUrl !== undefined && typeof t.baseUrl !== "string") {
        throw new Error(`upstream '${up.name}': transport.baseUrl must be a string`);
      }
    }
  }
  return raw as ScopeGateConfig;
}

/**
 * M1: fail-closed validation of composite auth at load. Env-name conflicts
 * across sources are config errors; nested types must be provider-backed
 * (huly, github_app, aws_sts, google_sa, jwt) — never composite/env/oauth2
 * (recursion or daemon-coupled types are refused).
 */
function validateCompositeAuth(up: UpstreamConfig): void {
  const auth = up.auth as Extract<UpstreamAuth, { type: "composite" }>;
  const seen = new Map<string, string>();
  for (const name of Object.keys(auth.env ?? {})) seen.set(name, "env");
  const PROVIDER_TYPES = new Set(["huly", "github_app", "aws_sts", "google_sa", "jwt"]);
  for (const mintAuth of auth.mint ?? []) {
    if (!mintAuth || !PROVIDER_TYPES.has(mintAuth.type)) {
      throw new Error(
        `upstream '${up.name}': composite.mint entries must be provider-backed auth ` +
          `(huly, github_app, aws_sts, google_sa, jwt) — got '${mintAuth?.type}'`,
      );
    }
    // Env produced by each provider must not collide with another source.
    const PRODUCED: Record<string, string[]> = {
      huly: ["HULY_TOKEN", "HULY_ENDPOINT", "HULY_WORKSPACE"],
      github_app: ["GITHUB_PERSONAL_ACCESS_TOKEN"],
      aws_sts: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
      google_sa: ["GOOGLE_ACCESS_TOKEN"],
      jwt: [],
    };
    for (const varName of PRODUCED[mintAuth.type] ?? []) {
      const prev = seen.get(varName);
      if (prev) {
        throw new Error(
          `upstream '${up.name}': composite env conflict on '${varName}' ` +
            `(from both ${prev} and ${mintAuth.type}) — rename one source (fail-closed)`,
        );
      }
      seen.set(varName, mintAuth.type);
    }
  }
  if (Object.keys(auth.env ?? {}).length === 0 && (auth.mint ?? []).length === 0) {
    throw new Error(`upstream '${up.name}': composite auth requires at least one of env/mint`);
  }
}

export function saveConfig(cfg: ScopeGateConfig): void {
  ensureDir();
  const tmp = CONFIG_PATH + ".tmp";
  fs.writeFileSync(tmp, YAML.stringify(cfg), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_PATH);
}

export function upsertUpstream(cfg: ScopeGateConfig, up: UpstreamConfig): void {
  const i = cfg.upstreams.findIndex((u) => u.name === up.name);
  if (i >= 0) cfg.upstreams[i] = up;
  else cfg.upstreams.push(up);
}
