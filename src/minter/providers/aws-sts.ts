/**
 * AWS STS provider (EPIC-02 H6): mints session credentials with the official
 * modular SDK (@aws-sdk/client-sts — SigV4 is NOT reimplemented by hand).
 *
 *   - roleArn set   -> AssumeRole (RoleSessionName: scopegate-<agentId>)
 *   - roleArn unset -> GetSessionToken
 *
 * Vault convention: auth.secretRef is a BASE NAME; the vault must hold
 * '<secretRef>_ACCESS_KEY_ID' and '<secretRef>_SECRET_ACCESS_KEY' (master
 * credentials allowed to call STS). Only the SESSION credentials are
 * injected — as env vars into stdio-spawned upstreams (HTTP/SigV4 signing is
 * out of scope for now).
 *
 * The STS client is injectable for tests.
 */
import {
  STSClient,
  AssumeRoleCommand,
  GetSessionTokenCommand,
} from "@aws-sdk/client-sts";
import type { UpstreamAuth } from "../../config/config.js";
import type { Vault } from "../../vault/vault.js";
import type { CredentialProvider, MintedCredential, MintOpts } from "../minter.js";

/** STS minimum DurationSeconds (AssumeRole/GetSessionToken floor). */
const STS_MIN_DURATION_S = 900;
/** Default provider ceiling: 15 min, aligned with the policy default_ttl. */
const DEFAULT_DURATION_S = 900;

/** Minimal STS client surface, so tests can inject a mock. */
export interface StsClientLike {
  send(command: AssumeRoleCommand | GetSessionTokenCommand): Promise<{
    Credentials?: {
      AccessKeyId?: string;
      SecretAccessKey?: string;
      SessionToken?: string;
      Expiration?: Date;
    };
  }>;
}

export type StsClientFactory = (opts: {
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
}) => StsClientLike;

const defaultFactory: StsClientFactory = ({ region, accessKeyId, secretAccessKey }) =>
  new STSClient({
    region,
    credentials: { accessKeyId, secretAccessKey },
  }) as StsClientLike;

export class AwsStsProvider implements CredentialProvider {
  readonly type = "aws_sts";

  constructor(private clientFactory: StsClientFactory = defaultFactory) {}

  supports(auth: UpstreamAuth): boolean {
    return auth.type === "aws_sts";
  }

  maxTtlMs(auth: UpstreamAuth): number {
    if (auth.type !== "aws_sts") return 0;
    return Math.max(STS_MIN_DURATION_S, auth.durationSeconds ?? DEFAULT_DURATION_S) * 1000;
  }

  async mint(auth: UpstreamAuth, vault: Vault, opts: MintOpts): Promise<MintedCredential> {
    if (auth.type !== "aws_sts") {
      throw new Error(`AwsStsProvider cannot mint for auth type '${auth.type}'`);
    }
    const nowMs = opts.nowMs ?? Date.now();
    const accessKeyId = vault.get(`${auth.secretRef}_ACCESS_KEY_ID`);
    const secretAccessKey = vault.get(`${auth.secretRef}_SECRET_ACCESS_KEY`);
    const client = this.clientFactory({
      region: auth.region ?? "us-east-1",
      accessKeyId,
      secretAccessKey,
    });

    // DurationSeconds cannot go below the STS floor of 900s; when the grant
    // is shorter, the gateway still treats the credential as dead at the
    // clamp (reported expiresAt) and re-mints.
    const requestedS = Math.floor(opts.ttlMs / 1000);
    const durationS = Math.max(STS_MIN_DURATION_S, requestedS);

    const command = auth.roleArn
      ? new AssumeRoleCommand({
          RoleArn: auth.roleArn,
          RoleSessionName: `scopegate-${opts.agentId ?? "agent"}`.replace(/[^\w+=,.@-]/g, "-"),
          DurationSeconds: durationS,
        })
      : new GetSessionTokenCommand({ DurationSeconds: durationS });

    const out = await client.send(command);
    const c = out.Credentials;
    if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) {
      throw new Error("STS returned incomplete session credentials");
    }
    const actualExpiry = c.Expiration ? c.Expiration.getTime() : nowMs + durationS * 1000;
    return {
      value: `${c.AccessKeyId}:${c.SecretAccessKey}:${c.SessionToken}`,
      env: {
        AWS_ACCESS_KEY_ID: c.AccessKeyId,
        AWS_SECRET_ACCESS_KEY: c.SecretAccessKey,
        AWS_SESSION_TOKEN: c.SessionToken,
      },
      expiresAt: Math.min(actualExpiry, nowMs + opts.ttlMs),
    };
  }
}
