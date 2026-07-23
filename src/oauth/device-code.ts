/**
 * Device Authorization Grant (RFC 8628) client — the only human step the
 * OAuth lifecycle allows. Used by `scopegate auth login <upstream>` when a
 * refresh grant dies (or on first onboarding).
 *
 *   1. POST the device authorization endpoint → device_code + user_code +
 *      verification_uri.
 *   2. The human visits the URI and enters the code (out-of-band; the gateway
 *      only DISPLAYS them, on stderr).
 *   3. Poll the token endpoint with grant_type
 *      urn:ietf:params:oauth:grant-type:device_code, respecting `interval`,
 *      `slow_down` (+5 s) and the device_code expiry.
 *
 * Token material is returned to the caller (the login command persists it);
 * nothing here logs secrets.
 */

export interface DeviceAuthorization {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  /** Seconds until the device_code dies. */
  expires_in: number;
  /** Minimum seconds between polls. */
  interval: number;
}

export interface DeviceFlowTokens {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

export class DeviceFlowError extends Error {
  constructor(
    message: string,
    readonly code:
      | "expired_token"
      | "access_denied"
      | "protocol"
      | "network",
  ) {
    super(message);
    this.name = "DeviceFlowError";
  }
}

const DEFAULT_POLL_INTERVAL_S = 5;
const DEFAULT_DEVICE_EXPIRY_S = 600;
const REQUEST_TIMEOUT_MS = 10_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postForm(
  url: string,
  params: URLSearchParams,
  fetchImpl: typeof fetch,
): Promise<{ status: number; data: Record<string, unknown> }> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: params.toString(),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (e) {
    throw new DeviceFlowError(
      `device endpoint unreachable: ${e instanceof Error ? e.message : String(e)}`,
      "network",
    );
  }
  const text = await res.text();
  let data: Record<string, unknown> = {};
  try {
    data = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    /* non-JSON body — surfaced via status below */
  }
  return { status: res.status, data };
}

/** Step 1: request a device_code + user_code from the authorization server. */
export async function requestDeviceCode(
  deviceEndpoint: string,
  clientId: string,
  opts: { scope?: string; fetchImpl?: typeof fetch } = {},
): Promise<DeviceAuthorization> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const params = new URLSearchParams({ client_id: clientId });
  if (opts.scope) params.set("scope", opts.scope);
  const { status, data } = await postForm(deviceEndpoint, params, fetchImpl);
  if (
    status !== 200 ||
    typeof data.device_code !== "string" ||
    typeof data.user_code !== "string" ||
    typeof data.verification_uri !== "string"
  ) {
    throw new DeviceFlowError(
      `device authorization endpoint answered ${status} without a usable device code`,
      "protocol",
    );
  }
  return {
    device_code: data.device_code,
    user_code: data.user_code,
    verification_uri: data.verification_uri,
    verification_uri_complete:
      typeof data.verification_uri_complete === "string"
        ? data.verification_uri_complete
        : undefined,
    expires_in:
      typeof data.expires_in === "number" && data.expires_in > 0
        ? data.expires_in
        : DEFAULT_DEVICE_EXPIRY_S,
    interval:
      typeof data.interval === "number" && data.interval >= 0
        ? data.interval
        : DEFAULT_POLL_INTERVAL_S,
  };
}

export interface RunDeviceFlowOpts {
  deviceEndpoint: string;
  tokenUrl: string;
  clientId: string;
  scope?: string;
  fetchImpl?: typeof fetch;
  /** Called exactly once with the code the human must enter. */
  onUserCode?: (auth: DeviceAuthorization) => void;
}

/**
 * Full RFC 8628 flow. Resolves with the tokens once the human approves;
 * rejects with DeviceFlowError on expiry (`expired_token`), refusal
 * (`access_denied`) or protocol/network failure.
 */
export async function runDeviceCodeFlow(
  opts: RunDeviceFlowOpts,
): Promise<DeviceFlowTokens> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const auth = await requestDeviceCode(opts.deviceEndpoint, opts.clientId, {
    scope: opts.scope,
    fetchImpl,
  });
  opts.onUserCode?.(auth);

  const deadline = Date.now() + auth.expires_in * 1000;
  let intervalMs = Math.max(1, auth.interval) * 1000;

  for (;;) {
    await sleep(intervalMs);
    if (Date.now() >= deadline) {
      throw new DeviceFlowError(
        "device code expired before the human authorized it",
        "expired_token",
      );
    }
    const params = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: auth.device_code,
      client_id: opts.clientId,
    });
    const { status, data } = await postForm(opts.tokenUrl, params, fetchImpl);
    if (status === 200 && typeof data.access_token === "string") {
      return {
        access_token: data.access_token,
        refresh_token:
          typeof data.refresh_token === "string" ? data.refresh_token : undefined,
        expires_in:
          typeof data.expires_in === "number" ? data.expires_in : undefined,
        scope: typeof data.scope === "string" ? data.scope : undefined,
      };
    }
    const errCode = typeof data.error === "string" ? data.error : "";
    switch (errCode) {
      case "authorization_pending":
        continue; // human has not approved yet — keep polling
      case "slow_down":
        intervalMs += 5_000; // RFC 8628 §3.5: add 5 s and keep polling
        continue;
      case "expired_token":
        throw new DeviceFlowError(
          "device code expired before the human authorized it",
          "expired_token",
        );
      case "access_denied":
        throw new DeviceFlowError(
          "the human denied the authorization request",
          "access_denied",
        );
      default:
        throw new DeviceFlowError(
          `device token poll failed (${status}${errCode ? `, ${errCode}` : ""})`,
          status >= 500 ? "network" : "protocol",
        );
    }
  }
}
