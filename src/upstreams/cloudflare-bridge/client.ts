/**
 * cloudflare-bridge client (EPIC-17): semantic interface over the Cloudflare
 * API v4 (zones, DNS records, Workers, Pages, R2) plus the factory the MCP
 * server uses to pick a backend:
 *
 *   createCloudflareClient(env)
 *     CLOUDFLARE_MOCK=1  → in-memory mock (mock-client.ts) — tests & local e2e
 *     otherwise          → real client over the REST API v4 (native fetch)
 *
 * Connection contract (frozen): CLOUDFLARE_API_TOKEN (scoped API token,
 * injected by the gateway at spawn via the upstream's transport.env —
 * registry/cloudflare.yaml, auth type env), CLOUDFLARE_API_URL (optional,
 * defaults to https://api.cloudflare.com/client/v4). The token is sent ONLY
 * as the Authorization: Bearer header; it NEVER appears in logs or error
 * messages.
 *
 * Error contract: the Cloudflare envelope {success, errors, result} is
 * unwrapped here — failures surface as clean Error/CloudflareApiError
 * messages carrying the CF code/message, with two distinguished cases:
 *   - 401/403 → actionable "deposit a scoped token" message
 *   - zone/record not found → dedicated messages pointing at list_zones /
 *     dns_list
 *
 * No new npm dependencies: native fetch (Node 22) only.
 */
import { createMockClient } from "./mock-client.js";

export const DEFAULT_API_URL = "https://api.cloudflare.com/client/v4";
export const REQUEST_TIMEOUT_MS = 15_000;

// --- Semantic output shapes (compact JSON — the frozen response contract) ---

export interface ZoneInfo {
  id: string;
  name: string;
  status: string;
}

export interface DnsRecordInfo {
  id: string;
  type: string;
  name: string;
  content: string;
  ttl: number;
  proxied: boolean;
}

export interface DnsRecordInput {
  type: string;
  name: string;
  content: string;
  ttl?: number;
  proxied?: boolean;
}

export interface DnsRecordPatch {
  type?: string;
  name?: string;
  content?: string;
  ttl?: number;
  proxied?: boolean;
}

export interface DnsRecordDeleted {
  id: string;
  deleted: true;
}

export interface DnsRecordsListed {
  zone: ZoneInfo;
  records: DnsRecordInfo[];
}

export interface WorkerInfo {
  id: string;
}

export interface PagesProjectInfo {
  name: string;
  subdomain: string;
}

export interface R2BucketInfo {
  name: string;
  creationDate?: string;
}

export interface WorkersListed {
  accountId: string;
  workers: WorkerInfo[];
}

export interface PagesProjectsListed {
  accountId: string;
  projects: PagesProjectInfo[];
}

export interface R2BucketsListed {
  accountId: string;
  buckets: R2BucketInfo[];
}

// --- The bridge client contract (real and mock both implement it) ---

export interface CloudflareBridgeClient {
  connect: () => Promise<void>;
  close: () => Promise<void>;

  listZones: () => Promise<ZoneInfo[]>;
  listDnsRecords: (filter: { zone: string; type?: string; name?: string }) => Promise<DnsRecordsListed>;
  createDnsRecord: (zone: string, input: DnsRecordInput) => Promise<DnsRecordInfo>;
  updateDnsRecord: (zone: string, recordId: string, patch: DnsRecordPatch) => Promise<DnsRecordInfo>;
  deleteDnsRecord: (zone: string, recordId: string) => Promise<DnsRecordDeleted>;

  listWorkers: (accountId?: string) => Promise<WorkersListed>;
  listPagesProjects: (accountId?: string) => Promise<PagesProjectsListed>;
  listR2Buckets: (accountId?: string) => Promise<R2BucketsListed>;
}

// --- Shared actionable error builders (never carry the token) ---

export function tokenRejectedError(status: number): Error {
  return new Error(
    `Cloudflare API token rejected or under-scoped (HTTP ${status}) — deposit a SCOPED API token ` +
      `(Zone.DNS edit on the zones you need + Workers/Pages/R2 read; never a Global API Key) with ` +
      `\`scopegate secret add cloudflare_api_token\`, then retry`,
  );
}

export function zoneNotFoundError(ref: string, hint?: string): Error {
  return new Error(
    `Zone not found: "${ref}" — pass a zone name (example.com) or zone id; ` +
      (hint ?? "use list_zones to see the zones this token can access"),
  );
}

export function recordNotFoundError(recordId: string, zoneName: string): Error {
  return new Error(
    `DNS record not found: "${recordId}" in zone "${zoneName}" — use dns_list {zone} to locate the record id`,
  );
}

/** CF API failure carrying the HTTP status (and first CF error code) for callers to distinguish 404s. */
export class CloudflareApiError extends Error {
  readonly status: number;
  readonly code?: number;

  constructor(message: string, status: number, code?: number) {
    super(message);
    this.name = "CloudflareApiError";
    this.status = status;
    if (code !== undefined) this.code = code;
  }
}

// --- Real client over the Cloudflare API v4 (native fetch) ---

interface CfErrorEntry {
  code?: number;
  message?: string;
}

interface CfEnvelope {
  success?: boolean;
  errors?: CfErrorEntry[];
  result?: unknown;
}

function toZoneInfo(z: Record<string, unknown>): ZoneInfo {
  return { id: String(z.id ?? ""), name: String(z.name ?? ""), status: String(z.status ?? "") };
}

function toDnsRecordInfo(r: Record<string, unknown>): DnsRecordInfo {
  return {
    id: String(r.id ?? ""),
    type: String(r.type ?? ""),
    name: String(r.name ?? ""),
    content: String(r.content ?? ""),
    ttl: typeof r.ttl === "number" ? r.ttl : 1,
    proxied: r.proxied === true,
  };
}

export class RealCloudflareClient implements CloudflareBridgeClient {
  private readonly token: string;
  private readonly baseUrl: string;
  private accountIdCache: string | null = null;

  constructor(opts: { token: string; apiUrl?: string }) {
    this.token = opts.token;
    this.baseUrl = (opts.apiUrl ?? DEFAULT_API_URL).trim().replace(/\/+$/, "");
  }

  /**
   * Startup check: verifies the token once. Two token kinds exist and they
   * verify at DIFFERENT endpoints: user tokens at `/user/tokens/verify`,
   * account tokens (created in an account's API Tokens section) at
   * `/accounts/<id>/tokens/verify` — the former 401s the latter. Try the
   * user endpoint first, then accept any token that can list accounts.
   */
  async connect(): Promise<void> {
    try {
      await this.request<unknown>("GET", "/user/tokens/verify");
      return;
    } catch (err) {
      // Fall through to the account-token probe.
      if (!(err instanceof Error) || !/rejected|under-scoped/i.test(err.message)) throw err;
    }
    await this.request<unknown>("GET", "/accounts?per_page=1");
  }

  async close(): Promise<void> {}

  /**
   * Single request helper: Bearer auth, 15s timeout, CF envelope unwrap.
   * The token is ONLY used in the Authorization header and is never copied
   * into an Error message.
   */
  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      if (controller.signal.aborted) {
        throw new Error(
          `Cloudflare API request timed out after ${Math.round(REQUEST_TIMEOUT_MS / 1000)}s (${method} ${path}) — check connectivity to ${this.baseUrl}`,
        );
      }
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(`Cloudflare API request failed (${method} ${path}): ${detail}`);
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 401 || res.status === 403) throw tokenRejectedError(res.status);

    let payload: CfEnvelope;
    try {
      payload = (await res.json()) as CfEnvelope;
    } catch {
      throw new Error(`Cloudflare API returned HTTP ${res.status} with a non-JSON response (${method} ${path})`);
    }
    if (!res.ok || payload.success !== true) {
      const entries = payload.errors ?? [];
      const detail =
        entries.map((e) => (e.code !== undefined ? `[${e.code}] ${e.message ?? "error"}` : (e.message ?? "error"))).join("; ") ||
        `HTTP ${res.status}`;
      throw new CloudflareApiError(`Cloudflare API error HTTP ${res.status} (${method} ${path}): ${detail}`, res.status, entries[0]?.code);
    }
    return payload.result as T;
  }

  /** Zones are accepted by name (example.com) or by id (frozen contract). */
  private async resolveZone(ref: string): Promise<ZoneInfo> {
    const trimmed = ref.trim();
    const byName = await this.request<Array<Record<string, unknown>>>("GET", `/zones?name=${encodeURIComponent(trimmed)}`);
    if (byName.length > 0) return toZoneInfo(byName[0]);
    try {
      const z = await this.request<Record<string, unknown>>("GET", `/zones/${encodeURIComponent(trimmed)}`);
      return toZoneInfo(z);
    } catch (err) {
      if (err instanceof CloudflareApiError && err.status === 404) throw zoneNotFoundError(ref);
      throw err;
    }
  }

  /** accountId optional: resolved once via GET /accounts (first account), then cached. */
  private async resolveAccountId(accountId?: string): Promise<string> {
    if (accountId !== undefined && accountId.trim() !== "") return accountId.trim();
    if (this.accountIdCache !== null) return this.accountIdCache;
    const accounts = await this.request<Array<Record<string, unknown>>>("GET", "/accounts");
    const first = accounts.find((a) => typeof a.id === "string" && a.id !== "");
    if (first === undefined) {
      throw new Error(
        'Cloudflare API token can access no accounts — pass "accountId" explicitly or deposit a token with account read access',
      );
    }
    this.accountIdCache = String(first.id);
    return this.accountIdCache;
  }

  async listZones(): Promise<ZoneInfo[]> {
    const zones = await this.request<Array<Record<string, unknown>>>("GET", "/zones");
    return zones.map(toZoneInfo).sort((a, b) => a.name.localeCompare(b.name));
  }

  async listDnsRecords(filter: { zone: string; type?: string; name?: string }): Promise<DnsRecordsListed> {
    const zone = await this.resolveZone(filter.zone);
    const params = new URLSearchParams();
    if (filter.type !== undefined && filter.type.trim() !== "") params.set("type", filter.type.trim().toUpperCase());
    if (filter.name !== undefined && filter.name.trim() !== "") params.set("name", filter.name.trim());
    const suffix = params.size > 0 ? `?${params.toString()}` : "";
    const records = await this.request<Array<Record<string, unknown>>>("GET", `/zones/${zone.id}/dns_records${suffix}`);
    return { zone, records: records.map(toDnsRecordInfo) };
  }

  async createDnsRecord(zone: string, input: DnsRecordInput): Promise<DnsRecordInfo> {
    const z = await this.resolveZone(zone);
    const body: Record<string, unknown> = { type: input.type, name: input.name, content: input.content };
    if (input.ttl !== undefined) body.ttl = input.ttl;
    if (input.proxied !== undefined) body.proxied = input.proxied;
    const record = await this.request<Record<string, unknown>>("POST", `/zones/${z.id}/dns_records`, body);
    return toDnsRecordInfo(record);
  }

  async updateDnsRecord(zone: string, recordId: string, patch: DnsRecordPatch): Promise<DnsRecordInfo> {
    const z = await this.resolveZone(zone);
    const body: Record<string, unknown> = {};
    if (patch.type !== undefined) body.type = patch.type;
    if (patch.name !== undefined) body.name = patch.name;
    if (patch.content !== undefined) body.content = patch.content;
    if (patch.ttl !== undefined) body.ttl = patch.ttl;
    if (patch.proxied !== undefined) body.proxied = patch.proxied;
    try {
      const record = await this.request<Record<string, unknown>>(
        "PATCH",
        `/zones/${z.id}/dns_records/${encodeURIComponent(recordId)}`,
        body,
      );
      return toDnsRecordInfo(record);
    } catch (err) {
      if (err instanceof CloudflareApiError && err.status === 404) throw recordNotFoundError(recordId, z.name);
      throw err;
    }
  }

  async deleteDnsRecord(zone: string, recordId: string): Promise<DnsRecordDeleted> {
    const z = await this.resolveZone(zone);
    try {
      const result = await this.request<Record<string, unknown>>(
        "DELETE",
        `/zones/${z.id}/dns_records/${encodeURIComponent(recordId)}`,
      );
      return { id: String(result.id ?? recordId), deleted: true };
    } catch (err) {
      if (err instanceof CloudflareApiError && err.status === 404) throw recordNotFoundError(recordId, z.name);
      throw err;
    }
  }

  async listWorkers(accountId?: string): Promise<WorkersListed> {
    const id = await this.resolveAccountId(accountId);
    const scripts = await this.request<Array<Record<string, unknown>>>("GET", `/accounts/${id}/workers/scripts`);
    return { accountId: id, workers: scripts.map((s) => ({ id: String(s.id ?? "") })) };
  }

  async listPagesProjects(accountId?: string): Promise<PagesProjectsListed> {
    const id = await this.resolveAccountId(accountId);
    const projects = await this.request<Array<Record<string, unknown>>>("GET", `/accounts/${id}/pages/projects`);
    return {
      accountId: id,
      projects: projects.map((p) => ({ name: String(p.name ?? ""), subdomain: String(p.subdomain ?? "") })),
    };
  }

  async listR2Buckets(accountId?: string): Promise<R2BucketsListed> {
    const id = await this.resolveAccountId(accountId);
    const buckets = await this.request<Array<Record<string, unknown>>>("GET", `/accounts/${id}/r2/buckets`);
    return {
      accountId: id,
      buckets: buckets.map((b) => {
        const out: R2BucketInfo = { name: String(b.name ?? "") };
        if (typeof b.creation_date === "string") out.creationDate = b.creation_date;
        return out;
      }),
    };
  }
}

// --- Factory -------------------------------------------------------------------

/**
 * Picks the backend from the environment (frozen contract):
 *   CLOUDFLARE_MOCK=1 → in-memory mock (no network, token not validated);
 *   otherwise         → real client (requires CLOUDFLARE_API_TOKEN;
 *                       CLOUDFLARE_API_URL optional, default API v4 URL).
 */
export function createCloudflareClient(env: NodeJS.ProcessEnv = process.env): CloudflareBridgeClient {
  if (env.CLOUDFLARE_MOCK === "1") return createMockClient();
  const token = env.CLOUDFLARE_API_TOKEN;
  if (token === undefined || token.trim() === "") {
    throw new Error(
      "cloudflare-bridge: missing required env CLOUDFLARE_API_TOKEN — the gateway injects it via the upstream's " +
        "transport.env (deposit it with `scopegate secret add cloudflare_api_token`, or set CLOUDFLARE_MOCK=1 for the in-memory mock)",
    );
  }
  return new RealCloudflareClient({ token, apiUrl: env.CLOUDFLARE_API_URL });
}
