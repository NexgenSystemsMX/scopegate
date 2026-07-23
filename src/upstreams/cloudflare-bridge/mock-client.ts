/**
 * In-memory mock of CloudflareBridgeClient (EPIC-17) — same semantics as the
 * real client, backed by plain Maps/arrays. Used when CLOUDFLARE_MOCK=1:
 * unit tests and the local e2e run WITHOUT network access or a live
 * Cloudflare account (the token is not validated).
 *
 * Seeded state (deterministic, so tests/e2e can assert against it):
 *   - zones    example.com (mock-zone-1), demo.dev (mock-zone-2)
 *   - records  A www.example.com → 192.0.2.1 (proxied), MX example.com → mail.example.com
 *   - account  mock-account-1 ("Mock Account")
 *   - workers  api-worker, auth-worker
 *   - pages    docs-site (docs-site.pages.dev)
 *   - r2       backups, assets
 *
 * Error messages mirror the real client (shared builders from client.ts) so
 * the mock can be read as a standalone spec of the bridge semantics.
 */
import {
  recordNotFoundError,
  zoneNotFoundError,
  type CloudflareBridgeClient,
  type DnsRecordDeleted,
  type DnsRecordInfo,
  type DnsRecordInput,
  type DnsRecordPatch,
  type DnsRecordsListed,
  type PagesProjectsListed,
  type R2BucketsListed,
  type WorkersListed,
  type ZoneInfo,
} from "./client.js";

interface MockRecord extends DnsRecordInfo {
  zoneId: string;
}

export class MockCloudflareClient implements CloudflareBridgeClient {
  private seq = 2; // seeded records take mock-record-1/2; creations start at 3
  private readonly zones = new Map<string, ZoneInfo>();
  private readonly records = new Map<string, MockRecord>();
  private readonly accounts: Array<{ id: string; name: string }> = [{ id: "mock-account-1", name: "Mock Account" }];
  private readonly workers = [{ id: "api-worker" }, { id: "auth-worker" }];
  private readonly pagesProjects = [{ name: "docs-site", subdomain: "docs-site.pages.dev" }];
  private readonly r2Buckets = [
    { name: "assets", creationDate: "2026-01-05T00:00:00.000Z" },
    { name: "backups", creationDate: "2026-02-10T00:00:00.000Z" },
  ];

  constructor() {
    this.zones.set("mock-zone-1", { id: "mock-zone-1", name: "example.com", status: "active" });
    this.zones.set("mock-zone-2", { id: "mock-zone-2", name: "demo.dev", status: "active" });
    this.records.set("mock-record-1", {
      id: "mock-record-1",
      zoneId: "mock-zone-1",
      type: "A",
      name: "www.example.com",
      content: "192.0.2.1",
      ttl: 1,
      proxied: true,
    });
    this.records.set("mock-record-2", {
      id: "mock-record-2",
      zoneId: "mock-zone-1",
      type: "MX",
      name: "example.com",
      content: "mail.example.com",
      ttl: 3600,
      proxied: false,
    });
  }

  async connect(): Promise<void> {}
  async close(): Promise<void> {}

  /** Zones are accepted by name (case-insensitive) or by id — like the real client. */
  private resolveZone(ref: string): ZoneInfo {
    const needle = ref.trim().toLowerCase();
    for (const z of this.zones.values()) {
      if (z.id === ref.trim() || z.name.toLowerCase() === needle) return z;
    }
    const known = [...this.zones.values()].map((z) => z.name).join(", ");
    throw zoneNotFoundError(ref, `available zones: ${known} (list_zones)`);
  }

  private resolveRecord(zone: ZoneInfo, recordId: string): MockRecord {
    const record = this.records.get(recordId);
    if (record !== undefined && record.zoneId === zone.id) return record;
    throw recordNotFoundError(recordId, zone.name);
  }

  /** accountId optional: omit it to use the first account (same as the real client's /accounts resolution). */
  private resolveAccountId(accountId?: string): string {
    if (accountId !== undefined && accountId.trim() !== "") {
      const id = accountId.trim();
      if (this.accounts.some((a) => a.id === id)) return id;
      throw new Error(
        `Account not found: "${id}" — available accounts: ${this.accounts.map((a) => a.id).join(", ")} ` +
          '(or omit "accountId" to use the first account the token can access)',
      );
    }
    return this.accounts[0].id;
  }

  private static toInfo(record: MockRecord): DnsRecordInfo {
    return {
      id: record.id,
      type: record.type,
      name: record.name,
      content: record.content,
      ttl: record.ttl,
      proxied: record.proxied,
    };
  }

  async listZones(): Promise<ZoneInfo[]> {
    return [...this.zones.values()].map((z) => ({ ...z })).sort((a, b) => a.name.localeCompare(b.name));
  }

  async listDnsRecords(filter: { zone: string; type?: string; name?: string }): Promise<DnsRecordsListed> {
    const zone = this.resolveZone(filter.zone);
    let records = [...this.records.values()].filter((r) => r.zoneId === zone.id);
    if (filter.type !== undefined && filter.type.trim() !== "") {
      const type = filter.type.trim().toUpperCase();
      records = records.filter((r) => r.type === type);
    }
    if (filter.name !== undefined && filter.name.trim() !== "") {
      const name = filter.name.trim().toLowerCase();
      records = records.filter((r) => r.name.toLowerCase() === name);
    }
    return { zone: { ...zone }, records: records.map(MockCloudflareClient.toInfo) };
  }

  async createDnsRecord(zone: string, input: DnsRecordInput): Promise<DnsRecordInfo> {
    const z = this.resolveZone(zone);
    this.seq += 1;
    const record: MockRecord = {
      id: `mock-record-${this.seq}`,
      zoneId: z.id,
      type: input.type.trim().toUpperCase(),
      name: input.name,
      content: input.content,
      ttl: input.ttl ?? 1,
      proxied: input.proxied ?? false,
    };
    this.records.set(record.id, record);
    return MockCloudflareClient.toInfo(record);
  }

  async updateDnsRecord(zone: string, recordId: string, patch: DnsRecordPatch): Promise<DnsRecordInfo> {
    const z = this.resolveZone(zone);
    const record = this.resolveRecord(z, recordId);
    if (patch.type !== undefined) record.type = patch.type.trim().toUpperCase();
    if (patch.name !== undefined) record.name = patch.name;
    if (patch.content !== undefined) record.content = patch.content;
    if (patch.ttl !== undefined) record.ttl = patch.ttl;
    if (patch.proxied !== undefined) record.proxied = patch.proxied;
    return MockCloudflareClient.toInfo(record);
  }

  async deleteDnsRecord(zone: string, recordId: string): Promise<DnsRecordDeleted> {
    const z = this.resolveZone(zone);
    const record = this.resolveRecord(z, recordId);
    this.records.delete(record.id);
    return { id: record.id, deleted: true };
  }

  async listWorkers(accountId?: string): Promise<WorkersListed> {
    const id = this.resolveAccountId(accountId);
    return { accountId: id, workers: this.workers.map((w) => ({ ...w })) };
  }

  async listPagesProjects(accountId?: string): Promise<PagesProjectsListed> {
    const id = this.resolveAccountId(accountId);
    return { accountId: id, projects: this.pagesProjects.map((p) => ({ ...p })) };
  }

  async listR2Buckets(accountId?: string): Promise<R2BucketsListed> {
    const id = this.resolveAccountId(accountId);
    return { accountId: id, buckets: this.r2Buckets.map((b) => ({ ...b })) };
  }
}

export function createMockClient(): MockCloudflareClient {
  return new MockCloudflareClient();
}
