/**
 * Task leases (mejora #1): grants that survive long agentic tasks.
 *
 * The problem: grants expire in minutes, tasks last hours. A task lease
 * groups every grant of one task under a double budget — total time
 * (`max_lease_total`, a HARD, fail-closed limit in `limits` exactly like
 * `max_ttl`) and write count (`max_writes`). While the lease is alive, the
 * agent renews its grants by itself (sliding TTL, never past the lease
 * deadline); when the lease dies, so does every grant bound to it.
 *
 * FILE CONTRACT: `~/.scopegate/leases.json`, mode 0600, atomic tmp+rename
 * writes (fsutil). Load discards expired/revoked leases from `open` status
 * (they stay on file as history with their terminal status).
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { atomicWriteFileSync } from "./fsutil.js";

export const LEASES_PATH = path.join(SCOPEGATE_DIR, "leases.json");

export interface Lease {
  leaseId: string;
  agentId: string;
  /** One line — what the agent says the task is (lands in audit). */
  goal: string;
  /** Upstream names the lease is scoped to (informational for now). */
  upstreams: string[];
  createdAt: number;
  /** Absolute deadline: createdAt + totalMs (after the hard clamp). */
  deadlineMs: number;
  /** Requested total duration in ms (before/after clamp — for display). */
  totalMs: number;
  /** The hard ceiling that was applied (limits.max_lease_total or default). */
  ceilingMs: number;
  maxWrites: number;
  writesUsed: number;
  status: "open" | "closed" | "expired" | "revoked";
}

interface LeasesFile {
  version: 1;
  leases: Lease[];
}

function isValidLease(v: unknown): v is Lease {
  if (!v || typeof v !== "object") return false;
  const r = v as Record<string, unknown>;
  return (
    typeof r.leaseId === "string" &&
    typeof r.agentId === "string" &&
    typeof r.goal === "string" &&
    Array.isArray(r.upstreams) &&
    typeof r.createdAt === "number" &&
    typeof r.deadlineMs === "number" &&
    typeof r.maxWrites === "number" &&
    typeof r.writesUsed === "number" &&
    typeof r.status === "string"
  );
}

export const DEFAULT_LEASE_TOTAL_MS = 4 * 3600 * 1000; // 4h
export const DEFAULT_LEASE_MAX_WRITES = 200;

export class LeaseStore {
  private leases: Lease[] = [];

  constructor(private filePath: string = LEASES_PATH) {
    this.load();
  }

  private load(): void {
    this.leases = [];
    if (!fs.existsSync(this.filePath)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as Partial<LeasesFile>;
      const list = Array.isArray(raw?.leases) ? raw.leases : [];
      this.leases = list.filter(isValidLease);
    } catch (e) {
      console.error(
        `[scopegate] warn: leases store at ${this.filePath} is unreadable (${(e as Error).message}) — starting empty`,
      );
      this.leases = [];
    }
  }

  private save(): void {
    ensureDir();
    const data: LeasesFile = { version: 1, leases: this.leases };
    atomicWriteFileSync(this.filePath, JSON.stringify(data, null, 2));
  }

  /** Open a new lease. `totalMs`/`maxWrites` are already clamped by the caller. */
  open(input: {
    agentId: string;
    goal: string;
    upstreams: string[];
    totalMs: number;
    ceilingMs: number;
    maxWrites: number;
  }): Lease {
    const now = Date.now();
    const lease: Lease = {
      leaseId: crypto.randomUUID(),
      agentId: input.agentId,
      goal: input.goal,
      upstreams: input.upstreams,
      createdAt: now,
      deadlineMs: now + input.totalMs,
      totalMs: input.totalMs,
      ceilingMs: input.ceilingMs,
      maxWrites: input.maxWrites,
      writesUsed: 0,
      status: "open",
    };
    this.leases.push(lease);
    this.save();
    return lease;
  }

  get(leaseId: string): Lease | undefined {
    return this.leases.find((l) => l.leaseId === leaseId);
  }

  /** Lazily terminal-mark a lease whose deadline passed (persisted). */
  private sweep(lease: Lease, now: number = Date.now()): Lease {
    if (lease.status === "open" && lease.deadlineMs <= now) {
      lease.status = "expired";
      this.save();
    }
    return lease;
  }

  /** Live = open and before the deadline. */
  isLive(leaseId: string, now: number = Date.now()): boolean {
    const lease = this.get(leaseId);
    if (!lease) return false;
    this.sweep(lease, now);
    return lease.status === "open" && lease.deadlineMs > now;
  }

  /** Remaining lease time (0 when dead). */
  remainingMs(leaseId: string, now: number = Date.now()): number {
    const lease = this.get(leaseId);
    if (!lease || !this.isLive(leaseId, now)) return 0;
    return lease.deadlineMs - now;
  }

  /**
   * Consume one write from the lease budget. Returns false when the budget
   * is exhausted or the lease is dead — the caller denies the call.
   */
  consumeWrite(leaseId: string, now: number = Date.now()): boolean {
    const lease = this.get(leaseId);
    if (!lease || !this.isLive(leaseId, now)) return false;
    if (lease.writesUsed >= lease.maxWrites) return false;
    lease.writesUsed += 1;
    this.save();
    return true;
  }

  /** Remaining write budget (0 when dead). */
  writesRemaining(leaseId: string, now: number = Date.now()): number {
    const lease = this.get(leaseId);
    if (!lease || !this.isLive(leaseId, now)) return 0;
    return Math.max(0, lease.maxWrites - lease.writesUsed);
  }

  close(leaseId: string): Lease | undefined {
    const lease = this.get(leaseId);
    if (!lease || lease.status !== "open") return undefined;
    lease.status = "closed";
    this.save();
    return lease;
  }

  revoke(leaseId: string): Lease | undefined {
    const lease = this.get(leaseId);
    if (!lease || lease.status !== "open") return undefined;
    lease.status = "revoked";
    this.save();
    return lease;
  }

  listForAgent(agentId: string, now: number = Date.now()): Lease[] {
    return this.leases
      .filter((l) => l.agentId === agentId)
      .map((l) => this.sweep(l, now));
  }
}
