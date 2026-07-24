/**
 * Persistent grant store (EPIC-04 H-04.2).
 *
 * Grants used to live only in engine memory: a gateway restart silently
 * dropped every active capability and `list_capabilities` lied afterwards.
 * They now persist to `~/.scopegate/grants.json`:
 *
 *   - mode 0600, atomic tmp+rename writes (see fsutil.ts);
 *   - load at startup discards expired grants (fail-closed: a corrupt or
 *     schema-invalid file yields an EMPTY store — no grant is ever
 *     resurrected from data we cannot parse);
 *   - expired grants are purged lazily on reads (the pre-existing purge in
 *     `isGranted()` semantics) and the purge is persisted;
 *   - each grant has a random UUID `id` surfaced by `list_capabilities`, and
 *     records the `redact` categories of the rule that issued it plus the
 *     `approvalId` when it was materialized from a human approval.
 *
 * Lifecycle audit events (grant_issued / grant_expired / grants_revoked) are
 * emitted by the PolicyEngine, which owns the business meaning of each
 * mutation; this class is deliberately just storage + matching.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import picomatch from "picomatch";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { atomicWriteFileSync } from "./fsutil.js";

export const GRANTS_PATH = path.join(SCOPEGATE_DIR, "grants.json");

export interface Grant {
  /** Random UUID — stable identifier shown by list_capabilities. */
  id: string;
  agentId: string;
  capability: string;
  grantedAt: number;
  expiresAt: number;
  /** Redaction categories inherited from the issuing rule (H-04.6). */
  redact?: string[];
  /** Set when the grant was materialized from a human approval (H-04.3). */
  approvalId?: string;
  /** The policy rule glob that issued the grant (informational). */
  rule?: string;
  /** Set when the grant belongs to a task lease (mejora #1). */
  leaseId?: string;
}

interface GrantsFile {
  version: 1;
  grants: Grant[];
}

function isValidGrant(g: unknown): g is Grant {
  if (!g || typeof g !== "object") return false;
  const r = g as Record<string, unknown>;
  return (
    typeof r.id === "string" &&
    typeof r.agentId === "string" &&
    typeof r.capability === "string" &&
    typeof r.grantedAt === "number" &&
    typeof r.expiresAt === "number"
  );
}

export class GrantStore {
  private grants: Grant[] = [];

  constructor(private filePath: string = GRANTS_PATH) {
    this.load();
  }

  /** Load from disk, discarding expired and malformed entries (fail-closed). */
  private load(): void {
    this.grants = [];
    if (!fs.existsSync(this.filePath)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8")) as Partial<GrantsFile>;
      const list = Array.isArray(raw?.grants) ? raw.grants : [];
      const now = Date.now();
      this.grants = list.filter(isValidGrant).filter((g) => g.expiresAt > now);
    } catch (e) {
      // Fail-closed: no grants from a file we cannot parse.
      console.error(
        `[scopegate] warn: grants store at ${this.filePath} is unreadable (${(e as Error).message}) — starting empty`,
      );
      this.grants = [];
    }
  }

  private save(): void {
    ensureDir();
    const data: GrantsFile = { version: 1, grants: this.grants };
    atomicWriteFileSync(this.filePath, JSON.stringify(data, null, 2));
  }

  /** Issue and persist a new grant. */
  issue(input: {
    agentId: string;
    capability: string;
    ttlMs: number;
    redact?: string[];
    approvalId?: string;
    rule?: string;
    leaseId?: string;
  }): Grant {
    const now = Date.now();
    const grant: Grant = {
      id: crypto.randomUUID(),
      agentId: input.agentId,
      capability: input.capability,
      grantedAt: now,
      expiresAt: now + input.ttlMs,
      ...(input.redact?.length ? { redact: input.redact } : {}),
      ...(input.approvalId ? { approvalId: input.approvalId } : {}),
      ...(input.rule ? { rule: input.rule } : {}),
      ...(input.leaseId ? { leaseId: input.leaseId } : {}),
    };
    this.grants.push(grant);
    this.save();
    return grant;
  }

  /** A single grant by id (undefined when absent or expired). */
  byId(agentId: string, grantId: string, now: number = Date.now()): Grant | undefined {
    this.purgeExpired(now);
    return this.grants.find((g) => g.agentId === agentId && g.id === grantId);
  }

  /**
   * Slide a grant's expiry forward (mejora #1 renew). The caller computes
   * the new expiry under every ceiling; this only persists it. grantedAt
   * stays — the full lease history remains attributable.
   */
  updateExpiry(agentId: string, grantId: string, newExpiresAt: number): Grant | undefined {
    const grant = this.grants.find((g) => g.agentId === agentId && g.id === grantId);
    if (!grant) return undefined;
    grant.expiresAt = newExpiresAt;
    this.save();
    return grant;
  }

  /** Revoke every grant bound to a lease; returns how many were dropped. */
  revokeLease(leaseId: string): number {
    const before = this.grants.length;
    this.grants = this.grants.filter((g) => g.leaseId !== leaseId);
    const removed = before - this.grants.length;
    if (removed > 0) this.save();
    return removed;
  }

  /**
   * Drop expired grants (the periodic purge, run lazily on reads). Returns
   * the grants that expired so the engine can audit `grant_expired` for each.
   */
  purgeExpired(now: number = Date.now()): Grant[] {
    const expired = this.grants.filter((g) => g.expiresAt <= now);
    if (expired.length === 0) return [];
    this.grants = this.grants.filter((g) => g.expiresAt > now);
    this.save();
    return expired;
  }

  /** True when a live grant covers the capability (exact or as a glob). */
  isGranted(agentId: string, capability: string, now: number = Date.now()): boolean {
    this.purgeExpired(now);
    return this.grants.some(
      (g) =>
        g.agentId === agentId &&
        (g.capability === capability || picomatch.isMatch(capability, g.capability)),
    );
  }

  /**
   * The latest live grant covering the capability (matches the historical
   * "latest covering grant wins" rule server.ts relied on). Carries the
   * redact categories and remaining TTL the server needs post-call.
   */
  coveringGrant(agentId: string, capability: string, now: number = Date.now()): Grant | undefined {
    this.purgeExpired(now);
    return [...this.grants].reverse().find(
      (g) =>
        g.agentId === agentId &&
        (g.capability === capability || picomatch.isMatch(capability, g.capability)),
    );
  }

  /** Live grants of one agent. */
  active(agentId: string, now: number = Date.now()): Grant[] {
    this.purgeExpired(now);
    return this.grants.filter((g) => g.agentId === agentId);
  }

  /** Revoke every grant of an agent; returns how many were dropped. */
  revokeAgent(agentId: string): number {
    const before = this.grants.length;
    this.grants = this.grants.filter((g) => g.agentId !== agentId);
    const removed = before - this.grants.length;
    if (removed > 0) this.save();
    return removed;
  }
}
