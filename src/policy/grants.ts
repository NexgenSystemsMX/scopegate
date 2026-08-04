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
 *
 * EPIC-06 (QM keychain semantics): grants gain the keychain fields of the QM
 * grant model — `audience`, `mode: "once"|"standing"`, `purpose` (declarative,
 * NOT enforceable), `status: "active"|"used"|"revoked"` and claim/revoke
 * timestamps. All of them are OPTIONAL: a grants.json written before EPIC-06
 * loads untouched and every pre-existing grant behaves exactly as
 * `standing` + self-audience + `active` (zero migration). Surgically
 * revoked/used grants stay in the file as TOMBSTONES until their TTL expires
 * — that is what lets a second claim answer "used"/"revoked" instead of a
 * bare "no grant". The ONE exception is the identity kill (`revokeAgent`:
 * honeytoken suspension, fleet revocation), which wipes the agent's grants
 * from the store outright — the EPIC-11 security contract.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import picomatch from "picomatch";
import { SCOPEGATE_DIR, ensureDir } from "../config/config.js";
import { atomicWriteFileSync } from "./fsutil.js";
import { matchesWhen } from "./when.js";

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
  /** Set on a CHILD grant delegated from this one (mejora #5). */
  parentGrantId?: string;
  /** Arg guard of the issuing rule (M6) — the grant covers a call only when
   *  its args satisfy it too. */
  when?: Record<string, string | number | boolean>;
  /* ------------------------- EPIC-06: QM keychain ------------------------ */
  /** Grantee audience (QM keychain): the logical agentId that may USE the
   *  grant, or the reserved literal "org" (any declared identity). Absent =
   *  self (`agentId`), which is the pre-EPIC-06 behaviour. */
  audience?: string;
  /** QM keychain mode. Absent = "standing" (pre-EPIC-06 behaviour): the grant
   *  authorizes calls until `expiresAt`. "once" authorizes EXACTLY ONE call —
   *  consumed atomically at authorization time (see claimOnce). */
  mode?: "once" | "standing";
  /** Declarative purpose: an instruction to the model plus an audit field.
   *  NOT enforceable — no gate ever evaluates it (same honesty as QM). */
  purpose?: string;
  /** Once/lifecycle state (QM: active|revoked|used). Absent = "active". */
  status?: "active" | "used" | "revoked";
  usedAt?: number;
  usedBy?: string;
  revokedAt?: number;
  /** Who asked for the grant when the holder did not (admin issue / promote). */
  requestedBy?: string;
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

/** A grant still usable for authorization (tombstones never are). */
function isLive(g: Grant): boolean {
  return g.status === undefined || g.status === "active";
}

export class GrantStore {
  private grants: Grant[] = [];

  /**
   * EPIC-06: predicate that tells whether a logical identity is DECLARED on
   * this gateway (a policies `agents:` section). Wired by the PolicyEngine,
   * which owns the policy set (hot-reload safe: it is a closure over the
   * engine, not a snapshot). Used only for `audience: "org"` matching — when
   * unset, org-audience grants cover NOBODY (fail-closed).
   */
  public agentAccepted?: (agentId: string) => boolean;

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
    parentGrantId?: string;
    when?: Record<string, string | number | boolean>;
    audience?: string;
    mode?: "once" | "standing";
    purpose?: string;
    requestedBy?: string;
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
      ...(input.parentGrantId ? { parentGrantId: input.parentGrantId } : {}),
      ...(input.when ? { when: input.when } : {}),
      ...(input.audience ? { audience: input.audience } : {}),
      ...(input.mode ? { mode: input.mode } : {}),
      ...(input.purpose ? { purpose: input.purpose } : {}),
      ...(input.requestedBy ? { requestedBy: input.requestedBy } : {}),
    };
    this.grants.push(grant);
    this.save();
    return grant;
  }

  /** A single LIVE grant by id (undefined when absent, expired, used or revoked). */
  byId(agentId: string, grantId: string, now: number = Date.now()): Grant | undefined {
    this.purgeExpired(now);
    return this.grants.find((g) => g.agentId === agentId && g.id === grantId && isLive(g));
  }

  /**
   * A single LIVE grant by id regardless of holder (EPIC-06 admin promote).
   * Ownership checks are the caller's job.
   */
  byIdAny(grantId: string, now: number = Date.now()): Grant | undefined {
    this.purgeExpired(now);
    return this.grants.find((g) => g.id === grantId && isLive(g));
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

  /**
   * EPIC-06 audience rule (QM keychain): does this grant cover the caller?
   *   - no `audience` → self: only the holder (`agentId`) — the historical rule;
   *   - `audience: "org"` → any identity DECLARED on the gateway (agentAccepted);
   *   - any other `audience` → exactly that logical agentId.
   * Note the holder is NOT covered when the audience names someone else.
   */
  private coversCaller(g: Grant, agentId: string): boolean {
    if (g.audience === undefined) return g.agentId === agentId;
    if (g.audience === "org") return this.agentAccepted?.(agentId) === true;
    return g.audience === agentId;
  }

  /** Capability + when-guard match (shared by every matcher). */
  private matchesCapability(
    g: Grant,
    capability: string,
    args?: Record<string, unknown>,
  ): boolean {
    return (
      (g.capability === capability || picomatch.isMatch(capability, g.capability)) &&
      (!g.when || matchesWhen(g.when, args))
    );
  }

  /** True when a live grant covers the capability (exact or as a glob) — and,
   *  for M6 `when`-guarded grants, when the call's args satisfy the guard. */
  isGranted(
    agentId: string,
    capability: string,
    now: number = Date.now(),
    args?: Record<string, unknown>,
  ): boolean {
    this.purgeExpired(now);
    return this.grants.some(
      (g) =>
        isLive(g) &&
        this.coversCaller(g, agentId) &&
        this.matchesCapability(g, capability, args),
    );
  }

  /**
   * The latest live grant covering the capability (matches the historical
   * "latest covering grant wins" rule server.ts relied on). Carries the
   * redact categories and remaining TTL the server needs post-call — and, for
   * M6 `when`-guarded grants, only matches when the call's args satisfy them.
   * EPIC-06: audience-aware and tombstone-skipping (a used/revoked grant
   * never covers).
   */
  coveringGrant(
    agentId: string,
    capability: string,
    now: number = Date.now(),
    args?: Record<string, unknown>,
  ): Grant | undefined {
    this.purgeExpired(now);
    return [...this.grants].reverse().find(
      (g) =>
        isLive(g) &&
        this.coversCaller(g, agentId) &&
        this.matchesCapability(g, capability, args),
    );
  }

  /**
   * EPIC-06: the latest grant RELATED to this caller for the capability,
   * regardless of lifecycle state (tombstones included). "Related" means the
   * caller holds it or is inside its audience. Used by the authorization
   * path to answer WHY a call is not covered (used / revoked / audience)
   * instead of a bare "none". Grants of unrelated identities stay invisible
   * (a caller never learns that somebody else holds a grant).
   */
  latestForCapability(
    agentId: string,
    capability: string,
    now: number = Date.now(),
    args?: Record<string, unknown>,
  ): Grant | undefined {
    this.purgeExpired(now);
    return [...this.grants].reverse().find(
      (g) =>
        (g.agentId === agentId ||
          g.audience === agentId ||
          g.audience === "org") &&
        this.matchesCapability(g, capability, args),
    );
  }

  /**
   * EPIC-06 (QM keychain once): atomic claim of a single-use grant. The
   * check-and-set is synchronous within this single-writer process and the
   * persist is the same atomic tmp+rename as every other mutation, so two
   * concurrent claims of the same grant yield EXACTLY ONE winner — the QM CAS
   * semantics for the supported topology (one gateway per SCOPEGATE_HOME).
   * If a multi-process store ever appears, this must move to a real CAS
   * (QM's postgres pattern: advisory lock + SELECT … FOR UPDATE); until then
   * the limitation is declared in the threat model.
   *
   * Claim = use: when the upstream call later fails the grant stays consumed
   * (no refund — same rule as QM's `used`).
   */
  claimOnce(grantId: string, usedBy: string): "ok" | "used" | "revoked" | "expired" {
    const g = this.grants.find((x) => x.id === grantId);
    if (!g) return "expired"; // purged between the covering check and the claim
    if (g.status === "revoked") return "revoked";
    if (g.status === "used") return "used";
    const now = Date.now();
    if (g.expiresAt <= now) {
      this.purgeExpired(now);
      return "expired";
    }
    g.status = "used";
    g.usedAt = now;
    g.usedBy = usedBy;
    this.save();
    return "ok";
  }

  /** Live grants of one agent (holder view — tombstones excluded). */
  active(agentId: string, now: number = Date.now()): Grant[] {
    this.purgeExpired(now);
    return this.grants.filter((g) => g.agentId === agentId && isLive(g));
  }

  /**
   * EPIC-06: live grants the agent can USE (holder, named audience, or org
   * audience) — the list view behind scopegate_list_capabilities. With
   * `includeTombstones`, the agent's OWN used/revoked grants (until TTL
   * expiry) are included too — lifecycle visibility (status/used_by) for the
   * model, never authorization.
   */
  usableBy(
    agentId: string,
    now: number = Date.now(),
    opts?: { includeTombstones?: boolean },
  ): Grant[] {
    this.purgeExpired(now);
    return this.grants.filter((g) => {
      if (isLive(g)) return this.coversCaller(g, agentId);
      return opts?.includeTombstones === true && g.agentId === agentId;
    });
  }

  /** Every unexpired grant, any holder, tombstones included (admin view). */
  all(now: number = Date.now()): Grant[] {
    this.purgeExpired(now);
    return [...this.grants];
  }

  /**
   * Revoke ONE grant by id, with cascade: a delegated (or promoted) child
   * must not outlive the parent that authorized it. EPIC-06: the cascade is
   * RECURSIVE (the whole descendant chain) and revocation is a TOMBSTONE
   * (`status: "revoked"` + `revokedAt`) kept until TTL expiry, so a later
   * claim/authorization attempt can be told apart from "no grant" (sticky
   * surgical revocation). Returns the grants revoked BY THIS CALL (already-
   * revoked tombstones are not double-counted); empty when the id is unknown.
   */
  revokeById(grantId: string): Grant[] {
    return this.revokeCascade(new Set([grantId]));
  }

  /**
   * IDENTITY KILL — revoke every grant of an agent (honeytoken suspension,
   * fleet revocation), with the full recursive cascade. Unlike the surgical
   * revokeById, this is SCORCHED EARTH: the agent's grants (prior tombstones
   * included) and every descendant are REMOVED from the store, not
   * tombstoned — the security contract of EPIC-11 is that after a suspension
   * nothing of the agent survives in grants.json. That is safe because both
   * callers deny EVERY request of the killed identity at their own fail-
   * closed checkpoint (honeytoken / cloud revocation) before any grant is
   * ever consulted, so the tombstones would never be read anyway. Returns
   * the grants revoked BY THIS CALL (pre-existing tombstones are wiped
   * silently, not double-counted).
   */
  revokeAgent(agentId: string): Grant[] {
    const seed = new Set(
      this.grants.filter((g) => g.agentId === agentId).map((g) => g.id),
    );
    if (seed.size === 0) return [];
    const ids = this.expandDescendants(seed);
    const wipedLive = this.grants.filter((g) => ids.has(g.id) && isLive(g));
    this.grants = this.grants.filter((g) => !ids.has(g.id));
    this.save();
    return wipedLive;
  }

  /** Shared cascade: seed ids + every transitive descendant, tombstoned. */
  private revokeCascade(seed: Set<string>): Grant[] {
    if (seed.size === 0) return [];
    const ids = this.expandDescendants(seed);
    const now = Date.now();
    const revoked: Grant[] = [];
    for (const g of this.grants) {
      if (ids.has(g.id) && isLive(g)) {
        g.status = "revoked";
        g.revokedAt = now;
        revoked.push(g);
      }
    }
    if (revoked.length > 0) this.save();
    return revoked;
  }

  /** Transitive closure over parentGrantId starting from a seed id set. */
  private expandDescendants(seed: Set<string>): Set<string> {
    const ids = new Set(seed);
    let grew = true;
    while (grew) {
      grew = false;
      for (const g of this.grants) {
        if (g.parentGrantId !== undefined && ids.has(g.parentGrantId) && !ids.has(g.id)) {
          ids.add(g.id);
          grew = true;
        }
      }
    }
    return ids;
  }
}
