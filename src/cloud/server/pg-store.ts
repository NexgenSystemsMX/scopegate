/**
 * ScopeGate Cloud persistence — Postgres backend (M13, additive).
 *
 * Activated by startCloudServer when SCOPEGATE_CLOUD_DATABASE_URL is set;
 * without it the FileStore default is untouched (local-first, dev-grade).
 *
 * WHY A WRITE-THROUGH MEMORY MIRROR: the `Store` interface (store.ts) is
 * synchronous — every feature module (enroll/ingest/policies/...) calls it
 * without await — while node-postgres is async-only. Rather than forcing an
 * async-interface refactor across the whole control plane, this store keeps
 * the exact FileStore semantics in memory (loaded once at boot) and persists
 * every mutation to Postgres on a serialized, fire-and-forget write queue.
 * Consequences, honestly stated:
 *   - Reads are served from the mirror: full FileStore parity, zero latency.
 *   - Writes are durable once the queue flushes, not at call time. The server
 *     flushes on graceful close (store.close()); a hard crash can lose the
 *     last few milliseconds of writes — the same class of window FileStore
 *     has between mutation and fsync, only wider. Acceptable at
 *     control-plane-for-a-team scale; making `Store` async end-to-end is the
 *     documented future hardening step.
 *   - Memory footprint grows with audit volume (FileStore streams the JSONL
 *     from disk instead). Bounded by SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS —
 *     set it in production.
 *
 * SCHEMA (created idempotently, IF NOT EXISTS, mirroring the FileStore
 * collections): teams, agents, policy_versions, audit_events, revocations,
 * approval_decisions. Timestamps are stored as TEXT holding the ISO-8601
 * strings the model already uses: round-trips stay byte-exact and the
 * lexicographic comparisons the codebase relies on (ts > since, window
 * filters, retention cutoffs) remain valid. `audit_events.detail` is TEXT
 * (verbatim JSON), NOT jsonb, so an exported event hashes to the same bytes
 * the gateway signed. ALL queries are parametrized — never interpolate.
 */
import type {
  Agent,
  ApprovalDecision,
  AuditQuery,
  PolicyVersion,
  Revocation,
  StoredAuditEvent,
  Team,
} from "./model.js";
import type { Store } from "./store.js";

/** Minimal subset of pg.Pool — the real Pool satisfies it; tests inject a mock. */
export interface PgPoolLike {
  query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
  end(): Promise<void>;
}

export type PgStoreOptions =
  | { connectionString: string }
  | { pool: PgPoolLike };

const SCHEMA: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS teams (
     team_id text PRIMARY KEY,
     name text NOT NULL,
     enroll_token text NOT NULL,
     slack_webhook_url text,
     created_at text NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS agents (
     team_id text NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
     agent_id text NOT NULL,
     fingerprint text NOT NULL,
     public_key text,
     secret_hash text NOT NULL,
     enrolled_at text NOT NULL,
     last_seen text,
     revoked boolean NOT NULL DEFAULT false,
     revoked_at text,
     last_chain_hash text,
     PRIMARY KEY (team_id, agent_id)
   )`,
  `CREATE INDEX IF NOT EXISTS agents_secret_hash_idx ON agents (secret_hash)`,
  `CREATE TABLE IF NOT EXISTS policy_versions (
     team_id text NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
     version integer NOT NULL,
     yaml text NOT NULL,
     signature text NOT NULL,
     signed_at text NOT NULL,
     PRIMARY KEY (team_id, version)
   )`,
  // id bigserial preserves global arrival order (= FileStore file order) for
  // export; the (team_id, agent_id, seq) PK is the at-least-once dedupe key.
  `CREATE TABLE IF NOT EXISTS audit_events (
     id bigserial UNIQUE,
     team_id text NOT NULL,
     agent_id text NOT NULL,
     seq integer NOT NULL,
     ts text NOT NULL,
     kind text NOT NULL,
     detail text NOT NULL,
     input_hash text,
     prev text NOT NULL,
     sig text NOT NULL,
     hash text NOT NULL,
     ingested_at text NOT NULL,
     sig_verified boolean NOT NULL,
     PRIMARY KEY (team_id, agent_id, seq)
   )`,
  `CREATE INDEX IF NOT EXISTS audit_events_team_ts_idx ON audit_events (team_id, ts)`,
  `CREATE TABLE IF NOT EXISTS revocations (
     id bigserial PRIMARY KEY,
     team_id text NOT NULL,
     agent_id text NOT NULL,
     reason text NOT NULL,
     ts text NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS approval_decisions (
     team_id text NOT NULL,
     approval_id text NOT NULL,
     agent_id text NOT NULL,
     decision text NOT NULL,
     reason text,
     ttl text,
     decided_by text NOT NULL,
     ts text NOT NULL,
     PRIMARY KEY (team_id, approval_id)
   )`,
];

/* ---------------------------------------------------------- row mapping */

function rowToTeam(r: Record<string, unknown>): Team {
  return {
    teamId: r.team_id as string,
    name: r.name as string,
    enrollToken: r.enroll_token as string,
    slackWebhookUrl: (r.slack_webhook_url as string | null) ?? undefined,
    createdAt: r.created_at as string,
  };
}

function rowToAgent(r: Record<string, unknown>): Agent {
  return {
    agentId: r.agent_id as string,
    teamId: r.team_id as string,
    fingerprint: r.fingerprint as string,
    publicKey: (r.public_key as string | null) ?? undefined,
    secretHash: r.secret_hash as string,
    enrolledAt: r.enrolled_at as string,
    lastSeen: (r.last_seen as string | null) ?? null,
    revoked: r.revoked as boolean,
    revokedAt: (r.revoked_at as string | null) ?? undefined,
    lastChainHash: (r.last_chain_hash as string | null) ?? undefined,
  };
}

function rowToPolicy(r: Record<string, unknown>): PolicyVersion {
  return {
    teamId: r.team_id as string,
    version: r.version as number,
    yaml: r.yaml as string,
    signature: r.signature as string,
    signedAt: r.signed_at as string,
  };
}

function rowToRevocation(r: Record<string, unknown>): Revocation {
  return {
    teamId: r.team_id as string,
    agentId: r.agent_id as string,
    reason: r.reason as string,
    ts: r.ts as string,
  };
}

function rowToDecision(r: Record<string, unknown>): ApprovalDecision {
  return {
    approvalId: r.approval_id as string,
    teamId: r.team_id as string,
    agentId: r.agent_id as string,
    decision: r.decision as "approved" | "denied",
    reason: (r.reason as string | null) ?? undefined,
    ttl: (r.ttl as string | null) ?? undefined,
    decidedBy: r.decided_by as string,
    ts: r.ts as string,
  };
}

function rowToAuditEvent(r: Record<string, unknown>): StoredAuditEvent {
  return {
    ts: r.ts as string,
    agentId: r.agent_id as string,
    kind: r.kind as string,
    detail: JSON.parse(r.detail as string) as Record<string, unknown>,
    inputHash: (r.input_hash as string | null) ?? undefined,
    prev: r.prev as string,
    seq: r.seq as number,
    sig: r.sig as string,
    hash: r.hash as string,
    _cloud: {
      ingestedAt: r.ingested_at as string,
      sigVerified: r.sig_verified as boolean,
    },
  };
}

export class PostgresStore implements Store {
  private readonly pool: PgPoolLike;
  private teams: Team[] = [];
  private agents: Agent[] = [];
  private policies: PolicyVersion[] = [];
  private revocations: Revocation[] = [];
  private decisions: ApprovalDecision[] = [];
  private readonly auditByTeam = new Map<string, StoredAuditEvent[]>();

  /** Serialized write-behind queue; a failed write never kills the chain. */
  private tail: Promise<void> = Promise.resolve();
  private writeError: Error | null = null;

  private constructor(pool: PgPoolLike) {
    this.pool = pool;
  }

  /**
   * Connect, create the schema (idempotent) and load the mirror. This is the
   * ONLY way to obtain a PostgresStore — the sync Store interface has no room
   * for async boot, so it happens here, before the server takes requests.
   */
  static async create(opts: PgStoreOptions): Promise<PostgresStore> {
    let pool: PgPoolLike;
    if ("pool" in opts) {
      pool = opts.pool;
    } else {
      const { Pool } = await import("pg");
      pool = new Pool({ connectionString: opts.connectionString }) as PgPoolLike;
    }
    const store = new PostgresStore(pool);
    for (const ddl of SCHEMA) await pool.query(ddl);
    await store.load();
    return store;
  }

  private async load(): Promise<void> {
    const [teams, agents, policies, revocations, decisions, audit] =
      await Promise.all([
        this.pool.query(`SELECT * FROM teams`),
        this.pool.query(`SELECT * FROM agents`),
        this.pool.query(`SELECT * FROM policy_versions ORDER BY team_id, version`),
        this.pool.query(`SELECT * FROM revocations ORDER BY id`),
        this.pool.query(`SELECT * FROM approval_decisions`),
        this.pool.query(`SELECT * FROM audit_events ORDER BY id`),
      ]);
    this.teams = teams.rows.map((r) => rowToTeam(r as Record<string, unknown>));
    this.agents = agents.rows.map((r) => rowToAgent(r as Record<string, unknown>));
    this.policies = policies.rows.map((r) => rowToPolicy(r as Record<string, unknown>));
    this.revocations = revocations.rows.map((r) => rowToRevocation(r as Record<string, unknown>));
    this.decisions = decisions.rows.map((r) => rowToDecision(r as Record<string, unknown>));
    for (const row of audit.rows) {
      const e = rowToAuditEvent(row as Record<string, unknown>);
      const teamId = (row as Record<string, unknown>).team_id as string;
      const list = this.auditByTeam.get(teamId) ?? [];
      list.push(e);
      this.auditByTeam.set(teamId, list);
    }
  }

  /** Last async write failure (also logged to stderr); null when healthy. */
  get lastWriteError(): Error | null {
    return this.writeError;
  }

  /** Settle every queued write. Awaited by close() and by tests. */
  async flush(): Promise<void> {
    await this.tail;
  }

  private closed = false;

  /** Flush pending writes and end the pool. Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.flush();
    await this.pool.end();
  }

  private enqueue(text: string, params: unknown[]): void {
    this.tail = this.tail
      .then(() => this.pool.query(text, params))
      .then(() => undefined)
      .catch((e) => {
        this.writeError = e as Error;
        console.error(
          `[scopegate-cloud] pg-store write failed (${text.slice(0, 60)}...): ${(e as Error).message}`,
        );
      });
  }

  // ------------------------------------------------------------- teams
  createTeam(team: Team): void {
    this.teams.push(team);
    this.enqueue(
      `INSERT INTO teams (team_id, name, enroll_token, slack_webhook_url, created_at)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (team_id) DO NOTHING`,
      [team.teamId, team.name, team.enrollToken, team.slackWebhookUrl ?? null, team.createdAt],
    );
  }

  getTeam(teamId: string): Team | undefined {
    return this.teams.find((t) => t.teamId === teamId);
  }

  findTeamByEnrollToken(enrollToken: string): Team | undefined {
    return this.teams.find((t) => t.enrollToken === enrollToken);
  }

  listTeams(): Team[] {
    return [...this.teams];
  }

  updateTeam(teamId: string, patch: Partial<Omit<Team, "teamId">>): Team | undefined {
    const t = this.getTeam(teamId);
    if (!t) return undefined;
    Object.assign(t, patch);
    // Full-row write from the patched mirror — patch keys never reach SQL.
    this.enqueue(
      `UPDATE teams SET name = $2, enroll_token = $3, slack_webhook_url = $4, created_at = $5
       WHERE team_id = $1`,
      [t.teamId, t.name, t.enrollToken, t.slackWebhookUrl ?? null, t.createdAt],
    );
    return t;
  }

  // ------------------------------------------------------------ agents
  upsertAgent(agent: Agent): void {
    const i = this.agents.findIndex(
      (a) => a.teamId === agent.teamId && a.agentId === agent.agentId,
    );
    if (i >= 0) this.agents[i] = agent;
    else this.agents.push(agent);
    this.enqueue(
      `INSERT INTO agents (team_id, agent_id, fingerprint, public_key, secret_hash,
                           enrolled_at, last_seen, revoked, revoked_at, last_chain_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (team_id, agent_id) DO UPDATE SET
         fingerprint = EXCLUDED.fingerprint,
         public_key = EXCLUDED.public_key,
         secret_hash = EXCLUDED.secret_hash,
         enrolled_at = EXCLUDED.enrolled_at,
         last_seen = EXCLUDED.last_seen,
         revoked = EXCLUDED.revoked,
         revoked_at = EXCLUDED.revoked_at,
         last_chain_hash = EXCLUDED.last_chain_hash`,
      [
        agent.teamId,
        agent.agentId,
        agent.fingerprint,
        agent.publicKey ?? null,
        agent.secretHash,
        agent.enrolledAt,
        agent.lastSeen ?? null,
        agent.revoked,
        agent.revokedAt ?? null,
        agent.lastChainHash ?? null,
      ],
    );
  }

  getAgent(teamId: string, agentId: string): Agent | undefined {
    return this.agents.find((a) => a.teamId === teamId && a.agentId === agentId);
  }

  findAgentBySecretHash(secretHash: string): Agent | undefined {
    return this.agents.find((a) => a.secretHash === secretHash);
  }

  listAgents(teamId: string): Agent[] {
    return this.agents.filter((a) => a.teamId === teamId);
  }

  updateAgent(
    teamId: string,
    agentId: string,
    patch: Partial<Omit<Agent, "agentId" | "teamId">>,
  ): Agent | undefined {
    const a = this.getAgent(teamId, agentId);
    if (!a) return undefined;
    Object.assign(a, patch);
    this.upsertAgentRow(a);
    return a;
  }

  private upsertAgentRow(a: Agent): void {
    this.enqueue(
      `UPDATE agents SET fingerprint = $3, public_key = $4, secret_hash = $5,
                         enrolled_at = $6, last_seen = $7, revoked = $8,
                         revoked_at = $9, last_chain_hash = $10
       WHERE team_id = $1 AND agent_id = $2`,
      [
        a.teamId,
        a.agentId,
        a.fingerprint,
        a.publicKey ?? null,
        a.secretHash,
        a.enrolledAt,
        a.lastSeen ?? null,
        a.revoked,
        a.revokedAt ?? null,
        a.lastChainHash ?? null,
      ],
    );
  }

  // ----------------------------------------------------------- policies
  addPolicyVersion(policy: PolicyVersion): void {
    this.policies.push(policy);
    this.enqueue(
      `INSERT INTO policy_versions (team_id, version, yaml, signature, signed_at)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT (team_id, version) DO NOTHING`,
      [policy.teamId, policy.version, policy.yaml, policy.signature, policy.signedAt],
    );
  }

  latestPolicy(teamId: string): PolicyVersion | undefined {
    let latest: PolicyVersion | undefined;
    for (const p of this.policies) {
      if (p.teamId === teamId && (!latest || p.version > latest.version)) latest = p;
    }
    return latest;
  }

  policyVersions(teamId: string): PolicyVersion[] {
    return this.policies
      .filter((p) => p.teamId === teamId)
      .sort((a, b) => a.version - b.version);
  }

  // -------------------------------------------------------------- audit
  appendAuditEvents(teamId: string, events: StoredAuditEvent[]): void {
    if (events.length === 0) return;
    const list = this.auditByTeam.get(teamId) ?? [];
    list.push(...events);
    this.auditByTeam.set(teamId, list);
    for (const e of events) {
      // ON CONFLICT DO NOTHING mirrors the server-side at-least-once dedupe
      // (knownAuditSeqs) at the storage layer.
      this.enqueue(
        `INSERT INTO audit_events (team_id, agent_id, seq, ts, kind, detail,
                                   input_hash, prev, sig, hash, ingested_at, sig_verified)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (team_id, agent_id, seq) DO NOTHING`,
        [
          teamId,
          e.agentId,
          e.seq,
          e.ts,
          e.kind,
          JSON.stringify(e.detail),
          e.inputHash ?? null,
          e.prev,
          e.sig,
          e.hash,
          e._cloud.ingestedAt,
          e._cloud.sigVerified,
        ],
      );
    }
  }

  private readAuditEvents(teamId: string): StoredAuditEvent[] {
    return this.auditByTeam.get(teamId) ?? [];
  }

  queryAuditEvents(teamId: string, query: AuditQuery): StoredAuditEvent[] {
    let events = [...this.readAuditEvents(teamId)];
    if (query.agentId) events = events.filter((e) => e.agentId === query.agentId);
    if (query.kind) events = events.filter((e) => e.kind === query.kind);
    if (query.since) {
      const since = query.since;
      events = events.filter((e) => e.ts >= since);
    }
    // Most recent first — the operational view for the dashboard/SIEM triage.
    events = events.slice().reverse();
    const limit = query.limit ?? 200;
    return events.slice(0, Math.max(1, Math.min(limit, 1000)));
  }

  knownAuditSeqs(teamId: string, agentId: string): Set<number> {
    const seqs = new Set<number>();
    for (const e of this.readAuditEvents(teamId)) {
      if (e.agentId === agentId) seqs.add(e.seq);
    }
    return seqs;
  }

  activeAgentsInWindow(teamId: string, startIso: string, endIso: string): string[] {
    const active = new Set<string>();
    for (const e of this.readAuditEvents(teamId)) {
      if (e.ts >= startIso && e.ts < endIso) active.add(e.agentId);
    }
    return [...active].sort();
  }

  /**
   * M13 retention: drop every event with ts < cutoffIso (ISO-8601 strings
   * compare chronologically) across all teams. Returns the number removed.
   */
  purgeAuditEvents(cutoffIso: string): number {
    let removed = 0;
    for (const [teamId, events] of this.auditByTeam) {
      const kept = events.filter((e) => e.ts >= cutoffIso);
      if (kept.length !== events.length) {
        removed += events.length - kept.length;
        this.auditByTeam.set(teamId, kept);
      }
    }
    if (removed > 0) {
      this.enqueue(`DELETE FROM audit_events WHERE ts < $1`, [cutoffIso]);
    }
    return removed;
  }

  // --------------------------------------------------------- revocations
  addRevocation(revocation: Revocation): void {
    this.revocations.push(revocation);
    this.enqueue(
      `INSERT INTO revocations (team_id, agent_id, reason, ts) VALUES ($1, $2, $3, $4)`,
      [revocation.teamId, revocation.agentId, revocation.reason, revocation.ts],
    );
  }

  listRevocations(teamId: string, since?: string): Revocation[] {
    return this.revocations.filter(
      (r) => r.teamId === teamId && (since === undefined || r.ts > since),
    );
  }

  // ------------------------------------------------- approval decisions
  addApprovalDecision(decision: ApprovalDecision): void {
    // Idempotent per approvalId — a re-resolve never duplicates the record.
    const existing = this.approvalDecision(decision.teamId, decision.approvalId);
    if (existing) return;
    this.decisions.push(decision);
    this.enqueue(
      `INSERT INTO approval_decisions (team_id, approval_id, agent_id, decision,
                                       reason, ttl, decided_by, ts)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (team_id, approval_id) DO NOTHING`,
      [
        decision.teamId,
        decision.approvalId,
        decision.agentId,
        decision.decision,
        decision.reason ?? null,
        decision.ttl ?? null,
        decision.decidedBy,
        decision.ts,
      ],
    );
  }

  approvalDecision(teamId: string, approvalId: string): ApprovalDecision | undefined {
    return this.decisions.find(
      (d) => d.teamId === teamId && d.approvalId === approvalId,
    );
  }

  approvalDecisions(teamId: string, since?: string): ApprovalDecision[] {
    return this.decisions.filter(
      (d) => d.teamId === teamId && (since === undefined || d.ts > since),
    );
  }

  // --------------------------------------------------------- audit export
  allAuditEvents(teamId: string): StoredAuditEvent[] {
    return [...this.readAuditEvents(teamId)];
  }
}
