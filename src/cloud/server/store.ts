/**
 * ScopeGate Cloud persistence (EPIC-10, H10.1).
 *
 * DEV-GRADE BY DESIGN: JSON documents per aggregate + one append-only JSONL
 * audit file per team, all under <home>/data/. Writes are atomic (tmp +
 * rename) with mode 0600. Everything is held in memory and written through
 * on mutation — correct and simple at control-plane-for-a-team scale, NOT a
 * multi-tenant SaaS store.
 *
 * The `Store` interface is the swap point for the Postgres backend (M13,
 * pg-store.ts — teams/agents/policy_versions/audit_events/revocations/
 * approval_decisions): feature modules (enroll/ingest/policies/...) only
 * ever talk to `Store`, so replacing FileStore does not touch API code.
 *
 * Layout:
 *   <home>/data/teams.json         { teams: Team[] }
 *   <home>/data/agents.json        { agents: Agent[] }
 *   <home>/data/policies.json      { policies: PolicyVersion[] }   (all versions)
 *   <home>/data/revocations.json   { revocations: Revocation[] }
 *   <home>/data/audit-<teamId>.jsonl   StoredAuditEvent per line (append-only)
 */
import fs from "node:fs";
import path from "node:path";
import type {
  Agent,
  ApprovalDecision,
  AuditQuery,
  PolicyVersion,
  Revocation,
  StoredAuditEvent,
  Team,
} from "./model.js";

export interface Store {
  // teams
  createTeam(team: Team): void;
  getTeam(teamId: string): Team | undefined;
  findTeamByEnrollToken(enrollToken: string): Team | undefined;
  listTeams(): Team[];
  updateTeam(teamId: string, patch: Partial<Omit<Team, "teamId">>): Team | undefined;

  // agents
  upsertAgent(agent: Agent): void;
  getAgent(teamId: string, agentId: string): Agent | undefined;
  findAgentBySecretHash(secretHash: string): Agent | undefined;
  listAgents(teamId: string): Agent[];
  updateAgent(
    teamId: string,
    agentId: string,
    patch: Partial<Omit<Agent, "agentId" | "teamId">>,
  ): Agent | undefined;

  // policies (append-only version history)
  addPolicyVersion(policy: PolicyVersion): void;
  latestPolicy(teamId: string): PolicyVersion | undefined;
  policyVersions(teamId: string): PolicyVersion[];

  // audit (append-only JSONL per team)
  appendAuditEvents(teamId: string, events: StoredAuditEvent[]): void;
  queryAuditEvents(teamId: string, query: AuditQuery): StoredAuditEvent[];
  /** seqs already stored for an agent (dedupe key per EPIC-07 at-least-once). */
  knownAuditSeqs(teamId: string, agentId: string): Set<number>;
  /** Distinct agents with ≥1 stored event whose ts falls in [startIso, endIso). */
  activeAgentsInWindow(teamId: string, startIso: string, endIso: string): string[];

  // revocations
  addRevocation(revocation: Revocation): void;
  listRevocations(teamId: string, since?: string): Revocation[];

  // approval decisions (panel → gateway feed; idempotent per approvalId)
  addApprovalDecision(decision: ApprovalDecision): void;
  approvalDecision(teamId: string, approvalId: string): ApprovalDecision | undefined;
  approvalDecisions(teamId: string, since?: string): ApprovalDecision[];

  /** All stored events for a team in chronological (file) order — audit export. */
  allAuditEvents(teamId: string): StoredAuditEvent[];

  /**
   * M13 retention: drop every audit event with ts < cutoffIso across ALL
   * teams (ISO-8601 strings compare chronologically). Returns the number of
   * events removed. Invoked periodically by the server when
   * SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS is set — never on the request path.
   */
  purgeAuditEvents(cutoffIso: string): number;

  /**
   * M13: release store resources on server shutdown. PostgresStore flushes
   * the write-behind queue and ends the pool; FileStore has nothing to
   * release (no-op optional).
   */
  close?(): Promise<void> | void;
}

function readJsonFile<T>(file: string, fallback: T): T {
  if (!fs.existsSync(file)) return fallback;
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

function writeJsonFileAtomic(file: string, value: unknown): void {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export class FileStore implements Store {
  private readonly dataDir: string;
  private teams: Team[];
  private agents: Agent[];
  private policies: PolicyVersion[];
  private revocations: Revocation[];
  private decisions: ApprovalDecision[];

  constructor(
    home: string,
    private readonly opts: { auditRetentionDays?: number } = {},
  ) {
    this.dataDir = path.join(home, "data");
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.teams = readJsonFile(this.file("teams.json"), { teams: [] }).teams;
    this.agents = readJsonFile(this.file("agents.json"), { agents: [] }).agents;
    this.policies = readJsonFile(this.file("policies.json"), { policies: [] }).policies;
    this.revocations = readJsonFile(this.file("revocations.json"), {
      revocations: [],
    }).revocations;
    this.decisions = readJsonFile(this.file("approvals.json"), {
      decisions: [],
    }).decisions;
  }

  private file(name: string): string {
    return path.join(this.dataDir, name);
  }

  private auditFile(teamId: string): string {
    // teamId is server-generated ([A-Za-z0-9-]) — safe as a filename component.
    return path.join(this.dataDir, `audit-${teamId}.jsonl`);
  }

  // ------------------------------------------------------------- teams
  createTeam(team: Team): void {
    this.teams.push(team);
    writeJsonFileAtomic(this.file("teams.json"), { teams: this.teams });
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
    writeJsonFileAtomic(this.file("teams.json"), { teams: this.teams });
    return t;
  }

  // ------------------------------------------------------------ agents
  upsertAgent(agent: Agent): void {
    const i = this.agents.findIndex(
      (a) => a.teamId === agent.teamId && a.agentId === agent.agentId,
    );
    if (i >= 0) this.agents[i] = agent;
    else this.agents.push(agent);
    writeJsonFileAtomic(this.file("agents.json"), { agents: this.agents });
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
    writeJsonFileAtomic(this.file("agents.json"), { agents: this.agents });
    return a;
  }

  // ----------------------------------------------------------- policies
  addPolicyVersion(policy: PolicyVersion): void {
    this.policies.push(policy);
    writeJsonFileAtomic(this.file("policies.json"), { policies: this.policies });
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
    this.pruneAuditRetention(teamId);
    const lines = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
    fs.appendFileSync(this.auditFile(teamId), lines, { mode: 0o600 });
  }

  /**
   * 90-day audit retention (default; AUDIT_RETENTION_DAYS env, 0 disables):
   * events older than the cutoff are dropped. Amortized — the file is only
   * rewritten when at least one event is past retention.
   */
  private pruneAuditRetention(teamId: string): void {
    const days = this.opts.auditRetentionDays ?? 90;
    if (days <= 0) return;
    const cutoff = Date.now() - days * 86_400_000;
    const events = this.readAuditEvents(teamId);
    if (events.length === 0) return;
    const oldest = Date.parse(events[0].ts);
    if (Number.isNaN(oldest) || oldest >= cutoff) return;
    const kept = events.filter((e) => {
      const t = Date.parse(e.ts);
      return !Number.isNaN(t) && t >= cutoff;
    });
    const tmp = this.auditFile(teamId) + ".tmp";
    fs.writeFileSync(tmp, kept.map((e) => JSON.stringify(e)).join("\n") + (kept.length ? "\n" : ""), {
      mode: 0o600,
    });
    fs.renameSync(tmp, this.auditFile(teamId));
  }

  private readAuditEvents(teamId: string): StoredAuditEvent[] {
    const file = this.auditFile(teamId);
    if (!fs.existsSync(file)) return [];
    return fs
      .readFileSync(file, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as StoredAuditEvent);
  }

  queryAuditEvents(teamId: string, query: AuditQuery): StoredAuditEvent[] {
    let events = this.readAuditEvents(teamId);
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
   * M13 periodic retention (SCOPEGATE_CLOUD_AUDIT_RETENTION_DAYS): drop every
   * event with ts < cutoffIso across all teams, rewriting only the files that
   * actually shrink. Same drop semantics as the append-time prune above
   * (legacy AUDIT_RETENTION_DAYS) but an independent, server-driven trigger.
   */
  purgeAuditEvents(cutoffIso: string): number {
    let removed = 0;
    for (const entry of fs.readdirSync(this.dataDir)) {
      const m = /^audit-(.+)\.jsonl$/.exec(entry);
      if (!m) continue;
      const teamId = m[1];
      const events = this.readAuditEvents(teamId);
      if (events.length === 0) continue;
      const kept = events.filter((e) => e.ts >= cutoffIso);
      if (kept.length === events.length) continue;
      removed += events.length - kept.length;
      const tmp = this.auditFile(teamId) + ".tmp";
      fs.writeFileSync(
        tmp,
        kept.map((e) => JSON.stringify(e)).join("\n") + (kept.length ? "\n" : ""),
        { mode: 0o600 },
      );
      fs.renameSync(tmp, this.auditFile(teamId));
    }
    return removed;
  }

  // --------------------------------------------------------- revocations
  addRevocation(revocation: Revocation): void {
    this.revocations.push(revocation);
    writeJsonFileAtomic(this.file("revocations.json"), {
      revocations: this.revocations,
    });
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
    writeJsonFileAtomic(this.file("approvals.json"), {
      decisions: this.decisions,
    });
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
    return this.readAuditEvents(teamId);
  }
}
