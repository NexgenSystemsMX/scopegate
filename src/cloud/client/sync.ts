/**
 * ScopeGate Cloud — sync client orchestrator (EPIC-10, gateway side).
 *
 * startCloudSync() is the single entry point wired into the gateway
 * (gateway/server.ts). With no cloud.json it returns null and the gateway
 * is byte-for-byte the OSS build — LOCAL-FIRST is structural: every loop
 * here is background, unref'd, failure-tolerant (a dead control plane just
 * means "last-good cache + local policy") and stopped cleanly on shutdown.
 *
 * Loops started when enrolled:
 *   - policy-sync    (default 60 s, SCOPEGATE_CLOUD_SYNC_INTERVAL_MS)
 *   - audit-export   (default 10 s, SCOPEGATE_CLOUD_AUDIT_INTERVAL_MS)
 *   - revocation-sync(default 15 s, SCOPEGATE_CLOUD_REVOCATION_INTERVAL_MS)
 *
 * Each loop: immediate first tick (async, never blocking gateway startup),
 * chained unref'd setTimeout, in-flight guard, exponential backoff on
 * consecutive failures (capped at 8× the base interval).
 */
import type { PolicyEngine } from "../../policy/engine.js";
import {
  loadCloudConfig,
  type CloudConfig,
} from "./cloud-config.js";
import {
  loadVerifiedTeamPolicyCache,
  syncTeamPolicyOnce,
  DEFAULT_POLICY_SYNC_INTERVAL_MS,
} from "./policy-sync.js";
import {
  exportAuditOnce,
  DEFAULT_AUDIT_EXPORT_INTERVAL_MS,
} from "./audit-exporter.js";
import {
  syncRevocationsOnce,
  DEFAULT_REVOCATION_SYNC_INTERVAL_MS,
} from "./revocation-sync.js";

export interface CloudSyncIntervals {
  policyMs: number;
  auditMs: number;
  revocationMs: number;
}

export interface CloudSyncDeps {
  policy: PolicyEngine;
  /** This gateway's agentId (request-path identity). */
  agentId: string;
  /** Injectable for tests; defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Injectable intervals for tests/e2e (env vars win over defaults). */
  intervals?: Partial<CloudSyncIntervals>;
}

export interface CloudSyncHandle {
  readonly config: CloudConfig;
  stop(): void;
}

function envMs(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * Generic background loop: runs tick() immediately (fire-and-forget) and
 * re-arms itself with backoff on failure. Timers are unref'd — the sync
 * client never keeps the gateway process alive.
 */
function startLoop(
  name: string,
  baseIntervalMs: number,
  tick: () => Promise<unknown>,
): { stop: () => void } {
  let stopped = false;
  let inFlight = false;
  let failures = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const arm = (delayMs: number) => {
    if (stopped) return;
    timer = setTimeout(() => {
      timer = null;
      void run();
    }, delayMs);
    timer.unref?.();
  };

  const run = async () => {
    if (stopped || inFlight) return;
    inFlight = true;
    try {
      await tick();
      failures = 0;
    } catch (e) {
      failures += 1;
      console.error(
        `[scopegate cloud] warn: ${name} failed (${(e as Error).message}) — ` +
          `retrying in ${Math.round((baseIntervalMs * Math.min(2 ** failures, 8)) / 1000)}s ` +
          `(local-first: the gateway keeps operating)`,
      );
    } finally {
      inFlight = false;
      const backoff = failures === 0 ? 1 : Math.min(2 ** failures, 8);
      arm(baseIntervalMs * backoff);
    }
  };

  void run(); // first tick: immediate but async — startup never blocks
  return {
    stop: () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
    },
  };
}

/**
 * Start the cloud sync client when (and only when) this gateway is enrolled.
 * Boot order: apply the signed team policy cache (if it verifies), then arm
 * the three loops. Returns null when not enrolled or the config is corrupt.
 */
export function startCloudSync(deps: CloudSyncDeps): CloudSyncHandle | null {
  const cfg = loadCloudConfig();
  if (!cfg) return null;

  // Boot: last-good signed cache. Absent/invalid → local-only + warn
  // (local-first; the first successful policy tick installs the layer).
  const cached = loadVerifiedTeamPolicyCache(cfg.cloudPubkey);
  if (cached) {
    deps.policy.applyTeamPolicy(cached.policies, cached.meta);
    console.error(
      `[scopegate cloud] info: team policy v${cached.meta.version} applied from signed cache ` +
        `(fetched ${cached.meta.fetchedAt})`,
    );
  } else {
    console.error(
      "[scopegate cloud] info: no verified team policy cache — running local-only until first sync",
    );
  }

  const intervals: CloudSyncIntervals = {
    policyMs:
      deps.intervals?.policyMs ??
      envMs("SCOPEGATE_CLOUD_SYNC_INTERVAL_MS", DEFAULT_POLICY_SYNC_INTERVAL_MS),
    auditMs:
      deps.intervals?.auditMs ??
      envMs("SCOPEGATE_CLOUD_AUDIT_INTERVAL_MS", DEFAULT_AUDIT_EXPORT_INTERVAL_MS),
    revocationMs:
      deps.intervals?.revocationMs ??
      envMs("SCOPEGATE_CLOUD_REVOCATION_INTERVAL_MS", DEFAULT_REVOCATION_SYNC_INTERVAL_MS),
  };
  const fetchImpl = deps.fetchImpl;

  let revocationCursor: string | null = null;
  const loops = [
    startLoop("policy-sync", intervals.policyMs, () =>
      syncTeamPolicyOnce(cfg, deps.policy, { fetchImpl }),
    ),
    startLoop("audit-export", intervals.auditMs, () =>
      exportAuditOnce(cfg, { fetchImpl }),
    ),
    startLoop("revocation-sync", intervals.revocationMs, async () => {
      const r = await syncRevocationsOnce(cfg, deps.policy, deps.agentId, revocationCursor, {
        fetchImpl,
      });
      revocationCursor = r.lastSeen;
    }),
  ];

  console.error(
    `[scopegate cloud] info: sync started — team=${cfg.teamId} agent=${cfg.agentId} ` +
      `(policy ${intervals.policyMs}ms, audit ${intervals.auditMs}ms, revocations ${intervals.revocationMs}ms)`,
  );

  return {
    config: cfg,
    stop: () => {
      for (const l of loops) l.stop();
    },
  };
}
