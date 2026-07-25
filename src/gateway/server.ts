/**
 * Agent-facing MCP server. The harness (Claude Code / Kimi Code) launches
 * this as its single MCP entry point over stdio (default); `--http` serves
 * the SAME server over Streamable HTTP (see ./http.ts) for networked
 * deployments.
 *
 * Request flow for a proxied tool call:
 *   0. Honeytoken checkpoint (EPIC-11): external canary sweep + fail-closed
 *      denial of EVERY request while the agent is suspended; then the
 *      cloud-revocation checkpoint (EPIC-10): same fail-closed denial while
 *      the agent is revoked from the fleet (cloud-revoked.json present).
 *   1. Map tool → capability '<upstream>:call:<tool>'
 *   2. Policy check: existing grant, or implicit auto-approve attempt
 *      (hard limits `deny` evaluated before any rule; require: human_approval
 *      creates a pending approval instead of a dead-end denial)
 *   3. Audit (input is hashed, never stored) — FAIL-CLOSED, see below
 *   4. Proxy call with credential injection + transparent retry
 *   5. Optional PII redaction of the response when the issuing rule carries
 *      `redact: [...]` (audit records replacement counts only)
 *
 * Error-handling contract (EPIC-01 H2):
 *   - Every handler exception becomes an MCP `isError` response with an
 *     actionable message. Stack traces NEVER reach the agent; they are
 *     logged to stderr for the human operator (stdout is the MCP channel).
 *   - Audit is fail-closed: an action that cannot be attributed must not
 *     happen. Startup aborts if audit.jsonl is not writable; at runtime an
 *     audit failure denies the action with an explicit error.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import crypto from "node:crypto";
import { secretRefsOf } from "../minter/minter.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  loadConfig,
  saveConfig,
  upsertUpstream,
  AUDIT_LOG_PATH,
  type ScopeGateConfig,
  type UpstreamConfig,
} from "../config/config.js";
import { Vault } from "../vault/vault.js";
import { PolicyEngine } from "../policy/engine.js";
import { redactToolResult } from "../policy/redact.js";
import { trackEvent } from "../telemetry/telemetry.js";
import { UpstreamProxy, log, errorMessage } from "./proxy.js";
import { MANAGEMENT_TOOLS } from "./tools.js";
import { classifyError } from "./errors.js";
import { isWriteTool } from "./side-effects.js";
import { readAuditEvents } from "../audit/verify.js";
import { taintOf, taintMode } from "./taint.js";
import {
  buildPreview,
  DEFAULT_MAX_INLINE_BYTES,
  getByPath,
  grepPayload,
  loadResult,
  payloadBytes,
  storeResult,
  unwrapMcpResult,
} from "./results.js";
import {
  queueIntent,
  latestIntentFor,
  resultFor,
  listApprovals,
  createApprovalRequest,
  checkDecision,
  type ApprovalIntent,
} from "../policy/approvals.js";
import { audit } from "../audit/log.js";
import {
  honeytokenCheckpoint,
  findCanaryRef,
  findCanaryRefsInText,
  respondCanaryTrigger,
} from "../honeytoken/honeytoken.js";
import { startCloudSync } from "../cloud/client/sync.js";
import { cloudRevocationCheckpoint } from "../cloud/client/revocation-sync.js";
import { loadRegistryManifest, manifestToUpstream } from "../registry/loader.js";
import { startHttpGateway, requireHttpToken, type HttpGatewayHandle } from "./http.js";

/** One-shot guard for the `first_tool_call` telemetry event (opt-in only). */
let firstToolCallTracked = false;

function text(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text:
          typeof payload === "string" ? payload : JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function err(message: string) {
  return { ...text(`ERROR: ${message}`), isError: true };
}

/** sha256 over the JSON of a result payload — what the audit records (never the payload). */
function hashResult(result: unknown): string {
  let serialized: string;
  try {
    serialized = JSON.stringify(result) ?? "null";
  } catch {
    serialized = "[unserializable]";
  }
  return crypto.createHash("sha256").update(serialized).digest("hex");
}

/**
 * Fail-closed audit: throws an actionable Error when the audit trail cannot
 * be written, so the enclosing handler denies the action instead of running
 * it unattributed.
 */
function auditOrThrow(
  agentId: string,
  kind: Parameters<typeof audit>[1],
  detail: Record<string, unknown>,
  input?: unknown,
): void {
  try {
    audit(agentId, kind, detail, input);
  } catch (e) {
    throw new Error(
      `Audit log unavailable (${errorMessage(e)}) — action denied (fail-closed). ` +
        `Check permissions on ${AUDIT_LOG_PATH}.`,
    );
  }
}

export interface GatewayOptions {
  /**
   * Transport to serve on. Default: "stdio" (the harness launches the
   * gateway as its MCP child). "http" serves the SAME agent-facing MCP
   * server over Streamable HTTP for networked deployments (Railway/Docker).
   */
  transport?: "stdio" | "http";
  /** HTTP listen port (transport "http"). 0 = ephemeral. Default 8080. */
  port?: number;
  /** HTTP bind host (transport "http"). Default 127.0.0.1. */
  host?: string;
}

/**
 * Boots the gateway and serves it. Resolves once the transport is up; in
 * http mode it also returns the handle (port + close) for tests — the CLI
 * ignores it.
 */
export async function runGateway(
  options: GatewayOptions = {},
): Promise<HttpGatewayHandle | void> {
  // Fail FAST in http mode — before spawning a single upstream: no bearer,
  // no network port. startHttpGateway re-checks (it is also a public API).
  if (options.transport === "http") requireHttpToken();
  const cfg = loadConfig();
  const vault = Vault.open();
  // Fail-closed first load: an INVALID policies.yaml aborts startup (the
  // gateway must never run with a policy set it cannot parse). Hot-reload
  // after boot keeps the last-good set instead (see startWatching).
  let policy: PolicyEngine;
  try {
    policy = PolicyEngine.load();
  } catch (e) {
    log(
      "error",
      `invalid policies.yaml — refusing to start (fail-closed): ${errorMessage(e)}`,
    );
    process.exit(1);
  }
  policy.startWatching();
  const agentId = process.env.SCOPEGATE_AGENT_ID ?? cfg.agentId;
  const proxy = new UpstreamProxy(cfg.upstreams, vault, {
    agentId,
    attestationDefault: cfg.attestation,
  });

  const status = await proxy.connectAll();
  // Fail-closed at startup: if the audit log is not writable, the gateway
  // must not serve a single unattributed call — abort with a clear message.
  try {
    audit(agentId, "gateway_start", { upstreams: status });
  } catch (e) {
    log(
      "error",
      `cannot write audit log at ${AUDIT_LOG_PATH} — aborting startup (fail-closed)`,
      { error: errorMessage(e) },
    );
    process.exit(1);
  }

  // EPIC-10: ScopeGate Cloud sync (management plane). LOCAL-FIRST: only
  // active when ~/.scopegate/cloud.json exists; every loop is background
  // and non-blocking, and a dead control plane leaves the gateway running
  // on local policy + the last signed team policy cache. Returns null when
  // the gateway is not enrolled (the OSS default).
  const cloudSync = startCloudSync({ policy, agentId });

  if (options.transport === "http") {
    // HTTP mode (Sprint 6): the SAME agent-facing MCP server, served over
    // Streamable HTTP. Bearer auth, /health and the SCOPEGATE_HTTP_LISTENING
    // line live in http.ts. Signal-driven shutdown closes the listener AND
    // runs the same cleanup as stdio mode.
    const handle = await startHttpGateway(
      {
        createAgentServer: (requestAgentId?: string) =>
          createAgentServer({ cfg, proxy, policy, vault, agentId: requestAgentId ?? agentId }),
        // M4: logical identities accepted on X-ScopeGate-Agent (policies
        // sections + the gateway default).
        allowedAgents: () => [agentId, ...policy.agentIds().filter((a) => a !== agentId)],
        connectedUpstreams: () =>
          Object.values(status).filter((s) => s.ok).length,
        // M12: readiness detail for /health (additive to the legacy count).
        readiness: () => {
          const circuits = proxy.circuitReport();
          const failed = Object.entries(circuits)
            .filter(([, c]) => c.state === "open")
            .map(([n]) => n);
          // `status` is the connectAll() snapshot taken at boot. An upstream
          // that connects later — or is respawned by the M2 proactive
          // refresh — stays `false` there forever, so /health kept reporting
          // it as failed while its tools answered fine (observed for 20h in
          // production). Trust the live cache when it has an entry; fall back
          // to the boot snapshot only for upstreams never seen since.
          const live = proxy.liveStatus();
          for (const [n, s] of Object.entries(status)) {
            const ok = live[n] ?? s.ok;
            if (!ok && !failed.includes(n)) failed.push(n);
          }
          const total = Math.max(Object.keys(circuits).length, Object.keys(status).length);
          return {
            upstreams_detail: { ok: Math.max(0, total - failed.length), failed },
            vault_mode: process.env.SCOPEGATE_VAULT_MODE ?? "auto",
            pending_approvals: listApprovals().filter((a) => a.effectiveStatus === "pending").length,
          };
        },
        // Write path for the human console. Its credential is separate
        // (SCOPEGATE_ADMIN_TOKEN) and the agent bearer is rejected there —
        // see gateway/admin.ts.
        admin: {
          vault,
          capabilities: () => ({
            active_grants: policy.activeGrants(agentId).map((g) => ({
              id: g.id,
              capability: g.capability,
              agent: agentId,
              expiresAt: g.expiresAt,
              remaining_seconds: Math.max(0, Math.round((g.expiresAt - Date.now()) / 1000)),
              ...(g.leaseId !== undefined ? { leaseId: g.leaseId } : {}),
            })),
            leases: policy.leasesForAgent(agentId).map((l) => ({
              lease_id: l.leaseId,
              goal: l.goal,
              expiresAt: l.deadlineMs,
            })),
          }),
          revokeCapability: (id: string) => {
            // Un id puede ser un grant o un lease; revocar el lease arrastra
            // sus grants (y sus delegaciones) por diseño de GrantStore.
            const lease = policy.leasesForAgent(agentId).find((l) => l.leaseId === id);
            if (lease !== undefined) {
              policy.revokeLease(agentId, id);
              return true;
            }
            const grant = policy.activeGrants(agentId).find((g) => g.id === id);
            if (grant === undefined) return false;
            policy.revokeGrantById(agentId, id);
            return true;
          },
          upstreamNames: () => cfg.upstreams.filter((u) => u.enabled !== false).map((u) => u.name),
          upstreamsUsingSecret: (ref: string) =>
            cfg.upstreams.filter((u) => secretRefsOf(u.auth).includes(ref)).map((u) => u.name),
          reload: async () => {
            // policy.startWatching() ya recarga el archivo solo; esto fuerza
            // el reintento de conexiones que fallaron por un secreto ausente,
            // que es justo lo que pasa al dar de alta una credencial nueva.
            await proxy.connectAll();
          },
        },
        // M12: metadata-only event tail for GET /events.
        recentEvents: ({ since, limit }) => {
          const sinceMs = since ? Date.parse(since) : Date.now() - 2 * 3600 * 1000;
          return readAuditEvents()
            .filter((e) => !Number.isNaN(sinceMs) && Date.parse(e.ts) >= sinceMs)
            .slice(-limit)
            .map((e) => ({
              ts: e.ts,
              kind: e.kind,
              agentId: e.agentId,
              ...(typeof e.detail.tool === "string" ? { tool: e.detail.tool } : {}),
              ...(typeof e.detail.capability === "string" ? { capability: e.detail.capability } : {}),
              ...(typeof e.detail.upstream === "string" ? { upstream: e.detail.upstream } : {}),
              ...(typeof e.detail.code === "string" ? { code: e.detail.code } : {}),
            }));
        },
        shutdown: async () => {
          cloudSync?.stop();
          policy.stopWatching();
          await proxy.closeAll();
        },
      },
      { port: options.port ?? 8080, host: options.host ?? "127.0.0.1" },
    );
    log(
      "info",
      `gateway up (http) · agent=${agentId} · upstreams=${JSON.stringify(status)}`,
    );
    return handle;
  }

  const server = createAgentServer({ cfg, proxy, policy, vault, agentId });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("info", `gateway up · agent=${agentId} · upstreams=${JSON.stringify(status)}`);

  const shutdown = async () => {
    cloudSync?.stop();
    policy.stopWatching();
    await proxy.closeAll();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

/**
 * The agent-facing MCP server (management tools + proxied upstream tools).
 * Transport-independent: stdio mode connects ONE instance; stateless http
 * mode builds a fresh instance per request over the same shared deps.
 * Exported for the embeddable library API (M7, src/api.ts).
 */
export function createAgentServer(deps: {
  cfg: ScopeGateConfig;
  proxy: UpstreamProxy;
  policy: PolicyEngine;
  vault: Vault;
  agentId: string;
}): Server {
  const { cfg, proxy, policy, vault, agentId } = deps;

  // Mejora #2 (approval continuation): the policy engine owns the approval
  // lifecycle; the proxy owns execution. This hook is the bridge — when an
  // approval materializes its grant, the queued intent runs HERE with the
  // remaining TTL of the covering grant (token_ttl clamp still applies) and
  // the outcome is audited (hash only, never the payload).
  policy.intentExecutor = async (intent: ApprovalIntent) => {
    const capability = intent.tool.includes("__")
      ? intent.tool.replace("__", ":call:")
      : intent.tool;
    const grant = policy.coveringGrant(intent.agentId, capability);
    const grantTtlMs = grant ? Math.max(0, grant.expiresAt - Date.now()) : undefined;
    const startedAt = Date.now();
    try {
      const result = await proxy.call(intent.tool, intent.args, { grantTtlMs });
      auditOrThrow(intent.agentId, "intent_executed", {
        approvalId: intent.approvalId,
        tool: intent.tool,
        status: "executed",
        durationMs: Date.now() - startedAt,
        resultHash: hashResult(result),
      });
      return { ok: true, result };
    } catch (e) {
      auditOrThrow(intent.agentId, "intent_executed", {
        approvalId: intent.approvalId,
        tool: intent.tool,
        status: "failed",
        durationMs: Date.now() - startedAt,
        error: errorMessage(e),
      });
      return { ok: false, error: errorMessage(e) };
    }
  };

  /**
   * Mejora #7: context-window protection. A proxied payload larger than
   * limits.max_inline_bytes (default 16 KiB) is persisted (AFTER policy
   * redaction, never before) and returned as preview + result_ref + stats.
   * The agent pages through it with scopegate_result_get/_grep.
   */
  const handleOversizedResult = (payload: unknown, toolName: string): ReturnType<typeof text> => {
    const maxInline = policy.maxInlineBytesFor(agentId) ?? DEFAULT_MAX_INLINE_BYTES;
    if (payloadBytes(payload) <= maxInline) return payload as ReturnType<typeof text>;
    const upstreamName = toolName.includes("__") ? toolName.split("__")[0] : "(unknown)";
    const stored = storeResult({
      agentId,
      upstream: upstreamName,
      tool: toolName,
      payload: unwrapMcpResult(payload),
    });
    auditOrThrow(agentId, "result_stored", {
      tool: toolName,
      upstream: upstreamName,
      ref: stored.ref,
      bytes: stored.bytes,
    });
    return text(buildPreview(stored));
  };

  /**
   * Mejora #10 (taint guard, enforce mode): a cross-upstream WRITE while the
   * agent's session is tainted degrades to needs_approval — never a hard
   * deny, always a human review of the exfil-shaped action. Returns the
   * approval when the gate fires, null otherwise.
   */
  const taintGate = (capability: string): { approvalId: string; expiresAt: number } | null => {
    if (taintMode() !== "enforce") return null;
    const rec = taintOf(agentId);
    if (!rec) return null;
    const parts = capability.split(":");
    if (parts.length < 3) return null;
    const [up, action, ...rest] = parts;
    // Only cross-upstream WRITES degrade; reads stay free (they caused the taint).
    const isWrite =
      action === "call" ? isWriteTool(up, rest.join(":")) : /^(write|deploy|delete|admin)/.test(action);
    if (!isWrite || up === rec.source) return null;
    const { request: ap } = createApprovalRequest({
      agentId,
      capability,
      ttl: null,
      reason:
        `[taint guard] cross-upstream write while the session is tainted by content from '${rec.source}' ` +
        `(score ${rec.score}, hits: ${rec.hits.join(", ")}). A human reviews this exfil-shaped action.`,
    });
    auditOrThrow(agentId, "approval_requested", {
      id: ap.id,
      capability,
      via: "taint_guard",
      taintSource: rec.source,
      score: rec.score,
      expiresAt: new Date(ap.expiresAt).toISOString(),
    });
    return { approvalId: ap.id, expiresAt: ap.expiresAt };
  };

  const server = new Server(
    { name: "scopegate", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  // M12: host observability — upstream state changes reach the harness as MCP
  // logMessage notifications (Kimi Code SDK surfaces them as events).
  // Fire-and-forget: a harness that ignores them changes nothing.
  proxy.onUpstreamEvent = (e) => {
    server
      .sendLoggingMessage({
        level: e.kind === "circuit_closed" ? "info" : "warning",
        logger: "scopegate",
        data: JSON.stringify(e),
      })
      .catch(() => {});
  };

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const proxied: Tool[] = proxy.listProxiedTools().map((t) => ({
      name: t.exposedName,
      description: t.description ?? `Proxied tool from upstream '${t.upstream}'`,
      inputSchema: t.inputSchema as Tool["inputSchema"],
    }));
    return { tools: [...MANAGEMENT_TOOLS, ...proxied] };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args = {} } = req.params;
    try {
      // EPIC-11 (honeytoken): fail-closed suspension gate + external canary
      // sweep. A suspended agent gets EVERY request denied until a human
      // clears the suspension (see src/honeytoken/honeytoken.ts header).
      const htGate = honeytokenCheckpoint(policy, agentId);
      if (htGate.suspended) {
        auditOrThrow(agentId, "capability_denied", {
          tool: name,
          code: "agent_suspended",
          reason: htGate.message,
        });
        return err(htGate.message ?? "Agent suspended.");
      }
      // EPIC-10: fleet-revocation gate. An agent revoked from the cloud gets
      // EVERY request denied (fail-closed) until a human removes
      // cloud-revoked.json. One mtime-cached stat per request; a no-op when
      // the gateway was never revoked (or never enrolled).
      const cloudGate = cloudRevocationCheckpoint(agentId);
      if (cloudGate.revoked) {
        auditOrThrow(agentId, "capability_denied", {
          tool: name,
          code: "agent_revoked_cloud",
          reason: cloudGate.message,
        });
        return err(cloudGate.message ?? "Agent revoked by ScopeGate Cloud.");
      }
      switch (name) {
        case "scopegate_request_capability": {
          const capability = String(args.capability ?? "");
          if (!capability) {
            return err(
              "Missing required argument 'capability' (e.g. 'github:write:org/repo'). Format: '<upstream>:<action>:<resource>'.",
            );
          }
          if (!args.reason) {
            return err(
              "Missing required argument 'reason' — a one-line justification recorded in the audit log.",
            );
          }
          // EPIC-11: a capability string mentioning a canary ref is a
          // honeytoken trigger — checked before any evaluation/rate limit.
          const htMention = findCanaryRefsInText(capability);
          if (htMention) {
            respondCanaryTrigger({
              policy,
              agentId,
              canary: htMention,
              vector: "request_capability",
              evidence: { capability },
            });
            return err(
              `Capability request denied: '${capability}' references honeytoken '${htMention.ref}'. ` +
                `This incident has been recorded and the operator alerted.`,
            );
          }
          // Anti-flood sliding window (H-04.7): checked before any evaluation.
          const rl = policy.checkRateLimit(agentId);
          if (!rl.allowed) {
            auditOrThrow(agentId, "capability_denied", {
              capability,
              reason: args.reason,
              decision: {
                allow: false,
                code: "capability_rate_limited",
                reason: rl.reason,
              },
            });
            return text({
              granted: false,
              code: "capability_rate_limited",
              reason: rl.reason,
              next_step:
                "Back off and retry after the rate window resets. Do NOT loop requests.",
            });
          }
          // Mejora #10: taint guard (enforce mode) — a cross-upstream write
          // while tainted degrades to human approval before any evaluation.
          const tg = taintGate(capability);
          if (tg) {
            return text({
              granted: false,
              status: "pending_human_approval",
              approval_id: tg.approvalId,
              approval_expires_at: new Date(tg.expiresAt).toISOString(),
              reason:
                "[taint guard] cross-upstream write while the session is tainted — a human reviews the exfil-shaped action.",
              next_step:
                "Ask the human to review the tainted content and approve (or scopegate deny). Never route around it.",
            });
          }
          const decision = policy.request(
            agentId,
            capability,
            args.ttl as string | undefined,
            String(args.reason),
            {
              leaseId:
                typeof args.lease_id === "string" && args.lease_id.length > 0
                  ? args.lease_id
                  : undefined,
            },
          );
          auditOrThrow(
            agentId,
            decision.allow
              ? "capability_request"
              : decision.code === "ceiling_blocked"
                ? "ceiling_blocked"
                : "capability_denied",
            { capability, reason: args.reason, decision },
          );
          if (decision.allow) {
            const leaseId = typeof args.lease_id === "string" && args.lease_id.length > 0
              ? args.lease_id
              : undefined;
            return text({
              granted: true,
              capability,
              expires_in_seconds: Math.round(decision.ttlMs / 1000),
              matched_rule: decision.rule,
              ...(leaseId ? { lease_id: leaseId, renewable: true } : {}),
            });
          }
          if (decision.escalation === "human_approval") {
            // M5 (native approvals): wait=true long-polls the human decision
            // inline (max 120s) instead of returning pending and forcing the
            // agent to re-call. On approval the grant materializes through the
            // normal idempotent re-request path — no parallel code path.
            if (args.wait === true) {
              const timeoutS = Math.min(
                Math.max(Number(args.timeout_s ?? 60) || 60, 1),
                120,
              );
              const approvalId = decision.approvalId!;
              const deadline = Date.now() + timeoutS * 1000;
              let outcome: "approved" | "denied" | "timeout" = "timeout";
              while (Date.now() < deadline) {
                const d = checkDecision(approvalId);
                if (d) {
                  outcome = d.decision === "approved" ? "approved" : "denied";
                  break;
                }
                await new Promise((r) => setTimeout(r, 500));
              }
              auditOrThrow(agentId, "approval_waited", {
                approvalId,
                capability,
                outcome,
                timeout_s: timeoutS,
              });
              if (outcome === "approved") {
                const leaseId =
                  typeof args.lease_id === "string" && args.lease_id.length > 0
                    ? args.lease_id
                    : undefined;
                const granted = policy.request(
                  agentId,
                  capability,
                  args.ttl as string | undefined,
                  String(args.reason),
                  { leaseId },
                );
                if (granted.allow) {
                  return text({
                    granted: true,
                    capability,
                    expires_in_seconds: Math.round(granted.ttlMs / 1000),
                    matched_rule: granted.rule,
                    via: "human_approval",
                    approval_id: approvalId,
                    ...(leaseId ? { lease_id: leaseId, renewable: true } : {}),
                  });
                }
                return text({
                  granted: false,
                  status: "approved_unmaterialized",
                  approval_id: approvalId,
                  reason: granted.reason,
                  next_step:
                    "The human approved but the grant did not materialize (policy may have changed). Re-call scopegate_request_capability with the SAME capability.",
                });
              }
              if (outcome === "denied") {
                return text({
                  granted: false,
                  status: "denied",
                  approval_id: approvalId,
                  reason: "A human denied this request.",
                  next_step:
                    "Do NOT retry the same capability. Ask the human what to change, or call scopegate_propose_policy with a narrower scope.",
                });
              }
              return text({
                granted: false,
                status: "approval_timeout",
                approval_id: approvalId,
                reason: `No human decision after ${timeoutS}s — the approval is still pending.`,
                next_step: `Re-call scopegate_request_capability with the SAME capability and wait:true to keep waiting, or ask the human to run: scopegate approve ${approvalId}`,
              });
            }
            // H-04.3: a pending request now exists in approvals.pending.jsonl.
            // Additive to the previous {granted:false, reason, next_step}
            // contract — older clients keep working.
            //
            // Mejora #2 (approval continuation): execute_on_approval queues
            // the intended call; when the human approves (CLI or panel), the
            // gateway executes it with the fresh grant and the agent collects
            // the outcome via scopegate_collect / scopegate_wait.
            let continuation: Record<string, unknown> | undefined;
            const eoa = args.execute_on_approval;
            if (eoa !== undefined) {
              const tool = typeof eoa === "object" && eoa !== null ? String((eoa as Record<string, unknown>).tool ?? "") : "";
              const eoaArgs = typeof eoa === "object" && eoa !== null && typeof (eoa as Record<string, unknown>).args === "object" && (eoa as Record<string, unknown>).args !== null
                ? (eoa as Record<string, unknown>).args as Record<string, unknown>
                : null;
              if (!tool || !eoaArgs) {
                return err(
                  "Invalid execute_on_approval — expected {tool: '<upstream>__<tool>', args: {...}}.",
                );
              }
              // The intent must be covered by the SAME approval: its capability
              // must match the requested one (no smuggling a different action).
              const intentCapability = tool.includes("__")
                ? tool.replace("__", ":call:")
                : tool;
              if (intentCapability !== capability) {
                return err(
                  `execute_on_approval rejected: the intent's capability '${intentCapability}' must equal the requested capability '${capability}' — a human approves exactly what they see.`,
                );
              }
              const intent = queueIntent({
                approvalId: decision.approvalId!,
                agentId,
                tool,
                args: eoaArgs,
                expiresAt: decision.approvalExpiresAt ?? Date.now() + 10 * 60 * 1000,
              });
              auditOrThrow(agentId, "intent_queued", {
                approvalId: intent.approvalId,
                tool: intent.tool,
                argsHash: intent.argsHash,
              });
              continuation = {
                queued: true,
                intent_id: intent.id,
                collect_with: `scopegate_collect {approval_id: "${intent.approvalId}"}`,
                wait_with: `scopegate_wait {approval_id: "${intent.approvalId}", timeout_s: 60}`,
              };
            }
            return text({
              granted: false,
              status: "pending_human_approval",
              approval_id: decision.approvalId,
              approval_expires_at: decision.approvalExpiresAt
                ? new Date(decision.approvalExpiresAt).toISOString()
                : undefined,
              reason: decision.reason,
              ...(continuation ? { continuation } : {}),
              instructions:
                `A human must approve this request. Ask them to run in their terminal: ` +
                `scopegate approve ${decision.approvalId} (or: scopegate deny ${decision.approvalId}). ` +
                (continuation
                  ? `On approval the queued intent executes automatically — collect it with scopegate_collect. `
                  : `Once approved, call scopegate_request_capability again with the SAME capability — ` +
                    `do NOT retry with broader scope.`),
              next_step: continuation
                ? "Wait for the human approval; the intent executes on approval — use scopegate_wait for short waits."
                : "Ask the human to approve this action, or wait for approval.",
            });
          }
          return text({
            granted: false,
            code: decision.code,
            reason: decision.reason,
            next_step:
              decision.code === "ceiling_blocked"
                ? "Hard limit hit — do NOT retry with broader scope. Ask a human to review policies.yaml."
                : "Call scopegate_propose_policy with a justification; a human will review it.",
          });
        }

        case "scopegate_request_capabilities": {
          // M15: batch request — ONE rate-limit evaluation for the whole
          // batch, per-item outcomes. No wait/continuation in batch mode.
          const reqs = Array.isArray(args.requests) ? args.requests : null;
          if (!reqs || reqs.length === 0) {
            return err(
              "Missing required argument 'requests' (non-empty array of {capability, reason?, ttl?, lease_id?}).",
            );
          }
          if (reqs.length > 20) return err("Batch too large — max 20 requests per call.");
          const rl = policy.checkRateLimit(agentId);
          if (!rl.allowed) {
            auditOrThrow(agentId, "capability_denied", {
              capability: "<batch>",
              reason: "batch request",
              decision: { allow: false, code: "capability_rate_limited", reason: rl.reason },
            });
            return text({
              granted: false,
              code: "capability_rate_limited",
              reason: rl.reason,
              next_step: "Back off and retry after the rate window resets. Do NOT loop requests.",
            });
          }
          const results: Record<string, unknown>[] = [];
          for (const item of reqs as Record<string, unknown>[]) {
            const capability = String(item?.capability ?? "");
            const reason =
              typeof item?.reason === "string" && item.reason ? item.reason : "batch request";
            if (!capability) {
              results.push({ capability: "", granted: false, code: "invalid", reason: "missing capability" });
              continue;
            }
            const htMention = findCanaryRefsInText(capability);
            if (htMention) {
              respondCanaryTrigger({
                policy,
                agentId,
                canary: htMention,
                vector: "request_capability",
                evidence: { capability },
              });
              results.push({
                capability,
                granted: false,
                code: "honeytoken",
                reason: `references honeytoken '${htMention.ref}' — incident recorded`,
              });
              continue;
            }
            const tg = taintGate(capability);
            if (tg) {
              results.push({
                capability,
                granted: false,
                status: "pending_human_approval",
                approval_id: tg.approvalId,
                reason: "[taint guard] cross-upstream write while the session is tainted.",
              });
              continue;
            }
            const leaseId =
              typeof item?.lease_id === "string" && item.lease_id.length > 0
                ? item.lease_id
                : undefined;
            const d = policy.request(
              agentId,
              capability,
              typeof item?.ttl === "string" ? item.ttl : undefined,
              reason,
              { leaseId },
            );
            auditOrThrow(
              agentId,
              d.allow ? "capability_request" : d.code === "ceiling_blocked" ? "ceiling_blocked" : "capability_denied",
              { capability, reason, decision: d, via: "batch" },
            );
            if (d.allow) {
              results.push({
                capability,
                granted: true,
                expires_in_seconds: Math.round(d.ttlMs / 1000),
                matched_rule: d.rule,
                ...(leaseId ? { lease_id: leaseId } : {}),
              });
            } else if (d.escalation === "human_approval") {
              results.push({
                capability,
                granted: false,
                status: "pending_human_approval",
                approval_id: d.approvalId,
                approval_expires_at: d.approvalExpiresAt
                  ? new Date(d.approvalExpiresAt).toISOString()
                  : undefined,
                reason: d.reason,
              });
            } else {
              results.push({ capability, granted: false, code: d.code, reason: d.reason });
            }
          }
          return text({
            results,
            granted: results.filter((r) => r.granted === true).length,
            total: results.length,
          });
        }

        case "scopegate_list_capabilities": {
          const grants = policy.activeGrants(agentId).map((g) => ({
            id: g.id,
            capability: g.capability,
            remaining_seconds: Math.max(
              0,
              Math.round((g.expiresAt - Date.now()) / 1000),
            ),
            ...(g.leaseId ? { lease_id: g.leaseId, renewable: true } : {}),
          }));
          const leases = policy.leasesForAgent(agentId).map((l) => ({
            lease_id: l.leaseId,
            goal: l.goal,
            status: l.status,
            deadline_at: new Date(l.deadlineMs).toISOString(),
            writes: { used: l.writesUsed, max: l.maxWrites },
          }));
          return text({ agentId, active_grants: grants, leases });
        }

        case "scopegate_open_task_lease": {
          // Mejora #1: open a task lease (double budget: total time + writes).
          const goal = String(args.goal ?? "").trim();
          if (!goal) return err("Missing required argument 'goal' — one line naming the task (lands in the audit log).");
          const upstreams = Array.isArray(args.upstreams)
            ? args.upstreams.filter((u): u is string => typeof u === "string" && u.length > 0)
            : [];
          let opened: ReturnType<typeof policy.openLease>;
          try {
            opened = policy.openLease(agentId, {
              goal,
              upstreams,
              max_total: typeof args.max_total === "string" ? args.max_total : undefined,
              max_writes: typeof args.max_writes === "number" ? args.max_writes : undefined,
            });
          } catch (e) {
            return err(errorMessage(e));
          }
          const { lease, clamped } = opened;
          return text({
            lease_id: lease.leaseId,
            goal: lease.goal,
            upstreams: lease.upstreams,
            total_ms: lease.totalMs,
            deadline_at: new Date(lease.deadlineMs).toISOString(),
            max_writes: lease.maxWrites,
            ...(clamped
              ? { clamped: true, note: "total clamped by limits.max_lease_total (the ceiling always wins)" }
              : {}),
            next_step:
              "Request capabilities with lease_id to bind them to this lease; renew them with scopegate_renew_capability before they die.",
          });
        }

        case "scopegate_renew_capability": {
          // Mejora #1: sliding-TTL renew for lease-covered grants.
          const grantId = String(args.grant_id ?? "");
          if (!grantId) return err("Missing required argument 'grant_id' (see scopegate_list_capabilities).");
          try {
            const renewed = policy.renewGrant(agentId, grantId);
            return text({
              renewed: true,
              grant_id: renewed.grantId,
              lease_id: renewed.leaseId,
              expires_at: new Date(renewed.expiresAt).toISOString(),
              expires_in_seconds: Math.max(0, Math.round((renewed.expiresAt - Date.now()) / 1000)),
            });
          } catch (e) {
            return err(errorMessage(e));
          }
        }

        case "scopegate_request_plan": {
          // Mejora #4: one task plan, one aggregated human decision.
          const goal = String(args.goal ?? "").trim();if (!goal) return err("Missing required argument 'goal' — one line naming the task (lands in the audit log).");
          const caps = Array.isArray(args.capabilities) ? args.capabilities : null;
          if (!caps || caps.length === 0) return err("Missing required argument 'capabilities' (non-empty array).");
          if (caps.length > 20) return err("Too many capabilities in one plan (max 20).");
          const items: { capability: string; ttl?: string }[] = [];
          for (const c of caps) {
            if (typeof c !== "object" || c === null) return err("Each plan item must be an object {capability, ttl?}.");
            const capability = String((c as Record<string, unknown>).capability ?? "");
            if (!capability) return err("Each plan item requires a non-empty 'capability' string.");
            const ttl = (c as Record<string, unknown>).ttl;
            items.push({ capability, ...(typeof ttl === "string" ? { ttl } : {}) });
          }
          try {
            const plan = policy.requestPlan(agentId, {
              goal,
              capabilities: items,
              open_lease: args.open_lease === true,
              max_total: typeof args.max_total === "string" ? args.max_total : undefined,
              max_writes: typeof args.max_writes === "number" ? args.max_writes : undefined,
            });
            return text({
              ...plan,
              ...(plan.pending
                ? {
                    instructions:
                      `The auto-approvable part is already granted. The rest is ONE aggregated approval: ` +
                      `ask the human to run scopegate approve ${plan.pending.approvalId} — on approval every bundled ` +
                      `capability is issued at once (your next request materializes them).`,
                  }
                : { instructions: "Everything in the plan was auto-approved — no human needed." }),
            });
          } catch (e) {
            return err(errorMessage(e));
          }
        }

        case "scopegate_delegate": {
          // Mejora #5: attenuated delegation to a child agent (subagent).
          const grantId = String(args.grant_id ?? "");
          const childId = String(args.child_agent_id ?? "");
          const scope = String(args.scope_subset ?? "");
          if (!grantId || !childId || !scope) {
            return err("Missing required arguments 'grant_id', 'child_agent_id' and 'scope_subset'.");
          }
          try {
            const delegated = policy.delegate(agentId, {
              grant_id: grantId,
              child_agent_id: childId,
              scope_subset: scope,
              ttl: typeof args.ttl === "string" ? args.ttl : undefined,
            });
            return text({
              delegated: true,
              child_grant_id: delegated.grantId,
              child_agent_id: delegated.childAgentId,
              capability: delegated.capability,
              expires_at: new Date(delegated.expiresAt).toISOString(),
              note: "The child grant is attenuated (subset + shorter ttl) and dies with the parent. The child sees it in its own scopegate_list_capabilities.",
            });
          } catch (e) {
            return err(errorMessage(e));
          }
        }

        case "scopegate_result_get": {
          // Mejora #7: slice a stored oversized payload by dot-path.
          const ref = String(args.ref ?? "");
          const path = String(args.path ?? "");
          if (!ref || !path) return err("Missing required arguments 'ref' and 'path'.");
          const stored = loadResult(ref, agentId);
          if (!stored) {
            return err(
              `Unknown or expired result_ref '${ref}' — refs live 2h and are per-agent. Re-run the tool call if you truly need it.`,
            );
          }
          const got = getByPath(stored.payload, path);
          if (!got.found) {
            return text({
              found: false,
              ref,
              path,
              note: "Path not present in the payload — adjust it (see the preview's stats.top_keys) instead of re-calling the tool.",
              top_keys:
                stored.payload !== null && typeof stored.payload === "object" && !Array.isArray(stored.payload)
                  ? Object.keys(stored.payload as Record<string, unknown>).slice(0, 20)
                  : undefined,
            });
          }
          return text({ found: true, ref, path, value: got.value });
        }

        case "scopegate_result_grep": {
          // Mejora #7: search a stored oversized payload.
          const ref = String(args.ref ?? "");
          const pattern = String(args.pattern ?? "");
          if (!ref || !pattern) return err("Missing required arguments 'ref' and 'pattern'.");
          const stored = loadResult(ref, agentId);
          if (!stored) {
            return err(
              `Unknown or expired result_ref '${ref}' — refs live 2h and are per-agent. Re-run the tool call if you truly need it.`,
            );
          }
          const hits = grepPayload(stored.payload, pattern);
          return text({ ref, pattern, count: hits.length, hits });
        }

        case "scopegate_register_upstream": {
          // EPIC-12: 1-click onboarding from the signed registry. The verified
          // manifest supplies name/transport/auth; from here on the flow is
          // IDENTICAL to a manual registration (same envelope validation, same
          // secretRef checks, same waiting_for_secrets contract).
          const fromRegistry =
            typeof args.from_registry === "string" && args.from_registry.trim()
              ? args.from_registry.trim()
              : undefined;
          let up: UpstreamConfig;
          const setupHints: Record<string, string> = {};
          if (fromRegistry) {
            let manifest;
            try {
              manifest = await loadRegistryManifest(fromRegistry);
            } catch (e) {
              // Fail-closed: an unverifiable registry registers NOTHING.
              auditOrThrow(agentId, "capability_denied", {
                action: "register_upstream",
                from_registry: fromRegistry,
                code: "registry_verification_failed",
                reason: errorMessage(e),
              });
              return err(
                `Registry entry '${fromRegistry}' could not be verified — nothing was registered (fail-closed): ${errorMessage(e)}`,
              );
            }
            up = manifestToUpstream(manifest);
            for (const s of manifest.setup?.secrets ?? []) setupHints[s.ref] = s.hint;
          } else {
            up = args as unknown as UpstreamConfig;
          }
          // Validate the envelope before touching config: a malformed entry
          // fails here with an actionable message, not later inside the proxy.
          if (!up.name || !/^[a-z0-9][a-z0-9_-]*$/i.test(up.name)) {
            return err(
              "Invalid or missing 'name'. Use lowercase letters, digits, '_' or '-' (e.g. 'github'). Tools are exposed as '<name>__<tool>'.",
            );
          }
          if (
            up.transport?.kind !== "http" &&
            up.transport?.kind !== "stdio" &&
            up.transport?.kind !== "openapi"
          ) {
            return err("Invalid or missing 'transport.kind' — must be 'http', 'stdio' or 'openapi'.");
          }
          if (up.transport.kind === "http" && !up.transport.url) {
            return err("Missing 'transport.url' for an http upstream.");
          }
          if (up.transport.kind === "stdio" && !up.transport.command) {
            return err("Missing 'transport.command' for a stdio upstream.");
          }
          if (up.transport.kind === "openapi" && !(up.transport as { spec?: string }).spec) {
            return err("Missing 'transport.spec' for an openapi upstream (https URL or local path to an OpenAPI 3 spec).");
          }
          // EPIC-11: a canary ref passed as a credential is a honeytoken
          // trigger — the decoy left the vault. Checked for every auth type
          // carrying a secretRef and for env mappings, before any other guard.
          const htRefs: string[] = [];
          if (up.auth && "secretRef" in up.auth && typeof up.auth.secretRef === "string") {
            htRefs.push(up.auth.secretRef);
          }
          if (up.auth?.type === "env") {
            htRefs.push(...Object.values(up.auth.env ?? {}));
          }
          for (const htRefValue of htRefs) {
            const htCanary = findCanaryRef(htRefValue);
            if (htCanary) {
              respondCanaryTrigger({
                policy,
                agentId,
                canary: htCanary,
                vector: "register_upstream",
                evidence: { upstream: up.name, ref: htRefValue },
              });
              return err(
                `Registration denied: '${htRefValue}' is a honeytoken. Using it as a credential means the decoy was exfiltrated. ` +
                  `This incident has been recorded and the operator alerted.`,
              );
            }
          }
          // Hard rule: never accept inline secrets, only refs.
          const missing: string[] = [];
          if (up.auth?.type === "bearer" || up.auth?.type === "oauth2") {
            if (!up.auth.secretRef) return err("auth.secretRef is required");
            if (looksLikeSecret(up.auth.secretRef)) {
              auditOrThrow(agentId, "capability_denied", {
                action: "register_upstream",
                name: up.name,
                code: "raw_secret_rejected",
              });
              return err(
                "secretRef looks like a raw secret value. Pass only a NAME; the human deposits the value with `scopegate secret add <name>`.",
              );
            }
            if (!vault.has(up.auth.secretRef)) missing.push(up.auth.secretRef);
          }
          if (up.auth?.type === "env") {
            for (const ref of Object.values(up.auth.env ?? {})) {
              if (looksLikeSecret(ref)) {
                auditOrThrow(agentId, "capability_denied", {
                  action: "register_upstream",
                  name: up.name,
                  code: "raw_secret_rejected",
                });
                return err(
                  `env value '${ref.slice(0, 8)}…' looks like a raw secret. Map ENV_VAR → secretRef NAME only.`,
                );
              }
              if (!vault.has(ref)) missing.push(ref);
            }
          }
          upsertUpstream(cfg, { ...up, enabled: true });
          saveConfig(cfg);
          auditOrThrow(agentId, "upstream_registered", {
            name: up.name,
            missing,
            ...(fromRegistry ? { from_registry: fromRegistry } : {}),
          });
          if (missing.length > 0) {
            return text({
              registered: up.name,
              status: "waiting_for_secrets",
              ...(fromRegistry ? { from_registry: fromRegistry } : {}),
              ...(fromRegistry
                ? {
                    setup_hints: Object.fromEntries(
                      missing.filter((r) => setupHints[r]).map((r) => [r, setupHints[r]]),
                    ),
                  }
                : {}),
              action_required: `Ask the human to run in their terminal: ${missing
                .map((r) => `scopegate secret add ${r}`)
                .join(" && ")}  — then call scopegate_diagnose.`,
            });
          }
          // Probe with a THROWAWAY proxy (the shared proxy picks the new
          // upstream up lazily on first call) and always close it, so no
          // half-open connection or spawned child process leaks.
          const probe = new UpstreamProxy([up], vault, { agentId });
          try {
            const diag = await probe.connectAll();
            // Quick win: tell the harness the tool list changed — new proxied
            // tools appear without an agent-session restart.
            void server.sendToolListChanged().catch(() => {});
            return text({ registered: up.name, connection: diag[up.name] });
          } finally {
            await probe.closeAll().catch(() => {});
          }
        }

        case "scopegate_diagnose": {
          const report = await proxy.diagnose();
          return text({ upstreams: report });
        }

        case "scopegate_propose_policy": {
          if (!args.match || !String(args.match).trim()) {
            return err(
              "Missing required argument 'match' — a capability glob, e.g. 'stripe:read:*'.",
            );
          }
          if (!args.justification || !String(args.justification).trim()) {
            return err(
              "Missing required argument 'justification' — a human reviews this proposal; explain why the capability is needed.",
            );
          }
          // propose_policy 2.0 (H-04.4): validation (glob/TTL/fields), dedup,
          // conflicts_with_limits lint. Rejections come back as tool errors.
          let proposal: { file: string; deduped: boolean; lint?: string };
          try {
            proposal = policy.proposePolicy(
              agentId,
              { match: String(args.match), ttl: args.ttl as string | undefined },
              String(args.justification),
            );
          } catch (e) {
            return err(errorMessage(e));
          }
          auditOrThrow(agentId, "policy_proposed", {
            match: args.match,
            deduped: proposal.deduped,
            ...(proposal.lint ? { lint: proposal.lint } : {}),
          });
          return text({
            queued: !proposal.deduped,
            deduped: proposal.deduped,
            pending_file: proposal.file,
            ...(proposal.lint
              ? {
                  lint: proposal.lint,
                  lint_note:
                    "This proposal conflicts with hard limits (deny glob or max_ttl). A human will see the flag during review.",
                }
              : {}),
            note: "A human must review and merge this into policies.yaml. It has NO effect until then.",
          });
        }

        case "scopegate_vault_status": {
          return text({ secret_refs: vault.listRefs() });
        }

        case "scopegate_inject_file": {
          // M10: governed secret materialization into files. The policy
          // engine's inverted default makes vault:inject:* escalate unless a
          // rule explicitly auto-approves it.
          const ref = String(args.ref ?? "");
          const out = String(args.out ?? "");
          if (!ref || !out) return err("Missing required arguments 'ref' and 'out'.");
          try {
            const { materializeSecret } = await import("../inject/inject.js");
            const res = await materializeSecret({
              ref,
              out,
              template: typeof args.template === "string" ? args.template : undefined,
              templateFile: typeof args.template_file === "string" ? args.template_file : undefined,
              agentId,
              policy,
            });
            if (res.status === "pending_human_approval") {
              return text({
                granted: false,
                status: "pending_human_approval",
                approval_id: res.approvalId,
                approval_expires_at: res.approvalExpiresAt
                  ? new Date(res.approvalExpiresAt).toISOString()
                  : undefined,
                reason: res.reason,
                instructions:
                  `A human must approve materializing this secret. Ask them to run: ` +
                  `scopegate approve ${res.approvalId} — then call scopegate_inject_file again with the SAME arguments.`,
              });
            }
            if (res.status === "denied") {
              return text({ granted: false, status: "denied", reason: res.reason });
            }
            return text({
              materialized: true,
              out: res.out,
              sha256: res.sha256,
              note: "Written 0600 (previous file backed up to <out>.bak). Re-run after rotation with: scopegate inject --refresh <out>.",
            });
          } catch (e) {
            return err(`inject failed: ${(e as Error).message}`);
          }
        }

        case "scopegate_upstream_health": {
          // Mejora #8: health as an MCP tool (diagnose lived CLI-side only) —
          // liveness + tool count + circuit-breaker state per upstream.
          const [diag, circuits] = await Promise.all([
            proxy.diagnose(),
            Promise.resolve(proxy.circuitReport()),
          ]);
          const upstreams: Record<string, unknown> = {};
          for (const [name, entry] of Object.entries(diag)) {
            upstreams[name] = { ...entry, circuit: circuits[name] ?? { state: "closed", failures: 0 } };
          }
          return text({ agentId, upstreams });
        }

        case "scopegate_can_i": {
          // Mejora #3: read-only policy preflight — NO side effects by design
          // (nothing issued, nothing queued, nothing audited).
          const capability = String(args.capability ?? "");
          if (!capability) {
            return err("Missing required argument 'capability' (e.g. 'github:write:org/repo').");
          }
          const evaluation = policy.evaluate(agentId, capability, args.ttl as string | undefined);
          const recommended_next =
            evaluation.decision === "allow"
              ? evaluation.covered_by_existing_grant
                ? "Proceed — a live grant already covers this; call the tool directly."
                : "Proceed — call scopegate_request_capability (or the tool directly)."
              : evaluation.decision === "needs_approval"
                ? "Plan for a human approval — request with execute_on_approval so the work completes on approval."
                : evaluation.hard
                  ? "Hard limit — do NOT attempt this in any form; only a human policy change would allow it."
                  : "Denied by policy — call scopegate_propose_policy with a justification, or pick another path.";
          return text({ capability, ...evaluation, recommended_next });
        }

        case "scopegate_policy_summary": {
          // Mejora #3: session-start digest for planning (read-only).
          return text(policy.policySummary(agentId));
        }

        case "scopegate_recall": {
          // Mejora #9: the agent's own audit as session memory — scoped to the
          // CALLING agentId only (you can never read another agent's trail).
          const sinceRaw = typeof args.since === "string" ? args.since : null;
          let sinceMs = Date.now() - 2 * 3600 * 1000;
          if (sinceRaw) {
            const parsed = Date.parse(sinceRaw);
            if (Number.isNaN(parsed)) return err(`Invalid 'since' (must be ISO 8601): ${sinceRaw}`);
            sinceMs = parsed;
          }
          const kindsFilter = Array.isArray(args.kinds)
            ? new Set(args.kinds.filter((k) => typeof k === "string"))
            : null;
          const limit = Math.min(Math.max(Number(args.limit ?? 50) || 50, 1), 200);

          const mine = readAuditEvents()
            .filter((e) => e.agentId === agentId)
            .filter((e) => Date.parse(e.ts) >= sinceMs)
            .filter((e) => (kindsFilter && kindsFilter.size > 0 ? kindsFilter.has(e.kind) : true));

          const recent = mine.slice(-limit).map((e) => ({
            ts: e.ts,
            kind: e.kind,
            ...(typeof e.detail.tool === "string" ? { tool: e.detail.tool } : {}),
            ...(typeof e.detail.capability === "string" ? { capability: e.detail.capability } : {}),
            ...(typeof e.detail.upstream === "string" ? { upstream: e.detail.upstream } : {}),
          }));
          const writes = mine
            .filter(
              (e) =>
                e.kind === "tool_call" &&
                typeof e.detail.tool === "string" &&
                e.detail.tool.includes("__") &&
                isWriteTool(
                  (e.detail.tool as string).split("__")[0],
                  (e.detail.tool as string).split("__").slice(1).join("__"),
                ),
            )
            .slice(-limit)
            .map((e) => ({ ts: e.ts, tool: e.detail.tool }));

          const activeGrants = policy.activeGrants(agentId).map((g) => ({
            id: g.id,
            capability: g.capability,
            remaining_seconds: Math.max(0, Math.round((g.expiresAt - Date.now()) / 1000)),
          }));
          const pendingApprovals = listApprovals()
            .filter((a) => a.agentId === agentId && a.effectiveStatus === "pending")
            .map((a) => ({
              approval_id: a.id,
              capability: a.capability,
              ttl: a.ttl,
              expires_at: new Date(a.expiresAt).toISOString(),
            }));

          return text({
            agentId,
            since: new Date(sinceMs).toISOString(),
            counts: { actions: mine.length, writes: writes.length, active_grants: activeGrants.length, pending_approvals: pendingApprovals.length },
            recent_actions: recent,
            writes,
            active_grants: activeGrants,
            pending_approvals: pendingApprovals,
          });
        }

        case "scopegate_events": {
          // M12: host-observability tail — metadata-only events (never args or
          // payloads), optionally filtered. The host renders these in its UI.
          const sinceRaw = typeof args.since === "string" ? args.since : null;
          let sinceMs = Date.now() - 2 * 3600 * 1000;
          if (sinceRaw) {
            const parsed = Date.parse(sinceRaw);
            if (Number.isNaN(parsed)) return err(`Invalid 'since' (must be ISO 8601): ${sinceRaw}`);
            sinceMs = parsed;
          }
          const kindsFilter = Array.isArray(args.kinds)
            ? new Set(args.kinds.filter((k) => typeof k === "string"))
            : null;
          const agentFilter = typeof args.agent === "string" && args.agent ? args.agent : null;
          const limit = Math.min(Math.max(Number(args.limit ?? 50) || 50, 1), 200);

          const events = readAuditEvents()
            .filter((e) => Date.parse(e.ts) >= sinceMs)
            .filter((e) => (agentFilter ? e.agentId === agentFilter : true))
            .filter((e) => (kindsFilter && kindsFilter.size > 0 ? kindsFilter.has(e.kind) : true))
            .slice(-limit)
            .map((e) => ({
              ts: e.ts,
              kind: e.kind,
              agentId: e.agentId,
              ...(typeof e.detail.tool === "string" ? { tool: e.detail.tool } : {}),
              ...(typeof e.detail.capability === "string" ? { capability: e.detail.capability } : {}),
              ...(typeof e.detail.upstream === "string" ? { upstream: e.detail.upstream } : {}),
              ...(typeof e.detail.code === "string" ? { code: e.detail.code } : {}),
            }));
          return text({
            since: new Date(sinceMs).toISOString(),
            count: events.length,
            events,
          });
        }

        case "scopegate_collect": {
          // Mejora #2: collect the outcome of an approval continuation.
          const approvalId = String(args.approval_id ?? "");
          if (!approvalId) return err("Missing required argument 'approval_id'.");
          // Trigger the engine's approval refresh: an approved request
          // materializes its grant and EXECUTES the queued intent here (fresh
          // mtime-checked reads — no cross-process watchers needed).
          const pendingIntent = latestIntentFor(approvalId);
          if (pendingIntent) {
            policy.isGranted(
              agentId,
              pendingIntent.tool.includes("__")
                ? pendingIntent.tool.replace("__", ":call:")
                : pendingIntent.tool,
            );
          }
          const result = resultFor(approvalId);
          if (result) {
            return text({
              status: result.status,
              approval_id: result.approvalId,
              tool: result.tool,
              executed_at: new Date(result.executedAt).toISOString(),
              duration_ms: result.durationMs,
              ...(result.status === "executed" ? { result: result.result } : { error: result.error }),
            });
          }
          const intent = latestIntentFor(approvalId);
          if (intent) {
            return text({
              status: intent.status === "queued" ? "pending" : intent.status,
              approval_id: approvalId,
              tool: intent.tool,
              queued_at: new Date(intent.createdAt).toISOString(),
              expires_at: new Date(intent.expiresAt).toISOString(),
            });
          }
          return text({
            status: "none",
            approval_id: approvalId,
            note: "No continuation intent exists for this approval_id (maybe it had no execute_on_approval, or the result expired).",
          });
        }

        case "scopegate_wait": {
          // Mejora #2: long-poll for short waits instead of turn-burning loops.
          const approvalId = String(args.approval_id ?? "");
          if (!approvalId) return err("Missing required argument 'approval_id'.");
          const timeoutS = Math.min(Math.max(Number(args.timeout_s ?? 60) || 60, 1), 120);
          const deadline = Date.now() + timeoutS * 1000;
          while (Date.now() < deadline) {
            // Trigger materialization/execution of the approval (if decided).
            const pendingIntent = latestIntentFor(approvalId);
            if (pendingIntent) {
              policy.isGranted(
                agentId,
                pendingIntent.tool.includes("__")
                  ? pendingIntent.tool.replace("__", ":call:")
                  : pendingIntent.tool,
              );
            }
            const result = resultFor(approvalId);
            if (result) {
              return text({
                status: result.status,
                approval_id: result.approvalId,
                tool: result.tool,
                executed_at: new Date(result.executedAt).toISOString(),
                duration_ms: result.durationMs,
                ...(result.status === "executed" ? { result: result.result } : { error: result.error }),
              });
            }
            const intent = latestIntentFor(approvalId);
            if (intent && intent.status === "expired") {
              return text({ status: "expired", approval_id: approvalId, tool: intent.tool });
            }
            await new Promise((r) => setTimeout(r, 500));
          }
          return text({
            status: "timeout",
            approval_id: approvalId,
            note: `No outcome after ${timeoutS}s. The approval is still pending — collect later with scopegate_collect, never abandon the task silently.`,
          });
        }

        default: {
          // Proxied upstream tool → enforce policy, audit, forward.
          const tool = proxy.resolve(name);
          if (!tool) return err(`Unknown tool '${name}'`);
          const capability = `${tool.upstream}:call:${tool.upstreamName}`;
          // Mejora #10: taint guard (enforce mode) — cross-upstream write
          // while tainted degrades to human approval.
          const tg = taintGate(capability);
          if (tg) {
            return text({
              granted: false,
              status: "pending_human_approval",
              approval_id: tg.approvalId,
              approval_expires_at: new Date(tg.expiresAt).toISOString(),
              reason:
                "[taint guard] cross-upstream write while the session is tainted — a human reviews the exfil-shaped action.",
              next_step:
                "Ask the human to review the tainted content and approve (or scopegate deny). Never route around it.",
            });
          }
          if (!policy.isGranted(agentId, capability, args as Record<string, unknown>)) {
            // Implicit request: succeeds only if an auto_approve rule matches.
            const d = policy.request(agentId, capability, undefined, "", {
              args: args as Record<string, unknown>,
            });
            if (!d.allow) {
              auditOrThrow(
                agentId,
                d.code === "ceiling_blocked" ? "ceiling_blocked" : "capability_denied",
                { capability, tool: name, reason: d.reason },
              );
              const hint =
                d.escalation === "human_approval" && d.approvalId
                  ? ` Approval request ${d.approvalId} is pending — ask the human to run: scopegate approve ${d.approvalId}`
                  : "";
              // Mejora #8: machine-readable envelope, same actionable message.
              return {
                ...text(
                  classifyError({
                    message: `Capability '${capability}' not granted. Call scopegate_request_capability first (or scopegate_propose_policy if denied). Reason: ${d.reason}${hint}`,
                    code: d.code === "no_rule" ? "missing_scope" : d.code,
                  }),
                ),
                isError: true,
              };
            }
          }
          auditOrThrow(agentId, "tool_call", { tool: name, upstream: tool.upstream }, args);
          // Remaining TTL of the covering grant → clamps any token the minter
          // mints for this call (token_ttl = min(provider ceiling, grant TTL)).
          // The same grant carries the redact categories of its issuing rule.
          const grant = policy.coveringGrant(agentId, capability, args as Record<string, unknown>);
          // Mejora #1: lease write budget — a lease-covered WRITE consumes one
          // unit of the task budget; exhausted (or dead) lease denies the call.
          if (grant?.leaseId && isWriteTool(tool.upstream, tool.upstreamName)) {
            if (!policy.consumeLeaseWrite(grant.leaseId)) {
              const msg =
                `Task lease write budget exhausted or lease dead (lease ${grant.leaseId}) — ` +
                `open a new lease with scopegate_open_task_lease, or ask a human to raise max_writes.`;
              auditOrThrow(agentId, "capability_denied", {
                tool: name,
                code: "lease_budget_exhausted",
                reason: msg,
              });
              return { ...text(classifyError({ message: msg, code: "policy_denied" })), isError: true };
            }
          }
          const grantTtlMs = grant
            ? Math.max(0, grant.expiresAt - Date.now())
            : undefined;
          const result = await proxy.call(name, args as Record<string, unknown>, {
            grantTtlMs,
          });
          // Opt-in telemetry (fire-and-forget): time to first successful tool
          // call is the north-star metric of the product plan (§7, < 90 s).
          if (!firstToolCallTracked) {
            firstToolCallTracked = true;
            trackEvent("first_tool_call", {
              latency_ms: Math.round(process.uptime() * 1000),
            });
          }
          // Mejora #1: structured <20%-TTL warning on lease-covered calls —
          // the agent renews BEFORE dying instead of learning from failure.
          if (
            grant?.leaseId &&
            result !== null &&
            typeof result === "object" &&
            Array.isArray((result as { content?: unknown[] }).content)
          ) {
            const remainingMs = grant.expiresAt - Date.now();
            const originalMs = Math.max(1, grant.expiresAt - grant.grantedAt);
            if (remainingMs / originalMs < 0.2) {
              (result as { content: unknown[] }).content.push({
                type: "text",
                text: JSON.stringify({
                  scopegate_notice: {
                    grant_id: grant.id,
                    expires_in_s: Math.max(0, Math.round(remainingMs / 1000)),
                    renewable: true,
                    hint: "Call scopegate_renew_capability {grant_id} BEFORE this grant dies — do not let the task fail mid-way.",
                  },
                }),
              });
            }
          }
          // H-04.6: redact PII in the RESPONSE when the issuing rule says so.
          // Applied here (policy layer), never inside proxy.ts; the audit
          // records replacement COUNTS only, never content.
          if (grant?.redact?.length) {
            const { result: redacted, counts } = redactToolResult(result, grant.redact);
            const total = Object.values(counts).reduce((a, b) => a + b, 0);
            if (total > 0) {
              auditOrThrow(agentId, "redaction_applied", {
                tool: name,
                upstream: tool.upstream,
                counts,
              });
            }
            return handleOversizedResult(redacted, name);
          }
          return handleOversizedResult(result as unknown, name);
        }
      }
    } catch (e) {
      // The agent gets a clean, actionable message — never a stack trace.
      // The full error (with stack) goes to stderr for the human operator.
      log("error", `tool call '${name}' failed: ${errorMessage(e)}`, {
        stack: e instanceof Error ? e.stack : undefined,
      });
      // Mejora #8: every failure is a machine-readable envelope — the agent
      // knows the kind and the recommended next action without parsing prose.
      return { ...text(classifyError({ message: errorMessage(e) })), isError: true };
    }
  });

  return server;
}

/**
 * Heuristic guard so agents can't smuggle raw secrets as "refs".
 * Exported for unit tests (EPIC-01 H1).
 */
export function looksLikeSecret(s: string): boolean {
  return (
    s.length > 40 ||
    /^(sk-|ghp_|gho_|xox[bap]-|AKIA|AIza|eyJ)/.test(s) ||
    /[A-Za-z0-9+/=]{32,}/.test(s)
  );
}
