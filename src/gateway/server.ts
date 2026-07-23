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
        createAgentServer: () =>
          createAgentServer({ cfg, proxy, policy, vault, agentId }),
        connectedUpstreams: () =>
          Object.values(status).filter((s) => s.ok).length,
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
 */
function createAgentServer(deps: {
  cfg: ScopeGateConfig;
  proxy: UpstreamProxy;
  policy: PolicyEngine;
  vault: Vault;
  agentId: string;
}): Server {
  const { cfg, proxy, policy, vault, agentId } = deps;
  const server = new Server(
    { name: "scopegate", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

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
          const decision = policy.request(
            agentId,
            capability,
            args.ttl as string | undefined,
            String(args.reason),
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
            return text({
              granted: true,
              capability,
              expires_in_seconds: Math.round(decision.ttlMs / 1000),
              matched_rule: decision.rule,
            });
          }
          if (decision.escalation === "human_approval") {
            // H-04.3: a pending request now exists in approvals.pending.jsonl.
            // Additive to the previous {granted:false, reason, next_step}
            // contract — older clients keep working.
            return text({
              granted: false,
              status: "pending_human_approval",
              approval_id: decision.approvalId,
              approval_expires_at: decision.approvalExpiresAt
                ? new Date(decision.approvalExpiresAt).toISOString()
                : undefined,
              reason: decision.reason,
              instructions:
                `A human must approve this request. Ask them to run in their terminal: ` +
                `scopegate approve ${decision.approvalId} (or: scopegate deny ${decision.approvalId}). ` +
                `Once approved, call scopegate_request_capability again with the SAME capability — ` +
                `do NOT retry with broader scope.`,
              next_step: "Ask the human to approve this action, or wait for approval.",
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

        case "scopegate_list_capabilities": {
          const grants = policy.activeGrants(agentId).map((g) => ({
            id: g.id,
            capability: g.capability,
            remaining_seconds: Math.max(
              0,
              Math.round((g.expiresAt - Date.now()) / 1000),
            ),
          }));
          return text({ agentId, active_grants: grants });
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
          if (up.transport?.kind !== "http" && up.transport?.kind !== "stdio") {
            return err("Invalid or missing 'transport.kind' — must be 'http' or 'stdio'.");
          }
          if (up.transport.kind === "http" && !up.transport.url) {
            return err("Missing 'transport.url' for an http upstream.");
          }
          if (up.transport.kind === "stdio" && !up.transport.command) {
            return err("Missing 'transport.command' for a stdio upstream.");
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

        default: {
          // Proxied upstream tool → enforce policy, audit, forward.
          const tool = proxy.resolve(name);
          if (!tool) return err(`Unknown tool '${name}'`);
          const capability = `${tool.upstream}:call:${tool.upstreamName}`;
          if (!policy.isGranted(agentId, capability)) {
            // Implicit request: succeeds only if an auto_approve rule matches.
            const d = policy.request(agentId, capability);
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
              return err(
                `Capability '${capability}' not granted. Call scopegate_request_capability first (or scopegate_propose_policy if denied). Reason: ${d.reason}${hint}`,
              );
            }
          }
          auditOrThrow(agentId, "tool_call", { tool: name, upstream: tool.upstream }, args);
          // Remaining TTL of the covering grant → clamps any token the minter
          // mints for this call (token_ttl = min(provider ceiling, grant TTL)).
          // The same grant carries the redact categories of its issuing rule.
          const grant = policy.coveringGrant(agentId, capability);
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
            return redacted as ReturnType<typeof text>;
          }
          return result as ReturnType<typeof text>;
        }
      }
    } catch (e) {
      // The agent gets a clean, actionable message — never a stack trace.
      // The full error (with stack) goes to stderr for the human operator.
      log("error", `tool call '${name}' failed: ${errorMessage(e)}`, {
        stack: e instanceof Error ? e.stack : undefined,
      });
      return err(errorMessage(e));
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
