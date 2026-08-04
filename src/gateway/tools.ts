/**
 * Management tools the AGENT itself uses to operate ScopeGate.
 * This is what makes the product agent-self-configurable.
 *
 * Hard rules encoded here:
 *   - register_upstream never accepts a secret value, only a secretRef.
 *     If the secret is missing, the agent is told to ask the HUMAN to run
 *     `scopegate secret add <ref>` (out-of-band, never through chat).
 *   - propose_policy writes to a pending file; it cannot change live policy.
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export const MANAGEMENT_TOOLS: Tool[] = [
  {
    name: "scopegate_request_capability",
    description:
      "Request an ephemeral capability for the current task. Format: '<upstream>:<action>:<resource>' (e.g. 'github:write:easyorder/*'). Returns a grant with TTL if policy auto-approves; status 'pending_human_approval' (with an approval_id) when a human must approve — poll the SAME capability afterwards, never a broader one. Hard limits (deny globs, max_ttl) are non-negotiable. Request the MINIMUM scope and the SHORTEST ttl that completes the task. Optional: pass execute_on_approval {tool, args} (tool's capability must equal the requested one) and the call executes automatically the moment the human approves — collect it with scopegate_collect or scopegate_wait. QM keychain options: `mode: 'once'` issues a single-use grant (consumed atomically by the first authorized call — a second call is denied 'used'); `audience` asks for a grant usable by ANOTHER declared agent (always escalates to human approval; 'org' is admin-only); `purpose` is a DECLARATIVE instruction recorded on the grant and in the audit — it is NOT enforced by the engine.",
    inputSchema: {
      type: "object",
      properties: {
        capability: { type: "string", description: "Capability string, e.g. 'github:write:easyorder/*'" },
        ttl: { type: "string", description: "Requested TTL like '5m', '15m', '1h'. Policy ceiling always wins." },
        reason: { type: "string", description: "One-line justification (goes to the audit log)." },
        mode: {
          type: "string",
          enum: ["once", "standing"],
          description: "Optional keychain mode (default 'standing'): 'once' = the grant authorizes EXACTLY ONE call, consumed atomically at authorization time.",
        },
        audience: {
          type: "string",
          description: "Optional grantee audience: another declared agentId that may USE the grant (never auto-approved — a human always decides). 'org' is reserved to the admin surface.",
        },
        purpose: {
          type: "string",
          description: "Optional declarative purpose — instruction to the model + audit field. NOT enforceable (defaults to `reason`).",
        },
        execute_on_approval: {
          type: "object",
          description: "Optional continuation: {tool: '<upstream>__<tool>', args: {...}} to execute automatically when the human approves. The tool's capability must equal the requested capability.",
          properties: {
            tool: { type: "string" },
            args: { type: "object", additionalProperties: true },
          },
          required: ["tool", "args"],
        },
        wait: {
          type: "boolean",
          description: "Optional: when the request escalates to human approval, block (long-poll) until the human decides or timeout_s elapses — returns the granted capability inline on approval. Prefer this over re-calling in a loop.",
        },
        timeout_s: {
          type: "number",
          description: "Max seconds to wait when wait=true (default 60, max 120).",
        },
      },
      required: ["capability", "reason"],
    },
  },
  {
    name: "scopegate_request_capabilities",
    description:
      "Batch version of scopegate_request_capability (M15): request several capabilities in ONE call (max 20) with a single rate-limit evaluation. Each item gets its own outcome — granted, pending_human_approval (with approval_id), or denied with reason. No wait/execute_on_approval in batch mode — use the single-call form for those.",
    inputSchema: {
      type: "object",
      properties: {
        requests: {
          type: "array",
          description: "Max 20 items.",
          items: {
            type: "object",
            properties: {
              capability: { type: "string" },
              ttl: { type: "string" },
              reason: { type: "string" },
              lease_id: { type: "string" },
            },
            required: ["capability"],
          },
        },
      },
      required: ["requests"],
    },
  },
  {
    name: "scopegate_collect",
    description:
      "Collect the outcome of an approval continuation (execute_on_approval). Returns {status: pending|executed|failed|expired|none, result?|error?} — call it after the human approves; never abandon a queued intent silently.",
    inputSchema: {
      type: "object",
      properties: {
        approval_id: { type: "string", description: "The approval_id returned by scopegate_request_capability." },
      },
      required: ["approval_id"],
    },
  },
  {
    name: "scopegate_wait",
    description:
      "Long-poll (up to timeout_s, max 120) for an approval continuation outcome. Prefer this over polling loops that burn turns. Returns the same shape as scopegate_collect, or {status: 'timeout'} when the approval is still pending.",
    inputSchema: {
      type: "object",
      properties: {
        approval_id: { type: "string", description: "The approval_id returned by scopegate_request_capability." },
        timeout_s: { type: "number", description: "Max seconds to wait (default 60, max 120)." },
      },
      required: ["approval_id"],
    },
  },
  {
    name: "scopegate_inject_file",
    description:
      "Materialize a vault secret into a file (legacy CLI configs — governed exception). Capability vault:inject:<ref> requires human approval BY DEFAULT (a policy rule must explicitly auto_approve it). Atomic 0600 write with backup; the rendered content's sha256 is audited, never the value. Prefer direct vault-backed flows whenever the tool supports them.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string", description: "Vault secretRef to materialize." },
        out: { type: "string", description: "Destination file path (written 0600, atomically)." },
        template: { type: "string", description: "Inline template containing {{secret}}. Omit for the raw secret." },
        template_file: { type: "string", description: "Path to a template file containing {{secret}} (wins over template)." },
      },
      required: ["ref", "out"],
    },
  },
  {
    name: "scopegate_upstream_health",
    description:
      "Health of every upstream as a machine-readable report: liveness, tool count, oauth state, and circuit-breaker state (closed|open|half_open with consecutive failure counts). Use it before deciding to retry a failing call.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "scopegate_can_i",
    description:
      "Read-only policy preflight: would this capability be allowed right now? Returns {decision: allow|needs_approval|deny, rule?, via?, ttl_ms?, code?, reason} with NO side effects (nothing issued, nothing queued, nothing audited). Use it to plan a task instead of learning from denials.",
    inputSchema: {
      type: "object",
      properties: {
        capability: { type: "string", description: "Capability string, e.g. 'github:write:easyorder/*'" },
        ttl: { type: "string", description: "Optional TTL to evaluate the effective clamp (e.g. '15m')." },
      },
      required: ["capability"],
    },
  },
  {
    name: "scopegate_delegate",
    description:
      "Delegate one of YOUR live grants to a child agent (subagent) with strict attenuation: scope_subset must be covered by the parent grant's capability and ttl must not exceed the parent's remaining TTL (any widening is refused fail-closed). The child grant carries the parent chain — revoking the parent kills every child.",
    inputSchema: {
      type: "object",
      properties: {
        grant_id: { type: "string", description: "Your live grant id (see scopegate_list_capabilities)." },
        child_agent_id: { type: "string", description: "The child agent's id (its SCOPEGATE_AGENT_ID) — must differ from yours." },
        scope_subset: { type: "string", description: "Capability covered by the parent grant (never broader)." },
        ttl: { type: "string", description: "Optional TTL like '15m' — must not exceed the parent's remaining TTL." },
      },
      required: ["grant_id", "child_agent_id", "scope_subset"],
    },
  },
  {
    name: "scopegate_request_plan",
    description:
      "Submit a whole task plan at once: auto-approvable capabilities are issued immediately, denials are reported, and every needs_approval capability is bundled into ONE aggregated human approval (blast radius visible as a single item). Set open_lease: true to bind the whole plan to a new task lease (mejora #1).",
    inputSchema: {
      type: "object",
      properties: {
        goal: { type: "string", description: "One line — the task this plan covers (lands in the audit log)." },
        capabilities: {
          type: "array",
          description: "The capabilities the task needs (max 20).",
          items: {
            type: "object",
            properties: {
              capability: { type: "string" },
              ttl: { type: "string" },
            },
            required: ["capability"],
          },
        },
        open_lease: { type: "boolean", description: "Also open a task lease and bind every grant of this plan to it." },
        max_total: { type: "string", description: "Lease total (with open_lease), clamped by limits.max_lease_total." },
        max_writes: { type: "number", description: "Lease write budget (with open_lease)." },
      },
      required: ["goal", "capabilities"],
    },
  },
  {
    name: "scopegate_result_get",
    description:
      "Read a slice of a stored oversized result (result_ref from a truncated response) by dot-path, e.g. 'content.0.text' or 'items.3.title'. Returns {found, value} — adjust the path instead of re-calling the tool.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string", description: "The result_ref (r-...)." },
        path: { type: "string", description: "Dot-path into the payload." },
      },
      required: ["ref", "path"],
    },
  },
  {
    name: "scopegate_result_grep",
    description:
      "Search a stored oversized result by substring or /regex/. Returns matching lines with their path (max 50) — context-sized by design.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string", description: "The result_ref (r-...)." },
        pattern: { type: "string", description: "Plain substring or /regex/ (with optional flags)." },
      },
      required: ["ref", "pattern"],
    },
  },
  {
    name: "scopegate_open_task_lease",
    description:
      "Open a task lease for long-running work: a double budget — total time (clamped by the hard limits.max_lease_total ceiling, default 4h) and write count (default 200). While the lease lives, renew your grants yourself with scopegate_renew_capability instead of dying mid-task. Request capabilities with lease_id to bind them; revoking the lease revokes every bound grant at once.",
    inputSchema: {
      type: "object",
      properties: {
        goal: { type: "string", description: "One line — the task this lease covers (lands in the audit log)." },
        upstreams: { type: "array", items: { type: "string" }, description: "Upstream names the lease is scoped to (empty = all)." },
        max_total: { type: "string", description: "Requested total duration like '2h' — clamped by limits.max_lease_total (default 4h, the ceiling always wins)." },
        max_writes: { type: "number", description: "Write budget for the task (default 200)." },
      },
      required: ["goal", "upstreams"],
    },
  },
  {
    name: "scopegate_renew_capability",
    description:
      "Renew a lease-covered grant (sliding TTL): new expiry = min(now + original ttl, lease deadline, rule ceilings). Auto-approved while the lease lives — call it BEFORE the grant dies (proxied responses warn you at <20% TTL).",
    inputSchema: {
      type: "object",
      properties: {
        grant_id: { type: "string", description: "The grant id from scopegate_list_capabilities." },
      },
      required: ["grant_id"],
    },
  },
  {
    name: "scopegate_policy_summary",
    description:
      "Your policy digest for session-start planning: which capability globs auto-approve, which require human approval, the hard-limit deny globs, and every ceiling (max_ttl, approval_ttl, rate_limit) plus the team-policy layer when installed. Read-only.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "scopegate_recall",
    description:
      "Your session memory: a scoped view of YOUR OWN signed audit trail — recent actions, writes effected, active grants with remaining TTL, and pending approvals. Use it after a restart or context compaction to reconstruct state instead of re-reading or repeating work. Only your agentId is visible.",
    inputSchema: {
      type: "object",
      properties: {
        since: { type: "string", description: "ISO 8601 lower bound (e.g. '2026-07-23T00:00:00Z'). Default: last 2 hours." },
        kinds: { type: "array", items: { type: "string" }, description: "Optional audit-kind filter (e.g. ['tool_call','grant_issued'])." },
        limit: { type: "number", description: "Max actions returned (default 50, max 200)." },
      },
    },
  },
  {
    name: "scopegate_events",
    description:
      "Host-observability tail (M12): recent gateway events as metadata ({ts, kind, agentId, upstream?, capability?, code?} — never payloads) for the host UI: capabilities denied, approvals requested/decided, upstream failures, grants, leases. Filter by since/kinds/agent. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        since: { type: "string", description: "ISO 8601 lower bound. Default: last 2 hours." },
        kinds: { type: "array", items: { type: "string" }, description: "Optional audit-kind filter (e.g. ['capability_denied','approval_requested'])." },
        agent: { type: "string", description: "Optional agentId filter (default: every identity on this gateway)." },
        limit: { type: "number", description: "Max events returned (default 50, max 200)." },
      },
    },
  },
  {
    name: "scopegate_list_capabilities",
    description:
      "List the currently active (non-expired) capability grants usable by this agent, with remaining TTL. QM keychain fields included when present: mode ('standing'|'once'), audience (grantee — 'org' means org-wide), purpose (declarative instruction, NOT enforced), status, used_by for consumed once grants, and held_by when another identity holds the grant for you.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "scopegate_revoke_capability",
    description:
      "Give up one of YOUR live grants before it expires (privilege attenuation — never needs approval). The cascade kills every descendant: delegated child grants and org promotions die with it. You can only revoke grants you HOLD; anything else requires the admin console.",
    inputSchema: {
      type: "object",
      properties: {
        grant_id: { type: "string", description: "Your live grant id (see scopegate_list_capabilities)." },
      },
      required: ["grant_id"],
    },
  },
  {
    name: "scopegate_register_upstream",
    description:
      "Register a new upstream MCP server or API behind the gateway. NEVER pass secret values here — only a secretRef name. If the vault is missing that secret, the response will instruct you to ask the human to deposit it via `scopegate secret add <ref>` in their terminal (out of band). New proxied tools appear after reconnect. Prefer the 1-click path when available: pass ONLY `from_registry` with a name from the signed ScopeGate registry (e.g. 'github', 'aws', 'notion', 'supabase', 'stripe') and name/transport/auth are taken from its verified manifest.",
    inputSchema: {
      type: "object",
      properties: {
        from_registry: {
          type: "string",
          description:
            "1-click onboarding: name of a pre-configured upstream in the signed ScopeGate registry (e.g. 'github'). When set, name/transport/auth come from the verified registry manifest — omit them. Fail-closed: a tampered or unknown registry entry is rejected.",
        },
        name: { type: "string", description: "Unique upstream name (lowercase, no spaces). Tools are exposed as '<name>__<tool>'. Required unless from_registry is set." },
        transport: {
          type: "object",
          description: "Either {kind:'http', url}, {kind:'stdio', command, args?} or {kind:'openapi', spec} (OpenAPI 3 spec URL/path — one governed tool per operation).",
          properties: {
            kind: { type: "string", enum: ["http", "stdio", "openapi"] },
            url: { type: "string" },
            spec: { type: "string" },
            command: { type: "string" },
            args: { type: "array", items: { type: "string" } },
          },
          required: ["kind"],
        },
        auth: {
          type: "object",
          description:
            "Auth spec. bearer: {type:'bearer', secretRef, header?, scheme?} | env: {type:'env', env:{ENV_VAR: secretRef}} | none: {type:'none'}",
          properties: {
            type: { type: "string", enum: ["none", "bearer", "env", "oauth2"] },
            secretRef: { type: "string" },
            header: { type: "string" },
            scheme: { type: "string" },
            env: { type: "object", additionalProperties: { type: "string" } },
          },
          required: ["type"],
        },
      },
      // No `required` here: either {from_registry} OR {name, transport, auth}
      // — the server validates the envelope and returns actionable errors.
    },
  },
  {
    name: "scopegate_diagnose",
    description:
      "Health-check every upstream connection (liveness + tool count). Use this to self-repair: a failing upstream is reconnected automatically on next call.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "scopegate_propose_policy",
    description:
      "Propose a new policy rule when a needed capability is denied. The proposal is validated (compilable glob, parseable ttl, only {match, ttl} are agent-settable), deduplicated, linted against hard limits, and queued for HUMAN review in policies.pending.yaml — it never takes effect on its own. Include a clear justification.",
    inputSchema: {
      type: "object",
      properties: {
        match: { type: "string", description: "Capability glob, e.g. 'stripe:read:*'" },
        ttl: { type: "string", description: "Suggested TTL ceiling, e.g. '10m'" },
        justification: { type: "string" },
      },
      required: ["match", "justification"],
    },
  },
  {
    name: "scopegate_vault_status",
    description:
      "List secret REF NAMES present in the vault (never values) so you can tell which secretRefs are available when registering upstreams.",
    inputSchema: { type: "object", properties: {} },
  },
];
