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
      "Request an ephemeral capability for the current task. Format: '<upstream>:<action>:<resource>' (e.g. 'github:write:easyorder/*'). Returns a grant with TTL if policy auto-approves; status 'pending_human_approval' (with an approval_id) when a human must approve — poll the SAME capability afterwards, never a broader one. Hard limits (deny globs, max_ttl) are non-negotiable. Request the MINIMUM scope and the SHORTEST ttl that completes the task.",
    inputSchema: {
      type: "object",
      properties: {
        capability: { type: "string", description: "Capability string, e.g. 'github:write:easyorder/*'" },
        ttl: { type: "string", description: "Requested TTL like '5m', '15m', '1h'. Policy ceiling always wins." },
        reason: { type: "string", description: "One-line justification (goes to the audit log)." },
      },
      required: ["capability", "reason"],
    },
  },
  {
    name: "scopegate_list_capabilities",
    description:
      "List the currently active (non-expired) capability grants for this agent, with remaining TTL.",
    inputSchema: { type: "object", properties: {} },
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
          description: "Either {kind:'http', url} or {kind:'stdio', command, args?}",
          properties: {
            kind: { type: "string", enum: ["http", "stdio"] },
            url: { type: "string" },
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
