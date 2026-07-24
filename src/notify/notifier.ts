/**
 * Approval notifier (EPIC-08 H8.5) — tells the human, out of band, that an
 * approval request is waiting. Channel: a Slack-compatible incoming webhook
 * whose URL is stored in the vault (see notify/config.ts for the contract).
 *
 * Discipline:
 *   - FIRE-AND-FORGET: invoked without await from approvals.ts; delivery
 *     happens in the background. This function NEVER throws — a notifier
 *     failure must not break, delay, or (above all) grant an approval.
 *   - FAIL-CLOSED: if the webhook is down, misconfigured, or the vault ref is
 *     missing, the pending request simply follows its normal course and
 *     expires on its own. Nothing is ever granted by a notification outcome.
 *   - SILENT WHEN DISABLED: no notify.json (or enabled != true) → no-op with
 *     a debug log only, so agent output and tests stay quiet.
 *
 * The message deliberately shows the RAW capability, agent and reason —
 * unembellished, so the human sees exactly what was asked (EPIC-08 risks:
 * prompt injection with misleading justifications).
 */
import { Vault } from "../vault/vault.js";
import type { ApprovalRequest } from "../policy/approvals.js";
import {
  loadNotifyConfig,
  notifyDebug,
  notifyWarn,
} from "./config.js";
import { postSlackWebhook } from "./webhook.js";

/** Hard budget for the webhook POST (H8.5: timeouts must be bounded). */
export const NOTIFY_TIMEOUT_MS = 3_000;

/** Slack `text` for an approval request. Exported for tests. */
export function buildApprovalText(req: ApprovalRequest): string {
  const expiresInS = Math.max(0, Math.round((req.expiresAt - Date.now()) / 1000));
  return (
    `:rotating_light: *ScopeGate approval requested*\n` +
    `• agent: \`${req.agentId}\`\n` +
    `• capability: \`${req.capability}\`\n` +
    `• requested ttl: \`${req.ttl ?? "(none)"}\`\n` +
    (req.reason ? `• reason: ${req.reason}\n` : "") +
    `• request expires in ~${expiresInS}s\n` +
    `Approve from your terminal: \`scopegate approve ${req.id}\`\n` +
    `Deny: \`scopegate deny ${req.id} --reason "..."\``
  );
}

/**
 * Queue a notification for a freshly created approval request. Resolves once
 * delivery (or failure) settled; callers that want true fire-and-forget
 * invoke it without await and attach a .catch — although every error path
 * inside is already absorbed and only logged.
 */
export async function notifyApprovalRequested(
  req: ApprovalRequest,
): Promise<void> {
  try {
    const cfg = loadNotifyConfig();
    if (!cfg.enabled) {
      notifyDebug(`approval ${req.id}: notifications disabled — skipping`);
      return;
    }

    // M5: pluggable channels first (slack/webhook/huly), then the legacy
    // single-slack path (unchanged behavior for existing configs).
    if (cfg.notifiers && cfg.notifiers.length > 0) {
      const { dispatchApprovalEvent } = await import("./channels.js");
      await dispatchApprovalEvent(
        cfg.notifiers,
        {
          kind: "approval_requested",
          approval_id: req.id,
          agentId: req.agentId,
          capability: req.capability,
          ttl: req.ttl,
          reason: req.reason,
          expiresAt: req.expiresAt,
          ts: new Date().toISOString(),
        },
        buildApprovalText(req),
      );
    }

    if (!cfg.slackWebhookRef) {
      return;
    }

    // The webhook URL is a vault secret; only its ref name sits in config.
    let url: string;
    try {
      url = Vault.open().get(cfg.slackWebhookRef).trim();
    } catch (e) {
      notifyWarn(
        `approval ${req.id}: cannot read webhook URL from vault ref ` +
          `'${cfg.slackWebhookRef}' (${(e as Error).message}) — skipping`,
      );
      return;
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      notifyWarn(`approval ${req.id}: vault ref '${cfg.slackWebhookRef}' is not a URL — skipping`);
      return;
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      notifyWarn(
        `approval ${req.id}: webhook URL protocol '${parsed.protocol}' refused (http/https only)`,
      );
      return;
    }

    await postSlackWebhook(
      url,
      { text: buildApprovalText(req) },
      NOTIFY_TIMEOUT_MS,
    );
    notifyDebug(`approval ${req.id}: webhook notified`);
  } catch (e) {
    // Fail-closed and never fatal: the request lives on and expires alone.
    notifyWarn(
      `approval ${req.id}: webhook notification failed (${(e as Error).message}) — ` +
        `the request stays pending and will expire normally`,
    );
  }
}

/**
 * M5.3: push the DECISION back to the channels (the host resumes the paused
 * task the moment the human decides). Same fire-and-forget discipline.
 */
export async function notifyApprovalDecided(
  approvalId: string,
  agentId: string,
  capability: string,
  decision: "approved" | "denied",
  decidedBy: string,
): Promise<void> {
  try {
    const cfg = loadNotifyConfig();
    if (!cfg.enabled) return;
    const channels = cfg.notifiers ?? [];
    const slackRef = cfg.slackWebhookRef
      ? [{ type: "slack" as const, ref: cfg.slackWebhookRef }]
      : [];
    const all = [...channels, ...slackRef];
    if (all.length === 0) return;
    const { dispatchApprovalEvent, buildDecisionText } = await import("./channels.js");
    const event = {
      kind: "approval_decided" as const,
      approval_id: approvalId,
      agentId,
      capability,
      decision,
      decidedBy,
      ts: new Date().toISOString(),
    };
    await dispatchApprovalEvent(all, event, buildDecisionText(event));
  } catch (e) {
    notifyWarn(`approval ${approvalId}: decision notification failed (${(e as Error).message})`);
  }
}
