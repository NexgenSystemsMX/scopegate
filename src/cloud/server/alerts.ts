/**
 * Approval & security alerts (EPIC-10, H10.6).
 *
 * When an ingested audit event is an `approval_requested`, and the team has
 * a Slack-compatible webhook configured (POST /v1/admin/alerts), the cloud
 * POSTs the human-approval prompt: what agent, what capability, why, and the
 * exact command to resolve it (`scopegate approve <id>`).
 *
 * Fire-and-forget BY DESIGN (same discipline as the gateway's notifier,
 * src/notify/webhook.ts — reused here): alerting NEVER blocks ingestion and
 * NEVER decides anything. A dead webhook means the approval request simply
 * lives out its TTL on the gateway — fail-closed, unchanged. Delivery
 * failures are swallowed; a one-line stderr note is the only trace.
 *
 * `AlertPoster` is injectable so tests can assert payloads without network.
 */
import { postSlackWebhook } from "../../notify/webhook.js";
import type { StoredAuditEvent, Team } from "./model.js";

export type AlertPoster = (webhookUrl: string, text: string) => Promise<void>;

const WEBHOOK_TIMEOUT_MS = 3000;

/** Default poster: Slack-compatible {"text": ...} with a hard 3 s timeout. */
export const slackPoster: AlertPoster = (webhookUrl, text) =>
  postSlackWebhook(webhookUrl, { text }, WEBHOOK_TIMEOUT_MS);

function firstString(
  detail: Record<string, unknown>,
  keys: string[],
): string | undefined {
  for (const k of keys) {
    const v = detail[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return undefined;
}

/** Human-readable Slack text for one approval_requested event. */
export function approvalAlertText(e: StoredAuditEvent): string {
  const d = e.detail;
  const id = firstString(d, ["id", "approvalId", "requestId"]) ?? "(unknown-id)";
  const capability = firstString(d, ["capability", "cap", "tool"]) ?? "(unknown)";
  const reason = firstString(d, ["reason"]) ?? "(no reason given)";
  return [
    `ScopeGate: approval requested`,
    `• agent:      ${e.agentId}`,
    `• capability: ${capability}`,
    `• reason:     ${reason}`,
    `• requested:  ${e.ts}`,
    `Resolve on the gateway:`,
    `  scopegate approve ${id}`,
    `  scopegate deny ${id} --reason "<why>"`,
  ].join("\n");
}

function chainGapAlertText(agentId: string, detail: Record<string, unknown>): string {
  return [
    `ScopeGate SECURITY: audit chain gap detected for agent ${agentId}`,
    `• expected prev: ${String(detail.expectedPrev ?? "unknown")}`,
    `• batch first seq: ${String(detail.batchFirstSeq ?? "unknown")}`,
    `A lost batch or log tampering — investigate the gateway.`,
  ].join("\n");
}

export interface Alerter {
  onAcceptedEvents(team: Team, events: StoredAuditEvent[]): void;
  onChainGap(team: Team, agentId: string, detail: Record<string, unknown>): void;
}

/**
 * Build the ingest hook that fans accepted events out to Slack. Synchronous
 * shell, async fire inside: POSTs are launched and their rejections absorbed
 * (`void …​.catch`), so ingest latency is never coupled to Slack's.
 */
export function makeSlackAlerter(poster: AlertPoster = slackPoster): Alerter {
  const fire = (team: Team, text: string): void => {
    const url = team.slackWebhookUrl;
    if (!url) return;
    void poster(url, text).catch((e: unknown) => {
      console.error(
        `[scopegate-cloud] alert delivery failed (team ${team.teamId}): ` +
          (e instanceof Error ? e.message : String(e)),
      );
    });
  };
  return {
    onAcceptedEvents(team, events) {
      for (const e of events) {
        if (e.kind === "approval_requested") fire(team, approvalAlertText(e));
      }
    },
    onChainGap(team, agentId, detail) {
      fire(team, chainGapAlertText(agentId, detail));
    },
  };
}
