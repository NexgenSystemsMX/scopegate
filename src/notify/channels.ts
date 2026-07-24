/**
 * Pluggable approval channels (M5): slack (legacy), generic HMAC-signed
 * webhook, and Huly (post into the channel/thread the user lives in).
 *
 * Delivery discipline (same as the legacy slack path): FIRE-AND-FORGET and
 * NEVER throwing — a channel failure must not break, delay, or grant an
 * approval. Every send is bounded (NOTIFY_TIMEOUT_MS) and best-effort.
 */
import crypto from "node:crypto";
import { Vault } from "../vault/vault.js";
import { Minter } from "../minter/minter.js";
import { NOTIFY_TIMEOUT_MS, buildApprovalText } from "./notifier.js";
import { notifyDebug, notifyWarn, type NotifyChannel } from "./config.js";
import { postSlackWebhook } from "./webhook.js";

export interface ApprovalEvent {
  kind: "approval_requested" | "approval_decided";
  approval_id: string;
  agentId: string;
  capability?: string;
  ttl?: string | null;
  reason?: string;
  expiresAt?: number;
  decision?: "approved" | "denied";
  decidedBy?: string;
  ts: string;
}

function vaultGet(ref: string): string | null {
  try {
    return Vault.open().get(ref).trim();
  } catch {
    return null;
  }
}

/** HMAC-SHA256 over the canonical event JSON (webhook authenticity). */
function signPayload(secret: string, body: string): string {
  return "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
}

async function postJson(url: string, body: string, headers: Record<string, string>): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NOTIFY_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body,
      signal: controller.signal,
    });
    if (!res.ok) notifyWarn(`webhook ${url} answered HTTP ${res.status}`);
  } finally {
    clearTimeout(timer);
  }
}

/** One channel delivery, best-effort. Never throws. */
async function deliver(channel: NotifyChannel, event: ApprovalEvent, text: string): Promise<void> {
  try {
    if (channel.type === "slack") {
      if (!channel.ref) return;
      const url = vaultGet(channel.ref);
      if (!url) {
        notifyWarn(`slack notifier: vault ref '${channel.ref}' unreadable — skipped`);
        return;
      }
      await postSlackWebhook(url, { text }, NOTIFY_TIMEOUT_MS);
      return;
    }

    if (channel.type === "webhook") {
      if (!channel.url) return;
      const body = JSON.stringify(event);
      const headers: Record<string, string> = {};
      if (channel.ref) {
        const secret = vaultGet(channel.ref);
        if (secret) headers["x-scopegate-signature"] = signPayload(secret, body);
      }
      await postJson(channel.url, body, headers);
      return;
    }

    if (channel.type === "huly") {
      if (!channel.ref || !channel.channel) return;
      const minter = new Minter(Vault.open());
      const res = await minter.resolve({
        name: "notify-huly",
        transport: { kind: "stdio", command: "huly-bridge" },
        auth: { type: "huly", secretRef: channel.ref },
      });
      if (!res) {
        notifyWarn(`huly notifier: no credential for ref '${channel.ref}' — skipped`);
        return;
      }
      const { createHulyClient } = await import("../upstreams/huly-bridge/client.js");
      const client = createHulyClient({
        HULY_TOKEN: res.cred.env?.HULY_TOKEN ?? "",
        HULY_ENDPOINT: res.cred.env?.HULY_ENDPOINT ?? "",
        HULY_WORKSPACE: res.cred.env?.HULY_WORKSPACE ?? "",
      } as NodeJS.ProcessEnv);
      await client.postMessage({ channel: channel.channel, message: text });
      return;
    }
  } catch (e) {
    notifyWarn(`notifier ${channel.type} delivery failed: ${(e as Error).message}`);
  }
}

/** Dispatch an approval event to every configured channel (best-effort). */
export async function dispatchApprovalEvent(
  channels: NotifyChannel[],
  event: ApprovalEvent,
  text: string,
): Promise<void> {
  await Promise.all(channels.map((c) => deliver(c, event, text)));
}

/** Slack-style text for a decision (approve/deny). */
export function buildDecisionText(event: ApprovalEvent): string {
  const icon = event.decision === "approved" ? ":white_check_mark:" : ":no_entry_sign:";
  return (
    `${icon} *ScopeGate approval ${event.decision}*\n` +
    `• approval: \`${event.approval_id}\`\n` +
    `• agent: \`${event.agentId}\`\n` +
    (event.capability ? `• capability: \`${event.capability}\`\n` : "") +
    `• decided by: \`${event.decidedBy}\``
  );
}

export { buildApprovalText, notifyDebug };
