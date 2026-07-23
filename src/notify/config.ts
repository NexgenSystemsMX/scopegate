/**
 * Notifier configuration (EPIC-08) — `~/.scopegate/notify.json`.
 *
 * This file is OWNED by the notify subsystem (no other component reads or
 * writes it). Shape:
 *
 *   { "slackWebhookRef"?: string, "enabled"?: boolean }
 *
 * SECURITY CONTRACT: the Slack webhook URL is a secret (anyone who knows it
 * can post to the channel). It therefore lives ONLY in the encrypted vault,
 * under the vault key named by `slackWebhookRef` — never in plaintext here or
 * in any other config file. A ref that looks like a raw URL is rejected.
 *
 * A missing/corrupt/disabled file is a SILENT no-op (debug-logged): the
 * approval flow never depends on notifications being delivered (fail-closed).
 */
import fs from "node:fs";
import path from "node:path";
import { SCOPEGATE_DIR } from "../config/config.js";

export const NOTIFY_CONFIG_PATH = path.join(SCOPEGATE_DIR, "notify.json");

export interface NotifyConfig {
  enabled: boolean;
  /** Vault secretRef holding the webhook URL. Undefined when disabled. */
  slackWebhookRef?: string;
}

/** Debug log, gated on SCOPEGATE_LOG_LEVEL=debug (same convention as vault). */
export function notifyDebug(msg: string): void {
  if ((process.env.SCOPEGATE_LOG_LEVEL ?? "").toLowerCase() === "debug") {
    console.error(`[scopegate] notify: ${msg}`);
  }
}

export function notifyWarn(msg: string): void {
  console.error(`[scopegate] notify: warn: ${msg}`);
}

/**
 * Load the notifier config. Never throws: anything short of a well-formed,
 * explicitly-enabled file resolves to `{ enabled: false }`.
 */
export function loadNotifyConfig(): NotifyConfig {
  let raw: string;
  try {
    raw = fs.readFileSync(NOTIFY_CONFIG_PATH, "utf8");
  } catch {
    notifyDebug(`no config at ${NOTIFY_CONFIG_PATH} — notifications disabled`);
    return { enabled: false };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    notifyWarn(
      `cannot parse ${NOTIFY_CONFIG_PATH} (${(e as Error).message}) — notifications disabled`,
    );
    return { enabled: false };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    notifyWarn(`${NOTIFY_CONFIG_PATH} must be a JSON object — notifications disabled`);
    return { enabled: false };
  }
  const cfg = parsed as { enabled?: unknown; slackWebhookRef?: unknown };
  if (cfg.enabled !== true) {
    notifyDebug("enabled != true — notifications disabled");
    return { enabled: false };
  }
  if (typeof cfg.slackWebhookRef !== "string" || !cfg.slackWebhookRef.trim()) {
    notifyWarn(
      `enabled but no 'slackWebhookRef' in ${NOTIFY_CONFIG_PATH} — notifications disabled. ` +
        `Store the webhook URL in the vault (scopegate secret add slack_webhook_url) ` +
        `and reference it by name.`,
    );
    return { enabled: false };
  }
  const ref = cfg.slackWebhookRef.trim();
  if (/^https?:\/\//i.test(ref)) {
    notifyWarn(
      `'slackWebhookRef' in ${NOTIFY_CONFIG_PATH} looks like a RAW URL — refused. ` +
        `The webhook URL is a secret: deposit it in the vault and keep only the ref name here.`,
    );
    return { enabled: false };
  }
  return { enabled: true, slackWebhookRef: ref };
}
