/**
 * Slack-compatible outgoing webhook POST (EPIC-08 H8.5).
 *
 * Fire-and-forget by design: the caller (notifier.ts) absorbs every failure.
 * A dead webhook NEVER blocks the approval flow and NEVER grants anything —
 * the pending request simply lives out its TTL and expires (fail-closed).
 *
 * Payload is Slack incoming-webhook compatible: `{"text": "..."}`.
 * Uses the native fetch (Node 22) — no new dependencies.
 */

export interface SlackPayload {
  text: string;
}

/**
 * POST `payload` to `url` with a hard timeout. Resolves on any 2xx; throws
 * otherwise (HTTP error, network error, timeout) — the caller decides what a
 * failure means (for approvals: nothing, the request just expires).
 */
export async function postSlackWebhook(
  url: string,
  payload: SlackPayload,
  timeoutMs: number,
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`webhook POST failed with HTTP ${res.status}`);
    }
  } finally {
    clearTimeout(timer);
  }
}
