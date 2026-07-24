/**
 * M5: pluggable approval channels (notify/channels.ts + notifier decisions).
 *
 *   - webhook channels POST the event JSON with an HMAC-SHA256 signature
 *     (x-scopegate-signature) when a vault ref is configured.
 *   - slack channels keep the legacy {text} payload against the vault-held
 *     webhook URL.
 *   - delivery is best-effort: a failing channel NEVER throws (the approval
 *     flow must not break because a notification endpoint is down).
 *   - notifyApprovalDecided pushes the decision to every configured channel.
 *
 * Every test gets a throwaway SCOPEGATE_HOME (helpers.ts); fetch is stubbed.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  vi.unstubAllGlobals();
  cleanupTempHome(home);
});

const EVENT = {
  kind: "approval_requested" as const,
  approval_id: "appr_123",
  agentId: "agent-x",
  capability: "github:write:easyorder/*",
  ttl: "10m",
  reason: "push the fix",
  ts: "2026-07-24T00:00:00.000Z",
};

describe("dispatchApprovalEvent", () => {
  it("webhook channel sends the event JSON with a valid HMAC signature", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("whsec", "topsecret");

    const calls: { url: string; headers: Record<string, string>; body: string }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: { headers: Record<string, string>; body: string }) => {
        calls.push({ url, headers: init.headers, body: init.body });
        return { ok: true, status: 200 };
      }),
    );

    const { dispatchApprovalEvent } = await import("../src/notify/channels.js");
    await dispatchApprovalEvent(
      [{ type: "webhook", url: "https://hook.test/approval", ref: "whsec" }],
      EVENT,
      "fallback text",
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://hook.test/approval");
    expect(JSON.parse(calls[0].body)).toMatchObject({
      kind: "approval_requested",
      approval_id: "appr_123",
    });
    const expected =
      "sha256=" +
      crypto.createHmac("sha256", "topsecret").update(calls[0].body).digest("hex");
    expect(calls[0].headers["x-scopegate-signature"]).toBe(expected);
  });

  it("slack channel posts the legacy {text} payload to the vault-held URL", async () => {
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("slack_url", "https://slack.test/hook");

    const calls: { url: string; body: string }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: { body: string }) => {
        calls.push({ url, body: init.body });
        return { ok: true, status: 200 };
      }),
    );

    const { dispatchApprovalEvent } = await import("../src/notify/channels.js");
    await dispatchApprovalEvent([{ type: "slack", ref: "slack_url" }], EVENT, "approval needed");

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://slack.test/hook");
    expect(JSON.parse(calls[0].body)).toEqual({ text: "approval needed" });
  });

  it("a failing channel never throws (fire-and-forget discipline)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("connection refused");
      }),
    );
    const { dispatchApprovalEvent } = await import("../src/notify/channels.js");
    await expect(
      dispatchApprovalEvent(
        [{ type: "webhook", url: "https://dead.test/hook" }],
        EVENT,
        "text",
      ),
    ).resolves.toBeUndefined();
  });
});

describe("buildDecisionText / notifyApprovalDecided", () => {
  it("decision text carries the decision, approval id and decider", async () => {
    const { buildDecisionText } = await import("../src/notify/channels.js");
    const text = buildDecisionText({
      ...EVENT,
      kind: "approval_decided",
      decision: "approved",
      decidedBy: "luis",
    });
    expect(text).toContain("approved");
    expect(text).toContain("appr_123");
    expect(text).toContain("luis");
    expect(text).toContain("github:write:easyorder/*");
  });

  it("notifyApprovalDecided dispatches to every configured channel from notify.json", async () => {
    fs.writeFileSync(
      path.join(home, "notify.json"),
      JSON.stringify({
        enabled: true,
        notifiers: [{ type: "webhook", url: "https://hook.test/decisions" }],
      }),
    );
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls.push(url);
        return { ok: true, status: 200 };
      }),
    );

    const { notifyApprovalDecided } = await import("../src/notify/notifier.js");
    await notifyApprovalDecided("appr_123", "agent-x", "github:write:easyorder/*", "denied", "luis");

    expect(calls).toEqual(["https://hook.test/decisions"]);
  });

  it("notifyApprovalDecided is a no-op when notifications are disabled", async () => {
    // No notify.json at all → disabled.
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { notifyApprovalDecided } = await import("../src/notify/notifier.js");
    await notifyApprovalDecided("appr_123", "agent-x", "cap", "approved", "luis");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
