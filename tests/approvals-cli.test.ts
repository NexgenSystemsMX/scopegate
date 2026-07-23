/**
 * EPIC-08 unit tests: the human approval CLI (approve/deny + guard),
 * the policies PR-style CLI (review/accept/reject) and the webhook notifier.
 */
import fs from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanupTempHome, useTempHome } from "./helpers.js";

let home: string;

beforeEach(() => {
  home = useTempHome();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  cleanupTempHome(home);
});

async function newRequest(opts: { ttl?: string | null } = {}) {
  const { createApprovalRequest } = await import("../src/policy/approvals.js");
  return createApprovalRequest({
    agentId: "agent-a",
    capability: "github:write:repo",
    ttl: opts.ttl === undefined ? "10m" : opts.ttl,
    reason: "push fix",
  }).request;
}

async function decisionsRaw(): Promise<string> {
  const { APPROVALS_DECISIONS_PATH } = await import("../src/policy/approvals.js");
  return fs.existsSync(APPROVALS_DECISIONS_PATH)
    ? fs.readFileSync(APPROVALS_DECISIONS_PATH, "utf8")
    : "";
}

async function auditEntries(): Promise<Array<{ kind: string; detail: Record<string, unknown> }>> {
  const { AUDIT_LOG_PATH } = await import("../src/config/config.js");
  if (!fs.existsSync(AUDIT_LOG_PATH)) return [];
  return fs
    .readFileSync(AUDIT_LOG_PATH, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));
}

const ENGINE_POLICIES = {
  version: 1 as const,
  agents: {
    "agent-a": {
      default_ttl: "15m",
      capabilities: [
        { match: "github:write:*", require: "human_approval" as const, ttl: "10m" },
      ],
    },
  },
};

/* ------------------------------------------------------------------------ */
/* Human guard                                                               */
/* ------------------------------------------------------------------------ */

describe("human guard (TTY or SCOPEGATE_APPROVAL_TOKEN)", () => {
  it("rejects a non-TTY process without the token, with an actionable message", async () => {
    const { assertHumanOrigin } = await import("../src/commands/approvals-cli.js");
    delete process.env.SCOPEGATE_APPROVAL_TOKEN;
    expect(() => assertHumanOrigin()).toThrow(/human-only/);
    expect(() => assertHumanOrigin()).toThrow(/SCOPEGATE_APPROVAL_TOKEN/);
  });

  it("accepts the token as origin 'token'", async () => {
    const { assertHumanOrigin } = await import("../src/commands/approvals-cli.js");
    process.env.SCOPEGATE_APPROVAL_TOKEN = "e2e-token";
    try {
      expect(assertHumanOrigin()).toBe("token");
    } finally {
      delete process.env.SCOPEGATE_APPROVAL_TOKEN;
    }
  });

  it("accepts an interactive TTY as origin 'tty'", async () => {
    const { assertHumanOrigin } = await import("../src/commands/approvals-cli.js");
    delete process.env.SCOPEGATE_APPROVAL_TOKEN;
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    try {
      expect(assertHumanOrigin()).toBe("tty");
    } finally {
      Object.defineProperty(process.stdin, "isTTY", { value: undefined, configurable: true });
    }
  });
});

/* ------------------------------------------------------------------------ */
/* approve / deny                                                            */
/* ------------------------------------------------------------------------ */

describe("approveRequest / denyRequest", () => {
  it("approve writes the decision with the CLI origin and is idempotent", async () => {
    const { approveRequest } = await import("../src/commands/approvals-cli.js");
    const req = await newRequest();
    const res = approveRequest({ id: req.id, origin: "token" });
    expect(res.decision.decision).toBe("approved");
    expect(res.decision.decidedBy).toBe("human:cli:token");
    expect(res.alreadyDecided).toBe(false);

    const again = approveRequest({ id: req.id, origin: "tty" });
    expect(again.alreadyDecided).toBe(true);
    expect(again.decision.decidedBy).toBe("human:cli:token"); // first decision wins
    expect((await decisionsRaw()).trim().split("\n")).toHaveLength(1);
  });

  it("deny requires --reason and writes a denied decision", async () => {
    const { denyRequest } = await import("../src/commands/approvals-cli.js");
    const req = await newRequest();
    expect(() => denyRequest({ id: req.id, reason: "  ", origin: "tty" })).toThrow(/--reason/);
    const res = denyRequest({ id: req.id, reason: "too risky", origin: "tty" });
    expect(res.decision.decision).toBe("denied");
    expect(res.decision.decidedBy).toBe("human:cli:tty");
  });

  it("rejects unknown ids and expired requests", async () => {
    const { approveRequest } = await import("../src/commands/approvals-cli.js");
    const { APPROVALS_PENDING_PATH, readPendingRequests } = await import(
      "../src/policy/approvals.js"
    );
    expect(() =>
      approveRequest({ id: "00000000-0000-0000-0000-000000000000", origin: "token" }),
    ).toThrow(/Unknown approval id/);

    const req = await newRequest();
    // Age the request beyond its expiry (as if 10 minutes had passed).
    const lines = readPendingRequests().map((r) => ({
      ...r,
      expiresAt: r.id === req.id ? Date.now() - 1 : r.expiresAt,
    }));
    fs.writeFileSync(
      APPROVALS_PENDING_PATH,
      lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
      { mode: 0o600 },
    );
    expect(() => approveRequest({ id: req.id, origin: "token" })).toThrow(/expired/);
  });

  it("--ttl can only SHORTEN the requested TTL and the engine honors the shortened value", async () => {
    const { approveRequest } = await import("../src/commands/approvals-cli.js");
    const { readPendingRequests } = await import("../src/policy/approvals.js");
    const { PolicyEngine } = await import("../src/policy/engine.js");

    // Extending is refused.
    const r1 = await newRequest();
    expect(() => approveRequest({ id: r1.id, ttl: "30m", origin: "token" })).toThrow(
      /SHORTEN/,
    );
    // Garbage is refused by the engine's own strict parser.
    expect(() => approveRequest({ id: r1.id, ttl: "soon", origin: "token" })).toThrow(
      /Invalid --ttl/,
    );

    // Shortening lands on the pending line and the materialized grant.
    approveRequest({ id: r1.id, ttl: "3m", origin: "token" });
    expect(readPendingRequests().find((r) => r.id === r1.id)?.ttl).toBe("3m");

    const engine = new PolicyEngine(ENGINE_POLICIES);
    const d = engine.request("agent-a", "github:write:repo", "10m", "push fix");
    expect(d.allow).toBe(true);
    const grants = engine.activeGrants("agent-a");
    expect(grants).toHaveLength(1);
    expect(grants[0].expiresAt - grants[0].grantedAt).toBe(3 * 60_000);

    // A request without an asked TTL accepts any valid --ttl (it shortens ∞).
    const r2 = await newRequest({ ttl: null });
    const res2 = approveRequest({ id: r2.id, ttl: "1m", origin: "token" });
    expect(res2.effectiveTtl).toBe("1m");
  });
});

/* ------------------------------------------------------------------------ */
/* policies review / accept / reject                                         */
/* ------------------------------------------------------------------------ */

describe("policies PR-style flow", () => {
  const POLICIES_YAML_WITH_COMMENT =
    "# human-owned file — keep this comment\n" +
    "version: 1\n" +
    "agents:\n" +
    "  agent-a:\n" +
    "    capabilities:\n" +
    "      - match: \"existing:rule:*\"\n" +
    "        auto_approve: true\n";

  async function seedPoliciesAndProposal() {
    const { POLICIES_PATH } = await import("../src/config/config.js");
    fs.writeFileSync(POLICIES_PATH, POLICIES_YAML_WITH_COMMENT, { mode: 0o600 });
    const { PolicyEngine } = await import("../src/policy/engine.js");
    PolicyEngine.proposeRule("agent-a", { match: "notion:read:*", ttl: "5m" }, "need to read docs");
    return POLICIES_PATH;
  }

  it("review lists pending proposals with agent/match/ttl/justification", async () => {
    await seedPoliciesAndProposal();
    const { readProposals } = await import("../src/commands/policies-cli.js");
    const list = readProposals();
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      index: 1,
      agentId: "agent-a",
      status: "pending_human_review",
      justification: "need to read docs",
    });
    expect(list[0].rule).toMatchObject({ match: "notion:read:*", ttl: "5m" });
  });

  it("accept appends the rule to policies.yaml (comments preserved), marks the proposal and audits", async () => {
    const POLICIES_PATH = await seedPoliciesAndProposal();
    const { acceptProposal, readProposals } = await import("../src/commands/policies-cli.js");

    acceptProposal(1, "token");

    const raw = fs.readFileSync(POLICIES_PATH, "utf8");
    expect(raw).toContain("# human-owned file — keep this comment"); // comments survive
    expect(raw).toContain("notion:read:*");
    expect(raw).toContain("existing:rule:*"); // previous rule untouched

    // The engine's own loader accepts the file and the rule is effective.
    const { PolicyEngine } = await import("../src/policy/engine.js");
    const engine = PolicyEngine.load();
    const d = engine.request("agent-a", "notion:read:page", "5m", "read");
    expect(d.allow).toBe(true);

    const proposals = readProposals();
    expect(proposals[0].status).toBe("accepted");
    expect(proposals[0].resolvedAt).toBeTruthy();

    const accepted = (await auditEntries()).filter((e) => e.kind === "policy_accepted");
    expect(accepted).toHaveLength(1);
    expect(accepted[0].detail).toMatchObject({
      proposedBy: "agent-a",
      match: "notion:read:*",
      decidedBy: "human:cli:token",
    });
  });

  it("reject marks the proposal with the reason, keeps policies.yaml untouched and audits", async () => {
    const POLICIES_PATH = await seedPoliciesAndProposal();
    const before = fs.readFileSync(POLICIES_PATH, "utf8");
    const { rejectProposal, readProposals } = await import("../src/commands/policies-cli.js");

    expect(() => rejectProposal(1, " ", "tty")).toThrow(/--reason/);
    rejectProposal(1, "not needed", "tty");

    expect(fs.readFileSync(POLICIES_PATH, "utf8")).toBe(before); // untouched
    const proposals = readProposals();
    expect(proposals[0].status).toBe("rejected");
    expect(proposals[0].resolutionReason).toBe("not needed");

    const rejected = (await auditEntries()).filter((e) => e.kind === "policy_rejected");
    expect(rejected).toHaveLength(1);
    expect(rejected[0].detail).toMatchObject({ match: "notion:read:*", reason: "not needed" });
  });

  it("deciding an unknown or already-decided proposal fails cleanly", async () => {
    await seedPoliciesAndProposal();
    const { acceptProposal, rejectProposal } = await import("../src/commands/policies-cli.js");
    expect(() => acceptProposal(7, "token")).toThrow(/No proposal #7/);
    rejectProposal(1, "no", "token");
    expect(() => acceptProposal(1, "token")).toThrow(/already 'rejected'/);
  });
});

/* ------------------------------------------------------------------------ */
/* notifier                                                                  */
/* ------------------------------------------------------------------------ */

describe("webhook notifier", () => {
  const fakeReq = {
    id: "11111111-2222-3333-4444-555555555555",
    agentId: "agent-a",
    capability: "github:write:repo",
    ttl: "5m",
    reason: "push fix",
    requestedAt: Date.now(),
    expiresAt: Date.now() + 600_000,
  };

  async function enableWebhook() {
    process.env.SCOPEGATE_VAULT_MODE = "local";
    const { NOTIFY_CONFIG_PATH } = await import("../src/notify/config.js");
    fs.writeFileSync(
      NOTIFY_CONFIG_PATH,
      JSON.stringify({ enabled: true, slackWebhookRef: "slack_webhook_url" }),
      { mode: 0o600 },
    );
    const { Vault } = await import("../src/vault/vault.js");
    Vault.open().set("slack_webhook_url", "https://hooks.slack.com/services/T00/B00/xxx");
  }

  afterEach(() => {
    delete process.env.SCOPEGATE_VAULT_MODE;
  });

  it("is a silent no-op without notify.json", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { notifyApprovalRequested } = await import("../src/notify/notifier.js");
    await notifyApprovalRequested(fakeReq);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("is a no-op when enabled=false", async () => {
    const { NOTIFY_CONFIG_PATH } = await import("../src/notify/config.js");
    fs.writeFileSync(NOTIFY_CONFIG_PATH, JSON.stringify({ enabled: false, slackWebhookRef: "x" }));
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { notifyApprovalRequested } = await import("../src/notify/notifier.js");
    await notifyApprovalRequested(fakeReq);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a raw URL in notify.json (the webhook URL must live in the vault)", async () => {
    const { NOTIFY_CONFIG_PATH } = await import("../src/notify/config.js");
    fs.writeFileSync(
      NOTIFY_CONFIG_PATH,
      JSON.stringify({ enabled: true, slackWebhookRef: "https://hooks.slack.com/services/leak" }),
    );
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { notifyApprovalRequested } = await import("../src/notify/notifier.js");
    await notifyApprovalRequested(fakeReq);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("POSTs a Slack-compatible payload with the URL read from the vault", async () => {
    await enableWebhook();
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    const { notifyApprovalRequested } = await import("../src/notify/notifier.js");

    await notifyApprovalRequested(fakeReq);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://hooks.slack.com/services/T00/B00/xxx");
    expect(init.method).toBe("POST");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const body = JSON.parse(String(init.body)) as { text: string };
    expect(body.text).toContain(`scopegate approve ${fakeReq.id}`);
    expect(body.text).toContain(fakeReq.capability);
    expect(body.text).toContain(fakeReq.agentId);
    expect(body.text).not.toContain("hooks.slack.com"); // the URL itself is never in the message
  });

  it("a dead webhook never throws and never grants (fail-closed)", async () => {
    await enableWebhook();
    const fetchMock = vi.fn().mockRejectedValue(new Error("connection refused"));
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { notifyApprovalRequested } = await import("../src/notify/notifier.js");
    await expect(notifyApprovalRequested(fakeReq)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("createApprovalRequest fires the notifier only for genuinely new requests (dedup stays silent)", async () => {
    await enableWebhook();
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    const { createApprovalRequest } = await import("../src/policy/approvals.js");

    createApprovalRequest({ agentId: "agent-a", capability: "github:write:repo" });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1), { timeout: 2000 });

    // Deduped re-request for the same agent+capability: no second notification.
    createApprovalRequest({ agentId: "agent-a", capability: "github:write:repo" });
    await new Promise((r) => setTimeout(r, 100));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
