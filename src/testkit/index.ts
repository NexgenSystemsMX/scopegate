/**
 * scopegate/testkit — integration-test helpers for consumers of the
 * embeddable API (M7): a fake upstream that needs no real credentials and a
 * one-call boot of an in-process gateway wired to an MCP client over an
 * in-memory transport.
 *
 *   import { bootFakeGateway } from "scopegate/testkit";
 *
 *   const t = await bootFakeGateway();
 *   const { tools } = await t.client.listTools();   // management + fakegit__*
 *   await t.callTool({ name: "fakegit__whoami", arguments: {} });
 *   await t.close();
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createGatewayServer, type EmbeddedGateway } from "../api.js";

/** Absolute path to the compiled fake upstream (spawn with `node <path>`). */
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SIBLING = path.join(HERE, "fake-upstream.js");
// Published package: index.js sits next to fake-upstream.js in dist/testkit.
// Repo tests (vitest resolves to src/): fall back to the compiled dist file.
export const fakeUpstreamPath = fs.existsSync(SIBLING)
  ? SIBLING
  : path.join(process.cwd(), "dist", "testkit", "fake-upstream.js");

export interface FakeGatewayHandle {
  gateway: EmbeddedGateway;
  client: Client;
  home: string;
  /** Close the client and the gateway. */
  close(): Promise<void>;
}

/**
 * Boot an in-process gateway against the fake upstream. Uses the ALREADY
 * resolved ScopeGate home: set process.env.SCOPEGATE_HOME to a throwaway dir
 * BEFORE importing this module (tests must never touch the real ~/.scopegate).
 */
export async function bootFakeGateway(opts: {
  agentId?: string;
  extraCapabilities?: Record<string, unknown>[];
} = {}): Promise<FakeGatewayHandle> {
  if (!process.env.SCOPEGATE_HOME) {
    throw new Error(
      "bootFakeGateway: set process.env.SCOPEGATE_HOME to a throwaway dir BEFORE importing 'scopegate/testkit' — " +
        "writing test config into the real ~/.scopegate is refused.",
    );
  }
  const { SCOPEGATE_DIR } = await import("../config/config.js");
  const home = SCOPEGATE_DIR;
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  const agentId = opts.agentId ?? "testkit-agent";
  fs.writeFileSync(
    path.join(home, "scopegate.yaml"),
    JSON.stringify({
      version: 1,
      agentId,
      upstreams: [
        {
          name: "fakegit",
          transport: { kind: "stdio", command: process.execPath, args: [fakeUpstreamPath] },
          auth: { type: "env", env: { FAKE_TOKEN: "fake_token" } },
        },
      ],
    }),
  );
  fs.writeFileSync(
    path.join(home, "policies.yaml"),
    JSON.stringify({
      version: 1,
      agents: {
        [agentId]: {
          default_ttl: "15m",
          capabilities: [
            { match: "fakegit:call:*", auto_approve: true, ttl: "15m" },
            ...(opts.extraCapabilities ?? []),
          ],
        },
      },
    }),
  );
  // Deposit the demo secret BEFORE boot: stdio env auth injects at spawn time.
  const { Vault } = await import("../vault/vault.js");
  Vault.open().set("fake_token", "supersecret123");
  const gateway = await createGatewayServer({ home, agentId });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await gateway.server.connect(serverTransport);
  const client = new Client({ name: "scopegate-testkit", version: "1.0.0" }, { capabilities: {} });
  await client.connect(clientTransport);
  return {
    gateway,
    client,
    home,
    close: async () => {
      await client.close().catch(() => {});
      await gateway.close();
      // The home is the caller's throwaway dir — they own its cleanup.
    },
  };
}
