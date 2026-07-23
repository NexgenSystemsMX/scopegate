#!/usr/bin/env node
/**
 * railway-bridge (EPIC-16): MCP stdio server exposing Railway operations
 * (services / status / deploys / logs / variables / domains) as 7 bare-named
 * tools. Deployed as a stdio upstream of the ScopeGate gateway, which adds the
 * `railway__` namespace and injects the env at spawn:
 *
 *   RAILWAY_TOKEN     Railway API token (injected by the gateway from the vault)
 *   RAILWAY_API_URL   optional GraphQL endpoint (default backboard v2)
 *   RAILWAY_MOCK=1    in-memory mock instead of the real client (tests/e2e)
 *
 * Invariants (shared with the gateway):
 *   - stdout belongs to the MCP protocol — logs go to stderr ONLY.
 *   - The token is never logged and never embedded in error messages.
 *   - Variable VALUES never leave the bridge (variables_list → "[redacted]").
 *   - Tool errors are MCP isError results with actionable messages.
 */
import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_API_URL, createRailwayClient, type RailwayBridgeClient } from "./client.js";
import { createRailwayHandlers, railwayTools, type ToolDefinition, type ToolHandler } from "./tools.js";

/** The closed list of 7 tools (frozen contract). */
export function buildToolList(): ToolDefinition[] {
  return [...railwayTools];
}

/** MCP Server with every handler registered against the given client. */
export function createBridgeServer(client: RailwayBridgeClient): Server {
  const handlers: Record<string, ToolHandler> = createRailwayHandlers(client);

  const server = new Server({ name: "railway-bridge", version: "1.0.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: buildToolList() }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const handler = handlers[req.params.name];
    if (handler === undefined) {
      return {
        content: [
          {
            type: "text",
            text: `Unknown tool "${req.params.name}". Available: ${buildToolList()
              .map((t) => t.name)
              .join(", ")}`,
          },
        ],
        isError: true,
      };
    }
    try {
      const result = await handler((req.params.arguments ?? {}) as Record<string, unknown>);
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    } catch (err) {
      // Errors must be actionable but NEVER carry secrets: client/factory
      // messages are authored secret-free; anything unexpected is normalized.
      const message = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text", text: message }], isError: true };
    }
  });

  return server;
}

export async function main(): Promise<void> {
  const mock = process.env.RAILWAY_MOCK === "1";
  let client: RailwayBridgeClient;
  try {
    client = createRailwayClient(process.env);
  } catch (err) {
    console.error(`[railway-bridge] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
  try {
    await client.connect();
  } catch (err) {
    // The API URL may appear here (not secret); the token never does.
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[railway-bridge] failed to connect to Railway: ${message}`);
    process.exit(1);
  }

  const server = createBridgeServer(client);
  await server.connect(new StdioServerTransport());
  console.error(
    `[railway-bridge] ready — mode=${mock ? "mock" : "live"} api=${mock ? "mock" : (process.env.RAILWAY_API_URL ?? DEFAULT_API_URL)} tools=${buildToolList().length}`,
  );

  const shutdown = (): void => {
    void client
      .close()
      .catch(() => undefined)
      .finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

const invokedAsScript = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsScript) {
  main().catch((err) => {
    console.error(`[railway-bridge] fatal: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
