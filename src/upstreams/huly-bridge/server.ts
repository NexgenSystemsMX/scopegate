#!/usr/bin/env node
/**
 * huly-bridge (EPIC-14): MCP stdio server exposing the four Huly surfaces
 * (tracker / documents / chunter / contact) as 13 bare-named tools. Deployed
 * as a stdio upstream of the ScopeGate gateway, which adds the `huly__`
 * namespace and injects the env at spawn:
 *
 *   HULY_TOKEN        workspace token (injected by the gateway via minter)
 *   HULY_ENDPOINT     Huly base URL (wss:// transactor URLs are normalized)
 *   HULY_WORKSPACE    workspace name
 *   HULY_CLIENT_MOCK=1  in-memory mock instead of the real client (tests/e2e)
 *
 * Invariants (shared with the gateway):
 *   - stdout belongs to the MCP protocol — logs go to stderr ONLY.
 *   - The token is never logged and never embedded in error messages.
 *   - Tool errors are MCP isError results with actionable messages.
 */
import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { createHulyClient, type HulyBridgeClient } from "./client.js";
import { createTrackerHandlers, trackerTools, type ToolDefinition, type ToolHandler } from "./tools-tracker.js";
import { createDocumentHandlers, documentTools } from "./tools-documents.js";
import { chunterTools, createChunterHandlers } from "./tools-chunter.js";
import { contactTools, createContactHandlers } from "./tools-contact.js";

/** The closed list of 13 tools (frozen contract). */
export function buildToolList(): ToolDefinition[] {
  return [...trackerTools, ...documentTools, ...chunterTools, ...contactTools];
}

/** MCP Server with every surface handler registered against the given client. */
export function createBridgeServer(client: HulyBridgeClient): Server {
  const handlers: Record<string, ToolHandler> = {
    ...createTrackerHandlers(client),
    ...createDocumentHandlers(client),
    ...createChunterHandlers(client),
    ...createContactHandlers(client),
  };

  const server = new Server({ name: "huly-bridge", version: "1.0.0" }, { capabilities: { tools: {} } });

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
  const mock = process.env.HULY_CLIENT_MOCK === "1";
  let client: HulyBridgeClient;
  try {
    client = createHulyClient(process.env);
  } catch (err) {
    console.error(`[huly-bridge] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
  try {
    await client.connect();
  } catch (err) {
    // Endpoint/workspace may appear here (not secret); the token never does.
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[huly-bridge] failed to connect to Huly: ${message}`);
    process.exit(1);
  }

  const server = createBridgeServer(client);
  await server.connect(new StdioServerTransport());
  console.error(
    `[huly-bridge] ready — workspace=${process.env.HULY_WORKSPACE ?? "mock"} mode=${mock ? "mock" : "live"} tools=${buildToolList().length}`,
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
    console.error(`[huly-bridge] fatal: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
