#!/usr/bin/env node
/**
 * cloudflare-bridge (EPIC-17): MCP stdio server exposing Cloudflare API v4
 * surfaces (zones / DNS records / Workers / Pages / R2) as 8 bare-named
 * tools. Deployed as a stdio upstream of the ScopeGate gateway, which adds
 * the `cloudflare__` namespace and injects the env at spawn:
 *
 *   CLOUDFLARE_API_TOKEN  scoped API token (injected by the gateway; auth type env)
 *   CLOUDFLARE_API_URL    API base URL (optional, default https://api.cloudflare.com/client/v4)
 *   CLOUDFLARE_MOCK=1     in-memory mock instead of the real client (tests/e2e)
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
import { createCloudflareClient, DEFAULT_API_URL, type CloudflareBridgeClient } from "./client.js";
import { cloudflareTools, createCloudflareHandlers, type ToolDefinition } from "./tools.js";

/** The closed list of 8 tools (frozen contract). */
export function buildToolList(): ToolDefinition[] {
  return cloudflareTools;
}

/** MCP Server with every surface handler registered against the given client. */
export function createBridgeServer(client: CloudflareBridgeClient): Server {
  const handlers: Record<string, ReturnType<typeof createCloudflareHandlers>[string]> = createCloudflareHandlers(client);

  const server = new Server({ name: "cloudflare-bridge", version: "1.0.0" }, { capabilities: { tools: {} } });

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
  const mock = process.env.CLOUDFLARE_MOCK === "1";
  let client: CloudflareBridgeClient;
  try {
    client = createCloudflareClient(process.env);
  } catch (err) {
    console.error(`[cloudflare-bridge] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
  try {
    await client.connect();
  } catch (err) {
    // The API base URL may appear here (not secret); the token never does.
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[cloudflare-bridge] failed to verify the Cloudflare token: ${message}`);
    process.exit(1);
  }

  const server = createBridgeServer(client);
  await server.connect(new StdioServerTransport());
  console.error(
    `[cloudflare-bridge] ready — mode=${mock ? "mock" : "live"} api=${process.env.CLOUDFLARE_API_URL ?? DEFAULT_API_URL} tools=${buildToolList().length}`,
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
    console.error(`[cloudflare-bridge] fatal: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
