/**
 * scopegate/testkit — fake MCP upstream shipped inside the package so
 * consumers can integration-test their ScopeGate setup without real
 * credentials. Spawned as `node <this file>` (stdio MCP).
 *
 * Tools:
 *   - whoami  → auth status (FAKE_TOKEN must equal "supersecret123")
 *   - echo    → returns the message arg verbatim
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "scopegate-testkit-fake", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "whoami",
      description: "Auth status probe",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "echo",
      description: "Returns the message verbatim",
      inputSchema: {
        type: "object",
        properties: { message: { type: "string" } },
        required: ["message"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === "echo") {
    return {
      content: [
        { type: "text", text: String(req.params.arguments?.message ?? "") },
      ],
    };
  }
  const ok = process.env.FAKE_TOKEN === "supersecret123";
  return {
    content: [
      {
        type: "text",
        text: `authenticated=${ok} (token ${process.env.FAKE_TOKEN ? "present" : "MISSING"})`,
      },
    ],
  };
});

await server.connect(new StdioServerTransport());
