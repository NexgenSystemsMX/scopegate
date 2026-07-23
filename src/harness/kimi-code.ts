/**
 * Kimi Code adapter: project `.kimi-code/mcp.json` and user
 * `~/.kimi-code/mcp.json` (or `$KIMI_CODE_HOME/mcp.json` when the env var is
 * set — it overrides the default ~/.kimi-code dir in the harness itself).
 * `mcpServers` format; Kimi extras (transport: "sse", bearerTokenEnvVar,
 * enabledTools) are mapped by the shared migration core. Detection falls
 * back to the `kimi` CLI on PATH.
 */
import path from "node:path";
import type { HarnessAdapter } from "./types.js";
import { homeDir, projectDir } from "./util.js";
import { makeMcpJsonAdapter } from "./mcp-json.js";

export const kimiCodeAdapter: HarnessAdapter = makeMcpJsonAdapter(
  "kimi-code",
  () => [
    { scope: "project", path: path.join(projectDir(), ".kimi-code", "mcp.json") },
    {
      scope: "user",
      path: process.env.KIMI_CODE_HOME
        ? path.join(process.env.KIMI_CODE_HOME, "mcp.json")
        : path.join(homeDir(), ".kimi-code", "mcp.json"),
    },
  ],
  "kimi",
);
