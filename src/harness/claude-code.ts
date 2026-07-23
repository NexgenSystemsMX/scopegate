/**
 * Claude Code adapter: project `.mcp.json` and user `~/.claude.json`,
 * `mcpServers` format. Detection falls back to the `claude` CLI on PATH.
 */
import path from "node:path";
import type { HarnessAdapter } from "./types.js";
import { homeDir, projectDir } from "./util.js";
import { makeMcpJsonAdapter } from "./mcp-json.js";

export const claudeCodeAdapter: HarnessAdapter = makeMcpJsonAdapter(
  "claude-code",
  () => [
    { scope: "project", path: path.join(projectDir(), ".mcp.json") },
    { scope: "user", path: path.join(homeDir(), ".claude.json") },
  ],
  "claude",
);
