/**
 * Cursor adapter: project `.cursor/mcp.json` and user `~/.cursor/mcp.json`,
 * `mcpServers` format (de-facto Claude-style layout). Detection falls back
 * to the `cursor-agent` (CLI) or `cursor` (editor) executables on PATH.
 */
import path from "node:path";
import type { HarnessAdapter } from "./types.js";
import { homeDir, projectDir } from "./util.js";
import { makeMcpJsonAdapter } from "./mcp-json.js";

export const cursorAdapter: HarnessAdapter = makeMcpJsonAdapter(
  "cursor",
  () => [
    { scope: "project", path: path.join(projectDir(), ".cursor", "mcp.json") },
    { scope: "user", path: path.join(homeDir(), ".cursor", "mcp.json") },
  ],
  ["cursor-agent", "cursor"],
);
