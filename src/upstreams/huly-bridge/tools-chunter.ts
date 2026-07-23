/**
 * Chunter tools (EPIC-14): Huly channels and chat messages (the Slack
 * surface). Message text flows as markdown; markup conversion happens at the
 * client boundary.
 */
import type { HulyBridgeClient } from "./client.js";
import { optionalLimit, optionalString, requireString, type ToolDefinition, type ToolHandler } from "./tools-tracker.js";

export const chunterTools: ToolDefinition[] = [
  {
    name: "chunter_post_message",
    description: "Post a message to a channel (or to a thread when " + '"thread"' + " is given)",
    inputSchema: {
      type: "object",
      properties: {
        channel: { type: "string", description: "Channel name (e.g. general) or id" },
        message: { type: "string", description: "Message body (markdown)" },
        thread: { type: "string", description: "Parent message id to reply in a thread" },
      },
      required: ["channel", "message"],
    },
  },
  {
    name: "chunter_list_channels",
    description: "List channels in the workspace",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "chunter_list_messages",
    description: "List recent messages of a channel (or of a thread)",
    inputSchema: {
      type: "object",
      properties: {
        channel: { type: "string", description: "Channel name (e.g. general) or id" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
        thread: { type: "string", description: "Parent message id — list the thread instead of the channel" },
      },
      required: ["channel"],
    },
  },
];

export function createChunterHandlers(client: HulyBridgeClient): Record<string, ToolHandler> {
  return {
    chunter_post_message: async (args) => {
      return await client.postMessage({
        channel: requireString(args, "channel", "use chunter_list_channels to see names"),
        message: requireString(args, "message"),
        thread: optionalString(args, "thread"),
      });
    },

    chunter_list_channels: async () => {
      const channels = await client.listChannels();
      return { channels, count: channels.length };
    },

    chunter_list_messages: async (args) => {
      const messages = await client.listMessages({
        channel: requireString(args, "channel", "use chunter_list_channels to see names"),
        limit: optionalLimit(args),
        thread: optionalString(args, "thread"),
      });
      return { messages, count: messages.length };
    },
  };
}
