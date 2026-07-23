/**
 * Contact tools (EPIC-14): Huly persons directory.
 */
import type { HulyBridgeClient } from "./client.js";
import { optionalLimit, type ToolDefinition, type ToolHandler } from "./tools-tracker.js";

export const contactTools: ToolDefinition[] = [
  {
    name: "contact_list_persons",
    description: "List persons in the workspace contacts",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number", description: "Max results (default 50, max 100)" },
      },
    },
  },
];

export function createContactHandlers(client: HulyBridgeClient): Record<string, ToolHandler> {
  return {
    contact_list_persons: async (args) => {
      const persons = await client.listPersons({ limit: optionalLimit(args, 50) });
      return { persons, count: persons.length };
    },
  };
}
