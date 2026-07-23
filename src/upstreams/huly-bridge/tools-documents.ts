/**
 * Documents tools (EPIC-14): Huly teamspace documents (the Notion surface).
 * Content flows as markdown; conversion happens at the client boundary.
 */
import type { HulyBridgeClient } from "./client.js";
import { optionalLimit, optionalString, requireString, type ToolDefinition, type ToolHandler } from "./tools-tracker.js";

export const documentTools: ToolDefinition[] = [
  {
    name: "documents_create",
    description: "Create a document in a Huly teamspace",
    inputSchema: {
      type: "object",
      properties: {
        teamspace: { type: "string", description: "Teamspace name or id" },
        title: { type: "string", description: "Document title" },
        content: { type: "string", description: "Document content (markdown)" },
      },
      required: ["teamspace", "title", "content"],
    },
  },
  {
    name: "documents_read",
    description: "Read a document (content returned as markdown)",
    inputSchema: {
      type: "object",
      properties: {
        documentId: { type: "string", description: "Document id from documents_create/documents_list" },
      },
      required: ["documentId"],
    },
  },
  {
    name: "documents_update",
    description: "Replace the content of a document (markdown)",
    inputSchema: {
      type: "object",
      properties: {
        documentId: { type: "string", description: "Document id from documents_create/documents_list" },
        content: { type: "string", description: "New content (markdown)" },
      },
      required: ["documentId", "content"],
    },
  },
  {
    name: "documents_list",
    description: "List documents, optionally filtered by teamspace",
    inputSchema: {
      type: "object",
      properties: {
        teamspace: { type: "string", description: "Teamspace name or id" },
        limit: { type: "number", description: "Max results (default 20, max 100)" },
      },
    },
  },
];

export function createDocumentHandlers(client: HulyBridgeClient): Record<string, ToolHandler> {
  return {
    documents_create: async (args) => {
      return await client.createDocument({
        teamspace: requireString(args, "teamspace", "pass the teamspace name (e.g. general) or id"),
        title: requireString(args, "title"),
        content: requireString(args, "content"),
      });
    },

    documents_read: async (args) => {
      return await client.readDocument(
        requireString(args, "documentId", "pass a document id from documents_create or documents_list"),
      );
    },

    documents_update: async (args) => {
      return await client.updateDocument(
        requireString(args, "documentId", "pass a document id from documents_create or documents_list"),
        requireString(args, "content"),
      );
    },

    documents_list: async (args) => {
      const documents = await client.listDocuments({
        teamspace: optionalString(args, "teamspace"),
        limit: optionalLimit(args),
      });
      return { documents, count: documents.length };
    },
  };
}
