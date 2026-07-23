/**
 * huly-bridge client (EPIC-14): semantic interface over a Huly workspace
 * (tracker + documents + chunter + contact) plus the factory the MCP server
 * uses to pick a backend:
 *
 *   createHulyClient(env)
 *     HULY_CLIENT_MOCK=1  → in-memory mock (mock-client.ts) — tests & local e2e
 *     otherwise           → real client over @hcengineering/api-client
 *
 * The interface speaks PLAIN MARKDOWN in and out; markup conversion happens
 * only here, at the real-client boundary (the mock stores text as-is):
 *
 *   - Inline ProseMirror markup (chunter messages, issue comments — model
 *     type TypeMarkup): written via markdownToHulyMarkup(), read via
 *     hulyMarkupToMarkdown() with a plain-text fallback.
 *   - Collaborative blob refs (issue description, document content — model
 *     type MarkupBlobRef): written through the api-client's MarkupContent
 *     auto-upload (markdown()), read back via fetchMarkup(..., 'markdown').
 *     Reads additionally tolerate legacy inline values (same heuristic as
 *     the kimi-tag reference: inline values contain HTML/JSON/mentions).
 *
 * Connection contract (frozen): HULY_TOKEN (workspace token, injected by the
 * gateway at spawn), HULY_ENDPOINT (Huly base URL; a wss:// transactor URL is
 * normalized to https:// so /config.json can be fetched), HULY_WORKSPACE
 * (workspace name). The token NEVER appears in logs or error messages.
 *
 * Class refs are raw strings (kimi-tag pattern) so we do not drag the UI
 * plugin dependency chain (@hcengineering/tracker, chunter, document…).
 *
 * The @hcengineering/* packages ship CJS without .d.ts in this install, so
 * they are imported as untyped default CJS packages (see huly-modules.d.ts)
 * and adapted to the structural PlatformClientLike subset below (same
 * mockeable-subset pattern as kimi-tag's HierarchyClient/ChangelogClient).
 */
import hulyApiClientPkg from "@hcengineering/api-client";
import textPkg from "@hcengineering/text";
import textMarkdownPkg from "@hcengineering/text-markdown";
import { createMockClient } from "./mock-client.js";

const { connect, markdown, NodeWebSocketFactory } = hulyApiClientPkg as any;
const { jsonToMarkup, markupToJSON, markupToText } = textPkg as any;
const { markdownToMarkup, markupToMarkdown } = textMarkdownPkg as any;

// --- Class refs (verified against the Huly model + kimi-tag production code) ---

export const CLASS_PROJECT = "tracker:class:Project";
export const CLASS_ISSUE = "tracker:class:Issue";
export const CLASS_CHAT_MESSAGE = "chunter:class:ChatMessage";
export const CLASS_THREAD_MESSAGE = "chunter:class:ThreadMessage";
export const CLASS_CHANNEL = "chunter:class:Channel";
export const CLASS_DOCUMENT = "document:class:Document";
export const CLASS_TEAMSPACE = "document:class:Teamspace";
export const CLASS_PERSON = "contact:class:Person";
export const SPACE_CORE = "core:space:Space";
export const NO_PARENT_ISSUE = "tracker:ids:NoParent";
export const NO_PARENT_DOC = "document:ids:NoParent";
export const KIND_ISSUE = "tracker:taskTypes:Issue";

// --- Status / priority maps (from the kimi-tag reference, proven in prod) ---

export const STATUS_REFS: Record<string, string> = {
  backlog: "tracker:status:Backlog",
  todo: "tracker:status:Todo",
  in_progress: "tracker:status:InProgress",
  done: "tracker:status:Done",
  canceled: "tracker:status:Canceled",
};

const STATUS_NAMES: Record<string, string> = Object.fromEntries(
  Object.entries(STATUS_REFS).map(([name, ref]) => [ref, name]),
);

/** Accepts a friendly name (backlog/todo/in_progress/done/canceled) or a raw ref. */
export function resolveStatusRef(input: string): string {
  const friendly = input.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (STATUS_REFS[friendly] !== undefined) return STATUS_REFS[friendly];
  if (input.startsWith("tracker:status:")) return input;
  throw new Error(
    `Invalid status "${input}". Valid: ${Object.keys(STATUS_REFS).join(", ")} (or a tracker:status:* ref)`,
  );
}

export function statusName(ref: string): string {
  return STATUS_NAMES[ref] ?? ref;
}

export const PRIORITY_VALUES: Record<string, number> = {
  none: 0,
  urgent: 1,
  high: 2,
  medium: 3,
  low: 4,
};

const PRIORITY_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(PRIORITY_VALUES).map(([name, v]) => [v, name]),
) as Record<number, string>;

/** Accepts a number (0-4) or a name (urgent/high/medium/low/none). */
export function resolvePriority(input: string | number): number {
  if (typeof input === "number") {
    if (Number.isInteger(input) && input >= 0 && input <= 4) return input;
    throw new Error(`Invalid priority ${input} (range 0-4)`);
  }
  const friendly = input.trim().toLowerCase();
  const v = PRIORITY_VALUES[friendly];
  if (v !== undefined) return v;
  const asNum = Number.parseInt(friendly, 10);
  if (Number.isInteger(asNum) && asNum >= 0 && asNum <= 4) return asNum;
  throw new Error(
    `Invalid priority "${input}". Valid: ${Object.keys(PRIORITY_VALUES).join(", ")} or 0-4`,
  );
}

export function priorityName(value: number): string {
  return PRIORITY_NAMES[value] ?? String(value);
}

// --- Markup conversion (the ONLY place Huly markup is handled) ---

/** markdown → inline ProseMirror-JSON markup string (chunter messages, issue comments). */
export function markdownToHulyMarkup(md: string): string {
  return jsonToMarkup(markdownToMarkup(md, { refUrl: "", imageUrl: "" })) as string;
}

/**
 * Inline ProseMirror markup string → markdown. Falls back to plain text
 * extraction (and finally to the raw value) so a response NEVER carries a
 * giant raw markup blob (frozen response contract).
 */
export function hulyMarkupToMarkdown(markup: string): string {
  if (markup === "") return "";
  try {
    return (markupToMarkdown(markupToJSON(markup)) as string).trim();
  } catch {
    try {
      return (markupToText(markup) as string).trim();
    } catch {
      return markup;
    }
  }
}

// --- Semantic output shapes (compact JSON — the frozen response contract) ---

export interface IssueCreated {
  id: string;
  identifier: string;
  title: string;
  updatedAt: number;
}

export interface IssueUpdated {
  identifier: string;
  updated: string[];
  updatedAt: number;
}

export interface CommentCreated {
  id: string;
  issue: string;
  updatedAt: number;
}

export interface IssueSummary {
  id: string;
  identifier: string;
  title: string;
  status: string;
  priority: string;
  assignee: string | null;
  updatedAt: number;
}

export interface ProjectInfo {
  id: string;
  identifier: string;
  name: string;
  issues: number;
}

export interface DocumentCreated {
  id: string;
  title: string;
  teamspace: string;
  updatedAt: number;
}

export interface DocumentInfo {
  id: string;
  title: string;
  teamspace: string;
  content: string;
  updatedAt: number;
}

export interface DocumentSummary {
  id: string;
  title: string;
  teamspace: string;
  updatedAt: number;
}

export interface ChannelInfo {
  id: string;
  name: string;
}

export interface MessagePosted {
  id: string;
  channel: string;
  thread?: string;
  updatedAt: number;
}

export interface MessageInfo {
  id: string;
  author: string;
  text: string;
  createdAt: number;
}

export interface PersonInfo {
  id: string;
  name: string;
}

// --- The bridge client contract (real and mock both implement it) ---

export interface CreateIssueInput {
  project: string;
  title: string;
  description?: string;
  priority?: string | number;
  assignee?: string;
}

export interface UpdateIssueFields {
  title?: string;
  description?: string;
  status?: string;
  priority?: string | number;
  assignee?: string;
}

export interface SearchIssuesFilter {
  query?: string;
  project?: string;
  status?: string;
  limit?: number;
}

export interface HulyBridgeClient {
  connect: () => Promise<void>;
  close: () => Promise<void>;

  createIssue: (input: CreateIssueInput) => Promise<IssueCreated>;
  updateIssue: (issueId: string, fields: UpdateIssueFields) => Promise<IssueUpdated>;
  commentIssue: (issueId: string, message: string) => Promise<CommentCreated>;
  searchIssues: (filter: SearchIssuesFilter) => Promise<IssueSummary[]>;
  listProjects: () => Promise<ProjectInfo[]>;

  createDocument: (input: { teamspace: string; title: string; content: string }) => Promise<DocumentCreated>;
  readDocument: (documentId: string) => Promise<DocumentInfo>;
  updateDocument: (documentId: string, content: string) => Promise<DocumentCreated>;
  listDocuments: (filter: { teamspace?: string; limit?: number }) => Promise<DocumentSummary[]>;

  postMessage: (input: { channel: string; message: string; thread?: string }) => Promise<MessagePosted>;
  listChannels: () => Promise<ChannelInfo[]>;
  listMessages: (filter: { channel: string; limit?: number; thread?: string }) => Promise<MessageInfo[]>;

  listPersons: (filter: { limit?: number }) => Promise<PersonInfo[]>;
}

// --- Structural subset of the api-client PlatformClient (mockeable) ---

export interface PlatformClientLike {
  findOne: (_class: string, query: Record<string, unknown>) => Promise<Record<string, unknown> | undefined>;
  findAll: (_class: string, query: Record<string, unknown>) => Promise<Array<Record<string, unknown>>>;
  createDoc: (_class: string, space: string, attributes: Record<string, unknown>) => Promise<string>;
  updateDoc: (
    _class: string,
    space: string,
    objectId: string,
    operations: Record<string, unknown>,
    retrieve?: boolean,
  ) => Promise<unknown>;
  addCollection: (
    _class: string,
    space: string,
    attachedTo: string,
    attachedToClass: string,
    collection: string,
    attributes: Record<string, unknown>,
  ) => Promise<string>;
  fetchMarkup: (objectClass: string, objectId: string, objectAttr: string, id: unknown, format: string) => Promise<string>;
  close: () => Promise<void>;
}

/** Adapts the untyped api-client PlatformClient to the structural subset. */
function toPlatformClientLike(platform: any): PlatformClientLike {
  return {
    findOne: async (_class, query) =>
      (await platform.findOne(_class, query)) as Record<string, unknown> | undefined,
    findAll: async (_class, query) => (await platform.findAll(_class, query)) as Array<Record<string, unknown>>,
    createDoc: async (_class, space, attributes) => String(await platform.createDoc(_class, space, attributes)),
    updateDoc: async (_class, space, objectId, operations, retrieve) =>
      await platform.updateDoc(_class, space, objectId, operations, retrieve),
    addCollection: async (_class, space, attachedTo, attachedToClass, collection, attributes) =>
      String(await platform.addCollection(_class, space, attachedTo, attachedToClass, collection, attributes)),
    fetchMarkup: async (objectClass, objectId, objectAttr, id, format) =>
      String(await platform.fetchMarkup(objectClass, objectId, objectAttr, id, format)),
    close: async () => await platform.close(),
  };
}

/**
 * wss://host/_transactor → https://host (the api-client `connect()` flow
 * fetches `<base>/config.json`, which Huly serves at the ORIGIN root, not
 * under the transactor path — hitting `<endpoint>/config.json` 404s as
 * "Failed to fetch config"). Only the transactor path is stripped; any other
 * path (proxied/subpath installs) is preserved.
 */
export function normalizeEndpoint(endpoint: string): string {
  let url = endpoint.trim().replace(/\/+$/, "");
  if (url.startsWith("wss://")) url = "https://" + url.slice("wss://".length);
  else if (url.startsWith("ws://")) url = "http://" + url.slice("ws://".length);
  url = url.replace(/\/_transactor$/, "");
  return url;
}

interface DocLike {
  _id: string;
  space?: string;
  modifiedOn?: number;
  createdOn?: number;
}

// --- Real client -------------------------------------------------------------

export interface RealClientOptions {
  token: string;
  endpoint: string;
  workspace: string;
}

export class RealHulyClient implements HulyBridgeClient {
  private platform: PlatformClientLike | null = null;

  constructor(private readonly opts: RealClientOptions) {}

  async connect(): Promise<void> {
    const baseUrl = normalizeEndpoint(this.opts.endpoint);
    const platform = await connect(baseUrl, {
      token: this.opts.token,
      workspace: this.opts.workspace,
      socketFactory: NodeWebSocketFactory,
    });
    this.platform = toPlatformClientLike(platform);
  }

  async close(): Promise<void> {
    if (this.platform !== null) {
      await this.platform.close().catch(() => undefined);
      this.platform = null;
    }
  }

  private requirePlatform(): PlatformClientLike {
    if (this.platform === null) throw new Error("huly-bridge client is not connected");
    return this.platform;
  }

  /**
   * Resolves a markup attribute to markdown. Inline values (HTML/JSON/mentions
   * per the kimi-tag heuristic) convert locally; anything else is treated as a
   * collaborator blob ref and fetched via fetchMarkup.
   */
  private async resolveMarkupText(
    objectClass: string,
    objectId: string,
    value: string,
    attr: string,
  ): Promise<string> {
    if (value === "") return "";
    if (/[<{@\s]/.test(value)) return hulyMarkupToMarkdown(value);
    try {
      const fetched = await this.requirePlatform().fetchMarkup(objectClass, objectId, attr, value, "markdown");
      // Defensive: if the collaborator handed back raw PM-JSON, convert it.
      if (fetched.trimStart().startsWith("{")) return hulyMarkupToMarkdown(fetched);
      return fetched.trim();
    } catch {
      return hulyMarkupToMarkdown(value);
    }
  }

  // --- tracker ---

  private async resolveProject(projectRef: string): Promise<Record<string, unknown>> {
    const p = this.requirePlatform();
    const byId = await p.findOne(CLASS_PROJECT, { _id: projectRef });
    if (byId !== undefined) return byId;
    const byIdentifier = await p.findOne(CLASS_PROJECT, { identifier: projectRef.trim().toUpperCase() });
    if (byIdentifier !== undefined) return byIdentifier;
    throw new Error(
      `Project not found: "${projectRef}" — pass the project identifier (e.g. DEMO) or id; use tracker_list_projects to see them`,
    );
  }

  private async resolveIssue(issueId: string): Promise<Record<string, unknown> & DocLike> {
    const p = this.requirePlatform();
    // Read-after-write: a just-created issue can take a moment to become
    // visible to a fresh findOne through the tx pipeline. A couple of quick
    // retries make create→comment/update flows deterministic for callers.
    const attempts = 3;
    for (let i = 0; i < attempts; i++) {
      const byIdentifier = await p.findOne(CLASS_ISSUE, { identifier: issueId.trim().toUpperCase() });
      if (byIdentifier !== undefined) return byIdentifier as Record<string, unknown> & DocLike;
      const byId = await p.findOne(CLASS_ISSUE, { _id: issueId });
      if (byId !== undefined) return byId as Record<string, unknown> & DocLike;
      if (i < attempts - 1) await new Promise((r) => setTimeout(r, 350 * (i + 1)));
    }
    throw new Error(
      `Issue not found: "${issueId}" — pass an identifier (e.g. DEMO-1) or id; use tracker_search_issues to locate it`,
    );
  }

  async createIssue(input: CreateIssueInput): Promise<IssueCreated> {
    const p = this.requirePlatform();
    const project = await this.resolveProject(input.project);
    const projectId = String(project._id);
    const projectIdentifier = String(project.identifier);

    // Canonical recipe (kimi-tag / pod-github): atomic $inc of Project.sequence.
    const updated = (await p.updateDoc(CLASS_PROJECT, SPACE_CORE, projectId, { $inc: { sequence: 1 } }, true)) as {
      sequence?: number;
    };
    const number = updated.sequence ?? (typeof project.sequence === "number" ? project.sequence + 1 : 1);
    const identifier = `${projectIdentifier}-${number}`;

    const id = await p.addCollection(CLASS_ISSUE, projectId, NO_PARENT_ISSUE, CLASS_ISSUE, "subIssues", {
      title: input.title,
      // MarkupContent instance → the api-client auto-uploads to the collaborator
      // and stores the blob ref (the model type for Issue.description).
      description:
        input.description !== undefined && input.description !== "" ? markdown(input.description) : null,
      status: STATUS_REFS.backlog,
      priority: input.priority !== undefined ? resolvePriority(input.priority) : 0,
      kind: KIND_ISSUE,
      component: null,
      milestone: null,
      number,
      rank: `a${Date.now()}`,
      comments: 0,
      subIssues: 0,
      startDate: null,
      dueDate: null,
      parents: [],
      reportedTime: 0,
      remainingTime: 0,
      estimation: 0,
      reports: 0,
      relations: [],
      childInfo: [],
      identifier,
      assignee: input.assignee ?? null,
    });
    return { id, identifier, title: input.title, updatedAt: Date.now() };
  }

  async updateIssue(issueId: string, fields: UpdateIssueFields): Promise<IssueUpdated> {
    const p = this.requirePlatform();
    const issue = await this.resolveIssue(issueId);
    const ops: Record<string, unknown> = {};
    if (fields.status !== undefined) ops.status = resolveStatusRef(fields.status);
    if (fields.priority !== undefined) ops.priority = resolvePriority(fields.priority);
    if (fields.title !== undefined) ops.title = fields.title;
    if (fields.description !== undefined) {
      ops.description = fields.description !== "" ? markdown(fields.description) : null;
    }
    if (fields.assignee !== undefined) ops.assignee = fields.assignee;
    const updatedFields = Object.keys(ops);
    if (updatedFields.length === 0) {
      throw new Error(
        'Nothing to update: pass at least one of title/description/status/priority/assignee inside "fields"',
      );
    }
    await p.updateDoc(CLASS_ISSUE, String(issue.space ?? SPACE_CORE), String(issue._id), ops);
    return { identifier: String(issue.identifier), updated: updatedFields, updatedAt: Date.now() };
  }

  async commentIssue(issueId: string, message: string): Promise<CommentCreated> {
    const p = this.requirePlatform();
    const issue = await this.resolveIssue(issueId);
    // Issue comments are chunter ChatMessages in the 'comments' collection
    // (inline TypeMarkup — same recipe as kimi-tag's addComment).
    const id = await p.addCollection(
      CLASS_CHAT_MESSAGE,
      String(issue.space ?? SPACE_CORE),
      String(issue._id),
      CLASS_ISSUE,
      "comments",
      { message: markdownToHulyMarkup(message) },
    );
    return { id, issue: String(issue.identifier), updatedAt: Date.now() };
  }

  async searchIssues(filter: SearchIssuesFilter): Promise<IssueSummary[]> {
    const p = this.requirePlatform();
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    const query: Record<string, unknown> = {};
    if (filter.project !== undefined && filter.project !== "") {
      const project = await this.resolveProject(filter.project);
      query.space = project._id;
    }
    if (filter.status !== undefined && filter.status !== "") {
      query.status = resolveStatusRef(filter.status);
    }
    const docs = await p.findAll(CLASS_ISSUE, query);
    let issues = docs as Array<Record<string, unknown> & DocLike>;
    if (filter.query !== undefined && filter.query.trim() !== "") {
      const needle = filter.query.trim().toLowerCase();
      issues = issues.filter((i) => String(i.title ?? "").toLowerCase().includes(needle));
    }
    return issues
      .sort((a, b) => Number(a.number ?? 0) - Number(b.number ?? 0))
      .slice(0, limit)
      .map((i) => ({
        id: String(i._id),
        identifier: String(i.identifier),
        title: String(i.title ?? ""),
        status: statusName(String(i.status ?? "")),
        priority: priorityName(Number(i.priority ?? 0)),
        assignee: i.assignee !== null && i.assignee !== undefined ? String(i.assignee) : null,
        updatedAt: Number(i.modifiedOn ?? i.createdOn ?? 0),
      }));
  }

  async listProjects(): Promise<ProjectInfo[]> {
    const p = this.requirePlatform();
    const projects = await p.findAll(CLASS_PROJECT, {});
    const out: ProjectInfo[] = [];
    for (const raw of projects) {
      const issues = await p.findAll(CLASS_ISSUE, { space: raw._id });
      out.push({
        id: String(raw._id),
        identifier: String(raw.identifier ?? ""),
        name: String(raw.name ?? ""),
        issues: issues.length,
      });
    }
    return out.sort((a, b) => a.identifier.localeCompare(b.identifier));
  }

  // --- documents ---

  private async resolveTeamspace(teamspaceRef: string): Promise<Record<string, unknown>> {
    const p = this.requirePlatform();
    const byId = await p.findOne(CLASS_TEAMSPACE, { _id: teamspaceRef });
    if (byId !== undefined) return byId;
    const byName = await p.findOne(CLASS_TEAMSPACE, { name: teamspaceRef.trim() });
    if (byName !== undefined) return byName;
    throw new Error(
      `Teamspace not found: "${teamspaceRef}" — pass the teamspace name or id; use documents_list without a teamspace to see what exists`,
    );
  }

  private async resolveDocument(documentId: string): Promise<Record<string, unknown> & DocLike> {
    const p = this.requirePlatform();
    const doc = await p.findOne(CLASS_DOCUMENT, { _id: documentId });
    if (doc !== undefined) return doc as Record<string, unknown> & DocLike;
    throw new Error(
      `Document not found: "${documentId}" — pass a document id returned by documents_create or documents_list`,
    );
  }

  async createDocument(input: { teamspace: string; title: string; content: string }): Promise<DocumentCreated> {
    const p = this.requirePlatform();
    const teamspace = await this.resolveTeamspace(input.teamspace);
    // Document.content is a collaborative blob ref: MarkupContent auto-upload.
    const id = await p.createDoc(CLASS_DOCUMENT, String(teamspace._id), {
      title: input.title,
      content: markdown(input.content),
      parent: NO_PARENT_DOC,
      rank: `a${Date.now()}`,
      attachments: 0,
      embeddings: 0,
      labels: 0,
      comments: 0,
      references: 0,
    });
    return {
      id,
      title: input.title,
      teamspace: String(teamspace.name ?? teamspace._id),
      updatedAt: Date.now(),
    };
  }

  async readDocument(documentId: string): Promise<DocumentInfo> {
    const doc = await this.resolveDocument(documentId);
    const content =
      doc.content !== null && doc.content !== undefined && doc.content !== ""
        ? await this.resolveMarkupText(CLASS_DOCUMENT, String(doc._id), String(doc.content), "content")
        : "";
    return {
      id: String(doc._id),
      title: String(doc.title ?? ""),
      teamspace: String(doc.space ?? ""),
      content,
      updatedAt: Number(doc.modifiedOn ?? doc.createdOn ?? 0),
    };
  }

  async updateDocument(documentId: string, content: string): Promise<DocumentCreated> {
    const p = this.requirePlatform();
    const doc = await this.resolveDocument(documentId);
    await p.updateDoc(CLASS_DOCUMENT, String(doc.space ?? SPACE_CORE), String(doc._id), {
      content: markdown(content),
    });
    return {
      id: String(doc._id),
      title: String(doc.title ?? ""),
      teamspace: String(doc.space ?? ""),
      updatedAt: Date.now(),
    };
  }

  async listDocuments(filter: { teamspace?: string; limit?: number }): Promise<DocumentSummary[]> {
    const p = this.requirePlatform();
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    const query: Record<string, unknown> = {};
    if (filter.teamspace !== undefined && filter.teamspace !== "") {
      const teamspace = await this.resolveTeamspace(filter.teamspace);
      query.space = teamspace._id;
    }
    const docs = (await p.findAll(CLASS_DOCUMENT, query)) as Array<Record<string, unknown> & DocLike>;
    return docs
      .sort((a, b) => Number(b.modifiedOn ?? 0) - Number(a.modifiedOn ?? 0))
      .slice(0, limit)
      .map((d) => ({
        id: String(d._id),
        title: String(d.title ?? ""),
        teamspace: String(d.space ?? ""),
        updatedAt: Number(d.modifiedOn ?? d.createdOn ?? 0),
      }));
  }

  // --- chunter ---

  private async resolveChannel(channelRef: string): Promise<Record<string, unknown>> {
    const p = this.requirePlatform();
    const byId = await p.findOne(CLASS_CHANNEL, { _id: channelRef });
    if (byId !== undefined) return byId;
    const byName = await p.findOne(CLASS_CHANNEL, { name: channelRef.trim() });
    if (byName !== undefined) return byName;
    throw new Error(
      `Channel not found: "${channelRef}" — pass the channel name or id; use chunter_list_channels to see them`,
    );
  }

  async postMessage(input: { channel: string; message: string; thread?: string }): Promise<MessagePosted> {
    const p = this.requirePlatform();
    const channel = await this.resolveChannel(input.channel);
    const channelId = String(channel._id);

    if (input.thread === undefined || input.thread === "" || input.thread === channelId) {
      const id = await p.addCollection(CLASS_CHAT_MESSAGE, channelId, channelId, CLASS_CHANNEL, "messages", {
        message: markdownToHulyMarkup(input.message),
      });
      return { id, channel: String(channel.name ?? channelId), updatedAt: Date.now() };
    }

    // Thread reply: ThreadMessage attached to the parent message ('replies').
    const parent = await p.findOne(CLASS_CHAT_MESSAGE, { _id: input.thread });
    if (parent === undefined) {
      throw new Error(
        `Thread parent message not found: "${input.thread}" — pass a message id from chunter_list_messages, or omit "thread" to post in the channel`,
      );
    }
    const id = await p.addCollection(
      CLASS_THREAD_MESSAGE,
      String(parent.space ?? channelId),
      input.thread,
      CLASS_CHAT_MESSAGE,
      "replies",
      {
        message: markdownToHulyMarkup(input.message),
        objectId: parent.attachedTo ?? channelId,
        objectClass: parent.attachedToClass ?? CLASS_CHANNEL,
      },
    );
    return { id, channel: String(channel.name ?? channelId), thread: input.thread, updatedAt: Date.now() };
  }

  async listChannels(): Promise<ChannelInfo[]> {
    const p = this.requirePlatform();
    const channels = await p.findAll(CLASS_CHANNEL, {});
    return channels
      .map((c) => ({ id: String(c._id), name: String(c.name ?? "") }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async listMessages(filter: { channel: string; limit?: number; thread?: string }): Promise<MessageInfo[]> {
    const p = this.requirePlatform();
    const channel = await this.resolveChannel(filter.channel);
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;

    if (filter.thread !== undefined && filter.thread !== "") {
      // Thread history: parent message first, then its replies, oldest first.
      const out: MessageInfo[] = [];
      const parent = await p.findOne(CLASS_CHAT_MESSAGE, { _id: filter.thread });
      if (parent === undefined) {
        throw new Error(
          `Thread parent message not found: "${filter.thread}" — pass a message id from chunter_list_messages`,
        );
      }
      out.push({
        id: String(parent._id),
        author: String(parent.modifiedBy ?? ""),
        text: await this.resolveMarkupText(CLASS_CHAT_MESSAGE, String(parent._id), String(parent.message ?? ""), "message"),
        createdAt: Number(parent.createdOn ?? parent.modifiedOn ?? 0),
      });
      const replies = await p.findAll(CLASS_THREAD_MESSAGE, { attachedTo: filter.thread });
      const sorted = replies.sort((a, b) => Number(a.createdOn ?? 0) - Number(b.createdOn ?? 0));
      for (const r of sorted.slice(0, Math.max(0, limit - out.length))) {
        out.push({
          id: String(r._id),
          author: String(r.modifiedBy ?? ""),
          text: await this.resolveMarkupText(CLASS_THREAD_MESSAGE, String(r._id), String(r.message ?? ""), "message"),
          createdAt: Number(r.createdOn ?? r.modifiedOn ?? 0),
        });
      }
      return out;
    }

    const messages = await p.findAll(CLASS_CHAT_MESSAGE, { attachedTo: channel._id });
    const sorted = messages
      .sort((a, b) => Number(a.createdOn ?? 0) - Number(b.createdOn ?? 0))
      .slice(-limit);
    const out: MessageInfo[] = [];
    for (const m of sorted) {
      out.push({
        id: String(m._id),
        author: String(m.modifiedBy ?? ""),
        text: await this.resolveMarkupText(CLASS_CHAT_MESSAGE, String(m._id), String(m.message ?? ""), "message"),
        createdAt: Number(m.createdOn ?? m.modifiedOn ?? 0),
      });
    }
    return out;
  }

  // --- contact ---

  async listPersons(filter: { limit?: number }): Promise<PersonInfo[]> {
    const p = this.requirePlatform();
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 50;
    const persons = await p.findAll(CLASS_PERSON, {});
    return persons
      .map((person) => ({ id: String(person._id), name: String(person.name ?? "") }))
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit);
  }
}

// --- Factory -------------------------------------------------------------------

/**
 * Picks the backend from the environment (frozen contract):
 *   HULY_CLIENT_MOCK=1 → in-memory mock (no network, token not validated);
 *   otherwise          → real client (requires HULY_TOKEN / HULY_ENDPOINT / HULY_WORKSPACE).
 */
export function createHulyClient(env: NodeJS.ProcessEnv = process.env): HulyBridgeClient {
  if (env.HULY_CLIENT_MOCK === "1") return createMockClient();
  const missing = ["HULY_TOKEN", "HULY_ENDPOINT", "HULY_WORKSPACE"].filter((k) => {
    const v = env[k];
    return v === undefined || v.trim() === "";
  });
  if (missing.length > 0) {
    throw new Error(
      `huly-bridge: missing required env ${missing.join(", ")} — the gateway injects them via the upstream's transport.env (or set HULY_CLIENT_MOCK=1 for the in-memory mock)`,
    );
  }
  return new RealHulyClient({
    token: env.HULY_TOKEN as string,
    endpoint: env.HULY_ENDPOINT as string,
    workspace: env.HULY_WORKSPACE as string,
  });
}
