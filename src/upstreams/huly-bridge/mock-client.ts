/**
 * In-memory mock of HulyBridgeClient (EPIC-14) — same semantics as the real
 * client, backed by plain Maps. Used when HULY_CLIENT_MOCK=1: unit tests and
 * the local e2e run WITHOUT a live Huly instance (the token is not validated).
 *
 * The mock works at the semantic level: it stores markdown/text exactly as
 * received (markup conversion only exists at the real-client boundary), so a
 * write→read round-trip through the mock returns the original markdown.
 *
 * Seeded state (deterministic, so tests/e2e can assert against it):
 *   - project   "Demo Project"   (identifier DEMO)
 *   - teamspace "general"
 *   - channels  "general", "random"
 *   - persons   "Ada Lovelace", "Grace Hopper"
 *
 * The status/priority maps intentionally duplicate the domain knowledge in
 * client.ts (kept independent so there is no import cycle and the mock can be
 * read as a standalone spec of the bridge semantics).
 */
import type {
  ChannelInfo,
  CommentCreated,
  CreateIssueInput,
  DocumentCreated,
  DocumentInfo,
  DocumentSummary,
  HulyBridgeClient,
  IssueComment,
  IssueCreated,
  IssueDetails,
  IssueSummary,
  IssueUpdated,
  MessageEdited,
  MessageInfo,
  MessagePosted,
  PersonInfo,
  ProjectInfo,
  SearchIssuesFilter,
  UpdateIssueFields,
} from "./client.js";

const STATUS_REFS: Record<string, string> = {
  backlog: "tracker:status:Backlog",
  todo: "tracker:status:Todo",
  in_progress: "tracker:status:InProgress",
  done: "tracker:status:Done",
  canceled: "tracker:status:Canceled",
};

const STATUS_NAMES: Record<string, string> = Object.fromEntries(
  Object.entries(STATUS_REFS).map(([name, ref]) => [ref, name]),
);

const PRIORITY_VALUES: Record<string, number> = {
  none: 0,
  urgent: 1,
  high: 2,
  medium: 3,
  low: 4,
};

const PRIORITY_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(PRIORITY_VALUES).map(([name, v]) => [v, name]),
) as Record<number, string>;

function resolveStatusRef(input: string): string {
  const friendly = input.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (STATUS_REFS[friendly] !== undefined) return STATUS_REFS[friendly];
  if (input.startsWith("tracker:status:")) return input;
  throw new Error(
    `Invalid status "${input}". Valid: ${Object.keys(STATUS_REFS).join(", ")} (or a tracker:status:* ref)`,
  );
}

function resolvePriority(input: string | number): number {
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

function resolveDueDate(input: string): number | null {
  const trimmed = input.trim();
  if (trimmed === "") return null;
  const ts = Date.parse(trimmed);
  if (Number.isNaN(ts)) {
    throw new Error(`Invalid dueDate "${input}" — pass an ISO date (e.g. 2026-08-01) or "" to clear it`);
  }
  return ts;
}

interface MockIssue {
  id: string;
  identifier: string;
  projectId: string;
  title: string;
  description: string;
  status: string;
  priority: number;
  assignee: string | null;
  milestone: string | null;
  dueDate: number | null;
  number: number;
  updatedAt: number;
}

interface MockDocument {
  id: string;
  teamspaceId: string;
  title: string;
  content: string;
  updatedAt: number;
}

interface MockMessage {
  id: string;
  channelId: string;
  thread?: string;
  author: string;
  text: string;
  createdAt: number;
}

export class MockHulyClient implements HulyBridgeClient {
  private seq = 0;
  private readonly projects = new Map<string, { id: string; identifier: string; name: string; sequence: number }>();
  private readonly issues = new Map<string, MockIssue>();
  private readonly comments: Array<{ id: string; issueId: string; author: string; text: string; createdAt: number }> = [];
  private readonly teamspaces = new Map<string, { id: string; name: string }>();
  private readonly documents = new Map<string, MockDocument>();
  private readonly channels = new Map<string, { id: string; name: string }>();
  private readonly messages: MockMessage[] = [];
  private readonly persons: PersonInfo[] = [];

  constructor(private readonly now: () => number = () => Date.now()) {
    this.projects.set("mock-project-1", { id: "mock-project-1", identifier: "DEMO", name: "Demo Project", sequence: 0 });
    this.teamspaces.set("mock-teamspace-1", { id: "mock-teamspace-1", name: "general" });
    this.channels.set("mock-channel-1", { id: "mock-channel-1", name: "general" });
    this.channels.set("mock-channel-2", { id: "mock-channel-2", name: "random" });
    this.persons.push({ id: "mock-person-1", name: "Ada Lovelace" }, { id: "mock-person-2", name: "Grace Hopper" });
  }

  private nextId(prefix: string): string {
    this.seq += 1;
    return `${prefix}-${this.seq}`;
  }

  async connect(): Promise<void> {}
  async close(): Promise<void> {}

  // --- tracker ---

  private resolveProject(ref: string): { id: string; identifier: string; name: string; sequence: number } {
    for (const p of this.projects.values()) {
      if (p.id === ref || p.identifier === ref.trim().toUpperCase()) return p;
    }
    const known = [...this.projects.values()].map((p) => p.identifier).join(", ");
    throw new Error(`Project not found: "${ref}" — available projects: ${known} (tracker_list_projects)`);
  }

  private resolveIssue(issueId: string): MockIssue {
    for (const issue of this.issues.values()) {
      if (issue.id === issueId || issue.identifier === issueId.trim().toUpperCase()) return issue;
    }
    throw new Error(
      `Issue not found: "${issueId}" — pass an identifier (e.g. DEMO-1) or id; use tracker_search_issues to locate it`,
    );
  }

  async createIssue(input: CreateIssueInput): Promise<IssueCreated> {
    const project = this.resolveProject(input.project);
    project.sequence += 1;
    const identifier = `${project.identifier}-${project.sequence}`;
    const issue: MockIssue = {
      id: this.nextId("mock-issue"),
      identifier,
      projectId: project.id,
      title: input.title,
      description: input.description ?? "",
      status: input.status !== undefined ? resolveStatusRef(input.status) : STATUS_REFS.backlog,
      priority: input.priority !== undefined ? resolvePriority(input.priority) : 0,
      assignee: input.assignee ?? null,
      milestone: null,
      dueDate: null,
      number: project.sequence,
      updatedAt: this.now(),
    };
    this.issues.set(issue.id, issue);
    return { id: issue.id, identifier, title: issue.title, updatedAt: issue.updatedAt };
  }

  async updateIssue(issueId: string, fields: UpdateIssueFields): Promise<IssueUpdated> {
    const issue = this.resolveIssue(issueId);
    const updated: string[] = [];
    if (fields.status !== undefined) {
      issue.status = resolveStatusRef(fields.status);
      updated.push("status");
    }
    if (fields.priority !== undefined) {
      issue.priority = resolvePriority(fields.priority);
      updated.push("priority");
    }
    if (fields.title !== undefined) {
      issue.title = fields.title;
      updated.push("title");
    }
    if (fields.description !== undefined) {
      issue.description = fields.description;
      updated.push("description");
    }
    if (fields.assignee !== undefined) {
      issue.assignee = fields.assignee;
      updated.push("assignee");
    }
    if (fields.milestone !== undefined) {
      issue.milestone = fields.milestone !== "" ? fields.milestone : null;
      updated.push("milestone");
    }
    if (fields.dueDate !== undefined) {
      issue.dueDate = resolveDueDate(fields.dueDate);
      updated.push("dueDate");
    }
    if (updated.length === 0) {
      throw new Error(
        'Nothing to update: pass at least one of title/description/status/priority/assignee/milestone/dueDate inside "fields"',
      );
    }
    issue.updatedAt = this.now();
    return { identifier: issue.identifier, updated, updatedAt: issue.updatedAt };
  }

  async commentIssue(issueId: string, message: string): Promise<CommentCreated> {
    const issue = this.resolveIssue(issueId);
    const id = this.nextId("mock-comment");
    this.comments.push({ id, issueId: issue.id, author: "mock-bot", text: message, createdAt: this.now() });
    issue.updatedAt = this.now();
    return { id, issue: issue.identifier, updatedAt: issue.updatedAt };
  }

  async searchIssues(filter: SearchIssuesFilter): Promise<IssueSummary[]> {
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    let issues = [...this.issues.values()];
    if (filter.project !== undefined && filter.project !== "") {
      const project = this.resolveProject(filter.project);
      issues = issues.filter((i) => i.projectId === project.id);
    }
    if (filter.status !== undefined && filter.status !== "") {
      const statusRef = resolveStatusRef(filter.status);
      issues = issues.filter((i) => i.status === statusRef);
    }
    if (filter.assignee !== undefined && filter.assignee !== "") {
      issues = issues.filter((i) => i.assignee === filter.assignee);
    }
    if (filter.query !== undefined && filter.query.trim() !== "") {
      const needle = filter.query.trim().toLowerCase();
      issues = issues.filter((i) => i.title.toLowerCase().includes(needle));
    }
    return issues
      .sort((a, b) => a.number - b.number)
      .slice(0, limit)
      .map((i) => ({
        id: i.id,
        identifier: i.identifier,
        title: i.title,
        status: STATUS_NAMES[i.status] ?? i.status,
        priority: PRIORITY_NAMES[i.priority] ?? String(i.priority),
        assignee: i.assignee,
        updatedAt: i.updatedAt,
      }));
  }

  async readIssue(issueId: string): Promise<IssueDetails> {
    const issue = this.resolveIssue(issueId);
    const project = this.projects.get(issue.projectId);
    return {
      id: issue.id,
      identifier: issue.identifier,
      title: issue.title,
      description: issue.description,
      status: STATUS_NAMES[issue.status] ?? issue.status,
      priority: PRIORITY_NAMES[issue.priority] ?? String(issue.priority),
      assignee: issue.assignee,
      project: project?.identifier ?? issue.projectId,
    };
  }

  async readComments(issueId: string, limit?: number): Promise<IssueComment[]> {
    const issue = this.resolveIssue(issueId);
    const lim = limit !== undefined && limit > 0 ? Math.floor(limit) : 20;
    return this.comments
      .filter((c) => c.issueId === issue.id)
      .sort((a, b) => a.createdAt - b.createdAt)
      .slice(-lim)
      .map((c) => ({ id: c.id, author: c.author, text: c.text, createdAt: c.createdAt }));
  }

  async listProjects(): Promise<ProjectInfo[]> {
    return [...this.projects.values()]
      .map((p) => ({
        id: p.id,
        identifier: p.identifier,
        name: p.name,
        issues: [...this.issues.values()].filter((i) => i.projectId === p.id).length,
      }))
      .sort((a, b) => a.identifier.localeCompare(b.identifier));
  }

  // --- documents ---

  private resolveTeamspace(ref: string): { id: string; name: string } {
    for (const t of this.teamspaces.values()) {
      if (t.id === ref || t.name === ref.trim()) return t;
    }
    const known = [...this.teamspaces.values()].map((t) => t.name).join(", ");
    throw new Error(`Teamspace not found: "${ref}" — available teamspaces: ${known}`);
  }

  private resolveDocument(documentId: string): MockDocument {
    const doc = this.documents.get(documentId);
    if (doc !== undefined) return doc;
    throw new Error(
      `Document not found: "${documentId}" — pass a document id returned by documents_create or documents_list`,
    );
  }

  async createDocument(input: { teamspace: string; title: string; content: string }): Promise<DocumentCreated> {
    const teamspace = this.resolveTeamspace(input.teamspace);
    const doc: MockDocument = {
      id: this.nextId("mock-doc"),
      teamspaceId: teamspace.id,
      title: input.title,
      content: input.content,
      updatedAt: this.now(),
    };
    this.documents.set(doc.id, doc);
    return { id: doc.id, title: doc.title, teamspace: teamspace.name, updatedAt: doc.updatedAt };
  }

  async readDocument(documentId: string): Promise<DocumentInfo> {
    const doc = this.resolveDocument(documentId);
    const teamspace = this.teamspaces.get(doc.teamspaceId);
    return {
      id: doc.id,
      title: doc.title,
      teamspace: teamspace?.name ?? doc.teamspaceId,
      content: doc.content,
      updatedAt: doc.updatedAt,
    };
  }

  async updateDocument(documentId: string, content: string): Promise<DocumentCreated> {
    const doc = this.resolveDocument(documentId);
    doc.content = content;
    doc.updatedAt = this.now();
    const teamspace = this.teamspaces.get(doc.teamspaceId);
    return { id: doc.id, title: doc.title, teamspace: teamspace?.name ?? doc.teamspaceId, updatedAt: doc.updatedAt };
  }

  async listDocuments(filter: { teamspace?: string; limit?: number }): Promise<DocumentSummary[]> {
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    let docs = [...this.documents.values()];
    if (filter.teamspace !== undefined && filter.teamspace !== "") {
      const teamspace = this.resolveTeamspace(filter.teamspace);
      docs = docs.filter((d) => d.teamspaceId === teamspace.id);
    }
    return docs
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, limit)
      .map((d) => ({
        id: d.id,
        title: d.title,
        teamspace: this.teamspaces.get(d.teamspaceId)?.name ?? d.teamspaceId,
        updatedAt: d.updatedAt,
      }));
  }

  // --- chunter ---

  private resolveChannel(ref: string): { id: string; name: string } {
    for (const c of this.channels.values()) {
      if (c.id === ref || c.name === ref.trim()) return c;
    }
    const known = [...this.channels.values()].map((c) => c.name).join(", ");
    throw new Error(`Channel not found: "${ref}" — available channels: ${known} (chunter_list_channels)`);
  }

  async postMessage(input: { channel: string; message: string; thread?: string }): Promise<MessagePosted> {
    const channel = this.resolveChannel(input.channel);
    if (input.thread !== undefined && input.thread !== "") {
      const parent = this.messages.find((m) => m.id === input.thread);
      if (parent === undefined) {
        throw new Error(
          `Thread parent message not found: "${input.thread}" — pass a message id from chunter_list_messages, or omit "thread" to post in the channel`,
        );
      }
      const msg: MockMessage = {
        id: this.nextId("mock-msg"),
        channelId: channel.id,
        thread: input.thread,
        author: "mock-bot",
        text: input.message,
        createdAt: this.now(),
      };
      this.messages.push(msg);
      return { id: msg.id, channel: channel.name, thread: input.thread, updatedAt: msg.createdAt };
    }
    const msg: MockMessage = {
      id: this.nextId("mock-msg"),
      channelId: channel.id,
      author: "mock-bot",
      text: input.message,
      createdAt: this.now(),
    };
    this.messages.push(msg);
    return { id: msg.id, channel: channel.name, updatedAt: msg.createdAt };
  }

  async editMessage(input: { channel: string; messageId: string; content: string }): Promise<MessageEdited> {
    const channel = this.resolveChannel(input.channel);
    const msg = this.messages.find((m) => m.id === input.messageId);
    if (msg === undefined || msg.channelId !== channel.id) {
      throw new Error(
        `Message not found: "${input.messageId}" in channel "${channel.name}" — pass a message id from chunter_list_messages`,
      );
    }
    msg.text = input.content;
    return { id: msg.id, channel: channel.name, updatedAt: this.now() };
  }

  async listChannels(): Promise<ChannelInfo[]> {
    return [...this.channels.values()]
      .map((c) => ({ id: c.id, name: c.name }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async listMessages(filter: { channel: string; limit?: number; thread?: string }): Promise<MessageInfo[]> {
    const channel = this.resolveChannel(filter.channel);
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 20;
    let msgs: MockMessage[];
    if (filter.thread !== undefined && filter.thread !== "") {
      const parent = this.messages.find((m) => m.id === filter.thread);
      if (parent === undefined) {
        throw new Error(
          `Thread parent message not found: "${filter.thread}" — pass a message id from chunter_list_messages`,
        );
      }
      msgs = [parent, ...this.messages.filter((m) => m.thread === filter.thread)];
    } else {
      msgs = this.messages.filter((m) => m.channelId === channel.id && m.thread === undefined);
    }
    return msgs
      .sort((a, b) => a.createdAt - b.createdAt)
      .slice(0, limit)
      .map((m) => ({ id: m.id, author: m.author, text: m.text, createdAt: m.createdAt }));
  }

  // --- contact ---

  async listPersons(filter: { limit?: number }): Promise<PersonInfo[]> {
    const limit = filter.limit !== undefined && filter.limit > 0 ? Math.floor(filter.limit) : 50;
    return this.persons.slice(0, limit);
  }
}

export function createMockClient(now?: () => number): MockHulyClient {
  return new MockHulyClient(now);
}
