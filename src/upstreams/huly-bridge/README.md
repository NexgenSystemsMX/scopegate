# huly-bridge (EPIC-14)

MCP stdio server that exposes the four Huly surfaces as tools, deployable as a
stdio upstream of the ScopeGate gateway. One Huly workspace replaces
Jira + Linear (tracker), Notion (documents) and Slack (chunter), plus the
contacts directory (contact).

The agent never sees the Huly token: the gateway injects it into the bridge
process environment at spawn (minter/`transport.env`), and the bridge talks to
the Huly transactor over websocket.

## Env contract (frozen)

| Var | Required | Meaning |
| --- | --- | --- |
| `HULY_TOKEN` | live mode | Workspace token, injected by the gateway. Never logged, never validated in mock mode. |
| `HULY_ENDPOINT` | live mode | Huly base URL. A `wss://` transactor URL is normalized to `https://` (the client fetches `<base>/config.json` and negotiates the real transactor endpoint via `selectWorkspace`). |
| `HULY_WORKSPACE` | live mode | Workspace name. |
| `HULY_CLIENT_MOCK` | optional | `1` → in-memory mock (`mock-client.ts`), no network. Used by `tests/huly-bridge.test.ts` and `e2e-huly.mjs`. |

Missing vars in live mode abort startup with an actionable stderr message.
stdout is reserved for MCP framing; logs go to stderr only, without secrets.

## Tools (16, bare names — the gateway adds the `huly__` namespace)

- **tracker**: `tracker_create_issue` `{project, title, description?, priority?, assignee?, status?}`,
  `tracker_update_issue` `{issueId, fields}` (fields: `title`, `description`, `status`,
  `priority`, `assignee`, `milestone`, `dueDate` — ISO date, `""` clears),
  `tracker_comment_issue` `{issueId, message}`,
  `tracker_search_issues` `{query?, project?, status?, assignee?, limit?}`,
  `tracker_read_issue` `{issueId}` (full issue incl. markdown description),
  `tracker_read_comments` `{issueId, limit?}`, `tracker_list_projects` `{}`.
- **documents**: `documents_create` `{teamspace, title, content}`,
  `documents_read` `{documentId}`, `documents_update` `{documentId, content}`,
  `documents_list` `{teamspace?, limit?}`.
- **chunter**: `chunter_post_message` `{channel, message, thread?, thinking?}`
  (`thinking: true` prefixes the body with `💭 ` — Huly chat has no native
  thinking flag), `chunter_edit_message` `{channel, messageId, content}`,
  `chunter_list_channels` `{}`, `chunter_list_messages` `{channel, limit?, thread?}`.
- **contact**: `contact_list_persons` `{limit?}`.

Responses are compact JSON (`id`, `title`/`name`, `updatedAt`, …). Errors are
MCP `isError` results with actionable messages (what to pass, which listing
tool to use). Status names: `backlog|todo|in_progress|done|canceled`;
priority: `urgent|high|medium|low|none` or `0-4`.

## Content conversion (decision)

The tool surface speaks **markdown in and out**; Huly markup only exists at
the real-client boundary (`client.ts`):

- **Inline ProseMirror markup** (chunter messages, issue comments — model
  `TypeMarkup`): written with `markdownToHulyMarkup()`
  (`jsonToMarkup(markdownToMarkup(...))`, the canonical shape the official
  Huly ai-bot uses), read back with `hulyMarkupToMarkdown()`
  (`markupToMarkdown(markupToJSON(...))`, falling back to `markupToText`
  plain-text extraction and finally to the raw value — a response never
  carries a giant raw markup blob).
- **Collaborative blob refs** (issue description, document content — model
  `MarkupBlobRef`): written through the api-client's `MarkupContent`
  auto-upload (`markdown()` helper → collaborator upload + ref storage), read
  back via `fetchMarkup(..., "markdown")`. Reads additionally tolerate legacy
  inline values (the kimi-tag heuristic: inline values contain `<`, `{`, `@`
  or whitespace).

Class refs are raw strings (`tracker:class:Issue`, `chunter:class:Channel`,
`document:class:Document`, `document:class:Teamspace`, `contact:class:Person`,
`chunter:class:ChatMessage`, `chunter:class:ThreadMessage`) so no UI plugin
dependencies are dragged in. Issue creation uses the canonical atomic
`$inc Project.sequence` recipe (verified in production by kimi-tag and the
official pod-github). Thread replies are `ThreadMessage` docs attached to the
parent message (`replies` collection + `objectId`/`objectClass`).

## Mock mode

`HULY_CLIENT_MOCK=1` selects an in-memory client with the same semantics,
seeded deterministically: project `DEMO`, teamspace `general`, channels
`general`/`random`, persons `Ada Lovelace`/`Grace Hopper`. The token is not
validated. Markdown is stored verbatim (no markup conversion in the mock).

## Deployment as a gateway upstream

```yaml
upstreams:
  - name: huly
    transport:
      kind: stdio
      command: node
      args: [dist/upstreams/huly-bridge/server.js]
      env:
        HULY_TOKEN: <injected-by-minter>
        HULY_ENDPOINT: wss://huly2.nexgen.systems
        HULY_WORKSPACE: nexgen
    auth: { type: none }   # the bridge authenticates with HULY_TOKEN itself
```

Policies gate calls per tool: `huly:call:tracker_create_issue`, `huly:call:*`, …

## Files

- `client.ts` — semantic client interface, real client over
  `@hcengineering/api-client` (token auth + `NodeWebSocketFactory`), markup
  conversion, status/priority maps, and the env-driven factory.
- `mock-client.ts` — in-memory implementation (self-contained spec of the
  bridge semantics; status/priority maps duplicated on purpose to avoid an
  import cycle).
- `tools-tracker.ts` / `tools-documents.ts` / `tools-chunter.ts` /
  `tools-contact.ts` — tool schemas + arg validation + handlers.
- `server.ts` — MCP stdio server (`createBridgeServer` is transport-agnostic
  and unit-tested over `InMemoryTransport`).
- `huly-modules.d.ts` — ambient declarations for the `@hcengineering/*`
  packages: the 0.7.423 tarballs point their `types` field at a folder that is
  not shipped, so the modules are declared untyped (consumed as CJS via
  default import + destructure, the kimi-tag interop pattern). No new npm
  dependencies were added.

## Verification

```sh
npm run build
npx vitest run tests/huly-bridge.test.ts   # 27 tests
node e2e-huly.mjs                          # full gateway e2e in mock mode
```
