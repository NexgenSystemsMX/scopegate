# google-bridge (EPIC-18)

MCP stdio server that exposes Google Workspace (Drive, Gmail, Calendar) as
tools, deployable as a stdio upstream of the ScopeGate gateway.

The agent never sees Google credentials: the gateway mints a ~1h access token
from the service-account key in the vault (`google_sa` minter provider — RS256
JWT exchanged at `oauth2.googleapis.com/token`, same pattern as `github_app`)
and injects it into the bridge process environment at spawn. The SA private
key never leaves the vault.

## Env contract (frozen)

| Var | Required | Meaning |
| --- | --- | --- |
| `GOOGLE_ACCESS_TOKEN` | live mode | Access token, injected by the gateway via the minter. Never logged, never validated in mock mode. |
| `GOOGLE_API_URL` | optional | API base URL. Default: `https://www.googleapis.com`. |
| `GOOGLE_MOCK` | optional | `1` → in-memory mock (`mock-client.ts`), no network. Used by `tests/google-bridge.test.ts` and `e2e-google.mjs`. |

A missing token in live mode aborts startup with an actionable stderr message.
stdout is reserved for MCP framing; logs go to stderr only, without secrets.

## Scopes (minted token)

The `google_sa` provider requests these scopes by default (frozen):

- `https://www.googleapis.com/auth/drive.readonly` — drive_list / drive_search / drive_read
- `https://www.googleapis.com/auth/gmail.send` — gmail_send
- `https://www.googleapis.com/auth/calendar.readonly` — calendar_list

To widen them, set `auth.scopes` on the upstream config (and grant the same
scopes to the service account, or to its client id under domain-wide
delegation when the vault blob sets `subject`). Common additions:

- `https://www.googleapis.com/auth/calendar.events` — **calendar_create**
- `https://www.googleapis.com/auth/gmail.readonly` — gmail_list against inboxes
  beyond the token's granted set
- `https://www.googleapis.com/auth/drive` — Drive write operations

A 401 surfaces as "token rejected — retry to force a re-mint / re-check the
vault blob"; a 403 as "insufficient scope — widen `auth.scopes` …". Neither
ever carries the token.

## Tools (7, bare names — the gateway adds the `google__` namespace)

- **drive**: `drive_list` `{query?, limit?}` (name substring filter),
  `drive_search` `{query, limit?}` (full-text),
  `drive_read` `{fileId}` — metadata plus content. Raw text files are read as
  UTF-8; Google Docs/Sheets/Slides are exported to text (`text/plain` /
  `text/csv`); other `application/vnd.google-apps.*` types and binary files
  return metadata with a `note` instead of content. **Content is capped at
  1 MiB** (`DRIVE_READ_MAX_CHARS` = 1 048 576 chars): larger texts return the
  first 1 MiB with `truncated: true` and a note.
- **gmail**: `gmail_send` `{to, subject, body, cc?}` — builds an RFC 822
  `text/plain` message (header-injection safe; non-ASCII subjects are RFC 2047
  encoded) and uploads it base64url as `raw`. `gmail_list` `{query?, limit?}`
  returns `{id, threadId, subject, from, date, snippet}` per message.
- **calendar**: `calendar_list` `{calendarId?=primary, limit?, timeMin?=now}`
  (single events, ordered by start), `calendar_create`
  `{summary, start, end, attendees?, calendarId?=primary, description?}` —
  `start`/`end` are ISO 8601 datetimes, or `YYYY-MM-DD` for all-day events.

Responses are compact JSON. Errors are MCP `isError` results with actionable
messages (what to pass, which listing tool to use, which scope/flow to fix).

## Mock mode

`GOOGLE_MOCK=1` selects an in-memory client with the same semantics, seeded
deterministically: files `Roadmap.md` (markdown), `Team budget` (Sheet),
`Spec doc` (Doc), `logo.pdf` (binary); messages from `ada@example.com` and
`billing@vendor.io`; one `Daily standup` event in `primary`. The token is not
validated. The drive_read cap is applied in the tools layer, identical to the
real backend path.

## Deployment as a gateway upstream

```yaml
upstreams:
  - name: google
    transport:
      kind: stdio
      command: node
      args: [dist/upstreams/google-bridge/server.js]
    auth:
      type: google_sa
      secretRef: google_sa        # vault blob {client_email, private_key, subject?}
      # scopes: [...]             # optional widening (see Scopes above)
```

The gateway injects `GOOGLE_ACCESS_TOKEN` at spawn (minted from the vault
blob). Policies gate calls per tool: `google:call:drive_read`,
`google:call:*`, …

## Files

- `client.ts` — semantic client interface, real client over the Google REST
  APIs (native fetch, no new dependencies), RFC 822 construction, Drive
  export/text rules, the shared error mapping, and the env-driven factory.
- `mock-client.ts` — in-memory implementation (self-contained spec of the
  bridge semantics).
- `tools.ts` — the 7 tool schemas + arg validation + handlers; the drive_read
  1 MiB cap is applied here (`capDriveContent`).
- `server.ts` — MCP stdio server (`createBridgeServer` is transport-agnostic
  and unit-tested over `InMemoryTransport`).

## Verification

```sh
npm run build
npx vitest run tests/google-bridge.test.ts tests/google-sa.test.ts
node e2e-google.mjs                        # full gateway e2e in mock mode
```
