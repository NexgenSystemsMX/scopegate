# railway-bridge (EPIC-16)

MCP stdio server that exposes Railway operations as tools, deployable as a
stdio upstream of the ScopeGate gateway, over the Railway public GraphQL API
(backboard v2). Zero new npm dependencies: the real client uses native
`fetch`.

The agent never sees the Railway token: the gateway injects it into the bridge
process environment at spawn (minter/`transport.env`, see
`registry/railway.yaml` — auth type `env`), and the bridge only sends it in
the `Authorization: Bearer` header.

## Env contract (frozen)

| Var | Required | Meaning |
| --- | --- | --- |
| `RAILWAY_TOKEN` | live mode | Railway API token, injected by the gateway. Never logged, never embedded in errors, never validated in mock mode. |
| `RAILWAY_API_URL` | optional | GraphQL endpoint. Default `https://backboard.railway.com/graphql/v2`. |
| `RAILWAY_MOCK` | optional | `1` → in-memory mock (`mock-client.ts`), no network. Used by `tests/railway-bridge.test.ts` and `e2e-railway.mjs`. |

A missing token in live mode aborts startup with an actionable stderr message
pointing at `scopegate secret add railway_token`. stdout is reserved for MCP
framing; logs go to stderr only, without secrets.

## Tools (7, bare names — the gateway adds the `railway__` namespace)

- `list_services` `{projectId?}` — without `projectId` lists every accessible
  project with its services grouped; with it, just that project.
- `service_status` `{service, projectId?}` — latest deployment: `status`,
  `createdAt`, `url` (when the deployment exposes one).
- `deploy` `{service, projectId?}` — triggers a NEW deployment
  (`serviceInstanceDeployV2`), returns an acceptance with the deployment id.
- `redeploy` `{service, projectId?}` — redeploys the latest deployment
  (`deploymentRedeploy`), returns an acceptance.
- `get_logs` `{service, lines?=100, projectId?}` — deploy (runtime) logs of
  the latest deployment (`deploymentLogs`), most recent last.
- `variables_list` `{service, projectId?}` — variable NAMES only (see
  redaction below).
- `domain_status` `{service, projectId?}` — `serviceDomains` +
  `customDomains` (with DNS status).

`service` accepts a name (case-insensitive) or an id. When `projectId` is
omitted the service is resolved across every accessible project: zero matches
→ *service not found*; more than one → *ambiguous, pass projectId*; both
distinct from the *project not found* error of an unknown `projectId`.

Responses are compact JSON. Errors are MCP `isError` results with actionable
messages (what to pass, which listing tool to use, where to deposit the
token).

## Redaction (hard contract)

`variables_list` never returns values. Any value the API returns is replaced
by `"[redacted]"` inside the client (`client.ts`), before anything leaves the
bridge — the mock applies the same rule, and both the unit tests and the e2e
assert that no seeded value leaks.

## Real client (decision)

GraphQL shapes verified against the official Railway API cookbook
(`railwayapp/docs`, `content/docs/integrations/api/*`):

- Reads: `projects` / `project(id)` (with `services` + `environments`
  connections), `deployments(input, first: 1)`, `deploymentLogs`, `variables`,
  `domains`.
- Writes: `serviceInstanceDeployV2(serviceId, environmentId)` → deployment id
  scalar; `deploymentRedeploy(id)` → `Deployment`.

One POST per call, `Authorization: Bearer <token>`, 15 s timeout
(`AbortSignal.timeout`). HTTP 401/403 and "unauthorized"-style GraphQL errors
are normalized to an actionable deposit-the-token message; other GraphQL
errors surface as `Railway API error: <message>` — never with the token.

## Mock mode

`RAILWAY_MOCK=1` selects an in-memory client with the same semantics, seeded
deterministically: projects `Demo Project` (services `api` — SUCCESS with url,
variables, domains, logs — and `worker` — FAILED) and `Infra` (services
`worker` — BUILDING, a deliberate duplicate to exercise the ambiguous-service
error — and `postgres` — no deployments). The token is not validated.
`deploy`/`redeploy` mutate the mock state like the real API would.

## Deployment as a gateway upstream

```yaml
upstreams:
  - name: railway
    transport:
      kind: stdio
      command: node
      args: [dist/upstreams/railway-bridge/server.js]
      env:
        RAILWAY_TOKEN: <injected-by-minter>
    auth: { type: none }   # the bridge authenticates with RAILWAY_TOKEN itself
```

Policies gate calls per tool: `railway:call:deploy`, `railway:call:*`, …
(`registry/railway.yaml` recommends `require: human_approval` for the write
tools).

## Files

- `client.ts` — semantic client interface, real client over the backboard
  GraphQL API (native fetch, bearer auth, 15 s timeout), service/project/
  environment resolution, hard variable redaction, and the env-driven factory.
- `mock-client.ts` — in-memory implementation (self-contained spec of the
  bridge semantics; constants/helpers duplicated on purpose to avoid an
  import cycle).
- `tools.ts` — tool schemas + arg validation + handlers.
- `server.ts` — MCP stdio server (`createBridgeServer` is transport-agnostic
  and unit-tested over `InMemoryTransport`).

## Verification

```sh
npm run build
npx vitest run tests/railway-bridge.test.ts
node e2e-railway.mjs                       # full gateway e2e in mock mode
```
