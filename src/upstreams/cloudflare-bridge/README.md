# cloudflare-bridge (EPIC-17)

MCP stdio server that operates Cloudflare via the API v4 — zones, DNS
records, Workers, Pages projects and R2 buckets — deployable as a stdio
upstream of the ScopeGate gateway.

The agent never sees the API token: the gateway injects it into the bridge
process environment at spawn (`transport.env`, see `registry/cloudflare.yaml`,
auth type `env`), and the bridge only sends it as the `Authorization: Bearer`
header. It is never logged and never embedded in error messages.

## Env contract (frozen)

| Var | Required | Meaning |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | live mode | Scoped API token, injected by the gateway. Never logged, never validated in mock mode. |
| `CLOUDFLARE_API_URL` | optional | API base URL. Default `https://api.cloudflare.com/client/v4`. |
| `CLOUDFLARE_MOCK` | optional | `1` → in-memory mock (`mock-client.ts`), no network. Used by `tests/cloudflare-bridge.test.ts` and `e2e-cloudflare.mjs`. |

A missing token in live mode aborts startup with an actionable stderr message.
stdout is reserved for MCP framing; logs go to stderr only, without secrets.

## Tools (8, bare names — the gateway adds the `cloudflare__` namespace)

- `list_zones` `{}`
- `dns_list` `{zone, type?, name?}` — `zone` by name (`example.com`) or id;
  `type`/`name` are exact-match filters (type is case-insensitive).
- `dns_create` `{zone, type, name, content, ttl?, proxied?}`
- `dns_update` `{zone, recordId, type?, name?, content?, ttl?, proxied?}` —
  at least one field required.
- `dns_delete` `{zone, recordId}` — the bridge imposes NO extra check; the
  gateway POLICY gates it (`require: human_approval`).
- `workers_list` `{accountId?}`
- `pages_projects` `{accountId?}`
- `r2_buckets` `{accountId?}`

**accountId resolution:** when `accountId` is omitted, the bridge resolves it
via `GET /accounts` and uses the FIRST account the token can access (cached
per process in the real client). The response always carries the `accountId`
that was used. Pass `accountId` explicitly for multi-account tokens.

Responses are compact JSON (`id`, `name`, `status`, `content`, `ttl`,
`proxied`, …). Errors are MCP `isError` results with actionable messages:

- `401/403` → "token rejected or under-scoped": deposit a SCOPED API token
  (Zone.DNS edit on the zones you need + Workers/Pages/R2 read — never a
  Global API Key) with `scopegate secret add cloudflare_api_token`.
- unknown zone → "Zone not found" (points at `list_zones`), distinguished
  from unknown record → "DNS record not found" (points at `dns_list`).
- any other Cloudflare failure surfaces the envelope's `[code] message`.

## Real client (decision)

Native `fetch` (Node 22) — **zero new npm dependencies**. Every request:
`Authorization: Bearer <token>`, JSON body, **15s timeout** (AbortController).
The CF envelope `{success, errors, result}` is unwrapped in one place
(`request()`); `connect()` verifies the token once at startup via
`GET /user/tokens/verify` so a bad token fails fast with the actionable
message. Zones are resolved by name first (`GET /zones?name=…`), then by id
(`GET /zones/:id`); record ops map HTTP 404 to the dedicated
"DNS record not found" error (zone resolution already succeeded, so a 404
there can only be the record).

## Mock mode

`CLOUDFLARE_MOCK=1` selects an in-memory client with the same semantics,
seeded deterministically: zones `example.com`/`demo.dev`, records
`A www.example.com` (proxied) and `MX example.com`, account `mock-account-1`,
workers `api-worker`/`auth-worker`, Pages project `docs-site`, R2 buckets
`assets`/`backups`. The token is not validated.

## Deployment as a gateway upstream

```yaml
upstreams:
  - name: cloudflare
    transport:
      kind: stdio
      command: node
      args: [dist/upstreams/cloudflare-bridge/server.js]
      env:
        CLOUDFLARE_API_TOKEN: <injected-from-vault>
    auth: { type: env, env: { CLOUDFLARE_API_TOKEN: cloudflare_api_token } }
```

Policies gate calls per tool: `cloudflare:call:dns_delete` (require human
approval), `cloudflare:call:*`, …

## Files

- `client.ts` — semantic client interface, real client over the API v4
  (native fetch, Bearer auth, 15s timeout, envelope unwrap, zone/account
  resolution), shared actionable error builders, and the env-driven factory.
- `mock-client.ts` — in-memory implementation (self-contained spec of the
  bridge semantics).
- `tools.ts` — the 8 tool schemas + arg validation + handlers.
- `server.ts` — MCP stdio server (`createBridgeServer` is transport-agnostic
  and unit-tested over `InMemoryTransport`).

## Verification

```sh
npm run build
npx vitest run tests/cloudflare-bridge.test.ts
node e2e-cloudflare.mjs                    # full gateway e2e in mock mode
```
