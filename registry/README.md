# ScopeGate Upstream Registry

Local, signed registry of pre-configured upstreams for 1-click onboarding
(EPIC-12). An agent (or human) registers any of these upstreams with a single
reference instead of a full spec:

```
scopegate_register_upstream { "from_registry": "github" }
```

The gateway resolves the manifest, **verifies it fail-closed** (signed index +
per-manifest sha256 + stdio command allowlist), builds the `UpstreamConfig`,
and runs the exact same secretRef validation as a manual registration —
including the `waiting_for_secrets` flow, enriched with the manifest's
per-secret `hint`.

## Layout

| File | Role |
|---|---|
| `<name>.yaml` | Manifest, format `registry/v1` (see below). |
| `index.json` | `{version, updatedAt, manifests: {name: {file, sha256}}}` — sha256 over the exact manifest bytes. |
| `index.sig` | Ed25519 signature (`ed25519:<base64>`) over the exact `index.json` bytes. |
| `keys/dev-public.pem` | Public key, ALSO embedded in `src/registry/verify.ts` (the client trusts the embedded copy, not this file). |
| `keys/dev-private.pem` | **DEV-ONLY signing key.** Signs this in-repo development registry. Replace with the release key (EPIC-09) for production distribution; never sign a production index with it. |
| `sign-index.mjs` | Regenerates `index.json` + `index.sig` after any manifest edit: `node registry/sign-index.mjs` (keep-first keypair generation). |

## Manifest format (`registry/v1`)

```yaml
version: registry/v1
name: github                      # must match the index key / file basename
description: human one-liner
transport:                        # 1:1 with UpstreamConfig.transport
  kind: stdio                     # or http (then: url)
  command: npx                    # stdio only: must be a BARE name on the
  args: ["-y", "@modelcontextprotocol/server-github"]   # embedded allowlist
auth:                             # 1:1 with UpstreamConfig.auth
  type: env
  env: { GITHUB_PERSONAL_ACCESS_TOKEN: github_pat }   # ref NAMES, never values
docs: https://…                   # optional
setup:
  secrets:
    - ref: github_pat             # ref name the human must deposit
      hint: where to obtain it + `scopegate secret add github_pat`
```

Hard rules enforced by the client (`src/registry/`):

- **Fail-closed**: a missing/invalid index signature, a sha256 mismatch, an
  unknown name, or a malformed manifest is an ERROR — never a warning.
- **Supply-chain allowlist**: a stdio manifest is accepted only if `command`
  is a bare executable name (no path separators) on the embedded allowlist
  (`npx`, `node`, `uvx`, `uv`, `docker`, `python`, `python3`, `deno`, `bun`).
- Manifests carry secret **ref names** only; values enter through
  `scopegate secret add <ref>` (out-of-band, human-only).
- `fakegit.yaml` is a **test fixture** for `e2e-registry.mjs`, not a real
  service (documented in the manifest itself).

## Auth types (new in wave 2)

The `auth.type` field accepts every type supported by the token minter
(`src/minter/`). Wave 2 (EPIC-13/EPIC-18) adds two minted types on top of the
wave-1 set (`none`, `bearer`, `env`, `oauth2`, `jwt`, `github_app`,
`aws_sts`):

- **`huly`** (EPIC-13) — the vault holds a JSON blob
  `{email, password, workspace, accountsUrl?}` at `secretRef`; the gateway logs
  in against the Huly account service (`login` → `selectWorkspace` with
  `@hcengineering/account-client`) and mints a short-lived workspace token
  (cache at 80% of the TTL). The bridge receives `HULY_TOKEN` /
  `HULY_ENDPOINT` / `HULY_WORKSPACE` as spawn env; the account password never
  leaves the vault. Optional `accountsUrl` overrides the blob's.
- **`google_sa`** (EPIC-18) — the vault holds a Google service-account JSON
  key at `secretRef`; the gateway signs a service-account JWT (RS256) and
  exchanges it at `oauth2.googleapis.com/token` for a ~1h access token — the
  same pattern as `github_app`. The bridge receives `GOOGLE_ACCESS_TOKEN`; the
  SA private key never leaves the vault. (User OAuth via the device-code
  daemon, auth type `oauth2`, remains the supported alternative — EPIC-03.)

The `railway` and `cloudflare` wave-2 manifests use the wave-1 `env` type
(long-lived API tokens — declared `fallback:injection` mode, injected only as
spawn env; their destructive tools are gated by policy).

## Client resolution order

1. `SCOPEGATE_REGISTRY_PATH` — local directory (or `file://` URL). No cache.
2. `SCOPEGATE_REGISTRY_URL` — `http(s)` base URL; fetched files are cached in
   `~/.scopegate/registry-cache/` (used only when the URL is unreachable, and
   still fully signature-verified before use).
3. Default: the bundled `registry/` directory shipped with the package.

## Contributing a manifest

1. Add `<name>.yaml` following the format above (realistic transport/auth,
   actionable `setup.secrets` hints, secret refs only).
2. Re-sign: `node registry/sign-index.mjs`.
3. Verify: `npm test` (registry tests load and verify every shipped manifest).

Note: `package.json`'s `files` allowlist does not yet include `registry/`;
it must be added before this registry ships in the npm tarball (tracked for
the packaging sprint — outside EPIC-12 registry scope).
