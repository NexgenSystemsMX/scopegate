# LEARNINGS.md — ScopeGate

Accumulated operational lessons from working on this repo. Written for
future agents (human or AI): each entry is **symptom → root cause → rule**.
Read before non-trivial work; append a new entry whenever you learn
something the hard way. Keep entries dated and evidence-linked
(file:line, commit, or CI run).

Entry template:

```
## N. Short title (YYYY-MM-DD)
- **Symptom.** What you observed (the failure, the surprise).
- **Root cause.** Why it actually happened.
- **Rule.** What to do differently next time — imperative, checkable.
```

---

## 1. The production Docker image is a CI merge gate (2026-07-29)

- **Symptom.** The published image `ghcr.io/luisrosasx/scopegate` failed to
  build while `npm run build` was green locally; the break shipped across
  three consecutive `master` pushes (fixed in `aac4f23`, PR #1).
- **Root cause.** The Dockerfile's `npm ci` triggers the `prepare` script
  (`npm run build`) **before** the sources are copied into the build stage,
  so the compile ran with no sources present (see the comments in
  `Dockerfile:22-32`). Unit tests never exercise the image build.
- **Rule.** Any change to `package.json` scripts, `tsconfig.json`, or the
  file layout must be validated against the Docker build, not just `tsc`.
  CI (`ci.yml`) builds and smoke-runs the image as a merge gate — do not
  merge with that job red.

## 2. Windows CRLF breaks the registry signature tests (2026-08-03)

- **Symptom.** On Windows, 5 tests in `tests/registry.test.ts` fail while
  the whole suite is green on Linux runners.
- **Root cause.** `core.autocrlf` rewrites `registry/*.json` line endings
  on checkout; the sha256 pins in `index.json` and the Ed25519 signature
  (`index.sig`) cover the LF bytes, so verification fails on the CRLF
  working copy. Pre-existing, environment-only — not a product bug.
- **Rule.** When validating registry changes on Windows, verify against the
  committed bytes (`git show HEAD:registry/...`), not the working tree; the
  suite result on Linux CI is the authoritative one.

## 3. `/health` must report liveness, not a boot snapshot (2026-07-28)

- **Symptom.** `GET /health` reported healthy upstreams as down
  (`2a212b5` — "leia un snapshot de arranque y reportaba caidos upstreams
  vivos").
- **Root cause.** The handler served the status snapshot captured at
  gateway boot instead of probing current connection state.
- **Rule.** Health/readiness surfaces must reflect live state. Any change
  to connection lifecycle (reconnect, self-heal, circuit breaker) needs a
  health-endpoint assertion in `e2e-http.mjs` / `e2e-prod.mjs`.

## 4. Deployment drift: the cloud service start command is not in the repo (2026-08-03)

- **Symptom.** `railway.toml` fully describes the **gateway** service, but
  the `scopegate-cloud` service (landing/panel/`/v1` at scopegate.io)
  starts with `node dist/cli.js cloud serve --home /data`, which exists
  only as a Railway dashboard override.
- **Root cause.** Two services, one repo — the repo's config covers one of
  them; the other was configured by hand.
- **Rule.** When changing `cloud serve` flags or paths (`site/`,
  `src/cloud/dashboard/`, `/data`), check the dashboard override too —
  repo-only reasoning breaks the public site. Long term: move the override
  into versioned config.

## 5. Docs links rot silently: `docs/Implementacion/` was referenced but never existed (2026-08-03)

- **Symptom.** Five places (`README.md`, `docs-site/index.md`,
  `docs-site/cli-reference.md`, `docs-site/security-model.md` ×2) linked to
  EPIC design docs under `docs/Implementacion/` — all dead links; `docs/`
  only ever contained `agents/`.
- **Root cause.** Design docs lived outside the repo (or were removed)
  while in-repo references kept pointing at them; no link checking in CI.
- **Rule.** Never reference a repo path that does not exist at commit time.
  When moving or dropping design docs, grep for the old path first. Treat
  doc-only PRs as the place to reconcile links.
