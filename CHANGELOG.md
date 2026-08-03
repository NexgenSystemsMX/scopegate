# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(`0.x` during the beta: minor = features, patch = fixes).

## [Unreleased]

### Added

- Ecosystem documentation: `ARCHITECTURE.md` (components, data flow,
  Mermaid diagram, deployment modes), `CLAUDE.md` (agent guidance for
  developing this repo), `LEARNINGS.md` (operational lessons log),
  `.env.example` (every environment variable the code reads, names only),
  and a "Nexum.Work Ecosystem" section in `README.md`.

### Changed

- `CONTRIBUTING.md`: explicit trunk-based flow (short-lived branch from
  `master` → PR → squash merge → delete branch) and Conventional Commits.

### Documentation

- Synced `AGENTS.md` and `docs/ecosistema.md` with the live state of the
  Nexgen ecosystem (4 systems): Railway service map, production gateways
  embedded in the kimi-tag project, human-approval matrix
  (`9422a41`).

## [0.2.1] - 2026-07-30

### Added

- Agent identities per glob: policies can match agent ids with glob
  patterns, and a structured rules API exposes them (`aac4f23`, PR #1).
- `GET /admin/agents` — the admin surface now serves a fleet of agents,
  not a single one (`94503eb`).
- `/admin/*` gateway surface with its own credential
  (`SCOPEGATE_ADMIN_TOKEN`) for human consoles (`b7c0a31`).

### Fixed

- Production Docker image build: the `prepare` script ran `npm run build`
  before sources were copied into the build stage; documented in
  `Dockerfile` and gated in CI (`aac4f23`, PR #1).
- `/health` no longer serves a boot-time snapshot that reported live
  upstreams as down (`2a212b5`).
- Audit rotation keeps the hash chain intact and no longer leaves orphaned
  child processes (`6e65499`).
- `npm prepare` script so the package installs cleanly from git without
  being published to npm (`502563c`).

## [0.2.0] - 2026-07-24

### Added

- Milestones M1–M15: composite auth (multi-service MCPs 100% minted),
  proactive stdio mint refresh with self-heal, `when:` argument guards,
  multi-identity `X-ScopeGate-Agent` over HTTP, `git-credential` helper
  minting GitHub App tokens, native approvals with `wait: true` and
  Slack/webhook/Huly channels, embeddable library API + testkit, huly
  bridge at 16 tools, governed file injection (`vault:inject:*`
  default-escalation), `github-official` registry entry and the OpenAPI
  importer transport, host observability (`scopegate_events`, `/events`),
  `PostgresStore` + `cloud enroll` CLI + audit retention, registry
  pool/exposeTools/attestation, `honeytoken plant` CLI, batch
  `scopegate_request_capabilities`. 21 MCP tools total.
- Agent waves A–E: machine-readable error envelopes + upstream health +
  circuit breaker, approval continuations (`execute_on_approval`),
  policy preflight (`scopegate_can_i`, `scopegate_policy_summary`),
  agent recall, task leases, idempotent writes, result handles,
  capability plans, attenuated subagent delegation with cascade
  revocation, return-path taint tracking.
- Interactive landing page with SEO/GEO metadata and the production e2e
  suites (`e2e-prod`, `e2e-ecosystem-prod`, `e2e-landing-prod`).

### Fixed

- `release.yml` working-directory (package at repo root); repository/homepage
  URLs point at `NexgenSystemsMX/scopegate` for npm provenance.
- Google SA JWT-bearer grant URN; Cloudflare bridge accepts account-scoped
  tokens at boot verify.

[Unreleased]: https://github.com/NexgenSystemsMX/scopegate/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/NexgenSystemsMX/scopegate/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/NexgenSystemsMX/scopegate/releases/tag/v0.2.0
