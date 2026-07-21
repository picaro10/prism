# Changelog

All notable changes to PRISM are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and PRISM follows semantic versioning.

## [Unreleased]

### Added
- **Quality gate by severity** — `--fail-on <severity>`, `--max-critical <n>`, `--max-high <n>`.
  The overall score is no longer the only gate: a single new critical can't hide behind a good
  average. Every failing rule is reported.
- CI now runs `test:coverage` (enforced thresholds) and holds the self-audit to a high bar
  (`--min-score 8.5 --fail-on critical`) with a JUnit sidecar. `--fail-on critical` is the hard
  door; `--max-high` is deliberately left off the dogfood since `DEP-AUDIT-HIGH` is dynamic
  (transitive advisories appear outside our control) and would make CI flaky.

### Fixed
- **CI never triggered** — the workflow listened on `master` while the published repo runs on
  `main`, so pushes/PRs ran no checks. Now targets `main`.
- **CI test failure on clean checkout** — the secrets analyzer test scans a fixture `.env` that
  the global `.gitignore` excluded, so it was never committed; passed locally, failed on CI.
  Added a `.gitignore` exception for `tests/fixtures/**/.env` and committed the (fake-secret)
  fixture.
- Bumped `fast-uri` (transitive) to clear a high-severity advisory.
- README intro contradicted itself (called the LLM layer "future work" while documenting it as
  shipped). Reworded: deterministic static analysis + an optional, opt-in LLM triage layer, both
  shipped today.

## [1.0.0] — 2026-07-21

First public release. Published as a clean history; the full internal development log is kept
private (it referenced third-party project internals).

### Features
- **Six static analyzers**: structure, secrets, dependencies, docker, tests, consistency —
  weighted scoring, obsessive false-positive hunting.
- **AI triage layer** (`--ai`, opt-in): an LLM judges each finding real / false-positive /
  uncertain in context, with adversarial re-check, N-model voting, remediation proposals, and an
  executive summary. Anthropic + OpenRouter clients. `--dry-run` for canned, zero-cost runs.
- **Outputs**: colored CLI, JSON (stable contract), self-contained HTML, JUnit XML sidecar.
- **Inputs**: local path, git URL (shallow clone), `.zip` archive (zip-slip guarded).
- **Local dashboard** over saved reports.
- **Agent-ready tooling**: semantic exit codes, `--min-score`, `prism diff` (regression gate),
  `prism agent install` (wire PRISM into a coding agent's loop), `prism finding get`
  (self-contained bundle for auto-fix), `prism doctor` (environment check).
- Graceful Ctrl-C (temp cleanup), once-per-day update check.

MIT licensed. © 2026 LatenciaTech (Spain).
