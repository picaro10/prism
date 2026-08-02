# Changelog

All notable changes to PRISM are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and PRISM follows semantic versioning.

## [Unreleased]

### Added
- **Semgrep taint analysis in the security category.** When semgrep is on PATH,
  PRISM runs a curated, embedded rule pack (13 rules — no registry fetch, no
  metrics) of real dataflow checks: SQLi, XSS (reflected + DOM), SSRF, path
  traversal, deserialization (pickle/marshal/yaml), and command/code injection,
  for JS/TS and Python. Findings land as `SG-*` under `security` with CWE/OWASP
  metadata and go through the same context filter (fixtures skipped, test files
  downgraded) and — with `--ai` — the same adversarial triage as every other
  finding. Without semgrep the category degrades to an info notice
  (`SEC-SEMGREP-MISSING`), never a penalty; an installed-but-failing semgrep
  reports `SEC-SEMGREP-ERROR` (unknown ≠ clean). Output is capped at 200
  findings (`SEC-SEMGREP-TRUNCATED`).
- **Multi-ecosystem SCA via OSV.dev.** Pinned lockfiles beyond npm —
  `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `go.mod`,
  `composer.lock`, `Gemfile.lock` — are parsed and checked against the public
  OSV.dev API. Critical/high advisories become `DEP-OSV-CRITICAL`/`DEP-OSV-HIGH`
  under `dependencies` (npm-audit parity: -2/-1); lower or unclassified ones
  group into one `DEP-OSV-LOWER` note; an unreachable API reports
  `DEP-OSV-SKIP` (unknown ≠ clean). Dynamic external signal: it informs —
  never gate CI on its counts. Offline-safe: no lockfiles, no network call.
- **`prism doctor` reports semgrep** (ok + version, or a warn with the install
  hint).
- The engine now merges same-category analyzer results into one
  `CategoryScore` (min score, concatenated findings) — `security` is the first
  category with two engines (secrets + semgrep).

## [1.3.0] — 2026-08-02

**CLI decomposition & hardening** — the post-audit refactor: modular CLI, deep report validation, a11y, coverage floor raised.

### Changed
- **CLI split by command** — `src/cli/index.ts` (775 lines mixing declaration,
  validation, config, lifecycle, rendering, AI and dashboard) is now a thin
  entry that registers per-command modules (`commands/analyze`, `commands/triage`,
  `commands/reports`, `commands/setup`) over a `shared.ts` contract (exit codes,
  option validation, report loading). No behavior change — the spawn-based
  exit-code e2e suite passes unchanged.
- **Deep report validation everywhere** — a shared Zod schema
  (`core/report-schema.ts`) now validates saved reports at every entry point
  (`triage`, `diff`, `finding get`, dashboard). Structurally broken reports
  fail fast with reasons (exit 2) instead of crashing a renderer with a 500;
  the dashboard also caps report files at 25 MB before parsing.
- **HTML/dashboard accessibility** — score bars carry `role="meter"` with aria
  values and labels; only critical/high finding sections start expanded; the
  dashboard table gains a caption and a horizontal-scroll wrapper; both pages
  have print styles.
- **Coverage floor raised** — thresholds 78/72/78/78 → 85/77/87/87. New unit
  suites for the CLI renderer, `core/baseline.ts` (real git worktree path),
  the OpenRouter HTTP layer (mocked fetch), report schema, and CLI shared
  helpers. Only the spawn-tested command wiring stays excluded from in-process
  coverage.

## [1.2.1] — 2026-08-02

**Honest scoring & hardening** — driven by an external audit; every confirmed finding fixed.

### Fixed
- **Scoring can no longer mask findings.** Positive signals (CI, linter, test config,
  test ratio) now *earn* the last stretch of a category score instead of refunding
  penalty points — a category with real findings can no longer render a perfect 10.
  The Docker-presence bonus is gone entirely (it said nothing about code structure,
  and was being detected from test fixtures). The overall score is capped at 9.9
  whenever any scoreable (non-info) finding exists — no more "10/10" via rounding.
- **Not-analyzed ≠ perfect.** Categories with nothing to analyze (no Dockerfiles, no
  workflows, no source code to test) report `applicable: false`, are excluded from
  the overall weighted average, and render as **N/A** in CLI/HTML instead of 10/10.
- **`npm audit` no longer fails open.** When the audit can't run (offline, npm
  missing, unparseable output) the category takes a low-severity finding and a
  -1 penalty: unknown vulnerability status is not a clean bill of health.
- **CLI flag validation.** `--max-critical`, `--max-high`, `--output`,
  `--ai-provider`, `--ai-concurrency` and `--min-score` are validated on both
  `analyze` and `triage`; invalid values exit 2 (usage) instead of being silently
  ignored with exit 0. `mapWithConcurrency` treats an invalid limit as sequential
  (a NaN limit used to spawn zero workers and report success with zero results).
- **Fixture Dockerfiles no longer flag the project as dockerized** (`hasDocker` and
  the Docker framework tag now use the same user-authored-context filter as the
  analyzer).
- **Suppressions annotate category summaries** ("· N finding(s) suppressed by
  config") so a summary can no longer describe findings that were removed.
- README: "seven analyzers" → eight.

### Security
- **Saved reports are treated as untrusted input.** `triage` and `finding get`
  confine every file read to the report's `projectPath` — absolute paths and
  `../` escapes are rejected (a manipulated report could previously read
  arbitrary local files, and `triage --ai` could send them to the LLM provider).
  `triage` now also prints which directory it is about to read.
- **Zip-bomb guards** on `.zip` targets: entry count, total declared uncompressed
  size and per-entry compression ratio are checked before a single byte is
  written.
- **Dependency cleanup:** removed unused production deps `glob` (which carried the
  high-severity `brace-expansion` advisory) and `table`; pinned `esbuild` past
  GHSA-g7r4-m6w7-qqqr. `npm audit`: **0 vulnerabilities**.
- **OpenRouter client timeout** (120s) — a hung connection can no longer block an
  audit indefinitely.

### Changed
- Windows groundwork: scanner paths are normalized to POSIX separators at the
  source, and CI now runs a `windows-latest` matrix leg.
- The library entry (`dist/core/engine`) exports the public types (`PrismConfig`,
  `AuditReport`, `Finding`, `CategoryScore`, `Analyzer`, …) and
  `CATEGORY_WEIGHTS`. Removed the dead `PrismConfig.ignorePatterns` option.

## [1.2.0] — 2026-07-22

**Workflow Intelligence** — the eighth audit dimension.

### Added
- **Workflow analyzer** (`WFL-*`, weight 1.0×) — CI/CD risks in GitHub Actions, deliberately
  not an actionlint/zizmor rebuild: PRISM's angle is cross-checking the YAML against the
  **actual repository**. Twelve rules: `WFL-001` pwn request (`pull_request_target` + PR-head
  checkout, critical), `WFL-002` script injection from untrusted event data, `WFL-003`
  unpinned third-party actions (aggregate penalty capped — one missing convention, not N
  failures), `WFL-004`/`WFL-005` missing/over-broad permissions, `WFL-006` triggers filtering
  **only branches that don't exist** (the workflow never runs — the exact bug this project
  shipped v1.0.0 with; needs the repo, invisible to YAML linters), `WFL-007`/`WFL-008` missing
  timeouts/concurrency, `WFL-009` fail-open gates (`continue-on-error` on checks), `WFL-010`
  setup-node without cache despite a committed lockfile, `WFL-011` self-hosted runners on PR
  triggers, `WFL-PARSE` unparseable YAML.
- Local branch discovery without the git binary (`.git/refs/heads` + `packed-refs`) powering
  the cross-checks.
- Rule catalog page (`docs/rules/workflow.md`), benchmark cases (planted pwn-request/injection
  workflow + hygienic-workflow FP trap), and — dogfood first — PRISM's own `ci.yml` fixed for
  the three findings the analyzer raised against it (permissions, timeouts, concurrency).
- New dependency: `yaml` (pure JS, zero transitive deps) — structural rules deserve a real
  parser, not regex gymnastics.

## [1.1.0] — 2026-07-22

First release published to npm (`@latenciatech/prism`).

### Added
- **Persistent config file** — `prism.config.json` / `.prismrc.json` at the target root, with a
  strict schema (unknown keys are a usage error, so a typo can't silently disable a gate).
  Every key mirrors a CLI flag; precedence is explicit CLI flag > config file > default.
  Discovery only trusts **local** targets — a cloned/extracted third-party repo can't pick its
  own gates (`--config` opts in explicitly, `--no-config` disables discovery).
- **`prism init`** — interactive wizard (TTY only; `--yes`/non-TTY writes defaults, never
  blocks CI) that asks the decisions worth making once and writes `prism.config.json`.
- **Justified suppressions** — accept one reviewed finding without excluding the file: rule id +
  optional gitignore-style file pattern + **mandatory reason** + optional `expires` date.
  Applied before scoring/gates/AI triage; suppressed findings stay listed in the output with
  their reasons; expired entries resurface with a warning, stale entries warn too.
- **CI package smoke** — `npm pack` → install the tarball into a clean project → run
  `doctor`/`init`/`analyze` from the installed binary. Verifies the artifact users receive,
  not just the source tree.
- **README**: honest language/platform support matrix; roadmap aligned with shipped reality;
  the footer no longer contradicts the MIT license.
- **Four new agentic rules** — `AGT-003` destructive tool without a confirmation gate (aggregate
  penalty capped: N ungated tools share one root cause), `AGT-004` external content interpolated
  into a prompt (the prompt-injection front door), `AGT-005` MCP/agent server bound to `0.0.0.0`,
  `AGT-006` security gate whose catch returns permissive (fails open). All conservative, all
  carrying the anti-self-detection guard, all field-tested before merging.
- **Public rule catalog** — `docs/rules/` documents all 68 rules with severities and their
  field-tested false-positive notes; a sync test fails CI if a rule ships undocumented or the
  catalog goes stale. Issue templates (bug/FP/FN/new-rule) and a full add-a-rule checklist in
  CONTRIBUTING.
- **Reproducible FP benchmark** — `npm run bench`: a corpus of planted true positives plus the
  false-positive traps actually hit in the field, materialized to temp projects at run time
  (risky literals are assembled, never committed). Reports precision/recall/timing and fails CI
  on any regression in either direction. PRISM's own repo now carries a `prism.config.json`
  whose justified suppressions cover the benchmark corpus — the feature, dogfooded.
- **Agentic analyzer** — a new audit dimension for AI-agent code that mainstream analyzers
  (Semgrep, Sonar) don't model: `AGT-001` shell commands built with interpolation/concatenation
  (agent command injection; `execFile` is the safe pattern), `AGT-002` environment secrets
  interpolated into an LLM prompt/message. High-signal and conservative — skips comments and
  regex definitions so a scanner doesn't flag itself.
- **New-code gate** — `--baseline <git-ref|report.json>`. Severity rules apply only to findings
  not already in the baseline ("clean as you code"): legacy debt doesn't block, new code can't
  add a critical. Diffs by a **fingerprint** (rule + file + normalized code) that survives line
  moves and re-indentation, so a shifted finding isn't mistaken for a new one.
- **SARIF 2.1.0 output** — `--sarif <path>` for GitHub Code Scanning (inline PR annotations),
  VS Code, and other tooling, with `security-severity` for alert ranking.
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
