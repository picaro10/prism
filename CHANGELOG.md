# Changelog

All notable changes to PRISM are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and PRISM follows semantic versioning.

## [1.6.0] — 2026-09-17

**The AI-layer release.** The triage judge now reads code only when code can
change the verdict, is measured by its own benchmark, remembers what it has
already judged, and sees across files. Plus the scanner file cap and the
bus-factor docs from the last audit. Every AI claim below was measured
against a live model, not only against the test suite.

### Added
- **Cross-file context for the AI judge (`neighborhood` tier).** A line-level
  rule fires in one file, but what makes it benign often lives in another —
  the executor gating every destructive tool, the validator rejecting shell
  metacharacters, the assertion helper calling `expect()`. `src/ai/
  neighborhood.ts` now picks those files deterministically from the import
  graph (no model in the loop): modules the flagged file imports whose
  imported names are used within 40 lines of a flagged line, and modules
  importing the flagged file that mention an anchor token from it (string
  literals, identifiers — not the binding name itself). Comments and string
  contents are ignored when checking usage (`git log` must not summon a
  module named `log`), template interpolations are kept. Bounded: 4 files,
  12 KB each, 30 KB total; TS/JS with tsconfig aliases; empty when nothing
  qualifies. Related files are shown to the judge with the reason each is
  there, and the prompt requires that a gate or sanitizer excuse a finding
  only if the flagged code actually goes through it. The verdict cache key
  covers neighbors, so editing a validator re-judges the code that relies
  on it. AI-triage benchmark: cross-file false positives caught 1/3 → 3/3,
  15/15 overall, 0 real issues excused. `prism triage` re-scans the root to
  get the inventory the graph needs.
- **Verdict cache for the AI layer.** Every final triage verdict and fix is
  stored under a key of prompt text + judge (provider, model, panel) +
  finding identity + hash of the content the model read, in the operator's
  cache directory (`PRISM_CACHE_DIR` / `$XDG_CACHE_HOME/prism` /
  `%LOCALAPPDATA%\prism\cache` / `~/.cache/prism`, one file per project —
  never inside the audited tree). Unchanged findings on unchanged files are
  reused instead of re-judged: the next CI push, `prism triage` on a saved
  report, and the same run after a Ctrl-C all pay only for what changed.
  Writes are atomic after every store (resume for free); verdicts
  synthesized from a failed call or an abstaining panel voter are never
  cached. Reported as `N from cache` in the tally and `[cached]` on each
  reused verdict. `--no-ai-cache` / `ai.cache: false` opt out; clones and
  zips never use it. `LLMClient` gains an `id` so a different model never
  answers from another's memory.
- **AI-triage benchmark (`npm run bench:ai`).** The static benchmark measures
  the rules; this one measures the judge. 15 cases in `benchmarks/ai/cases.ts`
  — findings the static layer really emits, each with the verdict a careful
  reviewer reaches: 9 genuine issues the model must not excuse (including the
  two field judgment errors: a disconnected test excused as "testing style",
  a real 0.0.0.0 binding excused by citing another service), 3 same-file
  false positives it should catch, 3 cross-file false positives whose
  evidence lives in another module (reported as their own rate — the
  baseline for cross-file context). Hard-fails only on a real issue excused
  as a false positive; `--dry-run` exercises the corpus offline, and the test
  suite health-checks every case's target finding so the corpus cannot rot.
  First live run (claude-opus-4-8): 13/15 hits, 0 excused, 100% of same-file
  FPs caught, 1 of 3 cross-file FPs caught.
- **Context tiers for AI triage.** Every rule now declares how much code its
  triage needs (`CONTEXT_TIER` in `src/core/rule-metadata.ts`): `none` for
  rules whose evidence is a project-level fact (god files, import cycles,
  dependency advisories, missing tests, mixed conventions — reading the file
  cannot change the verdict), `file` for line patterns (the default, and the
  fallback for any unknown rule), `neighborhood` for cross-file rules
  (agentic, taint — reserved for the upcoming import-graph context, reads the
  file until then). `none`-tier findings are batched into content-less calls
  of at most 25, which also bounds the previously unbounded project-level
  group. On a real 37-finding report (25 of them god files) this cuts triage
  from 33 calls to 8 and the file content sent from 1.2 MB to 34 KB. Remediation
  keeps reading files: proposing a fix needs the content.
- **File-inventory cap in the scanner.** `MAX_SCAN_FILES` (100,000) bounds the
  directory walk so a pathological or hostile tree (a monorepo with millions of
  entries, a whole disk) cannot spin the walker or hand every analyzer an
  unbounded workload — same doctrine as `MAX_ZIP_ENTRIES`. Hitting the cap sets
  `scanWarnings.truncated` and the structure summary reports the coverage gap;
  a capped scan never reads as a small, clean project. `scanProject(root,
  { maxFiles })` is injectable for tests.
- `SECURITY.md` (private disclosure via GitHub Security Advisories),
  `.github/CODEOWNERS` (trust-boundary modules flagged for mandatory review
  once a second maintainer exists) and `docs/ARCHITECTURE.md` (audit pipeline,
  trust boundaries, scoring doctrine). `CONTRIBUTING.md` links both.

### Changed
- README and package description repositioned: PRISM is the complete auditor
  for AI-written code — security, code quality and structure — not only the
  security auditor. Install section no longer says "once published"; test
  count and analyzer count brought up to date; N/A scoring documented as
  "excluded from the overall", not a silent 10/10.

## [1.5.1] — 2026-08-03

**Security + honesty follow-up to 1.5.0.** A second adversarial audit (three
parallel review passes + empirical attacks on the published CLI) found real
defects — two of them **RCE regressions introduced by 1.5.0 itself**. 1.5.0 is
deprecated on npm; upgrade.

### Security — Critical
- **RCE via `git ls-files` on an untrusted repo (introduced in 1.5.0).** The
  1.5.0 tracked-`.env` check invoked `git`, and `git` honors a repo-config
  `core.fsmonitor` command — verified: it executes. A repo shipping its own
  `.git/config` (unpacked from a zip/artifact) ran code as the operator on
  `prism analyze`. All git invocations now run with `core.fsmonitor=false`,
  `core.hooksPath=/dev/null`, `protocol.ext.allow=never`, and system/global
  config neutered (`src/utils/git-safe.ts`).
- **RCE via `git worktree add --baseline` (pre-existing).** The baseline
  checkout ran post-checkout hooks / fsmonitor from the untrusted repo. Same
  hardening applied; `--` terminates option parsing.
- **Downloaded archives are stripped of `.git/`** after extraction, closing the
  hook/fsmonitor/smudge vector for zip targets at the source.

### Security — High
- **HTML/dashboard stored XSS** via `aiTriage.summary` counts (the one
  unescaped slot); numeric coercion applied and the schema now requires numeric
  summary fields.
- **`npm audit` no longer trusts the repo's `.npmrc` transport/TLS** (proxy,
  cafile, strict-ssl) — a hostile `.npmrc` could MITM the request and exfiltrate
  the dep tree + registry auth. Env overrides pin them; `--ignore-scripts` and a
  32 MB buffer added.

### Fixed
- **Cross-report fingerprint collision (1.5.0 fix was incomplete).** A wildcard
  dep swapped for a different one (both `DEP-002` on `package.json`) was
  invisible to the new-code gate. Line-less fingerprints now include a
  digit-normalized title discriminator. **One-time effect: baselines captured
  under ≤1.5.0 will show line-less findings as "new" on the first 1.5.1 run —
  re-capture the baseline once after upgrading.**
- **Tracked-`.env` detection now works when auditing a subdirectory** of a repo
  (the check was gated on a `.git` entry at the audit root).
- **`stripStringLiterals` no longer hides a real skipped test** when an
  apostrophe in a comment or a quote in a regex precedes it (comments + regex
  literals are stripped first).
- **`loadAllowlistedEnv`** strips inline `# comments` from unquoted values and
  handles CRLF (a `KEY=v # note` no longer 401s every AI call).
- **`checkReportRoot`** no longer refuses every report when the process runs
  from a filesystem root (docker with no WORKDIR).
- **Secrets counters**: files skipped as security-tools are not counted as
  "scanned", and a processing error no longer double-counts a file as unreadable.
- **OSV**: a ranges-only `requirements.txt` / `require`-less `go.mod` no longer
  raises a false `DEP-OSV-INCOMPLETE`; the over-cap drop count no longer
  multiplies across lockfiles.

### Changed — honesty
- **Coverage gaps are shown in the CLI and HTML**, not just JSON: every
  analyzer's read-error/skip/incomplete disclosure now renders under the
  category score (it previously lived only in `category.summary`, which those
  reporters never printed).
- **yarn/pnpm projects** now get an explicit `DEP-AUDIT-SKIP` (npm audit can't
  check them) instead of silent "clean".
- **semgrep** surfaces `errors[]`/`paths.skipped` as `SEC-SEMGREP-INCOMPLETE`
  (a rule/file timeout no longer reads as "clean"), scans with `--no-git-ignore`
  (a repo can't exclude itself), and reports the real finding count when capped.
- **The scanner** counts unreadable directories / unstat-able files and the
  structure summary surfaces them (the inventory no longer undercounts silently).
- **`projectMeta` is optional again** with renderer guards — requiring it made
  the dashboard silently drop older reports.

### Security — Low / hardening
- `git-refs` walk uses `lstat` + a depth cap (no symlink-loop DoS) and caps
  `packed-refs` size; `repoNameFromUrl` is sanitized (no `..`); JUnit + CLI
  output strip control characters from untrusted finding text; the update-check
  cache moved to a per-user tmp dir with a symlink guard and version-shape
  validation.

## [1.5.0] — 2026-08-03

**The trust-boundary and honesty release** — every functional finding from the
post-1.4.1 external audit, verified against the code and fixed.

### Fixed
- **Baseline fingerprints no longer conflate distinct line-less findings.**
  Two findings with the same rule + file but no line (e.g. two wildcard
  dependencies both raising `DEP-002` on `package.json`, or two hits on
  identical duplicated lines) hashed to one identity, so the new-code gate
  treated a NEW duplicate as preexisting debt. Colliding fingerprints now get
  a deterministic ordinal hashed in; the first occurrence keeps the legacy
  fingerprint, so existing baselines stay valid.
- **`SEC-ENV-COMMITTED` now checks the git index.** The scanner filters its
  inventory through `.gitignore`, but ignoring a file does not untrack it — a
  `.env` committed first and gitignored later stayed in the repository while
  becoming invisible to the rule that exists to catch exactly that. The
  secrets analyzer now asks `git ls-files` directly (argv-only, no shell, no
  hooks) and reports tracked env files as *actually committed*, with rotation
  advice. Degrades silently when git is unavailable.
- **`TST-012` no longer counts `.skip` inside string literals.** A file
  holding `it.skip(...)` as fixture *data* (PRISM's own test suite among
  them) was reported as containing skipped tests.
- **Docs/code mismatch:** `DEP-AUDIT-SKIP` is documented as `low` (what the
  code emits, with its −1 penalty), not `info`.

### Changed
- **Saved reports are validated for real.** `parseReport` now requires
  `projectMeta` (present in every report since v1.0.0; the HTML and CLI
  renderers dereference it unconditionally) and validates `aiTriage`,
  `aiRemediation`, and `suppressed` deeply — a JSON that passes validation can
  no longer crash a renderer afterwards.
- **`triage` and `finding get` no longer trust the report's `projectPath`
  blindly.** Reads were already confined to that root — but the report itself
  chooses it. The recorded root is now honored only when it resolves inside
  the current working directory; anything else requires an explicit
  `--root <path>` (new flag on both commands). `triage` refuses loudly;
  `finding get` degrades to a null snippet with a warning.
- **The CLI imports `.env` selectively.** In `cd project && prism analyze .`
  the cwd `.env` IS the analyzed project's — untrusted input. It is no longer
  loaded wholesale into the auditor's process: only `ANTHROPIC_API_KEY`,
  `OPENROUTER_API_KEY` and `PRISM_*` are imported, and the real environment
  always wins. (The old comment claiming the cwd `.env` was "not the target's"
  was simply false in the most common invocation.)
- **Coverage gaps are reported, not swallowed.**
  - Secrets: the summary's "N files scanned" now counts files actually READ,
    and says out loud how many were skipped (>2MB) or unreadable.
  - OSV: a non-empty lockfile that yields no packages (unreadable or
    unparseable) and packages dropped past the 2000-package cap now raise
    `DEP-OSV-INCOMPLETE` (low, −0.5) — unchecked is unknown, not clean.
  - npm audit: moderate/low vulnerabilities appear as `DEP-AUDIT-LOWER`
    (info, no penalty) instead of vanishing from the report.
- **README honesty:** the static layer's network use is now stated precisely
  (npm audit / OSV.dev / update check exchange package names & versions, never
  code, and degrade to explicit UNKNOWN findings offline), and the score is
  documented as a heuristic indicator, not a calibrated metric.
- **CI supply chain:** GitHub Actions pinned to full commit SHAs, semgrep
  install pinned to a version.

## [1.4.1] — 2026-08-02

**Severity honesty in the OSV layer** — a credibility bug found auditing 1.4.0
hours after publishing it, and the exact failure mode this project exists to
call out.

### Fixed
- **`DEP-OSV-LOWER` no longer buries criticals.** The per-run classification
  budget (30 advisories) was a cap on *truth*, not on noise: everything beyond
  it stayed `unknown`, and `unknown` was folded into the **low** bucket. On ten
  stale Python packages PRISM reported **4 criticals and 9 highs** while 223
  advisories sat in a `low` note — the real figures are **29 and 119**.
  Unclassified advisories now get their own `DEP-OSV-UNKNOWN` finding at
  **medium** with a real penalty, stating plainly that unknown severity is not
  low severity, and disclosing when the budget was exceeded. Same doctrine as
  `DEP-AUDIT-SKIP`: unknown ≠ clean.
- **Severity now follows the OSV `aliases` chain.** Roughly half of PyPI
  advisories are `PYSEC-*` records with no severity that mirror a `GHSA-*` one
  that has it; one hop recovers them. Budget raised 30 → 300 (concurrency 4 →
  8) so a realistic dependency tree is fully classified.
- **Taint rules no longer depend on a variable name.** A handler naming its
  parameter `request` (Fastify, Next.js app router) instead of `req` hid
  identical SQLi/SSRF/traversal/injection findings. All JS/TS rules now list
  both conventions as sources.

### Changed
- **Benchmark covers the v1.4.0 pillars** — 15 → 21 cases: planted SQLi taint
  (Express) and Python pickle deserialization, plus the two FP traps taint
  analysis is famous for failing (a parameterized query whose *params* carry
  request data, and `path.basename()` sanitizing a traversal); an OSV.dev case
  on a known-vulnerable pin, and its trap (a vulnerable lockfile living in
  `tests/fixtures/` must never reach the network, let alone produce findings).
  Cases can now declare `requires: 'semgrep' | 'osv'`; the runner probes and
  **skips them with an explicit SKIPPED line** when the capability is missing —
  an absent binary or an unreachable external API can never read as a
  regression, nor hide behind a silent pass. Live-database findings may declare
  `allowExtra` so OSV reclassifying an advisory can't break CI, while recall
  stays pinned. Both bugs above are pinned as regression cases (23 total):
  criticals must surface as `DEP-OSV-CRITICAL`, and the `request`-named handler
  must still trip the SQLi rule.

## [1.4.0] — 2026-08-02

**The security release** — three pillars that reposition PRISM as the security
auditor for AI-written code and the pipelines that ship it: real taint/dataflow
analysis (semgrep + adversarial AI triage), multi-ecosystem SCA (OSV.dev), and
CWE/OWASP metadata across the catalog with SARIF tags.

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
- **CWE / OWASP Top 10 (2021) mapping across the rule catalog.** Every
  security-relevant rule (secrets, taint, agentic, workflow, docker, dependency
  advisories) maps to a CWE and an OWASP category in
  `src/core/rule-metadata.ts` (documented in `docs/rules/cwe-owasp.md`). SARIF
  rules now carry `external/cwe/…` and `external/owasp/…` tags next to the
  existing `security-severity`, so GitHub Code Scanning classifies PRISM
  alerts like CodeQL/Snyk output. Quality rules deliberately stay unmapped —
  no CWE theater. Tests keep the map, the docs page, and the semgrep rule
  pack in sync.
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
