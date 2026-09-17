# Usage

Every command and flag, the configuration file, the scoring model, and the development workflow. The [README](../README.md) is the short version.

## Requirements

- Node.js **≥ 22**
- npm

---

## Install

**From npm**:

```sh
npm install -g @latenciatech/prism
prism analyze <path>
# or without installing:
npx @latenciatech/prism analyze <path>
```

**From source**:

```sh
git clone https://github.com/picaro10/prism.git
cd prism
npm install
npm run build
node dist/cli/index.js analyze <path>
```

The compiled CLI is placed at `dist/cli/index.js` and exposed as the `prism` binary via the `bin` field in `package.json`.

During development you can run without building:

```sh
npm run dev -- analyze <path>
# equivalent to: tsx src/cli/index.ts analyze <path>
```

---

## Usage

### `analyze` — full audit

```
prism analyze <target> [options]
```

The target can be a **local path**, a **git URL** (`https://…`, `git@…`, or anything ending in
`.git` — shallow-cloned to a temp dir), or a **.zip archive** (extracted to a temp dir, with
zip-slip protection). Temporary copies are deleted after the audit unless `--keep` is passed.

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-o, --output <format>` | `cli` | Output format: `cli` (colored terminal), `json`, or `html` |
| `-f, --file <path>` | — | Output file path (json: stdout if omitted; html: `prism-report.html`) |
| `--only <categories>` | all | Run only the specified analyzers (comma-separated) |
| `--min-score <n>` | `6` | Fail (exit `1`) when the overall score is below this (0–10) |
| `--fail-on <severity>` | — | Fail when any finding is at or above this severity (`critical`/`high`/`medium`/`low`) |
| `--max-critical <n>` | — | Fail when there are more than N critical findings |
| `--max-high <n>` | — | Fail when there are more than N high findings |
| `--baseline <ref>` | — | New-code gate: severity rules apply only to findings **not** in this baseline (a git ref like `origin/main`, or a saved `.json` report) |
| `--junit <path>` | — | Also write a JUnit XML report (findings as failed test cases) for CI |
| `--sarif <path>` | — | Also write a SARIF 2.1.0 report (for GitHub Code Scanning, VS Code, etc.) |
| `--dry-run` | false | Run the AI layer with canned responses — no network, no key |
| `--keep` | false | Keep the temporary clone/extraction instead of deleting it |
| `-v, --verbose` | false | Show per-file progress during the audit |
| `--config <path>` | auto | Explicit config file (default: discover `prism.config.json` / `.prismrc.json` in the target root) |
| `--no-config` | — | Ignore any config file for this run |

**Examples:**

```sh
# Full audit with terminal output
prism analyze /path/to/project

# Audit a GitHub repo directly
prism analyze https://github.com/user/repo

# Audit a zip archive
prism analyze project.zip

# Save a JSON report to disk
prism analyze /path/to/project -o json -f report.json

# Print JSON to stdout
prism analyze /path/to/project -o json

# Run only security and tests analyzers
prism analyze /path/to/project --only security,tests

# Verbose mode (shows per-analyzer progress)
prism analyze /path/to/project -v
```

**Exit codes** (a stable contract for CI and coding agents):

| Code | Meaning |
|---|---|
| `0` | The audit ran and the score met the threshold (`--min-score`, default 6) |
| `1` | The audit ran but the score is **below** the threshold — findings to fix |
| `2` | Usage/config error — bad flag, missing API key, unresolvable target |
| `3` | Internal error — the audit threw and could not complete |

Codes `0`/`1` are the audit *result*; `2`/`3` mean it could not produce one. A CI gate keys
on `0` vs non-zero; an agent can tell "fix the findings" (`1`) from "you invoked me wrong" (`2`).

**Quality gate for CI.** The score is not the only door — a single new critical can hide behind a
good average. Combine `--min-score` with per-severity rules so security issues fail hard:

```sh
prism analyze . --min-score 8.5 --fail-on critical --max-high 0 --junit prism-junit.xml
```

The gate fails (exit `1`) if *any* rule trips: score below `--min-score`, a finding at or above
`--fail-on`, or a count over `--max-critical`/`--max-high`. Every failing reason is printed.

**New-code gate ("clean as you code").** `--baseline <git-ref>` makes the severity rules apply
only to findings that are **not** already in the baseline — so legacy debt doesn't block, but new
code can't add a critical. PRISM checks the ref out into a temporary worktree, audits it, and
diffs by a **fingerprint** (rule + file + normalized code) that survives line moves and
re-indentation, so a shifted finding isn't mistaken for a new one:

```sh
# Fail only if THIS branch introduces a new critical vs. main:
prism analyze . --baseline origin/main --fail-on critical --min-score 0
```

`--baseline` also accepts a saved `.json` report instead of a git ref.

**SARIF for GitHub Code Scanning.** `--sarif prism.sarif` writes a SARIF 2.1.0 document; upload it
with `github/codeql-action/upload-sarif` and findings appear as inline annotations on the PR and
in the repo's Security tab, ranked by `security-severity`. Every security-relevant rule carries a
**CWE and OWASP Top 10 (2021) mapping** (`external/cwe/…` / `external/owasp/…` tags — see
[docs/rules/cwe-owasp.md](rules/cwe-owasp.md)), so PRISM alerts classify and group alongside
CodeQL or Snyk output.

**JSON output** (`-o json`) is a stable, documented interface: with `-f` it writes the report
file; without `-f` it prints **only** the JSON to stdout (all logs go to stderr), so it pipes
cleanly to `jq` or a file.

**JUnit for CI:** `--junit report.xml` writes a JUnit XML sidecar alongside any output format —
each finding becomes a failed test case, so GitHub Actions / GitLab render them natively:

```sh
prism analyze . --junit prism-junit.xml   # findings show up as failed tests in the CI UI
```

**Other behavior:** interrupting a run with Ctrl-C cleans up any temporary clone/extraction
before exiting (code `130`). PRISM checks npm for a newer version at most once per 24h (only the
package name is sent); set `PRISM_NO_UPDATE_CHECK=1` to disable it.

### `init` — create a persistent config

```
prism init [--dir <path>] [--yes] [--force]
```

An interactive wizard (on a TTY) that asks the decisions worth making once — score threshold,
severity gate, analyzers, AI provider, output format — and writes a `prism.config.json`. From
then on `prism analyze .` needs no flags. `--yes` (or a non-TTY stdin, so it never blocks CI)
skips the wizard and writes sensible defaults; `--force` overwrites an existing file.

### Configuration file

`prism analyze` discovers `prism.config.json` (or `.prismrc.json`) at the analyzed project's
root. Every key mirrors a CLI flag, and precedence is always: **explicit CLI flag > config file
> built-in default**.

```json
{
  "minScore": 8,
  "categories": ["security", "dependencies", "tests", "structure", "docker"],
  "failOn": "critical",
  "baseline": "origin/main",
  "ai": {
    "enabled": true,
    "provider": "openrouter",
    "model": "anthropic/claude-sonnet-4.6",
    "verify": true,
    "remediate": true
  },
  "output": { "format": "html", "file": "reports/prism.html", "sarif": "prism.sarif" },
  "suppressions": [
    {
      "rule": "SEC-STRIPE-SK",
      "file": "tests/fixtures/**",
      "reason": "Fake key used to test the detector itself",
      "expires": "2027-01-01"
    }
  ]
}
```

The schema is **strict**: an unknown key (a typo like `minscore`) is a usage error, not a
silently ignored setting — a misspelled gate must not become a disabled gate.

**Justified suppressions.** `.prismignore` removes whole paths from analysis; a suppression
accepts **one reviewed finding** and leaves everything else armed. Each entry names a rule id,
an optional file pattern (gitignore syntax), a **mandatory `reason`** — that's what makes it
justified — and an optional `expires` date so exceptions can't quietly outlive their
justification. Suppressed findings are removed from the report, the score, the quality gates,
and the AI triage (no tokens spent judging what a human already ruled on), but they are
**listed in the output with their reasons** — transparency, not a black hole. An expired entry
stops applying and warns; an entry that matches nothing warns as stale. The score refund uses a
standard per-severity table (critical 1.5 · high 1.0 · medium 0.5 · low 0.2), an approximation
by design since each analyzer scores with its own penalties.

**Trust boundary.** Config discovery only applies to **local** targets. A config file inside a
cloned git URL or extracted `.zip` is ignored (with a notice): a third-party repo you're
auditing doesn't get to pick its own gates or suppress its own findings. Pass `--config <path>`
to opt in explicitly.

### `scan` — quick metadata

```
prism scan <path>
```

Prints project metadata without running the full audit: file count, detected stack, runtime, package manager, git/Docker/CI presence, and detected frameworks. Useful for a fast sanity check.

### `doctor` — environment check

```
prism doctor
```

Reports whether the environment is ready: Node version (must be ≥ 22), `git` availability
(needed for git URLs), an AI provider key (for `--ai`), and a writable working directory.
Exits `1` only on a **blocking** issue (e.g. unsupported Node); warnings (missing key, no git)
exit `0` since static analysis works without them.

### `finding get` — a self-contained bundle for one finding

```
prism finding get <report.json> <findingKey> [--context <n>]
```

Prints a single JSON object with everything a coding agent needs to act on one finding: the
finding itself, a code **snippet** around the flagged line (±`--context`, default 3), the AI
**verdict** and proposed **fix** (if the report was triaged), the fix **target** (`file:line`),
and **scan** correlation (project, timestamp, score) so bundles from different scans never mix.
JSON is the only thing on stdout, so it pipes straight into an agent:

```sh
prism analyze . --ai -o json -f report.json
prism finding get report.json "SEC-DB-URL|docker-compose.yml|8"
```

The `findingKey` is the `id|file|line` string shown in the JSON report. A moved report whose
source file is gone still works — the snippet degrades to `null` rather than failing.

### `diff` — compare two reports (regression gate)

```
prism diff <baseline.json> <current.json>
```

Compares two saved JSON reports by finding. It lists **new** findings (regressions) and
**resolved** ones, shows the score delta, and **exits `1` when any new finding appeared** —
otherwise `0`. Bad/missing report files exit `2`. Ideal as a CI baseline gate:

```sh
prism analyze . -o json -f current.json
prism diff baseline.json current.json   # fails the build on a regression
```

### `agent install` — wire PRISM into a coding agent

```
prism agent install <claude|cursor|codex|agents> [--dir <path>] [--min-score <n>]
```

Writes a short **verification skill** into the target agent's rule file — `CLAUDE.md` for
`claude`, `.cursorrules` for `cursor`, `AGENTS.md` for `codex`/`agents` — instructing the agent
to run `prism analyze . --output json` before finishing a task and to fix any regression it
introduced (keyed on the exit-code contract above). The block lives between managed markers
(`<!-- prism:start -->…<!-- prism:end -->`), so re-running updates it in place and **never
touches your own content**. This turns PRISM from a one-off audit into a standing gate inside
the agent's loop.

### `dashboard` — local web UI over saved reports

```
prism dashboard [dir]          # default dir: ./reports
prism dashboard reports -p 4180
```

Serves a local dashboard (bound to `127.0.0.1` only — PRISM practices what it flags) listing
every PRISM JSON report in the directory: project, score, findings count, AI triage tally, and
date. Click through to the full HTML render of any report. Reports are re-read on every refresh, so
new audits appear without restarting. Only plain file names inside the directory are served —
path traversal gets a 404.

---

## Example output

```
  🔍 PRISM
  AI-powered project auditor by LatenciaTech

  ✔ Audit complete in 312ms

  ┌─────────────────────────────────────────────────────┐
  │  my-project                             7.6 / 10   │
  └─────────────────────────────────────────────────────┘

  Category       Score   Findings
  ──────────────────────────────────
  security        6.5      3
  dependencies    9.0      1
  tests           7.0      2
  structure       8.5      2
  docker          5.0      4
  consistency     9.5      0

  Findings (8 total)
  ──────────────────────────────────
  CRITICAL
    [SEC-001] Hardcoded API key detected
              src/services/payment.ts:42
              Suggestion: Move to environment variable.

  HIGH
    [DOC-001] Missing .dockerignore
              Dockerfile present but no .dockerignore — COPY . . may
              bundle secrets and node_modules into the image.

    [DOC-010] Container runs as root
              Dockerfile.api has no USER directive.

  MEDIUM
    [STR-011] God file detected (1,247 LOC)
              src/core/engine.ts · Consider splitting into focused modules.

  ...
```

The JSON output (`-o json`) mirrors this structure as a machine-readable object including `overallScore`, per-category `score` and `findings` arrays, `projectMeta` (detected stack, frameworks, package manager), and `durationMs`.

The HTML output (`-o html`) renders the same report — scores, category bars, findings grouped by severity, AI verdicts with panel tallies, fix proposals, and the executive summary — as a **single self-contained file**: inline CSS, no JavaScript, no external assets, all content HTML-escaped. Open it in any browser, attach it to an email, or archive it; it needs nothing else.

---

## Scoring weights

```
Overall score = Σ(category_score × weight) / Σ(weights)

Security      × 2.0
Dependencies  × 1.5
Tests         × 1.5
Agentic       × 1.5
Structure     × 1.0
Docker        × 1.0
Workflow      × 1.0
Consistency   × 0.8
```

A category with nothing to analyze is **N/A, not a silent 10/10**: a project with no Docker configuration gets `docker: N/A` and the category is excluded from the overall score entirely — "not analyzed" must never read as "perfect". A project with zero source files (pure infrastructure/Docker/YAML repo) likewise gets `tests: N/A` rather than a critical finding.

---

## False-positive elimination

Credibility is the primary design constraint. Every analyzer decision is checked against file context before a finding is emitted.

**File-context classifier** (`src/utils/file-context.ts`) assigns each file one of: `source`, `test`, `fixture`, `template`, `security-tool`, `documentation`, `generated`, `vendor`, `config-template`. Files classified as fixture, template, documentation, generated, or vendor are skipped entirely. Findings in test files have their severity stepped down one level.

**`.prismignore`** — place a `.prismignore` file at the project root to exclude paths from analysis. It uses the same syntax as `.gitignore`.

**Specific decisions driven by credibility:**

- The `SEC-AWS-SECRET` regex (any 40-character base64 string) was removed because it was the single largest source of false positives across all tested projects. Only `SEC-AWS-KEY` (AKIA prefix) is retained.
- Docker secret mount paths (`./secrets/...`, `/run/secrets/...`) in docker-compose `environment` blocks are not flagged as hardcoded credentials.
- Tests that import only integration frameworks (`supertest`, `playwright`, `@modelcontextprotocol/sdk`, `@nestjs/testing`, etc.) or fork a subprocess (`node:child_process` + `fork/spawn`) are recognized as integration tests, not flagged for missing SUT imports.
- Projects with `totalLoc = 0` (no source files) return `tests: N/A` rather than a critical finding.
- The import graph used for circular-dependency detection (`STR-012`) only counts value imports; `import type` statements that vanish at compile time are excluded from cycle detection.

Every one of these started as a wrong finding on a real project. Each is now a trap in the
[false-positive benchmark](#false-positive-benchmark) (n = 28 cases, half of them traps), which
fails CI if the rule ever fires again — that, not a percentage, is the false-positive claim.

---

## Development

### Run tests

```sh
npm test               # vitest run (single pass)
npm run test:watch     # vitest watch mode
npm run test:coverage  # with coverage report
```

A large regression suite covers every analyzer, the utility modules (`loc`, `import-graph`, `file-context`, `prismignore`), the AI layer (with an injected fake client — the suite never hits the network), the benchmark corpora, and end-to-end CLI scenarios on Linux, macOS and Windows.

### Lint

```sh
npm run lint           # biome check
npm run lint:fix       # biome check --write
```

### Self-audit

```sh
npm run audit          # runs: tsx src/cli/index.ts analyze .
```

### False-positive benchmark

```sh
npm run bench          # planted issues must be found; field-tested FP traps must stay silent
```

A reproducible corpus (see `benchmarks/cases.ts`) that fails CI on any precision/recall
regression — coverage gained at the cost of noise never merges. **n = 28 cases**: 14 planted
issues that must be found and 14 false-positive traps that must stay silent, each trap a
mistake PRISM actually made on a real project (7 cases need semgrep or OSV.dev and are skipped,
loudly, when unavailable). A green run means "no regression on those 28", nothing more.

### AI-triage benchmark

```sh
npm run bench:ai                  # live model from ANTHROPIC_API_KEY / OPENROUTER_API_KEY
npm run bench:ai -- --dry-run     # exercise the corpus offline, zero cost
npm run bench:ai -- --vote a,b    # measure a verification panel
```

The static benchmark measures the rules; this one measures the **judge**. Every case in
`benchmarks/ai/cases.ts` is a finding the static layer really emits, paired with the verdict a
careful reviewer reaches — genuine issues the model must not excuse (including the two judgment
errors seen in the field), same-file false positives it should catch, and cross-file false
positives whose evidence lives in another module (reported separately, as the baseline for
cross-file context). The run hard-fails only when a **real issue is excused as a false positive**
— the one outcome that hides risk; missed false positives and `uncertain` verdicts are reported as
rates. It needs a key and a live model, so it runs before releases, not on every push; the
corpus itself is health-checked offline in the test suite so a case can never rot unnoticed.
**n = 17 cases**: 11 genuine issues, 3 same-file false positives, 3 cross-file false positives.
Last live run (claude-opus-4-8): 17/17, 0 real issues excused. Seventeen is a signal, not a
statistic — the corpus grows with every field false positive or false negative, and so should
your reading of these numbers.

---
