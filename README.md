# PRISM

[![CI](https://github.com/picaro10/prism/actions/workflows/ci.yml/badge.svg)](https://github.com/picaro10/prism/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%E2%89%A522-brightgreen)

**Static-analysis project auditor for code quality, security, and structural health.**

PRISM is a CLI tool by [LatenciaTech](https://latenciatech.com) that scans a local codebase and produces a scored audit report across seven dimensions. It combines **deterministic static analysis** with an **optional LLM triage layer**: the static analysis works fully offline and needs no API key, while the AI enrichment (`--ai`) is opt-in and judges each finding in context. Both are shipped and working today.

---

## What PRISM checks

| Category | Weight | What it analyzes |
|---|---|---|
| **Security** | 2.0× | Hardcoded secrets, API keys, tokens; `.env` files committed to the repo; Shannon-entropy anomalies. |
| **Dependencies** | 1.5× | Lock file presence; wildcard versions (`*`, `^`, `~` in sensitive positions); `npm audit` vulnerabilities; Python `requirements.txt` unpinned versions; `engines` field. |
| **Tests** | 1.5× | Test suite existence; test-to-source ratio; decorative tests (zero assertions in entire file); empty test files; skipped/disabled tests; snapshot overuse; tests with no SUT import. |
| **Structure** | 1.0× | README, `.gitignore`, linter config, `tsconfig`; flat-root dumps; excessive nesting; god files (`STR-011`: >400 / >600 / >900 / >1500 LOC with tiered severity); circular import dependencies (`STR-012`, via Tarjan SCC on the resolved import graph); dead files (`STR-013`: TS/JS source nothing reaches — counts type-only imports, tsconfig aliases, package.json refs, path strings in code/HTML/Dockerfiles/shell, shebang and convention entries; skips itself if a tsconfig is unparseable). |
| **Docker** | 1.0× | Container running as root; no multi-stage build; `:latest` tag; missing `.dockerignore`; missing `HEALTHCHECK`; `docker-compose` privileged mode, hardcoded credentials, missing restart policy, missing resource limits, ports bound to `0.0.0.0`. |
| **Consistency** | 0.8× | Mixed file-naming conventions (kebab/snake/camel/pascal) within the same language; mixed natural language (Spanish + English identifiers in the same file); inconsistent indentation (tabs vs spaces). |
| **Agentic** | 1.5× | AI-agent-specific risks that mainstream analyzers don't model: shell commands built with interpolation/concatenation (`AGT-001`, agent command injection — `execFile` is the safe pattern); environment secrets interpolated into an LLM prompt/message (`AGT-002`, credential leaking into model context). High-signal and conservative by design. |

The overall score is a weighted average of per-category scores, each on a 0–10 scale.

**Full rule catalog:** every rule id, severity, and its known false-positive traps are documented
in [`docs/rules/`](docs/rules/README.md). A test keeps the catalog in sync with the analyzers —
an undocumented rule fails CI.

---

## Requirements

- Node.js **≥ 22**
- npm

---

## Install

**From npm** (once published):

```sh
npm install -g @latenciatech/prism
prism analyze <path>
# or without installing:
npx @latenciatech/prism analyze <path>
```

**From source** (works today):

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
in the repo's Security tab, ranked by `security-severity`.

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

### `--ai` — AI triage (Fase 2)

```
# Static analysis + LLM triage of every finding
prism analyze <path> --ai

# Override the triage model (default: claude-opus-4-8)
prism analyze <path> --ai --ai-model claude-sonnet-4-6

# Exercise the full AI pipeline with canned responses — no network, no API key
prism analyze <path> --dry-run
```

`--dry-run` runs the whole triage → remediation → summary pipeline with canned verdicts (each
clearly marked `[dry-run]`), so you can see the report shape or test the flow at **zero token
cost** and without a key. It also works on the `triage` command.

The static layer flags patterns; the AI layer **judges them in context**. With `--ai`, PRISM
sends each finding (and the surrounding file's code) to Claude, which classifies it as
`✓ real`, `✗ likely FP`, or `? uncertain`, with a confidence and a one-line reason — the same
judgment that distinguishes a Docker mount path from a hardcoded secret, or a test fixture
from production code.

- **Two providers.** Default is the Anthropic API (`ANTHROPIC_API_KEY`), with full native
  features (structured outputs, adaptive thinking, prompt caching). You can also use
  **OpenRouter** (`OPENROUTER_API_KEY`), which is OpenAI-compatible — set `--ai-provider openrouter`
  (auto-detected when only `OPENROUTER_API_KEY` is present). The OpenRouter default model is
  `openai/gpt-4.1-mini` (cheap, for development); override with `--ai-model <slug>` (e.g.
  `--ai-model anthropic/claude-opus-4.8`). OpenRouter uses JSON mode instead of Anthropic-native
  structured outputs.
- **Opt-in and offline-by-default.** Without `--ai`, PRISM makes no network calls and needs no
  key. `--ai` fails fast if the selected provider's key is missing.
- **Privacy note.** `--ai` sends snippets of the analyzed project's source (including the lines
  that triggered each finding — a flagged secret's line among them) to the selected external
  provider (Anthropic or OpenRouter). Do not use `--ai` on code you cannot share with a third
  party. The static-only mode never transmits anything.
- **It annotates, it does not re-score.** The static score is unchanged; the AI overlay informs
  the human. If the AI call fails, the static report is still produced.
- **False-positives are double-checked.** Any verdict the first pass calls `false-positive` gets
  an adversarial re-check that must confirm it with concrete code evidence — otherwise the
  finding stays `real`/`uncertain`. This catches lenient or hallucinated FPs (disable with
  `--no-ai-verify`). Per-file calls run concurrently (`--ai-concurrency <n>`, default 5).
- **N-model vote.** A single model makes confident judgment errors (and re-checking with the
  same model shares its blind spots). `--ai-vote model-a,model-b,model-c` makes every
  false-positive verdict face a panel: the FP survives only if the panel is **unanimous** —
  any skeptic's dissent blocks the excusal (the N-voter generalization of the single
  adversarial re-check). A blocked FP becomes `real` (strict majority) or `uncertain`
  (anything less — surfaced for the human). The tally is appended to the reasoning
  (`[panel: 1 real · 2 fp · 0 uncertain]`). A voter that errors abstains as `uncertain`.
  Only false-positive verdicts pay the panel cost.
- **Remediation guide.** Every finding the triage confirms as `real` gets a concrete fix
  proposal — what to change, where, with a short snippet when it helps — plus an honest effort
  estimate (`low`/`medium`/`high`). Rendered inline under each finding (`🔧 fix`) and included
  in JSON as `aiRemediation`. Only confirmed-real findings pay the extra call; disable with
  `--no-ai-remediate`.
- **Executive summary.** After triage, one more call writes a short prose assessment of the
  project (overall health, what's urgent), focused on the confirmed-real findings. Rendered at
  the top of the report (`🧠 AI Assessment`) and included in JSON as `aiSummary`. Disable with
  `--no-ai-summary`.
- Verdicts appear inline under each finding, plus a summary line
  (`AI triage: N real · M false positives · K uncertain`), and are included in JSON output
  under `aiTriage`.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
prism analyze . --ai
```

### `triage` — re-run AI triage on a saved report

```
prism analyze <path> -o json -f report.json     # scan once
prism triage report.json                          # re-triage cheaply, as often as you like
prism triage report.json --ai-model openai/gpt-4o-mini   # compare models without re-scanning
```

Decouples the (cheap, fast) static scan from the (paid) LLM passes. Loads a saved JSON report,
re-reads the project's files from its recorded `projectPath`, and runs triage + remediation +
summary again — without re-scanning. Ideal for iterating on the AI layer or comparing models on
the same report. Takes the same `--ai-*` flags as `analyze --ai`; requires the provider's API key.

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
Consistency   × 0.8
```

A project with no Docker configuration scores 10/10 for that category (not penalized for something that doesn't apply). A project with zero source files (pure infrastructure/Docker/YAML repo) is not penalized for having no tests.

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

The false-positive rate has been tracked across five real projects. As of v0.9.0 the measured credibility on `orion_new` (1,000+ files) is approximately 96%.

---

## Development

### Run tests

```sh
npm test               # vitest run (single pass)
npm run test:watch     # vitest watch mode
npm run test:coverage  # with coverage report
```

The test suite has 400+ tests covering all analyzers, utility modules (`loc`, `import-graph`, `file-context`, `prismignore`), the AI triage layer (with an injected fake client — the suite never hits the network), and integration scenarios.

### Lint

```sh
npm run lint           # biome check
npm run lint:fix       # biome check --write
```

### Self-audit

```sh
npm run audit          # runs: tsx src/cli/index.ts analyze .
```

---

## Language & platform support

PRISM inspects some ecosystems deeply and others only at the metadata level. The score reflects
**what PRISM understands** — a high score on an unsupported stack means "nothing wrong in what
was inspected", not "deep audit passed":

| Area | Support |
|---|---|
| TypeScript / JavaScript | **Full** — all seven analyzers, import graph, dead-file and cycle detection |
| Python | Partial — dependencies (`requirements.txt` pinning) and basic structure |
| Docker / Compose | Full — Dockerfile and docker-compose checks |
| Secrets / entropy | Language-agnostic — any text file |
| Monorepos | Partial — analyzed as one tree; per-package scoring not yet separated |
| Dynamic imports | Limited — `import()` with non-literal arguments is not resolved in the graph |
| Generated / vendored code | Excluded by the file-context classifier |
| Other languages (Rust, Java, Go…) | Metadata and structure only — no language-aware analysis |

---

## Roadmap

| Phase | Status | Description |
|---|---|---|
| **Fase 1** — Static analysis CLI | **Done** | 7 analyzers, weighted scoring, JSON/CLI output, CI exit codes |
| **Fase 2** — LLM triage | **Done** | `--ai`: triage + adversarial re-check + N-model vote, remediation guide, executive summary, standalone `triage` |
| **Fase 3** — Reports & outputs | **Done** | Self-contained HTML, JUnit XML, SARIF 2.1.0 |
| **Fase 4** — Dashboard + multi-input | **Done** | Local dashboard, git URL input, `.zip` input |
| **Fase 5** — Agent-ready | **Done (v1.0.0)** | Exit-code contract, `diff`, `finding get`, `agent install`, quality/new-code gates |
| **Fase 6** — Persistent config | **Done** | `prism.config.json` + `prism init` wizard, justified suppressions with reasons and expiry |
| **Next** | Planned | Public rule catalog, reproducible FP benchmark, more agentic checks (MCP exposure, destructive tools without confirmation, prompt injection, fail-open fallbacks) |

---

## License

[MIT](LICENSE) — © 2026 LatenciaTech (Spain).
