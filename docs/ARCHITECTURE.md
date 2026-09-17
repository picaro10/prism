# Architecture

This is the map a new contributor needs before touching code: how an audit
runs end to end, why the trust boundaries are drawn where they are, and the
doctrine behind the scoring — not a tour of every file.

## Audit pipeline (`src/core/engine.ts` — `runAudit`)

1. **Scan** (`src/core/scanner.ts`) — walk the target tree respecting
   `.gitignore` — the root one and every nested one, rewritten with git
   semantics (plus a fixed always-ignore list: `node_modules`, `.git`,
   `dist`, …), build a flat file list + tree, detect language/framework.
   Bounded: `MAX_SCAN_FILES` (100,000) caps the inventory so a pathological
   tree can't spin the walker unbounded; a capped scan sets
   `scanWarnings.truncated` and the structure analyzer surfaces it in its
   summary — never a silent undercount.
2. **Confined reader** (`src/utils/safe-read.ts`) — every analyzer reads
   files through `confinedReader(root)`, which rejects `../`/absolute paths
   and caps a single read at 15MB (`MAX_READ_BYTES`). Analyzers never call
   `fs.readFile` directly against arbitrary paths from a scan or a report.
3. **Analyzers run** (`src/analyzers/*.ts`) — each implements the `Analyzer`
   interface (`analyze(scan, readFile) → AnalyzerResult`), is independent of
   the others, and returns `{ category, score, findings[], summary,
   applicable? }`. A thrown analyzer error is caught per-analyzer and turned
   into a `high`-severity finding for that category — one broken analyzer
   does not abort the audit.
4. **Merge by category** (`mergeResultsByCategory`) — two analyzers can share
   a category (`secrets` + `semgrep` → `security`; multi-ecosystem
   `dependencies` + `osv` → `dependencies`). Merged score is the **min**
   across members (a category is only as healthy as its weakest signal,
   deliberately — see "Scoring doctrine" below), findings concatenate,
   `applicable: false` only survives if *every* member had nothing to check.
5. **Suppressions** (`src/core/suppressions.ts`) apply before scoring,
   fingerprinting, gates, and AI triage — a human-justified suppression
   should not cost AI-triage tokens or trip the new-code gate.
6. **Score** (`calculateOverallScore`) — weighted average across categories
   (`CATEGORY_WEIGHTS`: security 2.0, tests/deps/agentic 1.5, structure/
   docker/workflow 1.0, consistency 0.8). Non-applicable categories are
   excluded from the average entirely, not counted as a free 10.
7. **Fingerprints** (`src/core/fingerprint.ts`) — stable, line-shift-robust
   IDs per finding, used by the baseline / new-code gate to tell "already
   known" from "introduced by this diff."
8. **AI triage** (opt-in, `src/ai/`) — `applyAiTriage` runs after the static
   report is fully built and never mutates it destructively: a triage
   failure is caught and logged via `onProgress`, the static report always
   survives. What the model gets to read is decided per rule by its
   **context tier** (`CONTEXT_TIER`, `src/core/rule-metadata.ts`): `none`
   (the evidence is a project-level fact — a count, the graph, an advisory
   database — so the finding is batched without file content), `file` (a
   line pattern; the file is sent — and the default for any unknown rule,
   so a new rule can only be made cheaper on purpose), `neighborhood`
   (the verdict depends on code elsewhere: `src/ai/neighborhood.ts` walks
   the import graph — imports whose names are used near the flagged line,
   importers that mention an anchor token from it — and attaches those
   files as evidence, bounded and deterministic, falling back to `file`
   when nothing qualifies). Remediation ignores tiers on purpose:
   proposing a fix genuinely needs the content.
   Final verdicts and fixes go through the **verdict cache**
   (`src/ai/cache.ts`): keyed by prompt text, judge identity, finding
   identity and a hash of the content sent, stored in the operator's cache
   dir (never in the audited tree — a hostile repo cannot plant entries),
   written atomically after every store so an interrupted run resumes for
   free. Synthesized verdicts (failed call, skipped finding, abstaining
   panel voter) are never cached — a transient failure must not freeze into
   a judgment.

## Trust boundaries — the modules that matter most

PRISM's job is to run against code it does not trust. These are the modules
that carry that boundary; changes here get the most scrutiny (see
`.github/CODEOWNERS`):

- **`src/core/input.ts`** — resolves a CLI target (local path / git URL /
  `.zip`) to a directory. `assertSafeGitUrl` blocks argument-injection
  (`-`-prefixed targets) and remote-helper transports (`ext::…`, any
  `scheme::` form) before ever shelling out to `git clone`. Zip extraction
  checks entry count, total uncompressed size, and per-entry compression
  ratio **before writing a byte** (zip-bomb guard), and rejects zip-slip
  paths that would escape the destination directory.
- **`src/utils/git-safe.ts`** — every git invocation against a
  possibly-hostile repo goes through `safeGitArgs()`/`safeGitEnv()`, which
  neutralize `core.fsmonitor`, `core.hooksPath`, and `ext::` remote helpers a
  malicious `.git/config` could otherwise use to run arbitrary commands as
  the operator. Uses a real empty dir/file, not `/dev/null` — that path
  isn't portable to native Windows git.
- **`src/dashboard/server.ts`** — the local report viewer binds to loopback
  and additionally validates the `Host` header (`isLocalHost`) against
  DNS-rebinding; `/report?f=` only ever resolves a plain basename against
  reports it already enumerated, so it can't be made to read outside its
  directory.
- **`src/cli/shared.ts`** — `checkReportRoot` handles the case where a
  *saved report* (untrusted — it could be handed to you by someone else)
  names its own `projectPath`. That path is only trusted if it resolves
  (post-`realpath`, anti-symlink) inside the current working directory;
  otherwise the operator must pass `--root` explicitly. `loadAllowlistedEnv`
  only ever imports `ANTHROPIC_API_KEY` / `OPENROUTER_API_KEY` / `PRISM_*`
  from a `.env` in cwd — in `cd project && prism analyze .` that `.env`
  belongs to the *audited* project, so nothing else from it reaches the
  auditor's process or subprocesses.

## Scoring doctrine

- **The score is a heuristic indicator, not a calibrated metric.** It is
  documented as such deliberately, after an external audit flagged the
  README implying otherwise. Don't build features that assume the number is
  comparable across unrelated projects or stable across PRISM versions.
- **"Unknown is not clean."** Every place PRISM cannot fully verify
  something — `npm audit` unreachable, an OSV advisory budget exceeded, a
  semgrep rule timing out, a lockfile PRISM couldn't parse — emits an
  explicit low/medium-severity finding saying so, instead of silently
  passing. If you add a new external call or a new cap, follow this pattern:
  degrade to a visible "unknown" finding, never to silence.
- **Category merge uses `min`, not sum**, on purpose (see
  `mergeResultsByCategory`) — summing would double-count a category's weight
  when two analyzers share it and would decalibrate the benchmark. This has
  been raised in external review and re-affirmed, not overlooked.
- **A perfect 10/10 never displays if there are any non-info findings** —
  `calculateOverallScore` caps a rounds-to-10 result at 9.9 so the number
  never claims more certainty than the findings support.

## Where a new detection rule goes

- Static/structural check → new `Finding` in the relevant `src/analyzers/*.ts`,
  ID prefix matching the file (`STR-*`, `DEP-*`, `AGT-*`, `WFL-*`, …).
- Taint/dataflow check → `src/analyzers/semgrep-rules.ts` (embedded YAML,
  `prism-severity`/`cwe`/`owasp`/`fix` metadata per rule — see
  `docs/rules/README.md` for the authoring guide and the CWE/OWASP catalog
  sync tests that keep source, rule-pack metadata, and docs in agreement).
- Every new rule needs a benchmark case (`benchmarks/cases.ts`) — a planted
  true positive AND, where the rule class is known for false positives, a
  trap that must stay silent.
- Changes to the AI layer (`src/ai/`, prompts, tiers, context) are measured
  with `npm run bench:ai` against `benchmarks/ai/cases.ts`: findings the
  static layer really emits, each with the verdict a careful reviewer
  reaches. The gate is asymmetric on purpose — a real issue excused as a
  false positive fails the run (hidden risk); a false positive kept as real
  is reported (noise). Cross-file cases are the baseline the import-graph
  context has to move.
