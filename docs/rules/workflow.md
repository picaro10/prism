# Workflow rules (`WFL-*`) — weight 1.0×

CI/CD risks in GitHub Actions workflows (`.github/workflows/*.yml`). A project with no
workflows scores 10/10 here — absence isn't a defect.

Deliberately **not** an actionlint/zizmor rebuild: syntax validation and deep Actions auditing
have excellent dedicated tools. PRISM's angle is what a linter that sees the YAML in isolation
cannot do — **cross-checks against the actual repository** (do the filtered branches exist? is
there a lockfile the cache setting ignores?) plus the integrated score, suppressions, baseline,
and AI triage every category gets.

| ID | Severity | What it detects |
|---|---|---|
| `WFL-001` | critical | `pull_request_target` checking out the PR head — the classic "pwn request" takeover. |
| `WFL-002` | high | Untrusted event data (`github.event.issue.title`, `github.head_ref`…) interpolated into a `run:` script — script injection, the workflow cousin of `AGT-001`. |
| `WFL-003` | high / medium | Third-party action pinned to a mutable branch (high) or tag (medium) instead of a commit SHA. First-party (`actions/`, `github/`) tags are accepted practice. |
| `WFL-004` | medium | No `permissions:` block anywhere — the default `GITHUB_TOKEN` can be write-broad. |
| `WFL-005` | high | `permissions: write-all` — every scope granted explicitly. |
| `WFL-006` | high | A `push`/`pull_request` trigger whose `branches:` filter names **only branches that don't exist** in the repo — the workflow never runs, its badge lies. Cross-checked against real local branches; globs are skipped. |
| `WFL-007` | low | No job sets `timeout-minutes` (one finding per workflow) — a hang holds the runner for GitHub's 6-hour default. |
| `WFL-008` | low | No `concurrency` group on a push/PR workflow (one per workflow) — redundant runs stack up. |
| `WFL-009` | high | `continue-on-error: true` on a job/step that is a quality or security gate — the check fails **open**, the workflow cousin of `AGT-006`. |
| `WFL-010` | low | `actions/setup-node` without `cache:` while the repo commits a lockfile — every run re-downloads the tree. Cross-checked against real repo files. |
| `WFL-011` | medium | Self-hosted runner on a PR-triggered workflow — fork code executing on your own infrastructure. |
| `WFL-PARSE` | medium | The workflow file is not valid YAML — it will fail at load time on GitHub. |

## Notes

- **`WFL-006` is a field lesson codified.** This project shipped v1.0.0 with CI listening on
  `master` while the repo ran on `main` — the workflow never triggered and the README sold
  checks nobody executed. That bug is invisible to a YAML linter; it needs the repo.
- **`WFL-003`'s aggregate penalty is capped** (like `AGT-003`): ten unpinned actions are one
  missing convention, not ten independent failures. Every occurrence is still listed.
- **`WFL-002` fix pattern:** route the value through `env:` and reference it as `"$VAR"` — the
  shell then treats it as data, not code.

## Suppression

```json
{ "rule": "WFL-003", "file": ".github/workflows/release.yml", "reason": "Vendor action audited and mirrored internally", "expires": "2027-01-01" }
```
