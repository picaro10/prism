# Dependency rules (`DEP-*`) — weight 1.5×

| ID | Severity | What it detects |
|---|---|---|
| `DEP-001` | high | No lock file (`package-lock.json`/`yarn.lock`/`pnpm-lock.yaml`) — unreproducible installs. |
| `DEP-002` | high | Wildcard version (`*`, bare `latest`) for a dependency. |
| `DEP-003` | medium | Very high dependency count. |
| `DEP-004` | low | No `engines` field in `package.json`. |
| `DEP-005` | medium | No `test` script defined. |
| `DEP-AUDIT-CRITICAL` | critical | `npm audit` reports critical vulnerabilities. |
| `DEP-AUDIT-HIGH` | high | `npm audit` reports high vulnerabilities. |
| `DEP-AUDIT-SKIP` | info | `npm audit` could not run (offline, no lock file) — audit coverage is unknown. |
| `DEP-PARSE-ERR` | high | `package.json` is not parseable. |
| `DEP-PY-001` | medium | Unpinned versions in `requirements.txt`. |

## Multi-ecosystem SCA (`DEP-OSV-*`, via OSV.dev)

Known-vulnerability lookup for **non-npm lockfiles** against the public [OSV.dev](https://osv.dev)
API: `requirements.txt` (pinned), `poetry.lock`, `Pipfile.lock` (PyPI), `Cargo.lock` (crates.io),
`go.mod` (Go), `composer.lock` (Packagist), `Gemfile.lock` (RubyGems). npm stays with `npm audit`.
Runs only when such a lockfile exists; lockfiles in fixture/vendor/template paths are ignored.

| ID | Severity | What it detects |
|---|---|---|
| `DEP-OSV-CRITICAL` | critical | OSV.dev reports critical advisories for locked packages. |
| `DEP-OSV-HIGH` | high | OSV.dev reports high advisories for locked packages. |
| `DEP-OSV-LOWER` | low | Lower-severity or unclassified advisories (grouped into one note). |
| `DEP-OSV-SKIP` | low | Lockfiles exist but OSV.dev was unreachable — advisory status is unknown, not clean. |

Like `DEP-AUDIT-*`, this is a **dynamic external signal** — see the note below. It informs; never
build a count-based CI gate on it.

## Notes

- **`DEP-AUDIT-*` and `DEP-OSV-*` are dynamic.** They depend on external vulnerability databases, so new findings
  can appear without any code change. Don't build a CI gate on `--max-high 0` because of it —
  gate on `--fail-on critical` (which you control by updating) and let the score floor handle
  the rest. This is a field-learned lesson, not a guess.
- Transitive advisories with no upstream fix are the classic justified suppression:

```json
{ "rule": "DEP-AUDIT-HIGH", "reason": "Transitive via build tool X, no upstream fix; tracked in issue #12", "expires": "2026-12-31" }
```
