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

## Notes

- **`DEP-AUDIT-*` is dynamic.** It depends on external vulnerability databases, so new findings
  can appear without any code change. Don't build a CI gate on `--max-high 0` because of it —
  gate on `--fail-on critical` (which you control by updating) and let the score floor handle
  the rest. This is a field-learned lesson, not a guess.
- Transitive advisories with no upstream fix are the classic justified suppression:

```json
{ "rule": "DEP-AUDIT-HIGH", "reason": "Transitive via build tool X, no upstream fix; tracked in issue #12", "expires": "2026-12-31" }
```
