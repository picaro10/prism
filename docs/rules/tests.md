# Test rules (`TST-*`) — weight 1.5×

| ID | Severity | What it detects |
|---|---|---|
| `TST-001` | critical | No test files at all in a project with source code. |
| `TST-002` | high / medium | Very low / low test-to-source ratio. |
| `TST-003` | medium | No test framework configuration found. |
| `TST-010` | medium | Empty or near-empty test file. |
| `TST-011` | high | A test file with zero assertions (decorative tests). |
| `TST-012` | low | Skipped/disabled tests (`it.skip`, `xit`, `@pytest.mark.skip`). |
| `TST-013` | low | Heavy snapshot usage (snapshots instead of assertions). |
| `TST-014` | medium | A test file that never imports its subject under test. |

## False-positive notes (field-tested)

- **Integration tests are recognized.** A test importing only integration frameworks
  (`supertest`, `playwright`, `@modelcontextprotocol/sdk`, `@nestjs/testing`, …) or forking a
  subprocess is not flagged by `TST-014` — it exercises the system from outside by design.
- **Projects with zero source files** (pure infra/Docker/YAML repos) score `tests: N/A`
  rather than being punished for having no tests of code they don't contain.
- `TST-011` counts assertions across the whole file; helper-heavy suites that assert through
  utilities can look decorative — verify before trusting, suppress with the reason if genuine:

```json
{ "rule": "TST-011", "file": "tests/e2e/**", "reason": "Assertions live in the shared harness helpers" }
```
