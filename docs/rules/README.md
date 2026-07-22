# PRISM rule catalog

Every rule PRISM can emit, by category. Each category page lists all its rules with severity and
intent; rules with known false-positive traps document them explicitly — credibility is PRISM's
primary design constraint, and a rule you can't trust is worse than no rule.

| Category | Weight | Rules |
|---|---|---|
| [Security](security.md) | 2.0× | `SEC-*` — secrets, keys, committed .env, entropy |
| [Agentic](agentic.md) | 1.5× | `AGT-*` — AI-agent-specific risks (PRISM's own territory) |
| [Dependencies](dependencies.md) | 1.5× | `DEP-*` — lock files, wildcards, npm audit, Python pinning |
| [Tests](tests.md) | 1.5× | `TST-*` — existence, ratio, decorative tests |
| [Structure](structure.md) | 1.0× | `STR-*` — layout, god files, circular imports, dead files |
| [Docker](docker.md) | 1.0× | `DOC-*` — Dockerfile and docker-compose hygiene |
| [Consistency](consistency.md) | 0.8× | `CON-*` — naming, language and indentation consistency |

Rule IDs are stable: reports, suppressions, SARIF output, and the baseline gate all key on them.

## Suppressing a rule

Any finding can be accepted with a **justified suppression** in `prism.config.json` — rule id,
optional file pattern (gitignore syntax), a mandatory reason, and an optional expiry:

```json
{
  "suppressions": [
    {
      "rule": "AGT-003",
      "file": "src/skills/**",
      "reason": "Destructive tools are gated by the external policy engine (data/policies/default.yml)",
      "expires": "2027-01-01"
    }
  ]
}
```

Suppressed findings are removed from the score and the gates but stay listed in the output with
their reasons. See the README's *Configuration file* section for the full semantics.

## Meta rules

| ID | Severity | Meaning |
|---|---|---|
| `<ANALYZER>-ERROR` | high | An analyzer threw and could not complete; its category scores 0 for the run. |
