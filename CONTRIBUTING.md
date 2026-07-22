# Contributing to PRISM

Thanks for your interest in PRISM, an open-source project by
[LatenciaTech](https://latenciatech.com). Contributions are welcome.

## Development setup

```sh
git clone https://github.com/picaro10/prism.git
cd prism
npm install
```

## The workflow

Everything the CI enforces, you can run locally before opening a PR:

```sh
npm run lint          # Biome
npx tsc --noEmit      # type check (0 errors)
npm run test:coverage # tests + enforced coverage thresholds
npm run build         # tsup bundle
npm run audit         # PRISM audits itself (dogfood)
```

PRISM holds itself to its own bar: the CI self-audit runs
`analyze . --min-score 8.5 --fail-on critical`, so a change that regresses
PRISM's own quality score (or introduces a critical finding) fails the build.

## Guidelines

- **Tests first.** New behavior needs a regression test; the project is
  test-driven and the false-positive hunt lives in the test suite.
- **Keep the false-positive bar high.** PRISM's value is that it doesn't cry
  wolf. A new check that adds noise is worse than no check.
- **Match the surrounding code.** Strict TypeScript (no `any`), ESM imports with
  `.js` extensions, Biome formatting. Findings and messages are in English.
- Open an issue first for anything large or design-changing.

## Adding a detection rule

The most common contribution. The checklist a rule PR must satisfy:

1. **Open a [new-rule proposal](.github/ISSUE_TEMPLATE/new-rule.md) first** with a vulnerable
   example, a correct example, and the false-positive traps you already thought of.
2. **Pick the ID**: `<CAT>-<NNN>` in the category's namespace (`SEC`/`DEP`/`TST`/`STR`/`DOC`/
   `CON`/`AGT` — see [docs/rules](docs/rules/README.md)). IDs are stable public API: reports,
   suppressions, SARIF, and baselines key on them. Never renumber or reuse an ID.
3. **Implement in the category's analyzer** (`src/analyzers/<category>.ts`) as a small exported
   pure function (`detectX(content): number[]` returning 1-based lines) the analyzer loops
   over — that's what makes it unit-testable. Emit a `Finding` with `id`, `severity`, `title`,
   `description`, actionable `suggestion`, `file`, `line`.
4. **Regex vs parser:** line-level regex heuristics are the norm here (fast, dependency-free);
   they must carry the **anti-self-detection guard** (skip comments and regex/pattern-definition
   lines — see `isPatternDefinition` in `src/analyzers/agentic.ts`). If a rule genuinely needs
   cross-file resolution, look at the import-graph utilities (`src/utils/import-graph.ts`,
   used by `STR-012`/`STR-013`) before reaching for a parser dependency.
5. **Tests, both directions:** every vulnerable example fires; every correct/legitimate example
   does NOT. FP tests are not optional — they are the point.
6. **Document it** in `docs/rules/<category>.md` (a sync test fails CI if you don't), including
   its known false-positive traps and, when relevant, a sensible suppression example.
7. **Dogfood must stay green:** `npm run audit` — if your rule flags PRISM itself, either PRISM
   has the problem (fix it) or your rule has one (fix that).

**Severity guide:** `critical` = exploitable secret/vuln right now · `high` = a real risk with a
clear failure path · `medium` = a risk that depends on context · `low` = hygiene · `info` =
signal only, no score impact expected.

## Validation before sending

```sh
npm run lint && npx tsc --noEmit && npm run test:coverage && npm run build && npm run bench && npm run audit
```

All six green locally = CI green (plus the package-smoke job, which verifies the packed
tarball installs and runs). `npm run bench` is the false-positive benchmark: planted issues
must be found, historical FP traps must stay silent — a rule change that regresses either
direction fails before it dirties a real report.

## License

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
