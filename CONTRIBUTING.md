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

## License

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
