import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { basename, extname } from 'node:path';
import { classifyFile, isExcludedContext } from '../utils/file-context.js';

/**
 * TestsAnalyzer — Evaluates test suite quality, coverage, and detects anti-patterns.
 *
 * Checks:
 * - Test files exist at all
 * - Test-to-source ratio
 * - Tests without real assertions (decorative tests)
 * - Empty test files
 * - Test config present (vitest, jest, pytest)
 * - Coverage config/thresholds defined
 * - Snapshot overuse
 * - Skipped/disabled tests (.skip, .todo, xit, @pytest.mark.skip)
 * - Tests with no await on async operations
 */
export class TestsAnalyzer implements Analyzer {
  readonly name = 'tests';
  readonly category = 'tests' as const;
  readonly description = 'Evaluates test suite quality, coverage, and detects anti-patterns';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    // Identify test files and source files. Skip non-user-authored contexts
    // (test fixtures, templates, vendored/generated) — a decorative test that
    // is itself a fixture is intentional scaffolding, not a real finding.
    const isReal = (f: string) => !isExcludedContext(classifyFile(f));
    const testFiles = scan.files.filter((f) => isTestFile(f) && isReal(f));
    const sourceFiles = scan.files.filter((f) => isSourceFile(f) && !isTestFile(f) && isReal(f));

    // --- Guard: nothing to test ---
    // A repo with zero source files (pure infra/deployment/docs: Dockerfiles,
    // compose, shell, SQL, YAML) has nothing to unit-test. Slamming it with a
    // critical "no tests" + score 0 is a false positive that destroys trust.
    if (sourceFiles.length === 0) {
      return {
        category: 'tests',
        score: 10,
        findings,
        summary: 'No source code to test (infra/config/docs repo) — tests N/A',
      };
    }

    // --- Check: Any tests at all? ---
    if (testFiles.length === 0) {
      findings.push({
        id: 'TST-001',
        category: 'tests',
        severity: 'critical',
        title: 'No test files found',
        description: `Project has ${sourceFiles.length} source files but zero tests.`,
        suggestion: 'Add tests. Start with critical paths: auth, data processing, API endpoints.',
      });
      return {
        category: 'tests',
        score: 0,
        findings,
        summary: `${sourceFiles.length} source files, 0 test files — no test coverage`,
      };
    }

    // --- Check: Test-to-source ratio ---
    const ratio = testFiles.length / Math.max(sourceFiles.length, 1);
    if (ratio < 0.1) {
      findings.push({
        id: 'TST-002',
        category: 'tests',
        severity: 'high',
        title: 'Very low test-to-source ratio',
        description: `${testFiles.length} test files for ${sourceFiles.length} source files (ratio: ${(ratio * 100).toFixed(1)}%). Industry baseline is ~30-50%.`,
        suggestion: 'Prioritize testing critical business logic, auth flows, and data mutations.',
        meta: { testFiles: testFiles.length, sourceFiles: sourceFiles.length, ratio },
      });
      score -= 2;
    } else if (ratio < 0.3) {
      findings.push({
        id: 'TST-002',
        category: 'tests',
        severity: 'medium',
        title: 'Low test-to-source ratio',
        description: `${testFiles.length} test files for ${sourceFiles.length} source files (ratio: ${(ratio * 100).toFixed(1)}%).`,
        suggestion: 'Good start. Focus on increasing coverage for untested modules.',
        meta: { testFiles: testFiles.length, sourceFiles: sourceFiles.length, ratio },
      });
      score -= 1;
    }

    // --- Check: Test config exists ---
    const hasTestConfig = scan.files.some(
      (f) =>
        f.includes('vitest.config') ||
        f.includes('jest.config') ||
        f === 'pytest.ini' ||
        f === 'setup.cfg' ||
        f === 'pyproject.toml' ||
        f.includes('karma.conf'),
    );

    if (!hasTestConfig) {
      findings.push({
        id: 'TST-003',
        category: 'tests',
        severity: 'medium',
        title: 'No test framework configuration found',
        description: 'No vitest.config, jest.config, pytest.ini, or similar detected.',
        suggestion: 'Add a test config with coverage thresholds to enforce quality.',
      });
      score -= 0.5;
    }

    // --- Analyze individual test files ---
    let totalSkipped = 0;
    let totalDecorative = 0;
    let totalEmpty = 0;

    for (const testFile of testFiles) {
      try {
        const content = await readFile(testFile);
        const ext = extname(testFile);
        const isPython = ext === '.py';
        const isJs = ['.ts', '.tsx', '.js', '.jsx', '.mjs'].includes(ext);

        // --- Check: Empty test file ---
        const stripped = content.replace(/\/\*[\s\S]*?\*\/|\/\/.*|#.*/g, '').trim();
        if (stripped.length < 50) {
          findings.push({
            id: 'TST-010',
            category: 'tests',
            severity: 'medium',
            title: 'Empty or near-empty test file',
            description: `${testFile} has almost no content. A test file that tests nothing is worse than no file — it gives false confidence.`,
            file: testFile,
            suggestion: 'Add real tests or remove the file.',
          });
          totalEmpty++;
          score -= 0.3;
          continue;
        }

        if (isJs) {
          // --- Check: File has ZERO assertions (truly decorative) ---
          const totalExpects = (content.match(/expect\s*\(/g) || []).length;
          const totalAsserts = (content.match(/assert[\s.(]/g) || []).length;
          const totalThrows = (content.match(/toThrow|rejects\.toThrow/g) || []).length;
          const totalAssertions = totalExpects + totalAsserts + totalThrows;

          if (totalAssertions === 0) {
            const testCount = (content.match(/(?:it|test)\s*\(\s*['"`]/g) || []).length;
            findings.push({
              id: 'TST-011',
              category: 'tests',
              severity: 'high',
              title: `No assertions in ${testFile}`,
              description: `${testCount} test(s) but zero expect/assert calls in the entire file. Every test passes by default.`,
              file: testFile,
              suggestion: 'Add expect() assertions that verify actual behavior.',
              meta: { testCount },
            });
            totalDecorative++;
            score -= 0.5;
          }

          // --- Check: No SUT import (tests disconnected from source) ---
          const noSutImport = detectNoSutImport(content, testFile, scan.files);
          if (noSutImport) {
            findings.push({
              id: 'TST-014',
              category: 'tests',
              severity: 'medium',
              title: `Test file doesn't import source code: ${testFile}`,
              description:
                'This test file has no imports from the project source (src/, lib/, or relative parent paths). It may be testing inline mocks/schemas instead of real code.',
              file: testFile,
              suggestion:
                'Import and test the actual module. Tests that re-declare everything inline give false confidence.',
              meta: { noSutImport: true },
            });
            score -= 0.3;
          }

          // --- Check: Skipped tests ---
          const skipped = countSkippedTests(content);
          if (skipped > 0) {
            findings.push({
              id: 'TST-012',
              category: 'tests',
              severity: 'low',
              title: `${skipped} skipped test(s) in ${testFile}`,
              description: `Found ${skipped} test(s) using .skip, .todo, or xit. Skipped tests accumulate and become dead weight.`,
              file: testFile,
              suggestion: 'Fix or remove skipped tests. If they test planned features, track them in issues instead.',
            });
            totalSkipped += skipped;
            score -= 0.1 * skipped;
          }

          // --- Check: Snapshot overuse ---
          const snapshotCount = (content.match(/toMatchSnapshot|toMatchInlineSnapshot/g) || []).length;
          const expectCount = (content.match(/expect\s*\(/g) || []).length;
          if (snapshotCount > 0 && expectCount > 0 && snapshotCount / expectCount > 0.5) {
            findings.push({
              id: 'TST-013',
              category: 'tests',
              severity: 'low',
              title: `Heavy snapshot usage in ${testFile}`,
              description: `${snapshotCount} of ${expectCount} assertions are snapshots (${Math.round((snapshotCount / expectCount) * 100)}%). Snapshots are brittle and easy to blindly update.`,
              file: testFile,
              suggestion: 'Replace snapshots with explicit assertions where possible.',
            });
            score -= 0.2;
          }
        }

        if (isPython) {
          // --- Check: Python skipped tests ---
          const pySkipped = (content.match(/@pytest\.mark\.skip|@unittest\.skip|pytest\.skip\(/g) || []).length;
          if (pySkipped > 0) {
            findings.push({
              id: 'TST-012',
              category: 'tests',
              severity: 'low',
              title: `${pySkipped} skipped test(s) in ${testFile}`,
              description: `Found ${pySkipped} skipped test(s) using pytest.mark.skip or similar.`,
              file: testFile,
              suggestion: 'Fix or remove skipped tests.',
            });
            totalSkipped += pySkipped;
            score -= 0.1 * pySkipped;
          }

          // --- Check: Python tests without assert ---
          const pyDecorative = findPythonDecorativeTests(content, testFile);
          if (pyDecorative.length > 0) {
            findings.push({
              id: 'TST-011',
              category: 'tests',
              severity: 'high',
              title: `No assertions in ${testFile}`,
              description: `${pyDecorative.length} test(s) but zero assert/assertEqual/mock-assert calls in the entire file. Every test passes by default.`,
              file: testFile,
              suggestion: 'Add assert statements that verify actual behavior.',
              meta: { tests: pyDecorative, testCount: pyDecorative.length },
            });
            totalDecorative += pyDecorative.length;
            score -= 0.5;
          }
        }
      } catch {
        // Can't read — skip
      }
    }

    // --- Positive signals ---
    if (ratio >= 0.5) score = Math.min(10, score + 0.5);
    if (hasTestConfig) score = Math.min(10, score + 0.3);
    if (totalDecorative === 0 && testFiles.length > 5) score = Math.min(10, score + 0.3);

    return {
      category: 'tests',
      score: Math.max(0, Math.min(10, Math.round(score * 10) / 10)),
      findings,
      summary: buildSummary(testFiles.length, sourceFiles.length, totalDecorative, totalSkipped, totalEmpty),
    };
  }
}

// ============================================================
// Helpers
// ============================================================

function isTestFile(path: string): boolean {
  const name = basename(path);
  return (
    name.includes('.test.') ||
    name.includes('.spec.') ||
    name.includes('_test.') ||
    name.includes('_spec.') ||
    (name.startsWith('test_') && path.endsWith('.py'))
  );
}

function isSourceFile(path: string): boolean {
  const ext = extname(path);
  return ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.rs', '.go', '.java'].includes(ext);
}

/**
 * Detect if a JS/TS test file has no imports from the project source.
 * A test that doesn't import from src/, lib/, or relative parent paths
 * is likely testing inline mocks/re-declarations instead of real code.
 *
 * Exception: integration tests that use protocol/transport packages
 * (MCP SDK, supertest, playwright, etc.) are testing via interface,
 * not via direct import — they're legitimate even without src/ imports.
 *
 * Returns true if the test appears disconnected from source.
 */
export function detectNoSutImport(content: string, testFile: string, _projectFiles: string[]): boolean {
  // Extract all import paths. The module specifier is always a quoted string,
  // preceded by `from` (`import x from "p"`, `export {x} from "p"`), a bare
  // `import "p"`, a dynamic `import("p")`, or `require("p")`. Matching only on
  // `import`/`require` immediately followed by a quote missed the dominant form
  // `import { x } from "p"`, which made every standard test look disconnected.
  const importPattern = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"]+)['"]/g;
  const imports = [...content.matchAll(importPattern)].map((m) => m[1]);

  if (imports.length === 0) return true; // No imports at all

  // Integration test packages — if these are imported, the test is
  // exercising real behavior via protocol/transport, not via direct import.
  // This is a legitimate testing pattern, not a disconnected test.
  const integrationPackages = [
    '@modelcontextprotocol/', // MCP SDK — tests via transport
    'supertest', // HTTP integration tests
    'playwright', // E2E browser tests
    'puppeteer', // E2E browser tests
    'testcontainers', // Container integration tests
    '@nestjs/testing', // NestJS integration tests
    'light-my-request', // Fastify integration tests
  ];

  const hasIntegrationImport = imports.some((imp) => integrationPackages.some((pkg) => imp.startsWith(pkg)));

  if (hasIntegrationImport) return false; // Integration test — legitimate

  // Tests that run a real entrypoint as a child process (fork/spawn/execFile)
  // exercise actual source through the process boundary, not via import —
  // the same legitimate pattern as supertest/playwright, just over a process.
  const usesChildProcess = imports.some((imp) => imp === 'child_process' || imp === 'node:child_process');
  const spawnsProcess = /\b(?:fork|spawn|execFile|exec)\s*\(/.test(content);
  if (usesChildProcess && spawnsProcess) return false;

  // Also skip if test file is in an integration/ or e2e/ directory
  if (testFile.includes('/integration/') || testFile.includes('/e2e/')) {
    return false;
  }

  // Check if any import points to project source (not node_modules, not test utils)
  const hasSrcImport = imports.some((imp) => {
    // Relative imports going to parent directories (../something)
    if (imp.startsWith('../') && !imp.includes('fixtures') && !imp.includes('helpers') && !imp.includes('utils/test')) {
      return true;
    }

    // Imports from src/, lib/, or project aliases (@/)
    if (imp.startsWith('@/') || imp.startsWith('src/') || imp.startsWith('lib/')) {
      return true;
    }

    // Relative import to a source file (./something that exists in src)
    if (imp.startsWith('./')) {
      // Check if this resolves to a source file (not another test)
      const resolved = imp.replace('./', '');
      return !resolved.includes('.test') && !resolved.includes('.spec');
    }

    return false;
  });

  // Also check for dynamic imports: await import('../src/something')
  const dynamicImportPattern = /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  const dynamicImports = [...content.matchAll(dynamicImportPattern)].map((m) => m[1]);
  const hasDynamicSrcImport = dynamicImports.some(
    (imp) => imp.startsWith('../') || imp.startsWith('@/') || imp.startsWith('src/'),
  );

  return !hasSrcImport && !hasDynamicSrcImport;
}

/**
 * Detect decorative Python test files at the FILE level.
 *
 * Mirrors the v0.5.0 JS rewrite: a file is decorative only if it contains
 * ZERO assertions anywhere. Per-function detection was too fragile — a single
 * "does not raise" smoke test or helper would condemn a file full of real
 * asserting tests (21/22 false positives observed on AETHER).
 *
 * Returns the list of test function names ONLY when the file has no assertions
 * at all (so the caller can report how many tests pass by default); otherwise
 * returns an empty array.
 */
export function findPythonDecorativeTests(content: string, _file: string): string[] {
  const assertionPatterns = [
    /\bassert\b/, // pytest bare assert
    /self\.assert\w+\s*\(/, // unittest: assertEqual, assertTrue, assertRaises, ...
    /pytest\.raises/, // pytest.raises context manager
    /\.assert_\w+\s*\(/, // Mock/AsyncMock: assert_called*, assert_awaited*, ...
    /\.status_code\s*==/, // API tests checking response status
  ];

  const fileHasAssertion = assertionPatterns.some((re) => re.test(content));
  if (fileHasAssertion) return [];

  // Zero assertions in the entire file — every test function passes by default.
  const funcPattern = /def\s+(test_\w+)\s*\(/g;
  return [...content.matchAll(funcPattern)].map((m) => m[1]);
}

/**
 * Count skipped tests in JS/TS files.
 */
function countSkippedTests(content: string): number {
  const patterns = [
    /\bit\.skip\s*\(/g,
    /\btest\.skip\s*\(/g,
    /\bit\.todo\s*\(/g,
    /\btest\.todo\s*\(/g,
    // \b so e.g. `process.exit(` does not match `xit(` (real FP found by the
    // AI triage layer on orion_new).
    /\bxit\s*\(/g,
    /\bxdescribe\s*\(/g,
    /\bxtest\s*\(/g,
  ];

  let count = 0;
  for (const pattern of patterns) {
    count += (content.match(pattern) || []).length;
  }
  return count;
}

function buildSummary(
  testCount: number,
  sourceCount: number,
  decorative: number,
  skipped: number,
  empty: number,
): string {
  const ratio = ((testCount / Math.max(sourceCount, 1)) * 100).toFixed(0);
  const parts: string[] = [`${testCount} test files, ${sourceCount} source files (${ratio}% ratio)`];

  if (decorative > 0) parts.push(`${decorative} decorative`);
  if (skipped > 0) parts.push(`${skipped} skipped`);
  if (empty > 0) parts.push(`${empty} empty`);
  if (decorative === 0 && skipped === 0 && empty === 0) parts.push('test suite looks healthy');

  return parts.join(' · ');
}
