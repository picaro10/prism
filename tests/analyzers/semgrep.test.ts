import { describe, it, expect } from 'vitest';
import { SemgrepAnalyzer, type SemgrepRunner } from '../../src/analyzers/semgrep.js';
import type { ProjectScan, FileReader } from '../../src/core/types.js';

const scan: ProjectScan = {
  rootPath: '/project',
  files: ['src/app.ts'],
  fileTree: [],
  meta: {
    stack: { primary: 'TypeScript', secondary: [] },
    totalLoc: 0,
    totalFiles: 1,
    hasGit: true,
    hasDocker: false,
    hasCi: true,
    frameworks: [],
  },
};

const readFile: FileReader = async () => '';

function semgrepJson(results: unknown[]): string {
  return JSON.stringify({ results, errors: [], paths: { scanned: ['src/app.ts'] } });
}

function result(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    check_id: 'tmp.prism-rules.prism-sqli-string-concat',
    path: 'src/app.ts',
    start: { line: 42, col: 3 },
    end: { line: 42, col: 60 },
    extra: {
      message: 'User input flows into a SQL query string',
      severity: 'ERROR',
      lines: 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
      metadata: {
        'prism-severity': 'critical',
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        fix: 'Use parameterized queries',
      },
    },
    ...overrides,
  };
}

function fakeRunner(stdout: string): SemgrepRunner {
  return async () => ({ stdout });
}

describe('SemgrepAnalyzer', () => {
  it('degrades with an info notice when semgrep is not installed', async () => {
    const enoent: SemgrepRunner = async () => {
      const err = new Error('spawn semgrep ENOENT') as Error & { code: string };
      err.code = 'ENOENT';
      throw err;
    };
    const res = await new SemgrepAnalyzer(enoent).analyze(scan, readFile);

    expect(res.category).toBe('security');
    expect(res.score).toBe(10);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].id).toBe('SEC-SEMGREP-MISSING');
    expect(res.findings[0].severity).toBe('info');
    expect(res.summary.toLowerCase()).toContain('not installed');
  });

  it('maps semgrep JSON results to PRISM findings under security', async () => {
    const res = await new SemgrepAnalyzer(fakeRunner(semgrepJson([result()]))).analyze(scan, readFile);

    expect(res.findings).toHaveLength(1);
    const f = res.findings[0];
    expect(f.id).toBe('SG-SQLI-STRING-CONCAT');
    expect(f.category).toBe('security');
    expect(f.severity).toBe('critical'); // prism-severity metadata wins over ERROR→high
    expect(f.file).toBe('src/app.ts');
    expect(f.line).toBe(42);
    expect(f.title).toContain('SQL');
    expect(f.suggestion).toBe('Use parameterized queries');
    expect(f.meta).toMatchObject({
      engine: 'semgrep',
      checkId: 'tmp.prism-rules.prism-sqli-string-concat',
      cwe: 'CWE-89',
      owasp: 'A03:2021',
    });
  });

  it('falls back to semgrep severity mapping when no prism-severity metadata', async () => {
    const mk = (severity: string, name: string) =>
      result({
        check_id: `tmp.prism-rules.${name}`,
        extra: { message: 'm', severity, lines: '', metadata: {} },
      });
    const res = await new SemgrepAnalyzer(
      fakeRunner(semgrepJson([mk('ERROR', 'a'), mk('WARNING', 'b'), mk('INFO', 'c')])),
    ).analyze(scan, readFile);

    expect(res.findings.map((f) => f.severity)).toEqual(['high', 'medium', 'low']);
  });

  it('clean run yields no findings and a 10', async () => {
    const res = await new SemgrepAnalyzer(fakeRunner(semgrepJson([]))).analyze(scan, readFile);
    expect(res.findings).toEqual([]);
    expect(res.score).toBe(10);
  });

  it('penalizes the score per mapped severity', async () => {
    // one critical (-1.5) + one high (-1) → 7.5
    const high = result({
      check_id: 'tmp.prism-rules.prism-xss-render',
      extra: { message: 'xss', severity: 'ERROR', lines: '', metadata: {} },
    });
    const res = await new SemgrepAnalyzer(fakeRunner(semgrepJson([result(), high]))).analyze(scan, readFile);
    expect(res.score).toBe(7.5);
  });

  it('skips findings in excluded contexts and downgrades test files', async () => {
    const inFixture = result({ path: 'tests/fixtures/vuln.ts' });
    const inTest = result({ path: 'src/app.test.ts' });
    const res = await new SemgrepAnalyzer(fakeRunner(semgrepJson([inFixture, inTest]))).analyze(scan, readFile);

    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].file).toBe('src/app.test.ts');
    expect(res.findings[0].severity).toBe('medium'); // critical downgraded in test context
  });

  it('reports a low-severity notice when semgrep runs but output is unusable', async () => {
    const res = await new SemgrepAnalyzer(fakeRunner('not json at all')).analyze(scan, readFile);

    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].id).toBe('SEC-SEMGREP-ERROR');
    expect(res.findings[0].severity).toBe('low');
    expect(res.score).toBe(9.5);
  });

  it('caps the number of mapped findings and says so', async () => {
    const many = Array.from({ length: 250 }, (_, i) => result({ start: { line: i + 1, col: 1 } }));
    const res = await new SemgrepAnalyzer(fakeRunner(semgrepJson(many))).analyze(scan, readFile);

    const truncation = res.findings.find((f) => f.id === 'SEC-SEMGREP-TRUNCATED');
    expect(res.findings.length).toBeLessThanOrEqual(201);
    expect(truncation).toBeDefined();
    expect(res.score).toBe(0);
  });

  it('does not invoke semgrep when the project has no JS/TS/Python files', async () => {
    let called = false;
    const spy: SemgrepRunner = async () => {
      called = true;
      return { stdout: semgrepJson([]) };
    };
    const goScan: ProjectScan = { ...scan, files: ['main.go', 'go.mod'] };
    const res = await new SemgrepAnalyzer(spy).analyze(goScan, readFile);

    expect(called).toBe(false);
    expect(res.findings).toEqual([]);
    expect(res.score).toBe(10);
  });

  it('invokes the runner with the JSON flag, a rules config, and the project root as cwd', async () => {
    let seenArgs: string[] = [];
    let seenCwd = '';
    const spy: SemgrepRunner = async (args, opts) => {
      seenArgs = args;
      seenCwd = opts.cwd;
      return { stdout: semgrepJson([]) };
    };
    await new SemgrepAnalyzer(spy).analyze(scan, readFile);

    expect(seenArgs).toContain('--json');
    expect(seenArgs.some((a) => a === '--config')).toBe(true);
    expect(seenArgs).toContain('--metrics=off');
    expect(seenCwd).toBe('/project');
  });
});
