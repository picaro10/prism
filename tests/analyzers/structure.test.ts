import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { scanProject } from '../../src/core/scanner.js';
import { StructureAnalyzer } from '../../src/analyzers/structure.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ProjectScan } from '../../src/core/types.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

describe('StructureAnalyzer', () => {
  const analyzer = new StructureAnalyzer();

  async function runAnalysis() {
    const scan = await scanProject(FIXTURE_PATH);
    const fileReader = async (p: string) => readFile(join(FIXTURE_PATH, p), 'utf-8');
    return analyzer.analyze(scan, fileReader);
  }

  it('returns a score between 0 and 10', async () => {
    const result = await runAnalysis();

    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(10);
  });

  it('returns the correct category', async () => {
    const result = await runAnalysis();

    expect(result.category).toBe('structure');
  });

  it('does not flag missing README (fixture has one)', async () => {
    const result = await runAnalysis();

    const readmeFinding = result.findings.find((f) => f.id === 'STR-001');
    expect(readmeFinding).toBeUndefined();
  });

  it('detects missing linter config', async () => {
    const result = await runAnalysis();

    const linterFinding = result.findings.find((f) => f.id === 'STR-006');
    expect(linterFinding).toBeDefined();
    expect(linterFinding?.severity).toBe('medium');
  });

  it('generates a non-empty summary', async () => {
    const result = await runAnalysis();

    expect(result.summary.length).toBeGreaterThan(0);
  });

  it('all findings have required fields', async () => {
    const result = await runAnalysis();

    for (const finding of result.findings) {
      expect(finding.id).toBeTruthy();
      expect(finding.category).toBe('structure');
      expect(finding.severity).toBeTruthy();
      expect(finding.title).toBeTruthy();
      expect(finding.description).toBeTruthy();
    }
  });
});

// Build a synthetic scan whose FileReader returns explicit per-file source text.
function scanWithContent(contents: Record<string, string>): {
  scan: ProjectScan;
  reader: (p: string) => Promise<string>;
} {
  const paths = Object.keys(contents);
  const scan: ProjectScan = {
    rootPath: '/fake',
    files: paths,
    fileTree: [],
    meta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: paths.length,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
  };
  return { scan, reader: async (p: string) => contents[p] ?? '' };
}

describe('StructureAnalyzer — circular dependencies (STR-012)', () => {
  const analyzer = new StructureAnalyzer();

  it('flags a value-import cycle between two files', async () => {
    const { scan, reader } = scanWithContent({
      'src/a.ts': `import { b } from './b.js';\nexport const a = 1;`,
      'src/b.ts': `import { a } from './a.js';\nexport const b = 2;`,
    });
    const result = await analyzer.analyze(scan, reader);
    const cyc = result.findings.find((f) => f.id === 'STR-012');
    expect(cyc).toBeDefined();
    expect(cyc?.severity).toBe('medium');
    expect((cyc?.meta?.cycle as string[]).sort()).toEqual(['src/a.ts', 'src/b.ts']);
  });

  it('does NOT flag a type-only cycle', async () => {
    const { scan, reader } = scanWithContent({
      'src/a.ts': `import type { B } from './b.js';\nexport type A = number;`,
      'src/b.ts': `import type { A } from './a.js';\nexport type B = string;`,
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-012')).toBeUndefined();
    expect(result.summary).toContain('no circular dependencies');
  });

  it('reports "no circular dependencies" in the summary when clean', async () => {
    const { scan, reader } = scanWithContent({
      'src/a.ts': `import { b } from './b.js';`,
      'src/b.ts': 'export const b = 2;',
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-012')).toBeUndefined();
    expect(result.summary).toContain('no circular dependencies');
  });

  it('reports both a god file and a cycle in the same scan', async () => {
    const longBody = Array.from({ length: 700 }, (_, i) => `const v${i} = ${i};`).join('\n');
    const { scan, reader } = scanWithContent({
      'src/a.ts': `import { b } from './b.js';\n${longBody}\nexport const a = 1;`,
      'src/b.ts': `import { a } from './a.js';\nexport const b = 2;`,
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.some((f) => f.id === 'STR-011' && f.file === 'src/a.ts')).toBe(true);
    expect(result.findings.some((f) => f.id === 'STR-012')).toBe(true);
    expect(result.summary).toContain('god file');
    expect(result.summary).toContain('circular dependenc');
  });

  it('detects a 3-file cycle and reports the full chain', async () => {
    const { scan, reader } = scanWithContent({
      'src/a.ts': `import { b } from './b.js';\nexport const a = 1;`,
      'src/b.ts': `import { c } from './c.js';\nexport const b = 2;`,
      'src/c.ts': `import { a } from './a.js';\nexport const c = 3;`,
    });
    const result = await analyzer.analyze(scan, reader);
    const cyc = result.findings.find((f) => f.id === 'STR-012');
    expect(cyc).toBeDefined();
    expect((cyc?.meta?.cycle as string[]).sort()).toEqual(['src/a.ts', 'src/b.ts', 'src/c.ts']);
    // chain closes the loop: starts and ends with the same file
    const chain = cyc?.description ?? '';
    expect(chain).toContain('→');
  });

  it('ignores cycles formed through non-source files (node_modules)', async () => {
    const { scan, reader } = scanWithContent({
      'src/a.ts': `import { b } from '../node_modules/pkg/b.js';`,
      'node_modules/pkg/b.ts': `import { a } from '../../src/a.js';`,
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-012')).toBeUndefined();
  });

  it('caps cycle findings at 20 and notes the overflow in the summary', async () => {
    // 25 independent 2-node cycles: a0<->b0, a1<->b1, ... a24<->b24
    const contents: Record<string, string> = {};
    for (let i = 0; i < 25; i++) {
      contents[`src/a${i}.ts`] = `import { b } from './b${i}.js';\nexport const a = 1;`;
      contents[`src/b${i}.ts`] = `import { a } from './a${i}.js';\nexport const b = 2;`;
    }
    const { scan, reader } = scanWithContent(contents);
    const result = await analyzer.analyze(scan, reader);
    const cyc = result.findings.filter((f) => f.id === 'STR-012');
    expect(cyc).toHaveLength(20);
    expect(result.summary).toContain('25 circular dependencies');
    expect(result.summary).toContain('5 more');
  });
});

describe('StructureAnalyzer — dead files (STR-013)', () => {
  const analyzer = new StructureAnalyzer();

  it('flags an orphan source file but spares imported files and entries', async () => {
    const { scan, reader } = scanWithContent({
      'src/index.ts': `import { b } from './b.js';`,
      'src/b.ts': 'export const b = 2;',
      'src/orphan.ts': 'export const dead = 1;',
    });
    const result = await analyzer.analyze(scan, reader);
    const dead = result.findings.filter((f) => f.id === 'STR-013');
    expect(dead).toHaveLength(1);
    expect(dead[0].file).toBe('src/orphan.ts');
    expect(dead[0].severity).toBe('low');
    expect(result.summary).toContain('1 dead file');
  });

  it('spares a file reachable only through a tsconfig alias', async () => {
    const { scan, reader } = scanWithContent({
      'tsconfig.json': JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@/*': ['./src/*'] } } }),
      'src/index.ts': `import { x } from '@/aliased.js';`,
      'src/aliased.ts': 'export const x = 1;',
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-013')).toBeUndefined();
  });

  it('skips the check and says so when a tsconfig cannot be parsed', async () => {
    const { scan, reader } = scanWithContent({
      'tsconfig.json': '{ paths: ??? broken',
      'src/orphan.ts': 'export const dead = 1;',
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-013')).toBeUndefined();
    expect(result.summary).toContain('dead-file analysis skipped');
  });

  it('warns in the description when the project has non-literal dynamic imports', async () => {
    const { scan, reader } = scanWithContent({
      'src/index.ts': 'await import(pluginName);',
      'src/orphan.ts': 'export const dead = 1;',
    });
    const result = await analyzer.analyze(scan, reader);
    const dead = result.findings.find((f) => f.id === 'STR-013');
    expect(dead?.description).toMatch(/dynamic imports PRISM cannot resolve/);
  });

  it('never flags non-TS/JS files', async () => {
    const { scan, reader } = scanWithContent({
      'scripts/standalone.py': 'print("hi")',
      'src/index.ts': 'export const x = 1;',
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-013')).toBeUndefined();
  });

  it('caps dead-file findings at 20 and notes the overflow', async () => {
    const contents: Record<string, string> = { 'src/index.ts': 'export const x = 1;' };
    for (let i = 0; i < 25; i++) contents[`src/dead${i}.ts`] = `export const d${i} = 1;`;
    const { scan, reader } = scanWithContent(contents);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.filter((f) => f.id === 'STR-013')).toHaveLength(20);
    expect(result.summary).toContain('25 dead files');
    expect(result.summary).toContain('5 more not listed');
  });
});

// Build a synthetic scan whose FileReader returns a string with `loc` lines.
function scanWith(files: { path: string; loc: number; charsPerLine?: number }[]): {
  scan: ProjectScan;
  reader: (p: string) => Promise<string>;
} {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const scan: ProjectScan = {
    rootPath: '/fake',
    files: files.map((f) => f.path),
    fileTree: [],
    meta: {
      stack: { primary: 'typescript', secondary: [] },
      totalLoc: 0,
      totalFiles: files.length,
      hasGit: true,
      hasDocker: false,
      hasCi: false,
      frameworks: [],
    },
  };
  const reader = async (p: string) => {
    const f = byPath.get(p);
    if (!f) return '';
    const lineLen = f.charsPerLine ?? 4;
    const line = 'x'.repeat(lineLen);
    return Array.from({ length: f.loc }, () => line).join('\n');
  };
  return { scan, reader };
}

describe('StructureAnalyzer — god files (STR-011)', () => {
  const analyzer = new StructureAnalyzer();

  it('flags a 1600-line source file as high severity', async () => {
    const { scan, reader } = scanWith([{ path: 'src/huge.ts', loc: 1600 }]);
    const result = await analyzer.analyze(scan, reader);
    const god = result.findings.find((f) => f.id === 'STR-011' && f.file === 'src/huge.ts');
    expect(god).toBeDefined();
    expect(god?.severity).toBe('high');
    expect(god?.meta?.loc).toBe(1600);
  });

  it('assigns the correct tier per file', async () => {
    const { scan, reader } = scanWith([
      { path: 'src/low.ts', loc: 700 },
      { path: 'src/medium.ts', loc: 1000 },
      { path: 'src/high.ts', loc: 2000 },
    ]);
    const result = await analyzer.analyze(scan, reader);
    const tier = (file: string) => result.findings.find((f) => f.id === 'STR-011' && f.file === file)?.severity;
    expect(tier('src/low.ts')).toBe('low');
    expect(tier('src/medium.ts')).toBe('medium');
    expect(tier('src/high.ts')).toBe('high');
  });

  it('does NOT emit a finding for an info-tier file (>400, <=600)', async () => {
    const { scan, reader } = scanWith([{ path: 'src/mild.ts', loc: 450 }]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-011')).toBeUndefined();
  });

  it('does NOT flag normal-sized files', async () => {
    const { scan, reader } = scanWith([{ path: 'src/normal.ts', loc: 120 }]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-011')).toBeUndefined();
  });

  it('lowers the score for a high-severity god file', async () => {
    const { scan, reader } = scanWith([{ path: 'src/huge.ts', loc: 1600 }]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.score).toBeLessThan(10);
  });

  it('excludes vendored, generated, fixture, template, doc and test files', async () => {
    const { scan, reader } = scanWith([
      { path: 'node_modules/pkg/huge.js', loc: 5000 }, // vendor
      { path: 'vendor/lib.go', loc: 5000 }, // vendor
      { path: 'src/__fixtures__/big-fixture.ts', loc: 5000 }, // fixture
      { path: 'examples/demo.ts', loc: 5000 }, // template
      { path: 'src/huge.test.ts', loc: 5000 }, // test
    ]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.filter((f) => f.id === 'STR-011')).toHaveLength(0);
  });

  it('skips minified files (one very long line)', async () => {
    const { scan, reader } = scanWith([{ path: 'src/bundle.js', loc: 1, charsPerLine: 30000 }]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-011')).toBeUndefined();
  });

  it('skips a god file whose lines average over 500 chars (data/minified)', async () => {
    const { scan, reader } = scanWith([{ path: 'src/data.ts', loc: 700, charsPerLine: 600 }]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-011')).toBeUndefined();
  });

  it('caps individual findings at 25 and notes the overflow in the summary', async () => {
    const files = Array.from({ length: 30 }, (_, i) => ({ path: `src/f${i}.ts`, loc: 650 }));
    const { scan, reader } = scanWith(files);
    const result = await analyzer.analyze(scan, reader);
    const god = result.findings.filter((f) => f.id === 'STR-011');
    expect(god).toHaveLength(25);
    expect(result.summary).toContain('5 more files exceed 600 LOC');
  });

  it('appends distribution metrics to the summary', async () => {
    const { scan, reader } = scanWith([
      { path: 'src/a.ts', loc: 1000 },
      { path: 'src/b.ts', loc: 100 },
      { path: 'src/c.ts', loc: 50 },
    ]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.summary).toContain('1.1k LOC');
    expect(result.summary).toContain('3 source files');
    expect(result.summary).toContain('largest src/a.ts (1000)');
    expect(result.summary).toContain('god file'); // a.ts is a god file (medium)
    expect(result.summary).toContain('median 100 LOC');
    expect(result.summary).toContain('top-5 = 100% of code');
  });
});
