# Structure profundo (God files + distribución) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend PRISM's `StructureAnalyzer` to be content-aware — detect "god files" by line count (`STR-011`) and surface size-distribution metrics in the summary, with zero import-graph machinery.

**Architecture:** A new pure-function helper module `src/utils/loc.ts` (line counting, god-file tier classification, distribution metrics) is unit-tested in isolation. The existing `StructureAnalyzer.analyze` (currently path-only, ignores its `FileReader`) gains a content-reading pass that reuses the existing `classifyFile()` context classifier as the anti-false-positive gate. Distribution metrics are appended to the result's `summary` string — no change to the `AnalyzerResult` contract.

**Tech Stack:** TypeScript + Node 22, Vitest. No new dependencies.

> **Note on commits:** `/opt/prism` is NOT a git repository. The standard "commit" step is replaced throughout by a "run the full suite green" checkpoint (`npx vitest run`). If git is later initialized, treat each checkpoint as a commit boundary.

---

## File Structure

- **Create** `src/utils/loc.ts` — pure helpers: `countLoc`, `classifyGodFile`, `computeSizeMetrics`, plus the exported `GOD_FILE_FINDING_THRESHOLD` and `MAX_GOD_FILE_FINDINGS` constants and the `SizeMetrics`/`MeasuredFile` types.
- **Create** `tests/utils/loc.test.ts` — unit tests for the three helpers.
- **Modify** `src/analyzers/structure.ts` — add the content-reading god-file pass + distribution summary; import from `loc.ts` and `file-context.ts`.
- **Modify** `tests/analyzers/structure.test.ts` — integration tests via synthetic `ProjectScan` + fake `FileReader`.

The `loc.ts` helpers know nothing about findings or the analyzer; the analyzer knows nothing about how a median is computed. Each is testable alone.

---

## Task 1: LOC helper module — `countLoc` and `classifyGodFile`

**Files:**
- Create: `src/utils/loc.ts`
- Test: `tests/utils/loc.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/utils/loc.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { countLoc, classifyGodFile } from '../../src/utils/loc.js';

describe('countLoc', () => {
  it('counts an empty string as 1 line', () => {
    expect(countLoc('')).toBe(1);
  });

  it('counts a single line with no trailing newline', () => {
    expect(countLoc('const x = 1;')).toBe(1);
  });

  it('counts N lines', () => {
    expect(countLoc('a\nb\nc')).toBe(3);
  });

  it('counts a trailing newline as a final empty line', () => {
    expect(countLoc('a\nb\n')).toBe(3);
  });
});

describe('classifyGodFile', () => {
  it('returns null below the info threshold', () => {
    expect(classifyGodFile(400)).toBeNull();
    expect(classifyGodFile(10)).toBeNull();
  });

  it('returns info above 400', () => {
    expect(classifyGodFile(401)).toBe('info');
    expect(classifyGodFile(600)).toBe('info');
  });

  it('returns low above 600', () => {
    expect(classifyGodFile(601)).toBe('low');
    expect(classifyGodFile(900)).toBe('low');
  });

  it('returns medium above 900', () => {
    expect(classifyGodFile(901)).toBe('medium');
    expect(classifyGodFile(1500)).toBe('medium');
  });

  it('returns high above 1500', () => {
    expect(classifyGodFile(1501)).toBe('high');
    expect(classifyGodFile(99999)).toBe('high');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/utils/loc.test.ts`
Expected: FAIL — `Failed to resolve import "../../src/utils/loc.js"` (module does not exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `src/utils/loc.ts`:

```ts
/**
 * Line-of-code helpers for the structure analyzer's god-file detection.
 * Pure functions — no findings, no I/O. Total-line counting (decision "(a)"):
 * transparent and reproducible, same spirit as the file-level TST-011 rewrite.
 */

export type GodFileTier = 'high' | 'medium' | 'low' | 'info';

/** Total number of lines in a file's content. */
export function countLoc(content: string): number {
  return content.split('\n').length;
}

/**
 * Classify a file by its line count into a god-file tier, or null if it is
 * within normal size. Thresholds are strict `>` comparisons; there is no
 * `critical` tier (a large file is debt, not a vulnerability).
 */
export function classifyGodFile(loc: number): GodFileTier | null {
  if (loc > 1500) return 'high';
  if (loc > 900) return 'medium';
  if (loc > 600) return 'low';
  if (loc > 400) return 'info';
  return null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/utils/loc.test.ts`
Expected: PASS (10 tests).

- [ ] **Step 5: Checkpoint — full suite green**

Run: `npx vitest run`
Expected: all existing tests still pass plus the new file (`101 → 111 passed`).

---

## Task 2: LOC helper module — `computeSizeMetrics`

**Files:**
- Modify: `src/utils/loc.ts`
- Test: `tests/utils/loc.test.ts:append`

- [ ] **Step 1: Write the failing tests**

Append to `tests/utils/loc.test.ts`:

```ts
import { computeSizeMetrics } from '../../src/utils/loc.js';

describe('computeSizeMetrics', () => {
  it('handles an empty list', () => {
    const m = computeSizeMetrics([]);
    expect(m).toEqual({ totalLoc: 0, fileCount: 0, median: 0, largest: null, top5Pct: 0 });
  });

  it('handles a single file', () => {
    const m = computeSizeMetrics([{ path: 'a.ts', loc: 100 }]);
    expect(m.totalLoc).toBe(100);
    expect(m.fileCount).toBe(1);
    expect(m.median).toBe(100);
    expect(m.largest).toEqual({ path: 'a.ts', loc: 100 });
    expect(m.top5Pct).toBe(100);
  });

  it('computes the median of an odd-length list', () => {
    const m = computeSizeMetrics([
      { path: 'a', loc: 10 },
      { path: 'b', loc: 30 },
      { path: 'c', loc: 20 },
    ]);
    expect(m.median).toBe(20);
  });

  it('computes the median of an even-length list as the average of the two middle values', () => {
    const m = computeSizeMetrics([
      { path: 'a', loc: 10 },
      { path: 'b', loc: 20 },
      { path: 'c', loc: 30 },
      { path: 'd', loc: 40 },
    ]);
    expect(m.median).toBe(25);
  });

  it('reports the largest file and top-5 concentration', () => {
    const files = [
      { path: 'big', loc: 1000 },
      { path: 'b', loc: 50 },
      { path: 'c', loc: 40 },
      { path: 'd', loc: 30 },
      { path: 'e', loc: 20 },
      { path: 'f', loc: 10 }, // not in top 5
    ];
    const m = computeSizeMetrics(files);
    expect(m.largest).toEqual({ path: 'big', loc: 1000 });
    // top 5 = 1000+50+40+30+20 = 1140 of 1150 total = 99%
    expect(m.totalLoc).toBe(1150);
    expect(m.top5Pct).toBe(99);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/utils/loc.test.ts`
Expected: FAIL — `computeSizeMetrics is not a function` / import unresolved.

- [ ] **Step 3: Write minimal implementation**

Append to `src/utils/loc.ts`:

```ts
export interface MeasuredFile {
  path: string;
  loc: number;
}

export interface SizeMetrics {
  totalLoc: number;
  fileCount: number;
  median: number;
  largest: MeasuredFile | null;
  /** % of total LOC held by the 5 largest files (0 when there is no code). */
  top5Pct: number;
}

export function computeSizeMetrics(measured: MeasuredFile[]): SizeMetrics {
  if (measured.length === 0) {
    return { totalLoc: 0, fileCount: 0, median: 0, largest: null, top5Pct: 0 };
  }

  const locs = measured.map((m) => m.loc);
  const totalLoc = locs.reduce((sum, n) => sum + n, 0);

  const sortedAsc = [...locs].sort((a, b) => a - b);
  const mid = Math.floor(sortedAsc.length / 2);
  const median =
    sortedAsc.length % 2 === 0
      ? Math.round((sortedAsc[mid - 1] + sortedAsc[mid]) / 2)
      : sortedAsc[mid];

  const byLocDesc = [...measured].sort((a, b) => b.loc - a.loc);
  const largest = byLocDesc[0];
  const top5Loc = byLocDesc.slice(0, 5).reduce((sum, m) => sum + m.loc, 0);
  const top5Pct = totalLoc === 0 ? 0 : Math.round((top5Loc / totalLoc) * 100);

  return { totalLoc, fileCount: measured.length, median, largest, top5Pct };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/utils/loc.test.ts`
Expected: PASS (15 tests total in the file).

- [ ] **Step 5: Checkpoint — full suite green**

Run: `npx vitest run`
Expected: all pass (`111 → 116 passed`).

---

## Task 3: God-file detection in `StructureAnalyzer` (per-file findings)

**Files:**
- Modify: `src/analyzers/structure.ts`
- Test: `tests/analyzers/structure.test.ts`

Read the current test file first to match its imports and style. It currently uses
`scanProject` against a fixture. We add a new `describe` block that builds a synthetic
`ProjectScan` and a fake `FileReader`, matching the pattern used in
`tests/analyzers/tests.test.ts` (the v0.7.1 TST-001 tests).

- [ ] **Step 1: Write the failing tests**

Append to `tests/analyzers/structure.test.ts` (add imports at top of file if missing):

```ts
import type { ProjectScan } from '../../src/core/types.js';
import { StructureAnalyzer } from '../../src/analyzers/structure.js';

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
    const lineLen = f.charsPerLine ?? 4; // "x = 1" style short lines
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
      { path: 'src/low.ts', loc: 700 },     // low
      { path: 'src/medium.ts', loc: 1000 }, // medium
      { path: 'src/high.ts', loc: 2000 },   // high
    ]);
    const result = await analyzer.analyze(scan, reader);
    const tier = (file: string) =>
      result.findings.find((f) => f.id === 'STR-011' && f.file === file)?.severity;
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
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: FAIL — no `STR-011` findings are produced yet (`god` is undefined).

- [ ] **Step 3: Write minimal implementation**

In `src/analyzers/structure.ts`, update the imports at the top:

```ts
import { classifyFile } from '../utils/file-context.js';
import { countLoc, classifyGodFile, computeSizeMetrics, type MeasuredFile, type GodFileTier } from '../utils/loc.js';
```

Add this module-level constant near the top of the file (after the imports):

```ts
const GOD_FILE_SOURCE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.rs', '.go', '.java'];
const MAX_GOD_FILE_FINDINGS = 25;
/** Per-tier score deduction; total god-file deduction is capped (see below). */
const GOD_FILE_PENALTY: Record<Exclude<GodFileTier, 'info'>, number> = {
  low: 0.2,
  medium: 0.5,
  high: 1.0,
};
const GOD_FILE_PENALTY_CAP = 3.0;
```

Inside `analyze`, AFTER the existing STR-010 block and BEFORE the `// --- Positive signals ---`
section, insert the god-file pass. The method signature already receives `_readFile`; rename
that parameter to `readFile` in the method signature (`async analyze(scan: ProjectScan, readFile: FileReader)`):

```ts
    // --- Check: God files (content-aware) ---
    const measured: MeasuredFile[] = [];
    const godFiles: { path: string; loc: number; tier: GodFileTier }[] = [];

    for (const file of scan.files) {
      // Anti-FP gate: only real production source counts.
      if (!GOD_FILE_SOURCE_EXTS.includes(extname(file))) continue;
      if (classifyFile(file) !== 'source') continue;

      let content: string;
      try {
        content = await readFile(file);
      } catch {
        continue; // unreadable — skip
      }

      const loc = countLoc(content);
      // Skip minified/bundled/data files: not hand-written.
      if (content.length / Math.max(loc, 1) > 500) continue;

      measured.push({ path: file, loc });

      const tier = classifyGodFile(loc);
      if (tier) godFiles.push({ path: file, loc, tier });
    }

    // Emit per-file findings only for low/medium/high (info is metrics-only).
    const findingTiers: GodFileTier[] = ['low', 'medium', 'high'];
    const reportable = godFiles
      .filter((g) => findingTiers.includes(g.tier))
      .sort((a, b) => b.loc - a.loc);

    let godPenalty = 0;
    for (const g of reportable.slice(0, MAX_GOD_FILE_FINDINGS)) {
      const severity = g.tier as 'low' | 'medium' | 'high';
      findings.push({
        id: 'STR-011',
        category: 'structure',
        severity,
        title: `God file: ${g.path} (${g.loc} LOC)`,
        description: `${g.path} tiene ${g.loc} líneas. Los archivos grandes concentran responsabilidades, dificultan el test y el review.`,
        file: g.path,
        suggestion: 'Considerá dividir este archivo por responsabilidad en módulos más chicos.',
        meta: { loc: g.loc, tier: g.tier },
      });
      godPenalty += GOD_FILE_PENALTY[severity];
    }
    score -= Math.min(godPenalty, GOD_FILE_PENALTY_CAP);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: PASS (existing 6 + 4 new).

- [ ] **Step 5: Checkpoint — full suite green**

Run: `npx vitest run`
Expected: all pass (`116 → 120 passed`).

---

## Task 4: Anti-FP exclusions + minified guard

**Files:**
- Test: `tests/analyzers/structure.test.ts` (append)
- (No implementation change expected — this task PROVES the Task 3 gate works. If a test fails, fix the gate in `structure.ts`.)

- [ ] **Step 1: Write the failing tests**

Append to the `describe('StructureAnalyzer — god files (STR-011)')` block:

```ts
  it('excludes vendored, generated, fixture, template, doc and test files', async () => {
    const { scan, reader } = scanWith([
      { path: 'node_modules/pkg/huge.js', loc: 5000 },        // vendor
      { path: 'vendor/lib.go', loc: 5000 },                    // vendor
      { path: 'src/__fixtures__/big-fixture.ts', loc: 5000 },  // fixture
      { path: 'examples/demo.ts', loc: 5000 },                 // template
      { path: 'src/huge.test.ts', loc: 5000 },                 // test
    ]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.filter((f) => f.id === 'STR-011')).toHaveLength(0);
  });

  it('skips minified files (one very long line)', async () => {
    const { scan, reader } = scanWith([
      { path: 'src/bundle.js', loc: 1, charsPerLine: 30000 }, // 1 line, huge
    ]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-011')).toBeUndefined();
  });

  it('skips a god file whose lines average over 500 chars (data/minified)', async () => {
    const { scan, reader } = scanWith([
      { path: 'src/data.ts', loc: 700, charsPerLine: 600 }, // big, but not hand-written
    ]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-011')).toBeUndefined();
  });
```

Note: confirm `classifyFile('examples/demo.ts')` returns `'template'` and the
`node_modules`/`vendor` paths return `'vendor'` — both are non-`'source'`, so the gate
excludes them. The fixture path uses `__fixtures__` (a `FIXTURE_SEGMENTS` entry).

- [ ] **Step 2: Run tests to verify the assumption / catch gaps**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: PASS if the Task 3 gate is correct. If any exclusion fails, the gate logic in
`structure.ts` is wrong — fix it there (do not weaken the test).

- [ ] **Step 3: (Conditional) fix the gate**

Only if a test failed: re-check the `classifyFile(file) !== 'source'` line and the minified
guard `content.length / Math.max(loc, 1) > 500` in `structure.ts`. No new code is expected.

- [ ] **Step 4: Checkpoint — full suite green**

Run: `npx vitest run`
Expected: all pass (`120 → 123 passed`).

---

## Task 5: Finding cap (no silent truncation)

**Files:**
- Modify: `src/analyzers/structure.ts` (summary line — added in Task 6; the cap note is wired here)
- Test: `tests/analyzers/structure.test.ts` (append)

- [ ] **Step 1: Write the failing test**

Append to the god-files `describe` block:

```ts
  it('caps individual findings at 25 and notes the overflow in the summary', async () => {
    // 30 files all > 600 LOC (low tier)
    const files = Array.from({ length: 30 }, (_, i) => ({ path: `src/f${i}.ts`, loc: 650 }));
    const { scan, reader } = scanWith(files);
    const result = await analyzer.analyze(scan, reader);
    const god = result.findings.filter((f) => f.id === 'STR-011');
    expect(god).toHaveLength(25);
    expect(result.summary).toContain('5 more files exceed 600 LOC');
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: FAIL — the cap holds 25 findings (Task 3) but the summary note does not exist yet.

- [ ] **Step 3: Write minimal implementation**

In `structure.ts`, after the god-file finding loop (from Task 3), compute the overflow count
so Task 6's summary can use it. Add this right after `score -= Math.min(godPenalty, GOD_FILE_PENALTY_CAP);`:

```ts
    const godOverflow = Math.max(0, reportable.length - MAX_GOD_FILE_FINDINGS);
```

Then thread `measured` and `godOverflow` (and the tier counts) into the summary. Since the
summary is produced by `buildSummary(scan, findings)` today, extend its signature to accept
the new data. Update the `buildSummary` call AND definition (full change shown in Task 6).
For this task, just ensure `godOverflow` is in scope; the assertion passes once Task 6 lands.

> This task and Task 6 are tightly coupled (cap note lives in the summary). Implement Step 3
> here, then complete the summary in Task 6, then run this test. If executing strictly
> task-by-task, run this test at the end of Task 6.

- [ ] **Step 4: Defer verification to Task 6**

Run: `npx vitest run tests/analyzers/structure.test.ts -t 'caps individual findings'`
Expected: FAIL until Task 6 adds the summary note. Proceed to Task 6.

---

## Task 6: Distribution metrics in the summary

**Files:**
- Modify: `src/analyzers/structure.ts` (`buildSummary` + its call site)
- Test: `tests/analyzers/structure.test.ts` (append)

- [ ] **Step 1: Write the failing test**

Append to the god-files `describe` block:

```ts
  it('appends distribution metrics to the summary', async () => {
    const { scan, reader } = scanWith([
      { path: 'src/a.ts', loc: 1000 },
      { path: 'src/b.ts', loc: 100 },
      { path: 'src/c.ts', loc: 50 },
    ]);
    const result = await analyzer.analyze(scan, reader);
    expect(result.summary).toContain('1.2k LOC');
    expect(result.summary).toContain('3 source files');
    expect(result.summary).toContain('largest src/a.ts (1000)');
    expect(result.summary).toContain('god file'); // a.ts is a god file (medium)
  });
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: FAIL — summary does not contain the distribution line yet.

- [ ] **Step 3: Write minimal implementation**

In `structure.ts`, replace the `buildSummary` call inside `analyze`. The current call is:

```ts
      summary: buildSummary(scan, findings),
```

Replace with:

```ts
      summary: buildSummary(scan, findings, computeSizeMetrics(measured), godOverflow),
```

Then replace the `buildSummary` function definition with this expanded version:

```ts
function buildSummary(
  scan: ProjectScan,
  findings: Finding[],
  metrics: SizeMetrics,
  godOverflow: number,
): string {
  const criticals = findings.filter((f) => f.severity === 'critical').length;
  const highs = findings.filter((f) => f.severity === 'high').length;
  const parts: string[] = [];

  parts.push(`${scan.meta.totalFiles} files scanned`);
  parts.push(`Stack: ${scan.meta.stack.primary}`);

  if (scan.meta.frameworks.length > 0) {
    parts.push(`Frameworks: ${scan.meta.frameworks.join(', ')}`);
  }

  // Distribution metrics (god files + size distribution).
  if (metrics.fileCount > 0) {
    const k = metrics.totalLoc >= 1000
      ? `${(metrics.totalLoc / 1000).toFixed(1)}k LOC`
      : `${metrics.totalLoc} LOC`;
    parts.push(k);
    parts.push(`${metrics.fileCount} source files`);
    parts.push(`median ${metrics.median}`);
    if (metrics.largest) parts.push(`largest ${metrics.largest.path} (${metrics.largest.loc})`);
    parts.push(`top-5 = ${metrics.top5Pct}% of code`);

    const godCount = findings.filter((f) => f.id === 'STR-011').length;
    if (godCount > 0) parts.push(`${godCount} god file${godCount === 1 ? '' : 's'}`);
    if (godOverflow > 0) parts.push(`${godOverflow} more files exceed 600 LOC`);
  }

  if (criticals > 0) parts.push(`${criticals} critical issue${criticals > 1 ? 's' : ''}`);
  if (highs > 0) parts.push(`${highs} high issue${highs > 1 ? 's' : ''}`);
  if (findings.length === 0) parts.push('Clean structure');

  return parts.join(' · ');
}
```

Note: the test `'appends distribution metrics'` expects `1150 LOC` (not `1.2k LOC`) — 1150
rounds to `1.2k` via `toFixed(1)`. **Adjust the test OR the threshold:** 1150 ≥ 1000 so it
renders as `1.2k LOC`. Change that test's assertion to `expect(result.summary).toContain('1.2k LOC')`.
(The cap test in Task 5 uses 30×650 = 19500 → `19.5k LOC`, unaffected.)

Also ensure `SizeMetrics` is imported in `structure.ts`:

```ts
import { countLoc, classifyGodFile, computeSizeMetrics, type MeasuredFile, type GodFileTier, type SizeMetrics } from '../utils/loc.js';
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: PASS — including the Task 5 cap test (`5 archivos más superan 600 LOC`) and this
distribution test (with the `1.2k LOC` assertion).

- [ ] **Step 5: Checkpoint — full suite green**

Run: `npx vitest run`
Expected: all pass (`123 → 125 passed`).

---

## Task 7: Real-world verification + version bump + log

**Files:**
- Modify: `package.json`, `src/cli/index.ts` (version `0.7.1` → `0.8.0`)
- Modify: `SESSION_LOG.md`

- [ ] **Step 1: Run PRISM against the real external repos**

Run:
```bash
npx tsx src/cli/index.ts analyze /opt/orion_new -o json -f /tmp/orion-v8.json
npx tsx src/cli/index.ts analyze /opt/tecofri-n8n -o json -f /tmp/teco-v8.json
```
Then inspect STR-011 findings:
```bash
node -e "const r=require('/tmp/orion-v8.json'); const g=r.findings.filter(f=>f.id==='STR-011'); console.log('god files:', g.length); g.slice(0,10).forEach(f=>console.log(' ', f.severity, f.file, f.meta.loc))"
```
Expected: god files reported are genuinely large production source files. Manually spot-check
2-3 of the largest against the actual repo (`wc -l <file>`) to confirm LOC is accurate and the
file is real source (not vendored/generated that slipped the gate).

- [ ] **Step 2: Confirm no new false positives**

For each STR-011 hit, verify it is NOT a generated/vendored/fixture file. If any FP is found,
return to the Task 3/4 gate — do not ship with known FPs (project credibility ethos).

- [ ] **Step 3: Bump version to 0.8.0**

Edit `package.json`: `"version": "0.7.1"` → `"version": "0.8.0"`.
Edit `src/cli/index.ts`: `.version('0.7.1')` → `.version('0.8.0')`.

Run: `npx tsx src/cli/index.ts --version`
Expected: `0.8.0`.

- [ ] **Step 4: Add the v0.8.0 entry to SESSION_LOG.md**

Add a `### v0.8.0 — Structure profundo (god files + distribución)` section in the
"Cronología de versiones" following the existing format: what was built, the anti-FP gate,
real-world results from Step 1, test count, and mark the "Structure profundo" pendiente as
`[x]` done (note that dead files + circular deps remain for v0.9.0). Update the header
version line and test count.

- [ ] **Step 5: Final checkpoint — full suite green**

Run: `npx vitest run`
Expected: all pass. Record the final count in the log.

---

## Self-Review notes

- **Spec coverage:** god files STR-011 (Tasks 3,5) ✓ · tiers >400/600/900/1500 (Task 1) ✓ ·
  info = metrics-only (Task 3 test) ✓ · per-file findings + cap 25 + overflow note (Tasks 3,5) ✓ ·
  distribution in summary (Task 6) ✓ · anti-FP gate: source-only via classifyFile, ext filter,
  minified guard, read-error skip (Tasks 3,4) ✓ · scoring low/med/high with −3.0 cap (Task 3) ✓ ·
  unit tests for all 3 helpers (Tasks 1,2) ✓ · integration via synthetic scan (Tasks 3–6) ✓ ·
  real-world verification (Task 7) ✓.
- **Type consistency:** `MeasuredFile`/`SizeMetrics`/`GodFileTier` defined in `loc.ts` (Tasks 1,2)
  and imported in `structure.ts` (Tasks 3,6). `buildSummary` signature changed once (Task 6) and
  its only call site updated in the same task. `MAX_GOD_FILE_FINDINGS`, `GOD_FILE_PENALTY`,
  `GOD_FILE_PENALTY_CAP` defined once (Task 3) and reused (Task 5 overflow).
- **Coupling flag:** Tasks 5 and 6 both touch the summary; Task 5's assertion only goes green
  after Task 6. This is called out explicitly in both tasks.
