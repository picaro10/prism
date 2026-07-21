# Import graph + circular dependency detection (TS/JS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a TS/JS import-graph engine and use it for circular-dependency detection (`STR-012`) in PRISM's StructureAnalyzer, ignoring harmless type-only cycles.

**Architecture:** A new pure-helper module `src/utils/import-graph.ts` does all the work — extract imports (with type-only flag), resolve relative specifiers to project files, build a value-edge graph over `source`-context TS/JS files, and find cycles via Tarjan SCC. `StructureAnalyzer` calls `buildImportGraph` + `findCycles` and emits `STR-012` findings, mirroring the v0.8.0 god-file pattern. Resolution is relative-only by design (aliases/bare specifiers → external → no edge), so an imperfect graph misses cycles (safe false negative) rather than inventing them.

**Tech Stack:** TypeScript + Node 22, Vitest. No new dependencies.

> **Note on commits:** `/opt/prism` is NOT a git repository. The standard "commit" step is replaced throughout by a "run the full suite green" checkpoint (`npx vitest run`) plus `npx tsc --noEmit`. The current baseline is 127 passing tests.

---

## File Structure

- **Create** `src/utils/import-graph.ts` — pure engine: `extractImports`, `resolveSpecifier`, `buildImportGraph`, `findCycles`, plus the `ImportEdge` type and the `GRAPH_SOURCE_EXTS` constant.
- **Create** `tests/utils/import-graph.test.ts` — unit tests for the four functions.
- **Modify** `src/analyzers/structure.ts` — add the STR-012 cycle pass + summary line; import from `import-graph.ts`.
- **Modify** `tests/analyzers/structure.test.ts` — integration tests via synthetic `ProjectScan` + fake `FileReader`. The existing `scanWith` helper returns repeated `'x'` lines, which is fine for god files but NOT for imports; this plan adds a second helper `scanWithContent` that maps each file to explicit source text.

The four engine functions are independent and individually testable. The analyzer only orchestrates: call two functions, format findings.

---

## Task 1: `extractImports` — parse import statements with type-only flag

**Files:**
- Create: `src/utils/import-graph.ts`
- Test: `tests/utils/import-graph.test.ts`

- [ ] **Step 1: Write the failing tests**

Create `tests/utils/import-graph.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { extractImports } from '../../src/utils/import-graph.js';

describe('extractImports', () => {
  it('extracts a named value import', () => {
    const edges = extractImports(`import { foo } from './a.js';`);
    expect(edges).toEqual([{ specifier: './a.js', typeOnly: false }]);
  });

  it('extracts default, namespace and side-effect imports', () => {
    const edges = extractImports(
      `import A from './a.js';\nimport * as B from './b.js';\nimport './c.js';`,
    );
    expect(edges.map((e) => e.specifier)).toEqual(['./a.js', './b.js', './c.js']);
    expect(edges.every((e) => e.typeOnly === false)).toBe(true);
  });

  it('extracts re-exports and require', () => {
    const edges = extractImports(
      `export { x } from './a.js';\nexport * from './b.js';\nconst c = require('./c.js');`,
    );
    expect(edges.map((e) => e.specifier).sort()).toEqual(['./a.js', './b.js', './c.js']);
  });

  it('extracts dynamic import with a string literal', () => {
    const edges = extractImports(`const m = await import('./a.js');`);
    expect(edges).toEqual([{ specifier: './a.js', typeOnly: false }]);
  });

  it('ignores dynamic import with a non-literal argument', () => {
    const edges = extractImports(`const m = await import(modName);`);
    expect(edges).toEqual([]);
  });

  it('flags `import type` statements as type-only', () => {
    const edges = extractImports(`import type { T } from './types.js';`);
    expect(edges).toEqual([{ specifier: './types.js', typeOnly: true }]);
  });

  it('flags `export type ... from` as type-only', () => {
    const edges = extractImports(`export type { T } from './types.js';`);
    expect(edges).toEqual([{ specifier: './types.js', typeOnly: true }]);
  });

  it('treats inline mixed imports (type X, value Y) as a value edge', () => {
    const edges = extractImports(`import { type X, Y } from './a.js';`);
    expect(edges).toEqual([{ specifier: './a.js', typeOnly: false }]);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/utils/import-graph.test.ts`
Expected: FAIL — module/function does not exist.

- [ ] **Step 3: Write minimal implementation**

Create `src/utils/import-graph.ts`:

```ts
import { dirname, join, normalize } from 'node:path';
import { classifyFile } from './file-context.js';

/** A single import found in a file. */
export interface ImportEdge {
  /** The module specifier string literal, verbatim. */
  specifier: string;
  /** True only when the whole statement is `import type` / `export type`. */
  typeOnly: boolean;
}

/** Source extensions whose imports participate in the graph. */
export const GRAPH_SOURCE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs'];

/**
 * Extract all import specifiers from TS/JS content, flagging type-only statements.
 *
 * A statement is type-only only when it begins with `import type` or `export type`
 * (statement-level erasure). Inline `import { type X, Y }` is a value edge because
 * `Y` is a runtime value. `import(expr)` with a non-literal argument yields no edge.
 */
export function extractImports(content: string): ImportEdge[] {
  const edges: ImportEdge[] = [];

  // `import ... from 'x'` and `export ... from 'x'` — capture the keyword + the
  // clause between it and `from` so we can detect a leading `type`.
  const fromRe = /\b(import|export)\b([^'"]*?)\bfrom\s*['"]([^'"]+)['"]/g;
  for (const m of content.matchAll(fromRe)) {
    const clause = m[2];
    // type-only iff the word `type` immediately follows the keyword (before any binding).
    const typeOnly = /^\s+type\b/.test(clause);
    edges.push({ specifier: m[3], typeOnly });
  }

  // Side-effect `import 'x'` (no `from`). Exclude `import type` (always has bindings).
  const sideEffectRe = /\bimport\s*['"]([^'"]+)['"]/g;
  for (const m of content.matchAll(sideEffectRe)) {
    edges.push({ specifier: m[1], typeOnly: false });
  }

  // `require('x')` and dynamic `import('x')` — string literal only.
  const callRe = /\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of content.matchAll(callRe)) {
    edges.push({ specifier: m[1], typeOnly: false });
  }

  return edges;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/utils/import-graph.test.ts`
Expected: PASS (8 tests).

> Note: the side-effect regex `\bimport\s*['"]…` will ALSO match the `import` in
> `import('x')` only if a quote immediately follows `(`... it does not, because `(`
> is between. It will not match `import { foo } from 'x'` (a binding, not a quote,
> follows). Verify the `import './c.js'` case yields exactly one edge (not duplicated
> by the call regex). If `import './c.js'` produces a duplicate edge, dedupe is handled
> later in `buildImportGraph` (a Set), so unit-test `extractImports` only for presence
> of the specifier in that combined test, not exact array equality. The provided tests
> already use `.map(e => e.specifier)` for the multi-import case to avoid ordering/dup
> fragility; keep that pattern if you hit duplicates.

- [ ] **Step 5: Checkpoint**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: all green (`127 → 135 passed`), no type errors.

---

## Task 2: `resolveSpecifier` — relative module resolution

**Files:**
- Modify: `src/utils/import-graph.ts`
- Test: `tests/utils/import-graph.test.ts` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/utils/import-graph.test.ts`:

```ts
import { resolveSpecifier } from '../../src/utils/import-graph.js';

describe('resolveSpecifier', () => {
  const files = new Set([
    'src/a.ts',
    'src/b.ts',
    'src/c/index.ts',
    'src/d.tsx',
    'src/e.js',
  ]);

  it('resolves ./x to ./x.ts', () => {
    expect(resolveSpecifier('src/main.ts', './a', files)).toBe('src/a.ts');
  });

  it('resolves ./x to ./x/index.ts', () => {
    expect(resolveSpecifier('src/main.ts', './c', files)).toBe('src/c/index.ts');
  });

  it('resolves a ../ path', () => {
    expect(resolveSpecifier('src/sub/main.ts', '../a', files)).toBe('src/a.ts');
  });

  it('rewrites a .js specifier to a .ts file (TS ESM convention)', () => {
    expect(resolveSpecifier('src/main.ts', './a.js', files)).toBe('src/a.ts');
  });

  it('resolves a .tsx file', () => {
    expect(resolveSpecifier('src/main.ts', './d', files)).toBe('src/d.tsx');
  });

  it('returns null for a bare specifier (external package)', () => {
    expect(resolveSpecifier('src/main.ts', 'react', files)).toBeNull();
  });

  it('returns null for an alias specifier', () => {
    expect(resolveSpecifier('src/main.ts', '@/a', files)).toBeNull();
  });

  it('returns null when the target does not exist in the file set', () => {
    expect(resolveSpecifier('src/main.ts', './does-not-exist', files)).toBeNull();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/utils/import-graph.test.ts`
Expected: FAIL — `resolveSpecifier` is not a function.

- [ ] **Step 3: Write minimal implementation**

Append to `src/utils/import-graph.ts`:

```ts
const RESOLVE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cts', '.mts'];
const INDEX_FILES = RESOLVE_EXTS.map((ext) => `/index${ext}`);

/**
 * Resolve a RELATIVE specifier (`./` or `../`) to an existing project file, or null.
 * Bare specifiers and aliases (anything not starting with `.`) return null (external).
 * `fileSet` holds project-relative paths; resolution must hit a member of it.
 */
export function resolveSpecifier(
  importerPath: string,
  specifier: string,
  fileSet: Set<string>,
): string | null {
  if (!specifier.startsWith('.')) return null; // bare or alias → external

  const baseDir = dirname(importerPath);
  // Normalize to a project-relative path (no leading ./), POSIX-style.
  const raw = normalize(join(baseDir, specifier)).replaceAll('\\', '/');

  // Candidate list, in priority order.
  const candidates: string[] = [];

  // 1. Exact path as written.
  candidates.push(raw);

  // 2. TS rewrite: a .js/.jsx/.mjs/.cjs specifier often maps to a .ts/.tsx/.mts/.cts file.
  const jsToTs: Record<string, string[]> = {
    '.js': ['.ts', '.tsx'],
    '.jsx': ['.tsx'],
    '.mjs': ['.mts'],
    '.cjs': ['.cts'],
  };
  for (const [jsExt, tsExts] of Object.entries(jsToTs)) {
    if (raw.endsWith(jsExt)) {
      const stem = raw.slice(0, -jsExt.length);
      for (const tsExt of tsExts) candidates.push(stem + tsExt);
    }
  }

  // 3. Append source extensions (for extensionless specifiers like './a').
  for (const ext of RESOLVE_EXTS) candidates.push(raw + ext);

  // 4. Directory index files.
  for (const idx of INDEX_FILES) candidates.push(raw + idx);

  for (const cand of candidates) {
    if (fileSet.has(cand)) return cand;
  }
  return null;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/utils/import-graph.test.ts`
Expected: PASS (16 tests total in the file).

> Note on the `./a.js` → `src/a.ts` case: `raw` = `src/a.js`. Candidate 1 (`src/a.js`)
> is not in the set; the TS-rewrite step adds `src/a.ts` (matches). Confirm the exact
> `.js` file is preferred only when it actually exists — here `src/e.js` IS in the set,
> so `resolveSpecifier('src/main.ts', './e.js', files)` must return `src/e.js` (candidate 1
> hits before any rewrite). The provided tests cover `./a.js`→`.ts`; the `./e.js`→`.js`
> direction is implied — if unsure, add a quick assertion for it.

- [ ] **Step 5: Checkpoint**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: all green (`135 → 143 passed`), no type errors.

---

## Task 3: `buildImportGraph` + `findCycles`

**Files:**
- Modify: `src/utils/import-graph.ts`
- Test: `tests/utils/import-graph.test.ts` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/utils/import-graph.test.ts`:

```ts
import { buildImportGraph, findCycles } from '../../src/utils/import-graph.js';

describe('buildImportGraph', () => {
  it('builds value edges between source files and skips type-only + external', async () => {
    const files = ['src/a.ts', 'src/b.ts'];
    const contents: Record<string, string> = {
      'src/a.ts': `import { b } from './b.js';\nimport React from 'react';`,
      'src/b.ts': `import type { A } from './a.js';`, // type-only → no edge
    };
    const graph = await buildImportGraph(files, async (p) => contents[p] ?? '');
    expect([...(graph.get('src/a.ts') ?? [])]).toEqual(['src/b.ts']);
    expect([...(graph.get('src/b.ts') ?? [])]).toEqual([]); // type-only edge dropped
  });

  it('excludes non-source-context files as nodes', async () => {
    const files = ['src/a.ts', 'node_modules/pkg/b.ts'];
    const contents: Record<string, string> = {
      'src/a.ts': `import { b } from '../node_modules/pkg/b.js';`,
      'node_modules/pkg/b.ts': `import { a } from '../../src/a.js';`,
    };
    const graph = await buildImportGraph(files, async (p) => contents[p] ?? '');
    expect(graph.has('node_modules/pkg/b.ts')).toBe(false);
  });
});

describe('findCycles', () => {
  function g(edges: Record<string, string[]>): Map<string, Set<string>> {
    const m = new Map<string, Set<string>>();
    for (const [k, vs] of Object.entries(edges)) m.set(k, new Set(vs));
    return m;
  }

  it('returns no cycles for an acyclic graph', () => {
    expect(findCycles(g({ a: ['b'], b: ['c'], c: [] }))).toEqual([]);
  });

  it('detects a 2-node cycle', () => {
    const cycles = findCycles(g({ a: ['b'], b: ['a'] }));
    expect(cycles).toHaveLength(1);
    expect(cycles[0].sort()).toEqual(['a', 'b']);
  });

  it('detects a 3-node cycle', () => {
    const cycles = findCycles(g({ a: ['b'], b: ['c'], c: ['a'] }));
    expect(cycles).toHaveLength(1);
    expect(cycles[0].sort()).toEqual(['a', 'b', 'c']);
  });

  it('detects a self-loop', () => {
    const cycles = findCycles(g({ a: ['a'] }));
    expect(cycles).toHaveLength(1);
    expect(cycles[0]).toEqual(['a']);
  });

  it('finds one cycle among disconnected components', () => {
    const cycles = findCycles(g({ a: ['b'], b: ['a'], x: ['y'], y: [] }));
    expect(cycles).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/utils/import-graph.test.ts`
Expected: FAIL — `buildImportGraph` / `findCycles` not defined.

- [ ] **Step 3: Write minimal implementation**

Append to `src/utils/import-graph.ts`:

```ts
import { extname } from 'node:path';

/**
 * Build a directed graph of VALUE imports between `source`-context TS/JS files.
 * Nodes: every TS/JS source file. Edges: importer → resolved project target,
 * excluding type-only edges and unresolved/external specifiers.
 */
export async function buildImportGraph(
  files: string[],
  readFile: (path: string) => Promise<string>,
): Promise<Map<string, Set<string>>> {
  const graph = new Map<string, Set<string>>();
  const fileSet = new Set(files);

  const nodes = files.filter(
    (f) => GRAPH_SOURCE_EXTS.includes(extname(f)) && classifyFile(f) === 'source',
  );
  const nodeSet = new Set(nodes);

  for (const file of nodes) {
    const out = new Set<string>();
    let content: string;
    try {
      content = await readFile(file);
    } catch {
      graph.set(file, out);
      continue;
    }
    for (const edge of extractImports(content)) {
      if (edge.typeOnly) continue;
      const target = resolveSpecifier(file, edge.specifier, fileSet);
      // Only edges to other graph nodes (source files) matter for source cycles.
      if (target && target !== file && nodeSet.has(target)) out.add(target);
      else if (target === file) out.add(target); // self-loop preserved
    }
    graph.set(file, out);
  }

  return graph;
}

/**
 * Find cycles via Tarjan's strongly-connected-components algorithm.
 * Returns each SCC of size >= 2, plus any self-loop (node with an edge to itself),
 * as a list of node names. Each cycle appears once.
 */
export function findCycles(graph: Map<string, Set<string>>): string[][] {
  let index = 0;
  const stack: string[] = [];
  const onStack = new Set<string>();
  const indices = new Map<string, number>();
  const lowlink = new Map<string, number>();
  const cycles: string[][] = [];

  function strongConnect(v: string): void {
    indices.set(v, index);
    lowlink.set(v, index);
    index++;
    stack.push(v);
    onStack.add(v);

    for (const w of graph.get(v) ?? []) {
      if (!indices.has(w)) {
        strongConnect(w);
        lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v)!, indices.get(w)!));
      }
    }

    if (lowlink.get(v) === indices.get(v)) {
      const scc: string[] = [];
      let w: string;
      do {
        w = stack.pop()!;
        onStack.delete(w);
        scc.push(w);
      } while (w !== v);

      if (scc.length > 1) {
        cycles.push(scc);
      } else {
        // size-1 SCC is a cycle only if it has a self-edge
        const only = scc[0];
        if (graph.get(only)?.has(only)) cycles.push(scc);
      }
    }
  }

  for (const v of graph.keys()) {
    if (!indices.has(v)) strongConnect(v);
  }

  return cycles;
}
```

> Note: Tarjan recursion depth equals the longest dependency chain. For very large graphs
> this could in theory overflow the stack, but real TS/JS projects don't chain thousands
> of modules deep linearly, and the existing analyzers already read every file — this is
> acceptable. Do NOT add iterative-Tarjan complexity unless a real stack overflow is
> observed (YAGNI).

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/utils/import-graph.test.ts`
Expected: PASS (all engine tests; ~26 in the file).

- [ ] **Step 5: Checkpoint**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: all green, no type errors.

---

## Task 4: STR-012 wiring in StructureAnalyzer + summary

**Files:**
- Modify: `src/analyzers/structure.ts`
- Test: `tests/analyzers/structure.test.ts` (append)

First read `src/analyzers/structure.ts` to see the current `analyze` body, the `buildSummary`
signature (it currently takes `(scan, findings, metrics, godOverflow)`), and how STR-011 is
emitted. Also read the top of `tests/analyzers/structure.test.ts` to reuse imports.

- [ ] **Step 1: Write the failing tests**

Append to `tests/analyzers/structure.test.ts`. Add a content-based scan helper near the
existing `scanWith` helper (do NOT modify `scanWith`):

```ts
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
      'src/b.ts': `export const b = 2;`,
    });
    const result = await analyzer.analyze(scan, reader);
    expect(result.findings.find((f) => f.id === 'STR-012')).toBeUndefined();
    expect(result.summary).toContain('no circular dependencies');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: FAIL — no STR-012 findings / no "circular dependencies" summary text.

- [ ] **Step 3: Write minimal implementation**

(a) Add the import at the top of `src/analyzers/structure.ts`:
```ts
import { buildImportGraph, findCycles } from '../utils/import-graph.js';
```

(b) Add module-level constants near the other god-file constants:
```ts
const MAX_CYCLE_FINDINGS = 20;
const CYCLE_PENALTY = 0.5;
const CYCLE_PENALTY_CAP = 2.0;
```

(c) Insert the cycle pass AFTER the god-file block and BEFORE the `// --- Positive signals ---`
section. It must compute a `cycleCount` and `cycleOverflow` that the summary will use:
```ts
    // --- Check: Circular dependencies (TS/JS value-import graph) ---
    const graph = await buildImportGraph(scan.files, readFile);
    const cycles = findCycles(graph);

    let cyclePenalty = 0;
    for (const cycle of cycles.slice(0, MAX_CYCLE_FINDINGS)) {
      const chain = [...cycle, cycle[0]].join(' → ');
      findings.push({
        id: 'STR-012',
        category: 'structure',
        severity: 'medium',
        title: `Circular dependency (${cycle.length} file${cycle.length === 1 ? '' : 's'})`,
        description: `Circular import chain: ${chain}. Circular dependencies can cause partially-initialized modules at runtime and make the code harder to reason about.`,
        suggestion: 'Break the cycle by extracting shared code into a separate module, or invert one dependency.',
        meta: { cycle },
      });
      cyclePenalty += CYCLE_PENALTY;
    }
    score -= Math.min(cyclePenalty, CYCLE_PENALTY_CAP);
    const cycleOverflow = Math.max(0, cycles.length - MAX_CYCLE_FINDINGS);
```

(d) The summary must report cycle status. The `buildSummary` call currently is:
```ts
      summary: buildSummary(scan, findings, computeSizeMetrics(measured), godOverflow),
```
Change it to pass cycle info:
```ts
      summary: buildSummary(scan, findings, computeSizeMetrics(measured), godOverflow, cycles.length, cycleOverflow),
```

(e) Extend the `buildSummary` definition signature and add the cycle line. Find the current
signature `function buildSummary(scan, findings, metrics, godOverflow)` and replace its
signature + the metrics block's tail. Specifically change the signature to:
```ts
function buildSummary(
  scan: ProjectScan,
  findings: Finding[],
  metrics: SizeMetrics,
  godOverflow: number,
  cycleCount: number,
  cycleOverflow: number,
): string {
```
And inside the `if (metrics.fileCount > 0) { ... }` block, AFTER the god-file lines
(`if (godOverflow > 0) ...`), add:
```ts
    if (cycleCount === 0) {
      parts.push('no circular dependencies');
    } else {
      parts.push(`${cycleCount} circular dependenc${cycleCount === 1 ? 'y' : 'ies'}`);
      if (cycleOverflow > 0) parts.push(`${cycleOverflow} more`);
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: PASS (existing structure tests + 3 new).

- [ ] **Step 5: Checkpoint**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: all green, no type errors.

---

## Task 5: FP-guard integration tests (vendor exclusion + cap)

**Files:**
- Test: `tests/analyzers/structure.test.ts` (append)
- (No implementation change expected — proves Task 3/4 gates. If a test fails, fix the engine, not the test.)

- [ ] **Step 1: Write the failing tests**

Append to the STR-012 `describe` block:

```ts
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
```

- [ ] **Step 2: Run the tests**

Run: `npx vitest run tests/analyzers/structure.test.ts`
Expected: PASS. If the node_modules test fails, the graph is admitting non-source nodes —
fix the `classifyFile(f) === 'source'` filter in `buildImportGraph`. If the cap test shows
≠20 findings, fix the `slice(0, MAX_CYCLE_FINDINGS)` in structure.ts. Do not weaken tests.

- [ ] **Step 3: Checkpoint**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: all green, no type errors.

---

## Task 6: Real-world verification + version bump + log

**Files:**
- Modify: `package.json`, `src/cli/index.ts` (version `0.8.0` → `0.9.0`)
- Modify: `SESSION_LOG.md`

- [ ] **Step 1: Run PRISM against the real external repos**

Run:
```bash
npx tsx src/cli/index.ts analyze /opt/orion_new -o json -f /tmp/orion-v9.json
npx tsx src/cli/index.ts analyze /opt/tecofri-n8n -o json -f /tmp/teco-v9.json
node -e "const r=require('/tmp/orion-v9.json'); const c=r.findings.filter(f=>f.id==='STR-012'); console.log('cycles:', c.length); c.slice(0,8).forEach(f=>console.log(' ', (f.meta.cycle||[]).join(' -> ')))"
node -e "const r=require('/tmp/orion-v9.json'); console.log(r.categories.find(c=>c.category==='structure').summary)"
```

- [ ] **Step 2: Verify each reported cycle is real (no false positives)**

For 2-3 reported cycles, open the files and confirm the value imports genuinely form a loop
(`grep -nE "^import|require|from" <each file>`). Confirm none of the cycle members are
generated/vendored. Because resolution is relative-only, also sanity-check the OPPOSITE risk:
if orion reports ZERO cycles, that's plausibly because its cross-module imports use path
aliases (which we deliberately don't resolve) — note this in the log as expected, not a bug.

- [ ] **Step 3: Bump version to 0.9.0**

Edit `package.json`: `"version": "0.8.0"` → `"version": "0.9.0"`.
Edit `src/cli/index.ts`: `.version('0.8.0')` → `.version('0.9.0')`.
Run: `npx tsx src/cli/index.ts --version` → Expected: `0.9.0`.

- [ ] **Step 4: Add the v0.9.0 entry to SESSION_LOG.md**

Add a `### v0.9.0 — Grafo de imports + dependencias circulares (TS/JS)` section in the
"Cronología de versiones", following the existing format: what was built (engine + STR-012),
the design choices (type-only ignored, relative-only resolution and its false-negative
tradeoff), real-world results from Step 1, final test count. Update the header version line
and test count. Update the "Structure profundo" pending item: cycles now done, only dead
files remain (note them as the v0.10.0 candidate). Add a row to the projects-audited table
if cycles were found.

- [ ] **Step 5: Final checkpoint**

Run: `npx vitest run` then `npx tsc --noEmit`
Expected: all green. Record the final count in the log.

---

## Self-Review notes

- **Spec coverage:** `extractImports` w/ type-only + dynamic (Task 1) ✓ · `resolveSpecifier`
  relative-only + .js→.ts + index + extensions, bare/alias→null (Task 2) ✓ · `buildImportGraph`
  source-only nodes, type-only excluded, external→no edge (Task 3) ✓ · `findCycles` Tarjan SCC
  + self-loop (Task 3) ✓ · STR-012 medium, chain in description, meta.cycle, cap 20 + overflow
  note, −0.5/cap −2.0 (Task 4) ✓ · summary "no circular dependencies"/"N circular dependencies"
  (Task 4) ✓ · anti-FP guards proven (Task 5) ✓ · real-world verification (Task 6) ✓.
- **Type consistency:** `ImportEdge` and `GRAPH_SOURCE_EXTS` defined in Task 1; `resolveSpecifier`
  signature `(importerPath, specifier, fileSet)` consistent Tasks 2-3; `buildImportGraph`/`findCycles`
  signatures consistent Tasks 3-4. `buildSummary` gains exactly two params (`cycleCount`,
  `cycleOverflow`) in Task 4, and its single call site is updated in the same task.
- **Placeholder scan:** no TBD/TODO; all code blocks complete.
- **Coupling note:** Task 4 changes `buildSummary` (already 4-arg from v0.8.0) to 6-arg — the
  ONLY call site is in `analyze`, updated in the same step. No other caller exists.
