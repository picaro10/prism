import { describe, it, expect } from 'vitest';
import {
  extractImports,
  stripComments,
  resolveSpecifier,
  buildImportGraph,
  findCycles,
} from '../../src/utils/import-graph.js';

describe('extractImports', () => {
  it('extracts a named value import', () => {
    const edges = extractImports(`import { foo } from './a.js';`);
    expect(edges).toEqual([{ specifier: './a.js', typeOnly: false }]);
  });

  it('extracts default, namespace and side-effect imports', () => {
    const edges = extractImports(`import A from './a.js';\nimport * as B from './b.js';\nimport './c.js';`);
    expect(edges.map((e) => e.specifier)).toEqual(['./a.js', './b.js', './c.js']);
    expect(edges.every((e) => e.typeOnly === false)).toBe(true);
  });

  it('extracts re-exports and require', () => {
    const edges = extractImports(`export { x } from './a.js';\nexport * from './b.js';\nconst c = require('./c.js');`);
    expect(edges.map((e) => e.specifier).sort()).toEqual(['./a.js', './b.js', './c.js']);
  });

  it('ignores imports inside line and block comments (would fabricate cycles)', () => {
    const src = [
      `import { real } from './real.js';`,
      `// import { commented } from './line-comment.js';`,
      `/* import { blocked } from './block-comment.js'; */`,
      '/*',
      ` * import { multiline } from './multi.js';`,
      ' */',
    ].join('\n');
    expect(extractImports(src).map((e) => e.specifier)).toEqual(['./real.js']);
  });

  it('does not treat "//" inside a string literal as a comment', () => {
    const src = `const url = "http://example.com";\nimport { x } from './a.js';`;
    expect(extractImports(src).map((e) => e.specifier)).toEqual(['./a.js']);
  });

  it('extracts dynamic import with a string literal', () => {
    const edges = extractImports(`const m = await import('./a.js');`);
    expect(edges).toEqual([{ specifier: './a.js', typeOnly: false }]);
  });

  it('ignores dynamic import with a non-literal argument', () => {
    const edges = extractImports('const m = await import(modName);');
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

  it('handles a multi-line import statement', () => {
    const edges = extractImports(`import {\n  foo,\n  bar,\n} from './a.js';`);
    expect(edges).toEqual([{ specifier: './a.js', typeOnly: false }]);
  });
});

describe('stripComments', () => {
  it('removes comments but preserves string content and newlines', () => {
    const out = stripComments(`const a = 1; // trailing\nconst u = "a//b"; /* mid */ const z = 2;`);
    expect(out).toContain('"a//b"');
    expect(out).not.toContain('trailing');
    expect(out).not.toContain('mid');
    expect(out.split('\n').length).toBe(2); // newline preserved
  });
});

describe('resolveSpecifier', () => {
  const files = new Set(['src/a.ts', 'src/b.ts', 'src/c/index.ts', 'src/d.tsx', 'src/e.js']);

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

  it('prefers an existing .js file over rewriting', () => {
    expect(resolveSpecifier('src/main.ts', './e.js', files)).toBe('src/e.js');
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

  it('detects two independent cycles', () => {
    const cycles = findCycles(g({ a: ['b'], b: ['a'], c: ['d'], d: ['c'] }));
    expect(cycles).toHaveLength(2);
  });

  it('excludes a tail node that points into a cycle', () => {
    const cycles = findCycles(g({ entry: ['a'], a: ['b'], b: ['a'] }));
    expect(cycles).toHaveLength(1);
    expect(cycles[0].sort()).toEqual(['a', 'b']);
  });
});
