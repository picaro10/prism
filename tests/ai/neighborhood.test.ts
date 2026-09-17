import { describe, it, expect } from 'vitest';
import {
  extractImportBindings,
  anchorTokens,
  buildNeighborhoodIndex,
  buildNeighborhood,
  unitContext,
  codeOnly,
  MAX_NEIGHBORS,
  MAX_NEIGHBOR_CHARS,
} from '../../src/ai/neighborhood.js';
import type { Finding } from '../../src/core/types.js';

const finding = (p: Partial<Finding>): Finding => ({
  id: 'AGT-001',
  category: 'agentic',
  severity: 'high',
  title: 't',
  description: 'd',
  ...p,
});

/** An in-memory project: path → content. */
function project(files: Record<string, string>) {
  const readFile = async (p: string) => {
    if (!(p in files)) throw new Error(`ENOENT ${p}`);
    return files[p];
  };
  return { files: Object.keys(files), readFile };
}

describe('extractImportBindings', () => {
  it('reads default, named (with alias), namespace, mixed, and require bindings', () => {
    const src = [
      "import a from './a.js';",
      "import { b, c as cc } from './b.js';",
      "import * as ns from './ns.js';",
      "import d, { e } from './d.js';",
      "const { f } = require('./f.js');",
      "const g = require('./g.js');",
      "import type { T } from './t.js';",
      "import { type U, v } from './u.js';",
      "// import { ghost } from './ghost.js';",
    ].join('\n');
    const b = extractImportBindings(src);
    const by = Object.fromEntries(b.map((x) => [x.specifier, x.names]));
    expect(by['./a.js']).toEqual(['a']);
    expect(by['./b.js']).toEqual(['b', 'cc']);
    expect(by['./ns.js']).toEqual(['ns']);
    expect(by['./d.js']).toEqual(['e', 'd']);
    expect(by['./f.js']).toEqual(['f']);
    expect(by['./g.js']).toEqual(['g']);
    expect(by['./t.js']).toBeUndefined(); // type-only statement: nothing runs through it
    expect(by['./u.js']).toEqual(['U', 'v']);
    expect(by['./ghost.js']).toBeUndefined(); // commented out
  });
});

describe('anchorTokens', () => {
  it('keeps string literals and meaningful identifiers, drops boilerplate', () => {
    const t = anchorTokens("  name: 'delete_file', description: 'x' ");
    expect(t).toContain('delete_file');
    expect(t).not.toContain('name');
    expect(t).not.toContain('description');
    expect(anchorTokens('return execSync(`git log ${ref}`)')).toEqual(expect.arrayContaining(['execSync']));
    expect(anchorTokens('return execSync(`git log ${ref}`)')).not.toContain('ref'); // too short to anchor
  });
});

describe('buildNeighborhood', () => {
  const validatorProject = () =>
    project({
      'package.json': '{}',
      'src/validate.ts':
        'export function assertSafeRef(ref: string) { if (!/^[\\w./-]+$/.test(ref)) throw new Error("bad"); }\n',
      'src/git.ts': [
        'import { execSync } from "node:child_process";',
        'import { assertSafeRef } from "./validate.js";',
        'import { log } from "./log.js";',
        'export function recentCommits(ref: string) {',
        '  assertSafeRef(ref);',
        '  return execSync(`git log -5 ${ref}`).toString();',
        '}',
        '',
      ].join('\n'),
      'src/log.ts': 'export const log = console.log;\n',
      'src/unrelated.ts': 'export const x = 1;\n',
    });

  it('brings in the imported module whose name is used near the flagged line, and only that one', async () => {
    const p = validatorProject();
    const index = await buildNeighborhoodIndex(p.files, p.readFile);
    const content = await p.readFile('src/git.ts');
    const n = await buildNeighborhood(
      'src/git.ts',
      content,
      [finding({ file: 'src/git.ts', line: 6 })],
      index,
      p.readFile,
    );
    expect(n.map((x) => x.file)).toEqual(['src/validate.ts']); // log.ts imported but never used → out
    expect(n[0].content).toMatch(/assertSafeRef/);
    expect(n[0].reason).toMatch(/assertSafeRef used near/);
  });

  it('brings in an importer that mentions an anchor token from the flagged line', async () => {
    const p = project({
      'src/tools.ts': "export const tools = [{ name: 'delete_file', description: 'd', parameters: {} }];\n",
      'src/executor.ts': [
        'import { tools } from "./tools.js";',
        "const DESTRUCTIVE = new Set(['delete_file']);",
        'export async function run(name: string) { if (DESTRUCTIVE.has(name)) await approve(name); }',
        '',
      ].join('\n'),
      'src/other-importer.ts': 'import { tools } from "./tools.js";\nexport const n = tools.length;\n',
    });
    const index = await buildNeighborhoodIndex(p.files, p.readFile);
    const content = await p.readFile('src/tools.ts');
    const n = await buildNeighborhood(
      'src/tools.ts',
      content,
      [finding({ id: 'AGT-003', file: 'src/tools.ts', line: 1 })],
      index,
      p.readFile,
    );
    expect(n.map((x) => x.file)).toEqual(['src/executor.ts']); // other-importer never mentions delete_file
    expect(n[0].reason).toMatch(/imports src\/tools\.ts; mentions delete_file/);
  });

  it('resolves tsconfig path aliases', async () => {
    const p = project({
      'tsconfig.json': '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } } }',
      'src/validate.ts': 'export const assertSafeRef = (r: string) => r;\n',
      'src/git.ts':
        'import { assertSafeRef } from "@/validate";\nexport const f = (r: string) => run(assertSafeRef(r));\n',
    });
    const index = await buildNeighborhoodIndex(p.files, p.readFile);
    const n = await buildNeighborhood(
      'src/git.ts',
      await p.readFile('src/git.ts'),
      [finding({ file: 'src/git.ts', line: 2 })],
      index,
      p.readFile,
    );
    expect(n.map((x) => x.file)).toEqual(['src/validate.ts']);
  });

  it('returns nothing for file-tier findings, non-TS/JS files, or when nothing qualifies', async () => {
    const p = validatorProject();
    const index = await buildNeighborhoodIndex(p.files, p.readFile);
    const content = await p.readFile('src/git.ts');
    expect(
      await buildNeighborhood('src/git.ts', content, [finding({ id: 'SEC-AWS-KEY', line: 6 })], index, p.readFile),
    ).toEqual([]);
    expect(await buildNeighborhood('src/app.py', 'import os\n', [finding({ line: 1 })], index, p.readFile)).toEqual([]);
    expect(
      await buildNeighborhood('src/unrelated.ts', 'export const x = 1;\n', [finding({ line: 1 })], index, p.readFile),
    ).toEqual([]);
  });

  it('is bounded: at most MAX_NEIGHBORS files, each truncated at MAX_NEIGHBOR_CHARS', async () => {
    const files: Record<string, string> = {};
    const imports: string[] = [];
    const uses: string[] = [];
    for (let i = 0; i < 8; i++) {
      files[`src/m${i}.ts`] = `export const fn${i} = () => ${i};\n${'// pad\n'.repeat(4000)}`;
      imports.push(`import { fn${i} } from "./m${i}.js";`);
      uses.push(`fn${i}()`);
    }
    files['src/main.ts'] =
      `${imports.join('\n')}\nexport const go = (cmd: string) => execSync(\`x ${'${cmd}'}\`) + ${uses.join(' + ')};\n`;
    const p = project(files);
    const index = await buildNeighborhoodIndex(p.files, p.readFile);
    const n = await buildNeighborhood(
      'src/main.ts',
      files['src/main.ts'],
      [finding({ file: 'src/main.ts', line: 9 })],
      index,
      p.readFile,
    );
    expect(n.length).toBeLessThanOrEqual(MAX_NEIGHBORS);
    for (const x of n) expect(x.content.length).toBeLessThanOrEqual(MAX_NEIGHBOR_CHARS + 20);
    expect(n.some((x) => x.content.includes('[truncated]'))).toBe(true);
  });

  it('is deterministic: same project, same order', async () => {
    const p = validatorProject();
    const index = await buildNeighborhoodIndex(p.files, p.readFile);
    const content = await p.readFile('src/git.ts');
    const a = await buildNeighborhood('src/git.ts', content, [finding({ line: 6 })], index, p.readFile);
    const b = await buildNeighborhood('src/git.ts', content, [finding({ line: 6 })], index, p.readFile);
    expect(a).toEqual(b);
  });
});

describe('unitContext', () => {
  it('is the bare content without neighbors and changes with any neighbor content', () => {
    expect(unitContext('abc', undefined)).toBe('abc');
    expect(unitContext('abc', [])).toBe('abc');
    const a = unitContext('abc', [{ file: 'x', content: '1', reason: 'r' }]);
    const b = unitContext('abc', [{ file: 'x', content: '2', reason: 'r' }]);
    expect(a).not.toBe(b);
  });
});

describe('codeOnly', () => {
  it('drops comments and string contents but keeps template interpolations', () => {
    const src = 'const a = "log"; // log\nexec(`git log ${sanitize(cmd)}`); /* log */\n';
    const out = codeOnly(src);
    expect(out).not.toMatch(/\blog\b/);
    expect(out).toMatch(/sanitize\(cmd\)/);
  });
});
