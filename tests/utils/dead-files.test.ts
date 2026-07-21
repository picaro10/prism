import { describe, it, expect } from 'vitest';
import {
  parseTsconfigAliases,
  collectPackageEntryPoints,
  isConventionEntry,
  findDeadFiles,
  resolvePathToken,
} from '../../src/utils/dead-files.js';
import { resolveAliasSpecifier, scanReachability, hasNonLiteralDynamicImport } from '../../src/utils/import-graph.js';

function readerOf(contents: Record<string, string>) {
  return async (path: string) => {
    const c = contents[path];
    if (c === undefined) throw new Error('ENOENT');
    return c;
  };
}

describe('parseTsconfigAliases', () => {
  it('parses baseUrl and paths from clean JSON', () => {
    const a = parseTsconfigAliases(
      JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@/*': ['./src/*'] } } }),
      'tsconfig.json',
    );
    expect(a).toEqual({ baseDir: '', baseUrl: '.', paths: { '@/*': ['./src/*'] } });
  });

  it('tolerates JSONC comments and trailing commas', () => {
    const jsonc = `{
      // path aliases
      "compilerOptions": {
        /* base */ "baseUrl": ".",
        "paths": { "@/*": ["./src/*"], },
      },
    }`;
    const a = parseTsconfigAliases(jsonc, 'packages/app/tsconfig.json');
    expect(a).toMatchObject({ baseDir: 'packages/app', baseUrl: '.' });
  });

  it('returns null when there are no aliases', () => {
    expect(parseTsconfigAliases(JSON.stringify({ compilerOptions: { strict: true } }), 'tsconfig.json')).toBeNull();
    expect(parseTsconfigAliases(JSON.stringify({}), 'tsconfig.json')).toBeNull();
  });

  it("returns 'unparseable' for content JSON repair cannot save", () => {
    expect(parseTsconfigAliases('{ "compilerOptions": { paths: ???', 'tsconfig.json')).toBe('unparseable');
  });
});

describe('resolveAliasSpecifier', () => {
  const fileSet = new Set(['src/utils/loc.ts', 'src/index.ts', 'lib/helper.ts']);

  it('resolves a star pattern through paths', () => {
    const aliases = [{ baseDir: '', baseUrl: null, paths: { '@/*': ['./src/*'] } }];
    expect(resolveAliasSpecifier('@/utils/loc', aliases, fileSet)).toBe('src/utils/loc.ts');
    expect(resolveAliasSpecifier('@/nope', aliases, fileSet)).toBeNull();
  });

  it('resolves an exact (starless) pattern', () => {
    const aliases = [{ baseDir: '', baseUrl: null, paths: { helper: ['./lib/helper.ts'] } }];
    expect(resolveAliasSpecifier('helper', aliases, fileSet)).toBe('lib/helper.ts');
  });

  it('resolves bare specifiers via an explicit baseUrl', () => {
    const aliases = [{ baseDir: '', baseUrl: './src', paths: {} }];
    expect(resolveAliasSpecifier('utils/loc', aliases, fileSet)).toBe('src/utils/loc.ts');
  });

  it('does not treat bare specifiers as internal without an explicit baseUrl', () => {
    const aliases = [{ baseDir: '', baseUrl: null, paths: { '@/*': ['./src/*'] } }];
    expect(resolveAliasSpecifier('lib/helper', aliases, fileSet)).toBeNull();
  });

  it('respects the tsconfig directory of a nested package', () => {
    const set = new Set(['packages/app/src/a.ts']);
    const aliases = [{ baseDir: 'packages/app', baseUrl: '.', paths: { '@/*': ['./src/*'] } }];
    expect(resolveAliasSpecifier('@/a', aliases, set)).toBe('packages/app/src/a.ts');
  });
});

describe('hasNonLiteralDynamicImport', () => {
  it('detects import/require with a variable argument', () => {
    expect(hasNonLiteralDynamicImport('await import(pluginPath)')).toBe(true);
    expect(hasNonLiteralDynamicImport('require(name + ".js")')).toBe(true);
  });

  it('ignores string-literal imports', () => {
    expect(hasNonLiteralDynamicImport('await import("./x.js"); require(\'./y\')')).toBe(false);
  });
});

describe('scanReachability', () => {
  it('counts type-only imports and test-file imports as reachability', async () => {
    const contents: Record<string, string> = {
      'src/a.ts': 'import type { T } from "./types.js";',
      'tests/a.test.ts': 'import { helper } from "../src/helper.js";',
      'src/types.ts': 'export interface T {}',
      'src/helper.ts': 'export const helper = 1;',
      'src/orphan.ts': 'export const x = 1;',
    };
    const r = await scanReachability(Object.keys(contents), readerOf(contents));
    expect(r.imported.has('src/types.ts')).toBe(true); // type-only edge counts
    expect(r.imported.has('src/helper.ts')).toBe(true); // test importer counts
    expect(r.imported.has('src/orphan.ts')).toBe(false);
    expect(r.sourceFiles).not.toContain('tests/a.test.ts'); // tests are not candidates
  });

  it('flags shebang files and excludes .d.ts from candidates', async () => {
    const contents: Record<string, string> = {
      'scripts/run.ts': '#!/usr/bin/env tsx\nconsole.log(1);',
      'src/globals.d.ts': 'declare const VERSION: string;',
    };
    const r = await scanReachability(Object.keys(contents), readerOf(contents));
    expect(r.shebangFiles.has('scripts/run.ts')).toBe(true);
    expect(r.sourceFiles).not.toContain('src/globals.d.ts');
  });
});

describe('collectPackageEntryPoints', () => {
  const fileSet = new Set(['src/index.ts', 'src/cli/index.ts', 'src/core/engine.ts', 'packages/app/src/main.ts']);

  it('collects main/bin/exports and script tokens', () => {
    const pkg = JSON.stringify({
      main: 'src/index.ts',
      bin: { prism: './src/cli/index.ts' },
      scripts: { build: 'tsup src/cli/index.ts --dts && tsup src/core/engine.ts' },
    });
    const entries = collectPackageEntryPoints('package.json', pkg, fileSet);
    expect(entries).toEqual(new Set(['src/index.ts', 'src/cli/index.ts', 'src/core/engine.ts']));
  });

  it('resolves refs relative to a nested package.json (monorepo)', () => {
    const pkg = JSON.stringify({ exports: { '.': { import: './src/main.ts' } } });
    const entries = collectPackageEntryPoints('packages/app/package.json', pkg, fileSet);
    expect(entries).toEqual(new Set(['packages/app/src/main.ts']));
  });

  it('returns nothing for unparseable package.json', () => {
    expect(collectPackageEntryPoints('package.json', '{oops', fileSet).size).toBe(0);
  });
});

describe('isConventionEntry', () => {
  it('recognizes framework conventions and config/stories files', () => {
    expect(isConventionEntry('pages/about.tsx')).toBe(true);
    expect(isConventionEntry('src/routes/users.ts')).toBe(true);
    expect(isConventionEntry('app/dashboard/page.tsx')).toBe(true);
    expect(isConventionEntry('src/app/layout.tsx')).toBe(true);
    expect(isConventionEntry('vitest.config.ts')).toBe(true);
    expect(isConventionEntry('src/Button.stories.tsx')).toBe(true);
    expect(isConventionEntry('index.ts')).toBe(true);
    expect(isConventionEntry('src/index.ts')).toBe(true);
  });

  it('does not claim ordinary source files', () => {
    expect(isConventionEntry('src/utils/loc.ts')).toBe(false);
    expect(isConventionEntry('src/utils/index.ts')).toBe(false); // nested index is a real candidate
    expect(isConventionEntry('src/pagesHelper.ts')).toBe(false);
  });
});

describe('resolvePathToken', () => {
  const fileSet = new Set(['src/workers/agents/index.ts', 'ops-agent/index.mjs', 'dashboard/src/main.tsx']);

  it('maps a build-output reference (dist/x.js) back to its source file', () => {
    expect(resolvePathToken('dist/workers/agents/index.js', '', fileSet)).toBe('src/workers/agents/index.ts');
  });

  it('resolves an absolute path by stripping leading segments', () => {
    expect(resolvePathToken('/opt/orion_new/ops-agent/index.mjs', 'tests/unit', fileSet)).toBe('ops-agent/index.mjs');
  });

  it('resolves an HTML root-relative src against the referrer directory', () => {
    expect(resolvePathToken('/src/main.tsx', 'dashboard', fileSet)).toBe('dashboard/src/main.tsx');
  });

  it('resolves relative tokens only against the referrer directory', () => {
    expect(resolvePathToken('../../ops-agent/index.mjs', 'tests/unit', fileSet)).toBe('ops-agent/index.mjs');
    expect(resolvePathToken('./nope.ts', 'src', fileSet)).toBeNull();
  });
});

describe('findDeadFiles', () => {
  it('spares files referenced by Dockerfiles, HTML, and fork() paths', async () => {
    const contents: Record<string, string> = {
      'docker/Dockerfile.agents': 'CMD ["node", "dist/workers/agents/index.js"]',
      'dashboard/index.html': '<script type="module" src="/src/main.tsx"></script>',
      'tests/unit/ops.test.ts': "const p = resolve('/abs/proj/ops-agent/index.mjs'); fork(p);",
      'src/workers/agents/index.ts': 'export const w = 1;',
      'dashboard/src/main.tsx': 'export const app = 1;',
      'ops-agent/index.mjs': 'export const agent = 1;',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual([]);
  });

  it('treats files under scripts/, bin/ and tools/ as manual entry points', async () => {
    const contents: Record<string, string> = {
      'scripts/oauth-refresh.ts': 'console.log(1);',
      'tools/migrate.ts': 'console.log(2);',
      'src/index.ts': 'export const x = 1;',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual([]);
  });

  it('flags an orphan and spares imported/entry/convention files', async () => {
    const contents: Record<string, string> = {
      'package.json': JSON.stringify({ main: 'src/index.ts' }),
      'src/index.ts': 'import { used } from "./used.js";',
      'src/used.ts': 'export const used = 1;',
      'src/orphan.ts': 'export const dead = 1;',
      'scripts/tool.ts': '#!/usr/bin/env tsx\nconsole.log(1);',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual(['src/orphan.ts']);
    expect(r.skippedReason).toBeUndefined();
  });

  it('spares a file reachable only through a tsconfig alias', async () => {
    const contents: Record<string, string> = {
      'tsconfig.json': JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@/*': ['./src/*'] } } }),
      'src/index.ts': 'import { x } from "@/aliased.js";',
      'src/aliased.ts': 'export const x = 1;',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual([]);
  });

  it('skips the whole analysis when a tsconfig with possible aliases cannot be parsed', async () => {
    const contents: Record<string, string> = {
      'tsconfig.json': '{ paths: ??? broken',
      'src/orphan.ts': 'export const dead = 1;',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual([]);
    expect(r.skippedReason).toMatch(/tsconfig\.json/);
  });

  it('reports non-literal dynamic imports so findings can warn', async () => {
    const contents: Record<string, string> = {
      'src/index.ts': 'await import(pluginName);',
      'src/orphan.ts': 'export const dead = 1;',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual(['src/orphan.ts']);
    expect(r.hasNonLiteralDynamic).toBe(true);
  });

  it('a file imported only via type-only import is not dead', async () => {
    const contents: Record<string, string> = {
      'src/index.ts': 'import type { T } from "./types.js"; export const x: T = 1 as T;',
      'src/types.ts': 'export type T = number;',
    };
    const r = await findDeadFiles(Object.keys(contents), readerOf(contents));
    expect(r.dead).toEqual([]);
  });
});
