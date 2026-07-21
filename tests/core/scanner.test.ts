import { describe, it, expect, afterEach } from 'vitest';
import { resolve, join } from 'node:path';
import { mkdtemp, mkdir, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { scanProject } from '../../src/core/scanner.js';

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-project');

const tmpDirs: string[] = [];
afterEach(async () => {
  while (tmpDirs.length) {
    const d = tmpDirs.pop()!;
    await rm(d, { recursive: true, force: true }).catch(() => {});
  }
});
async function makeProject(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'prism-scan-'));
  tmpDirs.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, rel);
    await mkdir(join(abs, '..'), { recursive: true });
    await writeFile(abs, content);
  }
  return root;
}

describe('scanProject', () => {
  it('scans the fixture project and returns files', async () => {
    const scan = await scanProject(FIXTURE_PATH);

    expect(scan.rootPath).toBe(FIXTURE_PATH);
    expect(scan.files.length).toBeGreaterThan(0);
    expect(scan.files).toContain('package.json');
    expect(scan.files).toContain('README.md');
    expect(scan.files).toContain('src/config.ts');
  });

  it('excludes node_modules and .git', async () => {
    const scan = await scanProject(FIXTURE_PATH);

    const hasNodeModules = scan.files.some((f) => f.includes('node_modules'));
    const hasGit = scan.files.some((f) => f.startsWith('.git/'));

    expect(hasNodeModules).toBe(false);
    expect(hasGit).toBe(false);
  });

  it('detects TypeScript as primary stack', async () => {
    const scan = await scanProject(FIXTURE_PATH);

    expect(scan.meta.stack.primary).toBe('typescript');
  });

  it('detects package manager', async () => {
    const scan = await scanProject(FIXTURE_PATH);

    // Fixture has no lock file, so packageManager should be undefined
    expect(scan.meta.packageManager).toBeUndefined();
  });

  it('builds a file tree with correct structure', async () => {
    const scan = await scanProject(FIXTURE_PATH);

    expect(scan.fileTree.length).toBeGreaterThan(0);

    const srcDir = scan.fileTree.find((n) => n.name === 'src');
    expect(srcDir).toBeDefined();
    expect(srcDir?.type).toBe('directory');
    expect(srcDir?.children?.length).toBeGreaterThan(0);
  });

  it('counts total files correctly', async () => {
    const scan = await scanProject(FIXTURE_PATH);

    expect(scan.meta.totalFiles).toBe(scan.files.length);
  });

  it('does not claim Express/FastAPI without the real dependency', async () => {
    const noExpress = await makeProject({
      'package.json': JSON.stringify({ dependencies: { chalk: '^5' } }),
      'src/index.ts': 'export const x = 1;',
    });
    const scan = await scanProject(noExpress);
    expect(scan.meta.frameworks).not.toContain('Express');

    const withExpress = await makeProject({
      'package.json': JSON.stringify({ dependencies: { express: '^4' } }),
      'src/index.ts': 'export const x = 1;',
    });
    const scan2 = await scanProject(withExpress);
    expect(scan2.meta.frameworks).toContain('Express');
  });

  it('honors dir-only gitignore patterns with a trailing slash (logs/)', async () => {
    const root = await makeProject({
      '.gitignore': 'logs/\n',
      'logs/app.log': 'noise',
      'logs/deep/more.log': 'noise',
      'src/index.ts': 'export const x = 1;',
    });
    const scan = await scanProject(root);
    expect(scan.files.some((f) => f.startsWith('logs'))).toBe(false);
    // and the ignored dir is not reported as an (empty) directory node
    expect(scan.fileTree.some((n) => n.name === 'logs')).toBe(false);
  });

  it('does not abort the whole scan on an unreadable subdirectory', async () => {
    const root = await makeProject({
      'src/index.ts': 'export const x = 1;',
      'locked/secret.ts': 'export const y = 2;',
    });
    await chmod(join(root, 'locked'), 0o000);
    // Must resolve (not throw) and still see the readable file.
    const scan = await scanProject(root);
    await chmod(join(root, 'locked'), 0o755); // restore so cleanup can remove it
    expect(scan.files).toContain('src/index.ts');
  });
});
