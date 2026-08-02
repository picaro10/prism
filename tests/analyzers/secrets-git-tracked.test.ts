import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile, mkdir } from 'node:fs/promises';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanProject } from '../../src/core/scanner.js';
import { SecretsAnalyzer } from '../../src/analyzers/secrets.js';
import { gitTrackedFiles } from '../../src/utils/git-files.js';

// Regression for the scanner/.gitignore blind spot: a .env that was COMMITTED
// and only later added to .gitignore stays tracked in git, but disappears from
// the scanner inventory — SEC-ENV-COMMITTED used to go silent on exactly the
// case its name promises to catch.

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, {
    cwd,
    stdio: 'ignore',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'prism-test',
      GIT_AUTHOR_EMAIL: 'test@prism.local',
      GIT_COMMITTER_NAME: 'prism-test',
      GIT_COMMITTER_EMAIL: 'test@prism.local',
    },
  });
}

describe('SEC-ENV-COMMITTED via git index (tracked but gitignored)', () => {
  let repo: string;

  beforeAll(async () => {
    repo = await mkdtemp(join(tmpdir(), 'prism-git-env-'));
    git(repo, 'init', '-q');
    await writeFile(join(repo, '.env'), 'API_KEY=sk-live-notaplaceholder123456\n');
    await writeFile(join(repo, 'index.js'), 'console.log("app")\n');
    git(repo, 'add', '.');
    git(repo, 'commit', '-q', '-m', 'initial (leaks .env)');
    // The too-late fix: ignore it AFTER it was committed. Git keeps tracking it.
    await writeFile(join(repo, '.gitignore'), '.env\n');
  });

  afterAll(async () => {
    await rm(repo, { recursive: true, force: true });
  });

  it('gitTrackedFiles lists the tracked .env even though .gitignore excludes it', async () => {
    const tracked = await gitTrackedFiles(repo);
    expect(tracked).not.toBeNull();
    expect(tracked).toContain('.env');
  });

  it('gitTrackedFiles returns null outside a git repo instead of throwing', async () => {
    const plain = await mkdtemp(join(tmpdir(), 'prism-nogit-'));
    try {
      expect(await gitTrackedFiles(plain)).toBeNull();
    } finally {
      await rm(plain, { recursive: true, force: true });
    }
  });

  it('raises SEC-ENV-COMMITTED for a tracked .env that the scanner cannot see', async () => {
    const scan = await scanProject(repo);
    expect(scan.files).not.toContain('.env'); // the blind spot: inventory filtered by .gitignore

    const analyzer = new SecretsAnalyzer();
    const result = await analyzer.analyze(scan, async (p) => readFile(join(repo, p), 'utf-8'));

    const envFinding = result.findings.find((f) => f.id === 'SEC-ENV-COMMITTED');
    expect(envFinding).toBeDefined();
    expect(envFinding?.severity).toBe('critical');
    expect(envFinding?.description).toContain('tracked in git');
  });

  it('does not double-count a .env that is both in the inventory and tracked', async () => {
    // Same repo, but .env NOT gitignored → it appears in the inventory AND in
    // the index. Must still be one finding over one file.
    const repo2 = await mkdtemp(join(tmpdir(), 'prism-git-env2-'));
    try {
      git(repo2, 'init', '-q');
      await writeFile(join(repo2, '.env'), 'API_KEY=sk-live-notaplaceholder123456\n');
      git(repo2, 'add', '.');
      git(repo2, 'commit', '-q', '-m', 'leak');
      const scan = await scanProject(repo2);
      const analyzer = new SecretsAnalyzer();
      const result = await analyzer.analyze(scan, async (p) => readFile(join(repo2, p), 'utf-8'));
      const envFindings = result.findings.filter((f) => f.id === 'SEC-ENV-COMMITTED');
      expect(envFindings).toHaveLength(1);
      expect((envFindings[0].meta as { files: string[] }).files).toEqual(['.env']);
    } finally {
      await rm(repo2, { recursive: true, force: true });
    }
  });

  it('does not flag tracked fixture .env files (excluded context still applies)', async () => {
    const repo3 = await mkdtemp(join(tmpdir(), 'prism-git-env3-'));
    try {
      git(repo3, 'init', '-q');
      await mkdir(join(repo3, 'tests', 'fixtures'), { recursive: true });
      await writeFile(join(repo3, 'tests', 'fixtures', '.env'), 'FAKE=1\n');
      await writeFile(join(repo3, 'index.js'), '1\n');
      git(repo3, 'add', '.');
      git(repo3, 'commit', '-q', '-m', 'fixture env');
      await writeFile(join(repo3, '.gitignore'), '.env\n');
      const scan = await scanProject(repo3);
      const analyzer = new SecretsAnalyzer();
      const result = await analyzer.analyze(scan, async (p) => readFile(join(repo3, p), 'utf-8'));
      expect(result.findings.find((f) => f.id === 'SEC-ENV-COMMITTED')).toBeUndefined();
    } finally {
      await rm(repo3, { recursive: true, force: true });
    }
  });
});

describe('secrets summary honesty (scanned vs skipped vs unreadable)', () => {
  it('counts only files actually read, and reports large-file skips and read errors', async () => {
    const scan: import('../../src/core/types.js').ProjectScan = {
      rootPath: '/fake',
      files: ['a.ts', 'big.ts', 'gone.ts'],
      fileTree: [],
      meta: {
        stack: { primary: 'typescript', secondary: [] },
        totalLoc: 0,
        totalFiles: 3,
        hasGit: false,
        hasDocker: false,
        hasCi: false,
        frameworks: [],
      },
    };
    const analyzer = new SecretsAnalyzer();
    const result = await analyzer.analyze(scan, async (p) => {
      if (p === 'a.ts') return 'const x = 1;\n';
      if (p === 'big.ts') return 'x'.repeat(2 * 1024 * 1024 + 1);
      throw new Error('ENOENT');
    });
    // Before the fix this said "3 files scanned" — the candidate count.
    expect(result.summary).toContain('1 files scanned');
    expect(result.summary).toContain('1 skipped (>2MB, not scanned)');
    expect(result.summary).toContain('1 unreadable (not scanned)');
  });
});
