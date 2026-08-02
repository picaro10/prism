import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveBaselineReport } from '../../src/core/baseline.js';

let repo: string;

beforeAll(() => {
  // A tiny real git repo — the worktree path is the whole point of baseline.ts
  // and was at 0% coverage.
  repo = mkdtempSync(join(tmpdir(), 'prism-baseline-repo-'));
  const git = (...args: string[]) => execFileSync('git', args, { cwd: repo });
  git('init', '--quiet');
  git('config', 'user.email', 'test@test');
  git('config', 'user.name', 'test');
  mkdirSync(join(repo, 'src'));
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'baseline-demo', version: '1.0.0' }));
  writeFileSync(join(repo, 'src', 'a.ts'), 'export const a = 1;\n');
  git('add', '-A');
  git('commit', '--quiet', '-m', 'init');
}, 30_000);

afterAll(() => {
  rmSync(repo, { recursive: true, force: true });
});

describe('resolveBaselineReport', () => {
  it('loads a .json file path as a saved report', async () => {
    const reportPath = join(repo, 'saved.json');
    writeFileSync(reportPath, JSON.stringify({ projectName: 'x', overallScore: 5, findings: [], categories: [] }));
    const r = await resolveBaselineReport(reportPath, repo);
    expect(r.projectName).toBe('x');
    rmSync(reportPath);
  });

  it('resolves a git ref via a temporary worktree and audits it', async () => {
    const r = await resolveBaselineReport('HEAD', repo);
    expect(r.projectName).toBe('baseline-demo');
    expect(r.overallScore).toBeGreaterThanOrEqual(0);
    expect(r.categories.length).toBeGreaterThan(0);
  }, 60_000);

  it('throws a clear error for a ref that does not exist', async () => {
    await expect(resolveBaselineReport('no-such-ref', repo)).rejects.toThrow(/Could not resolve baseline/);
  });

  it('throws a clear error outside a git repo', async () => {
    const plain = mkdtempSync(join(tmpdir(), 'prism-nogit-'));
    try {
      await expect(resolveBaselineReport('HEAD', plain)).rejects.toThrow(/Could not resolve baseline/);
    } finally {
      rmSync(plain, { recursive: true, force: true });
    }
  });
});
