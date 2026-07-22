import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { localBranches } from '../../src/utils/git-refs.js';

const SHA = 'a'.repeat(40);

describe('localBranches', () => {
  it('reads loose refs including nested branch names', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-gitrefs-'));
    try {
      mkdirSync(join(dir, '.git', 'refs', 'heads', 'feature'), { recursive: true });
      writeFileSync(join(dir, '.git', 'refs', 'heads', 'main'), `${SHA}\n`);
      writeFileSync(join(dir, '.git', 'refs', 'heads', 'feature', 'x'), `${SHA}\n`);
      expect(localBranches(dir)).toEqual(['feature/x', 'main']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reads packed-refs and merges with loose refs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-gitrefs-'));
    try {
      mkdirSync(join(dir, '.git', 'refs', 'heads'), { recursive: true });
      writeFileSync(join(dir, '.git', 'refs', 'heads', 'dev'), `${SHA}\n`);
      writeFileSync(
        join(dir, '.git', 'packed-refs'),
        `# pack-refs with: peeled fully-peeled sorted\n${SHA} refs/heads/main\n${SHA} refs/tags/v1.0.0\n`,
      );
      expect(localBranches(dir)).toEqual(['dev', 'main']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('returns [] for a non-git directory (unknown, not "no branches")', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-gitrefs-'));
    try {
      expect(localBranches(dir)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reads this repository (integration sanity)', () => {
    expect(localBranches(resolve(__dirname, '../..'))).toContain('main');
  });
});
