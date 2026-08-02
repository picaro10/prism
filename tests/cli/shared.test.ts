import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EXIT, parseVoteModels, usageError, loadReportOrExit } from '../../src/cli/shared.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** Make process.exit throw so exit paths become assertable. */
function trapExit(): void {
  vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`exit:${code}`);
  }) as never);
  vi.spyOn(console, 'error').mockImplementation(() => {});
}

describe('parseVoteModels', () => {
  it('splits and trims a comma-separated list', () => {
    expect(parseVoteModels('a, b ,c')).toEqual(['a', 'b', 'c']);
  });

  it('returns undefined for empty/boolean/undefined input', () => {
    expect(parseVoteModels('')).toBeUndefined();
    expect(parseVoteModels(true)).toBeUndefined();
    expect(parseVoteModels(undefined)).toBeUndefined();
    expect(parseVoteModels(' , ,')).toBeUndefined();
  });
});

describe('usageError', () => {
  it('exits with the usage code (2)', () => {
    trapExit();
    expect(() => usageError('bad flag')).toThrow(`exit:${EXIT.USAGE}`);
  });
});

describe('loadReportOrExit', () => {
  it('loads and deep-validates a real report file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-shared-'));
    const path = join(dir, 'r.json');
    writeFileSync(
      path,
      JSON.stringify({
        projectName: 'demo',
        projectPath: '/tmp/demo',
        overallScore: 5,
        categories: [],
        findings: [],
      }),
    );
    try {
      const report = await loadReportOrExit(path);
      expect(report.projectName).toBe('demo');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exits 2 for a missing file', async () => {
    trapExit();
    await expect(loadReportOrExit('/nonexistent/nowhere.json')).rejects.toThrow(`exit:${EXIT.USAGE}`);
  });

  it('exits 2 for invalid JSON', async () => {
    trapExit();
    const dir = mkdtempSync(join(tmpdir(), 'prism-shared-'));
    const path = join(dir, 'broken.json');
    writeFileSync(path, '{not json');
    try {
      await expect(loadReportOrExit(path)).rejects.toThrow(`exit:${EXIT.USAGE}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('exits 2 for structurally invalid reports (finding without severity)', async () => {
    trapExit();
    const dir = mkdtempSync(join(tmpdir(), 'prism-shared-'));
    const path = join(dir, 'invalid.json');
    writeFileSync(
      path,
      JSON.stringify({
        projectName: 'demo',
        projectPath: '/tmp/demo',
        overallScore: 5,
        categories: [],
        findings: [{ id: 'X', category: 'security', title: 't', description: 'd' }],
      }),
    );
    try {
      await expect(loadReportOrExit(path)).rejects.toThrow(`exit:${EXIT.USAGE}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
