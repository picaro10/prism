import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EXIT,
  parseVoteModels,
  usageError,
  loadReportOrExit,
  checkReportRoot,
  loadAllowlistedEnv,
} from '../../src/cli/shared.js';

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

describe('checkReportRoot', () => {
  it('accepts the current working directory itself', () => {
    const r = checkReportRoot(process.cwd());
    expect('root' in r).toBe(true);
  });

  it('accepts a subdirectory of cwd', () => {
    const r = checkReportRoot(join(process.cwd(), 'src'));
    expect('root' in r).toBe(true);
  });

  it('refuses a root OUTSIDE cwd (manipulated report must not read arbitrary dirs)', () => {
    const outside = mkdtempSync(join(tmpdir(), 'prism-outside-'));
    try {
      const r = checkReportRoot(outside);
      expect('reason' in r).toBe(true);
      if ('reason' in r) expect(r.reason).toContain('outside the current directory');
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('refuses a nonexistent recorded path', () => {
    const r = checkReportRoot('/definitely/not/a/real/path');
    expect('reason' in r).toBe(true);
  });

  it('honors an explicit --root override even outside cwd (operator asserts trust)', () => {
    const outside = mkdtempSync(join(tmpdir(), 'prism-override-'));
    try {
      const r = checkReportRoot('/whatever/the/report/says', outside);
      expect(r).toEqual({ root: outside });
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('refuses a --root that is not a directory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-badroot-'));
    const file = join(dir, 'f.txt');
    writeFileSync(file, 'x');
    try {
      const r = checkReportRoot('/whatever', file);
      expect('reason' in r).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

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
        projectMeta: {
          stack: { primary: 'typescript', secondary: [] },
          totalLoc: 0,
          totalFiles: 1,
          hasGit: false,
          hasDocker: false,
          hasCi: false,
          frameworks: [],
        },
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

describe('loadAllowlistedEnv', () => {
  it('imports only PRISM-consumed keys, never the target project secrets', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-env-'));
    const envPath = join(dir, '.env');
    writeFileSync(
      envPath,
      [
        'ANTHROPIC_API_KEY="sk-test-abc"',
        'PRISM_FUTURE_FLAG=on',
        'DATABASE_URL=postgres://real:secret@prod/db',
        'AWS_SECRET_ACCESS_KEY=leakme',
        'export OPENROUTER_API_KEY=or-key',
      ].join('\n'),
    );
    const saved = process.env;
    try {
      const {
        ANTHROPIC_API_KEY: _a,
        OPENROUTER_API_KEY: _o,
        PRISM_FUTURE_FLAG: _p,
        DATABASE_URL: _d,
        AWS_SECRET_ACCESS_KEY: _k,
        ...rest
      } = saved;
      process.env = { ...rest };
      loadAllowlistedEnv(envPath);
      expect(process.env.ANTHROPIC_API_KEY).toBe('sk-test-abc'); // quotes stripped
      expect(process.env.OPENROUTER_API_KEY).toBe('or-key'); // export prefix ok
      expect(process.env.PRISM_FUTURE_FLAG).toBe('on');
      expect(process.env.DATABASE_URL).toBeUndefined(); // target secret NOT imported
      expect(process.env.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    } finally {
      process.env = saved;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('never overrides the real environment', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-env2-'));
    const envPath = join(dir, '.env');
    writeFileSync(envPath, 'ANTHROPIC_API_KEY=from-file\n');
    const saved = process.env;
    try {
      process.env = { ...saved, ANTHROPIC_API_KEY: 'from-real-env' };
      loadAllowlistedEnv(envPath);
      expect(process.env.ANTHROPIC_API_KEY).toBe('from-real-env');
    } finally {
      process.env = saved;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('is a no-op for a missing file', () => {
    expect(() => loadAllowlistedEnv('/nope/definitely/missing/.env')).not.toThrow();
  });

  it('strips an inline # comment from an unquoted value but keeps # inside quotes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'prism-env3-'));
    const p = join(dir, '.env');
    writeFileSync(p, 'ANTHROPIC_API_KEY=sk-ant-real # work key\r\nOPENROUTER_API_KEY="or#notacomment"\r\n');
    const saved = process.env;
    try {
      const { ANTHROPIC_API_KEY: _a, OPENROUTER_API_KEY: _o, ...rest } = saved;
      process.env = { ...rest };
      loadAllowlistedEnv(p);
      expect(process.env.ANTHROPIC_API_KEY).toBe('sk-ant-real'); // inline comment + CRLF handled
      expect(process.env.OPENROUTER_API_KEY).toBe('or#notacomment'); // # inside quotes preserved
    } finally {
      process.env = saved;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
