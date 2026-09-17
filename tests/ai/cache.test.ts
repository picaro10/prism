import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { VerdictCache, cacheKey, judgeId, cacheBaseDir, MAX_CACHE_ENTRIES } from '../../src/ai/cache.js';
import type { Finding } from '../../src/core/types.js';

const finding = (p: Partial<Finding> = {}): Finding => ({
  id: 'SEC-AWS-KEY',
  category: 'security',
  severity: 'high',
  title: 't',
  description: 'd',
  file: 'src/a.ts',
  line: 3,
  ...p,
});

describe('cacheKey', () => {
  const base = { kind: 'triage' as const, judge: 'anthropic:m', content: 'abc', finding: finding() };

  it('is stable for identical inputs', () => {
    expect(cacheKey(base)).toBe(cacheKey({ ...base }));
    expect(cacheKey(base)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes with the judge, the content, the kind, and the finding identity', () => {
    const k = cacheKey(base);
    expect(cacheKey({ ...base, judge: 'anthropic:other' })).not.toBe(k);
    expect(cacheKey({ ...base, content: 'abd' })).not.toBe(k);
    expect(cacheKey({ ...base, kind: 'remediation' })).not.toBe(k);
    expect(cacheKey({ ...base, finding: finding({ id: 'SEC-GH-PAT' }) })).not.toBe(k);
    expect(cacheKey({ ...base, finding: finding({ file: 'src/b.ts' }) })).not.toBe(k);
    expect(cacheKey({ ...base, finding: finding({ description: 'other facts' }) })).not.toBe(k);
  });

  it('ignores the line number — the content hash already pins the code', () => {
    expect(cacheKey({ ...base, finding: finding({ line: 99 }) })).toBe(cacheKey(base));
  });
});

describe('judgeId', () => {
  it('folds the panel into the identity and tolerates clients without an id', () => {
    expect(judgeId('anthropic:m')).toBe('anthropic:m');
    expect(judgeId('anthropic:m', ['openrouter:a', undefined])).toBe('anthropic:m|panel:openrouter:a,unknown');
    expect(judgeId(undefined)).toBe('unknown');
  });
});

describe('cacheBaseDir', () => {
  it('honors PRISM_CACHE_DIR, then XDG_CACHE_HOME, then LOCALAPPDATA on Windows, then ~/.cache', () => {
    expect(cacheBaseDir({ PRISM_CACHE_DIR: '/x' })).toBe('/x');
    expect(cacheBaseDir({ XDG_CACHE_HOME: '/xdg' }, 'linux')).toBe(join('/xdg', 'prism'));
    expect(cacheBaseDir({ LOCALAPPDATA: 'C:\\la' }, 'win32')).toBe(join('C:\\la', 'prism', 'cache'));
    expect(cacheBaseDir({}, 'linux')).toMatch(/[\\/]\.cache[\\/]prism$/);
  });
});

describe('VerdictCache', () => {
  const tmp = () => mkdtempSync(join(tmpdir(), 'prism-cache-test-'));

  it('round-trips a value and persists it to disk atomically', () => {
    const dir = tmp();
    const c = new VerdictCache(join(dir, 'v.json'));
    expect(c.get('k')).toBeUndefined();
    c.put('k', { classification: 'real' });
    expect(c.get('k')).toEqual({ classification: 'real' });
    expect(c.stats).toEqual({ hits: 1, misses: 1, writes: 1 });
    // A fresh instance reads it back from the file — this is what survives a Ctrl-C.
    const again = new VerdictCache(join(dir, 'v.json'));
    expect(again.get('k')).toEqual({ classification: 'real' });
    expect(existsSync(join(dir, `v.json.${process.pid}.tmp`))).toBe(false);
  });

  it('starts empty on a corrupt or foreign file instead of throwing', () => {
    const dir = tmp();
    writeFileSync(join(dir, 'bad.json'), '{not json');
    expect(new VerdictCache(join(dir, 'bad.json')).get('k')).toBeUndefined();
    writeFileSync(join(dir, 'old.json'), JSON.stringify({ format: 0, entries: { k: { value: 1, usedAt: '' } } }));
    expect(new VerdictCache(join(dir, 'old.json')).get('k')).toBeUndefined();
  });

  it('evicts the least recently used entries beyond the cap', () => {
    // A small injected cap: 5,005 synchronous atomic writes took 11s on the
    // Windows CI runner (default vitest timeout is 5s) — the cap is the seam.
    const dir = tmp();
    const cap = 5;
    const c = new VerdictCache(join(dir, 'v.json'), cap);
    for (let i = 0; i < cap + 5; i++) c.put(`k${i}`, i);
    expect(c.size()).toBe(cap);
    expect(c.get('k0')).toBeUndefined(); // oldest, gone
    expect(c.get(`k${cap + 4}`)).toBe(cap + 4); // newest, kept
    expect(MAX_CACHE_ENTRIES).toBeGreaterThan(cap); // the production default stays generous
  });

  it('disables itself on a write failure instead of failing the run', () => {
    if (process.platform === 'win32' || process.getuid?.() === 0) return; // chmod is not a barrier there
    const dir = tmp();
    const locked = join(dir, 'locked');
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    const c = new VerdictCache(join(locked, 'v.json'));
    c.put('k', 1);
    expect(c.disabled).toBe(true);
    expect(c.get('k')).toBe(1); // memory still serves the run
    chmodSync(locked, 0o700);
  });

  it('forProject keys the file by the project path under the operator cache dir', () => {
    const dir = tmp();
    const a = VerdictCache.forProject(dir, { PRISM_CACHE_DIR: join(dir, 'cache') });
    const b = VerdictCache.forProject(join(dir, 'other'), { PRISM_CACHE_DIR: join(dir, 'cache') });
    expect(a.filePath.startsWith(join(dir, 'cache', 'verdicts'))).toBe(true);
    expect(a.filePath).not.toBe(b.filePath);
    a.put('k', 1);
    expect(JSON.parse(readFileSync(a.filePath, 'utf-8')).format).toBe(1);
  });
});
