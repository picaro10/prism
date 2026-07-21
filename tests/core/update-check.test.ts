import { describe, it, expect } from 'vitest';
import {
  parseVersion,
  isNewer,
  shouldCheck,
  checkForUpdate,
  type UpdateCheckDeps,
} from '../../src/core/update-check.js';

describe('parseVersion / isNewer', () => {
  it('parses dotted versions', () => {
    expect(parseVersion('v1.11.0')).toEqual([1, 11, 0]);
    expect(parseVersion('2.0')).toEqual([2, 0]);
  });
  it('compares numerically, not lexically', () => {
    expect(isNewer('1.9.0', '1.11.0')).toBe(true); // 11 > 9 despite string order
    expect(isNewer('1.11.0', '1.11.0')).toBe(false);
    expect(isNewer('2.0.0', '1.11.0')).toBe(false);
    expect(isNewer('1.11.0', '1.11.1')).toBe(true);
  });
});

describe('shouldCheck', () => {
  it('checks when never checked or the interval has elapsed', () => {
    expect(shouldCheck(undefined, 1000)).toBe(true);
    expect(shouldCheck(0, 25 * 60 * 60 * 1000)).toBe(true); // >24h
  });
  it('skips within the interval', () => {
    const now = 100 * 60 * 60 * 1000;
    expect(shouldCheck(now - 1000, now)).toBe(false);
  });
});

function deps(over: Partial<UpdateCheckDeps>): UpdateCheckDeps {
  return {
    now: 1_000_000_000_000,
    env: {},
    fetchLatest: async () => null,
    readCache: async () => null,
    writeCache: async () => {},
    ...over,
  };
}

describe('checkForUpdate', () => {
  it('opts out on PRISM_NO_UPDATE_CHECK', async () => {
    const d = deps({ env: { PRISM_NO_UPDATE_CHECK: '1' }, fetchLatest: async () => '9.9.9' });
    expect(await checkForUpdate('1.11.0', d)).toBeNull();
  });

  it('reports an available update after a fresh fetch', async () => {
    const d = deps({ fetchLatest: async () => '1.12.0' });
    expect(await checkForUpdate('1.11.0', d)).toEqual({ current: '1.11.0', latest: '1.12.0', hasUpdate: true });
  });

  it('returns null when already on the latest', async () => {
    const d = deps({ fetchLatest: async () => '1.11.0' });
    expect(await checkForUpdate('1.11.0', d)).toBeNull();
  });

  it('uses the cache (no fetch) within the interval', async () => {
    let fetched = false;
    const d = deps({
      readCache: async () => ({ lastCheck: 1_000_000_000_000 - 1000, latest: '1.12.0' }),
      fetchLatest: async () => {
        fetched = true;
        return '2.0.0';
      },
    });
    const res = await checkForUpdate('1.11.0', d);
    expect(fetched).toBe(false); // did not hit the network
    expect(res).toEqual({ current: '1.11.0', latest: '1.12.0', hasUpdate: true });
  });

  it('is error-safe: a throwing fetch yields null, never rejects', async () => {
    const d = deps({
      fetchLatest: async () => {
        throw new Error('offline');
      },
    });
    expect(await checkForUpdate('1.11.0', d)).toBeNull();
  });
});
